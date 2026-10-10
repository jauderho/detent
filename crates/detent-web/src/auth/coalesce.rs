//! One audit record per client address per minute for rejected credentials
//! (`THREAT_MODEL` TM-G4).
//!
//! ```text
//!   bad bearer token / unknown or expired session
//!            │
//!            ▼
//!   Coalescer::admit(ip, now) ──▶ Some(n)  log one record (n = refusals held back)
//!                             └─▶ None     inside the window: count it, log nothing
//! ```
//!
//! # Why
//!
//! A login failure is already bounded by the rate limiter. A rejected bearer
//! token is not: any client can send one on every request, and an audit line
//! per request would let it fill the log (and push the real records out
//! through rotation) at wire speed. So the first rejection from an address is
//! logged, the rest inside [`WINDOW`] are only counted, and the next record
//! after the window carries that count.
//!
//! # Guarantees
//!
//! * **The clock is a parameter**, so no test sleeps.
//! * **The table is bounded.** At most [`MAX_CLIENTS`] addresses are tracked;
//!   a new one past that evicts the one logged longest ago. Address churn
//!   therefore costs a constant amount of memory. It also means a client with
//!   many source addresses is logged once per address; the cost is the
//!   attacker's addresses, not an unbounded table.
//! * **IPv6 is keyed by its /64**, like the login limiter, so one subnet is
//!   one client.
//! * **Nothing about the credential is kept.** The key is the address; the
//!   value is a time and a count.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::ratelimit::normalize_ip;

/// The most often one address is logged.
pub const WINDOW: Duration = Duration::from_mins(1);

/// Addresses tracked before the longest-ago logged one is evicted.
pub const MAX_CLIENTS: usize = 256;

/// What is remembered about one address.
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// When this address was last logged.
    logged_at: Instant,
    /// Rejections since then that were not logged.
    suppressed: u32,
}

/// Decides which rejections reach the audit log.
#[derive(Default)]
pub struct Coalescer {
    /// Per-address state.
    clients: Mutex<HashMap<IpAddr, Entry>>,
}

impl std::fmt::Debug for Coalescer {
    /// A count, never an address.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coalescer")
            .field("tracked", &self.tracked())
            .finish_non_exhaustive()
    }
}

impl Coalescer {
    /// An empty coalescer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a rejection from `ip` at `now` is logged.
    ///
    /// `Some(n)` means log it, with `n` rejections held back since the last
    /// record for this address (`0` for the first). `None` means count it and
    /// log nothing.
    pub fn admit(&self, ip: IpAddr, now: Instant) -> Option<u32> {
        let key = normalize_ip(ip);
        // A poisoned lock fails open: one more record is better than none.
        let Ok(mut clients) = self.clients.lock() else {
            return Some(0);
        };
        if let Some(entry) = clients.get_mut(&key) {
            if now.saturating_duration_since(entry.logged_at) < WINDOW {
                entry.suppressed = entry.suppressed.saturating_add(1);
                return None;
            }
            let held_back = entry.suppressed;
            *entry = Entry {
                logged_at: now,
                suppressed: 0,
            };
            return Some(held_back);
        }
        if clients.len() >= MAX_CLIENTS {
            let oldest = clients
                .iter()
                .min_by_key(|(_key, entry)| entry.logged_at)
                .map(|(key, _entry)| *key);
            if let Some(oldest) = oldest {
                clients.remove(&oldest);
            }
        }
        clients.insert(
            key,
            Entry {
                logged_at: now,
                suppressed: 0,
            },
        );
        Some(0)
    }

    /// How many addresses are tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.clients.lock().map_or(0, |clients| clients.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{Coalescer, MAX_CLIENTS, WINDOW};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start
            .checked_add(Duration::from_secs(secs))
            .unwrap_or(start)
    }

    #[test]
    fn the_first_rejection_is_logged_and_the_rest_in_the_window_are_counted() {
        let coalescer = Coalescer::new();
        let start = Instant::now();
        assert_eq!(coalescer.admit(v4(7), start), Some(0));
        assert_eq!(coalescer.admit(v4(7), at(start, 1)), None);
        assert_eq!(coalescer.admit(v4(7), at(start, 59)), None);
        // Another address has its own window.
        assert_eq!(coalescer.admit(v4(8), at(start, 30)), Some(0));
        // After the window the next one is logged, carrying the count.
        assert_eq!(coalescer.admit(v4(7), at(start, 60)), Some(2));
        // And the count starts again.
        assert_eq!(coalescer.admit(v4(7), at(start, 61)), None);
        assert_eq!(coalescer.admit(v4(7), at(start, 120)), Some(1));
        assert_eq!(coalescer.admit(v4(7), at(start, 181)), Some(0));
    }

    #[test]
    fn an_ipv6_subnet_is_one_client() {
        let coalescer = Coalescer::new();
        let start = Instant::now();
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 9, 9, 9, 9));
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        assert_eq!(coalescer.admit(a, start), Some(0));
        assert_eq!(coalescer.admit(b, start), None);
        assert_eq!(coalescer.admit(other, start), Some(0));
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_one_logged_longest_ago() {
        let coalescer = Coalescer::new();
        let start = Instant::now();
        let ip = |n: usize| {
            IpAddr::V4(Ipv4Addr::from(
                u32::try_from(n)
                    .unwrap_or_default()
                    .wrapping_add(0x0a00_0000),
            ))
        };
        for n in 0..MAX_CLIENTS {
            let secs = u64::try_from(n).unwrap_or_default();
            assert_eq!(coalescer.admit(ip(n), at(start, secs)), Some(0));
        }
        assert_eq!(coalescer.tracked(), MAX_CLIENTS);
        // One more, still inside everyone's window: the first address goes.
        assert_eq!(coalescer.admit(ip(MAX_CLIENTS), at(start, 5)), Some(0));
        assert_eq!(coalescer.tracked(), MAX_CLIENTS);
        // Address 0 was evicted, so it is new again; address 1 is still held.
        assert_eq!(coalescer.admit(ip(1), at(start, 6)), None);
        assert_eq!(coalescer.admit(ip(0), at(start, 6)), Some(0));
        assert_eq!(coalescer.tracked(), MAX_CLIENTS);
    }

    #[test]
    fn the_window_is_one_minute_and_debug_shows_no_address() {
        assert_eq!(WINDOW, Duration::from_secs(60));
        let coalescer = Coalescer::new();
        let _ = coalescer.admit(v4(7), Instant::now());
        let shown = format!("{coalescer:?}");
        assert!(shown.contains("tracked: 1"), "{shown}");
        assert!(!shown.contains("198.51"), "{shown}");
    }
}
