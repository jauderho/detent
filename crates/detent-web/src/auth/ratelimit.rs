//! Login rate limiting: a token bucket per source address and per submitted
//! user name (PLAN §2.7, "Auth").
//!
//! ```text
//!   login attempt ─┬─▶ bucket[ip]   ─┐
//!                  └─▶ bucket[user] ─┴─▶ failures > max_failures ?
//!                                          │
//!                                          └─▶ blocked until now + 2^n · 2 s
//!                                              (capped at 15 min, audited)
//! ```
//!
//! # Guarantees
//!
//! * **The clock is a parameter.** Every method takes `now`, so the tests are
//!   deterministic and none of them sleeps.
//! * **The table cannot grow without bound.** Each map holds at most
//!   [`MAX_TRACKED`] entries; a new principal past that evicts the
//!   least-recently-seen one. An attacker who varies the source address or the
//!   submitted name therefore costs memory that is bounded by a constant.
//! * **Failures are counted for names that do not exist.** Limiting only real
//!   users would make lockout a user-enumeration oracle: `alice` would start
//!   answering 429 while `alicf` kept answering 401.
//! * **A success clears both buckets** for that principal pair, so one
//!   fat-fingered password does not follow an operator around all afternoon.
//!
//! # What eviction costs
//!
//! Evicting the least-recently-seen entry means an attacker with many source
//! addresses can push a *blocked* entry out of the table and retry sooner. The
//! alternative — refusing new principals while the table is full — turns the
//! same capability into a total lockout of the appliance, which is worse for a
//! box whose owner may be the only person who can reach it. The two maps are
//! kept separately so that address churn evicts addresses and cannot evict the
//! bucket that is throttling attempts against a named account.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::AuthError;

/// Entries kept per map before the least-recently-seen one is evicted.
pub const MAX_TRACKED: usize = 4096;

/// First backoff, applied on the failure after `max_failures`.
pub const BASE_BACKOFF: Duration = Duration::from_secs(2);

/// Ceiling on the exponential backoff.
pub const MAX_BACKOFF: Duration = Duration::from_mins(15);

/// How long an idle bucket is kept before a sweep may drop it.
pub const BUCKET_TTL: Duration = Duration::from_hours(1);

/// Sweeping must never release a principal that is still locked out. It
/// cannot, as long as the longest lockout is shorter than the time-to-live.
const _: () = assert!(MAX_BACKOFF.as_secs() < BUCKET_TTL.as_secs());

/// Which of the two buckets a decision was about, for the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// The address the attempt came from.
    Ip(IpAddr),
    /// The user name the attempt was for, whether or not it exists.
    User(String),
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Ip(ref ip) => write!(f, "ip:{ip}"),
            Self::User(ref name) => write!(f, "user:{name}"),
        }
    }
}

/// One principal's failure count and lockout deadline.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Consecutive failures since the last success.
    failures: u32,
    /// When the lockout ends, if one is running.
    blocked_until: Option<Instant>,
    /// Last time this bucket was touched, for eviction and sweeping.
    last_seen: Instant,
}

/// A bounded map of buckets.
#[derive(Debug)]
struct Buckets<K: Eq + Hash + Clone> {
    /// The buckets themselves.
    map: HashMap<K, Bucket>,
    /// Entries kept before eviction starts.
    cap: usize,
}

impl<K: Eq + Hash + Clone> Buckets<K> {
    /// An empty map holding at most `cap` entries.
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
        }
    }

    /// Seconds `key` must still wait, if it is locked out.
    fn retry_after<Q>(&self, key: &Q, now: Instant) -> Option<u64>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let bucket = self.map.get(key)?;
        let deadline = bucket.blocked_until?;
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return None;
        }
        // Rounded up: answering "wait 0 s" to somebody who must wait 400 ms
        // is an invitation to try again immediately.
        let whole = remaining.as_secs();
        Some(if remaining.subsec_nanos() > 0 {
            whole.saturating_add(1)
        } else {
            whole
        })
    }

    /// Count one failure and return `true` if it started or extended a
    /// lockout.
    fn fail<Q>(&mut self, key: &Q, max_failures: u32, now: Instant) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ToOwned<Owned = K> + ?Sized,
    {
        self.make_room(now);
        let bucket = self.map.entry(key.to_owned()).or_insert(Bucket {
            failures: 0,
            blocked_until: None,
            last_seen: now,
        });
        bucket.failures = bucket.failures.saturating_add(1);
        bucket.last_seen = now;
        // `max_failures` failures are what it takes to be locked out, not
        // what is forgiven: PLAN §2.7 says "5 failures -> exponential
        // backoff", so the fifth attempt is the one that blocks.
        let over = bucket
            .failures
            .saturating_add(1)
            .saturating_sub(max_failures);
        if over == 0 {
            return false;
        }
        let backoff = backoff_for(over);
        bucket.blocked_until = now.checked_add(backoff);
        true
    }

    /// Forget everything about `key`.
    fn clear<Q>(&mut self, key: &Q)
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.remove(key);
    }

    /// Drop buckets that have not been touched for [`BUCKET_TTL`].
    ///
    /// A bucket that is still locked out is always recent: the longest
    /// lockout is [`MAX_BACKOFF`], which the assertion below keeps shorter
    /// than the time-to-live, so "idle for an hour" implies "no longer
    /// blocked" and the sweep cannot release anybody early.
    fn sweep(&mut self, now: Instant) {
        self.map
            .retain(|_key, bucket| now.saturating_duration_since(bucket.last_seen) < BUCKET_TTL);
    }

    /// Make sure one more entry fits, evicting the least-recently-seen if not.
    fn make_room(&mut self, now: Instant) {
        if self.map.len() < self.cap {
            return;
        }
        self.sweep(now);
        if self.map.len() < self.cap {
            return;
        }
        let oldest = self
            .map
            .iter()
            .min_by_key(|(_key, bucket)| bucket.last_seen)
            .map(|(key, _bucket)| key.clone());
        if let Some(key) = oldest {
            self.map.remove(&key);
        }
    }
}

/// The backoff after `over` failures past the threshold: 2 s, 4 s, 8 s … up to
/// [`MAX_BACKOFF`].
fn backoff_for(over: u32) -> Duration {
    let doublings = over.saturating_sub(1);
    2_u32
        .checked_pow(doublings)
        .and_then(|factor| BASE_BACKOFF.checked_mul(factor))
        .map_or(MAX_BACKOFF, |backoff| backoff.min(MAX_BACKOFF))
}

/// Per-address and per-user login throttling.
pub struct RateLimiter {
    /// Buckets keyed by source address.
    ips: Mutex<Buckets<IpAddr>>,
    /// Buckets keyed by submitted user name.
    users: Mutex<Buckets<String>>,
    /// Failures allowed before backoff starts (`auth.max_failures`).
    max_failures: u32,
}

impl std::fmt::Debug for RateLimiter {
    /// Counts, never keys: a user name and a source address are both audit
    /// material, and this type is held inside application state that other
    /// code may print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (ips, users) = self.tracked();
        f.debug_struct("RateLimiter")
            .field("max_failures", &self.max_failures)
            .field("tracked_addresses", &ips)
            .field("tracked_users", &users)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// A limiter that allows `max_failures` consecutive failures per
    /// principal before it starts backing off.
    ///
    /// A configured zero is treated as one: a limiter that locks out on the
    /// zeroth attempt would lock out every user permanently.
    #[must_use]
    pub fn new(max_failures: u32) -> Self {
        Self {
            ips: Mutex::new(Buckets::new(MAX_TRACKED)),
            users: Mutex::new(Buckets::new(MAX_TRACKED)),
            max_failures: max_failures.max(1),
        }
    }

    /// Whether this attempt may proceed.
    ///
    /// # Errors
    ///
    /// [`AuthError::RateLimited`] carrying the seconds to wait, which is the
    /// longer of the two buckets' remaining lockouts.
    pub fn check(&self, ip: IpAddr, user: &str, now: Instant) -> Result<(), AuthError> {
        let by_ip = self
            .ips
            .lock()
            .ok()
            .and_then(|buckets| buckets.retry_after(&ip, now));
        let by_user = self
            .users
            .lock()
            .ok()
            .and_then(|buckets| buckets.retry_after(user, now));
        match by_ip.max(by_user) {
            Some(retry_after_secs) => Err(AuthError::RateLimited { retry_after_secs }),
            None => Ok(()),
        }
    }

    /// Count one failed attempt.
    ///
    /// Returns the principals this failure locked out, for the audit record;
    /// empty while the attempt count is still under the threshold.
    pub fn record_failure(&self, ip: IpAddr, user: &str, now: Instant) -> Vec<Principal> {
        let mut locked = Vec::new();
        if let Ok(mut buckets) = self.ips.lock()
            && buckets.fail(&ip, self.max_failures, now)
        {
            locked.push(Principal::Ip(ip));
        }
        if let Ok(mut buckets) = self.users.lock()
            && buckets.fail(user, self.max_failures, now)
        {
            locked.push(Principal::User(user.to_owned()));
        }
        locked
    }

    /// Forget this principal pair's failures after a successful login.
    pub fn record_success(&self, ip: IpAddr, user: &str) {
        if let Ok(mut buckets) = self.ips.lock() {
            buckets.clear(&ip);
        }
        if let Ok(mut buckets) = self.users.lock() {
            buckets.clear(user);
        }
    }

    /// Drop buckets that are neither blocked nor recently used.
    pub fn sweep(&self, now: Instant) {
        if let Ok(mut buckets) = self.ips.lock() {
            buckets.sweep(now);
        }
        if let Ok(mut buckets) = self.users.lock() {
            buckets.sweep(now);
        }
    }

    /// How many principals are currently tracked, as `(addresses, users)`.
    #[must_use]
    pub fn tracked(&self) -> (usize, usize) {
        let ips = self.ips.lock().map_or(0, |buckets| buckets.map.len());
        let users = self.users.lock().map_or(0, |buckets| buckets.map.len());
        (ips, users)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_BACKOFF, Buckets, MAX_BACKOFF, MAX_TRACKED, Principal, RateLimiter, backoff_for,
    };
    use crate::auth::AuthError;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    fn retry_after(limiter: &RateLimiter, at: Instant) -> Option<u64> {
        match limiter.check(ip(1), "alice", at) {
            Err(AuthError::RateLimited { retry_after_secs }) => Some(retry_after_secs),
            _ => None,
        }
    }

    #[test]
    fn the_first_failures_are_free_and_the_next_one_locks_out() {
        let limiter = RateLimiter::new(5);
        let start = Instant::now();
        for attempt in 0_u32..4 {
            assert!(limiter.record_failure(ip(1), "alice", start).is_empty());
            assert!(
                limiter.check(ip(1), "alice", start).is_ok(),
                "locked out after {attempt} failures"
            );
        }
        let locked = limiter.record_failure(ip(1), "alice", start);
        assert_eq!(
            locked,
            vec![Principal::Ip(ip(1)), Principal::User("alice".to_owned())]
        );
        assert_eq!(retry_after(&limiter, start), Some(BASE_BACKOFF.as_secs()));
    }

    #[test]
    fn the_backoff_doubles_and_is_capped() {
        assert_eq!(backoff_for(1), BASE_BACKOFF);
        assert_eq!(backoff_for(2), BASE_BACKOFF.saturating_mul(2));
        assert_eq!(backoff_for(3), BASE_BACKOFF.saturating_mul(4));
        assert_eq!(backoff_for(20), MAX_BACKOFF);
        // Far past the point where 2^n overflows a u32.
        assert_eq!(backoff_for(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn a_lockout_expires_on_its_own() -> R {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        assert!(!limiter.record_failure(ip(1), "alice", start).is_empty());
        assert_eq!(retry_after(&limiter, start), Some(BASE_BACKOFF.as_secs()));

        // Half way through: still locked, and the answer has been rounded up.
        let midway = start
            .checked_add(BASE_BACKOFF / 2)
            .ok_or("clock overflowed")?;
        assert_eq!(retry_after(&limiter, midway), Some(1));

        let after = start
            .checked_add(BASE_BACKOFF)
            .and_then(|t| t.checked_add(Duration::from_millis(1)))
            .ok_or("clock overflowed")?;
        assert_eq!(retry_after(&limiter, after), None);
        Ok(())
    }

    #[test]
    fn a_success_clears_the_counter() {
        let limiter = RateLimiter::new(3);
        let start = Instant::now();
        let _ = limiter.record_failure(ip(1), "alice", start);
        let _ = limiter.record_failure(ip(1), "alice", start);
        limiter.record_success(ip(1), "alice");
        assert_eq!(limiter.tracked(), (0, 0));

        // The count restarts, rather than resuming where it left off: two
        // more failures are still under the threshold of three.
        let _ = limiter.record_failure(ip(1), "alice", start);
        let _ = limiter.record_failure(ip(1), "alice", start);
        assert!(limiter.check(ip(1), "alice", start).is_ok());
        assert!(!limiter.record_failure(ip(1), "alice", start).is_empty());
    }

    #[test]
    fn the_two_buckets_are_independent() -> R {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        // One address, two different names: the address is locked out, and so
        // is each name it tried.
        assert_eq!(
            limiter.record_failure(ip(1), "alice", start),
            vec![Principal::Ip(ip(1)), Principal::User("alice".to_owned())]
        );
        match limiter.check(ip(1), "bob", start) {
            Err(AuthError::RateLimited { .. }) => {}
            other => return Err(format!("a locked address let `bob` through: {other:?}").into()),
        }
        // A different address trying `bob` is unaffected.
        assert!(limiter.check(ip(2), "bob", start).is_ok());
        // …but `alice` is locked wherever she is tried from.
        match limiter.check(ip(2), "alice", start) {
            Err(AuthError::RateLimited { .. }) => {}
            other => return Err(format!("a locked name was let through: {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_name_that_does_not_exist_is_still_throttled() {
        // Enumeration guard: the limiter never consults the user store.
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        assert_eq!(
            limiter.record_failure(ip(1), "no-such-user", start),
            vec![
                Principal::Ip(ip(1)),
                Principal::User("no-such-user".to_owned())
            ]
        );
    }

    #[test]
    fn the_maps_are_bounded_by_eviction() {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        // One failure per distinct name, more than the cap allows.
        for index in 0..MAX_TRACKED.saturating_add(50) {
            let at = start
                .checked_add(Duration::from_millis(
                    u64::try_from(index).unwrap_or_default(),
                ))
                .unwrap_or(start);
            let _ = limiter.record_failure(ip(1), &format!("user-{index}"), at);
        }
        let (ips, users) = limiter.tracked();
        assert_eq!(ips, 1);
        assert!(users <= MAX_TRACKED, "{users} entries tracked");
    }

    #[test]
    fn eviction_drops_the_least_recently_seen_entry() {
        let mut buckets: Buckets<String> = Buckets::new(2);
        let start = Instant::now();
        let later = start.checked_add(Duration::from_secs(1)).unwrap_or(start);
        let latest = start.checked_add(Duration::from_secs(2)).unwrap_or(start);
        assert!(buckets.fail("old", 0, start));
        assert!(buckets.fail("new", 0, later));
        assert!(buckets.fail("newest", 0, latest));
        assert_eq!(buckets.map.len(), 2);
        assert!(!buckets.map.contains_key("old"));
        assert!(buckets.map.contains_key("newest"));
    }

    #[test]
    fn a_sweep_keeps_blocked_and_recent_buckets_only() {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        let _ = limiter.record_failure(ip(1), "alice", start);
        assert_eq!(limiter.tracked(), (1, 1));

        // Long after the lockout and the idle window: both go.
        let much_later = start
            .checked_add(Duration::from_secs(7200))
            .unwrap_or(start);
        limiter.sweep(much_later);
        assert_eq!(limiter.tracked(), (0, 0));
    }

    #[test]
    fn a_bucket_that_is_still_locked_out_survives_a_sweep() -> R {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        // Enough failures to be blocked for the maximum backoff.
        for _ in 0_u32..20 {
            let _ = limiter.record_failure(ip(1), "alice", start);
        }
        // A sweep at any point inside the longest possible lockout leaves the
        // bucket in place, because the lockout is shorter than the idle
        // time-to-live.
        let inside = start.checked_add(MAX_BACKOFF).ok_or("clock overflowed")?;
        limiter.sweep(inside);
        assert_eq!(limiter.tracked(), (1, 1));
        match limiter.check(ip(1), "alice", start) {
            Err(AuthError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, MAX_BACKOFF.as_secs());
            }
            other => return Err(format!("expected a lockout, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_zero_threshold_is_treated_as_one() {
        let limiter = RateLimiter::new(0);
        let start = Instant::now();
        assert!(limiter.check(ip(1), "alice", start).is_ok());
        assert!(!limiter.record_failure(ip(1), "alice", start).is_empty());
    }

    #[test]
    fn a_principal_renders_for_the_audit_log() {
        assert_eq!(Principal::Ip(ip(7)).to_string(), "ip:198.51.100.7");
        assert_eq!(
            Principal::User("alice".to_owned()).to_string(),
            "user:alice"
        );
        assert!(format!("{:?}", Principal::Ip(ip(7))).contains("198.51.100.7"));
        assert_ne!(Principal::Ip(ip(7)), Principal::User("alice".to_owned()));
    }

    #[test]
    fn the_limiter_debug_shows_counts_and_no_names() {
        let limiter = RateLimiter::new(5);
        let start = Instant::now();
        let _ = limiter.record_failure(ip(1), "alice", start);
        let rendered = format!("{limiter:?}");
        assert!(rendered.contains("max_failures: 5"), "{rendered}");
        assert!(rendered.contains("tracked_addresses: 1"), "{rendered}");
        assert!(rendered.contains("tracked_users: 1"), "{rendered}");
        assert!(!rendered.contains("alice"), "{rendered}");
        assert!(!rendered.contains("198.51.100"), "{rendered}");
    }
}
