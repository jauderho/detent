//! A request budget per API token (ASVS 8.1.4, 11.1.4; threat WEB-13).
//!
//! ```text
//!   Bearer <token> ─▶ TokenStore::authenticate ─▶ budget[token id]
//!                                                   │
//!                         over `auth.token_burst` ──┴─▶ 429 + Retry-After
//!                         (refilled at `auth.token_rate_per_minute`)
//!                                                   │
//!                         first refusal of an episode ─▶ `token_rate_limited`
//! ```
//!
//! # Guarantees
//!
//! * **The clock is a parameter**, as in [`super::ratelimit`]: every method
//!   takes `now`, so no test sleeps.
//! * **A budget is keyed by the token id**, never by the token. The id is
//!   public (it names the token in listings and the audit log); the secret is
//!   not seen here at all.
//! * **One audit record per episode.** The first refusal reports
//!   [`Admission::Limited`] with `first` set; later refusals do not, until the
//!   bucket has refilled to its full burst. A client that keeps hammering
//!   never lets it refill, so it writes one record, not one per request.
//! * **The table cannot grow without bound.** It holds at most
//!   [`MAX_TRACKED_TOKENS`] entries: the token store's own cap plus a small
//!   margin for tokens revoked while their bucket was still draining. A full
//!   bucket is dropped before anything else, because dropping it loses
//!   nothing: a missing entry is a full bucket.
//!
//! # The bucket
//!
//! A token bucket written as its generic cell rate form: each bucket keeps
//! the instant at which it would be full again (`full_at`). A request costs
//! one `interval` (`60 s / rate`); it is refused when the bucket would then be
//! more than `burst` requests in debt. This needs no floating point and no
//! background refill.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::token::MAX_TOKENS;

/// Entries kept beyond [`MAX_TOKENS`], for revoked tokens whose bucket has not
/// refilled yet.
pub const TRACKED_MARGIN: usize = 8;

/// Entries kept before the fullest bucket is evicted.
pub const MAX_TRACKED_TOKENS: usize = MAX_TOKENS.saturating_add(TRACKED_MARGIN);

/// One minute, the period `auth.token_rate_per_minute` is counted over.
const MINUTE: Duration = Duration::from_mins(1);

/// What [`TokenLimiter::check`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The request may proceed.
    Allowed,
    /// The token is over its budget.
    Limited {
        /// Seconds until one more request fits, rounded up.
        retry_after_secs: u64,
        /// Whether this refusal starts an episode, and so is to be audited.
        first: bool,
    },
}

/// One token's budget.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// When the bucket is full again if no more requests arrive.
    full_at: Instant,
    /// Whether a refusal was already reported since the bucket was last full.
    limited: bool,
}

/// Per-token request budgets.
pub struct TokenLimiter {
    /// Buckets keyed by token id.
    buckets: Mutex<HashMap<String, Bucket>>,
    /// The cost of one request: `60 s / auth.token_rate_per_minute`.
    interval: Duration,
    /// How far ahead of `now` a bucket may run before it refuses:
    /// `interval · (auth.token_burst − 1)`.
    tolerance: Duration,
}

impl std::fmt::Debug for TokenLimiter {
    /// Counts, never ids, like [`super::RateLimiter`]'s.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenLimiter")
            .field("interval", &self.interval)
            .field("tolerance", &self.tolerance)
            .field("tracked_tokens", &self.tracked())
            .finish_non_exhaustive()
    }
}

impl TokenLimiter {
    /// A limiter that lets each token make `burst` requests at once and
    /// `rate_per_minute` a minute after that.
    ///
    /// A zero is treated as one: `Config::validate` refuses both, and a
    /// limiter built by hand must still not divide by zero.
    #[must_use]
    pub fn new(burst: u32, rate_per_minute: u32) -> Self {
        let interval = MINUTE.checked_div(rate_per_minute.max(1)).unwrap_or(MINUTE);
        let tolerance = interval
            .checked_mul(burst.max(1).saturating_sub(1))
            .unwrap_or(Duration::MAX);
        Self {
            buckets: Mutex::new(HashMap::new()),
            interval,
            tolerance,
        }
    }

    /// Charge one request to token `id` at `now`.
    pub fn check(&self, id: &str, now: Instant) -> Admission {
        let Ok(mut buckets) = self.buckets.lock() else {
            return Admission::Allowed;
        };
        if !buckets.contains_key(id) {
            make_room(&mut buckets, now);
        }
        let bucket = buckets.entry(id.to_owned()).or_insert(Bucket {
            full_at: now,
            limited: false,
        });
        if bucket.full_at <= now {
            // Full again: the episode, if there was one, is over.
            bucket.full_at = now;
            bucket.limited = false;
        }
        let debt = bucket.full_at.saturating_duration_since(now);
        if debt > self.tolerance {
            let wait = debt.saturating_sub(self.tolerance);
            let first = !bucket.limited;
            bucket.limited = true;
            return Admission::Limited {
                retry_after_secs: round_up_secs(wait),
                first,
            };
        }
        bucket.full_at = bucket
            .full_at
            .checked_add(self.interval)
            .unwrap_or(bucket.full_at);
        Admission::Allowed
    }

    /// How many tokens currently have a bucket.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.lock().map_or(0, |buckets| buckets.len())
    }
}

/// Make sure one more entry fits: drop full buckets, then, if the table is
/// still at the cap, the bucket closest to full.
fn make_room(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    if buckets.len() < MAX_TRACKED_TOKENS {
        return;
    }
    buckets.retain(|_id, bucket| bucket.full_at > now);
    if buckets.len() < MAX_TRACKED_TOKENS {
        return;
    }
    let fullest = buckets
        .iter()
        .min_by_key(|(_id, bucket)| bucket.full_at)
        .map(|(id, _bucket)| id.clone());
    if let Some(id) = fullest {
        buckets.remove(&id);
    }
}

/// Whole seconds in `wait`, rounded up: answering "wait 0 s" to somebody who
/// must wait 400 ms is an invitation to try again at once.
fn round_up_secs(wait: Duration) -> u64 {
    let whole = wait.as_secs();
    if wait.subsec_nanos() > 0 {
        whole.saturating_add(1)
    } else {
        whole
    }
}

#[cfg(test)]
mod tests {
    use super::{Admission, MAX_TRACKED_TOKENS, TokenLimiter, round_up_secs};
    use std::time::{Duration, Instant};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn at(start: Instant, millis: u64) -> Instant {
        start
            .checked_add(Duration::from_millis(millis))
            .unwrap_or(start)
    }

    /// Spend `count` requests of `id` at `now`; every one must be allowed.
    fn spend(limiter: &TokenLimiter, id: &str, count: u32, now: Instant) -> R {
        for request in 0..count {
            let admission = limiter.check(id, now);
            if admission != Admission::Allowed {
                return Err(format!("request {request} of {id} gave {admission:?}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn a_token_gets_its_burst_and_then_429() -> R {
        let limiter = TokenLimiter::new(60, 120);
        let start = Instant::now();
        spend(&limiter, "a", 60, start)?;
        // One request costs 500 ms at 120 a minute, so the next one fits in
        // half a second: rounded up to one.
        assert_eq!(
            limiter.check("a", start),
            Admission::Limited {
                retry_after_secs: 1,
                first: true
            }
        );
        Ok(())
    }

    #[test]
    fn the_bucket_refills_at_the_configured_rate() -> R {
        let limiter = TokenLimiter::new(2, 60);
        let start = Instant::now();
        spend(&limiter, "a", 2, start)?;
        assert!(matches!(
            limiter.check("a", at(start, 999)),
            Admission::Limited { .. }
        ));
        // One second buys one request at 60 a minute, and only one.
        assert_eq!(limiter.check("a", at(start, 1000)), Admission::Allowed);
        assert!(matches!(
            limiter.check("a", at(start, 1000)),
            Admission::Limited { .. }
        ));
        // After a full refill the whole burst is there again, and no more.
        spend(&limiter, "a", 2, at(start, 10_000))?;
        assert!(matches!(
            limiter.check("a", at(start, 10_000)),
            Admission::Limited { .. }
        ));
        Ok(())
    }

    #[test]
    fn retry_after_is_rounded_up_to_whole_seconds() -> R {
        assert_eq!(round_up_secs(Duration::from_millis(1)), 1);
        assert_eq!(round_up_secs(Duration::from_secs(2)), 2);
        assert_eq!(round_up_secs(Duration::from_millis(2001)), 3);

        // One request a minute: after the burst, the wait is the minute less
        // whatever has passed.
        let limiter = TokenLimiter::new(1, 1);
        let start = Instant::now();
        spend(&limiter, "a", 1, start)?;
        let retry = |millis| match limiter.check("a", at(start, millis)) {
            Admission::Limited {
                retry_after_secs, ..
            } => Some(retry_after_secs),
            Admission::Allowed => None,
        };
        assert_eq!(retry(0), Some(60));
        assert_eq!(retry(400), Some(60));
        assert_eq!(retry(59_001), Some(1));
        assert_eq!(retry(60_000), None);
        Ok(())
    }

    #[test]
    fn tokens_have_separate_budgets() -> R {
        let limiter = TokenLimiter::new(3, 60);
        let start = Instant::now();
        spend(&limiter, "a", 3, start)?;
        assert!(matches!(
            limiter.check("a", start),
            Admission::Limited { .. }
        ));
        spend(&limiter, "b", 3, start)?;
        assert_eq!(limiter.tracked(), 2);
        Ok(())
    }

    #[test]
    fn an_episode_is_reported_once_until_the_bucket_is_full_again() -> R {
        let limiter = TokenLimiter::new(2, 60);
        let start = Instant::now();
        spend(&limiter, "a", 2, start)?;
        let first = |admission| match admission {
            Admission::Limited { first, .. } => Some(first),
            Admission::Allowed => None,
        };
        assert_eq!(first(limiter.check("a", start)), Some(true));
        assert_eq!(first(limiter.check("a", start)), Some(false));
        // Partly refilled: one request fits, the next is refused again, and
        // it is still the same episode.
        assert_eq!(first(limiter.check("a", at(start, 1000))), None);
        assert_eq!(first(limiter.check("a", at(start, 1000))), Some(false));
        // Full again (two seconds after the last spend): a new episode.
        let later = at(start, 3000);
        spend(&limiter, "a", 2, later)?;
        assert_eq!(first(limiter.check("a", later)), Some(true));
        Ok(())
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_fullest_bucket() -> R {
        let limiter = TokenLimiter::new(2, 60);
        let start = Instant::now();
        // Two requests deep: the deepest debt in the table.
        spend(&limiter, "busy", 2, start)?;
        // Many more ids than the cap, each one request deep, none full yet.
        for index in 0..MAX_TRACKED_TOKENS.saturating_mul(3) {
            assert_eq!(
                limiter.check(&format!("id-{index}"), start),
                Admission::Allowed
            );
            assert!(limiter.tracked() <= MAX_TRACKED_TOKENS);
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_TOKENS);
        // The churn evicted shallower buckets, never the drained one.
        assert!(matches!(
            limiter.check("busy", start),
            Admission::Limited { first: true, .. }
        ));
        Ok(())
    }

    #[test]
    fn full_buckets_are_swept_when_the_table_is_full() {
        let limiter = TokenLimiter::new(1, 1);
        let start = Instant::now();
        for index in 0..MAX_TRACKED_TOKENS {
            let _ = limiter.check(&format!("id-{index}"), start);
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_TOKENS);
        // A minute later every bucket is full again, so a new id drops them
        // all: a missing bucket and a full one mean the same.
        assert_eq!(limiter.check("new", at(start, 60_000)), Admission::Allowed);
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn zero_settings_are_treated_as_one() {
        let limiter = TokenLimiter::new(0, 0);
        let start = Instant::now();
        assert_eq!(limiter.check("a", start), Admission::Allowed);
        assert_eq!(
            limiter.check("a", start),
            Admission::Limited {
                retry_after_secs: 60,
                first: true
            }
        );
    }

    #[test]
    fn the_debug_shows_counts_and_no_ids() {
        let limiter = TokenLimiter::new(60, 120);
        let _ = limiter.check("0123456789abcdef", Instant::now());
        let rendered = format!("{limiter:?}");
        assert!(rendered.contains("tracked_tokens: 1"), "{rendered}");
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
    }
}
