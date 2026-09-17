//! Renewal scheduling predicates: pure lifetime math, no I/O.
//!
//! The caller owns timing (PLAN Phase 6): these answer "how used is this
//! certificate" and "should it renew now", never sleeping or spawning. ARI's
//! `suggested_window` narrows the answer through
//! [`should_renew_in_window`]; the fetch itself lives with the caller, which
//! already owns the ACME account.

/// Expiry warning level: half the lifetime is gone, or a quarter remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// 50 % of the lifetime is used.
    Half,
    /// 75 % used — 25 % remains.
    Quarter,
}

/// `not_after <= not_before` is a broken lifetime, reported as fully used
/// rather than dividing by zero. Clock skew (`now < not_before`) clamps to 0.
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn percent_used(not_before: i64, not_after: i64, now: i64) -> u8 {
    if not_after <= not_before {
        return 100;
    }
    // i128 math: i64 seconds × 100 cannot overflow it.
    let elapsed = i128::from(now.saturating_sub(not_before).max(0));
    let total = i128::from(not_after) - i128::from(not_before);
    u8::try_from((elapsed * 100 / total).clamp(0, 100)).unwrap_or(100)
}

/// Warning for a used-percent, if any: 75+ is `Quarter`, 50+ is `Half`.
#[must_use]
pub fn warning_for(used_percent: u8) -> Option<Warning> {
    if used_percent >= 75 {
        Some(Warning::Quarter)
    } else if used_percent >= 50 {
        Some(Warning::Half)
    } else {
        None
    }
}

/// Whether the certificate should renew now: two thirds of its lifetime used.
///
/// The threshold is deliberately ahead of the 75 % `Quarter` warning so
/// renewal starts before the operator is told time is short.
#[must_use]
pub fn should_renew(not_before: i64, not_after: i64, now: i64) -> bool {
    percent_used(not_before, not_after, now) >= 66
}

/// Whether the certificate should renew now, narrowed by ARI's suggested
/// window: inside the window renews on the lifetime rule; outside it only a
/// nearly-spent certificate (≥90 %) renews early.
#[must_use]
pub fn should_renew_in_window(
    not_before: i64,
    not_after: i64,
    now: i64,
    window: Option<(i64, i64)>,
) -> bool {
    let used = percent_used(not_before, not_after, now);
    match window {
        None => used >= 66,
        Some((start, end)) => {
            if now >= start && now <= end {
                used >= 66
            } else {
                used >= 90
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pebble 160 h profile analog: 576_000 s lifetime.
    const NB: i64 = 1_700_000_000;
    const NA: i64 = NB + 576_000;

    #[test]
    fn warnings_fire_at_half_and_quarter_lifetime() {
        assert_eq!(warning_for(percent_used(NB, NA, NB)), None);
        assert_eq!(
            warning_for(percent_used(NB, NA, NB + 288_000)),
            Some(Warning::Half)
        );
        assert_eq!(
            warning_for(percent_used(NB, NA, NB + 432_000)),
            Some(Warning::Quarter)
        );
    }

    #[test]
    fn renew_starts_before_the_quarter_warning() {
        assert!(!should_renew(NB, NA, NB + 288_000));
        assert!(should_renew(NB, NA, NB + 380_160)); // 66 %
        assert!(should_renew(NB, NA, NA));
    }

    #[test]
    fn broken_lifetimes_and_skew_never_panic() {
        assert_eq!(percent_used(NA, NA, NA), 100);
        assert_eq!(percent_used(NA, NB, NB), 100); // not_after < not_before
        assert_eq!(percent_used(NB, NA, NB - 1_000), 0); // clock skew
        assert_eq!(percent_used(NB, NA, NA + 1_000_000), 100);
        assert!(should_renew(NA, NB, NB));
    }

    #[test]
    fn ari_window_narrows_but_nearly_spent_overrides() {
        let window = Some((NB + 400_000, NB + 500_000));
        // Inside the window the lifetime rule applies.
        assert!(!should_renew_in_window(NB, NA, NB + 300_000, window));
        assert!(should_renew_in_window(NB, NA, NB + 450_000, window));
        // Outside it only a nearly-spent cert renews early.
        assert!(!should_renew_in_window(NB, NA, NB + 300_000, None));
        assert!(should_renew_in_window(NB, NA, NB + 518_400, window)); // 90 %
        // No window is the plain lifetime rule.
        assert_eq!(
            should_renew_in_window(NB, NA, NB + 300_000, None),
            should_renew(NB, NA, NB + 300_000)
        );
    }
}
