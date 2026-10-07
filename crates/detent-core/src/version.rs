//! Dotted numeric version comparison, for `since`-gated options.
//!
//! A version is a run of dot-separated decimal numbers at the start of the
//! text. Anything after that run is ignored, so `4.19.5-Debian` is `4.19.5`.
//! Text with no such run, an empty component (`4..9`) or a component that
//! overflows `u64` is not a version: every function here answers `None`
//! ("unknown") for it, never a guess.

use std::cmp::Ordering;

/// The numeric components of `text`, or `None` when it is not a version.
fn components(text: &str) -> Option<Vec<u64>> {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let run = text.get(..end)?.trim_end_matches('.');
    run.split('.').map(|part| part.parse().ok()).collect()
}

/// Compares two versions numerically, component by component.
///
/// Missing trailing components count as `0`, so `4.9` equals `4.9.0` and
/// `4.10` is greater than `4.9`. `None` when either side is not a version.
#[must_use]
pub fn compare(left: &str, right: &str) -> Option<Ordering> {
    let left = components(left)?;
    let right = components(right)?;
    for index in 0..left.len().max(right.len()) {
        let l = left.get(index).copied().unwrap_or(0);
        let r = right.get(index).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            unequal => return Some(unequal),
        }
    }
    Some(Ordering::Equal)
}

/// Whether `installed` is at least `required`. `None` when either side is not
/// a version.
#[must_use]
pub fn at_least(installed: &str, required: &str) -> Option<bool> {
    compare(installed, required).map(Ordering::is_ge)
}

#[cfg(test)]
mod tests {
    use super::{at_least, compare};
    use std::cmp::Ordering;

    #[test]
    fn compares_numerically_not_textually() {
        assert_eq!(compare("4.10", "4.9"), Some(Ordering::Greater));
        assert_eq!(compare("4.9", "4.10"), Some(Ordering::Less));
        assert_eq!(compare("4.19.5", "4.24"), Some(Ordering::Less));
        assert_eq!(compare("10.0", "9.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn missing_trailing_components_are_zero() {
        assert_eq!(compare("4.9", "4.9.0"), Some(Ordering::Equal));
        assert_eq!(compare("4.9.0.0", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("4.9", "4.9.1"), Some(Ordering::Less));
        assert_eq!(compare("4", "4.0.0"), Some(Ordering::Equal));
    }

    #[test]
    fn leading_zeros_do_not_change_the_value() {
        assert_eq!(compare("4.09", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("04.9", "4.9"), Some(Ordering::Equal));
    }

    #[test]
    fn suffixes_after_the_numeric_run_are_ignored() {
        assert_eq!(compare("4.19.5-Debian", "4.19.5"), Some(Ordering::Equal));
        assert_eq!(compare("4.5+dfsg", "4.5"), Some(Ordering::Equal));
        assert_eq!(compare("4.9rc1", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("  4.9 ", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("4.9.", "4.9"), Some(Ordering::Equal));
    }

    #[test]
    fn text_without_a_leading_numeric_run_is_unknown() {
        for bad in ["", " ", "abc", "v4.9", "-4.9", ".9", "4..9", "Version 4.9"] {
            assert_eq!(compare(bad, "4.9"), None, "left {bad:?}");
            assert_eq!(compare("4.9", bad), None, "right {bad:?}");
            assert_eq!(at_least(bad, "4.9"), None, "at_least {bad:?}");
        }
    }

    #[test]
    fn a_component_that_overflows_is_unknown() {
        assert_eq!(compare("4.99999999999999999999999", "4.9"), None);
    }

    #[test]
    fn at_least_includes_equal() {
        assert_eq!(at_least("4.9", "4.9"), Some(true));
        assert_eq!(at_least("4.10", "4.9"), Some(true));
        assert_eq!(at_least("4.5", "4.9"), Some(false));
        assert_eq!(at_least("4.19.5-Debian", "4.24"), Some(false));
    }
}
