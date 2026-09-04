//! Extracts the first version-looking token (`\d+\.\d+(\.\d+)?`) from probe
//! output, without a regex dependency.

/// Find the first substring matching `\d+\.\d+(\.\d+)?` in `text`.
#[must_use]
pub(super) fn first_version_token(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if let Some(token) = match_at(&chars, i) {
            return Some(token);
        }
        i = i.saturating_add(1);
    }
    None
}

fn match_at(chars: &[char], start: usize) -> Option<String> {
    let (major, after_major) = take_digits(chars, start)?;
    let after_dot1 = expect_char(chars, after_major, '.')?;
    let (minor, after_minor) = take_digits(chars, after_dot1)?;

    let mut token = format!("{major}.{minor}");
    if let Some(after_dot2) = expect_char(chars, after_minor, '.')
        && let Some((patch, _)) = take_digits(chars, after_dot2)
    {
        token.push('.');
        token.push_str(&patch);
    }
    Some(token)
}

fn take_digits(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut end = start;
    while chars.get(end).is_some_and(char::is_ascii_digit) {
        end = end.saturating_add(1);
    }
    if end == start {
        return None;
    }
    let digits: String = chars.get(start..end)?.iter().collect();
    Some((digits, end))
}

fn expect_char(chars: &[char], pos: usize, expected: char) -> Option<usize> {
    if chars.get(pos) == Some(&expected) {
        Some(pos.saturating_add(1))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_major_minor_patch() {
        assert_eq!(
            first_version_token("chronyd (chrony) version 4.5 (+CMDMON...)"),
            Some("4.5".to_string())
        );
        assert_eq!(
            first_version_token("dnsmasq --version, version 2.90"),
            Some("2.90".to_string())
        );
        assert_eq!(
            first_version_token("kea-dhcp4 2.4.1 (Kea source)"),
            Some("2.4.1".to_string())
        );
    }

    #[test]
    fn skips_leading_non_version_numbers() {
        // A single lone integer (e.g. a build number) is not a version.
        assert_eq!(
            first_version_token("build 12345, unbound 1.19.3"),
            Some("1.19.3".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_version_token_present() {
        assert_eq!(first_version_token("no version here"), None);
        assert_eq!(first_version_token(""), None);
        assert_eq!(first_version_token("only 1 digit group"), None);
    }

    #[test]
    fn stops_patch_at_trailing_dot_with_no_digits() {
        assert_eq!(first_version_token("version 1.2."), Some("1.2".to_string()));
    }
}
