//! Key=value parser for `/etc/os-release` (`os-release(5)`).

use std::collections::BTreeMap;

/// Parse the contents of an os-release file into a key/value map.
///
/// Handles blank lines, `#` comments, unquoted values, single-quoted values
/// (literal, no escapes) and double-quoted values (backslash escapes for
/// `\\`, `\"`, `\$`, `` \` ``).
#[must_use]
pub(super) fn parse(contents: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        out.insert(key.to_string(), unquote(raw_value.trim()));
    }
    out
}

fn unquote(raw: &str) -> String {
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.to_string();
    }
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return unescape_double_quoted(inner);
    }
    raw.to_string()
}

fn unescape_double_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next @ ('\\' | '"' | '$' | '`')) => out.push(next),
                // A trailing lone backslash (unterminated escape): drop it.
                // A literal embedded newline can't occur here since `parse`
                // splits `contents` into lines before unescaping a value.
                None => {}
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unquoted_and_double_quoted_values() {
        let map = parse("ID=debian\nNAME=\"Debian GNU/Linux\"\n");
        assert_eq!(map.get("ID").map(String::as_str), Some("debian"));
        assert_eq!(
            map.get("NAME").map(String::as_str),
            Some("Debian GNU/Linux")
        );
    }

    #[test]
    fn parses_single_quoted_literal_value() {
        let map = parse("PRETTY_NAME='Arch\\Linux'\n");
        assert_eq!(
            map.get("PRETTY_NAME").map(String::as_str),
            Some("Arch\\Linux")
        );
    }

    #[test]
    fn unescapes_double_quoted_backslash_sequences() {
        let map = parse(r#"NAME="Quote \" Slash \\ Dollar \$ Tick \` Newline\\next Kept \x""#);
        assert_eq!(
            map.get("NAME").map(String::as_str),
            Some("Quote \" Slash \\ Dollar $ Tick ` Newline\\next Kept \\x")
        );
    }

    #[test]
    fn drops_trailing_lone_backslash_in_double_quoted_value() {
        let map = parse(r#"NAME="abc\""#);
        assert_eq!(map.get("NAME").map(String::as_str), Some("abc"));
    }

    #[test]
    fn skips_blank_lines_comments_and_malformed_lines() {
        let map = parse("\n# comment\nno-equals-sign\n=novalue\nID=alpine\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("ID").map(String::as_str), Some("alpine"));
    }

    #[test]
    fn empty_input_yields_empty_map() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn unterminated_quote_is_kept_literal() {
        let map = parse("ID=\"unterminated\n");
        assert_eq!(map.get("ID").map(String::as_str), Some("\"unterminated"));
    }
}
