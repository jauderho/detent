//! Finds the locales under `locales/`. Shared by `build.rs`, which generates the
//! catalogue from the result, and by the unit tests, which check the rules
//! against fixture directories.

use std::fs;
use std::path::Path;

/// The `.ftl` files every shipped locale directory must hold.
pub const REQUIRED_FILES: [&str; 3] = ["core.ftl", "web.ftl", "cli.ftl"];

/// The locale that defines every message id and is the last fallback.
pub const SOURCE_LOCALE: &str = "en-US";

/// A directory name that starts with this prefix is a pseudo-locale. It is a
/// test fixture, generated or partial, and is never compiled in.
const PSEUDO_PREFIX: &str = "qps-";

/// Whether `name` is a pseudo-locale directory (`qps-ploc`).
pub fn is_pseudo(name: &str) -> bool {
    name.starts_with(PSEUDO_PREFIX)
}

/// Whether `name` is a plain BCP 47 tag of the shape `ll-RR`, `ll-Ssss` or
/// `ll-Ssss-RR`: only ASCII letters and digits, split by single hyphens.
pub fn is_tag(name: &str) -> bool {
    let mut parts = name.split('-');
    let language_ok = parts
        .next()
        .is_some_and(|p| (2..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase()));
    language_ok
        && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The locale tags under `dir`, sorted, with a pseudo-locale left out.
///
/// Each remaining directory must hold every file in [`REQUIRED_FILES`], and
/// `en-US` must be one of them. A violation is an error text that names the
/// path, so a translator sees the fix in the build log.
pub fn scan(dir: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut tags = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // A name that is not UTF-8 gets U+FFFD here and so fails `is_tag`.
        let name = entry.file_name();
        let name = &*name.to_string_lossy();
        if name.starts_with('.') || is_pseudo(name) {
            continue;
        }
        if !is_tag(name) {
            return Err(format!(
                "{}: the directory name must be a language tag such as de-DE",
                path.display()
            ));
        }
        for file in REQUIRED_FILES {
            if !path.join(file).is_file() {
                return Err(format!(
                    "{}: missing {file} (each locale needs {})",
                    path.display(),
                    REQUIRED_FILES.join(", ")
                ));
            }
        }
        tags.push(name.to_owned());
    }
    if !tags.iter().any(|t| t == SOURCE_LOCALE) {
        return Err(format!(
            "{}: missing the {SOURCE_LOCALE} directory",
            dir.display()
        ));
    }
    tags.sort();
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_FILES, SOURCE_LOCALE, is_pseudo, is_tag, scan};
    use std::fs;
    use std::path::Path;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn locale(root: &Path, tag: &str, files: &[&str]) -> R {
        let dir = root.join(tag);
        fs::create_dir_all(&dir)?;
        for file in files {
            fs::write(dir.join(file), "hello = hi\n")?;
        }
        Ok(())
    }

    #[test]
    fn tags_and_pseudo_locales_are_told_apart() {
        for tag in [
            "en-US",
            "de-DE",
            "zh-TW",
            "hi-IN",
            "sr-Latn-RS",
            "es-419",
            "fil",
        ] {
            assert!(is_tag(tag), "{tag}");
        }
        for tag in [
            "", "en_US", "EN-us", "e-US", "english", "de-", "-DE", "de--DE", "de-D", "de-D/E",
        ] {
            assert!(!is_tag(tag), "{tag:?}");
        }
        assert!(is_pseudo("qps-ploc"));
        assert!(!is_pseudo("en-US"));
    }

    #[test]
    fn a_new_directory_with_all_files_is_picked_up() -> R {
        let root = tempfile::tempdir()?;
        locale(root.path(), SOURCE_LOCALE, &REQUIRED_FILES)?;
        locale(root.path(), "xx-YY", &REQUIRED_FILES)?;
        locale(root.path(), "de-DE", &REQUIRED_FILES)?;
        assert_eq!(scan(root.path())?, ["de-DE", "en-US", "xx-YY"]);
        Ok(())
    }

    #[test]
    fn pseudo_hidden_and_plain_files_are_left_out() -> R {
        let root = tempfile::tempdir()?;
        locale(root.path(), SOURCE_LOCALE, &REQUIRED_FILES)?;
        locale(root.path(), "qps-ploc", &["web.ftl"])?;
        locale(root.path(), ".git", &[])?;
        fs::write(root.path().join("README.md"), "not a locale")?;
        assert_eq!(scan(root.path())?, [SOURCE_LOCALE]);
        Ok(())
    }

    #[test]
    fn a_locale_with_a_missing_file_is_an_error_that_names_the_file() -> R {
        for missing in REQUIRED_FILES {
            let root = tempfile::tempdir()?;
            locale(root.path(), SOURCE_LOCALE, &REQUIRED_FILES)?;
            let have: Vec<&str> = REQUIRED_FILES
                .into_iter()
                .filter(|f| *f != missing)
                .collect();
            locale(root.path(), "fr-FR", &have)?;
            let error = scan(root.path())
                .err()
                .ok_or("a partial locale was accepted")?;
            assert!(
                error.contains("fr-FR") && error.contains(missing),
                "{error}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_badly_named_directory_is_an_error() -> R {
        let root = tempfile::tempdir()?;
        locale(root.path(), SOURCE_LOCALE, &REQUIRED_FILES)?;
        locale(root.path(), "French", &REQUIRED_FILES)?;
        let error = scan(root.path()).err().ok_or("a bad name was accepted")?;
        assert!(error.contains("French"), "{error}");
        Ok(())
    }

    #[test]
    fn the_source_locale_is_required() -> R {
        let root = tempfile::tempdir()?;
        locale(root.path(), "de-DE", &REQUIRED_FILES)?;
        let error = scan(root.path()).err().ok_or("no en-US was accepted")?;
        assert!(error.contains(SOURCE_LOCALE), "{error}");
        Ok(())
    }

    #[test]
    fn an_unreadable_directory_is_an_error() -> R {
        let root = tempfile::tempdir()?;
        let missing = root.path().join("nope");
        assert!(scan(&missing).is_err());
        Ok(())
    }
}
