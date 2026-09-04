//! Filesystem trait used by host detection so every branch can be tested
//! against an in-memory fake instead of the real filesystem.

use std::fs;
use std::path::Path;

/// Filesystem operations needed for host detection.
///
/// Every detection branch reads through this trait (rather than `std::fs`
/// directly) so it can be exercised with an in-memory fake in tests.
pub trait HostFs {
    /// Read `path` fully as UTF-8, or `None` if it can't be read (missing,
    /// not a regular file, not valid UTF-8, permission denied, ...).
    fn read_to_string(&self, path: &str) -> Option<String>;
    /// Whether `path` exists (following symlinks).
    fn exists(&self, path: &str) -> bool;
    /// The raw target of the symlink at `path`, or `None` if `path` isn't a
    /// symlink or doesn't exist.
    fn read_link(&self, path: &str) -> Option<String>;
    /// File and directory names directly inside `path` (base names, not
    /// full paths), or empty if `path` isn't a readable directory.
    fn list_dir(&self, path: &str) -> Vec<String>;
}

/// [`HostFs`] backed by the real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl HostFs for RealFs {
    fn read_to_string(&self, path: &str) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn read_link(&self, path: &str) -> Option<String> {
        fs::read_link(path)
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        let Ok(entries) = fs::read_dir(path) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn real_fs_reads_written_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("f.txt");
        let mut handle = std::fs::File::create(&file)?;
        write!(handle, "hello")?;
        drop(handle);

        let fs = RealFs;
        let path = file.to_string_lossy().into_owned();
        assert_eq!(fs.read_to_string(&path).as_deref(), Some("hello"));
        assert!(fs.exists(&path));
        assert!(!fs.exists(&format!("{path}.missing")));
        Ok(())
    }

    #[test]
    fn real_fs_missing_file_returns_none() {
        let fs = RealFs;
        assert_eq!(
            fs.read_to_string("/nonexistent/path/for/detent/tests"),
            None
        );
        assert_eq!(fs.read_link("/nonexistent/path/for/detent/tests"), None);
        assert!(fs.list_dir("/nonexistent/path/for/detent/tests").is_empty());
    }

    #[test]
    fn real_fs_lists_dir_and_reads_symlink() -> TestResult {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("a.txt"), b"a")?;
        std::fs::write(dir.path().join("b.txt"), b"b")?;

        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("a.txt"), &link)?;

        let fs = RealFs;
        let mut names = fs.list_dir(&dir.path().to_string_lossy());
        names.sort();
        assert_eq!(
            names,
            vec!["a.txt".to_string(), "b.txt".to_string(), "link".to_string()]
        );

        let target = fs.read_link(&link.to_string_lossy());
        assert!(target.is_some_and(|t| t.ends_with("a.txt")));
        Ok(())
    }
}
