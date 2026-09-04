//! In-memory [`HostFs`] and [`Prober`] fakes shared by this crate's unit
//! tests. Not part of the public API: integration tests under
//! `tests/host_*.rs` define their own, since they can only see `pub` items.

#![cfg(test)]

use std::collections::HashMap;

use super::io::HostFs;
use super::prober::{ProbeError, Prober};

/// An in-memory [`HostFs`]: files and symlinks are entries in `files` /
/// `links`; directory listings are derived from the file/link paths that
/// live directly under a given directory.
#[derive(Default)]
pub(crate) struct FakeFs {
    files: HashMap<String, String>,
    links: HashMap<String, String>,
    dirs: std::collections::HashSet<String>,
}

impl FakeFs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_file(mut self, path: &str, contents: &str) -> Self {
        self.files.insert(path.to_string(), contents.to_string());
        self
    }

    pub(crate) fn with_link(mut self, path: &str, target: &str) -> Self {
        self.links.insert(path.to_string(), target.to_string());
        self
    }

    /// Marks `path` as an existing (empty) directory, e.g. one that exists
    /// but currently has no matching glob entries.
    pub(crate) fn with_dir(mut self, path: &str) -> Self {
        self.dirs.insert(path.to_string());
        self
    }
}

impl HostFs for FakeFs {
    fn read_to_string(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    fn exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.links.contains_key(path) || self.dirs.contains(path)
    }

    fn read_link(&self, path: &str) -> Option<String> {
        self.links.get(path).cloned()
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        self.files
            .keys()
            .chain(self.links.keys())
            .filter_map(|full| full.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(str::to_string)
            .collect()
    }
}

/// An in-memory [`Prober`]: maps `(program, args)` to a canned result,
/// defaulting to [`ProbeError::Spawn`] for unconfigured commands.
#[derive(Default)]
pub(crate) struct FakeProber {
    responses: HashMap<(String, Vec<String>), Result<String, ProbeError>>,
}

impl FakeProber {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with(
        mut self,
        program: &str,
        args: &[&str],
        result: Result<&str, ProbeError>,
    ) -> Self {
        let key = key_for(program, args);
        self.responses
            .insert(key, result.map(std::string::ToString::to_string));
        self
    }
}

impl Prober for FakeProber {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, ProbeError> {
        let key = key_for(program, args);
        self.responses
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Err(ProbeError::Spawn("no fake response configured".to_string())))
    }
}

fn key_for(program: &str, args: &[&str]) -> (String, Vec<String>) {
    (
        program.to_string(),
        args.iter().map(|a| (*a).to_string()).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_fs_lists_only_direct_children() {
        let fs = FakeFs::new()
            .with_file("/etc/netplan/01.yaml", "")
            .with_file("/etc/netplan/nested/skip.yaml", "")
            .with_dir("/etc/empty");
        let mut names = fs.list_dir("/etc/netplan");
        names.sort();
        assert_eq!(names, vec!["01.yaml".to_string()]);
        assert!(fs.list_dir("/etc/empty").is_empty());
        assert!(fs.exists("/etc/empty"));
        assert!(!fs.exists("/etc/missing"));
    }

    #[test]
    fn fake_fs_reads_files_and_links() {
        let fs = FakeFs::new()
            .with_file("/etc/hostname", "box\n")
            .with_link("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
        assert_eq!(fs.read_to_string("/etc/hostname").as_deref(), Some("box\n"));
        assert_eq!(
            fs.read_link("/etc/resolv.conf").as_deref(),
            Some("/run/systemd/resolve/stub-resolv.conf")
        );
        assert_eq!(fs.read_link("/etc/hostname"), None);
    }
}
