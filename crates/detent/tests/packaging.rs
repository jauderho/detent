//! The packaged systemd unit (`packaging/systemd/detent.service`).
//!
//! systemd refuses to start a unit whose `ReadWritePaths` names a path that
//! does not exist (`226/NAMESPACE`), unless the entry carries a `-` prefix.
//! Track C A2 found this on Ubuntu, which has `/etc/chrony/` and no
//! `/etc/chrony.conf`.

const UNIT: &str = include_str!("../../../packaging/systemd/detent.service");

/// Paths every supported host has, or that the unit makes itself
/// (`StateDirectory`, `RuntimeDirectory` and `tmpfiles.d`).
const ALWAYS_PRESENT: &[&str] = &[
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/fstab",
    "/var/lib/detent",
    "/run/detent/staging",
];

/// The entries of every `ReadWritePaths=` line, with `\` continuations joined.
fn read_write_paths() -> Vec<String> {
    let joined = UNIT.replace("\\\n", " ");
    joined
        .lines()
        .filter_map(|line| line.trim().strip_prefix("ReadWritePaths="))
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_module_path_in_read_write_paths_is_optional() {
    let paths = read_write_paths();
    assert!(paths.len() > ALWAYS_PRESENT.len(), "{paths:?}");
    let required: Vec<&String> = paths
        .iter()
        .filter(|path| !path.starts_with('-') && !ALWAYS_PRESENT.contains(&path.as_str()))
        .collect();
    assert!(
        required.is_empty(),
        "these paths stop the unit on a host that lacks them: {required:?}"
    );
}
