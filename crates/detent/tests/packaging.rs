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

/// systemd removes `RuntimeDirectory=` on stop and makes it again on start;
/// `tmpfiles.d` runs only at boot or install. A `/run` path the unit needs
/// must therefore be one of its runtime directories, or `Restart=always`
/// fails at `226/NAMESPACE` (Track C A2).
#[test]
fn every_run_path_is_a_runtime_directory() {
    let joined = UNIT.replace("\\\n", " ");
    let runtime: Vec<String> = joined
        .lines()
        .filter_map(|line| line.trim().strip_prefix("RuntimeDirectory="))
        .flat_map(str::split_whitespace)
        .map(|dir| format!("/run/{dir}"))
        .collect();
    let missing: Vec<String> = read_write_paths()
        .into_iter()
        .map(|path| path.trim_start_matches('-').to_owned())
        .filter(|path| path.starts_with("/run/") && !runtime.contains(path))
        .collect();
    assert!(missing.is_empty(), "not made on restart: {missing:?}");
}
