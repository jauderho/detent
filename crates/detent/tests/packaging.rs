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

/// What `Policy::monitor` keeps (`crates/detent-platform/src/sandbox/mod.rs`).
const MONITOR_KEEPS: &[&str] = &["CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER"];

/// `PR_CAPBSET_DROP` needs `CAP_SETPCAP`. When the unit's bounding set holds
/// more than the monitor keeps, the monitor must drop the rest, so the unit
/// must grant `CAP_SETPCAP` too; without it `serve` fails with
/// `PR_CAPBSET_DROP failure: Operation not permitted` (Track C A2).
#[test]
fn the_bounding_set_lets_the_monitor_drop_what_it_does_not_keep() {
    let caps: Vec<&str> = UNIT
        .lines()
        .filter_map(|line| line.trim().strip_prefix("CapabilityBoundingSet="))
        .flat_map(str::split_whitespace)
        .collect();
    let extra: Vec<&&str> = caps
        .iter()
        .filter(|cap| !MONITOR_KEEPS.contains(cap) && **cap != "CAP_SETPCAP")
        .collect();
    assert!(
        extra.is_empty() || caps.contains(&"CAP_SETPCAP"),
        "the monitor cannot drop {extra:?} without CAP_SETPCAP"
    );
}

const TMPFILES: &str = include_str!("../../../packaging/tmpfiles.d/detent.conf");

/// `(mode, user, group)` of a `d` line in `tmpfiles.d/detent.conf`.
fn tmpfiles_dir(path: &str) -> Option<(String, String, String)> {
    TMPFILES.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["d", p, mode, user, group, ..] if *p == path => {
                Some(((*mode).to_owned(), (*user).to_owned(), (*group).to_owned()))
            }
            _ => None,
        }
    })
}

fn unit_value(key: &str) -> Option<&'static str> {
    UNIT.lines()
        .find_map(|line| line.trim().strip_prefix(key)?.strip_prefix('='))
}

/// `StateDirectory=` chowns the directory to the unit's `User=` on every
/// start, which undid `tmpfiles.d`'s `detent:detent` and locked the worker
/// out of its state root (Track C A2: the worker exited 1 at once).
#[test]
fn the_unit_does_not_take_the_state_root_from_the_worker() -> Result<(), &'static str> {
    let (_, owner, _) =
        tmpfiles_dir("/var/lib/detent").ok_or("tmpfiles.d does not make /var/lib/detent")?;
    if owner != unit_value("User").unwrap_or("root") {
        assert_eq!(unit_value("StateDirectory"), None);
    }
    Ok(())
}
