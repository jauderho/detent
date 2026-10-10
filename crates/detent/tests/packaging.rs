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

/// systemd warns at every start when `ConfigurationDirectoryMode` (default
/// 0755) differs from the mode `tmpfiles.d` gave `/etc/detent`.
#[test]
fn the_configuration_directory_mode_matches_tmpfiles() -> Result<(), &'static str> {
    let (mode, _, _) = tmpfiles_dir("/etc/detent").ok_or("tmpfiles.d does not make /etc/detent")?;
    if unit_value("ConfigurationDirectory").is_some() {
        assert_eq!(
            unit_value("ConfigurationDirectoryMode"),
            Some(mode.as_str())
        );
    }
    Ok(())
}

/// systemd 261 (testhost, Ubuntu) removes `CAP_SETUID` from a root service that
/// has `NoNewPrivileges=yes` and any seccomp-based directive, even when the
/// bounding set lists it; the monitor then cannot drop the worker to its
/// account (`setuid` gives `EPERM`). `AmbientCapabilities=` keeps
/// `CAP_SETUID`/`CAP_SETGID` through that exec (Track C A2).
#[test]
fn the_unit_keeps_setuid_for_the_worker_drop() {
    let bounding: Vec<&str> = UNIT
        .lines()
        .filter_map(|line| line.trim().strip_prefix("CapabilityBoundingSet="))
        .flat_map(str::split_whitespace)
        .collect();
    if unit_value("NoNewPrivileges") == Some("yes")
        && unit_value("SystemCallFilter").is_some()
        && bounding.contains(&"CAP_SETUID")
    {
        let ambient: Vec<&str> = unit_value("AmbientCapabilities")
            .map(|caps| caps.split_whitespace().collect())
            .unwrap_or_default();
        assert!(
            ambient.contains(&"CAP_SETUID") && ambient.contains(&"CAP_SETGID"),
            "AmbientCapabilities lacks CAP_SETUID/CAP_SETGID: {ambient:?}"
        );
    }
}

const POLKIT_RULE: &str = include_str!("../../../packaging/polkit/50-detent.rules");

/// The rule's code, without its comment lines.
fn polkit_code() -> String {
    POLKIT_RULE
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every double-quoted string on `line`.
fn quoted(line: &str) -> Vec<String> {
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The lines of the rule after the line holding `start`, up to the line that
/// closes it.
fn polkit_block(start: &str) -> Vec<String> {
    polkit_code()
        .lines()
        .skip_while(|line| !line.contains(start))
        .skip(1)
        .take_while(|line| {
            let line = line.trim_start();
            !line.starts_with(']') && !line.starts_with('}')
        })
        .map(str::to_owned)
        .collect()
}

/// `UNIT_VERBS`: unit -> verbs, as the rule grants them.
fn polkit_unit_verbs() -> std::collections::BTreeMap<String, Vec<String>> {
    polkit_block("var UNIT_VERBS = {")
        .iter()
        .filter_map(|line| {
            let mut strings = quoted(line).into_iter();
            let unit = strings.next()?;
            let mut verbs: Vec<String> = strings.collect();
            verbs.sort();
            Some((unit, verbs))
        })
        .collect()
}

/// The `systemctl` verb of a module's service action (the same mapping as
/// `action_verb` in `detent_platform::service::systemd`).
const fn verb(action: detent_core::descriptor::ServiceAction) -> &'static str {
    use detent_core::descriptor::ServiceAction;
    match action {
        ServiceAction::Restart => "restart",
        ServiceAction::Reload => "reload",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
    }
}

/// The unit -> verbs map the compiled modules' service bindings need.
fn module_unit_verbs() -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for module in detent_modules::modules() {
        for binding in module.descriptor().services {
            for unit in binding.units.systemd {
                let verbs = map.entry((*unit).to_owned()).or_default();
                verbs.extend(
                    binding
                        .actions
                        .iter()
                        .map(|action| verb(*action).to_owned()),
                );
                verbs.sort();
                verbs.dedup();
            }
        }
    }
    map
}

/// Capability-user mode: the runner's `systemctl` goes through polkit. Each
/// unit a compiled module binds must be granted with exactly the verbs its
/// binding allows: a missing unit makes the service action fail, an extra
/// verb grants more than detent ever asks for.
#[test]
fn the_polkit_rule_grants_each_module_unit_its_binding_verbs() {
    let granted = polkit_unit_verbs();
    for (unit, verbs) in module_unit_verbs() {
        assert_eq!(granted.get(&unit), Some(&verbs), "{unit}");
    }
}

/// With every module compiled in, the rule grants no unit that no module
/// binds.
#[cfg(all(
    feature = "module-resolver",
    feature = "module-chrony",
    feature = "module-mounts",
    feature = "module-nfs",
    feature = "module-samba",
    feature = "module-dhcp",
    feature = "module-network"
))]
#[test]
fn the_polkit_rule_grants_no_unit_that_no_module_binds() {
    assert_eq!(polkit_unit_verbs(), module_unit_verbs());
}

/// The rule names only the two systemd actions detent needs, and never
/// grants the update unit: polkit sees only the name of a transient unit,
/// not what it runs.
#[test]
fn the_polkit_rule_handles_only_two_actions_and_not_the_update_unit() {
    let code = polkit_code();
    let actions: Vec<String> = code
        .lines()
        .flat_map(quoted)
        .filter(|text| text.starts_with("org.freedesktop."))
        .collect();
    assert_eq!(
        actions,
        [
            "org.freedesktop.systemd1.reload-daemon",
            "org.freedesktop.systemd1.manage-units"
        ]
    );
    assert!(
        !code.contains("detent-update"),
        "the update unit is granted"
    );
    assert!(code.contains("subject.user != \"detent\""));
    assert!(code.contains("(verb == \"start\" || verb == \"stop\")"));
}

/// The mount units the rule refuses are the ones over the paths the runner
/// protects (`privsep::mounts`: `/etc`, `/usr`, `/boot`, the state root, the
/// binary directory and every ancestor of them), for the packaged state root
/// and binary directory. `/` itself: the pattern refuses a leading `-`.
#[test]
fn the_polkit_rule_protects_the_mount_points_the_runner_protects() {
    let mut expected = Vec::new();
    for path in ["/etc", "/usr", "/boot", "/var/lib/detent", "/usr/local/bin"] {
        for ancestor in std::path::Path::new(path).ancestors() {
            let name = ancestor
                .to_string_lossy()
                .trim_start_matches('/')
                .replace('/', "-");
            if !name.is_empty() {
                expected.push(format!("{name}.mount"));
                expected.push(format!("{name}.automount"));
            }
        }
    }
    expected.sort();
    expected.dedup();
    let mut refused: Vec<String> = polkit_block("var PROTECTED_MOUNT_UNITS = [")
        .iter()
        .flat_map(|line| quoted(line))
        .collect();
    refused.sort();
    assert_eq!(refused, expected);
    assert!(
        polkit_code().contains(
            r"var MOUNT_UNIT = /^[A-Za-z0-9:_.\\][A-Za-z0-9:_.\\-]*\.(mount|automount)$/;"
        )
    );
}

/// `packaging/install.sh`, from the repository root.
const INSTALL_SH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/install.sh");

/// Where `install.sh` puts the capability-user drop-in and the polkit rule.
const DROPIN: &str = "etc/systemd/system/detent.service.d/capability-user.conf";
const POLKIT: &str = "etc/polkit-1/rules.d/50-detent.rules";
/// Every file `install.sh` may place.
const INSTALLED: &[&str] = &[
    "usr/local/bin/detent",
    "etc/systemd/system/detent.service",
    "etc/sysusers.d/detent.conf",
    "etc/tmpfiles.d/detent.conf",
    DROPIN,
    POLKIT,
];

/// Run `install.sh` with `args` (no color); its status and stdout.
fn install_sh(args: &[&str]) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("bash")
        .arg(INSTALL_SH)
        .args(args)
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        output.status.success(),
        String::from_utf8(output.stdout)? + &String::from_utf8(output.stderr)?,
    ))
}

/// A stand-in for the binary, for `--binary`.
fn fake_binary(dir: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let path = dir.join("detent");
    std::fs::write(&path, b"#!/bin/sh\n")?;
    Ok(path.to_string_lossy().into_owned())
}

/// Capability-user mode needs the drop-in and the polkit rule, and the
/// operator must set the same mode in `detent.toml`.
#[test]
fn install_dryrun_in_capability_user_mode_installs_the_drop_in_and_the_rule()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::TempDir::new()?;
    let binary = fake_binary(dir.path())?;
    let (ok, text) = install_sh(&["--dryrun", "--mode", "capability-user", "--binary", &binary])?;
    assert!(ok, "{text}");
    assert!(text.contains(&format!("installing {DROPIN}")), "{text}");
    assert!(text.contains(&format!("installing {POLKIT}")), "{text}");
    assert!(
        text.contains("[privilege] mode = \"capability-user\""),
        "{text}"
    );
    Ok(())
}

/// A root-confined monitor never asks polkit: the rule is not installed.
#[test]
fn install_dryrun_in_root_confined_mode_installs_no_polkit_rule()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::TempDir::new()?;
    let binary = fake_binary(dir.path())?;
    let (ok, text) = install_sh(&["--dryrun", "--binary", &binary])?;
    assert!(ok, "{text}");
    assert!(
        text.contains("installing etc/systemd/system/detent.service"),
        "{text}"
    );
    assert!(!text.contains(&format!("installing {POLKIT}")), "{text}");
    assert!(!text.contains(&format!("installing {DROPIN}")), "{text}");
    assert!(!text.contains("[privilege]"), "{text}");
    Ok(())
}

#[test]
fn install_refuses_an_unknown_mode() -> Result<(), Box<dyn std::error::Error>> {
    let (ok, text) = install_sh(&["--dryrun", "--mode", "capability_user"])?;
    assert!(!ok, "{text}");
    assert!(text.contains("--mode must be"), "{text}");
    Ok(())
}

/// Under `--prefix`: a capability-user install places the drop-in and the
/// rule, a root-confined install over it removes both and keeps the rest,
/// and `--uninstall` removes everything.
#[test]
fn install_prefix_switches_modes_and_uninstalls() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::TempDir::new()?;
    let binary = fake_binary(dir.path())?;
    let root = dir.path().join("root");
    let prefix = root.to_string_lossy().into_owned();
    let present = |rel: &str| root.join(rel).exists();

    let (ok, text) = install_sh(&[
        "--prefix",
        &prefix,
        "--mode",
        "capability-user",
        "--binary",
        &binary,
    ])?;
    assert!(ok, "{text}");
    for rel in INSTALLED {
        assert!(
            present(rel),
            "{rel} missing after a capability-user install"
        );
    }
    assert_eq!(
        std::fs::read_to_string(root.join(POLKIT))?,
        POLKIT_RULE,
        "the installed rule is not the packaged one"
    );

    let (ok, text) = install_sh(&["--prefix", &prefix, "--binary", &binary])?;
    assert!(ok, "{text}");
    assert!(!present(DROPIN), "{text}");
    assert!(!present(POLKIT), "{text}");
    assert!(present("etc/systemd/system/detent.service"), "{text}");

    let (ok, text) = install_sh(&["--prefix", &prefix, "--uninstall"])?;
    assert!(ok, "{text}");
    for rel in INSTALLED {
        assert!(!present(rel), "{rel} left after --uninstall");
    }
    Ok(())
}

/// `--uninstall` stops and disables the service before any file is removed:
/// a monitor left running would keep the old binary alive past its removal.
#[test]
fn uninstall_dryrun_stops_the_service_before_removing_files()
-> Result<(), Box<dyn std::error::Error>> {
    let (ok, text) = install_sh(&["--dryrun", "--verbose", "--uninstall"])?;
    assert!(ok, "{text}");
    let stop = text
        .find("systemctl disable --now detent.service")
        .ok_or_else(|| format!("no stop step: {text}"))?;
    let first_removal = ["rm -f", "already absent:", "removing "]
        .iter()
        .filter_map(|needle| text.find(needle))
        .min();
    assert!(
        first_removal.is_some_and(|at| at > stop),
        "the stop step must come before the first file removal: {text}"
    );
    Ok(())
}

/// `--uninstall` removes the drop-in directory once it is empty, and keeps it
/// while another file is in it (`rmdir`, never a recursive delete).
#[test]
fn uninstall_under_prefix_removes_an_empty_drop_in_dir_and_keeps_a_used_one()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::TempDir::new()?;
    let binary = fake_binary(dir.path())?;
    let root = dir.path().join("root");
    let prefix = root.to_string_lossy().into_owned();
    let dropin_dir = root.join("etc/systemd/system/detent.service.d");

    let (ok, text) = install_sh(&[
        "--prefix",
        &prefix,
        "--mode",
        "capability-user",
        "--binary",
        &binary,
    ])?;
    assert!(ok, "{text}");
    let (ok, text) = install_sh(&["--prefix", &prefix, "--uninstall"])?;
    assert!(ok, "{text}");
    assert!(!dropin_dir.exists(), "empty drop-in dir left: {text}");

    std::fs::create_dir_all(&dropin_dir)?;
    std::fs::write(dropin_dir.join("local.conf"), b"")?;
    let (ok, text) = install_sh(&["--prefix", &prefix, "--uninstall"])?;
    assert!(ok, "{text}");
    assert!(
        dropin_dir.join("local.conf").exists(),
        "a file outside the packaging was removed: {text}"
    );
    Ok(())
}
