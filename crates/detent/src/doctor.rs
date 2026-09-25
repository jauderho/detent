//! `detent doctor`: what this host is, what this build can do, and what is
//! misconfigured.
//!
//! Every check reports one of three statuses. Only [`Status::Fail`] changes the
//! exit code, because `doctor` must be safe to run on a healthy box that simply
//! has not been set up yet: a state directory that does not exist is created on
//! first write, and a missing `detent.toml` means "defaults apply", so both are
//! notes rather than faults.
//!
//! # The two probes that touch the system
//!
//! * **privsep** really forks a pair ([`spawn_pair`]) with no worker account and
//!   no sandbox, completes the handshake and shuts it down. Nothing else proves
//!   the process model works on this kernel.
//! * **confinement** is *not* applied here. On Linux, installing a Landlock
//!   ruleset or a seccomp filter is irreversible for the calling process
//!   (`detent_platform::sandbox`), so `doctor` reads what the kernel advertises
//!   (`/sys/kernel/security/lsm`, `/proc/sys/kernel/seccomp/actions_avail`)
//!   instead of confining itself; `serve` applies it and reports the outcome it
//!   actually got. Off Linux, `sandbox::confine` is a documented no-op, so it is
//!   called and its own reporting types are rendered — which say `linux only`.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use detent_core::diag::MessageId;
use detent_ops::report::HostReport;
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{ExitReason, Hooks, Monitor, MonitorError};
use detent_platform::privsep::spawn::{NoSandbox, Role, SpawnConfig, abort_child, spawn_pair};
use serde::Serialize;

use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams};

/// Group/other write bits: a genuine misconfiguration on anything detent owns.
const WRITABLE_BY_OTHERS: u32 = 0o022;
/// Group/other read bits: worth mentioning, not a fault.
const READABLE_BY_OTHERS: u32 = 0o044;

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// As it should be.
    Ok,
    /// Worth knowing, not a fault.
    Warn,
    /// A genuine misconfiguration; `doctor` exits non-zero.
    Fail,
}

impl Status {
    /// The Fluent id of the status word.
    const fn message(self) -> MessageId {
        match self {
            Self::Ok => MessageId::new("cli-status-ok"),
            Self::Warn => MessageId::new("cli-status-warn"),
            Self::Fail => MessageId::new("cli-status-fail"),
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable name, and the suffix of its `cli-doctor-…` message id.
    pub name: &'static str,
    /// How it came out.
    pub status: Status,
    /// The identifiers and values the message interpolates.
    pub detail: String,
}

impl Check {
    /// A check with a rendered detail string.
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }

    /// The Fluent id of this check's sentence.
    fn message(&self) -> MessageId {
        match self.name {
            "modules" => MessageId::new("cli-doctor-modules"),
            "state-root" => MessageId::new("cli-doctor-state-root"),
            "config" => MessageId::new("cli-doctor-config"),
            "privsep" => MessageId::new("cli-doctor-privsep"),
            "landlock" => MessageId::new("cli-doctor-landlock"),
            "seccomp" => MessageId::new("cli-doctor-seccomp"),
            _ => MessageId::new("cli-doctor-confinement"),
        }
    }
}

/// The whole report, as `--json` serializes it.
#[derive(Debug, Serialize)]
struct Report {
    /// What was detected about this host.
    host: HostReport,
    /// Every check, in the order they ran.
    checks: Vec<Check>,
    /// False when any check failed.
    ok: bool,
}

/// Runs every check and renders the report.
///
/// # Errors
///
/// Whatever the streams report.
pub fn report(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let host = detent_platform::host::detect_real();
    let registry = detent_modules::modules();
    let descriptors: Vec<_> = registry.iter().map(|entry| entry.descriptor()).collect();

    // The privsep probe forks; anything already buffered must not be inherited
    // by a child that exits without flushing.
    streams.out.flush()?;
    streams.notes.flush()?;

    let mut checks = vec![
        modules_check(&descriptors),
        directory_check(&settings.state_root),
        config_check(&settings.config_path),
        privsep_check(&settings.state_root),
    ];
    checks.extend(confinement_checks(&descriptors, &settings.state_root));
    let ok = !checks.iter().any(|check| check.status == Status::Fail);

    if renderer.json {
        let text = serde_json::to_string_pretty(&Report {
            host: HostReport::from(&host),
            checks,
            ok,
        })
        .map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.host(streams.out, &host.profile)?;
        for check in &checks {
            let status = renderer.messages.get(check.status.message());
            let sentence = renderer
                .messages
                .format(check.message(), &[("detail", &check.detail)]);
            writeln!(streams.out, "{status} {sentence}")?;
        }
    }
    Ok(if ok { Exit::Ok } else { Exit::Failed })
}

/// Which modules this build was compiled with (PLAN §2.2).
fn modules_check(descriptors: &[&'static detent_core::descriptor::ModuleDescriptor]) -> Check {
    let ids: Vec<&str> = descriptors.iter().map(|entry| entry.id).collect();
    if ids.is_empty() {
        return Check::new("modules", Status::Warn, "none");
    }
    Check::new("modules", Status::Ok, ids.join(" "))
}

/// The state directory: present, a directory, safely owned, and not writable
/// by anyone else (PLAN §2.10 makes it `0700`).
fn directory_check(path: &Path) -> Check {
    let detail = path.display().to_string();
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Check::new("state-root", Status::Warn, format!("{detail} (absent)"));
    };
    if meta.file_type().is_symlink() {
        return Check::new(
            "state-root",
            Status::Fail,
            format!("{detail} (symbolic link)"),
        );
    }
    if !meta.is_dir() {
        return Check::new(
            "state-root",
            Status::Fail,
            format!("{detail} (not a directory)"),
        );
    }
    owned_mode_check("state-root", &detail, &meta)
}

/// The configuration file: absent is fine, a symlink or foreign owner is not.
fn config_check(path: &Path) -> Check {
    let detail = path.display().to_string();
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Check::new("config", Status::Warn, format!("{detail} (absent)"));
    };
    if meta.file_type().is_symlink() {
        return Check::new("config", Status::Fail, format!("{detail} (symbolic link)"));
    }
    owned_mode_check("config", &detail, &meta)
}

fn owned_mode_check(name: &'static str, path: &str, meta: &std::fs::Metadata) -> Check {
    let euid = rustix::process::geteuid().as_raw();
    let mode = meta.permissions().mode() & 0o7777;
    let uid = meta.uid();
    let status = if uid != 0 && uid != euid {
        Status::Fail
    } else {
        mode_status(mode)
    };
    Check::new(name, status, format!("{path} (uid {uid}, {mode:04o})"))
}

/// Fail on write access for group or other, warn on read access, otherwise ok.
const fn mode_status(mode: u32) -> Status {
    if mode & WRITABLE_BY_OTHERS != 0 {
        Status::Fail
    } else if mode & READABLE_BY_OTHERS != 0 {
        Status::Warn
    } else {
        Status::Ok
    }
}

/// Turn what the monitor served and what the child exited with into a
/// [`Check`].
///
/// Split out of [`privsep_check`] so the two failure arms are reachable from a
/// test without forking a pair rigged to fail — the same reason
/// `detent_platform::sandbox::seccomp_verdict` is its own function.
fn privsep_verdict(
    served: Result<ExitReason, MonitorError>,
    waited: std::io::Result<Option<i32>>,
    child_pid: i32,
) -> Check {
    match (served, waited) {
        (Ok(ExitReason::Shutdown), Ok(Some(0))) => {
            Check::new("privsep", Status::Ok, format!("pid {child_pid}"))
        }
        (Ok(reason), status) => Check::new(
            "privsep",
            Status::Fail,
            format!("{reason:?} status={status:?}"),
        ),
        (Err(err), _) => Check::new("privsep", Status::Fail, err.to_string()),
    }
}

/// Fork a real pair, shake hands, shut it down.
fn privsep_check(state_root: &Path) -> Check {
    let allow = match Allowlist::from_modules(&[], &Config::with_state_root(state_root)) {
        Ok(allow) => allow,
        Err(err) => return Check::new("privsep", Status::Fail, err.to_string()),
    };
    // No worker account and no sandbox: this probe answers "can this process
    // fork a working pair", not "is the production policy installable".
    let spawned = match spawn_pair(&SpawnConfig::unprivileged(), &NoSandbox) {
        Ok(spawned) => spawned,
        Err(err) => return Check::new("privsep", Status::Fail, err.to_string()),
    };
    match spawned.role {
        Role::Worker(mut client) => {
            // The child never returns: it must not run the parent's exit
            // handlers (`privsep::spawn` documents this contract).
            let ok = client.hello().is_ok() && client.shutdown().is_ok();
            abort_child(i32::from(!ok));
        }
        Role::Monitor(handle) => {
            let mut handle = handle;
            let served = Monitor::new(allow, Hooks::default()).serve(&mut handle.channel);
            let waited = handle.wait();
            privsep_verdict(served, waited, handle.child_pid)
        }
    }
}

/// What the kernel advertises about Landlock and seccomp.
#[cfg(target_os = "linux")]
fn confinement_checks(
    _descriptors: &[&'static detent_core::descriptor::ModuleDescriptor],
    _state_root: &Path,
) -> Vec<Check> {
    vec![
        kernel_feature("landlock", "/sys/kernel/security/lsm", "landlock"),
        kernel_feature("seccomp", "/proc/sys/kernel/seccomp/actions_avail", "errno"),
    ]
}

/// One kernel-advertised feature, read rather than installed.
#[cfg(target_os = "linux")]
fn kernel_feature(name: &'static str, path: &str, needle: &str) -> Check {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.contains(needle) => {
            Check::new(name, Status::Ok, contents.trim().to_owned())
        }
        Ok(contents) => Check::new(name, Status::Warn, contents.trim().to_owned()),
        Err(err) => Check::new(name, Status::Warn, format!("{path}: {err}")),
    }
}

/// Off Linux there is nothing to advertise: `confine` is the documented no-op,
/// and this reports what it says about itself.
#[cfg(not(target_os = "linux"))]
fn confinement_checks(
    descriptors: &[&'static detent_core::descriptor::ModuleDescriptor],
    state_root: &Path,
) -> Vec<Check> {
    use detent_platform::sandbox::{LandlockOutcome, Policy, confine};

    let Ok(allow) = Allowlist::from_modules(descriptors, &Config::with_state_root(state_root))
    else {
        return vec![Check::new("confinement", Status::Warn, "no allow-list")];
    };
    let policy = Policy::worker(&allow);
    let detail = match confine(detent_platform::sandbox::Role::Worker, &policy) {
        Ok(confinement) => match confinement.landlock {
            LandlockOutcome::Applied { abi, .. } => format!("landlock abi {abi}"),
            LandlockOutcome::Unavailable { reason } | LandlockOutcome::Skipped { reason } => reason,
        },
        Err(err) => err.to_string(),
    };
    vec![Check::new("confinement", Status::Warn, detail)]
}
#[cfg(all(test, not(target_os = "linux")))]
mod confinement_tests {
    use super::Status;
    use super::confinement_checks;
    #[test]
    fn a_duplicate_module_id_warns_instead_of_panicking() -> Result<(), String> {
        let descriptor = crate::tests_support::descriptor(std::path::Path::new("/etc/hosts"));
        let checks = confinement_checks(
            &[descriptor, descriptor],
            std::path::Path::new("/tmp/detent-test"),
        );
        let [check] = checks.as_slice() else {
            return Err(format!("one warning, got {checks:?}"));
        };
        assert_eq!(check.status, Status::Warn);
        assert!(check.detail.contains("allow-list"));
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_confinement_tests {
    use super::confinement_checks;
    #[test]
    fn linux_confinement_reports_landlock_and_seccomp() -> Result<(), String> {
        let checks = confinement_checks(&[], std::path::Path::new("/tmp/detent-test"));
        let [first, second] = checks.as_slice() else {
            return Err(format!("landlock plus seccomp, got {checks:?}"));
        };
        assert_eq!(first.name, "landlock");
        assert_eq!(second.name, "seccomp");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Check, ExitReason, MonitorError, Report, Status, config_check, directory_check,
        mode_status, modules_check, privsep_verdict, report,
    };
    use crate::i18n::Messages;
    use crate::output::{Exit, Renderer};
    use crate::run::{Settings, Streams};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn settings(root: &std::path::Path, config: PathBuf) -> Settings {
        Settings {
            state_root: root.to_path_buf(),
            config_path: config,
        }
    }

    fn run(settings: &Settings, json: bool) -> Result<(Exit, String), Box<dyn std::error::Error>> {
        let messages = Messages::new(Some("en-US"));
        let renderer = Renderer {
            messages: &messages,
            json,
            verbose: false,
        };
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = report_io(settings, &renderer, &mut input, &mut out, &mut notes)?;
        Ok((exit, String::from_utf8(out)?))
    }

    /// The `Streams` assembly for [`report`], so the `?` on the report
    /// call itself is reachable: tests feed a failing stream without
    /// forking anything.
    fn report_io(
        settings: &Settings,
        renderer: &Renderer<'_>,
        input: &mut dyn std::io::Read,
        out: &mut dyn std::io::Write,
        notes: &mut dyn std::io::Write,
    ) -> std::io::Result<Exit> {
        report(settings, renderer, &mut Streams { input, out, notes })
    }

    #[test]
    fn doctor_passes_on_a_well_permissioned_host() -> R {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("state");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let config = dir.path().join("detent.toml");
        std::fs::write(&config, b"[listen]\n")?;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640))?;

        let (exit, text) = run(&settings(&root, config), false)?;
        assert_eq!(exit, Exit::Ok, "{text}");
        assert!(text.contains("hosts") || text.contains("modules"), "{text}");
        // Every line resolved to a sentence rather than a bare id.
        assert!(!text.contains("cli-doctor"), "{text}");
        Ok(())
    }

    #[test]
    fn doctor_reports_json_with_a_verdict() -> R {
        let dir = tempfile::TempDir::new()?;
        let (_, text) = run(&settings(dir.path(), dir.path().join("nope.toml")), true)?;
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        assert!(parsed.pointer("/host/profile").is_some(), "{text}");
        assert!(parsed.pointer("/checks/0/name").is_some(), "{text}");
        assert!(
            parsed
                .pointer("/ok")
                .and_then(serde_json::Value::as_bool)
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn a_world_writable_state_directory_is_a_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("state");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777))?;
        let (exit, text) = run(&settings(&root, dir.path().join("nope.toml")), false)?;
        assert_eq!(exit, Exit::Failed, "{text}");
        Ok(())
    }

    #[test]
    fn a_state_root_that_is_a_file_fails_and_a_missing_one_only_warns() -> R {
        let dir = tempfile::TempDir::new()?;
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x")?;
        assert_eq!(directory_check(&file).status, Status::Fail);
        assert_eq!(
            directory_check(&dir.path().join("absent")).status,
            Status::Warn
        );
        Ok(())
    }

    #[test]
    fn config_permissions_decide_the_status() -> R {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("detent.toml");
        std::fs::write(&path, b"x")?;
        for (mode, expected) in [
            (0o600, Status::Ok),
            (0o644, Status::Warn),
            (0o666, Status::Fail),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            let check = config_check(&path);
            assert_eq!(check.status, expected, "{mode:o}: {check:?}");
            assert!(check.detail.contains(&format!("{mode:04o}")), "{check:?}");
        }
        assert_eq!(
            config_check(&dir.path().join("absent.toml")).status,
            Status::Warn
        );
        Ok(())
    }

    #[test]
    fn doctor_refuses_symlink_targets() -> R {
        let dir = tempfile::TempDir::new()?;
        let target = dir.path().join("target");
        std::fs::write(&target, b"x")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link)?;

        let config = config_check(&link);
        assert_eq!(config.status, Status::Fail);
        assert!(config.detail.contains("symbolic link"), "{config:?}");

        let state = directory_check(&link);
        assert_eq!(state.status, Status::Fail);
        assert!(state.detail.contains("symbolic link"), "{state:?}");
        Ok(())
    }

    #[test]
    fn mode_status_classifies_every_band() {
        assert_eq!(mode_status(0o700), Status::Ok);
        assert_eq!(mode_status(0o750), Status::Warn);
        assert_eq!(mode_status(0o770), Status::Fail);
        // PLAN §2.2: a build with no modules compiled in warns, not passes.
        let empty = modules_check(&[]);
        assert_eq!(empty.status, Status::Warn);
        assert_eq!(empty.detail, "none");
    }

    #[test]
    fn every_check_name_has_a_message_and_a_status_word() {
        let messages = Messages::new(None);
        for name in [
            "modules",
            "state-root",
            "config",
            "privsep",
            "landlock",
            "seccomp",
            "confinement",
        ] {
            let check = Check::new(name, Status::Ok, "detail");
            assert!(messages.has(check.message()), "{name} has no message");
        }
        for status in [Status::Ok, Status::Warn, Status::Fail] {
            assert!(messages.has(status.message()));
        }
    }

    #[test]
    fn the_report_serializes_its_checks() -> R {
        let json = serde_json::to_value(Report {
            host: detent_ops::report::HostReport::from(&detent_platform::host::Detected::default()),
            checks: vec![Check::new("modules", Status::Warn, "none")],
            ok: true,
        })?;
        assert_eq!(
            json.pointer("/checks/0/status").and_then(|v| v.as_str()),
            Some("warn")
        );
        Ok(())
    }

    /// The two failure arms of [`privsep_verdict`]: a pair that came up but
    /// stopped for the wrong reason, and one that never served at all. Both
    /// are reachable only by forking a deliberately broken pair, which is why
    /// the verdict is a function.
    #[test]
    fn privsep_verdict_reports_a_wrong_exit_reason_and_a_serve_error() {
        let ok = privsep_verdict(Ok(ExitReason::Shutdown), Ok(Some(0)), 42);
        assert_eq!(ok.status, Status::Ok);
        assert!(ok.detail.contains("42"), "{ok:?}");

        let wrong_reason = privsep_verdict(Ok(ExitReason::PeerClosed), Ok(Some(0)), 42);
        assert_eq!(wrong_reason.status, Status::Fail);
        assert!(
            wrong_reason.detail.contains("PeerClosed"),
            "{wrong_reason:?}"
        );

        let bad_status = privsep_verdict(Ok(ExitReason::Shutdown), Ok(Some(1)), 42);
        assert_eq!(bad_status.status, Status::Fail);

        let never_served = privsep_verdict(Err(MonitorError::CorruptMarker), Ok(Some(0)), 42);
        assert_eq!(never_served.status, Status::Fail);
        assert!(never_served.detail.contains("marker"), "{never_served:?}");
    }

    /// A kernel interface that is readable but does not list the feature is
    /// a warning quoting what the kernel does list — the operator sees why.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_feature_the_kernel_does_not_list_is_a_warning() -> R {
        let dir = tempfile::TempDir::new()?;
        let lsm = dir.path().join("lsm");
        std::fs::write(&lsm, "capability,yama\n")?;
        let check = super::kernel_feature("landlock", &lsm.display().to_string(), "landlock");
        assert_eq!(check.name, "landlock");
        assert_eq!(check.status, Status::Warn);
        assert_eq!(check.detail, "capability,yama");
        Ok(())
    }
}
