//! `detent doctor` rows for `[privilege] mode` (PLAN §2.4, Phase 12).
//!
//! Root-confined needs nothing beyond the unit, so it gets one row that
//! names the mode. Capability-user needs the host to provide what root
//! would otherwise give: the `detent` account, a state root it owns, a
//! backups directory the worker (the same uid) cannot read, the polkit rule
//! and daemon for service control, and a unit that really starts the service
//! as `detent` with the three ambient capabilities. Each is one row.
//!
//! Every input is passed in ([`Host`]), so each row is tested on its own;
//! [`Host::real`] reads the real host.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use detent_platform::privsep::mode::{CAPABILITY_USER_CAPS, PrivilegeMode};
use detent_platform::privsep::spawn::DEFAULT_WORKER_USER;
use detent_platform::privsep::users::{self, LookupError, UserIds};
use detent_platform::service::exec::{ProcessRunner, RealProcessRunner, STATUS_TIMEOUT};

use super::{Check, Status, WRITABLE_BY_OTHERS};

/// Where `install.sh --mode capability-user` puts the polkit rule.
pub(super) const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/50-detent.rules";

/// The rule this build ships.
const PACKAGED_RULE: &str = include_str!("../../../../packaging/polkit/50-detent.rules");

/// The line that makes a rule file the detent rule.
const RULE_MARKER: &str = "subject.user != \"detent\"";

/// Where distributions install the polkit daemon.
const POLKITD: &[&str] = &[
    "/usr/lib/polkit-1/polkitd",
    "/usr/libexec/polkitd",
    "/usr/lib/policykit-1/polkitd",
    "/usr/libexec/polkit-1/polkitd",
];

/// Where `systemctl` may live.
const SYSTEMCTL: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// The unit `install.sh` installs.
const UNIT: &str = "detent.service";

/// The `systemctl show` properties the unit row reads. A fixed literal.
const UNIT_PROPERTIES: &str = "--property=LoadState,User,AmbientCapabilities,NoNewPrivileges";

/// What the capability-user rows read from the host.
pub(super) struct Host<'a> {
    /// The state root (`/var/lib/detent`).
    pub state_root: &'a Path,
    /// The installed polkit rule.
    pub polkit_rule: &'a Path,
    /// The `detent` account.
    pub account: Result<UserIds, LookupError>,
    /// The `detent` group.
    pub group: Result<u32, LookupError>,
    /// Finds the polkit daemon and runs `systemctl show`.
    pub runner: &'a dyn ProcessRunner,
}

impl<'a> Host<'a> {
    /// The real host.
    pub(super) fn real(state_root: &'a Path) -> Self {
        Self {
            state_root,
            polkit_rule: Path::new(POLKIT_RULE),
            account: users::lookup_user(DEFAULT_WORKER_USER),
            group: users::lookup_group(DEFAULT_WORKER_USER),
            runner: &RealProcessRunner,
        }
    }
}

/// The rows for `mode`: the mode itself, then, in capability-user mode, one
/// row for each prerequisite.
pub(super) fn checks(mode: PrivilegeMode, host: &Host<'_>) -> Vec<Check> {
    let mut checks = vec![Check::new("privilege-mode", Status::Ok, mode.as_str())];
    if mode == PrivilegeMode::CapabilityUser {
        let account = host.account.as_ref().ok();
        checks.push(account_check(&host.account, &host.group));
        checks.push(state_owner_check(host.state_root, account));
        checks.push(backups_check(&host.state_root.join("backups"), account));
        let daemon = polkit_daemon_check(host.runner);
        checks.push(polkit_rule_check(
            host.polkit_rule,
            daemon.status == Status::Ok,
        ));
        checks.push(daemon);
        checks.push(unit_check(host.runner));
    }
    checks
}

/// The `detent` user and group exist.
fn account_check(
    account: &Result<UserIds, LookupError>,
    group: &Result<u32, LookupError>,
) -> Check {
    match (account, group) {
        (Ok(ids), Ok(gid)) => Check::new(
            "service-account",
            Status::Ok,
            format!("{DEFAULT_WORKER_USER} (uid {}, gid {gid})", ids.uid),
        ),
        (Err(err), _) | (_, Err(err)) => Check::new(
            "service-account",
            Status::Fail,
            format!("{DEFAULT_WORKER_USER}: {err} (systemd-sysusers creates it)"),
        ),
    }
}

/// The state root belongs to the service account: in this mode the monitor
/// and the worker both run as it.
fn state_owner_check(state_root: &Path, account: Option<&UserIds>) -> Check {
    let path = state_root.display();
    let Some(account) = account else {
        return Check::new("state-owner", Status::Warn, format!("{path} (no account)"));
    };
    match std::fs::symlink_metadata(state_root) {
        Ok(meta) if meta.is_dir() && meta.uid() == account.uid => {
            let mode = meta.permissions().mode() & 0o7777;
            let status = if mode & WRITABLE_BY_OTHERS == 0 {
                Status::Ok
            } else {
                Status::Fail
            };
            Check::new(
                "state-owner",
                status,
                format!("{path} (uid {}, {mode:04o})", meta.uid()),
            )
        }
        Ok(meta) if meta.is_dir() => Check::new(
            "state-owner",
            Status::Fail,
            format!(
                "{path} belongs to uid {}, the service runs as uid {}",
                meta.uid(),
                account.uid
            ),
        ),
        Ok(_) => Check::new(
            "state-owner",
            Status::Fail,
            format!("{path} (not a directory)"),
        ),
        Err(err) => Check::new("state-owner", Status::Fail, format!("{path}: {err}")),
    }
}

/// The backups directory: root's, `0700` (tmpfiles.d). The worker has the
/// service's uid in this mode, so a backups directory that uid owns is
/// readable by the worker; only Landlock would then keep it out.
fn backups_check(backups: &Path, account: Option<&UserIds>) -> Check {
    let path = backups.display();
    let meta = match std::fs::symlink_metadata(backups) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Check::new("backups-dir", Status::Warn, format!("{path} (absent)"));
        }
        Err(err) => return Check::new("backups-dir", Status::Fail, format!("{path}: {err}")),
    };
    let mode = meta.permissions().mode() & 0o7777;
    let detail = format!("{path} (uid {}, {mode:04o})", meta.uid());
    let status = if !meta.is_dir() || mode & 0o077 != 0 {
        Status::Fail
    } else if meta.uid() == 0 {
        Status::Ok
    } else if account.is_some_and(|account| account.uid == meta.uid()) {
        Status::Warn
    } else {
        Status::Fail
    };
    Check::new("backups-dir", status, detail)
}

/// The polkit rule: present, root's, not writable by others, and the detent
/// rule (the one this build ships, or at least one for the `detent` user).
///
/// Distributions make `rules.d` unreadable to other users (Ubuntu: `0750
/// root:polkitd`), so the `detent` user normally cannot even `stat` the
/// rule. That is the normal state of a correct install, not a fault: the row
/// is `ok` with a note that the content was not compared, but only when a
/// polkit daemon is installed (`daemon`). Otherwise it stays `warn`. As root
/// the rule is read and compared.
fn polkit_rule_check(rule: &Path, daemon: bool) -> Check {
    let path = rule.display();
    let unreadable = || {
        if daemon {
            Check::new(
                "polkit-rule",
                Status::Ok,
                format!(
                    "{path}: not readable by this user, content not compared \
                     (run `sudo detent doctor` to compare it)"
                ),
            )
        } else {
            Check::new(
                "polkit-rule",
                Status::Warn,
                format!("{path}: cannot read as this user (run doctor as root)"),
            )
        }
    };
    let meta = match std::fs::symlink_metadata(rule) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return unreadable();
        }
        Err(err) => {
            return Check::new(
                "polkit-rule",
                Status::Fail,
                format!("{path}: {err} (install.sh --mode capability-user installs it)"),
            );
        }
    };
    if !meta.file_type().is_file() {
        return Check::new(
            "polkit-rule",
            Status::Fail,
            format!("{path} (not a regular file)"),
        );
    }
    let mode = meta.permissions().mode() & 0o7777;
    if meta.uid() != 0 || mode & WRITABLE_BY_OTHERS != 0 {
        return Check::new(
            "polkit-rule",
            Status::Fail,
            format!(
                "{path} (uid {}, {mode:04o}): must be root's and not writable by others",
                meta.uid()
            ),
        );
    }
    match std::fs::read_to_string(rule) {
        Ok(text) if text == PACKAGED_RULE => {
            Check::new("polkit-rule", Status::Ok, path.to_string())
        }
        Ok(text) if text.contains(RULE_MARKER) => Check::new(
            "polkit-rule",
            Status::Warn,
            format!("{path} differs from the rule this build ships"),
        ),
        Ok(_) => Check::new(
            "polkit-rule",
            Status::Fail,
            format!("{path} is not the detent rule"),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => unreadable(),
        Err(err) => Check::new("polkit-rule", Status::Fail, format!("{path}: {err}")),
    }
}

/// A polkit daemon is installed.
fn polkit_daemon_check(runner: &dyn ProcessRunner) -> Check {
    match POLKITD.iter().copied().find(|path| runner.exists(path)) {
        Some(path) => Check::new("polkit-daemon", Status::Ok, path),
        None => Check::new(
            "polkit-daemon",
            Status::Fail,
            "not found (capability-user mode needs polkit 0.106 or later)",
        ),
    }
}

/// The installed unit starts the service as `detent`, with the three ambient
/// capabilities and `no_new_privs`, as `systemctl show` reports it.
fn unit_check(runner: &dyn ProcessRunner) -> Check {
    let Some(systemctl) = SYSTEMCTL.iter().copied().find(|path| runner.exists(path)) else {
        return Check::new("unit-capabilities", Status::Warn, "systemctl not found");
    };
    let args = [
        "show".to_owned(),
        UNIT_PROPERTIES.to_owned(),
        "--".to_owned(),
        UNIT.to_owned(),
    ];
    match runner.run(systemctl, &args, STATUS_TIMEOUT) {
        Ok(output) if !output.timed_out && output.status == Some(0) => {
            unit_verdict(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => Check::new(
            "unit-capabilities",
            Status::Warn,
            format!("systemctl show {UNIT} failed: {:?}", output.status),
        ),
        Err(err) => Check::new("unit-capabilities", Status::Warn, err.to_string()),
    }
}

/// Judge `systemctl show`'s `key=value` lines.
fn unit_verdict(show: &str) -> Check {
    let value = |key: &str| {
        show.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
            .trim()
    };
    if value("LoadState") != "loaded" {
        return Check::new(
            "unit-capabilities",
            Status::Fail,
            format!("{UNIT} is not loaded ({})", value("LoadState")),
        );
    }
    let ambient: Vec<String> = value("AmbientCapabilities")
        .split_whitespace()
        .map(str::to_ascii_uppercase)
        .collect();
    let missing: Vec<&str> = CAPABILITY_USER_CAPS
        .iter()
        .map(|cap| cap.name())
        .filter(|name| !ambient.iter().any(|held| held == name))
        .collect();
    let detail = format!(
        "User={} AmbientCapabilities={} NoNewPrivileges={}",
        value("User"),
        value("AmbientCapabilities"),
        value("NoNewPrivileges")
    );
    let ok = value("User") == DEFAULT_WORKER_USER
        && missing.is_empty()
        && value("NoNewPrivileges") == "yes";
    Check::new(
        "unit-capabilities",
        if ok { Status::Ok } else { Status::Fail },
        if missing.is_empty() {
            detail
        } else {
            format!("{detail} (missing {})", missing.join(" "))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Host, PACKAGED_RULE, account_check, backups_check, checks, polkit_daemon_check,
        polkit_rule_check, state_owner_check, unit_check, unit_verdict,
    };
    use crate::doctor::Status;
    use detent_platform::privsep::mode::PrivilegeMode;
    use detent_platform::privsep::users::{LookupError, UserIds};
    use detent_platform::service::exec::{ProcessError, ProcessOutput, ProcessRunner};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;
    use std::time::Duration;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A host whose programs are `present`, and whose `systemctl show`
    /// prints `show` (or fails when `None`).
    struct FakeRunner {
        present: Vec<&'static str>,
        show: Option<&'static str>,
    }

    impl ProcessRunner for FakeRunner {
        fn exists(&self, path: &'static str) -> bool {
            self.present.contains(&path)
        }

        fn run(
            &self,
            program: &'static str,
            args: &[String],
            _timeout: Duration,
        ) -> Result<ProcessOutput, ProcessError> {
            assert_eq!(args.first().map(String::as_str), Some("show"));
            assert_eq!(args.last().map(String::as_str), Some("detent.service"));
            match self.show {
                Some(text) => Ok(ProcessOutput {
                    status: Some(0),
                    stdout: text.as_bytes().to_vec(),
                    stderr: Vec::new(),
                    timed_out: false,
                }),
                None => Err(ProcessError {
                    program: program.to_owned(),
                    message: "no".to_owned(),
                }),
            }
        }
    }

    const GOOD_UNIT: &str = "LoadState=loaded\nUser=detent\n\
        AmbientCapabilities=cap_chown cap_dac_override cap_fowner\nNoNewPrivileges=yes\n";

    /// This process's ids: the owner of every file a test makes.
    fn me() -> UserIds {
        UserIds {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }

    #[test]
    fn root_confined_has_one_row_and_capability_user_has_seven() -> R {
        let dir = tempfile::TempDir::new()?;
        let runner = FakeRunner {
            present: vec![],
            show: None,
        };
        let host = Host {
            state_root: dir.path(),
            polkit_rule: &dir.path().join("rule"),
            account: Ok(me()),
            group: Ok(0),
            runner: &runner,
        };
        let root = checks(PrivilegeMode::RootConfined, &host);
        let [only] = root.as_slice() else {
            return Err(format!("one row, got {root:?}").into());
        };
        assert_eq!(only.status, Status::Ok);
        assert_eq!(only.detail, "root-confined");
        let names: Vec<&str> = checks(PrivilegeMode::CapabilityUser, &host)
            .iter()
            .map(|check| check.name)
            .collect();
        assert_eq!(
            names,
            [
                "privilege-mode",
                "service-account",
                "state-owner",
                "backups-dir",
                "polkit-rule",
                "polkit-daemon",
                "unit-capabilities"
            ]
        );
        for check in checks(PrivilegeMode::CapabilityUser, &host) {
            assert!(
                !check.message().as_str().ends_with("-confinement"),
                "{check:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_missing_account_or_group_fails() {
        let ids = UserIds { uid: 999, gid: 979 };
        assert_eq!(account_check(&Ok(ids), &Ok(979)).status, Status::Ok);
        let gone = || Err(LookupError::NotFound("detent".to_owned()));
        assert_eq!(account_check(&gone(), &Ok(979)).status, Status::Fail);
        let check = account_check(&Ok(ids), &Err(LookupError::NotFound("detent".to_owned())));
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("sysusers"), "{check:?}");
    }

    #[test]
    fn the_state_root_must_belong_to_the_service_account() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let owner = me();
        assert_eq!(
            state_owner_check(dir.path(), Some(&owner)).status,
            Status::Ok
        );
        let other = UserIds {
            uid: owner.uid.wrapping_add(1),
            gid: owner.gid,
        };
        let check = state_owner_check(dir.path(), Some(&other));
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("the service runs as"), "{check:?}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))?;
        assert_eq!(
            state_owner_check(dir.path(), Some(&owner)).status,
            Status::Fail
        );
        assert_eq!(state_owner_check(dir.path(), None).status, Status::Warn);
        assert_eq!(
            state_owner_check(&dir.path().join("absent"), Some(&owner)).status,
            Status::Fail
        );
        Ok(())
    }

    #[test]
    fn backups_owned_by_the_service_uid_warn_and_open_modes_fail() -> R {
        let dir = tempfile::TempDir::new()?;
        let backups = dir.path().join("backups");
        assert_eq!(backups_check(&backups, None).status, Status::Warn);
        std::fs::create_dir(&backups)?;
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700))?;
        let owner = me();
        let expected = if owner.uid == 0 {
            Status::Ok
        } else {
            Status::Warn
        };
        assert_eq!(backups_check(&backups, Some(&owner)).status, expected);
        let stranger = UserIds {
            uid: owner.uid.wrapping_add(1),
            gid: owner.gid,
        };
        let expected = if owner.uid == 0 {
            Status::Ok
        } else {
            Status::Fail
        };
        assert_eq!(backups_check(&backups, Some(&stranger)).status, expected);
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o750))?;
        assert_eq!(backups_check(&backups, Some(&owner)).status, Status::Fail);
        Ok(())
    }

    #[test]
    fn the_polkit_rule_must_be_present_root_owned_and_the_detent_rule() -> R {
        let dir = tempfile::TempDir::new()?;
        let rule = dir.path().join("50-detent.rules");
        let absent = polkit_rule_check(&rule, true);
        assert_eq!(absent.status, Status::Fail);
        assert!(
            absent.detail.contains("--mode capability-user"),
            "{absent:?}"
        );

        std::fs::write(&rule, PACKAGED_RULE)?;
        std::fs::set_permissions(&rule, std::fs::Permissions::from_mode(0o644))?;
        let root_owned = std::fs::metadata(&rule)?.uid() == 0;
        let packaged = polkit_rule_check(&rule, true);
        if root_owned {
            assert_eq!(packaged.status, Status::Ok, "{packaged:?}");
            std::fs::write(&rule, PACKAGED_RULE.replace("reload-daemon", "x"))?;
            assert_eq!(polkit_rule_check(&rule, true).status, Status::Warn);
            std::fs::write(&rule, "polkit.addRule(function () {});\n")?;
            assert_eq!(polkit_rule_check(&rule, true).status, Status::Fail);
            std::fs::write(&rule, PACKAGED_RULE)?;
        } else {
            // Not root: the file is this user's, and polkit would read a
            // rule anyone but root can change.
            assert_eq!(packaged.status, Status::Fail, "{packaged:?}");
            assert!(packaged.detail.contains("must be root's"), "{packaged:?}");
        }
        std::fs::set_permissions(&rule, std::fs::Permissions::from_mode(0o666))?;
        assert_eq!(polkit_rule_check(&rule, true).status, Status::Fail);

        let link = dir.path().join("link.rules");
        std::os::unix::fs::symlink(&rule, &link)?;
        let linked = polkit_rule_check(&link, true);
        assert_eq!(linked.status, Status::Fail);
        assert!(linked.detail.contains("not a regular file"), "{linked:?}");
        Ok(())
    }

    #[test]
    fn an_unreadable_polkit_rule_is_ok_with_a_note_only_beside_a_daemon() -> R {
        let dir = tempfile::TempDir::new()?;
        let rules = dir.path().join("rules.d");
        std::fs::create_dir(&rules)?;
        let rule = rules.join("50-detent.rules");
        std::fs::write(&rule, PACKAGED_RULE)?;
        // Like Ubuntu's `0750 root:polkitd`: this user cannot enter it.
        std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o000))?;
        let readable = std::fs::symlink_metadata(&rule).is_ok();
        let with_daemon = polkit_rule_check(&rule, true);
        let without = polkit_rule_check(&rule, false);
        std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o755))?;
        if readable {
            // Root reads through any mode; the row then compares the file.
            return Ok(());
        }
        assert_eq!(with_daemon.status, Status::Ok, "{with_daemon:?}");
        assert!(
            with_daemon.detail.contains("sudo detent doctor"),
            "{with_daemon:?}"
        );
        assert_eq!(without.status, Status::Warn, "{without:?}");
        Ok(())
    }

    #[test]
    fn the_polkit_daemon_is_found_in_any_distribution_path() {
        let found = polkit_daemon_check(&FakeRunner {
            present: vec!["/usr/libexec/polkitd"],
            show: None,
        });
        assert_eq!(found.status, Status::Ok);
        assert_eq!(found.detail, "/usr/libexec/polkitd");
        let none = polkit_daemon_check(&FakeRunner {
            present: vec![],
            show: None,
        });
        assert_eq!(none.status, Status::Fail);
    }

    #[test]
    fn the_unit_must_run_as_detent_with_the_three_ambient_capabilities() {
        assert_eq!(unit_verdict(GOOD_UNIT).status, Status::Ok);
        let root = unit_verdict(&GOOD_UNIT.replace("User=detent", "User="));
        assert_eq!(root.status, Status::Fail);
        let partial = unit_verdict(&GOOD_UNIT.replace("cap_chown ", ""));
        assert_eq!(partial.status, Status::Fail);
        assert!(partial.detail.contains("missing CAP_CHOWN"), "{partial:?}");
        let privs = unit_verdict(&GOOD_UNIT.replace("NoNewPrivileges=yes", "NoNewPrivileges=no"));
        assert_eq!(privs.status, Status::Fail);
        let absent = unit_verdict("LoadState=not-found\nUser=\n");
        assert_eq!(absent.status, Status::Fail);
        assert!(absent.detail.contains("not loaded"), "{absent:?}");
    }

    #[test]
    fn the_unit_row_runs_systemctl_show_and_warns_when_it_cannot() {
        let ok = unit_check(&FakeRunner {
            present: vec!["/usr/bin/systemctl"],
            show: Some(GOOD_UNIT),
        });
        assert_eq!(ok.status, Status::Ok, "{ok:?}");
        let failed = unit_check(&FakeRunner {
            present: vec!["/bin/systemctl"],
            show: None,
        });
        assert_eq!(failed.status, Status::Warn);
        let missing = unit_check(&FakeRunner {
            present: vec![],
            show: None,
        });
        assert_eq!(missing.status, Status::Warn);
        assert!(missing.detail.contains("systemctl"), "{missing:?}");
    }

    #[test]
    fn the_real_host_reads_the_packaged_rule_path() {
        let host = Host::real(Path::new("/var/lib/detent"));
        assert_eq!(host.polkit_rule, Path::new(super::POLKIT_RULE));
    }
}
