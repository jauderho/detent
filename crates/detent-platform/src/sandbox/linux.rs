//! Linux implementation of [`super::confine`] (PLAN §2.4; `docs/spikes/02-sandbox.md`).
//!
//! Only compiled under `cfg(target_os = "linux")` (see the `mod linux;` line
//! in `sandbox/mod.rs`), so it is free to use `caps`/`landlock`/`seccompiler`
//! directly — those crates do not exist in the dependency graph on any other
//! target.

use std::collections::HashSet;
use std::io;

use caps::{CapSet, Capability as CapsCapability, CapsHashSet};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

use super::caps_verdict;
use super::seccomp::{self, Arch, SeccompMode};
use super::{
    Capability, Confinement, LandlockOutcome, LandlockStatus, Outcome, Policy, Role, SandboxError,
};

/// Landlock ABI levels to probe, matching `docs/spikes/02-sandbox.md`'s
/// demonstrated approach: try from V1 upward under
/// [`CompatLevel::HardRequirement`] (which turns "the kernel does not
/// support this" into a plain `Err` instead of [`CompatLevel::BestEffort`]'s
/// silent downgrade — exactly what a probe needs), keeping the highest ABI
/// that creates successfully.
const PROBE_ABIS: &[ABI] = &[ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5];

pub fn confine(role: Role, policy: &Policy) -> Result<Confinement, SandboxError> {
    let no_new_privs = harden_no_new_privs();
    let dumpable_cleared = harden_dumpable();
    let caps = drop_capabilities(policy);
    caps_verdict(policy.require_caps, &caps)?;
    let landlock = install_landlock(policy)?;
    // Seccomp last: every syscall the steps above need has already run, so
    // installing their allow-list first would risk `SIGSYS`-ing them.
    let seccomp = install_seccomp(role);
    seccomp_verdict(policy.require_seccomp, &seccomp)?;

    Ok(Confinement {
        no_new_privs,
        dumpable_cleared,
        caps,
        landlock,
        seccomp,
    })
}

fn harden_no_new_privs() -> Outcome {
    match rustix::thread::set_no_new_privs(true) {
        Ok(()) => Outcome::Applied,
        Err(err) => Outcome::Unavailable {
            reason: io::Error::from(err).to_string(),
        },
    }
}

fn harden_dumpable() -> Outcome {
    match rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable) {
        Ok(()) => Outcome::Applied,
        Err(err) => Outcome::Unavailable {
            reason: io::Error::from(err).to_string(),
        },
    }
}

const fn to_caps_capability(cap: Capability) -> CapsCapability {
    match cap {
        Capability::DacOverride => CapsCapability::CAP_DAC_OVERRIDE,
        Capability::Chown => CapsCapability::CAP_CHOWN,
        Capability::Fowner => CapsCapability::CAP_FOWNER,
        Capability::SetUid => CapsCapability::CAP_SETUID,
        Capability::SetGid => CapsCapability::CAP_SETGID,
        Capability::Kill => CapsCapability::CAP_KILL,
    }
}

/// Whether the effective or permitted capability set is not empty.
pub(super) fn holds_capabilities() -> bool {
    sets_hold_capabilities(
        caps::read(None, CapSet::Effective),
        caps::read(None, CapSet::Permitted),
    )
}

/// A failed read counts as holding capabilities (fail closed).
fn sets_hold_capabilities(
    effective: Result<CapsHashSet, caps::errors::CapsError>,
    permitted: Result<CapsHashSet, caps::errors::CapsError>,
) -> bool {
    !matches!((effective, permitted), (Ok(e), Ok(p)) if e.is_empty() && p.is_empty())
}

fn drop_capabilities(policy: &Policy) -> Outcome {
    // An unprivileged worker can reach this hook after `setuid`. Its
    // effective and permitted sets are then already empty, so attempting to
    // drop the still-full bounding set would return EPERM. Treat that state as
    // the worker's required outcome; the monitor keeps the strict path.
    if !policy.require_caps
        && let Ok(effective) = caps::read(None, CapSet::Effective)
        && effective.is_empty()
        && let Ok(permitted) = caps::read(None, CapSet::Permitted)
        && permitted.is_empty()
    {
        return Outcome::Applied;
    }
    let retain: HashSet<CapsCapability> = policy
        .retained_caps
        .iter()
        .copied()
        .map(to_caps_capability)
        .collect();
    match drop_capabilities_inner(&retain) {
        Ok(()) => Outcome::Applied,
        Err(reason) => Outcome::Unavailable { reason },
    }
}

/// Drop the bounding set to exactly `retain`, then set the effective and
/// permitted sets to `retain` too (PLAN §2.4: drop the capability bounding
/// set, and the effective/permitted sets, to the policy set). Bounding-set
/// entries are dropped one at a time — `caps::drop` has no bulk form —
/// before the effective/permitted sets are replaced wholesale, so a partial
/// failure never leaves the process with a *larger* effective set than the
/// bounding set it just tried to shrink.
fn drop_capabilities_inner(retain: &HashSet<CapsCapability>) -> Result<(), String> {
    let bounding = caps::read(None, CapSet::Bounding).map_err(|err| err.to_string())?;
    for cap in bounding {
        if !retain.contains(&cap) {
            caps::drop(None, CapSet::Bounding, cap).map_err(|err| err.to_string())?;
        }
    }
    let retained: CapsHashSet = retain.iter().copied().collect();
    caps::set(None, CapSet::Effective, &retained).map_err(|err| err.to_string())?;
    caps::set(None, CapSet::Permitted, &retained).map_err(|err| err.to_string())?;
    Ok(())
}

fn install_landlock(policy: &Policy) -> Result<LandlockOutcome, SandboxError> {
    let Some(abi) = probe_abi() else {
        let reason = "kernel does not support Landlock ABI 1 (5.13+)".to_owned();
        return if policy.require_landlock {
            Err(SandboxError::LandlockRequired(reason))
        } else {
            Ok(LandlockOutcome::Unavailable { reason })
        };
    };

    match enforce_landlock(policy, abi) {
        Ok(status) => Ok(LandlockOutcome::Applied {
            abi: abi as u8,
            status,
        }),
        Err(err) => {
            let reason = err.to_string();
            if policy.require_landlock {
                Err(SandboxError::LandlockRequired(reason))
            } else {
                Ok(LandlockOutcome::Unavailable { reason })
            }
        }
    }
}

/// Try each ABI from [`PROBE_ABIS`] under [`CompatLevel::HardRequirement`],
/// keeping the highest one that creates successfully. Does not enforce
/// anything — [`enforce_landlock`] does that separately, at the ABI this
/// function found, under [`CompatLevel::BestEffort`].
fn probe_abi() -> Option<ABI> {
    let mut best = None;
    for &abi in PROBE_ABIS {
        let created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .and_then(Ruleset::create);
        match created {
            Ok(_) => best = Some(abi),
            Err(_) => break,
        }
    }
    best
}

/// Read access everywhere, full (read + write) access under each of
/// `policy.writable_paths`, then `restrict_self()`.
fn enforce_landlock(
    policy: &Policy,
    abi: ABI,
) -> Result<LandlockStatus, Box<dyn std::error::Error>> {
    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rule(PathBeneath::new(
            PathFd::new("/")?,
            AccessFs::from_read(abi),
        ))?;
    for path in &policy.writable_paths {
        // A missing directory (e.g. a module's backup directory before its
        // first write — `fs::atomic` creates it on demand) is skipped, not
        // fatal: aborting the whole ruleset because one of several target
        // directories has not been used yet would mean a fresh install never
        // gets Landlock protection for the directories that *do* exist.
        let Ok(fd) = PathFd::new(path) else {
            continue;
        };
        created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
    }
    let status = created.restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => LandlockStatus::FullyEnforced,
        RulesetStatus::PartiallyEnforced => LandlockStatus::PartiallyEnforced,
        RulesetStatus::NotEnforced => LandlockStatus::NotEnforced,
    })
}

/// Fail closed on a filter that did not install.
///
/// A filter that does not install is not a degraded sandbox, it is *no*
/// sandbox — and it is silent, because the process then works perfectly. Split
/// out of [`confine`] so all four combinations are reachable from a test
/// without having to make a real `seccomp(2)` call fail.
fn seccomp_verdict(required: bool, outcome: &Outcome) -> Result<(), SandboxError> {
    match *outcome {
        Outcome::Unavailable { ref reason } if required => {
            Err(SandboxError::SeccompRequired(reason.clone()))
        }
        _ => Ok(()),
    }
}
fn install_seccomp(role: Role) -> Outcome {
    match install_seccomp_inner(role) {
        Ok(()) => Outcome::Applied,
        Err(err) => Outcome::Unavailable {
            reason: err.to_string(),
        },
    }
}

fn install_seccomp_inner(role: Role) -> Result<(), seccomp::SeccompError> {
    let arch = Arch::host()?;
    let program = seccomp::compile(role, arch, SeccompMode::Enforce)?;
    seccompiler::apply_filter(&program)
        .map_err(|err| seccomp::SeccompError::Install(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::super::{Hooks, Outcome, Policy, Role, SandboxError, confine};
    use super::seccomp_verdict;
    use crate::privsep::allowlist::{Allowlist, Config};
    use crate::privsep::proto::{Request, Response};
    use crate::privsep::spawn::SandboxHooks;
    use crate::privsep::transport::Channel;
    use detent_core::descriptor::{
        HostProfile, ModuleDescriptor, Owner, PathSpec, Target, TargetKind, Upstream,
    };
    use detent_core::diag::MessageId;
    use std::path::Path;

    #[test]
    fn capability_read_fails_closed_and_reports_any_non_empty_set() {
        use super::{CapsHashSet, sets_hold_capabilities};
        let empty = || Ok(CapsHashSet::new());
        let full = || Ok([caps::Capability::CAP_CHOWN].into_iter().collect());
        let failed = || Err(caps::errors::CapsError::from("read failed"));
        assert!(!sets_hold_capabilities(empty(), empty()));
        assert!(sets_hold_capabilities(full(), empty()));
        assert!(sets_hold_capabilities(empty(), full()));
        assert!(sets_hold_capabilities(failed(), empty()));
        assert!(sets_hold_capabilities(empty(), failed()));
    }

    /// The container runs the tests as root, so the effective set is full.
    #[test]
    fn root_in_the_container_holds_capabilities() {
        if caps::has_cap(
            None,
            super::CapSet::Effective,
            caps::Capability::CAP_DAC_OVERRIDE,
        )
        .unwrap_or(false)
        {
            assert!(super::holds_capabilities());
        }
    }

    /// The production policies fail closed on seccomp, and every other
    /// combination is permitted. This is the guard on a failure that is
    /// otherwise completely silent: the filter does not install, `confine`
    /// reports success, and the process runs unfiltered while working
    /// perfectly — which is precisely what happened when `epoll_wait`, a
    /// syscall `aarch64` does not have, was in the worker's table.
    #[test]
    fn a_filter_that_does_not_install_is_fatal_only_when_required() {
        let unavailable = Outcome::Unavailable {
            reason: "kernel said no".to_owned(),
        };
        // `assert!(matches!(..))` rather than a `match` with a `panic!` arm:
        // `clippy::panic` is denied crate-wide, tests included.
        let verdict = seccomp_verdict(true, &unavailable);
        assert!(
            matches!(verdict, Err(SandboxError::SeccompRequired(ref reason)) if reason == "kernel said no"),
            "{verdict:?}"
        );
        assert!(seccomp_verdict(false, &unavailable).is_ok());
        assert!(seccomp_verdict(true, &Outcome::Applied).is_ok());
        assert!(
            seccomp_verdict(
                true,
                &Outcome::Skipped {
                    reason: "not attempted".to_owned(),
                },
            )
            .is_ok()
        );
    }
    // Forking helpers come from `privsep::sys`, the crate's single home for
    // `unsafe` POSIX calls. These children exit via
    // `exit_immediately_unflushed`, never `exit_immediately`: by the time they
    // exit they are confined, and writing a coverage profile needs `openat`
    // and `write`, which the installed seccomp filter denies. That is also why
    // the lines a confined child executes cannot be recorded — see
    // `coverage-baseline.json`.
    use crate::privsep::sys as fork;

    const fn always(_: &HostProfile) -> bool {
        true
    }

    static UPSTREAM: Upstream = Upstream {
        project: "test",
        repo_url: "https://example.invalid/test",
        tracked_version: "1.0",
        release_feed: None,
        docs: &[],
    };

    /// Run `f` in a forked child, `waitpid` it, and assert it exited `0`.
    /// Confinement is irreversible (dropped capabilities, an installed
    /// Landlock ruleset, and an installed seccomp filter cannot be undone in
    /// the calling process), so every test below that actually calls
    /// [`confine`] runs it here instead of in the test-harness thread
    /// directly — the same reason `privsep::spawn`'s own tests fork
    /// (`spawn_pair_forks_a_working_pair`). `f` reports success as `bool`;
    /// `exit_immediately_unflushed` is used instead of a normal return so the child
    /// never runs the parent's `atexit`/test harness teardown.
    fn in_forked_child(f: impl FnOnce() -> bool) -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: forking before starting any thread pool or runtime, and
        // the child does nothing but call `f` and `_exit`.
        #[allow(unsafe_code)]
        let side = unsafe { fork::fork_process() }?;
        match side {
            fork::Side::Child => {
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(false);
                fork::exit_immediately_unflushed(i32::from(!ok));
            }
            fork::Side::Parent(pid) => {
                let Some(pid) = rustix::process::Pid::from_raw(pid) else {
                    return Err("fork returned an invalid pid".into());
                };
                let status =
                    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())?;
                let exit_status = status.and_then(|(_, s)| s.exit_status());
                assert_eq!(
                    exit_status,
                    Some(0),
                    "child exited non-zero or was signalled"
                );
                Ok(())
            }
        }
    }

    fn fixture_allowlist(root: &Path) -> Result<Allowlist, Box<dyn std::error::Error>> {
        static TARGETS: &[Target] = &[Target {
            path: PathSpec::new("/etc/hosts"),
            kind: TargetKind::File,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: always,
        }];
        static HOSTS: ModuleDescriptor = ModuleDescriptor {
            id: "hosts",
            display_name_id: MessageId::new("hosts-name"),
            targets: TARGETS,
            upstream: UPSTREAM,
            services: &[],
            checks: &[],
            commit_confirm: false,
            security_notes: &[],
        };
        Ok(Allowlist::from_modules(
            &[&HOSTS],
            &Config::with_state_root(root),
        )?)
    }

    #[test]
    fn no_new_privs_is_set_afterwards() -> Result<(), Box<dyn std::error::Error>> {
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-nnp-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            // `Role::Monitor`, not `Worker`: verifying this reads
            // `/proc/self/status` *after* confinement, and the worker's
            // seccomp table deliberately has no filesystem syscalls at all
            // (Phase 2 scope — see the `WORKER` table's doc comment), so
            // that read would itself be `EPERM`'d, masking the thing this
            // test actually checks. The monitor's table does allow it, and
            // `no_new_privs` is applied identically for both roles.
            let Ok(confinement) = confine(Role::Monitor, &Policy::monitor(&allow)) else {
                return false;
            };
            let applied = matches!(confinement.no_new_privs, super::super::Outcome::Applied);
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let reported = status.lines().any(|l| l == "NoNewPrivs:\t1");
            applied && reported
        })
    }

    /// Shrinking the bounding set needs `CAP_SETPCAP` in the *effective* set.
    ///
    /// The monitor has it, because it starts as root — but a CI runner does
    /// not: an ordinary user has `CapEff: 0` with a full `CapBnd`, and
    /// `caps::drop` answers `EPERM`. The test therefore asserts the behaviour
    /// appropriate to the environment it is running in, rather than skipping,
    /// so the unprivileged case still pins something: that a refused drop is
    /// *reported* as refused and never mistaken for success.
    #[test]
    fn capability_bounding_set_shrinks_to_the_policy_set() -> Result<(), Box<dyn std::error::Error>>
    {
        let privileged =
            caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_SETPCAP)
                .unwrap_or(false);

        in_forked_child(move || {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-caps-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            let Ok(confinement) = confine(Role::Monitor, &Policy::monitor(&allow)) else {
                return false;
            };

            if !privileged {
                // No CAP_SETPCAP: the drop cannot succeed, and the one thing
                // that must hold is that `confine` says so instead of
                // claiming a confinement it did not get.
                return matches!(confinement.caps, super::super::Outcome::Unavailable { .. });
            }

            if !matches!(confinement.caps, super::super::Outcome::Applied) {
                return false;
            }
            let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
                return false;
            };
            let Some(line) = status.lines().find(|l| l.starts_with("CapBnd:")) else {
                return false;
            };
            let Some(hex) = line.split_whitespace().nth(1) else {
                return false;
            };
            let Ok(mask) = u64::from_str_radix(hex, 16) else {
                return false;
            };
            // CAP_DAC_OVERRIDE=1, CAP_CHOWN=0, CAP_FOWNER=3: exactly bits
            // 0, 1, 3 set, nothing else.
            mask == 0b1011
        })
    }

    #[test]
    fn landlock_reports_its_abi_and_denies_writes_outside_the_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-ll-{}", std::process::id()));
            let allowed = dir.join("allowed");
            if std::fs::create_dir_all(&allowed).is_err() {
                return false;
            }
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            // `Role::Monitor`'s seccomp table, for the same reason as
            // `no_new_privs_is_set_afterwards`: this test writes files
            // *after* confinement to observe Landlock's behaviour, and the
            // worker's table has no `openat` at all in Phase 2. Using the
            // monitor's table (which does) lets the write attempts reach
            // Landlock instead of being `EPERM`'d by seccomp first.
            let mut policy = Policy::monitor(&allow);
            policy.writable_paths = vec![allowed.clone()];
            let Ok(confinement) = confine(Role::Monitor, &policy) else {
                return false;
            };
            let applied_with_abi = matches!(
                confinement.landlock,
                super::super::LandlockOutcome::Applied { abi, .. } if abi >= 1
            );
            let write_inside_ok = std::fs::write(allowed.join("ok.txt"), b"x").is_ok();
            let write_outside_denied = std::fs::write("/tmp/denied-by-test", b"x")
                .err()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
            applied_with_abi && write_inside_ok && write_outside_denied
        })
    }

    #[test]
    fn log_mode_seccomp_lets_a_forbidden_syscall_through() -> Result<(), Box<dyn std::error::Error>>
    {
        in_forked_child(|| {
            let Ok(arch) = super::Arch::host() else {
                return false;
            };
            let Ok(program) = super::seccomp::compile(Role::Worker, arch, super::SeccompMode::Log)
            else {
                return false;
            };
            if seccompiler::apply_filter(&program).is_err() {
                return false;
            }
            // `ptrace` is on neither table. If this were `Enforce` mode the
            // process would die of `SIGSYS` right here (see
            // `enforce_mode_seccomp_kills_the_monitor_on_a_forbidden_syscall`);
            // in `Log` mode the kernel only logs the mismatch and lets the
            // call proceed (it then fails for its own unrelated reason —
            // `PTRACE_TRACEME` on a process already being traced by nothing
            // in particular is harmless — but is never `SIGSYS`ed), so
            // reaching this line at all is the assertion.
            #[allow(unsafe_code)]
            let _ = unsafe { libc_ptrace_traceme() };
            true
        })
    }

    #[test]
    fn enforce_mode_seccomp_refuses_ptrace() -> Result<(), Box<dyn std::error::Error>> {
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-sc-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            // Landlock and caps are dropped too here (the real `confine`),
            // so this exercises the full, ordered pipeline, not seccomp in
            // isolation.
            if confine(Role::Worker, &Policy::worker(&allow)).is_err() {
                return false;
            }
            // `ptrace` is not on the worker's allow-list; the worker's
            // default action is `SCMP_ACT_ERRNO(EPERM)`, so the raw syscall
            // must return `-1`/`EPERM` rather than succeeding or killing the
            // process outright.
            #[allow(unsafe_code)]
            let rc = unsafe { libc_ptrace_traceme() };
            rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(1)
        })
    }

    /// Slice W1 (STAGE4 4.3 item 5): under the real worker confinement, the
    /// audit writers' `File::sync_data()` call (`fdatasync`) on a file under
    /// the state root must succeed, not `EPERM` — the gap slice S2 hit live
    /// (`fdatasync(14) = -1 EPERM` after `POST /api/v1/system/cert/renew`).
    #[test]
    fn enforce_mode_worker_can_fdatasync_a_state_root_file()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        in_forked_child(|| {
            let dir = std::env::temp_dir()
                .join(format!("detent-sandbox-fdatasync-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            if confine(Role::Worker, &Policy::worker(&allow)).is_err() {
                return false;
            }
            let Ok(mut file) = std::fs::File::create(dir.join("audit.jsonl")) else {
                return false;
            };
            if file.write_all(b"record\n").is_err() {
                return false;
            }
            file.sync_data().is_ok()
        })
    }

    /// B11b follow-up: under the real worker confinement, `ensure_private`
    /// (called by both audit writers before each append) must tighten an
    /// existing `0755` directory under the state root to `0700`. It failed
    /// live: the helper asks for the effective uid (`geteuid`), which the
    /// `WORKER` filter refuses with `EPERM`.
    #[test]
    fn enforce_mode_worker_can_tighten_an_audit_directory() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt as _;
        in_forked_child(|| {
            let dir = std::env::temp_dir()
                .join(format!("detent-sandbox-private-dir-{}", std::process::id()));
            let audit = dir.join("audit");
            if std::fs::create_dir_all(&audit).is_err() {
                return false;
            }
            if std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o755)).is_err() {
                return false;
            }
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            if confine(Role::Worker, &Policy::worker(&allow)).is_err() {
                return false;
            }
            crate::fs::private_dir::ensure_private(&audit).is_ok()
                && std::fs::metadata(&audit)
                    .is_ok_and(|meta| meta.permissions().mode() & 0o7777 == 0o700)
        })
    }

    #[allow(unsafe_code)]
    unsafe fn libc_ptrace_traceme() -> i64 {
        unsafe extern "C" {
            fn syscall(num: std::ffi::c_long, ...) -> std::ffi::c_long;
        }
        const NR_PTRACE_AARCH64: std::ffi::c_long = 117;
        const NR_PTRACE_X86_64: std::ffi::c_long = 101;
        let nr = if cfg!(target_arch = "aarch64") {
            NR_PTRACE_AARCH64
        } else {
            NR_PTRACE_X86_64
        };
        // SAFETY: `PTRACE_TRACEME` (request 0) with the remaining arguments
        // zeroed is the documented no-target-pid form; it dereferences no
        // memory this process does not own.
        unsafe { syscall(nr, 0_i64, 0_i64, 0_i64, 0_i64) }
    }

    /// STAGE3 H6 spec test: confine as the monitor (`Enforce`, the real
    /// `confine`), then run `/bin/true` through the production runner.
    /// The parent asserts exit 0. Fails while the table forbids anything
    /// the spawn path needs; passes once it allows the full set.
    #[test]
    fn enforce_mode_monitor_can_spawn_a_validator() -> Result<(), Box<dyn std::error::Error>> {
        use crate::service::exec::{ProcessRunner, RealProcessRunner};
        use std::time::Duration;
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-spawn-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                return false;
            }
            RealProcessRunner
                .run("/bin/true", &[], Duration::from_secs(5))
                .is_ok_and(|out| out.status == Some(0) && !out.timed_out)
        })
    }

    /// A validator that needs what real ones need: `uname`, the uid calls,
    /// `findmnt` and `systemctl` (the H6 probe saw each killed by `SIGSYS`
    /// under the monitor's filter), then reads its candidate.
    static PROBE_CHECKS: &[detent_core::descriptor::ExternalCheck] =
        &[detent_core::descriptor::ExternalCheck {
            program: PathSpec::new("/bin/sh"),
            args: &[
                detent_core::descriptor::ArgTemplate::Literal("-c"),
                detent_core::descriptor::ArgTemplate::Literal(
                    "uname >/dev/null && id -u >/dev/null && findmnt --version >/dev/null \
                     && systemctl --version >/dev/null && test -s \"$0\"",
                ),
                detent_core::descriptor::ArgTemplate::TempFile,
            ],
            expects: detent_core::descriptor::CheckExpectation::ExitZero,
        }];

    /// STAGE3 H6: under the real monitor confinement, a validator run
    /// through the runner (forked before `confine`) is not bound by the
    /// monitor's seccomp filter, so it runs to completion.
    #[test]
    fn enforce_mode_monitor_runs_real_validators_through_the_runner()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::monitor::CheckRunner as _;
        use crate::privsep::runner::RunnerClient;
        use crate::privsep::spawn::{reap_child, spawn_runner};
        static PROBE: ModuleDescriptor = ModuleDescriptor {
            id: "probe",
            display_name_id: MessageId::new("probe-name"),
            targets: &[Target {
                path: PathSpec::new("/etc/hosts"),
                kind: TargetKind::File,
                mode: 0o644,
                owner: Owner::Root,
                backend_detect: always,
            }],
            upstream: UPSTREAM,
            services: &[],
            checks: PROBE_CHECKS,
            commit_confirm: false,
            security_notes: &[],
        };
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-runner-{}", std::process::id()));
            let staging = dir.join("staging");
            let candidate = staging.join("detent-validate-probe");
            if std::fs::create_dir_all(&staging).is_err()
                || std::fs::write(&candidate, b"candidate").is_err()
            {
                return false;
            }
            let Ok(allow) = Allowlist::from_modules(&[&PROBE], &Config::with_state_root(&dir))
            else {
                return false;
            };
            let Ok(runner) =
                spawn_runner(&allow, &staging, detent_core::descriptor::InitSystem::None)
            else {
                return false;
            };
            if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                return false;
            }
            let pid = runner.child_pid;
            let client = RunnerClient::new(runner.channel, &allow);
            let passed = PROBE_CHECKS.first().is_some_and(|check| {
                client
                    .run_check(check, &candidate)
                    .is_ok_and(|outcome| outcome.passed)
            });
            drop(client);
            reap_child(pid);
            passed
        })
    }

    /// B9 follow-up: the confined monitor makes its staging directory
    /// (`ensure_staging_dir`, reached by `RunCheck` and `UpdateApply`) and
    /// checks that it belongs to the monitor's effective uid. `MONITOR` does
    /// not list `geteuid` and kills the process on any call to it, so the uid
    /// must be read before confinement. The runner test above never reaches
    /// this code: it drives `RunnerClient` directly, with no `Monitor`, and
    /// makes the staging directory itself before it confines. Only the
    /// directory step is run here: the candidate file that `RunCheck` then
    /// drops calls the legacy `unlink`, which `MONITOR` also lacks (reported
    /// separately; not changed here).
    #[test]
    fn enforce_mode_monitor_checks_its_staging_directory_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::monitor::{Hooks, Monitor, ensure_staging_dir};
        in_forked_child(|| {
            let dir = std::env::temp_dir().join(format!(
                "detent-sandbox-monitor-staging-{}",
                std::process::id()
            ));
            if std::fs::create_dir_all(&dir).is_err() {
                return false;
            }
            let staging = dir.join("staging");
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            let policy = Policy::monitor(&allow);
            let _monitor = Monitor::new(allow, Hooks::default());
            if confine(Role::Monitor, &policy).is_err() {
                return false;
            }
            ensure_staging_dir(&staging).is_ok_and(|made| made == staging)
        })
    }

    /// B9 follow-up, production order: `spawn_pair` confines the monitor
    /// before the caller builds its `Monitor` (`detent serve` does this), so
    /// the effective uid must already be read by then.
    #[test]
    fn enforce_mode_monitor_built_after_spawn_pair_checks_its_staging_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::monitor::{Hooks, Monitor, ensure_staging_dir};
        use crate::privsep::spawn::{Role as SpawnRole, SpawnConfig, spawn_pair};
        struct ConfineMonitor(Policy);
        impl SandboxHooks for ConfineMonitor {
            fn confine_monitor(&self) -> Result<(), crate::privsep::spawn::SandboxError> {
                confine(Role::Monitor, &self.0)
                    .map(|_| ())
                    .map_err(|err| crate::privsep::spawn::SandboxError(err.to_string()))
            }
        }
        in_forked_child(|| {
            let dir = std::env::temp_dir().join(format!(
                "detent-sandbox-spawn-staging-{}",
                std::process::id()
            ));
            if std::fs::create_dir_all(&dir).is_err() {
                return false;
            }
            let staging = dir.join("staging");
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            let hooks = ConfineMonitor(Policy::monitor(&allow));
            let Ok(spawned) = spawn_pair(&SpawnConfig::unprivileged(), &hooks) else {
                return false;
            };
            match spawned.role {
                SpawnRole::Worker(_client) => fork::exit_immediately_unflushed(0),
                SpawnRole::Monitor(handle) => {
                    let _monitor = Monitor::new(allow, Hooks::default());
                    let made = ensure_staging_dir(&staging).is_ok_and(|made| made == staging);
                    made && matches!(handle.wait(), Ok(Some(0)))
                }
            }
        })
    }

    #[test]
    fn enforce_mode_seccomp_kills_the_monitor_on_a_forbidden_syscall()
    -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: as `in_forked_child`.
        #[allow(unsafe_code)]
        let side = unsafe { fork::fork_process() }?;
        match side {
            fork::Side::Child => {
                let dir = std::env::temp_dir()
                    .join(format!("detent-sandbox-kill-{}", std::process::id()));
                let _ = std::fs::create_dir_all(&dir);
                let allow = fixture_allowlist(&dir).unwrap_or_else(|_| {
                    fork::exit_immediately_unflushed(2);
                });
                if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                    fork::exit_immediately_unflushed(3);
                }
                // Not on the monitor's allow-list; the monitor's default
                // action is `SCMP_ACT_KILL_PROCESS`, so this must never
                // return.
                #[allow(unsafe_code)]
                let _ = unsafe { libc_ptrace_traceme() };
                fork::exit_immediately_unflushed(4);
            }
            fork::Side::Parent(pid) => {
                let Some(pid) = rustix::process::Pid::from_raw(pid) else {
                    return Err("fork returned an invalid pid".into());
                };
                let status =
                    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())?;
                // `SCMP_ACT_KILL_PROCESS` terminates the process with
                // `SIGSYS`; `exit_status()` is `None` for a signal death.
                let signalled = status.is_some_and(|(_, s)| s.exit_status().is_none());
                assert!(
                    signalled,
                    "monitor should have been killed by SIGSYS, status={status:?}"
                );
                Ok(())
            }
        }
    }

    /// C4 trace: the confined monitor of a real `detent serve` takes the
    /// state lock (`Monitor::lock`: `create_dir_all` of the state root, then
    /// `flock`). On `x86_64` `create_dir_all` issues `mkdir`, not `mkdirat`.
    /// Before `mkdir` and `flock` were in `MONITOR`, the filter killed the
    /// monitor here with `SIGSYS`.
    #[test]
    fn enforce_mode_monitor_takes_the_state_lock_and_creates_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-lock-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            if std::fs::create_dir_all(&dir).is_err() {
                return false;
            }
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                return false;
            }
            let locked = crate::privsep::monitor::Monitor::lock(&dir).is_ok();
            let created = std::fs::create_dir_all(dir.join("made/below")).is_ok()
                && dir.join("made/below").is_dir();
            locked && created
        })
    }

    /// `EPERM` from the `Acme` filter's default action.
    fn refused<T>(result: std::io::Result<T>) -> bool {
        result.err().and_then(|err| err.raw_os_error()) == Some(1)
    }

    /// A one-shot HTTPS/1.1 server on `listener`: reads one request head,
    /// answers `200` with the body `pong`.
    fn serve_one_https(
        listener: &std::net::TcpListener,
        config: std::sync::Arc<rustls::ServerConfig>,
    ) -> Result<(), String> {
        use std::io::{Read as _, Write as _};
        let (mut tcp, _) = listener.accept().map_err(|err| err.to_string())?;
        let mut conn = rustls::ServerConnection::new(config).map_err(|err| err.to_string())?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = tls.read(&mut buf).map_err(|err| err.to_string())?;
            if read == 0 {
                return Err("the client closed before the request ended".to_owned());
            }
            head.extend_from_slice(buf.get(..read).unwrap_or_default());
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong")
            .map_err(|err| err.to_string())?;
        tls.conn.send_close_notify();
        tls.flush().map_err(|err| err.to_string())
    }

    /// `GET https://localhost:<port>/` with the client stack `detent-acme`
    /// uses (`crate::order::tls13_connector` there): hyper-util's legacy
    /// client, hyper-rustls, TLS 1.3 only on aws-lc-rs, trusting `trusted`.
    /// The connector resolves `localhost` on a `spawn_blocking` thread.
    async fn fetch_over_tls(
        port: u16,
        trusted: rustls_pki_types::CertificateDer<'static>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use http_body_util::BodyExt as _;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted)?;
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build::<_, http_body_util::Empty<hyper::body::Bytes>>(connector);
        let response = client
            .get(format!("https://localhost:{port}/").parse()?)
            .await?;
        if response.status() != hyper::StatusCode::OK {
            return Err(format!("status {}", response.status()).into());
        }
        Ok(response.into_body().collect().await?.to_bytes().to_vec())
    }

    /// `write_json_atomically` in `crates/detent-acme/src/order.rs` (the
    /// account credentials store), call for call: `create_dir_all` of the
    /// parent, a stale pid-suffixed temp file removed, the temp file created
    /// `create_new` with mode `0600`, written, synced, renamed over `path`,
    /// then the parent directory synced (`detent_acme::sync_dir`); the temp
    /// file is removed on failure.
    fn write_credentials(path: &Path, json: &str) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        let write = || -> std::io::Result<()> {
            if tmp.exists() {
                std::fs::remove_file(&tmp)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)?;
            match path.parent() {
                Some(parent) => std::fs::File::open(parent)?.sync_all(),
                None => Ok(()),
            }
        };
        if let Err(err) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        Ok(())
    }

    /// The acme child's work under its enforced filter. Returns `0`, or the
    /// number of the first step that failed.
    fn acme_probe(
        port: u16,
        trusted: rustls_pki_types::CertificateDer<'static>,
        unlistened: tokio::net::TcpSocket,
        credentials: &Path,
    ) -> i32 {
        use std::net::ToSocketAddrs as _;
        // glibc/musl `getaddrinfo`, on this thread.
        if !("localhost", port)
            .to_socket_addrs()
            .is_ok_and(|mut addrs| addrs.next().is_some())
        {
            return 10;
        }
        // musl's resolver binds a UDP socket to port 0 before each query.
        if std::net::UdpSocket::bind("0.0.0.0:0").is_err() {
            return 17;
        }
        // No new listening socket: `listen` is refused.
        if !refused(std::net::TcpListener::bind("127.0.0.1:0")) {
            return 11;
        }
        // The credentials store, as `detent-acme` writes it: first into a
        // parent directory that does not exist yet, then again over a stale
        // temp file, which it removes.
        let account = credentials.join("account").join("account.json");
        let stale = account.with_extension(format!("{}.tmp", std::process::id()));
        if write_credentials(&account, "{}").is_err()
            || std::fs::write(&stale, b"stale").is_err()
            || write_credentials(&account, "{\"a\":1}").is_err()
        {
            return 12;
        }
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return 13;
        };
        runtime.block_on(async move {
            // A socket bound before the filter still cannot listen.
            if !refused(unlistened.listen(1)) {
                return 14;
            }
            match fetch_over_tls(port, trusted).await {
                Ok(body) if body == b"pong" => 0,
                Ok(_) => 15,
                Err(_) => 16,
            }
        })
    }

    /// ADR-015, through the production path: `spawn_acme` with the real
    /// [`Hooks`] confines the child as `Role::Acme`. Under that enforced
    /// filter the child resolves `localhost`, writes its credentials
    /// directory, and fetches `https://localhost:<port>/` from the parent over
    /// TLS 1.3 on a current-thread tokio runtime; a UDP socket binds to port
    /// 0 (musl's resolver), and `listen` answers `EPERM`.
    #[test]
    fn enforce_mode_acme_reaches_out_but_cannot_listen() -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::spawn::{SpawnConfig, spawn_acme};
        let dir = tempfile::tempdir()?;
        let credentials = dir.path().join("acme");
        std::fs::create_dir(&credentials)?;
        let allow = fixture_allowlist(dir.path())?;
        let hooks = Hooks::new(Policy::monitor(&allow), Policy::worker(&allow))
            .with_acme(Policy::acme(&credentials));

        let key = rcgen::KeyPair::generate()?;
        let cert =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
        let tls_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let unlistened = tokio::net::TcpSocket::new_v4()?;
        unlistened.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let trusted = cert.der().clone();

        // The fork happens before the server thread starts.
        let (handle, ()) = spawn_acme(
            &SpawnConfig::unprivileged(),
            &hooks,
            (),
            move |_channel, ()| acme_probe(addr.port(), trusted, unlistened, &credentials),
        )?;
        let server_thread = std::thread::spawn(move || {
            let served = serve_one_https(&listener, std::sync::Arc::new(tls_config));
            (served, listener)
        });
        let status = handle.wait()?;
        // Unblock `accept` if the child never connected.
        drop(std::net::TcpStream::connect(addr));
        let (served, _listener) = server_thread.join().map_err(|_| "server thread panicked")?;
        assert_eq!(status, Some(0), "the acme probe failed; server: {served:?}");
        assert!(served.is_ok(), "{served:?}");
        let account = dir.path().join("acme/account/account.json");
        assert_eq!(std::fs::read_to_string(&account)?, "{\"a\":1}");
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&account)?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::read_dir(dir.path().join("acme/account"))?.count(),
            1
        );
        Ok(())
    }

    /// Not `privsep::spawn::spawn_pair` itself (that is `spawn.rs`'s own
    /// coverage) — a manual fork exercising [`Hooks`] on both sides of a real
    /// process split and a real channel, which is what [`Hooks`] exists for.
    #[test]
    fn hooks_confine_both_roles_across_a_forked_pair() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("detent-sandbox-hooks-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let allow = fixture_allowlist(&dir)?;
        let hooks = Hooks::new(Policy::monitor(&allow), Policy::worker(&allow));

        let (mut monitor_end, worker_end) = Channel::pair()?;
        // SAFETY: as `in_forked_child`.
        #[allow(unsafe_code)]
        let side = unsafe { fork::fork_process() }?;
        match side {
            fork::Side::Child => {
                drop(monitor_end);
                let ok = hooks.confine_worker().is_ok() && hooks.confinement().is_some();
                let mut channel = worker_end;
                let ok = ok
                    && channel
                        .send(&Request::Shutdown)
                        .and_then(|()| channel.recv::<Response>())
                        .is_ok_and(|r| matches!(r, Response::ShuttingDown));
                fork::exit_immediately_unflushed(i32::from(!ok));
            }
            fork::Side::Parent(pid) => {
                drop(worker_end);
                hooks.confine_monitor().map_err(|err| err.to_string())?;
                assert!(hooks.confinement().is_some());
                let request = monitor_end.recv::<Request>()?;
                assert!(matches!(request, Request::Shutdown));
                monitor_end.send(&Response::ShuttingDown)?;
                let Some(pid) = rustix::process::Pid::from_raw(pid) else {
                    return Err("fork returned an invalid pid".into());
                };
                let status =
                    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())?;
                assert_eq!(status.and_then(|(_, s)| s.exit_status()), Some(0));
                Ok(())
            }
        }
    }
}
