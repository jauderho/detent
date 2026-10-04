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

/// What `drop_capabilities` reports for a process that is already
/// unprivileged, or `None` when the sets must still be dropped.
///
/// An unprivileged worker can reach the hook after `setuid`. Its effective and
/// permitted sets are then empty, and it cannot shrink the bounding set any
/// more (`PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective set). The
/// caller dropped the bounding set before the uid change, so that state is
/// `Applied` only when the bounding set holds nothing beyond `retained`;
/// otherwise the leftovers are reported. The monitor (`require_caps`) keeps
/// the strict path.
fn already_unprivileged(
    effective: &CapsHashSet,
    permitted: &CapsHashSet,
    bounding: &CapsHashSet,
    retained: &HashSet<CapsCapability>,
    require_caps: bool,
) -> Option<Outcome> {
    if require_caps || !effective.is_empty() || !permitted.is_empty() {
        return None;
    }
    let mut leftover: Vec<CapsCapability> = bounding.difference(retained).copied().collect();
    if leftover.is_empty() {
        return Some(Outcome::Applied);
    }
    leftover.sort_by_key(CapsCapability::index);
    let names: Vec<String> = leftover.iter().map(ToString::to_string).collect();
    Some(Outcome::Unavailable {
        reason: format!(
            "the bounding set still holds {} and cannot be dropped without CAP_SETPCAP",
            names.join(", ")
        ),
    })
}

fn drop_capabilities(policy: &Policy) -> Outcome {
    let retain: HashSet<CapsCapability> = policy
        .retained_caps
        .iter()
        .copied()
        .map(to_caps_capability)
        .collect();
    if let (Ok(effective), Ok(permitted), Ok(bounding)) = (
        caps::read(None, CapSet::Effective),
        caps::read(None, CapSet::Permitted),
        caps::read(None, CapSet::Bounding),
    ) && let Some(outcome) = already_unprivileged(
        &effective,
        &permitted,
        &bounding,
        &retain,
        policy.require_caps,
    ) {
        return outcome;
    }
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
    drop_bounding_to(retain)?;
    let retained: CapsHashSet = retain.iter().copied().collect();
    caps::set(None, CapSet::Effective, &retained).map_err(|err| err.to_string())?;
    caps::set(None, CapSet::Permitted, &retained).map_err(|err| err.to_string())?;
    Ok(())
}

/// Drop every capability not in `retain` from the bounding set. Needs
/// `CAP_SETPCAP` in the effective set, so a process that will change uid must
/// call it first.
fn drop_bounding_to(retain: &HashSet<CapsCapability>) -> Result<(), String> {
    let bounding = caps::read(None, CapSet::Bounding).map_err(|err| err.to_string())?;
    for cap in bounding {
        if !retain.contains(&cap) {
            caps::drop(None, CapSet::Bounding, cap).map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

/// Empty the bounding set of a process that is about to drop to an account
/// holding no capability (the worker and the acme process). A refusal is not
/// fatal: [`drop_capabilities`] reads the bounding set again afterwards and
/// reports what is left.
pub(super) fn drop_bounding_set() {
    let _ = drop_bounding_to(&HashSet::new());
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

    /// A worker that dropped its uid holds nothing in its effective and
    /// permitted sets, and cannot shrink the bounding set any more. It must
    /// not be reported as confined while the bounding set still holds
    /// capabilities (Track C A4).
    #[test]
    fn an_unprivileged_process_is_applied_only_with_an_empty_bounding_set() {
        use super::{CapsHashSet, HashSet, already_unprivileged};
        use caps::Capability as C;
        let empty = CapsHashSet::new;
        let some = |caps: &[C]| -> CapsHashSet { caps.iter().copied().collect() };
        let none = HashSet::new();

        let leftover = already_unprivileged(
            &empty(),
            &empty(),
            &some(&[C::CAP_SETUID, C::CAP_CHOWN]),
            &none,
            false,
        );
        assert!(
            matches!(&leftover, Some(Outcome::Unavailable { reason })
                if reason.contains("CAP_CHOWN") && reason.contains("CAP_SETUID")),
            "{leftover:?}"
        );
        assert_eq!(
            already_unprivileged(&empty(), &empty(), &empty(), &none, false),
            Some(Outcome::Applied)
        );
        // The bounding set may hold exactly what the policy retains.
        let kept: HashSet<C> = [C::CAP_CHOWN].into_iter().collect();
        assert_eq!(
            already_unprivileged(&empty(), &empty(), &some(&[C::CAP_CHOWN]), &kept, false),
            Some(Outcome::Applied)
        );
        // A required drop never takes the shortcut, and neither does a
        // process that still holds an effective or permitted capability.
        assert_eq!(
            already_unprivileged(&empty(), &empty(), &empty(), &none, true),
            None
        );
        assert_eq!(
            already_unprivileged(&some(&[C::CAP_CHOWN]), &empty(), &empty(), &none, false),
            None
        );
        assert_eq!(
            already_unprivileged(&empty(), &some(&[C::CAP_CHOWN]), &empty(), &none, false),
            None
        );
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

    /// Confines the monitor with the real `confine`, for a test that goes
    /// through `spawn_pair`.
    struct ConfineMonitor(Policy);

    impl SandboxHooks for ConfineMonitor {
        fn confine_monitor(&self) -> Result<(), crate::privsep::spawn::SandboxError> {
            confine(Role::Monitor, &self.0)
                .map(|_| ())
                .map_err(|err| crate::privsep::spawn::SandboxError(err.to_string()))
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
            id: "trace",
            display_name_id: MessageId::new("trace-name"),
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

    /// Confines the worker with the real `confine`, after checking what the
    /// privilege drop left behind. The check runs first because the worker's
    /// seccomp table has no `openat`: `/proc/self/status` cannot be read
    /// afterwards.
    struct ConfineDroppedWorker(Policy);

    impl SandboxHooks for ConfineDroppedWorker {
        fn confine_worker(&self) -> Result<(), crate::privsep::spawn::SandboxError> {
            let refuse = |why: &str| crate::privsep::spawn::SandboxError(why.to_owned());
            if rustix::process::geteuid().is_root() {
                return Err(refuse("still root"));
            }
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|err| crate::privsep::spawn::SandboxError(err.to_string()))?;
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix("CapBnd:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok());
            if mask != Some(0) {
                return Err(crate::privsep::spawn::SandboxError(format!(
                    "bounding set not empty: {mask:x?}"
                )));
            }
            match confine(Role::Worker, &self.0) {
                Ok(confinement) if matches!(confinement.caps, Outcome::Applied) => Ok(()),
                Ok(confinement) => Err(crate::privsep::spawn::SandboxError(format!(
                    "caps not applied: {:?}",
                    confinement.caps
                ))),
                Err(err) => Err(crate::privsep::spawn::SandboxError(err.to_string())),
            }
        }
    }

    /// Track C A4: the worker cannot shrink the bounding set after `setuid`
    /// (`PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective set), so
    /// `spawn_pair` must empty it while the process is still root. Before the
    /// fix `CapBnd` was still full here, and `confine` reported `Applied`
    /// anyway. Skips when not root or when the `detent` account is missing,
    /// as `spawn_pair_drops_to_the_worker_account_when_root` does.
    #[test]
    fn enforce_mode_worker_drops_the_bounding_set_before_its_uid_change()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::spawn::{
            DEFAULT_WORKER_USER, Role as SpawnRole, SpawnConfig, is_root, spawn_pair,
        };
        if !is_root() || crate::privsep::users::lookup_user(DEFAULT_WORKER_USER).is_err() {
            return Ok(());
        }
        in_forked_child(|| {
            let dir = std::env::temp_dir()
                .join(format!("detent-sandbox-worker-bnd-{}", std::process::id()));
            if std::fs::create_dir_all(&dir).is_err() {
                return false;
            }
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            let hooks = ConfineDroppedWorker(Policy::worker(&allow));
            let config = SpawnConfig {
                worker_user: Some(DEFAULT_WORKER_USER.to_owned()),
                ..SpawnConfig::default()
            };
            let Ok(spawned) = spawn_pair(&config, &hooks) else {
                return false;
            };
            match spawned.role {
                SpawnRole::Worker(_client) => fork::exit_immediately_unflushed(0),
                SpawnRole::Monitor(handle) => {
                    spawned.dropped_privileges && matches!(handle.wait(), Ok(Some(0)))
                }
            }
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

    /// Fork, confine the child as the monitor (`Enforce`, the real
    /// `confine`), run `act`, and return the signal that ended the child
    /// (`None` when it exited). Exit codes: 2 no allow-list, 3 `confine`
    /// failed, 4 `act` returned.
    fn confined_monitor_death(
        tag: &str,
        act: fn(),
    ) -> Result<Option<i32>, Box<dyn std::error::Error>> {
        // SAFETY: as `in_forked_child`.
        #[allow(unsafe_code)]
        let side = unsafe { fork::fork_process() }?;
        match side {
            fork::Side::Child => {
                let dir = std::env::temp_dir().join(format!("{tag}{}", std::process::id()));
                let _ = std::fs::create_dir_all(&dir);
                let allow = fixture_allowlist(&dir).unwrap_or_else(|_| {
                    fork::exit_immediately_unflushed(2);
                });
                if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                    fork::exit_immediately_unflushed(3);
                }
                act();
                fork::exit_immediately_unflushed(4);
            }
            fork::Side::Parent(pid) => {
                let Some(pid) = rustix::process::Pid::from_raw(pid) else {
                    return Err("fork returned an invalid pid".into());
                };
                let status =
                    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())?;
                Ok(status.and_then(|(_, s)| s.terminating_signal()))
            }
        }
    }

    /// Track C A1: validators and `systemctl` run in the runner, so the
    /// monitor filter allows no process creation. Confine as the monitor,
    /// then `exec` `/bin/true` in place (`CommandExt::exec`: no fork and no
    /// pipes, unlike `spawn`). The monitor's default action is
    /// `SCMP_ACT_KILL_PROCESS`, so the child must die by `SIGSYS` and never
    /// reach its exit call.
    #[test]
    fn enforce_mode_monitor_dies_by_sigsys_on_execve() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::process::CommandExt;
        let signal = confined_monitor_death("detent-sandbox-exec-", || {
            let _ = std::process::Command::new("/bin/true").exec();
        })?;
        assert_eq!(
            signal,
            Some(rustix::process::Signal::SYS.as_raw()),
            "monitor should have been killed by SIGSYS"
        );
        Ok(())
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
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-runner-{}", std::process::id()));
            let staging = dir.join("staging");
            // The runner reads the candidate beside the module's target, as
            // the monitor writes it.
            let etc = dir.join("etc");
            let candidate = etc.join(".detent-candidate-probe");
            if std::fs::create_dir_all(&staging).is_err()
                || std::fs::create_dir_all(&etc).is_err()
                // The runner trusts no group- or other-writable directory.
                || std::fs::set_permissions(
                    &etc,
                    <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
                )
                .is_err()
                || std::fs::write(&candidate, b"candidate").is_err()
            {
                return false;
            }
            let Some(target) = etc.join("probe.conf").to_str().map(ToOwned::to_owned) else {
                return false;
            };
            let probe: &'static ModuleDescriptor = Box::leak(Box::new(ModuleDescriptor {
                id: "probe",
                display_name_id: MessageId::new("probe-name"),
                targets: Box::leak(Box::new([Target {
                    path: PathSpec::new(Box::leak(target.into_boxed_str())),
                    kind: TargetKind::File,
                    mode: 0o644,
                    owner: Owner::Root,
                    backend_detect: always,
                }])),
                upstream: UPSTREAM,
                services: &[],
                checks: PROBE_CHECKS,
                commit_confirm: false,
                security_notes: &[],
            }));
            let Ok(allow) = Allowlist::from_modules(&[probe], &Config::with_state_root(&dir))
            else {
                return false;
            };
            let Ok(runner) = spawn_runner(&allow, &staging, &HostProfile::default()) else {
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
    /// (`ensure_staging_dir`, reached by `UpdateApply`, and by `RunCheck` for
    /// a module with no file target) and checks that it belongs to the
    /// monitor's effective uid. `MONITOR` does
    /// not list `geteuid` and kills the process on any call to it, so the uid
    /// must be read before confinement. The runner test above never reaches
    /// this code: it drives `RunnerClient` directly, with no `Monitor`, and
    /// makes the staging directory itself before it confines. Only the
    /// directory step is run here; the candidate file that `RunCheck` then
    /// removes is covered by `enforce_mode_monitor_runs_a_check_and_removes_its_candidate`.
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
        let signal = confined_monitor_death("detent-sandbox-kill-", || {
            // Not on the monitor's allow-list; the monitor's default
            // action is `SCMP_ACT_KILL_PROCESS`, so this must never
            // return.
            #[allow(unsafe_code)]
            let _ = unsafe { libc_ptrace_traceme() };
        })?;
        // `SCMP_ACT_KILL_PROCESS` terminates the process with `SIGSYS`.
        assert_eq!(
            signal,
            Some(rustix::process::Signal::SYS.as_raw()),
            "monitor should have been killed by SIGSYS"
        );
        Ok(())
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

    // -- A confined monitor, driven end to end ---------------------------------

    static DRIVE_CHECKS: &[detent_core::descriptor::ExternalCheck] =
        &[detent_core::descriptor::ExternalCheck {
            program: PathSpec::new("/bin/sh"),
            args: &[
                detent_core::descriptor::ArgTemplate::Literal("-c"),
                detent_core::descriptor::ArgTemplate::Literal(
                    "case \"$0\" in */etc/.detent-candidate-*) test -s \"$0\" ;; *) exit 1 ;; esac",
                ),
                detent_core::descriptor::ArgTemplate::TempFile,
            ],
            expects: detent_core::descriptor::CheckExpectation::ExitZero,
        }];

    type Json = serde_json::Value;
    type DynResult<T> = Result<T, detent_core::module::DynError>;

    /// A module with one target, and a check that runs.
    struct DriveModule(&'static ModuleDescriptor);

    impl detent_core::module::DynModule for DriveModule {
        fn id(&self) -> &'static str {
            self.0.id
        }
        fn descriptor(&self) -> &'static ModuleDescriptor {
            self.0
        }
        fn clone_box(&self) -> Box<dyn detent_core::module::DynModule> {
            Box::new(Self(self.0))
        }
        fn schema_json(&self) -> Json {
            Json::Null
        }
        fn parse_to_model_json(&self, src: &str) -> DynResult<Json> {
            Ok(serde_json::json!({ "text": src }))
        }
        fn apply_json(&self, src: &str, _model: &Json) -> DynResult<String> {
            Ok(src.to_owned())
        }
        fn validate_json(
            &self,
            _model: &Json,
            _ctx: &detent_core::descriptor::ValidationCtx<'_>,
        ) -> DynResult<detent_core::diag::Diagnostics> {
            Ok(detent_core::diag::Diagnostics::new())
        }
        fn defaults_json(&self, _profile: &HostProfile) -> DynResult<Json> {
            Ok(Json::Null)
        }
    }

    /// What a confined-monitor scenario, which runs in the worker, works on.
    struct Drive {
        state: std::path::PathBuf,
        target: std::path::PathBuf,
        #[cfg(feature = "update")]
        binary: std::path::PathBuf,
        staging: std::path::PathBuf,
        module: crate::privsep::proto::ModuleId,
        target_id: crate::privsep::proto::TargetId,
        check: crate::privsep::proto::CheckId,
    }

    /// The descriptor of the module a confined-monitor scenario serves.
    fn drive_descriptor(target_path: &str) -> &'static ModuleDescriptor {
        Box::leak(Box::new(ModuleDescriptor {
            id: "trace",
            display_name_id: MessageId::new("trace-name"),
            targets: Box::leak(Box::new([Target {
                path: PathSpec::new(Box::leak(target_path.to_owned().into_boxed_str())),
                kind: TargetKind::File,
                mode: 0o644,
                owner: Owner::Root,
                backend_detect: always,
            }])),
            upstream: UPSTREAM,
            services: &[],
            checks: DRIVE_CHECKS,
            commit_confirm: true,
            security_notes: &[],
        }))
    }

    /// The tag and the Sigstore fixtures of a release the verifier accepts.
    #[cfg(feature = "update")]
    const FIXTURE_TAG: &str = "v99.0.0";

    #[cfg(feature = "update")]
    fn fixture_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../detent-update/tests/fixtures")
    }

    #[cfg(feature = "update")]
    fn fixture_trust() -> Result<detent_update::trust::TrustRoot, Box<dyn std::error::Error>> {
        let root = std::fs::read_to_string(fixture_dir().join("fulcio-root.pem"))?;
        let rekor = std::fs::read_to_string(fixture_dir().join("rekor-pub.pem"))?;
        Ok(detent_update::trust::from_pems(&root, &rekor)?)
    }

    /// Run a real confined `Role::Monitor` (`Monitor::serve`, the real
    /// dispatch, a real runner for the check) against a worker that runs
    /// `scenario`. The test passes only when the worker's requests all
    /// succeed and the monitor exits after `Shutdown`. A syscall outside
    /// `MONITOR` kills the monitor with `SIGSYS`, which fails the forked
    /// child's exit check. `prepare` gets the state root before the fork.
    fn drive_confined_monitor(
        keep_backups: usize,
        prepare: fn(&Path) -> bool,
        scenario: fn(&mut crate::privsep::worker::Client, &Drive) -> bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::monitor::{ExitReason, Hooks, Monitor, NoServices};
        use crate::privsep::proto::PathKind;
        use crate::privsep::runner::RunnerClient;
        use crate::privsep::spawn::{
            Role as SpawnRole, SpawnConfig, reap_child, spawn_pair, spawn_runner,
        };
        let work = tempfile::TempDir::new()?;
        let state = work.path().join("state");
        let target = work.path().join("etc/target.conf");
        let staging = state.join("staging");
        // The running binary `ReplaceBinary` swaps: beside the target, so the
        // monitor's Landlock policy covers it (production: `current_exe`).
        let binary = work.path().join("etc/detent-old");
        std::fs::create_dir_all(&state)?;
        let etc = target.parent().ok_or("the target has no parent")?;
        std::fs::create_dir_all(etc)?;
        // Candidates are written here: it must pass the monitor's
        // candidate-directory check whatever the umask.
        std::fs::set_permissions(
            etc,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )?;
        std::fs::write(&target, b"v1")?;
        std::fs::write(&binary, b"old-binary")?;
        std::fs::set_permissions(
            &binary,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )?;
        let target_name = target.to_str().ok_or("target is not UTF-8")?.to_owned();
        let descriptor = drive_descriptor(&target_name);
        let config = Config {
            keep_backups,
            ..Config::with_state_root(&state)
        };
        let allow = Allowlist::from_modules(&[descriptor], &config)?;
        assert!(prepare(&state), "the scenario could not prepare its files");
        let runner = spawn_runner(&allow, &staging, &HostProfile::default())?;
        let runner_pid = runner.child_pid;
        let hooks = ConfineMonitor(Policy::monitor(&allow));
        #[cfg(feature = "update")]
        let trust = fixture_trust()?;
        // The runner ends when the last copy of its channel closes: the
        // forked child's, and this thread's own, which the closure holds.
        in_forked_child(move || {
            let Ok(spawned) = spawn_pair(&SpawnConfig::unprivileged(), &hooks) else {
                return false;
            };
            match spawned.role {
                SpawnRole::Worker(mut client) => {
                    drop(runner);
                    let ok = client.hello().is_ok()
                        && client
                            .module_id("trace")
                            .zip(client.target_id("trace", &target_name, PathKind::File))
                            .zip(client.check_id("trace"))
                            .is_some_and(|((module, target_id), check)| {
                                let drive = Drive {
                                    state,
                                    target,
                                    #[cfg(feature = "update")]
                                    binary,
                                    staging,
                                    module,
                                    target_id,
                                    check,
                                };
                                scenario(&mut client, &drive)
                            })
                        && client.shutdown().is_ok();
                    // Not confined: the coverage profile is written.
                    fork::exit_immediately(i32::from(!ok))
                }
                SpawnRole::Monitor(mut handle) => {
                    let checker = RunnerClient::new(runner.channel, &allow);
                    let hooks = Hooks {
                        checks: &checker,
                        services: &NoServices,
                    };
                    let mut monitor = Monitor::new(allow, hooks);
                    monitor.set_module_registry(vec![Box::new(DriveModule(descriptor))]);
                    monitor.set_staging_dir(staging);
                    monitor.set_binary_override(binary);
                    #[cfg(feature = "update")]
                    monitor.set_update_trust(trust);
                    let served = monitor.serve(&mut handle.channel);
                    drop(monitor);
                    drop(checker);
                    matches!(served, Ok(ExitReason::Shutdown))
                        && matches!(handle.wait(), Ok(Some(0)))
                }
            }
        })?;
        reap_child(runner_pid);
        Ok(())
    }

    /// Write `bytes` to the target, guarded by the digest of its current
    /// contents, and keep a rollback entry.
    fn drive_write(
        client: &mut crate::privsep::worker::Client,
        drive: &Drive,
        bytes: &[u8],
    ) -> bool {
        client.read_target(drive.target_id).is_ok_and(|current| {
            client
                .write_target(drive.target_id, Some(current.digest), bytes.to_vec(), true)
                .is_ok_and(|receipt| receipt.backed_up)
        })
    }

    /// True when the monitor's staging directory holds no file.
    fn drive_staging_is_empty(drive: &Drive) -> bool {
        std::fs::read_dir(&drive.staging).is_ok_and(|mut entries| entries.next().is_none())
    }

    /// True when no candidate file is left beside the target.
    fn drive_left_no_candidate(drive: &Drive) -> bool {
        drive
            .target
            .parent()
            .and_then(|dir| std::fs::read_dir(dir).ok())
            .is_some_and(|entries| {
                entries.flatten().all(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".detent-candidate-")
                })
            })
    }

    /// `RunCheck` writes a candidate file beside the target, the runner runs
    /// the check on it there (the check fails anywhere else), and the
    /// monitor removes it.
    #[test]
    fn enforce_mode_monitor_runs_a_check_and_removes_its_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |_| true,
            |client, drive| {
                client
                    .run_check(drive.check, b"candidate".to_vec())
                    .is_ok_and(|outcome| outcome.passed)
                    && drive_left_no_candidate(drive)
            },
        )
    }

    /// `WriteTarget` of a module that has a check runs the check on a
    /// candidate file, removes it, and backs the old contents up.
    #[test]
    fn enforce_mode_monitor_writes_a_target_that_has_a_check_and_a_backup()
    -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |_| true,
            |client, drive| {
                drive_write(client, drive, b"v2")
                    && drive_left_no_candidate(drive)
                    && std::fs::read(&drive.target).is_ok_and(|now| now == b"v2")
            },
        )
    }

    /// More writes than `keep_backups` rotate the oldest backup away.
    #[test]
    fn enforce_mode_monitor_rotates_backups() -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |_| true,
            |client, drive| {
                (2..=6).all(|n| drive_write(client, drive, format!("v{n}").as_bytes()))
                    && client
                        .list_backups(drive.module)
                        .is_ok_and(|backups| backups.len() == 2)
            },
        )
    }

    /// `Restore` puts a backup back over the target.
    #[test]
    fn enforce_mode_monitor_restores_a_backup() -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |_| true,
            |client, drive| {
                drive_write(client, drive, b"v2")
                    && client
                        .list_backups(drive.module)
                        .ok()
                        .and_then(|backups| backups.first().map(|newest| newest.id))
                        .is_some_and(|newest| client.restore(drive.module, newest).is_ok())
                    && std::fs::read(&drive.target).is_ok_and(|now| now == b"v1")
            },
        )
    }

    /// A `ReplaceBinary` that fails verification removes the monitor's own
    /// copy of the candidate image (B4's cleanup guard).
    #[test]
    fn enforce_mode_monitor_removes_the_staged_copy_of_a_refused_release()
    -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |state| {
                let staged = state.join("update/staged");
                std::fs::create_dir_all(&staged).is_ok()
                    && std::fs::write(staged.join("v999.0.0"), b"not a release").is_ok()
            },
            |client, drive| {
                let digest = crate::fs::atomic::Sha256Digest::of(b"not a release");
                matches!(
                    client.replace_binary("v999.0.0", 13, digest),
                    Err(crate::privsep::worker::ClientError::Remote(
                        crate::privsep::proto::ProtoError::VerificationFailed
                    ))
                ) && !drive.staging.join(digest.to_string()).exists()
            },
        )
    }

    /// Confirming and rolling back a commit remove the crash-recovery marker.
    #[test]
    fn enforce_mode_monitor_clears_the_commit_marker() -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::proto::CommitId;
        drive_confined_monitor(
            2,
            |_| true,
            |client, drive| {
                let marker = drive
                    .state
                    .join(crate::privsep::monitor::PENDING_COMMIT_MARKER);
                drive_write(client, drive, b"v2")
                    && client.start_confirm_timer(CommitId(1), 60, None).is_ok()
                    && marker.exists()
                    && client.confirm_commit(CommitId(1)).is_ok()
                    && !marker.exists()
                    && drive_write(client, drive, b"v3")
                    && client.start_confirm_timer(CommitId(2), 60, None).is_ok()
                    && client.rollback_commit(CommitId(2)).is_ok()
                    && !marker.exists()
            },
        )
    }

    /// Startup recovery of a marker a dead monitor left removes it.
    #[test]
    fn enforce_mode_monitor_removes_a_recovered_commit_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |state| {
                std::fs::write(
                    state.join(crate::privsep::monitor::PENDING_COMMIT_MARKER),
                    br#"{"commit":1,"deadline_unix_ms":0,"entries":[]}"#,
                )
                .is_ok()
            },
            |_, drive| {
                !drive
                    .state
                    .join(crate::privsep::monitor::PENDING_COMMIT_MARKER)
                    .exists()
            },
        )
    }

    /// A `ReplaceBinary` that passes verification swaps the new image over
    /// the running binary with `rename` and keeps the old one as `.prev`.
    #[cfg(feature = "update")]
    #[test]
    fn enforce_mode_monitor_swaps_a_verified_release() -> Result<(), Box<dyn std::error::Error>> {
        drive_confined_monitor(
            2,
            |state| {
                let staged = state.join("update/staged");
                std::fs::create_dir_all(&staged).is_ok()
                    && std::fs::copy(fixture_dir().join("binary.bin"), staged.join(FIXTURE_TAG))
                        .is_ok()
                    && std::fs::copy(
                        fixture_dir().join("valid.json"),
                        staged.join(format!("{FIXTURE_TAG}.sigstore.json")),
                    )
                    .is_ok()
            },
            |client, drive| {
                let Ok(image) = std::fs::read(fixture_dir().join("binary.bin")) else {
                    return false;
                };
                let digest = crate::fs::atomic::Sha256Digest::of(&image);
                let previous = drive.binary.with_file_name("detent-old.prev");
                client
                    .replace_binary(FIXTURE_TAG, image.len() as u64, digest)
                    .is_ok_and(|version| version == digest.to_string())
                    && std::fs::read(&drive.binary).is_ok_and(|now| now == image)
                    && std::fs::read(&previous).is_ok_and(|old| old == b"old-binary")
                    && std::fs::metadata(&drive.binary).is_ok_and(|meta| {
                        std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777
                            == 0o755
                    })
                    && drive_staging_is_empty(drive)
            },
        )
    }

    /// The previous-binary copy that `swap_running_binary` falls back to when
    /// the filesystem refuses a hard link, run under the monitor's filter.
    #[test]
    fn enforce_mode_monitor_copies_the_previous_binary() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let work = tempfile::TempDir::new()?;
        let target = work.path().join("detent");
        let previous = work.path().join("detent.prev");
        std::fs::write(&target, b"old-binary")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750))?;
        let allow = Allowlist::from_modules(&[], &Config::with_state_root(work.path()))?;
        let policy = Policy::monitor(&allow);
        in_forked_child(|| {
            confine(Role::Monitor, &policy).is_ok()
                && crate::privsep::monitor::copy_file(&target, &previous).is_ok()
        })?;
        assert_eq!(std::fs::read(&previous)?, b"old-binary");
        assert_eq!(
            std::fs::metadata(&previous)?.permissions().mode() & 0o7777,
            0o750
        );
        Ok(())
    }
}
