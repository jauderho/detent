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
    let landlock = install_landlock(policy)?;
    // Seccomp last: every syscall the steps above need has already run, so
    // installing their allow-list first would risk `SIGSYS`-ing them.
    let seccomp = install_seccomp(role);

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

fn drop_capabilities(policy: &Policy) -> Outcome {
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
    use super::super::{Hooks, Policy, Role, confine};
    use crate::privsep::allowlist::{Allowlist, Config};
    use crate::privsep::proto::{Request, Response};
    use crate::privsep::spawn::SandboxHooks;
    use crate::privsep::transport::Channel;
    use detent_core::descriptor::{
        HostProfile, ModuleDescriptor, Owner, PathSpec, Target, TargetKind, Upstream,
    };
    use detent_core::diag::MessageId;
    use std::path::Path;

    /// A private `fork`/`_exit` pair, scoped to this test module.
    ///
    /// `privsep::sys::fork_process`/`exit_immediately` do exactly this and
    /// are the crate's normal place for it — but that module is `mod sys`
    /// (private to `privsep`, not `pub(crate)`), so it is not reachable from
    /// `sandbox`, and this task's allowed diff does not include
    /// `privsep/mod.rs`. This duplicates the same two `extern "C"`
    /// declarations with the same `// SAFETY:` reasoning and the same
    /// isolation discipline (one small module, every `unsafe` commented)
    /// rather than inventing a different one.
    #[allow(unsafe_code)]
    mod fork {
        use std::ffi::c_int;

        unsafe extern "C" {
            fn fork() -> c_int;
            fn _exit(status: c_int) -> !;
        }

        /// Which side of a [`fork_process`] this is.
        pub enum Side {
            /// The original process; carries the child's pid.
            Parent(i32),
            /// The new process.
            Child,
        }

        /// `fork(2)`.
        ///
        /// # Safety
        ///
        /// As `privsep::sys::fork_process`: call before any thread pool or
        /// runtime starts, and treat the child as async-signal-safe
        /// territory only.
        pub unsafe fn fork_process() -> std::io::Result<Side> {
            // SAFETY: `fork` takes no arguments and touches no memory this
            // process owns; the only hazard is what the caller does
            // afterward in the child, which is this function's own `unsafe`
            // contract.
            let pid = unsafe { fork() };
            if pid < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(if pid == 0 {
                Side::Child
            } else {
                Side::Parent(pid)
            })
        }

        /// `_exit(2)`: terminate immediately, without unwinding, flushing,
        /// or running `atexit`/test-harness teardown.
        pub fn exit_immediately(status: c_int) -> ! {
            // SAFETY: `_exit` is async-signal-safe by definition, never
            // returns, and dereferences nothing.
            unsafe { _exit(status) }
        }
    }

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
    /// `exit_immediately` is used instead of a normal return so the child
    /// never runs the parent's `atexit`/test harness teardown.
    fn in_forked_child(f: impl FnOnce() -> bool) -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: forking before starting any thread pool or runtime, and
        // the child does nothing but call `f` and `_exit`.
        #[allow(unsafe_code)]
        let side = unsafe { fork::fork_process() }?;
        match side {
            fork::Side::Child => {
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(false);
                fork::exit_immediately(i32::from(!ok));
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

    #[test]
    fn capability_bounding_set_shrinks_to_the_policy_set() -> Result<(), Box<dyn std::error::Error>>
    {
        in_forked_child(|| {
            let dir =
                std::env::temp_dir().join(format!("detent-sandbox-caps-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let Ok(allow) = fixture_allowlist(&dir) else {
                return false;
            };
            let Ok(confinement) = confine(Role::Monitor, &Policy::monitor(&allow)) else {
                return false;
            };
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
                    fork::exit_immediately(2);
                });
                if confine(Role::Monitor, &Policy::monitor(&allow)).is_err() {
                    fork::exit_immediately(3);
                }
                // Not on the monitor's allow-list; the monitor's default
                // action is `SCMP_ACT_KILL_PROCESS`, so this must never
                // return.
                #[allow(unsafe_code)]
                let _ = unsafe { libc_ptrace_traceme() };
                fork::exit_immediately(4);
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
                fork::exit_immediately(i32::from(!ok));
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
