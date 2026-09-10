//! Linux sandboxing: capability drop, `no_new_privs`, Landlock, and seccomp
//! for the monitor and worker roles (PLAN §2.4; ADR-001; `docs/spikes/02-sandbox.md`).
//!
//! # Portability
//!
//! Every public type here is plain, portable data with no dependency on
//! `caps`, `landlock`, or `seccompiler` — those crates are linked only under
//! `cfg(target_os = "linux")` in `crates/detent-platform/Cargo.toml`, so
//! anything in this module's public API that touched their types directly
//! would not compile on macOS. [`confine`] is the one function whose *body*
//! differs by platform, matching the pattern `privsep::spawn::harden` already
//! uses: on Linux it does the real work described below (see `linux.rs`); on
//! every other OS (in practice the macOS dev host, PLAN §1.6) it reports
//! every field `Unavailable { reason: "linux only" }` and never returns
//! `Err`, so [`crate::privsep::spawn::spawn_pair`] behaves identically on a
//! developer's Mac.
//!
//! # What [`confine`] does, on Linux, in order
//!
//! 1. `PR_SET_NO_NEW_PRIVS`.
//! 2. `PR_SET_DUMPABLE = 0`.
//! 3. Drop the capability bounding set, and the effective/permitted sets, to
//!    exactly [`Policy::retained_caps`].
//! 4. Probe the highest Landlock ABI the kernel supports (§`docs/spikes/02-sandbox.md`
//!    demonstrated `ABI::V1..V5`, `CompatLevel::HardRequirement`, keeping the
//!    highest that creates successfully); if nothing reaches ABI 1 (kernel
//!    5.13), report [`LandlockOutcome::Unavailable`] and continue — unless
//!    [`Policy::require_landlock`], in which case [`confine`] returns
//!    `Err`. Otherwise install a ruleset at the negotiated ABI under
//!    `CompatLevel::BestEffort`: read access everywhere, full access under
//!    [`Policy::writable_paths`].
//! 5. Install the seccomp allow-list **last**, so no earlier step's own
//!    syscalls (Landlock's, `caps`', the `prctl`s above) can be blocked by
//!    the filter they are setting up. See [`seccomp`] for the tables and how
//!    they were derived.
//!
//! # What is deliberately not here
//!
//! PLAN §2.4 lists `CAP_SETUID`/`CAP_SETGID`/`CAP_KILL` as capabilities the
//! monitor needs "only before the fork". [`confine_monitor`](Hooks::confine_monitor)
//! runs *after* `privsep::spawn::spawn_pair`'s fork (see that module's
//! `SandboxHooks` contract), and the worker's own privilege drop
//! (`setgroups`/`setgid`/`setuid`, in `privsep::spawn::become_worker`) already
//! happens *before* `confine_worker` is called. So neither hook in this
//! module ever needs those three capabilities: [`Policy::monitor`] retains
//! only `CAP_DAC_OVERRIDE`/`CAP_CHOWN`/`CAP_FOWNER`, and the pre-fork
//! capabilities are the whole (not-yet-split) process's concern, outside
//! `confine`'s scope entirely.

#[cfg(target_os = "linux")]
mod linux;
pub mod seccomp;

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Serialize;

pub use seccomp::{Arch, SeccompError, SeccompMode};

use crate::privsep::allowlist::Allowlist;
use crate::privsep::proto::TargetId;
use crate::privsep::spawn::{SandboxError as SpawnSandboxError, SandboxHooks};

/// Which half of the privsep pair is being confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The privileged monitor.
    Monitor,
    /// The unprivileged worker.
    Worker,
}

/// The generic tri-state outcome for a confinement step with nothing extra
/// to report. `Applied` carries no data on purpose — the step either did
/// what it says or it did not; [`LandlockOutcome`] is the one step that
/// needs more than that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// The step ran and took effect.
    Applied,
    /// The platform or kernel does not support this step; confinement
    /// continued without it.
    Unavailable {
        /// Why.
        reason: String,
    },
    /// This step was not attempted (e.g. an empty policy made it a no-op).
    Skipped {
        /// Why.
        reason: String,
    },
}

/// Landlock's enforcement level, mirroring `landlock::RulesetStatus` without
/// depending on the crate outside `cfg(target_os = "linux")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockStatus {
    /// Every requested access right is enforced.
    FullyEnforced,
    /// Some requested access rights could not be enforced (older kernel ABI).
    PartiallyEnforced,
    /// Nothing was enforced.
    NotEnforced,
}

/// Landlock's own outcome. Unlike [`Outcome`], `Applied` needs to carry the
/// negotiated ABI and enforcement level — that is the whole point of
/// reporting it to `detent doctor` and the web health panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LandlockOutcome {
    /// A ruleset was installed.
    Applied {
        /// The Landlock ABI version the ruleset was built at.
        abi: u8,
        /// How completely it could be enforced at that ABI.
        status: LandlockStatus,
    },
    /// The kernel does not support Landlock ABI 1 or above (< 5.13), or
    /// installing the ruleset failed for another reason and
    /// [`Policy::require_landlock`] was not set.
    Unavailable {
        /// Why.
        reason: String,
    },
    /// Not attempted.
    Skipped {
        /// Why.
        reason: String,
    },
}

/// What was actually applied to a confined process (PLAN §2.4). `Serialize`
/// so `detent doctor` and the web health panel can render it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Confinement {
    /// `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privs: Outcome,
    /// `PR_SET_DUMPABLE = 0`.
    pub dumpable_cleared: Outcome,
    /// Capability bounding/effective/permitted sets dropped to the policy.
    pub caps: Outcome,
    /// The Landlock ruleset.
    pub landlock: LandlockOutcome,
    /// The seccomp filter.
    pub seccomp: Outcome,
}

/// A Linux capability a [`Policy`] may retain.
///
/// Not `caps::Capability`: that type exists only under
/// `cfg(target_os = "linux")`, and [`Policy`] must be constructible (and
/// tested) on macOS too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `CAP_DAC_OVERRIDE`.
    DacOverride,
    /// `CAP_CHOWN`.
    Chown,
    /// `CAP_FOWNER`.
    Fowner,
    /// `CAP_SETUID`.
    SetUid,
    /// `CAP_SETGID`.
    SetGid,
    /// `CAP_KILL`.
    Kill,
}

/// What [`confine`] should do for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Directories [`confine`] grants full (read + write) Landlock access
    /// to. Everywhere else is read-only.
    pub writable_paths: Vec<PathBuf>,
    /// Capabilities kept in the bounding, effective, and permitted sets;
    /// everything else is dropped.
    pub retained_caps: Vec<Capability>,
    /// When true, a kernel that cannot reach Landlock ABI 1 (or a ruleset
    /// that otherwise fails to install) makes [`confine`] return `Err`
    /// instead of degrading to [`LandlockOutcome::Unavailable`]. Default
    /// `false` (PLAN §2.4: warn and continue).
    pub require_landlock: bool,
    /// When true, a seccomp filter that does not install makes [`confine`]
    /// return `Err` instead of reporting [`Outcome::Unavailable`] and
    /// running the process unfiltered.
    ///
    /// Unlike [`Policy::require_landlock`] this defaults to **true** for
    /// [`Policy::monitor`] and [`Policy::worker`], because the two failures
    /// are not alike. Landlock is genuinely missing on kernels before 5.13,
    /// which is a real deployment a detent appliance has to survive. Seccomp
    /// filtering has been present since 3.5 and is enabled on every
    /// distribution kernel, so a failure here almost always means *our table
    /// is wrong for this architecture* — which is exactly what happened once:
    /// `epoll_wait` has no `aarch64` number, the filter failed to compile,
    /// and the worker ran with no filter at all while `confine` reported
    /// success. Nothing but an `strace` revealed it. Failing closed turns
    /// that class of mistake into a refusal to start.
    pub require_seccomp: bool,
}

impl Policy {
    /// The monitor's policy: write access to every enabled target's parent
    /// directory, each target's backup directory, and the state root
    /// (`Allowlist::state_root`, which also covers the check-tmp and
    /// pending-commit-marker paths); `CAP_DAC_OVERRIDE`/`CAP_CHOWN`/`CAP_FOWNER`
    /// retained (PLAN §2.4's root-confined minimum — see the module docs for
    /// why `CAP_SETUID`/`CAP_SETGID`/`CAP_KILL` are not part of this set).
    #[must_use]
    pub fn monitor(allowlist: &Allowlist) -> Self {
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        for target in all_targets(allowlist) {
            if let Some(parent) = target.path.parent() {
                paths.insert(parent.to_path_buf());
            }
            paths.insert(target.backup_dir.clone());
        }
        paths.insert(allowlist.state_root().to_path_buf());
        Self {
            writable_paths: paths.into_iter().collect(),
            retained_caps: vec![
                Capability::DacOverride,
                Capability::Chown,
                Capability::Fowner,
            ],
            require_landlock: false,
            require_seccomp: true,
        }
    }

    /// The worker's policy: write access to the state root only, no retained
    /// capabilities.
    #[must_use]
    pub fn worker(allowlist: &Allowlist) -> Self {
        Self {
            writable_paths: vec![allowlist.state_root().to_path_buf()],
            retained_caps: Vec::new(),
            require_landlock: false,
            require_seccomp: true,
        }
    }
}

/// Every target in `allowlist`, in id order.
fn all_targets(
    allowlist: &Allowlist,
) -> impl Iterator<Item = &crate::privsep::allowlist::TargetEntry> {
    (0..allowlist.target_count()).filter_map(move |index| {
        u16::try_from(index)
            .ok()
            .and_then(|id| allowlist.target(TargetId(id)))
    })
}

/// Confinement failed in a way [`Policy`] considers fatal (currently: only
/// [`Policy::require_landlock`] with a kernel that cannot satisfy it).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SandboxError {
    /// A hardening `prctl` failed.
    #[error("cannot harden the process: {op}: {reason}")]
    Harden {
        /// Which `prctl`.
        op: &'static str,
        /// The underlying error, stringified (the concrete `std::io::Error`
        /// does not need to cross this portable boundary).
        reason: String,
    },
    /// [`Policy::require_landlock`] was set and the kernel/ruleset could not
    /// satisfy it.
    #[error("landlock is required by policy but unavailable: {0}")]
    LandlockRequired(String),
    /// [`Policy::require_seccomp`] was set and the filter did not install.
    #[error("seccomp is required by policy but the filter did not install: {0}")]
    SeccompRequired(String),
}

/// Apply `policy` to the current process as `role`.
///
/// # Errors
///
/// [`SandboxError`] — see the module docs for exactly what runs and in what
/// order. On non-Linux platforms this never returns `Err`.
#[cfg(target_os = "linux")]
pub fn confine(role: Role, policy: &Policy) -> Result<Confinement, SandboxError> {
    linux::confine(role, policy)
}

/// As the Linux [`confine`], but every field is
/// [`Outcome::Unavailable`]/[`LandlockOutcome::Unavailable`] with
/// `reason: "linux only"`.
///
/// # Errors
///
/// Never returns `Err` on this platform.
#[cfg(not(target_os = "linux"))]
pub fn confine(role: Role, policy: &Policy) -> Result<Confinement, SandboxError> {
    let _ = (role, policy);
    let reason = || "linux only".to_owned();
    Ok(Confinement {
        no_new_privs: Outcome::Unavailable { reason: reason() },
        dumpable_cleared: Outcome::Unavailable { reason: reason() },
        caps: Outcome::Unavailable { reason: reason() },
        landlock: LandlockOutcome::Unavailable { reason: reason() },
        seccomp: Outcome::Unavailable { reason: reason() },
    })
}

/// Wires [`confine`] into [`crate::privsep::spawn::spawn_pair`] via
/// [`SandboxHooks`]. Captures the resulting [`Confinement`] for each side —
/// the trait's `Result<(), SandboxError>` return type would otherwise
/// discard it — so a caller can inspect what actually happened after the
/// fork (`detent doctor`, the web health panel).
#[derive(Debug)]
pub struct Hooks {
    monitor_policy: Policy,
    worker_policy: Policy,
    result: std::sync::OnceLock<Confinement>,
}

impl Hooks {
    /// Confine the monitor with `monitor_policy` and the worker with
    /// `worker_policy`.
    #[must_use]
    pub fn new(monitor_policy: Policy, worker_policy: Policy) -> Self {
        Self {
            monitor_policy,
            worker_policy,
            result: std::sync::OnceLock::new(),
        }
    }

    /// What [`confine`] applied to *this* process, once its hook has run.
    /// `None` beforehand.
    #[must_use]
    pub fn confinement(&self) -> Option<&Confinement> {
        self.result.get()
    }
}

impl SandboxHooks for Hooks {
    fn confine_monitor(&self) -> Result<(), SpawnSandboxError> {
        let confinement = confine(Role::Monitor, &self.monitor_policy)
            .map_err(|err| SpawnSandboxError(err.to_string()))?;
        let _ = self.result.set(confinement);
        Ok(())
    }

    fn confine_worker(&self) -> Result<(), SpawnSandboxError> {
        let confinement = confine(Role::Worker, &self.worker_policy)
            .map_err(|err| SpawnSandboxError(err.to_string()))?;
        let _ = self.result.set(confinement);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, LandlockOutcome, LandlockStatus, Outcome, Policy};
    // Only the non-Linux tests below construct a `Confinement`/call `confine`
    // directly: on Linux, `confine` is the real thing (irreversible — see
    // `linux.rs`'s own test module for why it always runs in a forked child
    // there instead).
    #[cfg(not(target_os = "linux"))]
    use super::{Confinement, Hooks, Role, confine};
    use crate::privsep::allowlist::{Allowlist, Config};
    #[cfg(not(target_os = "linux"))]
    use crate::privsep::spawn::SandboxHooks;
    use detent_core::descriptor::{
        HostProfile, ModuleDescriptor, Owner, PathSpec, Target, TargetKind, Upstream,
    };
    use detent_core::diag::MessageId;
    use std::path::{Path, PathBuf};

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

    static HOSTS_TARGETS: &[Target] = &[Target {
        path: PathSpec::new("/etc/hosts"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }];

    static CHRONY_TARGETS: &[Target] = &[
        Target {
            path: PathSpec::new("/etc/chrony/chrony.conf"),
            kind: TargetKind::File,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: always,
        },
        Target {
            path: PathSpec::new("/etc/chrony/conf.d"),
            kind: TargetKind::DropInDir,
            mode: 0o755,
            owner: Owner::Named("chrony"),
            backend_detect: always,
        },
    ];

    static HOSTS: ModuleDescriptor = ModuleDescriptor {
        id: "hosts",
        display_name_id: MessageId::new("hosts-name"),
        targets: HOSTS_TARGETS,
        upstream: UPSTREAM,
        services: &[],
        checks: &[],
        commit_confirm: false,
        security_notes: &[],
    };

    static CHRONY: ModuleDescriptor = ModuleDescriptor {
        id: "chrony",
        display_name_id: MessageId::new("chrony-name"),
        targets: CHRONY_TARGETS,
        upstream: UPSTREAM,
        services: &[],
        checks: &[],
        commit_confirm: true,
        security_notes: &[],
    };

    fn fixture(root: &Path) -> Result<Allowlist, Box<dyn std::error::Error>> {
        Ok(Allowlist::from_modules(
            &[&HOSTS, &CHRONY],
            &Config::with_state_root(root),
        )?)
    }

    #[test]
    fn monitor_policy_covers_every_target_parent_backup_dir_and_the_state_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-sandbox-test");
        let allow = fixture(root)?;
        let policy = Policy::monitor(&allow);

        assert!(policy.writable_paths.contains(&PathBuf::from("/etc")));
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/etc/chrony"))
        );
        assert!(policy.writable_paths.contains(&root.to_path_buf()));
        // Every target's own per-target backup dir is covered too, even
        // though it is a subdirectory of the state root already granted.
        assert!(
            policy
                .writable_paths
                .iter()
                .any(|p| p.starts_with(root.join("backups")))
        );
        assert_eq!(
            policy.retained_caps,
            vec![
                Capability::DacOverride,
                Capability::Chown,
                Capability::Fowner
            ]
        );
        assert!(!policy.require_landlock);
        Ok(())
    }

    #[test]
    fn worker_policy_is_state_root_only_with_no_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-sandbox-test-worker");
        let allow = fixture(root)?;
        let policy = Policy::worker(&allow);
        assert_eq!(policy.writable_paths, vec![root.to_path_buf()]);
        assert!(policy.retained_caps.is_empty());
        assert!(!policy.require_landlock);
        Ok(())
    }

    #[test]
    fn an_empty_allowlist_still_yields_a_policy_rooted_at_the_state_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-sandbox-test-empty");
        let allow = Allowlist::from_modules(&[], &Config::with_state_root(root))?;
        assert_eq!(
            Policy::monitor(&allow).writable_paths,
            vec![root.to_path_buf()]
        );
        assert_eq!(
            Policy::worker(&allow).writable_paths,
            vec![root.to_path_buf()]
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn confine_is_all_unavailable_and_never_errs_off_linux()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-sandbox-test-macos");
        let allow = fixture(root)?;
        for (role, policy) in [
            (Role::Monitor, Policy::monitor(&allow)),
            (Role::Worker, Policy::worker(&allow)),
        ] {
            let confinement = confine(role, &policy)?;
            let Confinement {
                no_new_privs,
                dumpable_cleared,
                caps,
                landlock,
                seccomp,
            } = confinement;
            for outcome in [&no_new_privs, &dumpable_cleared, &caps, &seccomp] {
                assert!(
                    matches!(outcome, Outcome::Unavailable { reason } if reason == "linux only")
                );
            }
            assert!(
                matches!(landlock, LandlockOutcome::Unavailable { reason } if reason == "linux only")
            );
        }
        // `require_landlock` does not change this: there is nothing to
        // require on a platform where the whole subsystem is `linux only`.
        let mut strict = Policy::monitor(&allow);
        strict.require_landlock = true;
        assert!(confine(Role::Monitor, &strict).is_ok());
        Ok(())
    }

    // Not run on Linux: `confine_monitor`/`confine_worker` call the real
    // `confine`, which on Linux drops capabilities and installs a seccomp
    // filter on the calling thread — irreversible, and Rust's test harness
    // reuses OS threads across tests, so doing that here would corrupt
    // whichever test runs next on the same worker thread. `linux.rs` has the
    // equivalent coverage of `Hooks` run inside a forked child, per this
    // crate's convention for anything that touches real confinement.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn hooks_capture_the_confinement_result_for_later_inspection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("/tmp/detent-sandbox-test-hooks");
        let allow = fixture(root)?;
        let hooks = Hooks::new(Policy::monitor(&allow), Policy::worker(&allow));
        assert!(hooks.confinement().is_none());
        hooks.confine_monitor().map_err(|err| err.to_string())?;
        assert!(hooks.confinement().is_some());
        // A second call (as if this were the worker's own process instead)
        // just overwrites nothing: `OnceLock::set` on an already-filled cell
        // is a no-op rather than an error, which is fine here because each
        // real process only ever calls one of the two hooks.
        hooks.confine_worker().map_err(|err| err.to_string())?;
        assert!(hooks.confinement().is_some());
        Ok(())
    }

    #[test]
    fn landlock_status_serializes_to_snake_case() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            serde_json::to_string(&LandlockStatus::FullyEnforced)?,
            "\"fully_enforced\""
        );
        assert_eq!(
            serde_json::to_string(&Outcome::Applied)?,
            "{\"outcome\":\"applied\"}"
        );
        assert_eq!(
            serde_json::to_string(&LandlockOutcome::Applied {
                abi: 1,
                status: LandlockStatus::FullyEnforced
            })?,
            "{\"outcome\":\"applied\",\"abi\":1,\"status\":\"fully_enforced\"}"
        );
        Ok(())
    }

    #[test]
    fn sandbox_error_display_carries_its_detail() {
        assert!(
            super::SandboxError::Harden {
                op: "PR_SET_NO_NEW_PRIVS",
                reason: "boom".to_owned()
            }
            .to_string()
            .contains("boom")
        );
        assert!(
            super::SandboxError::LandlockRequired("no landlock".to_owned())
                .to_string()
                .contains("no landlock")
        );
    }

    /// `Target::backend_detect` is not called by anything in this module
    /// (host-specific target selection is later work); this exercises the
    /// fixtures' shared `always` function directly, matching
    /// `privsep::allowlist`'s own test of the same pattern, so its trivial
    /// body is not silently untested.
    #[test]
    fn the_test_fixtures_backend_detect_always_matches() {
        assert!(always(&HostProfile::default_for_tests()));
    }
}
