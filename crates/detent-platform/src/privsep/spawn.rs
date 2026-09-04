//! Creating the monitor/worker pair (PLAN §2.4; ADR-001).
//!
//! `detent` ships as **one binary that forks**, never as a setuid helper and
//! never as an `exec` of a second program: an `exec` would need the worker's
//! path on disk to be trustworthy, and a setuid bit is exactly the thing
//! ADR-001 rejects. [`spawn_pair`] therefore creates a socket pair, forks, and
//! hands each side its own role.
//!
//! # What the child does before it is a worker
//!
//! In order, and only what is possible on the platform:
//!
//! 1. Drop the parent's end of the socket pair.
//! 2. Linux: `PR_SET_NO_NEW_PRIVS`, so no later `execve` can regain privilege.
//! 3. Linux: `PR_SET_DUMPABLE = 0`, so the process is not core-dumpable and
//!    `/proc/self` becomes root-owned.
//! 4. If `geteuid() == 0` and a worker account is configured: `setgroups([])`,
//!    `setgid`, `setuid`. When not root, this is skipped and reported in
//!    [`Spawned::dropped_privileges`] rather than failing — an unprivileged
//!    developer run is a supported mode (spike 02 showed the sandbox works
//!    unprivileged).
//! 5. [`SandboxHooks::confine_worker`].
//!
//! The parent calls [`SandboxHooks::confine_monitor`] and keeps its end.
//!
//! # Sandbox hook points
//!
//! Landlock and seccomp are a later Phase 2 subtask. They plug in through
//! [`SandboxHooks`] without this module changing: the default [`NoSandbox`]
//! does nothing, and both hooks run at the one point in the process lifetime
//! where confinement is still possible but privilege is no longer needed.

use std::time::Duration;

use super::sys::{self, Side};
use super::transport::{Channel, ChannelError, DEFAULT_TIMEOUT};
use super::users::{self, LookupError};
use super::worker::Client;

/// Default unprivileged account for the worker (PLAN §2.10).
pub const DEFAULT_WORKER_USER: &str = "detent";

/// How the pair should be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnConfig {
    /// Account the worker drops to when the monitor is root. `None` keeps the
    /// current credentials, which is only sensible in tests and in an
    /// unprivileged developer run.
    pub worker_user: Option<String>,
    /// Read timeout applied to both channels.
    pub read_timeout: Duration,
    /// Write timeout applied to both channels.
    pub write_timeout: Duration,
}

impl Default for SpawnConfig {
    fn default() -> Self {
        Self {
            worker_user: Some(DEFAULT_WORKER_USER.to_owned()),
            read_timeout: DEFAULT_TIMEOUT,
            write_timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl SpawnConfig {
    /// A configuration that keeps the current credentials.
    #[must_use]
    pub fn unprivileged() -> Self {
        Self {
            worker_user: None,
            ..Self::default()
        }
    }
}

/// Confinement applied to each role once its privileges are final.
///
/// Both methods are called after the fork and after the worker has dropped its
/// uid, which is the only moment at which a Landlock ruleset or a seccomp
/// filter can be installed with the right scope.
pub trait SandboxHooks {
    /// Confine the privileged monitor.
    ///
    /// # Errors
    ///
    /// Any confinement failure the implementor considers fatal.
    fn confine_monitor(&self) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Confine the unprivileged worker.
    ///
    /// # Errors
    ///
    /// Any confinement failure the implementor considers fatal.
    fn confine_worker(&self) -> Result<(), SandboxError> {
        Ok(())
    }
}

/// Confinement failed in a way the implementor considers fatal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("sandbox setup failed: {0}")]
pub struct SandboxError(pub String);

/// A [`SandboxHooks`] that confines nothing. The default until the
/// Landlock/seccomp subtask lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSandbox;

impl SandboxHooks for NoSandbox {}

/// Creating the pair failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpawnError {
    /// The socket pair could not be created or configured.
    #[error("cannot create the privsep socket pair")]
    Channel(#[source] ChannelError),
    /// The configured worker account does not exist.
    #[error("cannot resolve the worker account")]
    Account(#[source] LookupError),
    /// `fork(2)` failed.
    #[error("fork failed")]
    Fork(#[source] std::io::Error),
    /// A privilege-dropping call failed in the child.
    #[error("cannot drop privileges to uid {uid}")]
    DropPrivileges {
        /// The uid that was being switched to.
        uid: u32,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A hardening `prctl` failed in the child.
    #[error("cannot harden the worker process: {op}")]
    Harden {
        /// Which `prctl` failed.
        op: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A [`SandboxHooks`] implementation refused to continue.
    #[error("sandbox refused to start")]
    Sandbox(#[source] SandboxError),
}

/// The privileged side's handle on the pair.
#[derive(Debug)]
pub struct MonitorHandle {
    /// Pid of the worker process.
    pub child_pid: i32,
    /// The monitor's end of the socket pair.
    pub channel: Channel,
}

impl MonitorHandle {
    /// Reap the worker, blocking until it exits.
    ///
    /// Returns its exit status, or `None` when it was killed by a signal.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when `waitpid(2)` fails.
    pub fn wait(&self) -> std::io::Result<Option<i32>> {
        let Some(pid) = rustix::process::Pid::from_raw(self.child_pid) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let status = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
            .map_err(std::io::Error::from)?;
        Ok(status.and_then(|(_, status)| status.exit_status()))
    }
}

/// Which half of the pair the caller became.
#[derive(Debug)]
pub enum Role {
    /// The parent: privileged, serves requests.
    Monitor(MonitorHandle),
    /// The child: unprivileged, makes requests.
    Worker(Box<Client>),
}

/// The outcome of [`spawn_pair`], including what actually happened to the
/// child's credentials.
#[derive(Debug)]
pub struct Spawned {
    /// The role this process now has.
    pub role: Role,
    /// True when the worker's uid was actually changed. False when the process
    /// was not root — the caller should surface that as a degraded state in
    /// `detent doctor` rather than pretending it is confined.
    pub dropped_privileges: bool,
}

/// True when this process can drop privileges at all.
#[must_use]
pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Create the socket pair, fork, and put each side into its role.
///
/// # Errors
///
/// [`SpawnError::Account`] when the configured worker user does not exist —
/// checked in the *parent*, before the fork, so a misconfiguration is a clean
/// startup failure rather than a child that dies silently. Then
/// [`SpawnError::Channel`], [`SpawnError::Fork`], and in the child
/// [`SpawnError::Harden`], [`SpawnError::DropPrivileges`] and
/// [`SpawnError::Sandbox`].
pub fn spawn_pair(config: &SpawnConfig, sandbox: &dyn SandboxHooks) -> Result<Spawned, SpawnError> {
    let credentials = resolve_worker_account(config)?;
    let (monitor_end, worker_end) = Channel::pair_with(config.read_timeout, config.write_timeout)
        .map_err(SpawnError::Channel)?;

    // SAFETY of the fork itself is documented on `sys::fork_process`. The
    // obligation it places on the caller — do nothing in the child that could
    // deadlock on a lock held by a thread that did not survive the fork — is
    // met by forking before any runtime or thread pool starts, and by the
    // child path below doing nothing but syscalls and one small allocation.
    #[allow(unsafe_code)]
    let side = unsafe { sys::fork_process() }.map_err(SpawnError::Fork)?;

    match side {
        Side::Parent(child_pid) => {
            drop(worker_end);
            sandbox.confine_monitor().map_err(SpawnError::Sandbox)?;
            Ok(Spawned {
                role: Role::Monitor(MonitorHandle {
                    child_pid,
                    channel: monitor_end,
                }),
                dropped_privileges: credentials.is_some(),
            })
        }
        Side::Child => {
            drop(monitor_end);
            let dropped = become_worker(credentials, sandbox)?;
            Ok(Spawned {
                role: Role::Worker(Box::new(Client::new(worker_end))),
                dropped_privileges: dropped,
            })
        }
    }
}

/// Terminate a forked child that cannot continue, without running the parent's
/// `atexit` handlers. Exposed so a caller whose child setup fails after
/// [`spawn_pair`] returns can exit the same way.
pub fn abort_child(status: i32) -> ! {
    sys::exit_immediately(status)
}

/// Resolve the account to drop to, or `None` when no drop will happen.
fn resolve_worker_account(config: &SpawnConfig) -> Result<Option<(u32, u32)>, SpawnError> {
    let Some(name) = config.worker_user.as_deref() else {
        return Ok(None);
    };
    if !is_root() {
        // Not root: there is nothing to drop, and resolving the account would
        // fail on a developer machine that has no `detent` user.
        return Ok(None);
    }
    let ids = users::lookup_user(name).map_err(SpawnError::Account)?;
    Ok(Some((ids.uid, ids.gid)))
}

/// Everything the child does between `fork` and being a worker.
fn become_worker(
    credentials: Option<(u32, u32)>,
    sandbox: &dyn SandboxHooks,
) -> Result<bool, SpawnError> {
    harden()?;
    let dropped = match credentials {
        Some((uid, gid)) => {
            sys::drop_to(uid, gid).map_err(|source| SpawnError::DropPrivileges { uid, source })?;
            true
        }
        None => false,
    };
    sandbox.confine_worker().map_err(SpawnError::Sandbox)?;
    Ok(dropped)
}

/// `no_new_privs` and `dumpable = 0`.
///
/// Both are Linux `prctl`s with no macOS equivalent; on macOS this is a
/// documented no-op, consistent with PLAN §1.6's "service control and Linux
/// sandboxing are `cfg(target_os = "linux")` with a documented no-op on macOS".
#[cfg(target_os = "linux")]
fn harden() -> Result<(), SpawnError> {
    rustix::thread::set_no_new_privs(true).map_err(|err| SpawnError::Harden {
        op: "PR_SET_NO_NEW_PRIVS",
        source: err.into(),
    })?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).map_err(
        |err| SpawnError::Harden {
            op: "PR_SET_DUMPABLE",
            source: err.into(),
        },
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn harden() -> Result<(), SpawnError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_WORKER_USER, MonitorHandle, NoSandbox, Role, SandboxError, SandboxHooks,
        SpawnConfig, SpawnError, become_worker, harden, is_root, resolve_worker_account,
        spawn_pair,
    };
    use crate::privsep::allowlist::{Allowlist, Config};
    use crate::privsep::monitor::{ExitReason, Hooks, Monitor};
    use crate::privsep::transport::{Channel, DEFAULT_TIMEOUT};
    use std::time::Duration;

    #[test]
    fn wait_reports_an_invalid_pid_without_calling_waitpid() {
        let Ok((channel, _peer)) = Channel::pair() else {
            unreachable!("socketpair must succeed")
        };
        // `Pid::from_raw` rejects 0 and negative values; no real fork ever
        // produces one, but `MonitorHandle`'s fields are public, so a
        // malformed handle is directly constructible for this edge case.
        let handle = MonitorHandle {
            child_pid: 0,
            channel,
        };
        assert_eq!(
            handle.wait().err().map(|err| err.kind()),
            Some(std::io::ErrorKind::InvalidInput)
        );
    }

    struct Refuses;

    impl SandboxHooks for Refuses {
        fn confine_worker(&self) -> Result<(), SandboxError> {
            Err(SandboxError("no".to_owned()))
        }
    }

    #[test]
    fn the_default_configuration_names_the_documented_account() {
        let config = SpawnConfig::default();
        assert_eq!(config.worker_user.as_deref(), Some(DEFAULT_WORKER_USER));
        assert_eq!(config.read_timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.write_timeout, DEFAULT_TIMEOUT);
        assert_eq!(SpawnConfig::unprivileged().worker_user, None);
        assert_eq!(config, SpawnConfig::default());
        assert!(format!("{config:?}").contains("detent"));
    }

    #[test]
    fn account_resolution_is_skipped_when_it_cannot_apply() {
        // No account configured: nothing to resolve, root or not.
        assert_eq!(
            resolve_worker_account(&SpawnConfig::unprivileged()).ok(),
            Some(None)
        );
        let missing = SpawnConfig {
            worker_user: Some("detent-no-such-account".to_owned()),
            ..SpawnConfig::default()
        };
        if is_root() {
            // Running as root, an unknown account must be a clean failure.
            assert!(matches!(
                resolve_worker_account(&missing),
                Err(SpawnError::Account(_))
            ));
            // ... and a known one must resolve.
            let root = SpawnConfig {
                worker_user: Some("root".to_owned()),
                ..SpawnConfig::default()
            };
            assert_eq!(resolve_worker_account(&root).ok(), Some(Some((0, 0))));
        } else {
            // Not root: no drop is attempted, so the account is never looked
            // up and a missing one is not an error.
            assert_eq!(resolve_worker_account(&missing).ok(), Some(None));
        }
    }

    #[test]
    fn hardening_succeeds_on_this_platform() {
        // On Linux these `prctl`s work unprivileged (spike 02); on macOS this
        // is the documented no-op.
        assert!(harden().is_ok());
    }

    #[test]
    fn a_refusing_sandbox_stops_the_worker_from_starting() {
        assert!(matches!(
            become_worker(None, &Refuses),
            Err(SpawnError::Sandbox(_))
        ));
        assert_eq!(become_worker(None, &NoSandbox).ok(), Some(false));
        assert!(SandboxError("x".to_owned()).to_string().contains('x'));
        assert!(NoSandbox.confine_monitor().is_ok());
    }

    /// The real thing: fork, speak the protocol across the process boundary,
    /// and reap the child.
    #[test]
    fn spawn_pair_forks_a_working_pair() {
        let uid_before = rustix::process::geteuid().as_raw();
        let config = SpawnConfig {
            // Never drop privileges in the test suite, even when it runs as
            // root in a container: the child must stay able to talk back.
            worker_user: None,
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
        };
        let Ok(spawned) = spawn_pair(&config, &NoSandbox) else {
            unreachable!("spawn_pair must succeed")
        };
        assert!(!spawned.dropped_privileges);

        match spawned.role {
            Role::Worker(mut client) => {
                // Child. Anything that goes wrong here must not run the test
                // harness's exit handlers, or the parent sees a duplicated
                // test report.
                let ok = client.hello().is_ok()
                    && rustix::process::geteuid().as_raw() == uid_before
                    && client.shutdown().is_ok();
                super::abort_child(i32::from(!ok));
            }
            Role::Monitor(handle) => {
                let mut handle = handle;
                let Ok(allow) = Allowlist::from_modules(&[], &Config::default()) else {
                    unreachable!("an empty allow-list is valid")
                };
                let mut monitor = Monitor::new(allow, Hooks::default());
                let reason = monitor.serve(&mut handle.channel);
                assert_eq!(reason.ok(), Some(ExitReason::Shutdown));
                assert_eq!(handle.wait().ok(), Some(Some(0)));
                assert!(handle.child_pid > 0);
            }
        }
    }
}
