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

use std::io::{Read as _, Write as _};
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
/// Each method is called after its fork and after the worker or the acme
/// process has dropped its uid, which is the only moment at which a Landlock ruleset or a seccomp
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

    /// Confine the acme process ([`spawn_acme`], ADR-015).
    ///
    /// # Errors
    ///
    /// Any confinement failure the implementor considers fatal.
    fn confine_acme(&self) -> Result<(), SandboxError> {
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
        wait_for(self.child_pid)
    }
}

/// `waitpid(2)` on `child_pid`: its exit status, or `None` when a signal
/// killed it.
fn wait_for(child_pid: i32) -> std::io::Result<Option<i32>> {
    let Some(pid) = rustix::process::Pid::from_raw(child_pid) else {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    let status = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
        .map_err(std::io::Error::from)?;
    Ok(status.and_then(|(_, status)| status.exit_status()))
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

    let side = fork()?;

    // The worker waits for this byte before it can return as a usable role;
    // dropping the monitor end makes a failed startup exit.
    match side {
        Side::Parent(child_pid) => {
            drop(worker_end);
            let handle = MonitorHandle {
                child_pid,
                channel: monitor_end,
            };
            if let Err(err) = sandbox.confine_monitor() {
                drop(handle.channel);
                reap_child(child_pid);
                return Err(SpawnError::Sandbox(err));
            }
            if let Err(source) = handle.channel.socket().write_all(&[0]) {
                drop(handle.channel);
                reap_child(child_pid);
                return Err(SpawnError::Channel(ChannelError::Io(source)));
            }
            Ok(Spawned {
                role: Role::Monitor(handle),
                dropped_privileges: credentials.is_some(),
            })
        }
        Side::Child => {
            drop(monitor_end);
            let mut started = [0_u8; 1];
            if worker_end.socket().read_exact(&mut started).is_err() {
                abort_child(1);
            }
            let Ok(dropped) = become_worker(credentials, sandbox) else {
                abort_child(1);
            };
            Ok(Spawned {
                role: Role::Worker(Box::new(Client::new(worker_end))),
                dropped_privileges: dropped,
            })
        }
    }
}

/// `fork(2)`, for [`spawn_pair`], [`spawn_runner`] and [`spawn_acme`].
///
/// SAFETY of the fork itself is documented on `sys::fork_process`. The
/// obligation it places on the caller — do nothing in the child that could
/// deadlock on a lock held by a thread that did not survive the fork — is met
/// by both callers forking before any runtime or thread pool starts, and by
/// their child paths doing nothing but syscalls and small allocations.
fn fork() -> Result<Side, SpawnError> {
    #[allow(unsafe_code)]
    let side = unsafe { sys::fork_process() }.map_err(SpawnError::Fork)?;
    Ok(side)
}

/// The monitor's handle on the runner (STAGE3 H6).
#[derive(Debug)]
pub struct RunnerHandle {
    /// Pid of the runner process; reap it with [`reap_child`] once the
    /// channel is dropped.
    pub child_pid: i32,
    /// The monitor's end of the runner channel. Build a
    /// [`RunnerClient`](super::runner::RunnerClient) on it. A worker forked
    /// after the runner inherits this descriptor and must drop it first.
    pub channel: Channel,
}

/// Fork the runner, which answers [`RunnerRequest`](super::runner::RunnerRequest)s
/// with the real validator and service hooks, unconfined, until its channel
/// closes. Call it before [`spawn_pair`], so that the monitor's confinement
/// does not reach the runner's children.
///
/// # Errors
///
/// [`SpawnError::Channel`] and [`SpawnError::Fork`].
pub fn spawn_runner(
    allow: &super::allowlist::Allowlist,
    staging_dir: &std::path::Path,
    init: detent_core::descriptor::InitSystem,
) -> Result<RunnerHandle, SpawnError> {
    let (monitor_end, runner_end) =
        Channel::pair_with(super::runner::RUNNER_TIMEOUT, super::runner::RUNNER_TIMEOUT)
            .map_err(SpawnError::Channel)?;
    match fork()? {
        Side::Parent(child_pid) => {
            drop(runner_end);
            Ok(RunnerHandle {
                child_pid,
                channel: monitor_end,
            })
        }
        Side::Child => {
            drop(monitor_end);
            let mut channel = runner_end;
            let checks = crate::service::checks::ExternalCheckRunner::new();
            let services = crate::service::ServiceControlAdapter(crate::service::for_host(init));
            let hooks = super::monitor::Hooks {
                checks: &checks,
                services: &services,
            };
            super::runner::serve_runner(allow, staging_dir, &hooks, &mut channel);
            abort_child(0);
        }
    }
}

/// The parent's handle on the acme process (ADR-015).
#[derive(Debug)]
pub struct AcmeHandle {
    /// Pid of the acme process. The monitor keeps it and reaps it at
    /// shutdown.
    pub child_pid: i32,
    /// The worker's end of the acme channel. The monitor/worker pair forked
    /// after [`spawn_acme`] inherits it: the monitor drops it, the worker
    /// answers on it with [`acme_link`](super::acme::acme_link).
    pub channel: Channel,
}

impl AcmeHandle {
    /// Reap the acme process, blocking until it exits.
    ///
    /// Returns its exit status, or `None` when it was killed by a signal.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when `waitpid(2)` fails.
    pub fn wait(&self) -> std::io::Result<Option<i32>> {
        wait_for(self.child_pid)
    }
}

/// The acme child's exit status when `body` panics (Rust's own panic status).
const PANIC_STATUS: i32 = 101;

/// Fork the acme process (ADR-015). Call it after [`spawn_runner`] and before
/// [`spawn_pair`], before any thread or runtime starts.
///
/// The child hardens itself (`no_new_privs`, not dumpable), drops to
/// `config.worker_user` as the worker does, runs
/// [`SandboxHooks::confine_acme`], and then runs `body` on its end of the
/// channel and `inherited`. It exits with `body`'s return value and never
/// returns to the caller: it exits `101` when `body` panics. A child that
/// cannot drop or confine itself exits `1` without running `body`.
///
/// The child inherits every descriptor of the parent. The caller puts in
/// `inherited` every value the acme process must not keep, above all the
/// [`RunnerHandle`]: the runner is privileged and unconfined, and the acme
/// process must never be able to send it a request. `body` must drop
/// `inherited` first, before it runs any other code. The parent gets
/// `inherited` back unchanged.
///
/// The channel's timeouts are [`ACME_TIMEOUT`](super::acme::ACME_TIMEOUT),
/// not `config`'s.
///
/// # Errors
///
/// [`SpawnError::Account`] (checked before the fork), [`SpawnError::Channel`]
/// and [`SpawnError::Fork`]. The parent's `inherited` is dropped with the
/// error.
pub fn spawn_acme<T, F>(
    config: &SpawnConfig,
    sandbox: &dyn SandboxHooks,
    inherited: T,
    body: F,
) -> Result<(AcmeHandle, T), SpawnError>
where
    F: FnOnce(Channel, T) -> i32,
{
    let credentials = resolve_worker_account(config)?;
    let (worker_end, acme_end) =
        Channel::pair_with(super::acme::ACME_TIMEOUT, super::acme::ACME_TIMEOUT)
            .map_err(SpawnError::Channel)?;
    match fork()? {
        Side::Parent(child_pid) => {
            drop(acme_end);
            Ok((
                AcmeHandle {
                    child_pid,
                    channel: worker_end,
                },
                inherited,
            ))
        }
        Side::Child => {
            drop(worker_end);
            if drop_and_confine(credentials, || sandbox.confine_acme()).is_err() {
                abort_child(1);
            }
            // A panic must not unwind into the caller's stack in the child.
            let status = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                body(acme_end, inherited)
            }))
            .unwrap_or(PANIC_STATUS);
            abort_confined_child(status);
        }
    }
}

/// Reap a forked child, blocking until it exits.
pub fn reap_child(child_pid: i32) {
    if let Some(pid) = rustix::process::Pid::from_raw(child_pid) {
        let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
    }
}

/// Terminate a forked child that cannot continue, without running the parent's
/// `atexit` handlers. Exposed so a caller whose child setup fails after
/// [`spawn_pair`] returns can exit the same way.
pub fn abort_child(status: i32) -> ! {
    sys::exit_immediately(status)
}

/// [`abort_child`] for a child that already installed its sandbox: it writes
/// nothing on the way out (not even a coverage profile, whose file writes the
/// seccomp filter would refuse or punish).
pub fn abort_confined_child(status: i32) -> ! {
    sys::exit_immediately_unflushed(status)
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
    drop_and_confine(credentials, || sandbox.confine_worker())
}

/// Harden, drop to `credentials` when given, then `confine`. True when the
/// uid changed.
fn drop_and_confine(
    credentials: Option<(u32, u32)>,
    confine: impl FnOnce() -> Result<(), SandboxError>,
) -> Result<bool, SpawnError> {
    harden()?;
    let dropped = match credentials {
        Some((uid, gid)) => {
            sys::drop_to(uid, gid).map_err(|source| SpawnError::DropPrivileges { uid, source })?;
            true
        }
        None => false,
    };
    confine().map_err(SpawnError::Sandbox)?;
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
        spawn_acme, spawn_pair,
    };
    use crate::privsep::acme::{ACME_PROTO_VERSION, ACME_TIMEOUT, AcmeMessage};
    use crate::privsep::allowlist::{Allowlist, Config};
    use crate::privsep::monitor::{ExitReason, Hooks, Monitor};
    use crate::privsep::transport::{Channel, ChannelError, DEFAULT_TIMEOUT};
    use std::time::Duration;

    #[test]
    fn wait_reports_an_invalid_pid_without_calling_waitpid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (channel, _peer) = Channel::pair()?;
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
        Ok(())
    }

    struct Refuses;

    impl SandboxHooks for Refuses {
        fn confine_worker(&self) -> Result<(), SandboxError> {
            Err(SandboxError("no".to_owned()))
        }
    }

    struct RefusesMonitor;

    impl SandboxHooks for RefusesMonitor {
        fn confine_monitor(&self) -> Result<(), SandboxError> {
            Err(SandboxError("monitor refused".to_owned()))
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

    #[test]
    fn a_failed_worker_setup_exits_instead_of_returning() -> Result<(), Box<dyn std::error::Error>>
    {
        let spawned = spawn_pair(&SpawnConfig::unprivileged(), &Refuses)?;
        let Role::Monitor(handle) = spawned.role else {
            return Err("failed child unexpectedly returned to its caller".into());
        };
        assert_eq!(handle.wait()?, Some(1));
        Ok(())
    }

    struct RefusesAcme;

    impl SandboxHooks for RefusesAcme {
        fn confine_acme(&self) -> Result<(), SandboxError> {
            Err(SandboxError("acme refused".to_owned()))
        }
    }

    /// ADR-015: the acme child runs the caller's body, and the parent gets
    /// the body's return value as the child's exit status. Unprivileged, as
    /// the worker tests: no account drop, no real sandbox.
    #[test]
    fn spawn_acme_runs_the_body_in_a_child_and_reports_its_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = rustix::process::getpid();
        let (mut handle, ()) = spawn_acme(
            &SpawnConfig::unprivileged(),
            &NoSandbox,
            (),
            |mut channel, ()| {
                let in_child = rustix::process::getppid() == Some(parent);
                let sent = channel
                    .send(&AcmeMessage::Hello {
                        version: ACME_PROTO_VERSION,
                    })
                    .is_ok();
                if in_child && sent { 7 } else { 1 }
            },
        )?;
        assert_eq!(handle.channel.read_timeout(), ACME_TIMEOUT);
        assert_eq!(
            handle.channel.recv::<AcmeMessage>()?,
            AcmeMessage::Hello {
                version: ACME_PROTO_VERSION
            }
        );
        assert_eq!(handle.wait()?, Some(7));
        assert!(NoSandbox.confine_acme().is_ok());
        Ok(())
    }

    /// A panicking body ends the child with status 101; it never unwinds
    /// into the caller's stack (here: the test harness) in the child.
    #[test]
    fn a_panicking_acme_body_exits_101() -> Result<(), Box<dyn std::error::Error>> {
        let (handle, ()) = spawn_acme(&SpawnConfig::unprivileged(), &NoSandbox, (), |_, ()| {
            // A second mutable borrow of a `RefCell` panics.
            let cell = std::cell::RefCell::new(0);
            let _first = cell.borrow_mut();
            let _second = cell.borrow_mut();
            0
        })?;
        assert_eq!(handle.wait()?, Some(101));
        Ok(())
    }

    /// The parent gets `inherited` back, and the child's copy is gone once
    /// the body drops it: the peer of an inherited channel sees `Closed`
    /// while the child is still alive. A child that kept its copy would make
    /// `recv` time out instead.
    #[test]
    fn the_acme_child_drops_what_it_inherits_and_the_parent_keeps_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let short = Duration::from_secs(5);
        let (kept, mut peer) = Channel::pair_with(short, short)?;
        let (mut handle, kept) = spawn_acme(
            &SpawnConfig::unprivileged(),
            &NoSandbox,
            kept,
            |mut channel, inherited| {
                drop(inherited);
                // Stay alive until the parent has checked the peer.
                i32::from(channel.recv::<AcmeMessage>().is_err())
            },
        )?;
        assert_eq!(kept.read_timeout(), short);
        drop(kept);
        assert!(matches!(
            peer.recv::<AcmeMessage>(),
            Err(ChannelError::Closed)
        ));
        handle.channel.send(&AcmeMessage::Hello {
            version: ACME_PROTO_VERSION,
        })?;
        assert_eq!(handle.wait()?, Some(0));
        Ok(())
    }

    #[test]
    fn a_failed_acme_setup_exits_before_the_body_runs() -> Result<(), Box<dyn std::error::Error>> {
        let (mut handle, ()) =
            spawn_acme(&SpawnConfig::unprivileged(), &RefusesAcme, (), |_, ()| 0)?;
        assert_eq!(handle.wait()?, Some(1));
        assert!(matches!(
            handle.channel.recv::<AcmeMessage>(),
            Err(ChannelError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn a_failed_monitor_setup_returns_an_error_and_reaps_its_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let Err(SpawnError::Sandbox(err)) =
            spawn_pair(&SpawnConfig::unprivileged(), &RefusesMonitor)
        else {
            return Err("monitor setup failure did not return Sandbox".into());
        };
        assert_eq!(err.0, "monitor refused");
        Ok(())
    }

    /// The real thing: fork, speak the protocol across the process boundary,
    /// and reap the child.
    #[test]
    fn spawn_pair_forks_a_working_pair() -> Result<(), Box<dyn std::error::Error>> {
        let uid_before = rustix::process::geteuid().as_raw();
        let config = SpawnConfig {
            // Never drop privileges in the test suite, even when it runs as
            // root in a container: the child must stay able to talk back.
            worker_user: None,
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
        };
        let spawned = spawn_pair(&config, &NoSandbox)?;
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
                let state = tempfile::tempdir()?;
                let allow = Allowlist::from_modules(&[], &Config::with_state_root(state.path()))?;
                let mut monitor = Monitor::new(allow, Hooks::default());
                let reason = monitor.serve(&mut handle.channel);
                assert_eq!(reason.ok(), Some(ExitReason::Shutdown));
                assert_eq!(handle.wait().ok(), Some(Some(0)));
                assert!(handle.child_pid > 0);
            }
        }
        Ok(())
    }

    /// The privileged path: `spawn_pair_forks_a_working_pair` above always
    /// passes `worker_user: None`, so `sys::drop_to`, the root branch of
    /// `resolve_worker_account`, and `become_worker`'s `Some(credentials)`
    /// branch are never exercised there — those lines only run when the
    /// monitor actually starts as root with a worker account configured.
    /// Skips cleanly (not a failure) when not root, which is the normal case
    /// on a developer machine and in most CI jobs; the privileged CI job runs
    /// this in a container as root with the `detent` system account
    /// provisioned (see PLAN §6.1 `privileged-tests.yml`), which is also how
    /// to reproduce it locally: `docker run --rm -v "$PWD:/src" -w /src
    /// rust:1-bookworm bash -c "useradd -r detent && cargo test -p
    /// detent-platform --all-features"`.
    #[test]
    fn spawn_pair_drops_to_the_worker_account_when_root() -> Result<(), Box<dyn std::error::Error>>
    {
        if !is_root() {
            return Ok(());
        }
        // Root alone is not enough: the account must also exist. A CI runner or
        // a bare container is often root without a `detent` user, and this test
        // must skip there rather than fail on the environment.
        if crate::privsep::users::lookup_user(DEFAULT_WORKER_USER).is_err() {
            return Ok(());
        }
        let config = SpawnConfig {
            // The documented default account (PLAN §2.10); the privileged CI
            // job and the reproduction command above both provision it.
            worker_user: Some(DEFAULT_WORKER_USER.to_owned()),
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
        };
        let spawned = spawn_pair(&config, &NoSandbox)?;
        assert!(spawned.dropped_privileges);

        match spawned.role {
            Role::Worker(mut client) => {
                // Child, now running as the unprivileged `detent` account.
                // Anything that goes wrong here must not run the test
                // harness's exit handlers, or the parent sees a duplicated
                // test report.
                let ok = !rustix::process::geteuid().is_root()
                    && client.hello().is_ok()
                    && client.shutdown().is_ok();
                super::abort_child(i32::from(!ok));
            }
            Role::Monitor(handle) => {
                let mut handle = handle;
                let state = tempfile::tempdir()?;
                let allow = Allowlist::from_modules(&[], &Config::with_state_root(state.path()))?;
                let mut monitor = Monitor::new(allow, Hooks::default());
                let reason = monitor.serve(&mut handle.channel);
                assert_eq!(reason.ok(), Some(ExitReason::Shutdown));
                assert_eq!(handle.wait().ok(), Some(Some(0)));
                assert!(handle.child_pid > 0);
            }
        }
        Ok(())
    }
}
