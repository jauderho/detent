//! The privileged side of the privsep pair (PLAN §2.4, §2.5; ADR-001).
//!
//! The monitor is deliberately boring: one blocking loop, no `async`, no
//! threads, no TLS, no HTTP. It reads one [`Request`], performs exactly one
//! privileged action selected by an allow-list index, and writes exactly one
//! [`Response`]. A frame it cannot decode, or one that claims to be larger than
//! [`MAX_FRAME`](super::proto::MAX_FRAME), ends the loop with
//! [`ExitReason::ProtocolViolation`] so the supervisor restarts the pair.
//!
//! # Commit-confirm
//!
//! PLAN §2.5 puts the commit-confirm timer *here*, not in the worker, because
//! the whole point is to survive the worker becoming unreachable. Every
//! successful [`Request::WriteTarget`] that produced a backup is appended to a
//! journal. [`Request::StartConfirmTimer`] takes the journal, records it as the
//! single pending commit together with a deadline, and writes a
//! `pending-commit.json` marker. If [`Request::ConfirmCommit`] does not arrive
//! before the deadline, the monitor restores every recorded backup. If the
//! monitor itself dies first, [`Monitor::recover_pending`] does the same thing
//! at the next startup — which is why the marker records absolute paths rather
//! than ids: the module set may differ after an upgrade.
//!
//! The deadline is checked on every loop iteration, using a short receive
//! timeout while a commit is pending. There is no timer thread, so there is no
//! shared mutable state and no lock ordering to get wrong.
//!
//! Running external validators and driving service managers are separate Phase
//! 2 subtasks. They enter through [`CheckRunner`] and [`ServiceControl`]; the
//! default [`NoChecks`]/[`NoServices`] implementations answer
//! [`ProtoError::Unavailable`]. `Mount` goes to the same hook
//! ([`ServiceControl::start_added_mounts`]); before any rollback restores a
//! target of a module that declares mounts, the monitor has the units that
//! apply started stopped ([`ServiceControl::stop_started_mounts`]), and a
//! confirm forgets them.

use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use detent_core::descriptor::{
    ExternalCheck, HostProfile, ServiceAction as CoreServiceAction, ServiceBinding, ValidationCtx,
};
use detent_core::module::DynModule;
use serde::{Deserialize, Serialize};

use super::allowlist::{Allowlist, CANDIDATE_PREFIX};
use super::proto::{
    BackupId, BackupInfo, BindingId, CheckId, CheckOutcome, CommitId, IdKind, ModuleId,
    MountOutcome, PendingService, ProtoError, Request, Response, ServiceAction, ServiceOutcome,
    TargetContents, TargetId, WriteReceipt,
};
use super::transport::{Channel, ChannelError};
use crate::fs::atomic::{
    AtomicError, BackupEntry, InPlace, InPlaceMarker, WriteRequest, list_backups, read_with_digest,
    remove_marker, restore_backup_with, write_atomic,
};
use crate::service::MountUnitState;

/// Name of the crash-recovery marker inside the state root.
pub const PENDING_COMMIT_MARKER: &str = "pending-commit.json";

/// Name of the write-in-progress marker of an in-place write
/// ([`InPlaceMarker`]) inside the state root.
pub const IN_PLACE_MARKER: &str = "write-in-progress.json";

/// Exclusive monitor-lifetime lock inside the state root.
pub const MONITOR_LOCK: &str = "monitor.lock";

/// How often the loop wakes to re-check a pending commit-confirm deadline.
const PENDING_POLL: Duration = Duration::from_millis(20);

/// Upper bound on a commit-confirm timeout, in seconds. A worker cannot pin a
/// rollback indefinitely far into the future.
pub const MAX_CONFIRM_TIMEOUT_S: u16 = 3600;

/// Longest excerpt of a validator's output relayed to the worker.
const DETAIL_LIMIT: usize = 512;

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/// A collaborator the monitor needs is not present.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HookError {
    /// The subsystem is not wired up in this build or on this host.
    #[error("{0}")]
    Unavailable(String),
    /// The subsystem was present but failed.
    #[error("{0}")]
    Failed(String),
}

impl From<HookError> for ProtoError {
    fn from(err: HookError) -> Self {
        match err {
            HookError::Unavailable(message) => Self::Unavailable(message),
            HookError::Failed(message) => Self::Io(message),
        }
    }
}

/// Runs an upstream validator against a candidate file.
///
/// The candidate is written by the monitor to a file it owns; the implementor
/// receives the *static* [`ExternalCheck`] declaration and the path, and never
/// sees anything the worker sent except the file contents.
pub trait CheckRunner {
    /// Run `check` against the candidate file at `candidate`.
    ///
    /// # Errors
    ///
    /// [`HookError::Unavailable`] when no process execution is available,
    /// [`HookError::Failed`] when the validator could not be run.
    fn run_check(&self, check: &ExternalCheck, candidate: &Path)
    -> Result<CheckOutcome, HookError>;

    /// Whether this runner has a configured implementation.
    fn configured(&self) -> bool {
        true
    }
}

/// Drives the host's service manager.
pub trait ServiceControl {
    /// Apply `action` to `binding`.
    ///
    /// # Errors
    ///
    /// [`HookError::Unavailable`] when no service manager is available,
    /// [`HookError::Failed`] when the action could not be applied.
    fn service(
        &self,
        binding: &ServiceBinding,
        action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError>;

    /// Ask the init system to re-read its unit files, for a module whose
    /// descriptor sets `reload_unit_files`. Returns a short detail.
    ///
    /// The default answers [`HookError::Unavailable`], as [`NoServices`]
    /// does for every service action.
    ///
    /// # Errors
    ///
    /// [`HookError::Unavailable`] when no service manager is available,
    /// [`HookError::Failed`] when the reload failed.
    fn reload_unit_files(&self) -> Result<String, HookError> {
        Err(HookError::Unavailable(
            "service control is not available in this build".to_owned(),
        ))
    }

    /// The state of each mount unit in `units`
    /// ([`ServiceManager::mount_unit_states`](crate::service::ServiceManager::mount_unit_states)).
    /// The runner's hooks implement it; the default answers
    /// [`HookError::Unavailable`].
    ///
    /// # Errors
    ///
    /// [`HookError::Unavailable`] when no service manager or no mount
    /// support is available, [`HookError::Failed`] when the query failed.
    fn mount_unit_states(&self, _units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        Err(no_mount_units())
    }

    /// Start the mount units in `units`
    /// ([`ServiceManager::start_mount_units`](crate::service::ServiceManager::start_mount_units)).
    ///
    /// # Errors
    ///
    /// As [`ServiceControl::mount_unit_states`].
    fn start_mount_units(&self, _units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        Err(no_mount_units())
    }

    /// Stop the mount units in `units`
    /// ([`ServiceManager::stop_mount_units`](crate::service::ServiceManager::stop_mount_units)).
    ///
    /// # Errors
    ///
    /// As [`ServiceControl::mount_unit_states`].
    fn stop_mount_units(&self, _units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        Err(no_mount_units())
    }

    /// Start the mount units of the entries an apply added to `target`
    /// (`[mounts] activate_new_entries`). The runner client forwards it;
    /// the runner works out the units itself. The default answers
    /// [`HookError::Unavailable`].
    ///
    /// # Errors
    ///
    /// [`HookError::Unavailable`] when the runner or the init system cannot
    /// do it, [`HookError::Failed`] when it refused or failed.
    fn start_added_mounts(&self, _target: TargetId) -> Result<Vec<MountOutcome>, HookError> {
        Err(no_mount_units())
    }

    /// Stop the mount units the last [`ServiceControl::start_added_mounts`]
    /// started, for a rollback.
    ///
    /// # Errors
    ///
    /// As [`ServiceControl::start_added_mounts`].
    fn stop_started_mounts(&self) -> Result<Vec<MountOutcome>, HookError> {
        Err(no_mount_units())
    }

    /// Forget which mount units the last start started, after a confirm.
    ///
    /// # Errors
    ///
    /// As [`ServiceControl::start_added_mounts`].
    fn forget_started_mounts(&self) -> Result<(), HookError> {
        Err(no_mount_units())
    }
}

/// The default answer of the mount hooks of [`ServiceControl`].
fn no_mount_units() -> HookError {
    HookError::Unavailable("mount units are not available in this build".to_owned())
}

/// A [`CheckRunner`] that always reports the subsystem as absent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoChecks;

impl CheckRunner for NoChecks {
    fn configured(&self) -> bool {
        false
    }
    fn run_check(
        &self,
        _check: &ExternalCheck,
        _candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        Err(HookError::Unavailable(
            "external checks are not available in this build".to_owned(),
        ))
    }
}

/// A [`ServiceControl`] that always reports the subsystem as absent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoServices;

impl ServiceControl for NoServices {
    fn service(
        &self,
        _binding: &ServiceBinding,
        _action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        Err(HookError::Unavailable(
            "service control is not available in this build".to_owned(),
        ))
    }
}

/// The collaborators a [`Monitor`] delegates to.
pub struct Hooks<'a> {
    /// Runs external validators.
    pub checks: &'a dyn CheckRunner,
    /// Drives the service manager.
    pub services: &'a dyn ServiceControl,
}

impl std::fmt::Debug for Hooks<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hooks { .. }")
    }
}

impl Default for Hooks<'_> {
    fn default() -> Self {
        Self {
            checks: &NoChecks,
            services: &NoServices,
        }
    }
}

// ---------------------------------------------------------------------------
// Exit and errors
// ---------------------------------------------------------------------------

/// Why [`Monitor::serve`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitReason {
    /// The worker asked the monitor to stop.
    Shutdown,
    /// The worker closed the socket.
    PeerClosed,
    /// The handshake did not happen, or announced a different version.
    ProtocolMismatch,
    /// A frame was undecodable or over-large. The supervisor should restart
    /// the whole pair (PLAN §2.4).
    ProtocolViolation,
}

/// The monitor itself failed, as opposed to a request failing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MonitorError {
    /// The socket failed in a way that is not the peer's fault.
    #[error("privsep channel failed")]
    Channel(#[source] ChannelError),
    /// Another live monitor owns the state root.
    #[error("monitor is busy")]
    Busy,
    /// The state directory could not be read or written.
    #[error("{op} failed on the monitor's state directory")]
    State {
        /// What was being attempted.
        op: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The crash-recovery marker exists but cannot be parsed.
    #[error("pending-commit marker is corrupt")]
    CorruptMarker,
    /// The caller needs to change state, but the state lock cannot be taken
    /// (the state directory is not writable for this user).
    #[error("the state lock cannot be taken, so this monitor cannot change state")]
    LockUnavailable,
}

/// The monitor's hold on the state root.
///
/// Only [`StateLock::Held`] gives the mutual exclusion that state changes
/// need. [`StateLock::Unavailable`] exists so read-only commands (for example
/// `detent host`, run by a user who cannot create `/var/lib/detent`) can still
/// serve reads; a monitor in that state refuses every request that changes
/// state ([`ProtoError::StateLockUnavailable`]).
#[derive(Debug)]
pub enum StateLock {
    /// The exclusive lock on [`MONITOR_LOCK`]; released when dropped.
    Held(std::fs::File),
    /// The state directory or lock file is not accessible to this user.
    Unavailable,
}

impl StateLock {
    /// True when the exclusive lock is held.
    #[must_use]
    pub const fn is_held(&self) -> bool {
        matches!(self, Self::Held(_))
    }

    /// Fail with [`MonitorError::LockUnavailable`] unless the lock is held.
    ///
    /// # Errors
    ///
    /// [`MonitorError::LockUnavailable`] for [`StateLock::Unavailable`].
    pub fn require_held(self) -> Result<Self, MonitorError> {
        match self {
            Self::Held(_) => Ok(self),
            Self::Unavailable => Err(MonitorError::LockUnavailable),
        }
    }
}

// ---------------------------------------------------------------------------
// Commit-confirm state
// ---------------------------------------------------------------------------

/// One file to put back if a commit is not confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEntry {
    /// The target's id at the time the commit was armed. Advisory after a
    /// restart, since the module set may have changed.
    pub target: u16,
    /// Absolute path to restore.
    pub path: PathBuf,
    /// Absolute path of the backup to restore from.
    pub backup: PathBuf,
    /// Digest of the contents this write left on disk. A rollback restores
    /// only while the target still has it, so an edit made during the
    /// confirm window is kept. `None` (a marker from an older monitor)
    /// restores without the guard.
    #[serde(default)]
    pub new_digest: Option<crate::fs::atomic::Sha256Digest>,
}

/// The on-disk crash-recovery marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommitMarker {
    /// The armed commit id.
    pub commit: u32,
    /// Wall-clock deadline, milliseconds since the Unix epoch. Recorded for
    /// operators reading the file; recovery rolls back unconditionally,
    /// because a monitor that died before confirming never confirmed.
    pub deadline_unix_ms: u128,
    /// What to restore, in the order the writes happened.
    pub entries: Vec<RollbackEntry>,
    /// Service action to replay after restoring the files.
    #[serde(default)]
    pub service: Option<PendingService>,
}

/// What [`Monitor::recover_pending`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Recovered {
    /// The commit that was rolled back.
    pub commit: CommitId,
    /// How many targets were successfully restored.
    pub restored: usize,
    /// One message per entry that could not be restored.
    pub failures: Vec<String>,
}

/// What [`Monitor::recover_in_place`] did with a leftover in-place marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InPlaceRecovered {
    /// The target the marker named.
    pub path: PathBuf,
    /// What was done.
    pub outcome: InPlaceOutcome,
}

/// The outcome of [`Monitor::recover_in_place`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InPlaceOutcome {
    /// The target had the new or the previous contents; only the marker
    /// was removed.
    Whole,
    /// The target was torn; its backup was restored.
    Restored,
    /// The restore failed; the marker stays.
    Failed(String),
    /// The marker named no allow-listed target or backup; it was removed
    /// and nothing else was touched.
    Refused,
}

#[derive(Debug)]
struct Pending {
    commit: CommitId,
    deadline: Instant,
    entries: Vec<RollbackEntry>,
    service: Option<PendingService>,
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// The privileged request server.
pub struct Monitor<'a> {
    allow: Allowlist,
    hooks: Hooks<'a>,
    greeted: bool,
    journal: Vec<RollbackEntry>,
    pending: Option<Pending>,
    /// Monitor-only base for content-addressed update images. Production uses
    /// the systemd runtime directory; tests may override it per monitor.
    staging_dir: PathBuf,
    /// Test-only swap target. `None` (production) swaps `current_exe()`; the
    /// engine tests point it at their temp target instead. A field — not a
    /// global — so parallel tests cannot steer each other.
    binary_override: Option<PathBuf>,
    /// Test-only trust material; production uses [`detent_update::trust::embedded`].
    #[cfg(feature = "update")]
    update_trust: Option<detent_update::trust::TrustRoot>,
    /// Host facts used by the module validators.
    host_profile: HostProfile,
    /// Optional injected registry for synthetic descriptors. Production leaves
    /// this unset and resolves only compiled modules.
    module_registry: Option<Vec<Box<dyn DynModule>>>,
}
impl fmt::Debug for Monitor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Monitor")
            .field("allow", &self.allow)
            .field("hooks", &self.hooks)
            .field("greeted", &self.greeted)
            .finish_non_exhaustive()
    }
}

impl<'a> Monitor<'a> {
    /// Build a monitor over `allow`, delegating checks and services to `hooks`.
    #[must_use]
    pub fn new(allow: Allowlist, hooks: Hooks<'a>) -> Self {
        // A no-op after `spawn_pair` has read it; see `process_euid`.
        process_euid();
        Self {
            allow,
            hooks,
            greeted: false,
            journal: Vec::new(),
            pending: None,
            staging_dir: PathBuf::from(DEFAULT_STAGING_DIR),
            binary_override: None,
            #[cfg(feature = "update")]
            update_trust: None,
            host_profile: HostProfile::default(),
            module_registry: None,
        }
    }

    /// Inject the module registry used for synthetic descriptors.
    pub fn set_module_registry(&mut self, registry: Vec<Box<dyn DynModule>>) {
        self.module_registry = Some(registry);
    }

    /// Use explicit Sigstore trust material instead of the embedded roots.
    /// This keeps synthetic verifier fixtures out of production trust files.
    #[cfg(feature = "update")]
    pub fn set_update_trust(&mut self, trust: detent_update::trust::TrustRoot) {
        self.update_trust = Some(trust);
    }

    /// Supply the detected host facts used by module validation.
    pub fn set_host_profile(&mut self, profile: HostProfile) {
        self.host_profile = profile;
    }

    /// Point the binary swap at `path` instead of `current_exe()`. Test-only:
    /// keeps the `update_apply` engine tests from swapping their own test
    /// executable. Unconditional (not `#[cfg(test)]`): `cfg(test)` is false
    /// when `detent-ops`' integration test links against this crate, so the
    /// gate would hide it exactly where it is needed.
    pub fn set_binary_override(&mut self, path: PathBuf) {
        self.binary_override = Some(path);
    }

    /// Override the monitor-only base for materialized update images.
    ///
    /// Production uses [`DEFAULT_STAGING_DIR`], created by systemd. This is
    /// public rather than test-gated so the operations integration harness,
    /// which links this crate without `cfg(test)`, can keep each monitor in
    /// its own temporary directory.
    pub fn set_staging_dir(&mut self, path: PathBuf) {
        self.staging_dir = path;
    }

    /// The allow-list this monitor serves.
    #[must_use]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allow
    }

    /// True while a commit is armed and unconfirmed.
    #[must_use]
    pub const fn has_pending_commit(&self) -> bool {
        self.pending.is_some()
    }

    /// Serve requests until the worker shuts down, disconnects, or misbehaves.
    ///
    /// Exactly one response is sent for every request received.
    ///
    /// # Errors
    ///
    /// [`MonitorError::Channel`] when the socket fails for a reason that is not
    /// a protocol violation, and [`MonitorError::State`] when the state
    /// directory cannot be maintained.
    pub fn serve(&mut self, channel: &mut Channel) -> Result<ExitReason, MonitorError> {
        let state_lock = Self::lock(self.allow.state_root())?;
        if state_lock.is_held() {
            self.recover_pending()?;
        }
        self.serve_locked(channel, state_lock)
    }

    /// Serve after the caller has taken [`MONITOR_LOCK`] and recovered any
    /// leftover marker. The guard is held until every return path completes.
    ///
    /// With [`StateLock::Unavailable`] the monitor still answers reads but
    /// refuses every request that changes state
    /// ([`Request::changes_state`]).
    ///
    /// # Errors
    ///
    /// Returns a channel, protocol, or state error from serving or cleanup.
    pub fn serve_locked(
        &mut self,
        channel: &mut Channel,
        state_lock: StateLock,
    ) -> Result<ExitReason, MonitorError> {
        let lock_held = state_lock.is_held();
        // Kept until every return path completes.
        let _state_lock = state_lock;
        let result = self.serve_loop(channel, lock_held);
        let cleanup = self.rollback_pending_on_exit();
        match (result, cleanup) {
            (Ok(reason), Ok(())) => Ok(reason),
            (Err(err), Ok(())) | (Ok(_), Err(err)) => Err(err),
            (Err(_), Err(cleanup)) => Err(cleanup),
        }
    }

    /// Take the exclusive monitor lock without running recovery.
    ///
    /// Returns [`StateLock::Unavailable`] when the state directory or lock
    /// file is not accessible to this user. A monitor served with that value
    /// refuses every state change; use [`Monitor::lock_exclusive`] on a path
    /// that must write.
    ///
    /// # Errors
    ///
    /// Returns [`MonitorError::Busy`] when another monitor owns the lock, or
    /// a state error when the lock cannot be opened.
    pub fn lock(state_root: &Path) -> Result<StateLock, MonitorError> {
        lock_state(state_root)
    }

    /// As [`Monitor::lock`], but the lock must be held: `detent serve` and
    /// every one-shot command that writes call this and stop at startup.
    ///
    /// # Errors
    ///
    /// [`MonitorError::LockUnavailable`] when the state directory or lock
    /// file is not accessible, plus the errors of [`Monitor::lock`].
    pub fn lock_exclusive(state_root: &Path) -> Result<StateLock, MonitorError> {
        lock_state(state_root)?.require_held()
    }

    fn serve_loop(
        &mut self,
        channel: &mut Channel,
        state_lock_held: bool,
    ) -> Result<ExitReason, MonitorError> {
        let idle_timeout = channel.read_timeout();
        loop {
            let want = if self.pending.is_some() {
                PENDING_POLL
            } else {
                idle_timeout
            };
            if channel.read_timeout() != want {
                match channel.set_read_timeout(want) {
                    Ok(()) => {}
                    Err(ChannelError::Closed) => return Ok(ExitReason::PeerClosed),
                    Err(err) => return Err(MonitorError::Channel(err)),
                }
            }

            match channel.poll_recv::<Request>() {
                Ok(None) => {}
                Ok(Some(request)) => {
                    let stop = matches!(request, Request::Shutdown);
                    // Without the state lock nothing excludes a second
                    // monitor, so no state change may run. Before the
                    // handshake `dispatch` decides, so its errors stay the same.
                    let response = if !state_lock_held && self.greeted && request.changes_state() {
                        Response::Error(ProtoError::StateLockUnavailable)
                    } else {
                        self.dispatch(request)?
                    };
                    let fatal = matches!(
                        response,
                        Response::Error(
                            ProtoError::VersionMismatch { .. } | ProtoError::HandshakeRequired
                        )
                    );
                    if let Err(err) = channel.send(&response) {
                        return finish_send_error(err);
                    }
                    if stop {
                        return Ok(ExitReason::Shutdown);
                    }
                    if fatal {
                        tracing::warn!("privsep handshake failed; closing the channel");
                        return Ok(ExitReason::ProtocolMismatch);
                    }
                }
                Err(ChannelError::Closed) => return Ok(ExitReason::PeerClosed),
                Err(err) if err.is_protocol_violation() => {
                    tracing::error!(error = %err, "privsep protocol violation; closing the channel");
                    return Ok(ExitReason::ProtocolViolation);
                }
                Err(err) => return Err(MonitorError::Channel(err)),
            }

            self.enforce_deadline()?;
        }
    }

    fn rollback_pending_on_exit(&mut self) -> Result<(), MonitorError> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        if let Err(err) = self.stop_started_mounts(&pending.entries) {
            tracing::error!(error = %err, "stopping the started mounts before rollback failed");
        }
        let restored = roll_back(&pending.entries, &self.in_place_marker());
        if let Err(err) = self.replay_reload(&pending.entries) {
            tracing::error!(error = %err, "unit-file reload after rollback failed");
        }
        if let Err(err) = self.replay_service(pending.service) {
            tracing::error!(error = %err, "service replay after monitor shutdown failed");
        }
        self.clear_marker()?;
        tracing::warn!(
            commit = pending.commit.get(),
            restored,
            "commit-confirm rolled back because the monitor is stopping"
        );
        Ok(())
    }

    /// Handle one request. Never returns an error for a *request* failure;
    /// those become [`Response::Error`].
    fn dispatch(&mut self, request: Request) -> Result<Response, MonitorError> {
        if !self.greeted {
            return Ok(match request {
                Request::Hello { proto } if proto == super::proto::PROTO_VERSION => {
                    self.greeted = true;
                    Response::HelloAck(self.allow.hello_ack())
                }
                Request::Hello { proto } => Response::Error(ProtoError::VersionMismatch {
                    expected: super::proto::PROTO_VERSION,
                    got: proto,
                }),
                _ => Response::Error(ProtoError::HandshakeRequired),
            });
        }

        Ok(match request {
            // A second handshake is as much a protocol error as a missing one.
            Request::Hello { .. } => Response::Error(ProtoError::HandshakeRequired),
            Request::ReadTarget { target } => self.read_target(target),
            Request::WriteTarget {
                target,
                expected_prev,
                bytes,
                journal,
            } => self.write_target(target, expected_prev, &bytes, journal),
            Request::RunCheck { check, bytes } => self.run_check(check, &bytes),
            Request::Service { binding, action } => self.service(binding, action),
            Request::ListBackups { module } => self.list_backups(module),
            Request::Restore { module, backup } => self.restore(module, backup),
            Request::StartConfirmTimer {
                commit,
                timeout_s,
                service,
            } => self.start_confirm_timer(commit, timeout_s, service)?,
            Request::ConfirmCommit { commit } => self.confirm_commit(commit)?,
            Request::RollbackCommit { commit } => self.rollback_commit(commit)?,
            Request::PendingCommit => {
                Response::Pending(self.pending.as_ref().map(|pending| pending.commit))
            }
            Request::Mount { target } => self.mount(target),
            Request::ReplaceBinary { tag, len, sha256 } => self.replace_binary(&tag, len, sha256),
            Request::Shutdown => Response::ShuttingDown,
            Request::ReloadUnitFiles { module } => self.reload_unit_files(module),
        })
    }
    /// Materialize and authenticate a staged release, then atomically swap it.
    fn replace_binary(
        &self,
        tag: &str,
        len: u64,
        sha256: crate::fs::atomic::Sha256Digest,
    ) -> Response {
        // C1-e: refuse downgrades over privsep. The worker is untrusted; only
        // a CLI-typed operator path may downgrade. Parse `tag` as semver
        // (strip leading `v`, same as `detent-update::policy::version_of`)
        // and require it to be strictly greater than the running version.
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .unwrap_or_else(|_| semver::Version::new(0, 0, 0));
        let Ok(tag_version) = semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)) else {
            return Response::Error(ProtoError::Io(
                "release tag is not a semver version".to_owned(),
            ));
        };
        if tag_version <= current {
            return Response::Error(ProtoError::Io(format!(
                "refusing downgrade to {tag} from {}",
                env!("CARGO_PKG_VERSION")
            )));
        }
        let staged = staged_path(&self.staging_dir, sha256);
        if let Err(err) =
            materialize_staged(self.allow.state_root(), &self.staging_dir, tag, len, sha256)
        {
            return Response::Error(err);
        }
        // From here the monitor holds a copy of the candidate. Remove it on
        // every path that does not swap it in (the swap consumes it itself).
        let _copy = RemoveOnDrop(&staged);
        let bytes = match read_staged_verified(&staged, len, sha256) {
            Ok(bytes) => bytes,
            Err(err) => return Response::Error(err),
        };
        if let Err(err) = self.verify_release(&format!("{tag}.sigstore.json"), tag, sha256) {
            return Response::Error(err);
        }
        let target = self
            .binary_override
            .clone()
            .unwrap_or_else(current_exe_path);
        match swap_running_binary(&bytes, &staged, &target) {
            Ok(()) => Response::Replaced {
                version: sha256.to_string(),
            },
            Err(err) => Response::Error(err),
        }
    }

    /// Authenticate a staged release against its Sigstore bundle.
    #[cfg(feature = "update")]
    fn verify_release(
        &self,
        bundle_name: &str,
        tag: &str,
        sha256: crate::fs::atomic::Sha256Digest,
    ) -> Result<(), ProtoError> {
        // The worker writes the bundle, so open it as the staged binary is
        // opened: no symlink, no FIFO, no directory outside the state root's
        // owner.
        let opened = open_staged_input(self.allow.state_root(), bundle_name).map_err(|err| {
            tracing::warn!(error = ?err, "staged release bundle refused");
            ProtoError::VerificationFailed
        })?;
        let Ok(bundle) = read_bounded_file(&opened, detent_update::bundle::MAX_BUNDLE_BYTES) else {
            return Err(ProtoError::VerificationFailed);
        };
        let Ok(decoded) = detent_update::bundle::parse(&bundle) else {
            return Err(ProtoError::VerificationFailed);
        };
        let verified = if let Some(trust) = &self.update_trust {
            detent_update::verify::verify(&decoded, sha256.as_bytes(), tag, trust)
        } else {
            detent_update::trust::embedded().and_then(|trust| {
                detent_update::verify::verify(&decoded, sha256.as_bytes(), tag, &trust)
            })
        };
        verified.map_err(|err| {
            tracing::warn!(error = %err, "staged release verification failed");
            ProtoError::VerificationFailed
        })
    }

    /// A build without the `update` feature links no verifier, so it can
    /// authenticate nothing: every staged release is refused (fail closed).
    #[cfg(not(feature = "update"))]
    fn verify_release(
        &self,
        bundle_name: &str,
        tag: &str,
        _sha256: crate::fs::atomic::Sha256Digest,
    ) -> Result<(), ProtoError> {
        tracing::warn!(
            tag,
            bundle = bundle_name,
            staging = %self.staging_dir.display(),
            "staged release refused: built without the update feature"
        );
        Err(ProtoError::VerificationFailed)
    }

    // -- request handlers ---------------------------------------------------

    fn read_target(&self, id: TargetId) -> Response {
        let Some(entry) = self.allow.target(id) else {
            return unknown(IdKind::Target, u32::from(id.get()));
        };
        match read_with_digest(&entry.path) {
            Ok((bytes, digest)) => Response::Target(TargetContents {
                target: id,
                bytes,
                digest,
            }),
            Err(AtomicError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Response::Error(ProtoError::NotFound)
            }
            Err(err) => Response::Error(atomic_to_proto(&err)),
        }
    }

    fn write_target(
        &mut self,
        id: TargetId,
        expected_prev: Option<crate::fs::atomic::Sha256Digest>,
        bytes: &[u8],
        journal: bool,
    ) -> Response {
        let Some(entry) = self.allow.target(id).cloned() else {
            return unknown(IdKind::Target, u32::from(id.get()));
        };
        let previous = match read_with_digest(&entry.path) {
            Ok((contents, _)) => contents,
            Err(AtomicError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Vec::new()
            }
            Err(err) => return Response::Error(atomic_to_proto(&err)),
        };
        if let Err(response) = self.revalidate(entry.module, &previous, bytes) {
            return response;
        }
        let marker = self.in_place_marker();
        let request = WriteRequest {
            path: &entry.path,
            contents: bytes,
            expected_prev,
            backup_dir: &entry.backup_dir,
            keep_backups: self.allow.keep_backups(),
            create_missing: false,
            create_mode: entry.create_mode,
            in_place: InPlace::Marker(&marker),
        };
        let outcome = match write_atomic(&request) {
            Ok(outcome) => outcome,
            Err(err) => return Response::Error(atomic_to_proto(&err)),
        };
        if journal && outcome.backup.is_some() {
            if self.pending.is_none() {
                self.journal.clear();
            }
            if let Some(backup) = outcome.backup.clone() {
                self.journal.push(RollbackEntry {
                    target: id.get(),
                    path: entry.path.clone(),
                    backup,
                    new_digest: Some(outcome.new_digest),
                });
            }
        }
        Response::Written(WriteReceipt {
            target: id,
            prev_digest: outcome.prev_digest,
            new_digest: outcome.new_digest,
            created: outcome.created,
            backed_up: outcome.backup.is_some(),
            owner_preserved: outcome.owner_preserved,
        })
    }

    /// Re-run module and external validators before installing candidate bytes.
    fn revalidate(&self, module: ModuleId, previous: &[u8], bytes: &[u8]) -> Result<(), Response> {
        let Some(descriptor) = self.allow.module(module) else {
            return Err(unknown(IdKind::Module, u32::from(module.get())));
        };
        if Self::has_new_forbidden_exec_directive(descriptor.id, previous, bytes) {
            return Err(Response::Error(ProtoError::Io(
                "module content adds a forbidden execution directive".to_owned(),
            )));
        }
        let validation = if let Some(registry) = &self.module_registry {
            let Some(module) = registry.iter().find(|module| module.id() == descriptor.id) else {
                return Err(Response::Error(ProtoError::Io(
                    "module parser is unavailable".to_owned(),
                )));
            };
            Self::validate_candidate(module.as_ref(), bytes, &self.host_profile)
        } else {
            let modules = detent_modules::modules();
            let Some(module) = modules.iter().find(|module| module.id() == descriptor.id) else {
                return Err(Response::Error(ProtoError::Io(
                    "module parser is unavailable".to_owned(),
                )));
            };
            Self::validate_candidate(module.as_ref(), bytes, &self.host_profile)
        };
        validation?;
        if !self.hooks.checks.configured() {
            return Ok(());
        }
        if descriptor.checks.is_empty() {
            return Ok(());
        }
        let (candidate, candidate_path) = self
            .create_module_candidate(module)
            .map_err(Response::Error)?;
        let _remove = RemoveOnDrop(&candidate_path);
        write_all_and_sync(&candidate, bytes).map_err(|err| {
            Response::Error(ProtoError::Io(format!(
                "cannot write the candidate file: {}",
                err.kind()
            )))
        })?;
        for check in descriptor.checks {
            let outcome = self
                .hooks
                .checks
                .run_check(check, &candidate_path)
                .map_err(|err| Response::Error(err.into()))?;
            if !outcome.passed {
                return Err(Response::Error(ProtoError::Io(
                    "external validator rejected candidate content".to_owned(),
                )));
            }
        }
        Ok(())
    }

    fn validate_candidate(
        module: &dyn DynModule,
        bytes: &[u8],
        host_profile: &HostProfile,
    ) -> Result<(), Response> {
        let source = std::str::from_utf8(bytes).map_err(|_| {
            Response::Error(ProtoError::Io(
                "module content is not valid UTF-8".to_owned(),
            ))
        })?;
        let model = module.parse_to_model_json(source).map_err(|err| {
            Response::Error(ProtoError::Io(format!(
                "module parser rejected candidate content: {err}"
            )))
        })?;
        let diagnostics = module
            .validate_json(&model, &ValidationCtx::new(host_profile))
            .map_err(|err| {
                Response::Error(ProtoError::Io(format!(
                    "module validation rejected candidate content: {err}"
                )))
            })?;
        if diagnostics.has_errors() {
            return Err(Response::Error(ProtoError::Io(
                "module validation rejected candidate content".to_owned(),
            )));
        }
        Ok(())
    }

    /// Reject only newly introduced directives that ask a privileged daemon to
    /// execute content, or changed values of existing ones. Existing
    /// directives remain in place unchanged. See [`super::exec_deny`].
    fn has_new_forbidden_exec_directive(module: &str, previous: &[u8], candidate: &[u8]) -> bool {
        super::exec_deny::adds_exec_directive(module, previous, candidate)
    }

    /// Create the candidate file for `module`'s validators, in the one
    /// place both the write path and [`Request::RunCheck`] use: beside the
    /// module's primary target ([`Allowlist::candidate_dir`]), where the
    /// distro's `AppArmor` profile for the validator allows it to read, or
    /// monitor staging when the module has no file target. The directory
    /// comes from the allow-list, never from the request. A target directory
    /// that fails [`require_trusted_dir`] (owner root or the monitor's euid,
    /// so capability-user mode works) is refused, with no fallback. A trusted
    /// target directory the monitor cannot write — a read-only file system
    /// (the packaged unit's `ProtectSystem=strict` makes `/etc` read-only and
    /// lists only the target file in `ReadWritePaths=`) or no write
    /// permission — falls back to monitor staging. The runner looks in both
    /// places itself.
    fn create_module_candidate(
        &self,
        module: ModuleId,
    ) -> Result<(std::fs::File, PathBuf), ProtoError> {
        let cannot = |err: std::io::Error| {
            ProtoError::Io(format!("cannot create a candidate file: {}", err.kind()))
        };
        let Some(dir) = self.allow.candidate_dir(module, &self.host_profile) else {
            return create_candidate(&ensure_staging_dir(&self.staging_dir)?).map_err(cannot);
        };
        require_trusted_dir(dir, "candidate directory", DirOwner::EuidOrRoot)?;
        match create_candidate(dir) {
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ReadOnlyFilesystem | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                create_candidate(&ensure_staging_dir(&self.staging_dir)?).map_err(cannot)
            }
            created => created.map_err(cannot),
        }
    }

    fn run_check(&self, id: CheckId, bytes: &[u8]) -> Response {
        let Some(entry) = self.allow.check(id) else {
            return unknown(IdKind::Check, u32::from(id.get()));
        };
        let (candidate, candidate_path) = match self.create_module_candidate(entry.module) {
            Ok(created) => created,
            Err(err) => return Response::Error(err),
        };
        let _remove = RemoveOnDrop(&candidate_path);
        if let Err(err) = write_all_and_sync(&candidate, bytes) {
            return Response::Error(ProtoError::Io(format!(
                "cannot write the candidate file: {}",
                err.kind()
            )));
        }
        match self.hooks.checks.run_check(entry.check, &candidate_path) {
            Ok(mut outcome) => {
                outcome.check = id;
                outcome.detail = truncate(&outcome.detail);
                Response::Checked(outcome)
            }
            Err(err) => Response::Error(err.into()),
        }
    }

    fn service(&self, id: BindingId, action: ServiceAction) -> Response {
        let Some(entry) = self.allow.binding(id) else {
            return unknown(IdKind::Binding, u32::from(id.get()));
        };
        let Some(core) = action.to_core() else {
            // `Status` is not a mutation and has no core counterpart yet; the
            // service-manager subtask adds it.
            return Response::Error(ProtoError::Unsupported(
                "service status is not implemented yet".to_owned(),
            ));
        };
        if !entry.binding.actions.contains(&core) {
            return Response::Error(ProtoError::ActionNotAllowed);
        }
        match self.hooks.services.service(entry.binding, core) {
            Ok(mut outcome) => {
                outcome.binding = id;
                outcome.detail = truncate(&outcome.detail);
                Response::Serviced(outcome)
            }
            Err(err) => Response::Error(err.into()),
        }
    }

    /// Re-read the init system's unit files for `module`, which must
    /// declare `reload_unit_files`.
    fn reload_unit_files(&self, module: ModuleId) -> Response {
        let Some(descriptor) = self.allow.module(module) else {
            return unknown(IdKind::Module, u32::from(module.get()));
        };
        if !descriptor.reload_unit_files {
            return Response::Error(ProtoError::ActionNotAllowed);
        }
        match self.hooks.services.reload_unit_files() {
            Ok(detail) => Response::UnitFilesReloaded {
                detail: truncate(&detail),
            },
            Err(err) => Response::Error(err.into()),
        }
    }

    /// Start the mount units of the entries an apply added to `target`,
    /// whose module must declare mounts. With `[mounts]
    /// activate_new_entries` off nothing starts and the answer says so.
    fn mount(&self, target: TargetId) -> Response {
        let Some(entry) = self.allow.target(target) else {
            return unknown(IdKind::Target, u32::from(target.get()));
        };
        if self
            .allow
            .module(entry.module)
            .is_none_or(|module| module.added_mounts.is_none())
        {
            return Response::Error(ProtoError::ActionNotAllowed);
        }
        if !self.allow.config().activate_mounts {
            return Response::Mounted {
                activated: false,
                units: Vec::new(),
            };
        }
        match self.hooks.services.start_added_mounts(target) {
            Ok(units) => Response::Mounted {
                activated: true,
                units: units
                    .into_iter()
                    .map(|unit| MountOutcome {
                        detail: truncate(&unit.detail),
                        ..unit
                    })
                    .collect(),
            },
            Err(err) => Response::Error(err.into()),
        }
    }

    fn list_backups(&self, module: ModuleId) -> Response {
        match self.collect_backups(module) {
            Ok(entries) => {
                Response::Backups(entries.into_iter().map(|(info, _, _)| info).collect())
            }
            Err(response) => response,
        }
    }

    fn restore(&self, module: ModuleId, backup: BackupId) -> Response {
        let listing = match self.collect_backups(module) {
            Ok(entries) => entries,
            Err(response) => return response,
        };
        let Some((info, source, target_path)) =
            listing.get(usize::try_from(backup.get()).unwrap_or(usize::MAX))
        else {
            return unknown(IdKind::Backup, backup.get());
        };
        let marker = self.in_place_marker();
        match restore_backup_with(source, target_path, None, InPlace::Marker(&marker)) {
            Ok(outcome) => Response::Restored {
                target: info.target,
                new_digest: outcome.new_digest,
            },
            Err(err) => Response::Error(atomic_to_proto(&err)),
        }
    }

    /// The module's backups across all its targets, newest first, paired with
    /// the on-disk backup path and the live target path the worker never
    /// sees. The target path travels with each row (captured while iterating
    /// `self.allow.targets_of`) instead of being re-resolved by id later, so
    /// [`restore`](Self::restore) can never observe an id that the allowlist
    /// does not recognise.
    fn collect_backups(
        &self,
        module: ModuleId,
    ) -> Result<Vec<(BackupInfo, PathBuf, PathBuf)>, Response> {
        if self.allow.module(module).is_none() {
            return Err(unknown(IdKind::Module, u32::from(module.get())));
        }
        let mut rows: Vec<(TargetId, PathBuf, BackupEntry)> = Vec::new();
        for target in self.allow.targets_of(module) {
            match list_backups(&target.backup_dir) {
                Ok(entries) => rows.extend(
                    entries
                        .into_iter()
                        .map(|entry| (target.id, target.path.clone(), entry)),
                ),
                Err(err) => return Err(Response::Error(atomic_to_proto(&err))),
            }
        }
        rows.sort_by(|left, right| {
            right
                .2
                .created_utc
                .cmp(&left.2.created_utc)
                .then_with(|| left.2.path.cmp(&right.2.path))
        });
        Ok(rows
            .into_iter()
            .enumerate()
            .map(|(index, (target, target_path, entry))| {
                let info = BackupInfo {
                    id: BackupId(u32::try_from(index).unwrap_or(u32::MAX)),
                    target,
                    name: entry
                        .path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    created_unix_s: entry
                        .created_utc
                        .duration_since(UNIX_EPOCH)
                        .map(|since| since.as_secs())
                        .unwrap_or_default(),
                    digest: entry.digest,
                    len: entry.original_len,
                };
                (info, entry.path, target_path)
            })
            .collect())
    }

    // -- commit-confirm -----------------------------------------------------

    fn start_confirm_timer(
        &mut self,
        commit: CommitId,
        timeout_s: u16,
        service: Option<PendingService>,
    ) -> Result<Response, MonitorError> {
        if let Some(pending) = &self.pending {
            return Ok(Response::Error(ProtoError::CommitPending(pending.commit)));
        }
        let timeout_s = timeout_s.clamp(1, MAX_CONFIRM_TIMEOUT_S);
        let entries = std::mem::take(&mut self.journal);
        let rollback_targets = u16::try_from(entries.len()).unwrap_or(u16::MAX);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(u64::from(timeout_s)))
            .ok_or(MonitorError::CorruptMarker)?;
        let marker = PendingCommitMarker {
            commit: commit.get(),
            deadline_unix_ms: unix_millis()
                .saturating_add(u128::from(timeout_s).saturating_mul(1000)),
            entries: entries.clone(),
            service,
        };
        self.write_marker(&marker)?;
        self.pending = Some(Pending {
            commit,
            deadline,
            entries,
            service,
        });
        tracing::info!(
            commit = commit.get(),
            timeout_s,
            rollback_targets,
            "commit-confirm armed"
        );
        Ok(Response::ConfirmTimerStarted {
            commit,
            timeout_s,
            rollback_targets,
        })
    }

    fn confirm_commit(&mut self, commit: CommitId) -> Result<Response, MonitorError> {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.commit == commit && Instant::now() >= pending.deadline);
        if expired {
            self.enforce_deadline()?;
            return Ok(Response::Error(ProtoError::CommitExpired(commit)));
        }
        match &self.pending {
            Some(pending) if pending.commit == commit => {
                let entries = self
                    .pending
                    .take()
                    .map(|pending| pending.entries)
                    .unwrap_or_default();
                if self.starts_mounts(&entries)
                    && let Err(err) = self.hooks.services.forget_started_mounts()
                {
                    tracing::error!(error = %err, "forgetting the started mounts failed");
                }
                self.clear_marker()?;
                tracing::info!(commit = commit.get(), "commit confirmed");
                Ok(Response::Committed { commit })
            }
            _ => Ok(unknown(IdKind::Commit, commit.get())),
        }
    }

    /// Roll a pending commit back immediately, on request rather than at its
    /// deadline. Mirrors [`Self::confirm_commit`], inverted: a hit restores
    /// every recorded write instead of discarding the rollback.
    ///
    /// `take_if` gives the same atomic read-and-clear [`Self::enforce_deadline`]
    /// relies on, so a second `RollbackCommit` for the same id — or one that
    /// arrives after the deadline already took and rolled back the pending
    /// state — finds nothing pending and answers `unknown`, never restoring
    /// twice.
    fn rollback_commit(&mut self, commit: CommitId) -> Result<Response, MonitorError> {
        let Some(pending) = self.pending.take_if(|pending| pending.commit == commit) else {
            return Ok(unknown(IdKind::Commit, commit.get()));
        };
        if let Err(err) = self.stop_started_mounts(&pending.entries) {
            tracing::error!(error = %err, "stopping the started mounts before rollback failed");
        }
        let restored = roll_back(&pending.entries, &self.in_place_marker());
        if let Err(err) = self.replay_reload(&pending.entries) {
            tracing::error!(error = %err, "unit-file reload after rollback failed");
        }
        if let Err(err) = self.replay_service(pending.service) {
            tracing::error!(error = %err, "service replay after rollback failed");
        }
        self.clear_marker()?;
        tracing::warn!(
            commit = commit.get(),
            restored,
            "commit rolled back on request"
        );
        Ok(Response::RolledBack {
            commit,
            restored: u16::try_from(restored).unwrap_or(u16::MAX),
        })
    }

    /// Roll back if the pending commit's deadline has passed.
    fn enforce_deadline(&mut self) -> Result<(), MonitorError> {
        // `take_if` folds the "is anything pending" and "has it expired"
        // checks into one atomic read-and-clear: there is no window between
        // deciding a commit expired and taking it, so the "expired but
        // nothing to take" state below is unrepresentable rather than merely
        // unreached.
        let Some(pending) = self
            .pending
            .take_if(|pending| Instant::now() >= pending.deadline)
        else {
            return Ok(());
        };
        if let Err(err) = self.stop_started_mounts(&pending.entries) {
            tracing::error!(error = %err, "stopping the started mounts before rollback failed");
        }
        let restored = roll_back(&pending.entries, &self.in_place_marker());
        if let Err(err) = self.replay_reload(&pending.entries) {
            tracing::error!(error = %err, "unit-file reload after rollback failed");
        }
        if let Err(err) = self.replay_service(pending.service) {
            tracing::error!(error = %err, "service replay after rollback failed");
        }
        self.clear_marker()?;
        tracing::warn!(
            commit = pending.commit.get(),
            restored,
            "commit-confirm expired; rolled back"
        );
        Ok(())
    }

    // -- in-place write recovery ----------------------------------------------

    fn in_place_marker(&self) -> PathBuf {
        self.allow.state_root().join(IN_PLACE_MARKER)
    }

    /// Finish an in-place write a previous monitor left behind
    /// ([`IN_PLACE_MARKER`]; see `fs::atomic`). Called at the start of
    /// [`Self::recover_pending`].
    ///
    /// A marker whose target or backup is not an allow-listed target and its
    /// backup directory is removed with nothing else touched. A target that
    /// has the new or the previous contents is whole: the marker goes. Any
    /// other contents (a torn write, or none) are replaced by the backup
    /// through the normal restore path, then the marker goes. When that
    /// restore fails, the marker stays, so in-place writes stay refused
    /// until a later start succeeds.
    ///
    /// # Errors
    ///
    /// [`MonitorError::CorruptMarker`] when the marker is unparseable, and
    /// [`MonitorError::State`] when it cannot be read or removed.
    pub fn recover_in_place(&self) -> Result<Option<InPlaceRecovered>, MonitorError> {
        let marker_path = self.in_place_marker();
        let raw = match std::fs::read(&marker_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(MonitorError::State { op: "read", source }),
        };
        let marker: InPlaceMarker =
            serde_json::from_slice(&raw).map_err(|_| MonitorError::CorruptMarker)?;
        let remove = || {
            remove_marker(&marker_path).map_err(|err| MonitorError::State {
                op: "remove_file",
                source: std::io::Error::other(err.to_string()),
            })
        };
        let entry = (0..self.allow.target_count())
            .filter_map(|index| u16::try_from(index).ok())
            .filter_map(|index| self.allow.target(TargetId(index)))
            .find(|entry| {
                entry.path == marker.path
                    && entry.kind == super::proto::PathKind::File
                    && marker
                        .backup
                        .as_deref()
                        .and_then(Path::parent)
                        .is_some_and(|dir| dir == entry.backup_dir)
            });
        // `entry` matched only with a backup in its backup directory.
        let outcome = if let (Some(_), Some(backup)) = (entry, marker.backup.as_deref()) {
            let now = read_with_digest(&marker.path)
                .ok()
                .map(|(_, digest)| digest);
            if now == Some(marker.new) || now == Some(marker.prev) {
                remove()?;
                InPlaceOutcome::Whole
            } else {
                match restore_backup_with(backup, &marker.path, None, InPlace::Guarded) {
                    Ok(_) => {
                        remove()?;
                        InPlaceOutcome::Restored
                    }
                    Err(err) => InPlaceOutcome::Failed(err.to_string()),
                }
            }
        } else {
            remove()?;
            InPlaceOutcome::Refused
        };
        match &outcome {
            InPlaceOutcome::Whole => tracing::info!(
                path = %marker.path.display(),
                "an in-place write from a previous monitor was complete"
            ),
            InPlaceOutcome::Restored => tracing::warn!(
                path = %marker.path.display(),
                "restored the backup over a torn in-place write from a previous monitor"
            ),
            InPlaceOutcome::Failed(error) => tracing::error!(
                path = %marker.path.display(),
                error,
                "a torn in-place write could not be restored; the marker stays"
            ),
            InPlaceOutcome::Refused => tracing::error!(
                path = %marker.path.display(),
                "ignored an in-place marker that names no allow-listed target"
            ),
        }
        Ok(Some(InPlaceRecovered {
            path: marker.path,
            outcome,
        }))
    }

    // -- marker file --------------------------------------------------------

    fn marker_path(&self) -> PathBuf {
        self.allow.state_root().join(PENDING_COMMIT_MARKER)
    }

    fn write_marker(&self, marker: &PendingCommitMarker) -> Result<(), MonitorError> {
        let root = self.allow.state_root();
        std::fs::create_dir_all(root).map_err(|source| MonitorError::State {
            op: "create_dir_all",
            source,
        })?;
        let json = serde_json::to_vec(marker).map_err(|_| MonitorError::CorruptMarker)?;
        write_private(&self.marker_path(), &json).map_err(|source| MonitorError::State {
            op: "write",
            source,
        })
    }

    fn clear_marker(&self) -> Result<(), MonitorError> {
        match unlink(&self.marker_path()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(MonitorError::State {
                op: "remove_file",
                source,
            }),
        }
    }

    /// Reload the init system's unit files after a rollback of `entries`
    /// when one of them is a target of a module that declares
    /// `reload_unit_files`. Matched by path, as the marker records paths,
    /// not ids. It runs before the service replay, so a restarted service
    /// sees the regenerated units.
    fn replay_reload(&self, entries: &[RollbackEntry]) -> Result<(), HookError> {
        if !entries
            .iter()
            .any(|entry| self.allow.reloads_unit_files_after(&entry.path))
        {
            return Ok(());
        }
        self.hooks.services.reload_unit_files().map(|detail| {
            tracing::info!(detail, "reloaded unit files after file rollback");
        })
    }

    /// Whether one of `entries` is a target of a module that declares
    /// mounts. Matched by path, as for [`Self::replay_reload`].
    fn starts_mounts(&self, entries: &[RollbackEntry]) -> bool {
        entries
            .iter()
            .any(|entry| self.allow.starts_mounts_after(&entry.path))
    }

    /// Before a rollback of `entries` restores the files, stop the mount
    /// units the apply started, while the target still has the contents
    /// they were started for. Only the units the runner recorded stop.
    fn stop_started_mounts(&self, entries: &[RollbackEntry]) -> Result<(), HookError> {
        if !self.starts_mounts(entries) {
            return Ok(());
        }
        for unit in self.hooks.services.stop_started_mounts()? {
            tracing::info!(
                mountpoint = unit.mountpoint,
                unit = unit.unit,
                state = ?unit.state,
                detail = unit.detail,
                "stopped a mount the apply started"
            );
        }
        Ok(())
    }

    fn replay_service(&self, service: Option<PendingService>) -> Result<(), HookError> {
        let Some(service) = service else {
            return Ok(());
        };
        let entry = self.allow.binding(service.binding).ok_or_else(|| {
            HookError::Failed(format!("service binding {} disappeared", service.binding))
        })?;
        let action = service.action.to_core().ok_or_else(|| {
            HookError::Failed("pending service action is not mutating".to_owned())
        })?;
        if !entry.binding.actions.contains(&action) {
            return Err(HookError::Failed(
                "pending service action is no longer allowed".to_owned(),
            ));
        }
        self.hooks
            .services
            .service(entry.binding, action)
            .map(|outcome| {
                tracing::info!(
                    binding = service.binding.get(),
                    action = ?action,
                    active = outcome.active,
                    "replayed service action after file rollback"
                );
            })
    }

    /// Roll back a commit that was armed by a monitor that then died.
    ///
    /// Called once at startup, before the handshake. A marker on disk means
    /// the previous monitor armed a rollback and never got to confirm it, so
    /// the safe action is unconditional restoration — exactly what would have
    /// happened had the process survived to its deadline (PLAN §2.5).
    ///
    /// # Errors
    ///
    /// [`MonitorError::CorruptMarker`] when the marker is unparseable, and
    /// [`MonitorError::State`] when it cannot be read or removed.
    pub fn recover_pending(&self) -> Result<Option<Recovered>, MonitorError> {
        // First a torn in-place write, so a commit rollback below reads the
        // target as it was meant to be.
        self.recover_in_place()?;
        let path = self.marker_path();
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(MonitorError::State { op: "read", source });
            }
        };
        let marker: PendingCommitMarker =
            serde_json::from_slice(&raw).map_err(|_| MonitorError::CorruptMarker)?;
        let mut failures = Vec::new();
        if let Err(err) = self.stop_started_mounts(&marker.entries) {
            failures.push(err.to_string());
        }
        let in_place = self.in_place_marker();
        let mut restored = 0_usize;
        for entry in marker.entries.iter().rev() {
            match restore_backup_with(
                &entry.backup,
                &entry.path,
                entry.new_digest,
                InPlace::Marker(&in_place),
            ) {
                Ok(_) => restored = restored.saturating_add(1),
                Err(err) => failures.push(err.to_string()),
            }
        }
        if let Err(err) = self.replay_reload(&marker.entries) {
            failures.push(err.to_string());
        }
        if let Err(err) = self.replay_service(marker.service) {
            failures.push(err.to_string());
        }
        unlink(&path).map_err(|source| MonitorError::State {
            op: "remove_file",
            source,
        })?;
        tracing::warn!(
            commit = marker.commit,
            restored,
            failed = failures.len(),
            "recovered an unconfirmed commit from a previous monitor"
        );
        Ok(Some(Recovered {
            commit: CommitId(marker.commit),
            restored,
            failures,
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock_state(state_dir: &Path) -> Result<StateLock, MonitorError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Err(source) = std::fs::create_dir_all(state_dir) {
        return unavailable_when_denied("create_dir_all", source);
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state_dir.join(MONITOR_LOCK))
    {
        Ok(file) => file,
        Err(source) => return unavailable_when_denied("open lock", source),
    };
    if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        // A second live monitor is the intended error.
        return Err(MonitorError::Busy);
    }
    Ok(StateLock::Held(file))
}

/// `host` and other read-only commands run with the default `state_root`
/// (/var/lib/detent) even when the caller is not root. Creating that
/// directory would require privilege and must not turn a read-only command
/// into a startup failure, so `PermissionDenied` becomes
/// [`StateLock::Unavailable`]. That value excludes nothing: the monitor that
/// carries it refuses every state change. Any other error stays an error.
fn unavailable_when_denied(
    op: &'static str,
    source: std::io::Error,
) -> Result<StateLock, MonitorError> {
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        Ok(StateLock::Unavailable)
    } else {
        Err(MonitorError::State { op, source })
    }
}

/// Restore the recorded backups, newest write first. Failures are logged and
/// counted; one unreadable backup must not abandon the rest. A target that no
/// longer holds the contents detent wrote was edited during the confirm
/// window: it is skipped, logged, and not counted as restored.
fn roll_back(entries: &[RollbackEntry], marker: &Path) -> usize {
    let mut restored = 0_usize;
    for entry in entries.iter().rev() {
        match restore_backup_with(
            &entry.backup,
            &entry.path,
            entry.new_digest,
            InPlace::Marker(marker),
        ) {
            Ok(_) => restored = restored.saturating_add(1),
            Err(err @ AtomicError::Conflict { .. }) => tracing::warn!(
                error = %err,
                path = %entry.path.display(),
                "rollback skipped a target edited during the confirm window"
            ),
            Err(err) => tracing::error!(error = %err, "rollback of one target failed"),
        }
    }
    restored
}

fn unknown(kind: IdKind, id: u32) -> Response {
    Response::Error(ProtoError::UnknownId { kind, id })
}

/// Map a filesystem error onto the wire, dropping the path: the worker is the
/// untrusted side and must not learn which files exist from error messages.
fn atomic_to_proto(err: &AtomicError) -> ProtoError {
    match err {
        AtomicError::Conflict { expected, actual } => ProtoError::Conflict {
            expected: *expected,
            actual: *actual,
        },
        AtomicError::Io { op, source, .. } => ProtoError::Io(format!("{op}: {}", source.kind())),
        AtomicError::RelativePath { .. } => ProtoError::Io("path is not absolute".to_owned()),
        AtomicError::Symlink { .. } => ProtoError::Io("target is a symlink".to_owned()),
        AtomicError::NotRegularFile { .. } => {
            ProtoError::Io("target is not a regular file".to_owned())
        }
        AtomicError::BadDigest => ProtoError::Io("invalid digest".to_owned()),
        AtomicError::Clock => ProtoError::Io("system clock out of range".to_owned()),
    }
}

fn truncate(detail: &str) -> String {
    if detail.len() <= DETAIL_LIMIT {
        return detail.to_owned();
    }
    let mut end = DETAIL_LIMIT;
    while end > 0 && !detail.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    detail.get(..end).unwrap_or_default().to_owned()
}

fn write_all_and_sync(mut file: &std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

/// Write `bytes` to `path` with mode `0600`, replacing any previous content.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// ReplaceBinary (PLAN §2.9 step 5's binary swap)
// ---------------------------------------------------------------------------

/// Default monitor-only base for materialized update images. The service unit
/// creates this as a private systemd runtime directory.
pub const DEFAULT_STAGING_DIR: &str = "/run/detent/staging";

/// Directory under the state root containing worker-written tag inputs.
pub(crate) const STAGED_DIR: &str = "update/staged";
/// Suffix the replaced binary is kept under, next to the target.
pub(crate) const PREVIOUS_SUFFIX: &str = ".prev";

/// `<monitor_staging_dir>/<hex sha256>`.
fn staged_path(monitor_staging_dir: &Path, sha256: crate::fs::atomic::Sha256Digest) -> PathBuf {
    monitor_staging_dir.join(sha256.to_string())
}

fn staged_input_path(state_root: &Path, tag: &str) -> Result<PathBuf, ProtoError> {
    if tag.is_empty()
        || tag.len() > 128
        || tag == "."
        || tag == ".."
        || tag.contains('/')
        || tag.as_bytes().contains(&0)
    {
        return Err(ProtoError::VerificationFailed);
    }
    Ok(state_root.join(STAGED_DIR).join(tag))
}

/// The effective uid of this process, read once and then remembered.
///
/// `MONITOR` does not allow `geteuid` and kills the process on any call to
/// it, so a request handler must never ask the kernel. `spawn_pair` calls
/// this before it confines the monitor, and [`Monitor::new`] calls it for a
/// monitor that is not confined; every later owner check uses the stored
/// value. The monitor never changes its own uid, so the value stays true.
pub(crate) fn process_euid() -> u32 {
    static EUID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *EUID.get_or_init(|| rustix::process::geteuid().as_raw())
}

/// Open the worker-written input `<state_root>/update/staged/<name>` for
/// reading without following a symlink at any component below `state_root`.
///
/// Each directory is opened with `openat(O_NOFOLLOW | O_DIRECTORY)` and must
/// have the same owner as `state_root`, so a worker cannot point `update` or
/// `staged` at a root-readable directory elsewhere. The file is opened
/// `O_NONBLOCK` and must be a regular file: a planted FIFO would otherwise
/// block the monitor, and with it the commit-confirm deadline.
fn open_staged_input(state_root: &Path, name: &str) -> Result<std::fs::File, ProtoError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
    use rustix::io::Errno;
    let open_error = |err: Errno| ProtoError::Io(format!("open staged binary: {err}"));
    let stat_error = |err: Errno| ProtoError::Io(format!("stat staged binary: {err}"));
    let untrusted = || ProtoError::Io("staged input directory is not trusted".to_owned());
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = rustix::fs::open(state_root, dir_flags, Mode::empty()).map_err(open_error)?;
    let owner = fstat(&dir).map_err(stat_error)?.st_uid;
    for component in STAGED_DIR.split('/') {
        dir = match openat(&dir, component, dir_flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::LOOP | Errno::NOTDIR) => return Err(untrusted()),
            Err(err) => return Err(open_error(err)),
        };
        if fstat(&dir).map_err(stat_error)?.st_uid != owner {
            return Err(untrusted());
        }
    }
    let fd = openat(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(open_error)?;
    if FileType::from_raw_mode(fstat(&fd).map_err(stat_error)?.st_mode) != FileType::RegularFile {
        return Err(ProtoError::Io(
            "staged binary is not a regular file".to_owned(),
        ));
    }
    Ok(fd.into())
}

/// Create the monitor staging directory `0700` if it is missing (parents as
/// before), then require that it is a real directory, not a symlink, owned by
/// the monitor's euid, with no group or other write bit. An existing
/// directory that fails the check is refused, never repaired.
pub(crate) fn ensure_staging_dir(monitor_staging_dir: &Path) -> Result<PathBuf, ProtoError> {
    use std::os::unix::fs::DirBuilderExt as _;
    if let Some(parent) = monitor_staging_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            ProtoError::Io(format!("create monitor staging directory: {}", err.kind()))
        })?;
    }
    match std::fs::DirBuilder::new()
        .mode(0o700)
        .create(monitor_staging_dir)
    {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(ProtoError::Io(format!(
                "create monitor staging directory: {}",
                err.kind()
            )));
        }
    }
    require_trusted_dir(
        monitor_staging_dir,
        "monitor staging directory",
        DirOwner::Euid,
    )?;
    Ok(monitor_staging_dir.to_path_buf())
}

/// Which owners [`require_trusted_dir`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirOwner {
    /// Only this process's euid: a directory `detent` owns (staging).
    Euid,
    /// This process's euid or root: a target's directory, which root owns
    /// even when the monitor runs as `detent` (capability-user mode).
    EuidOrRoot,
}

impl DirOwner {
    /// Whether a directory owned by `uid` is accepted from a process whose
    /// effective uid is `euid`.
    const fn accepts(self, uid: u32, euid: u32) -> bool {
        match self {
            Self::Euid => uid == euid,
            Self::EuidOrRoot => uid == euid || uid == 0,
        }
    }
}

/// Require that `dir` is a real directory, not a symlink, owned as `owner`
/// accepts (against [`process_euid`]), with no group or other write bit.
/// `what` names it in the error.
pub(crate) fn require_trusted_dir(
    dir: &Path,
    what: &str,
    owner: DirOwner,
) -> Result<(), ProtoError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat};
    let untrusted = || ProtoError::Io(format!("{what} is not trusted"));
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| match err {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => untrusted(),
        err => ProtoError::Io(format!("open {what}: {err}")),
    })?;
    let stat = fstat(&fd).map_err(|err| ProtoError::Io(format!("stat {what}: {err}")))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || !owner.accepts(stat.st_uid, process_euid())
        || stat.st_mode & 0o022 != 0
    {
        return Err(untrusted());
    }
    Ok(())
}

/// Remove `path` with `unlinkat(2)`.
///
/// The confined monitor's seccomp table (`MONITOR`) allows `unlinkat` but not
/// the legacy `unlink` that `std::fs::remove_file` issues on `x86_64`, which
/// kills the process with `SIGSYS`. Every removal the monitor makes while it
/// serves goes through here.
fn unlink(path: &Path) -> std::io::Result<()> {
    rustix::fs::unlinkat(rustix::fs::CWD, path, rustix::fs::AtFlags::empty())
        .map_err(std::io::Error::from)
}

/// Rename `from` over `to` with `renameat(2)`.
///
/// `std::fs::rename` issues the legacy `rename` on `x86_64`, which `MONITOR`
/// lacks (see [`unlink`]).
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    rustix::fs::renameat(rustix::fs::CWD, from, rustix::fs::CWD, to).map_err(std::io::Error::from)
}

/// Copy the contents and the mode of `from` to a new file `to`.
///
/// `std::fs::copy` calls `copy_file_range(2)`, which `MONITOR` lacks, so this
/// reads and writes instead. `to` must not exist (`O_EXCL`). The mode is set
/// with `fchmod`, so the process umask does not change it, as in
/// `std::fs::copy`.
pub(crate) fn copy_file(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut source = std::fs::File::open(from)?;
    let permissions = source.metadata()?.permissions();
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes)?;
    let mut copy = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(permissions.mode())
        .open(to)?;
    copy.set_permissions(permissions)?;
    copy.write_all(&bytes)
}

/// Removes a file the monitor owns when dropped, so no failure path leaves a
/// candidate or an unauthenticated image behind; a missing file (already
/// swapped in) is not an error.
struct RemoveOnDrop<'a>(&'a Path);

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        let _ = unlink(self.0);
    }
}

/// Create a [`CANDIDATE_PREFIX`] file in `dir` (`O_EXCL`, `0600`) that
/// `tempfile` will not remove: its own drop calls the legacy `unlink` (see
/// [`unlink`]). The caller removes the returned path with [`RemoveOnDrop`].
fn create_candidate(dir: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    let (file, path) = tempfile::Builder::new()
        .prefix(CANDIDATE_PREFIX)
        .disable_cleanup(true)
        .tempfile_in(dir)?
        .into_parts();
    Ok((file, path.to_path_buf()))
}

fn materialize_staged(
    state_root: &Path,
    monitor_staging_dir: &Path,
    tag: &str,
    len: u64,
    expected: crate::fs::atomic::Sha256Digest,
) -> Result<(), ProtoError> {
    use rustix::fs::{Mode, OFlags};
    let source = staged_input_path(state_root, tag)?;
    let dir = ensure_staging_dir(monitor_staging_dir)?;
    let destination = staged_path(&dir, expected);
    if source == destination {
        return Err(ProtoError::VerificationFailed);
    }
    let mut bytes = Vec::new();
    let source_file = open_staged_input(state_root, tag)?;
    if let Err(err) = (&source_file)
        .take(u64::from(u32::MAX))
        .read_to_end(&mut bytes)
    {
        return Err(ProtoError::Io(format!(
            "read staged binary: {}",
            err.kind()
        )));
    }
    if bytes.len() as u64 != len {
        return Err(ProtoError::Io(
            "staged binary size does not match the request".to_owned(),
        ));
    }
    let actual = crate::fs::atomic::Sha256Digest::of(&bytes);
    if actual != expected {
        return Err(ProtoError::Conflict {
            expected,
            actual: Some(actual),
        });
    }
    let fd = rustix::fs::open(
        &destination,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|err| ProtoError::Io(format!("materialize staged binary: {err}")))?;
    let file: std::fs::File = fd.into();
    let written = write_all_and_sync(&file, &bytes)
        .map_err(|err| ProtoError::Io(format!("materialize staged binary: {}", err.kind())))
        .and_then(|()| {
            std::fs::File::open(dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| ProtoError::Io(format!("sync staging directory: {}", err.kind())))
        });
    if written.is_err() {
        // The copy is incomplete or not durable: do not leave it to be found.
        let _ = unlink(&destination);
    }
    written
}

#[cfg(feature = "update")]
fn read_bounded_file(file: &std::fs::File, max: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    file.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(std::io::Error::other("file exceeds size cap"));
    }
    Ok(bytes)
}

/// Open `path` with `O_NOFOLLOW`, require ownership by the monitor's own
/// euid, and return the bytes read from that same fd.
///
/// The `len` gate doubles as the allocation cap: at most `u32::MAX` bytes
/// are read (the privsep frame cap is 1 MiB, so production requests are far
/// smaller), and the digest gate compares the fd bytes against `expected`.
/// Reading from the open fd — not a second `fs::read(path)` — closes the
/// check-then-use race where a worker-owned path is swapped or replaced
/// between the check and the swap.
fn read_staged_verified(
    path: &Path,
    len: u64,
    expected: crate::fs::atomic::Sha256Digest,
) -> Result<Vec<u8>, ProtoError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(err) if err == rustix::io::Errno::NOENT => {
            return Err(ProtoError::Io("staged binary is missing".to_owned()));
        }
        Err(err) => {
            return Err(ProtoError::Io(format!("open staged binary: {err}")));
        }
    };
    let file: std::fs::File = fd.into();
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => {
            return Err(ProtoError::Io(format!(
                "stat staged binary: {}",
                err.kind()
            )));
        }
    };
    if !meta.is_file() {
        return Err(ProtoError::Io(
            "staged binary is not a regular file".to_owned(),
        ));
    }
    // A hard link shares the owner's uid, so ownership alone cannot prove the
    // worker did not link a root-owned file (an older signed build, `.prev`,
    // `/bin/true`) into the staged path: refuse anything with two names.
    if meta.nlink() != 1 {
        tracing::warn!("staged binary refused: hard link");
        return Err(ProtoError::Io("staged binary is not trusted".to_owned()));
    }
    // The monitor staging directory itself must belong to whoever the monitor
    // runs as and must not be group- or world-writable: otherwise a worker
    // could replace the materialized path between the check and the swap.
    // `fstatat` on the parent runs before the child opens above.
    let parent_meta = match std::fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| ProtoError::Io("staged binary is not trusted".to_owned()))?,
    ) {
        Ok(meta) => meta,
        Err(err) => {
            return Err(ProtoError::Io(format!(
                "stat staged directory: {}",
                err.kind()
            )));
        }
    };
    // The staged file must belong to whoever the monitor runs as: in
    // production that is root, so a `detent`-owned file the worker planted
    // refuses; in dev/test the monitor runs as the dev uid, so the same
    // comparison keeps the suite exercising the gate instead of skipping it.
    if meta.uid() != process_euid()
        || parent_meta.uid() != process_euid()
        || parent_meta.mode() & 0o022 != 0
    {
        tracing::warn!("staged binary refused: untrusted owner");
        return Err(ProtoError::Io("staged binary is not trusted".to_owned()));
    }
    if meta.len() != len {
        return Err(ProtoError::Io(
            "staged binary size does not match the request".to_owned(),
        ));
    }
    let capped = usize::try_from(len).unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    // ponytail: `take` caps a lying `len` (TOCTOU on size); the digest check
    // below still decides.
    if let Err(err) = (&file).take(u64::from(u32::MAX)).read_to_end(&mut bytes) {
        return Err(ProtoError::Io(format!(
            "read staged binary: {}",
            err.kind()
        )));
    }
    if bytes.len() != capped {
        return Err(ProtoError::Io(
            "staged binary size does not match the request".to_owned(),
        ));
    }
    let actual = crate::fs::atomic::Sha256Digest::of(&bytes);
    if actual != expected {
        return Err(ProtoError::Conflict {
            expected,
            actual: Some(actual),
        });
    }
    Ok(bytes)
}

/// Target of the binary swap in production: the running executable.
fn current_exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("detent"))
}

/// Atomically swap verified staged `bytes` over `target`, keeping the
/// previous binary at `<target>.prev`.
///
/// `bytes` are the image [`read_staged_verified`] already opened
/// (`O_NOFOLLOW`), ownership-checked, and hashed from the same fd — the swap
/// writes those bytes, never a re-read of `staged`, so a worker-owned path
/// swapped in after verification cannot reach the target. Renames on POSIX
/// are atomic on the same filesystem, and we keep the temp file in the
/// target's own directory to honor that. A hard link keeps the previous
/// binary as a cheap second name; on a filesystem that disallows links the
/// swap falls back to copying the bytes.
fn swap_running_binary(bytes: &[u8], staged: &Path, target: &Path) -> Result<(), ProtoError> {
    let previous = target.with_file_name({
        let mut name = std::ffi::OsString::from(target.file_name().map_or_else(
            || "detent".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        ));
        name.push(PREVIOUS_SUFFIX);
        name
    });

    // `symlink_metadata` so a symlinked target is refused rather than quietly
    // replaced: the running binary is always a regular file in production.
    let target_meta = match std::fs::symlink_metadata(target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProtoError::Io("running binary is missing".to_owned()));
        }
        Err(err) => {
            return Err(ProtoError::Io(format!(
                "stat running binary: {}",
                err.kind()
            )));
        }
    };
    if !target_meta.is_file() {
        return Err(ProtoError::Io(
            "running binary is not a regular file".to_owned(),
        ));
    }

    if let Err(err) = unlink(&previous)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(ProtoError::Io(format!(
            "unlink previous binary: {}",
            err.kind()
        )));
    }
    if let Err(err) = std::fs::hard_link(target, &previous)
        && let Err(copy_err) = copy_file(target, &previous)
    {
        return Err(ProtoError::Io(format!(
            "keep previous binary: {} (fallback copy: {})",
            err.kind(),
            copy_err.kind()
        )));
    }
    // Stage into the target's own directory first: the monitor staging base is
    // on a separate filesystem from the running binary, so a cross-filesystem
    // `rename` would fail with EXDEV. Write the verified `bytes` there, chmod,
    // then rename; same convention as `detent_update::install::stage`.
    let target_dir = target.parent().map_or_else(
        || std::path::PathBuf::from("/"),
        std::path::Path::to_path_buf,
    );
    let staged_name = staged.file_name().map_or_else(
        || std::ffi::OsString::from("detent-staged"),
        std::ffi::OsString::from,
    );
    let mut tmp_name = staged_name;
    // Pid-unique: two concurrent swaps on the same target must not share a
    // temp name. A crash after the write leaves at most one orphaned
    // `.tmp.<pid>` beside target.
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = target_dir.join(tmp_name);
    let _ = unlink(&tmp);
    write_temp_and_swap(
        bytes,
        staged,
        target,
        &target_dir,
        &tmp,
        &target_meta.permissions(),
    )
}

/// Write verified `bytes` to `tmp` (`create_new`, fsynced), chmod to the
/// target's mode, rename over `target`, and fsync the directory.
fn write_temp_and_swap(
    bytes: &[u8],
    staged: &Path,
    target: &Path,
    target_dir: &Path,
    tmp: &Path,
    permissions: &std::fs::Permissions,
) -> Result<(), ProtoError> {
    use rustix::fs::{Mode, OFlags};
    // Write the verified bytes (not a link/copy of the staged path): the
    // staged file was hashed from an open fd, and re-reading the path here
    // would re-open the worker's TOCTOU window. `EXCL` so a leftover temp
    // from a crashed swap is never silently truncated; `sync_all` before
    // the rename so a crash cannot leave a torn target behind.
    let fd = match rustix::fs::open(
        tmp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o700),
    ) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = unlink(tmp);
            return Err(ProtoError::Io(format!("stage binary in target dir: {err}")));
        }
    };
    let tmp_file: std::fs::File = fd.into();
    if let Err(err) = write_all_and_sync(&tmp_file, bytes) {
        let _ = unlink(tmp);
        return Err(ProtoError::Io(format!(
            "stage binary in target dir: {}",
            err.kind()
        )));
    }
    // The installed binary must keep the *target's* mode, not the staged
    // file's — otherwise the swap installs a non-executable binary and the
    // next `--self-test` fails with EACCES (a58f89c / stage_exec.rs).
    if let Err(err) = tmp_file.set_permissions(permissions.clone()) {
        let _ = unlink(tmp);
        return Err(ProtoError::Io(format!(
            "chmod staged binary: {}",
            err.kind()
        )));
    }
    if let Err(err) = tmp_file.sync_all() {
        let _ = unlink(tmp);
        return Err(ProtoError::Io(format!(
            "sync staged binary: {}",
            err.kind()
        )));
    }
    drop(tmp_file);
    if let Err(err) = rename(tmp, target) {
        let _ = unlink(tmp);
        return Err(ProtoError::Io(format!(
            "rename staged binary over target: {}",
            err.kind()
        )));
    }
    // Fsync the target directory so the rename itself is durable. A directory
    // that cannot be opened is an error too: skipping the fsync silently would
    // report a swap whose rename may not survive a crash.
    if let Err(err) = std::fs::File::open(target_dir).and_then(|dir| dir.sync_all()) {
        return Err(ProtoError::Io(format!(
            "sync target directory: {}",
            err.kind()
        )));
    }
    // Staged file consumed: the verified bytes now live at the target.
    let _ = unlink(staged);
    Ok(())
}

/// A failed send is only a monitor error when it is not simply the peer going
/// away underneath us.
fn finish_send_error(err: ChannelError) -> Result<ExitReason, MonitorError> {
    match err {
        // A worker that stops reading is as gone as one that closed the socket.
        ChannelError::Closed | ChannelError::Timeout => Ok(ExitReason::PeerClosed),
        ChannelError::Oversize { len } => {
            tracing::error!(len, "a response exceeded the frame limit");
            Ok(ExitReason::ProtocolViolation)
        }
        other => Err(MonitorError::Channel(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CheckRunner, DirOwner, ExitReason, HookError, Hooks, InPlaceOutcome, MAX_CONFIRM_TIMEOUT_S,
        MONITOR_LOCK, Monitor, MonitorError, PENDING_COMMIT_MARKER, PREVIOUS_SUFFIX,
        PendingCommitMarker, STAGED_DIR, ServiceControl, StateLock, finish_send_error,
        materialize_staged, read_staged_verified, staged_path, swap_running_binary,
        write_temp_and_swap,
    };
    use crate::fs::atomic::{AtomicError, InPlaceMarker, Sha256Digest};
    use crate::privsep::allowlist::{Allowlist, AllowlistError, Config};
    use crate::privsep::proto::{
        BackupId, BindingId, CheckId, CheckOutcome, CommitId, IdKind, ModuleId, MountOutcome,
        MountState, PROTO_VERSION, PendingService, ProtoError, Request, Response, ServiceAction,
        ServiceOutcome, TargetId,
    };
    use crate::privsep::transport::{Channel, ChannelError};
    use crate::privsep::worker::Client;
    use detent_core::descriptor::{
        ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, MountUnit,
        Owner, PathSpec, ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind,
        UnitNames, Upstream,
    };
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use detent_core::module::{DynError, DynModule, ModelError, ParseError};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::TempDir;

    /// A `tracing::Subscriber` that is interested in every callsite, so the
    /// crate's `tracing::info!`/`warn!`/`error!` call sites actually run
    /// (and are covered) instead of being skipped by interest-caching
    /// against tracing's default no-op dispatcher. Installed once, globally,
    /// because `tracing` panics if a global default is set twice.
    struct AlwaysOn;

    impl tracing::Subscriber for AlwaysOn {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, _event: &tracing::Event<'_>) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn install_tracing() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tracing::subscriber::set_global_default(AlwaysOn);
        });
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

    fn leak_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn leak<T>(value: T) -> &'static T {
        Box::leak(Box::new(value))
    }

    /// A one-target, one-check, one-service module descriptor pointing at a
    /// real temp file, mirroring the fixture in `tests/privsep_e2e.rs` but
    /// kept local so this module's white-box tests do not depend on an
    /// integration test crate.
    fn descriptor(target_path: &Path) -> &'static ModuleDescriptor {
        descriptor_with_id(target_path, "fake")
    }

    fn descriptor_with_id(
        target_path: &Path,
        module_id: &'static str,
    ) -> &'static ModuleDescriptor {
        descriptor_with_kind(target_path, module_id, TargetKind::File)
    }

    fn descriptor_with_kind(
        target_path: &Path,
        module_id: &'static str,
        kind: TargetKind,
    ) -> &'static ModuleDescriptor {
        let target_path = leak_str(target_path.display().to_string());
        let targets: &'static [Target] = leak(vec![Target {
            path: PathSpec::new(target_path),
            kind,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: always,
        }])
        .as_slice();
        let actions: &'static [CoreServiceAction] =
            leak(vec![CoreServiceAction::Restart]).as_slice();
        let services: &'static [ServiceBinding] = leak(vec![ServiceBinding {
            units: UnitNames {
                systemd: &["fake.service"],
                openrc: &[],
                bsdrc: &[],
            },
            actions,
        }])
        .as_slice();
        let args: &'static [ArgTemplate] =
            leak(vec![ArgTemplate::Literal("-p"), ArgTemplate::TempFile]).as_slice();
        let checks: &'static [ExternalCheck] = leak(vec![ExternalCheck {
            program: PathSpec::new("/nonexistent/detent-monitor-test-check"),
            args,
            expects: CheckExpectation::ExitZero,
        }])
        .as_slice();
        leak(ModuleDescriptor {
            id: module_id,
            display_name_id: MessageId::new("fake-name"),
            targets,
            upstream: UPSTREAM,
            services,
            checks,
            commit_confirm: false,
            reload_unit_files: false,
            added_mounts: None,
            security_notes: &[],
        })
    }

    struct SyntheticModule {
        descriptor: &'static ModuleDescriptor,
    }

    impl DynModule for SyntheticModule {
        fn id(&self) -> &'static str {
            self.descriptor.id
        }

        fn descriptor(&self) -> &'static ModuleDescriptor {
            self.descriptor
        }
        fn clone_box(&self) -> Box<dyn DynModule> {
            Box::new(Self {
                descriptor: self.descriptor,
            })
        }

        fn schema_json(&self) -> Value {
            Value::Null
        }

        fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError> {
            Ok(json!({ "text": src }))
        }

        fn apply_json(&self, src: &str, _model_json: &Value) -> Result<String, DynError> {
            Ok(src.to_owned())
        }

        fn validate_json(
            &self,
            _model_json: &Value,
            _ctx: &detent_core::descriptor::ValidationCtx<'_>,
        ) -> Result<Diagnostics, DynError> {
            Ok(Diagnostics::new())
        }

        fn defaults_json(&self, _profile: &HostProfile) -> Result<Value, DynError> {
            Ok(Value::Null)
        }
    }

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        state_root: PathBuf,
        target: PathBuf,
    }

    impl Fixture {
        fn allow(&self) -> Result<Allowlist, AllowlistError> {
            let module = descriptor(&self.target);
            Allowlist::from_modules(&[module], &Config::with_state_root(&self.state_root))
        }

        /// The allow-list of a module whose only target is the drop-in
        /// directory `conf.d`, so it has no file target to write beside.
        fn allow_without_a_file_target(&self) -> Result<Allowlist, AllowlistError> {
            let module =
                descriptor_with_kind(&self.root.join("conf.d"), "fake", TargetKind::DropInDir);
            Allowlist::from_modules(&[module], &Config::with_state_root(&self.state_root))
        }
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let root = dir.path().to_path_buf();
        let target = root.join("target.conf");
        assert!(std::fs::write(&target, b"v1").is_ok());
        Ok(Fixture {
            state_root: root.join("state"),
            root,
            _dir: dir,
            target,
        })
    }

    /// A monitor that has already completed the handshake, so `dispatch` can
    /// be called directly with any other request.
    fn greeted(allow: Allowlist, hooks: Hooks<'_>) -> Monitor<'_> {
        let registry = allow
            .module(ModuleId(0))
            .map(|descriptor| vec![Box::new(SyntheticModule { descriptor }) as Box<dyn DynModule>]);
        greeted_with_registry(allow, hooks, registry)
    }

    fn greeted_real(allow: Allowlist, hooks: Hooks<'_>) -> Monitor<'_> {
        greeted_with_registry(allow, hooks, None)
    }

    fn greeted_with_registry(
        allow: Allowlist,
        hooks: Hooks<'_>,
        registry: Option<Vec<Box<dyn DynModule>>>,
    ) -> Monitor<'_> {
        let staging_dir = allow.state_root().with_file_name("monitor-staging");
        let mut monitor = Monitor::new(allow, hooks);
        monitor.set_staging_dir(staging_dir);
        if let Some(registry) = registry {
            monitor.set_module_registry(registry);
        }
        let _ = monitor.dispatch(Request::Hello {
            proto: PROTO_VERSION,
        });
        monitor
    }

    struct OkChecks;
    impl CheckRunner for OkChecks {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            _candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            Ok(CheckOutcome {
                check: CheckId(0),
                passed: true,
                exit_code: Some(0),
                detail: "ok".to_owned(),
            })
        }
    }

    #[test]
    fn monitor_allows_existing_execution_directives() {
        let content = b"root preexec = /bin/true\n";
        assert!(!Monitor::has_new_forbidden_exec_directive(
            "samba", content, content
        ));
        assert!(Monitor::has_new_forbidden_exec_directive(
            "samba",
            b"[global]\n",
            b"[global]\nroot preexec = /bin/true\n"
        ));
    }

    struct CandidateChecks(PathBuf);
    impl CheckRunner for CandidateChecks {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            if candidate.parent() != Some(self.0.as_path()) {
                return Err(HookError::Failed(
                    "candidate is outside state root".to_owned(),
                ));
            }
            Ok(CheckOutcome {
                check: CheckId(0),
                passed: true,
                exit_code: Some(0),
                detail: "ok".to_owned(),
            })
        }
    }

    /// Records each candidate's path and contents while the check runs.
    #[derive(Default)]
    struct RecordingChecks(std::sync::Mutex<Vec<(PathBuf, Vec<u8>)>>);
    impl RecordingChecks {
        fn seen(&self) -> Vec<(PathBuf, Vec<u8>)> {
            self.0.lock().map(|seen| seen.clone()).unwrap_or_default()
        }
    }
    impl CheckRunner for RecordingChecks {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            let bytes =
                std::fs::read(candidate).map_err(|err| HookError::Failed(err.to_string()))?;
            self.0
                .lock()
                .map_err(|_| HookError::Failed("poisoned".to_owned()))?
                .push((candidate.to_path_buf(), bytes));
            Ok(CheckOutcome {
                check: CheckId(0),
                passed: true,
                exit_code: Some(0),
                detail: "ok".to_owned(),
            })
        }
    }

    /// True when `path` is a `.detent-candidate-` file directly in `dir`.
    fn is_candidate_in(path: &Path, dir: &Path) -> bool {
        path.parent() == Some(dir)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".detent-candidate-"))
    }

    /// Names of the entries of `dir`, sorted.
    fn entries(dir: &Path) -> Result<Vec<String>, std::io::Error> {
        let mut names = std::fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    struct FailingChecks;
    impl CheckRunner for FailingChecks {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            _candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            Err(HookError::Failed("boom".to_owned()))
        }
    }

    struct OkServices;
    impl ServiceControl for OkServices {
        fn service(
            &self,
            _binding: &ServiceBinding,
            _action: CoreServiceAction,
        ) -> Result<ServiceOutcome, HookError> {
            Ok(ServiceOutcome {
                binding: BindingId(0),
                active: true,
                detail: "running".to_owned(),
            })
        }
    }

    struct FailingServices;
    impl ServiceControl for FailingServices {
        fn service(
            &self,
            _binding: &ServiceBinding,
            _action: CoreServiceAction,
        ) -> Result<ServiceOutcome, HookError> {
            Err(HookError::Failed("boom".to_owned()))
        }

        fn reload_unit_files(&self) -> Result<String, HookError> {
            Err(HookError::Failed("reload boom".to_owned()))
        }
    }
    // -- getters and formatting ----------------------------------------------

    #[test]
    fn getters_expose_the_allowlist_and_pending_state() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let monitor = greeted(fx.allow()?, Hooks::default());
        assert_eq!(monitor.allowlist().module_id("fake"), Some(ModuleId(0)));
        assert!(!monitor.has_pending_commit());
        Ok(())
    }

    #[test]
    fn debug_format_of_the_monitor_does_not_panic() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let monitor = greeted(fx.allow()?, Hooks::default());
        assert!(format!("{monitor:?}").contains("Hooks"));
        Ok(())
    }

    // -- run_check ------------------------------------------------------------

    #[test]
    fn run_check_reports_success_through_a_working_check_runner()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &OkChecks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?;
        assert!(matches!(response, Response::Checked(outcome) if outcome.passed));
        Ok(())
    }

    /// The candidate goes beside the module's primary target, where the
    /// distro's `AppArmor` profile for the validator lets it read, under a
    /// dot name that include-directory loaders skip, and is removed after.
    #[test]
    fn run_check_places_the_candidate_beside_the_primary_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let allow = fx.allow()?;
        let staging_dir = allow.state_root().with_file_name("monitor-staging");
        let checks = RecordingChecks::default();
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?;
        assert!(matches!(response, Response::Checked(outcome) if outcome.passed));
        let seen = checks.seen();
        assert_eq!(seen.len(), 1);
        let (path, bytes) = seen.first().ok_or("the check did not run")?;
        assert!(is_candidate_in(path, &fx.root), "candidate at {path:?}");
        assert_eq!(bytes, b"candidate");
        assert!(!path.exists(), "the candidate must be removed");
        assert_eq!(entries(&fx.root)?, ["target.conf"]);
        assert!(!staging_dir.exists(), "staging must not be used");
        Ok(())
    }

    /// A module whose primary target is not a file keeps using monitor
    /// staging.
    #[test]
    fn run_check_uses_monitor_staging_for_a_module_without_a_file_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let allow = fx.allow_without_a_file_target()?;
        let staging_dir = allow.state_root().with_file_name("monitor-staging");
        let checks = RecordingChecks::default();
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?;
        assert!(matches!(response, Response::Checked(outcome) if outcome.passed));
        let seen = checks.seen();
        let (path, bytes) = seen.first().ok_or("the check did not run")?;
        assert!(is_candidate_in(path, &staging_dir), "candidate at {path:?}");
        assert_eq!(bytes, b"candidate");
        assert_eq!(std::fs::read_dir(&staging_dir)?.count(), 0);
        Ok(())
    }

    /// A monitor over the fixture module with its target at `target`.
    fn run_check_beside(
        target: &Path,
        checks: &RecordingChecks,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let allow = Allowlist::from_modules(
            &[descriptor(target)],
            &Config::with_state_root(work.path().join("state")),
        )?;
        let hooks = Hooks {
            checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        Ok(monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?)
    }

    fn assert_candidate_dir_refused(response: &Response) {
        assert!(
            matches!(response, Response::Error(ProtoError::Io(message)) if message == "candidate directory is not trusted"),
            "expected the candidate directory to be refused, got {response:?}"
        );
    }

    /// Fail closed on a target directory others can write to: no fallback
    /// to staging, and nothing is left behind.
    #[test]
    fn run_check_refuses_a_group_writable_target_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let etc = fx.root.join("etc");
        std::fs::create_dir(&etc)?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o770))?;
        let checks = RecordingChecks::default();
        assert_candidate_dir_refused(&run_check_beside(&etc.join("target.conf"), &checks)?);
        assert!(checks.seen().is_empty());
        assert!(entries(&etc)?.is_empty());
        assert_eq!(
            std::fs::metadata(&etc)?.permissions().mode() & 0o777,
            0o770,
            "an existing directory must not be chmodded"
        );
        Ok(())
    }

    #[test]
    fn run_check_refuses_a_symlinked_target_directory() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let real = fx.root.join("real");
        std::fs::create_dir(&real)?;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755))?;
        let link = fx.root.join("etc");
        std::os::unix::fs::symlink(&real, &link)?;
        let checks = RecordingChecks::default();
        assert_candidate_dir_refused(&run_check_beside(&link.join("target.conf"), &checks)?);
        assert!(checks.seen().is_empty());
        assert!(entries(&real)?.is_empty());
        Ok(())
    }

    /// A uid that is neither root nor, in these tests, the euid.
    const STRANGER_UID: u32 = 65534;

    /// A target directory owned by a uid that is neither root nor the euid is
    /// refused. Only root can make one, so an unprivileged run relies on
    /// `dir_owner_accepts_only_the_owners_it_names` instead.
    #[test]
    fn run_check_refuses_a_target_directory_owned_by_another_user()
    -> Result<(), Box<dyn std::error::Error>> {
        if !rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        let etc = fx.root.join("etc");
        std::fs::create_dir(&etc)?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755))?;
        rustix::fs::chown(
            &etc,
            Some(rustix::fs::Uid::from_raw(STRANGER_UID)),
            Some(rustix::fs::Gid::from_raw(STRANGER_UID)),
        )?;
        let checks = RecordingChecks::default();
        assert_candidate_dir_refused(&run_check_beside(&etc.join("target.conf"), &checks)?);
        assert!(checks.seen().is_empty());
        assert!(entries(&etc)?.is_empty());
        Ok(())
    }

    /// Capability-user mode: a monitor that is not root still trusts a
    /// root-owned target directory. `/usr` is root-owned and not writable
    /// for an unprivileged user, so the directory check passes, creating the
    /// candidate there is denied, and the candidate goes to monitor staging
    /// instead. As root the directory would really be written to, so that
    /// run relies on `dir_owner_accepts_only_the_owners_it_names` instead.
    #[test]
    fn run_check_trusts_a_root_owned_target_directory() -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let checks = RecordingChecks::default();
        let response = run_check_beside(Path::new("/usr/detent-monitor-test.conf"), &checks)?;
        assert!(
            matches!(&response, Response::Checked(outcome) if outcome.passed),
            "expected the root-owned directory to be trusted, got {response:?}"
        );
        let seen = checks.seen();
        let (path, _) = seen.first().ok_or("the check did not run")?;
        assert!(
            path.parent()
                .is_some_and(|dir| dir.ends_with("monitor-staging")),
            "candidate at {path:?}"
        );
        Ok(())
    }

    /// A trusted target directory the monitor cannot write (a read-only file
    /// system under `ProtectSystem=strict`, or no write permission) is not a
    /// dead end: the candidate goes to monitor staging and the check runs.
    /// Only an unprivileged run can provoke it (root ignores the mode).
    #[test]
    fn run_check_falls_back_to_staging_when_the_target_directory_is_not_writable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let work = TempDir::new()?;
        let etc = work.path().join("etc");
        std::fs::create_dir(&etc)?;
        std::fs::write(etc.join("target.conf"), b"v1")?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o555))?;
        let allow = Allowlist::from_modules(
            &[descriptor(&etc.join("target.conf"))],
            &Config::with_state_root(work.path().join("state")),
        )?;
        let staging_dir = allow.state_root().with_file_name("monitor-staging");
        let checks = RecordingChecks::default();
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?;
        let write = write_v2(&mut monitor)?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755))?;
        assert!(
            matches!(&response, Response::Checked(outcome) if outcome.passed),
            "{response:?}"
        );
        // The write path places its candidate the same way; the write itself
        // then fails in the read-only directory, after the check.
        assert!(
            !matches!(&write, Response::Error(ProtoError::Io(message)) if message.starts_with("cannot create a candidate file")),
            "{write:?}"
        );
        let seen = checks.seen();
        assert_eq!(seen.len(), 2, "both checks ran: {seen:?}");
        for (path, _) in &seen {
            assert!(is_candidate_in(path, &staging_dir), "candidate at {path:?}");
        }
        assert_eq!(entries(&etc)?, ["target.conf"]);
        assert_eq!(entries(&staging_dir)?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn dir_owner_accepts_only_the_owners_it_names() {
        let euid = 1000;
        assert!(DirOwner::Euid.accepts(euid, euid));
        assert!(!DirOwner::Euid.accepts(0, euid));
        assert!(!DirOwner::Euid.accepts(STRANGER_UID, euid));
        assert!(DirOwner::EuidOrRoot.accepts(euid, euid));
        assert!(DirOwner::EuidOrRoot.accepts(0, euid));
        assert!(!DirOwner::EuidOrRoot.accepts(STRANGER_UID, euid));
        // A root monitor: root is its own euid.
        assert!(DirOwner::Euid.accepts(0, 0));
        assert!(DirOwner::EuidOrRoot.accepts(0, 0));
        assert!(!DirOwner::EuidOrRoot.accepts(STRANGER_UID, 0));
    }

    #[test]
    fn run_check_maps_a_failed_hook_to_an_io_error() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &FailingChecks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: Vec::new(),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    #[test]
    fn run_check_rejects_an_unknown_check_id() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(99),
            bytes: Vec::new(),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId { .. })
        ));
        Ok(())
    }

    #[test]
    fn run_check_reports_io_error_when_the_candidate_directory_cannot_be_created()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let staging_dir = fx.state_root.join("staging");
        assert!(std::fs::write(&staging_dir, b"not a directory").is_ok());
        let mut monitor = greeted(fx.allow_without_a_file_target()?, Hooks::default());
        monitor.set_staging_dir(staging_dir);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: Vec::new(),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    #[test]
    fn run_check_reports_io_error_when_the_candidate_directory_is_not_writable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            // root ignores DAC, so the failure cannot be provoked this way.
            return Ok(());
        }
        let fx = fixture()?;
        let tmp_dir = fx.state_root.join("staging");
        assert!(std::fs::create_dir_all(&tmp_dir).is_ok());
        assert!(std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o500)).is_ok());
        let mut monitor = greeted(fx.allow_without_a_file_target()?, Hooks::default());
        monitor.set_staging_dir(tmp_dir.clone());
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: Vec::new(),
        })?;
        assert!(std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o700)).is_ok());
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    fn run_check_in(staging_dir: PathBuf) -> Result<Response, Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let checks = CandidateChecks(staging_dir.clone());
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow_without_a_file_target()?, hooks);
        monitor.set_staging_dir(staging_dir);
        Ok(monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?)
    }

    fn assert_staging_refused(response: &Response) {
        assert!(
            matches!(response, Response::Error(ProtoError::Io(message)) if message == "monitor staging directory is not trusted"),
            "expected the staging directory to be refused, got {response:?}"
        );
    }

    #[test]
    fn run_check_refuses_a_world_writable_staging_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let staging_dir = work.path().join("staging");
        std::fs::create_dir(&staging_dir)?;
        std::fs::set_permissions(&staging_dir, std::fs::Permissions::from_mode(0o777))?;
        assert_staging_refused(&run_check_in(staging_dir.clone())?);
        let mode = std::fs::metadata(&staging_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o777, "an existing directory must not be chmodded");
        Ok(())
    }

    #[test]
    fn run_check_refuses_a_symlinked_staging_directory() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let real = work.path().join("real");
        std::fs::create_dir(&real)?;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))?;
        let staging_dir = work.path().join("staging");
        std::os::unix::fs::symlink(&real, &staging_dir)?;
        assert_staging_refused(&run_check_in(staging_dir)?);
        assert_eq!(std::fs::read_dir(&real)?.count(), 0);
        Ok(())
    }

    #[test]
    fn run_check_refuses_a_staging_directory_owned_by_another_user()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let staging_dir = if rustix::process::geteuid().is_root() {
            let dir = work.path().join("staging");
            std::fs::create_dir(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            rustix::fs::chown(
                &dir,
                Some(rustix::fs::Uid::from_raw(65534)),
                Some(rustix::fs::Gid::from_raw(65534)),
            )?;
            dir
        } else {
            // Unprivileged: an existing root-owned, non-writable directory.
            PathBuf::from("/usr")
        };
        assert_staging_refused(&run_check_in(staging_dir)?);
        Ok(())
    }

    #[test]
    fn run_check_creates_a_missing_staging_directory_private()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let staging_dir = work.path().join("nested").join("staging");
        let response = run_check_in(staging_dir.clone())?;
        assert!(
            !matches!(&response, Response::Error(ProtoError::Io(message)) if message.contains("not trusted")),
            "a fresh staging directory must be accepted, got {response:?}"
        );
        assert_eq!(
            std::fs::metadata(&staging_dir)?.permissions().mode() & 0o777,
            0o700
        );
        Ok(())
    }

    // -- service ----------------------------------------------------------------

    #[test]
    fn service_reports_success_through_a_working_service_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &OkServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::Service {
            binding: BindingId(0),
            action: ServiceAction::Restart,
        })?;
        assert!(matches!(response, Response::Serviced(outcome) if outcome.active));
        Ok(())
    }

    #[test]
    fn service_maps_a_failed_hook_to_an_io_error() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &FailingServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::Service {
            binding: BindingId(0),
            action: ServiceAction::Restart,
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    #[test]
    fn service_rejects_an_unknown_binding_id() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::Service {
            binding: BindingId(99),
            action: ServiceAction::Restart,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId { .. })
        ));
        Ok(())
    }

    #[test]
    fn service_status_is_not_implemented_yet() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::Service {
            binding: BindingId(0),
            action: ServiceAction::Status,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::Unsupported(_))
        ));
        Ok(())
    }

    #[test]
    fn service_rejects_an_action_the_binding_did_not_declare()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        // The fixture's binding only declares `Restart`.
        let response = monitor.dispatch(Request::Service {
            binding: BindingId(0),
            action: ServiceAction::Stop,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::ActionNotAllowed)
        ));
        Ok(())
    }

    // -- read/write targets -----------------------------------------------------

    #[test]
    fn read_target_reports_not_found_when_the_file_is_gone()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(std::fs::remove_file(&fx.target).is_ok());
        let response = monitor.dispatch(Request::ReadTarget {
            target: TargetId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::NotFound)));
        Ok(())
    }

    #[test]
    fn write_target_rejects_an_unknown_target_id() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::WriteTarget {
            target: TargetId(99),
            expected_prev: None,
            bytes: b"x".to_vec(),
            journal: false,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId { .. })
        ));
        Ok(())
    }

    #[test]
    fn write_target_creates_a_missing_file() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(std::fs::remove_file(&fx.target).is_ok());
        let response = monitor.dispatch(Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: b"created\n".to_vec(),
            journal: false,
        })?;
        assert!(matches!(response, Response::Written(receipt) if receipt.created));
        assert_eq!(std::fs::read(&fx.target)?, b"created\n");
        Ok(())
    }

    #[test]
    fn write_target_refuses_new_root_exec_directives() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let target = dir.path().join("smb.conf");
        let original = b"[global]\nworkgroup = EXAMPLE\n";
        std::fs::write(&target, original)?;
        let allow = Allowlist::from_modules(
            &[descriptor_with_id(&target, "samba")],
            &Config::with_state_root(dir.path().join("state")),
        )?;
        let mut monitor = greeted_real(allow, Hooks::default());
        // The second spelling is the one the H23 probe wrote to disk.
        for candidate in [
            &b"[global]\nworkgroup = EXAMPLE\nroot preexec = /bin/sh\n"[..],
            b"[global]\nworkgroup = EXAMPLE\nrootpreexec = /bin/sh\n",
        ] {
            let response = monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: candidate.to_vec(),
                journal: false,
            })?;
            assert!(matches!(response, Response::Error(_)));
            assert_eq!(std::fs::read(&target)?, original);
        }
        Ok(())
    }
    // -- backups and restore ------------------------------------------------

    #[test]
    fn list_backups_rejects_an_unknown_module() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::ListBackups {
            module: ModuleId(99),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId { .. })
        ));
        Ok(())
    }

    #[test]
    fn restore_rejects_an_unknown_module() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::Restore {
            module: ModuleId(99),
            backup: BackupId(0),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId { .. })
        ));
        Ok(())
    }

    #[test]
    fn list_backups_reports_io_error_when_a_backup_is_unreadable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        let entry = monitor
            .allowlist()
            .target(TargetId(0))
            .ok_or("the target this test just wrote to must resolve")?;
        let backup_dir = entry.backup_dir.clone();
        let mut entries = std::fs::read_dir(&backup_dir)?;
        let backup_file = entries
            .next()
            .ok_or("the write above just created exactly one backup file")??;
        assert!(
            std::fs::set_permissions(backup_file.path(), std::fs::Permissions::from_mode(0o000))
                .is_ok()
        );
        let response = monitor.dispatch(Request::ListBackups {
            module: ModuleId(0),
        });
        assert!(
            std::fs::set_permissions(backup_file.path(), std::fs::Permissions::from_mode(0o600))
                .is_ok()
        );
        let response = response?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    /// With the target directory not writable, a restore goes in place on
    /// the target file; only when the file itself is not writable either is
    /// it an error, and then no in-place marker is left.
    #[test]
    fn restore_reports_io_error_when_the_target_directory_is_not_writable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        let restore = |monitor: &mut Monitor<'_>, file_mode: u32, backup: u32| {
            std::fs::set_permissions(&fx.target, std::fs::Permissions::from_mode(file_mode))?;
            std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o500))?;
            let response = monitor.dispatch(Request::Restore {
                module: ModuleId(0),
                backup: BackupId(backup),
            });
            std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&fx.target, std::fs::Permissions::from_mode(0o644))?;
            Ok::<_, Box<dyn std::error::Error>>(response?)
        };
        let refused = restore(&mut monitor, 0o444, 0)?;
        assert!(
            matches!(refused, Response::Error(ProtoError::Io(_))),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v2");
        assert!(!fx.state_root.join(super::IN_PLACE_MARKER).exists());
        // The refused attempt kept a backup of `v2` first: `v1` is now the
        // second newest.
        let restored = restore(&mut monitor, 0o644, 1)?;
        assert!(
            matches!(restored, Response::Restored { .. }),
            "{restored:?}"
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    // -- commit-confirm -------------------------------------------------------

    #[test]
    fn enforce_deadline_logs_and_counts_a_failed_rollback() -> Result<(), Box<dyn std::error::Error>>
    {
        install_tracing();
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        let entry = monitor
            .allowlist()
            .target(TargetId(0))
            .ok_or("the target this test just wrote to must resolve")?;
        let backup_dir = entry.backup_dir.clone();
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 1,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        assert!(monitor.has_pending_commit());
        // Delete the backup the rollback needs, so it fails and is counted
        // rather than crashing the loop.
        assert!(std::fs::remove_dir_all(&backup_dir).is_ok());
        std::thread::sleep(Duration::from_millis(1300));
        assert!(monitor.enforce_deadline().is_ok());
        assert!(!monitor.has_pending_commit());
        Ok(())
    }

    #[test]
    fn confirm_commit_and_start_confirm_timer_log_through_tracing()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        let response = monitor.dispatch(Request::StartConfirmTimer {
            commit: CommitId(1),
            timeout_s: 1,
            service: None,
        })?;
        assert!(matches!(response, Response::ConfirmTimerStarted { .. }));
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(response, Response::Committed { .. }));
        assert_eq!(MAX_CONFIRM_TIMEOUT_S, 3600);
        Ok(())
    }

    #[test]
    fn confirm_after_deadline_is_rejected_and_rolls_back() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 1,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        std::thread::sleep(Duration::from_millis(1100));
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::CommitExpired(CommitId(1)))
        ));
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn rollback_commit_restores_the_target_and_clears_the_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: MAX_CONFIRM_TIMEOUT_S,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        assert!(fx.state_root.join(PENDING_COMMIT_MARKER).is_file());

        let response = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::RolledBack { commit, restored } if commit == CommitId(1) && restored == 1
        ));
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).is_file());
        Ok(())
    }

    #[test]
    fn rollback_commit_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: MAX_CONFIRM_TIMEOUT_S,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        assert!(matches!(
            monitor.dispatch(Request::RollbackCommit {
                commit: CommitId(1),
            })?,
            Response::RolledBack { .. }
        ));
        // The same request a second time finds nothing pending: it must not
        // restore again.
        let repeat = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            repeat,
            Response::Error(ProtoError::UnknownId {
                kind: IdKind::Commit,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rollback_commit_rejects_an_id_that_was_never_armed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId {
                kind: IdKind::Commit,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rollback_commit_after_the_deadline_already_fired_answers_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 1,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        std::thread::sleep(Duration::from_millis(1300));
        assert!(monitor.enforce_deadline().is_ok());
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");

        let response = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::UnknownId {
                kind: IdKind::Commit,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn write_marker_reports_io_error_when_the_state_root_cannot_be_created()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        // Now that the backup exists, replace the state root with a plain
        // file, so `write_marker`'s `create_dir_all` fails with `ENOTDIR`
        // when `StartConfirmTimer` tries to record the pending commit.
        assert!(std::fs::remove_dir_all(&fx.state_root).is_ok());
        assert!(std::fs::write(&fx.state_root, b"not a directory").is_ok());
        let response = monitor.dispatch(Request::StartConfirmTimer {
            commit: CommitId(1),
            timeout_s: 1,
            service: None,
        });
        assert!(response.is_err());
        Ok(())
    }

    #[test]
    fn write_marker_reports_io_error_when_the_state_root_is_not_writable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        // `create_dir_all` on an already-existing directory is a no-op
        // success; making it read-only instead fails the marker *file*'s
        // own creation a step later, inside `write_private`.
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o500))
                .is_ok()
        );
        let response = monitor.dispatch(Request::StartConfirmTimer {
            commit: CommitId(1),
            timeout_s: 1,
            service: None,
        });
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o700))
                .is_ok()
        );
        assert!(response.is_err());
        Ok(())
    }

    // -- recover_pending ------------------------------------------------------

    #[test]
    fn recover_pending_reports_none_when_no_marker_exists() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        assert_eq!(monitor.recover_pending().ok(), Some(None));
        Ok(())
    }

    #[test]
    fn recover_pending_reports_a_corrupt_marker() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let marker_path = fx.state_root.join(PENDING_COMMIT_MARKER);
        assert!(std::fs::write(&marker_path, b"not json").is_ok());
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        assert!(monitor.recover_pending().is_err());
        Ok(())
    }

    #[test]
    fn recover_pending_counts_a_failed_restore() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let marker_path = fx.state_root.join(PENDING_COMMIT_MARKER);
        // A marker whose backup file does not exist: recovery must still
        // remove the marker and report the failure rather than erroring out.
        let marker = serde_json::json!({
            "commit": 5,
            "deadline_unix_ms": 0,
            "entries": [{
                "target": 0,
                "path": fx.target,
                "backup": fx.root.join("no-such-backup"),
            }],
        });
        let bytes = serde_json::to_vec(&marker)?;
        assert!(std::fs::write(&marker_path, bytes).is_ok());
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.commit, CommitId(5));
        assert_eq!(recovered.restored, 0);
        assert_eq!(recovered.failures.len(), 1);
        assert!(!marker_path.is_file());
        Ok(())
    }

    // -- finish_send_error ------------------------------------------------------

    #[test]
    fn finish_send_error_classifies_every_channel_error() {
        install_tracing();
        assert_eq!(
            finish_send_error(ChannelError::Closed).ok(),
            Some(ExitReason::PeerClosed)
        );
        assert_eq!(
            finish_send_error(ChannelError::Timeout).ok(),
            Some(ExitReason::PeerClosed)
        );
        assert_eq!(
            finish_send_error(ChannelError::Oversize { len: 5 }).ok(),
            Some(ExitReason::ProtocolViolation)
        );
        assert!(matches!(
            finish_send_error(ChannelError::Io(std::io::Error::other("x"))),
            Err(super::MonitorError::Channel(ChannelError::Io(_)))
        ));
    }

    // -- handshake gating -------------------------------------------------------

    #[test]
    fn dispatch_requires_the_handshake_before_anything_else()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = Monitor::new(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::ReadTarget {
            target: TargetId(0),
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::HandshakeRequired)
        ));
        Ok(())
    }

    #[test]
    fn a_second_hello_is_a_handshake_error() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::Hello {
            proto: PROTO_VERSION,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::HandshakeRequired)
        ));
        Ok(())
    }

    // -- serve() ------------------------------------------------------------

    #[test]
    fn serve_reports_peer_closed_when_the_worker_disconnects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = Monitor::new(fx.allow()?, Hooks::default());
        let (mut channel, worker_end) = Channel::pair()?;
        drop(worker_end);
        assert_eq!(
            monitor.serve(&mut channel).ok(),
            Some(ExitReason::PeerClosed)
        );
        Ok(())
    }

    #[test]
    fn shutdown_with_a_pending_commit_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let (mut monitor_end, worker_end) = Channel::pair()?;
        let allow = fx.allow()?;
        let module = descriptor(&fx.target);
        let monitor = std::thread::spawn(move || {
            let mut monitor = Monitor::new(allow, Hooks::default());
            monitor.set_module_registry(vec![Box::new(SyntheticModule { descriptor: module })]);
            monitor.serve(&mut monitor_end)
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        client.write_target(TargetId(0), None, b"v2".to_vec(), true)?;
        client.start_confirm_timer(CommitId(1), 60, None)?;
        client.shutdown()?;
        assert_eq!(
            monitor.join().map_err(|_| "monitor thread panicked")??,
            ExitReason::Shutdown
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());
        Ok(())
    }

    #[test]
    fn serve_surfaces_a_non_protocol_channel_error() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = Monitor::new(fx.allow()?, Hooks::default());
        let (mut left, right) = std::os::unix::net::UnixStream::pair()?;
        let mut channel =
            Channel::with_timeouts(right, Duration::from_millis(30), Duration::from_millis(30))?;
        // A 4-byte length header advertising a body that never arrives is a
        // mid-frame timeout: fatal, but neither a clean disconnect nor a
        // protocol violation, so `serve` must surface it as an `Err`.
        assert!(std::io::Write::write_all(&mut left, &8_u32.to_be_bytes()).is_ok());
        assert!(monitor.serve(&mut channel).is_err());
        drop(left);
        Ok(())
    }

    // -- backup ordering ------------------------------------------------------

    #[test]
    fn list_backups_orders_multiple_entries_newest_first() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v3".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        let response = monitor.dispatch(Request::ListBackups {
            module: ModuleId(0),
        })?;
        let Response::Backups(entries) = response else {
            unreachable!("ListBackups always answers with Response::Backups")
        };
        assert_eq!(entries.len(), 2);
        Ok(())
    }

    // -- enforce_deadline / markers -------------------------------------------

    #[test]
    fn enforce_deadline_is_a_no_op_before_the_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: MAX_CONFIRM_TIMEOUT_S,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        assert!(monitor.enforce_deadline().is_ok());
        assert!(monitor.has_pending_commit());
        Ok(())
    }

    #[test]
    fn confirm_commit_tolerates_a_marker_removed_out_of_band()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 1,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        // `clear_marker` must tolerate the marker already being gone.
        assert!(std::fs::remove_file(fx.state_root.join(PENDING_COMMIT_MARKER)).is_ok());
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(response, Response::Committed { .. }));
        Ok(())
    }

    #[test]
    fn confirm_commit_reports_io_error_when_the_marker_cannot_be_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 1,
                service: None,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o500))
                .is_ok()
        );
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        });
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o700))
                .is_ok()
        );
        assert!(response.is_err());
        Ok(())
    }

    #[test]
    fn recover_pending_reports_io_error_when_the_marker_is_unreadable()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let marker_path = fx.state_root.join(PENDING_COMMIT_MARKER);
        assert!(std::fs::write(&marker_path, b"{}").is_ok());
        assert!(
            std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o000)).is_ok()
        );
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let result = monitor.recover_pending();
        assert!(
            std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600)).is_ok()
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn recover_pending_reports_io_error_when_the_marker_cannot_be_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let fx = fixture()?;
        assert!(std::fs::create_dir_all(&fx.state_root).is_ok());
        let marker_path = fx.state_root.join(PENDING_COMMIT_MARKER);
        let marker = serde_json::json!({
            "commit": 9,
            "deadline_unix_ms": 0,
            "entries": [],
        });
        let bytes = serde_json::to_vec(&marker)?;
        assert!(std::fs::write(&marker_path, bytes).is_ok());
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o500))
                .is_ok()
        );
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let result = monitor.recover_pending();
        assert!(
            std::fs::set_permissions(&fx.state_root, std::fs::Permissions::from_mode(0o700))
                .is_ok()
        );
        assert!(result.is_err());
        Ok(())
    }

    // -- atomic_to_proto ------------------------------------------------------
    //
    // `RelativePath`, `BadDigest`, and `Clock` cannot flow out of any
    // `crate::fs::atomic` call the monitor actually makes (target and backup
    // paths are validated absolute at allowlist construction; digests never
    // travel through `AtomicError` on the monitor's paths; the system clock
    // is never adversarially controlled in these tests). `atomic_to_proto`
    // is still a total function over every `AtomicError` variant, so it is
    // exercised directly here rather than left dead.

    #[test]
    fn atomic_to_proto_maps_relative_path_to_an_io_error() {
        let err = AtomicError::RelativePath {
            path: PathBuf::from("relative"),
        };
        assert!(matches!(super::atomic_to_proto(&err), ProtoError::Io(_)));
    }

    #[test]
    fn atomic_to_proto_maps_bad_digest_to_an_io_error() {
        assert!(matches!(
            super::atomic_to_proto(&AtomicError::BadDigest),
            ProtoError::Io(_)
        ));
    }

    #[test]
    fn atomic_to_proto_maps_clock_to_an_io_error() {
        assert!(matches!(
            super::atomic_to_proto(&AtomicError::Clock),
            ProtoError::Io(_)
        ));
    }

    #[test]
    fn read_target_maps_a_symlink_target_to_an_io_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        assert!(std::fs::remove_file(&fx.target).is_ok());
        let elsewhere = fx.root.join("elsewhere");
        assert!(std::fs::write(&elsewhere, b"x").is_ok());
        #[cfg(unix)]
        assert!(std::os::unix::fs::symlink(&elsewhere, &fx.target).is_ok());
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::ReadTarget {
            target: TargetId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    #[test]
    fn read_target_maps_a_directory_target_to_an_io_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        assert!(std::fs::remove_file(&fx.target).is_ok());
        assert!(std::fs::create_dir_all(&fx.target).is_ok());
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::ReadTarget {
            target: TargetId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    // -- truncate ---------------------------------------------------------------

    #[test]
    fn run_check_truncates_an_overlong_detail() -> Result<(), Box<dyn std::error::Error>> {
        struct Verbose(String);
        impl CheckRunner for Verbose {
            fn run_check(
                &self,
                _check: &ExternalCheck,
                _candidate: &Path,
            ) -> Result<CheckOutcome, HookError> {
                Ok(CheckOutcome {
                    check: CheckId(0),
                    passed: true,
                    exit_code: Some(0),
                    detail: self.0.clone(),
                })
            }
        }
        let fx = fixture()?;
        // A 3-byte-per-character string so the 512-byte cut point lands
        // mid-character (512 is not a multiple of 3), exercising the
        // char-boundary backoff loop, not just the byte-length cap.
        let verbose = Verbose("€".repeat(200));
        assert_eq!(verbose.0.len(), 600);
        let hooks = Hooks {
            checks: &verbose,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: Vec::new(),
        })?;
        let Response::Checked(outcome) = response else {
            unreachable!("RunCheck always answers with Response::Checked here")
        };
        assert!(outcome.detail.len() <= 512);
        assert!(outcome.detail.len() > 512 - 3);
        assert!(outcome.detail.is_char_boundary(outcome.detail.len()));
        Ok(())
    }

    // -- ReplaceBinary ------------------------------------------------------

    fn swap_target(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, std::io::Error> {
        let path = dir.join(name);
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    const FIXTURE_TAG: &str = "v99.0.0";

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../detent-update/tests/fixtures")
    }

    #[cfg(feature = "update")]
    fn fixture_trust() -> Result<detent_update::trust::TrustRoot, Box<dyn std::error::Error>> {
        let root = std::fs::read_to_string(fixture_dir().join("fulcio-root.pem"))?;
        let rekor = std::fs::read_to_string(fixture_dir().join("rekor-pub.pem"))?;
        let ct = std::fs::read_to_string(fixture_dir().join("ctfe-pub.pem"))?;
        Ok(detent_update::trust::from_pems_with_ct(&root, &rekor, &ct)?)
    }

    fn plant_release(
        state_root: &Path,
        bundle_name: &str,
    ) -> Result<(Sha256Digest, Vec<u8>), Box<dyn std::error::Error>> {
        plant_release_for(state_root, bundle_name, FIXTURE_TAG)
    }

    fn plant_release_for(
        state_root: &Path,
        bundle_name: &str,
        tag: &str,
    ) -> Result<(Sha256Digest, Vec<u8>), Box<dyn std::error::Error>> {
        let bytes = std::fs::read(fixture_dir().join("binary.bin"))?;
        let digest = Sha256Digest::of(&bytes);
        let dir = state_root.join(STAGED_DIR);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(tag), &bytes)?;
        std::fs::copy(
            fixture_dir().join(bundle_name),
            dir.join(format!("{tag}.sigstore.json")),
        )?;
        Ok((digest, bytes))
    }

    fn update_monitor(
        state_root: &Path,
        staging_dir: &Path,
        target: PathBuf,
    ) -> Result<Monitor<'static>, Box<dyn std::error::Error>> {
        let config = Config::with_state_root(state_root);
        let mut monitor = Monitor::new(Allowlist::from_modules(&[], &config)?, Hooks::default());
        monitor.set_staging_dir(staging_dir.to_path_buf());
        monitor.set_binary_override(target);
        #[cfg(feature = "update")]
        monitor.set_update_trust(fixture_trust()?);
        let _ = monitor.dispatch(Request::Hello {
            proto: PROTO_VERSION,
        });
        Ok(monitor)
    }

    #[cfg(feature = "update")]
    #[test]
    fn monitor_materializes_and_verifies_a_valid_release() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-old", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;

        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        let Response::Replaced { version } = response else {
            return Err(format!("expected Replaced, got {response:?}").into());
        };
        assert_eq!(version, digest.to_string());
        assert_eq!(std::fs::read(&target)?, bytes);
        Ok(())
    }

    #[test]
    fn materialized_digest_is_monitor_owned_private_and_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let staging_dir = work.path().join("monitor-staging");
        materialize_staged(
            &state_root,
            &staging_dir,
            FIXTURE_TAG,
            bytes.len() as u64,
            digest,
        )?;
        let materialized = staged_path(&staging_dir, digest);
        assert!(!materialized.starts_with(&state_root));
        let meta = std::fs::metadata(&materialized)?;
        assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(meta.mode() & 0o777, 0o600);
        let staging_meta = std::fs::metadata(&staging_dir)?;
        assert_eq!(staging_meta.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(staging_meta.mode() & 0o022, 0);
        Ok(())
    }

    #[test]
    fn monitor_rejects_group_writable_staging_permissions() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let staging_dir = work.path().join("monitor-staging");
        std::fs::create_dir(&staging_dir)?;
        std::fs::set_permissions(&staging_dir, std::fs::Permissions::from_mode(0o770))?;

        let error = match materialize_staged(
            &state_root,
            &staging_dir,
            FIXTURE_TAG,
            bytes.len() as u64,
            digest,
        ) {
            Ok(()) => return Err("group-writable staging must be rejected".into()),
            Err(error) => error,
        };
        assert!(
            matches!(error, ProtoError::Io(message) if message == "monitor staging directory is not trusted")
        );
        Ok(())
    }

    #[cfg(not(feature = "update"))]
    #[test]
    fn a_build_without_the_update_feature_refuses_a_valid_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-old", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;

        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::VerificationFailed)
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn monitor_rejects_wrong_identity_without_swapping() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-identity", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "wrong-identity.json")?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::VerificationFailed)
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn monitor_rejects_a_tampered_digest_without_swapping() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-digest", b"old-binary")?;
        let (_, bytes) = plant_release(&state_root, "valid.json")?;
        let claimed = Sha256Digest::of(b"different bytes");
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: claimed,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::Conflict { .. })
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn replace_binary_refuses_an_older_signed_release() -> Result<(), Box<dyn std::error::Error>> {
        // `older-tag.json` is a valid Sigstore bundle for v0.0.0 (< 0.0.1),
        // so only the monitor-side downgrade check can refuse it.
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-downgrade", b"old-binary")?;
        let (digest, bytes) = plant_release_for(&state_root, "older-tag.json", "v0.0.0")?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: "v0.0.0".to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(
            matches!(response, Response::Error(_)),
            "older signed tag must be refused, got {response:?}"
        );
        assert_eq!(
            std::fs::read(&target)?,
            b"old-binary",
            "target must be unchanged on downgrade refusal"
        );
        Ok(())
    }

    // -- revalidate: module parsers and external checks -----------------------

    /// A check runner that runs the validator and reports a rejection.
    struct RejectingChecks;
    impl CheckRunner for RejectingChecks {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            _candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            Ok(CheckOutcome {
                check: CheckId(0),
                passed: false,
                exit_code: Some(1),
                detail: "rejected".to_owned(),
            })
        }
    }

    /// Which step of module validation a [`RejectingModule`] fails.
    #[derive(Clone, Copy)]
    enum RejectAt {
        Parse,
        Validate,
        Diagnose,
    }

    /// A module whose parser or validator refuses every candidate.
    struct RejectingModule {
        descriptor: &'static ModuleDescriptor,
        at: RejectAt,
    }

    impl DynModule for RejectingModule {
        fn id(&self) -> &'static str {
            self.descriptor.id
        }

        fn descriptor(&self) -> &'static ModuleDescriptor {
            self.descriptor
        }

        fn clone_box(&self) -> Box<dyn DynModule> {
            Box::new(Self {
                descriptor: self.descriptor,
                at: self.at,
            })
        }

        fn schema_json(&self) -> Value {
            Value::Null
        }

        fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError> {
            match self.at {
                RejectAt::Parse => Err(DynError::Parse(ParseError::Malformed {
                    message: "bad grammar".to_owned(),
                    span: None,
                })),
                RejectAt::Validate | RejectAt::Diagnose => Ok(json!({ "text": src })),
            }
        }

        fn apply_json(&self, src: &str, _model_json: &Value) -> Result<String, DynError> {
            Ok(src.to_owned())
        }

        fn validate_json(
            &self,
            _model_json: &Value,
            _ctx: &detent_core::descriptor::ValidationCtx<'_>,
        ) -> Result<Diagnostics, DynError> {
            match self.at {
                RejectAt::Validate => Err(DynError::Model(ModelError::Shape {
                    message: "bad shape".to_owned(),
                })),
                RejectAt::Parse | RejectAt::Diagnose => {
                    let mut diagnostics = Diagnostics::new();
                    diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        MessageId::new("fake-invalid"),
                    ));
                    Ok(diagnostics)
                }
            }
        }

        fn defaults_json(&self, _profile: &HostProfile) -> Result<Value, DynError> {
            Ok(Value::Null)
        }
    }

    /// Write `v2` over the fixture's `v1` target without journaling.
    fn write_v2(monitor: &mut Monitor<'_>) -> Result<Response, super::MonitorError> {
        monitor.dispatch(Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: b"v2".to_vec(),
            journal: false,
        })
    }

    /// The message of a `Response::Error(ProtoError::Io(_))`, if it is one.
    fn io_message(response: &Response) -> Option<&str> {
        match response {
            Response::Error(ProtoError::Io(message)) => Some(message),
            _ => None,
        }
    }

    #[test]
    fn write_target_installs_content_the_external_check_accepts_beside_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let checks = RecordingChecks::default();
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        assert!(matches!(write_v2(&mut monitor)?, Response::Written(_)));
        assert_eq!(std::fs::read(&fx.target)?, b"v2");
        let seen = checks.seen();
        let (path, bytes) = seen.first().ok_or("the check did not run")?;
        assert!(is_candidate_in(path, &fx.root), "candidate at {path:?}");
        assert_eq!(bytes, b"v2");
        // The candidate file is temporary: nothing is left beside the target.
        assert!(
            entries(&fx.root)?
                .iter()
                .all(|name| !name.starts_with(".detent-candidate-")),
            "a candidate was left behind"
        );
        Ok(())
    }

    #[test]
    fn write_target_refuses_when_the_target_directory_is_group_writable()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let etc = work.path().join("etc");
        std::fs::create_dir(&etc)?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o775))?;
        let target = etc.join("target.conf");
        std::fs::write(&target, b"v1")?;
        let allow = Allowlist::from_modules(
            &[descriptor(&target)],
            &Config::with_state_root(work.path().join("state")),
        )?;
        let checks = RecordingChecks::default();
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        assert_candidate_dir_refused(&write_v2(&mut monitor)?);
        assert!(checks.seen().is_empty());
        assert_eq!(std::fs::read(&target)?, b"v1");
        assert_eq!(entries(&etc)?, ["target.conf"]);
        Ok(())
    }

    #[test]
    fn write_target_refuses_content_the_external_check_rejects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &RejectingChecks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = write_v2(&mut monitor)?;
        assert_eq!(
            io_message(&response),
            Some("external validator rejected candidate content")
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_maps_a_failed_external_check_to_an_io_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &FailingChecks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = write_v2(&mut monitor)?;
        assert_eq!(io_message(&response), Some("boom"));
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_reports_io_error_when_the_check_candidate_directory_cannot_be_created()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &OkChecks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(fx.allow_without_a_file_target()?, hooks);
        // A directory below a regular file cannot exist (ENOTDIR), root or not.
        monitor.set_staging_dir(fx.target.join("staging"));
        let response = write_v2(&mut monitor)?;
        assert!(
            io_message(&response)
                .is_some_and(|message| message.starts_with("create monitor staging directory")),
            "unexpected response {response:?}"
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_refuses_when_the_registry_has_no_parser_for_the_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted_with_registry(fx.allow()?, Hooks::default(), Some(Vec::new()));
        let response = write_v2(&mut monitor)?;
        assert_eq!(io_message(&response), Some("module parser is unavailable"));
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_refuses_a_module_with_no_compiled_parser()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        // No registry: the monitor looks the id "fake" up among the compiled
        // modules, which do not have it.
        let mut monitor = greeted_real(fx.allow()?, Hooks::default());
        let response = write_v2(&mut monitor)?;
        assert_eq!(io_message(&response), Some("module parser is unavailable"));
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_refuses_content_that_is_not_utf8() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: vec![0xff, 0xfe, 0xfd],
            journal: false,
        })?;
        assert_eq!(
            io_message(&response),
            Some("module content is not valid UTF-8")
        );
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn write_target_refuses_content_the_module_parser_or_validator_rejects()
    -> Result<(), Box<dyn std::error::Error>> {
        for (at, expected) in [
            (
                RejectAt::Parse,
                "module parser rejected candidate content: malformed input: bad grammar",
            ),
            (
                RejectAt::Validate,
                "module validation rejected candidate content: model does not match its schema: bad shape",
            ),
            (
                RejectAt::Diagnose,
                "module validation rejected candidate content",
            ),
        ] {
            let fx = fixture()?;
            let allow = fx.allow()?;
            let descriptor = allow
                .module(ModuleId(0))
                .ok_or("the fixture declares module 0")?;
            let registry: Vec<Box<dyn DynModule>> =
                vec![Box::new(RejectingModule { descriptor, at })];
            let mut monitor = greeted_with_registry(allow, Hooks::default(), Some(registry));
            let response = write_v2(&mut monitor)?;
            assert_eq!(io_message(&response), Some(expected));
            assert_eq!(std::fs::read(&fx.target)?, b"v1");
        }
        Ok(())
    }

    #[test]
    fn new_execution_directives_are_detected_per_module() {
        let cases: [(&str, &[u8], &[u8], bool); 17] = [
            // Comments, blank lines and `;` remarks never count.
            ("samba", b"", b"\n# preexec = /x\n; include = /y\n", false),
            ("dhcp", b"", b"dhcp-script=/bin/sh\n", true),
            ("chrony", b"", b"confdir /etc/chrony.d\n", true),
            ("resolver", b"", b"include: /etc/extra.conf\n", true),
            ("resolver", b"", b"server:\n", false),
            // A bare `up` with a short command, and `down`-family hooks.
            ("network", b"", b"up /bin/sh -c x\n", true),
            ("network", b"", b"down=/bin/true\n", true),
            ("network", b"", b"pre-up /bin/true\n", true),
            // A static route in the `ip route add ... via <gw>` shape is allowed.
            (
                "network",
                b"",
                b"up ip route add 10.0.0.0/8 via 192.0.2.1\n",
                false,
            ),
            // Five or more words in any other shape is still a command.
            ("network", b"", b"up /bin/sh -c 'a b c'\n", true),
            ("network", b"up /bin/true\n", b"up /bin/true\n", false),
            ("network", b"", b"address 192.0.2.2\n", false),
            // Owner decision 2026-10-07: harmless x-systemd options pass;
            // ones that run a program (makefs) are refused.
            (
                "mounts",
                b"",
                b"/dev/sda1 /mnt ext4 x-systemd.automount 0 0\n",
                false,
            ),
            (
                "mounts",
                b"",
                b"/dev/sda1 /mnt ext4 x-systemd.makefs 0 0\n",
                true,
            ),
            ("mounts", b"", b"/dev/sda1 /mnt ext4 defaults 0 0\n", false),
            // NFS options split on commas as well as whitespace.
            ("nfs", b"", b"/srv 192.0.2.0/24(rw,no_root_squash)\n", true),
            ("unknown", b"", b"preexec = /bin/true\n", false),
        ];
        for (module, previous, candidate, expected) in cases {
            assert_eq!(
                Monitor::has_new_forbidden_exec_directive(module, previous, candidate),
                expected,
                "module {module}, candidate {:?}",
                String::from_utf8_lossy(candidate)
            );
        }
    }

    // -- marker, lock and service-replay failures -------------------------------

    /// Write `v2` with journaling and arm commit 1 with `service`.
    fn arm_commit(
        monitor: &mut Monitor<'_>,
        service: Option<PendingService>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            monitor.dispatch(Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            })?,
            Response::Written(_)
        ));
        assert!(matches!(
            monitor.dispatch(Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 60,
                service,
            })?,
            Response::ConfirmTimerStarted { .. }
        ));
        Ok(())
    }

    const RESTART_BINDING_0: PendingService = PendingService {
        binding: BindingId(0),
        action: ServiceAction::Restart,
    };

    #[test]
    fn start_confirm_timer_reports_a_state_error_when_the_marker_cannot_be_written()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        // A directory where the marker file goes: opening it for writing
        // fails with EISDIR, root or not.
        std::fs::create_dir_all(fx.state_root.join(PENDING_COMMIT_MARKER))?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = monitor.dispatch(Request::StartConfirmTimer {
            commit: CommitId(1),
            timeout_s: 60,
            service: None,
        });
        assert!(matches!(
            response,
            Err(super::MonitorError::State { op: "write", .. })
        ));
        assert!(!monitor.has_pending_commit());
        Ok(())
    }

    #[test]
    fn confirm_commit_reports_a_state_error_when_the_marker_is_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        arm_commit(&mut monitor, None)?;
        let marker = fx.state_root.join(PENDING_COMMIT_MARKER);
        std::fs::remove_file(&marker)?;
        std::fs::create_dir(&marker)?;
        std::fs::write(marker.join("keep"), b"x")?;
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        });
        assert!(matches!(
            response,
            Err(super::MonitorError::State {
                op: "remove_file",
                ..
            })
        ));
        // The confirmed write stays; only the marker cleanup failed.
        assert_eq!(std::fs::read(&fx.target)?, b"v2");
        Ok(())
    }

    #[test]
    fn recover_pending_reports_a_state_error_when_the_marker_is_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        std::fs::create_dir_all(fx.state_root.join(PENDING_COMMIT_MARKER))?;
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        assert!(matches!(
            monitor.recover_pending(),
            Err(super::MonitorError::State { op: "read", .. })
        ));
        Ok(())
    }

    /// Plant a marker with no rollback entries and `service` to replay.
    fn plant_marker(
        fx: &Fixture,
        service: PendingService,
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&fx.state_root)?;
        let marker = PendingCommitMarker {
            commit: 7,
            deadline_unix_ms: 0,
            entries: Vec::new(),
            service: Some(service),
        };
        std::fs::write(
            fx.state_root.join(PENDING_COMMIT_MARKER),
            serde_json::to_vec(&marker)?,
        )?;
        Ok(())
    }

    #[test]
    fn recover_pending_reports_a_service_binding_that_disappeared()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        plant_marker(
            &fx,
            PendingService {
                binding: BindingId(99),
                action: ServiceAction::Restart,
            },
        )?;
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.commit, CommitId(7));
        assert_eq!(recovered.failures.len(), 1);
        assert!(
            recovered
                .failures
                .iter()
                .all(|failure| failure.contains("service binding 99 disappeared")),
            "unexpected failures {:?}",
            recovered.failures
        );
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());
        Ok(())
    }

    #[test]
    fn recover_pending_refuses_to_replay_a_non_mutating_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        plant_marker(
            &fx,
            PendingService {
                binding: BindingId(0),
                action: ServiceAction::Status,
            },
        )?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &OkServices,
        };
        let monitor = Monitor::new(fx.allow()?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(
            recovered.failures,
            vec!["pending service action is not mutating".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn rollback_commit_replays_the_service_action_after_restoring()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        let response = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::RolledBack {
                commit: CommitId(1),
                restored: 1
            }
        ));
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        services.assert_replayed_after_restore();
        Ok(())
    }

    #[test]
    fn a_failed_service_replay_does_not_stop_an_expired_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &FailingServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        if let Some(pending) = monitor.pending.as_mut() {
            pending.deadline = std::time::Instant::now();
        }
        monitor.enforce_deadline()?;
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());
        Ok(())
    }

    #[test]
    fn a_failed_service_replay_does_not_stop_the_rollback_on_exit()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &FailingServices,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        monitor.rollback_pending_on_exit()?;
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());
        Ok(())
    }

    /// Records each service call with the target's contents at call time, so
    /// a test can check the replay ran and ran after the file was restored.
    struct RecordingServices {
        target: PathBuf,
        calls: std::cell::RefCell<Vec<(CoreServiceAction, Vec<u8>)>>,
        /// The target's contents at each unit-file reload.
        reloads: std::cell::RefCell<Vec<Vec<u8>>>,
        /// Each mount hook call (`start`, `stop`, `forget`) with the target's
        /// contents at call time.
        mounts: std::cell::RefCell<Vec<(&'static str, Vec<u8>)>>,
    }

    impl RecordingServices {
        fn new(target: &Path) -> Self {
            Self {
                target: target.to_path_buf(),
                calls: std::cell::RefCell::new(Vec::new()),
                reloads: std::cell::RefCell::new(Vec::new()),
                mounts: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn mount_event(&self, event: &'static str) {
            let contents = std::fs::read(&self.target).unwrap_or_default();
            self.mounts.borrow_mut().push((event, contents));
        }

        /// The one call every rollback path must make: a restart, seen
        /// after the file is back to `v1`.
        fn assert_replayed_after_restore(&self) {
            assert_eq!(
                *self.calls.borrow(),
                vec![(CoreServiceAction::Restart, b"v1".to_vec())]
            );
        }
    }

    impl ServiceControl for RecordingServices {
        fn service(
            &self,
            _binding: &ServiceBinding,
            action: CoreServiceAction,
        ) -> Result<ServiceOutcome, HookError> {
            let contents = std::fs::read(&self.target).unwrap_or_default();
            self.calls.borrow_mut().push((action, contents));
            Ok(ServiceOutcome {
                binding: BindingId(0),
                active: true,
                detail: "running".to_owned(),
            })
        }

        fn reload_unit_files(&self) -> Result<String, HookError> {
            let contents = std::fs::read(&self.target).unwrap_or_default();
            self.reloads.borrow_mut().push(contents);
            Ok("reloaded".to_owned())
        }

        fn start_added_mounts(&self, _target: TargetId) -> Result<Vec<MountOutcome>, HookError> {
            self.mount_event("start");
            Ok(vec![srv_mounted()])
        }

        fn stop_started_mounts(&self) -> Result<Vec<MountOutcome>, HookError> {
            self.mount_event("stop");
            Ok(Vec::new())
        }

        fn forget_started_mounts(&self) -> Result<(), HookError> {
            self.mount_event("forget");
            Ok(())
        }
    }

    fn srv_mounted() -> MountOutcome {
        MountOutcome {
            mountpoint: "/srv".to_owned(),
            unit: "srv.mount".to_owned(),
            state: MountState::Mounted,
            detail: String::new(),
        }
    }

    // -- in-place writes ------------------------------------------------------

    /// Under the packaged unit `/etc` is read-only and only the target file
    /// is writable. A `0555` directory stands in for that (unprivileged runs
    /// only; root ignores the mode): the write and the rollback both go to
    /// the same inode, and no marker is left.
    #[test]
    fn a_read_only_target_directory_is_written_and_rolled_back_in_place()
    -> Result<(), Box<dyn std::error::Error>> {
        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let work = TempDir::new()?;
        let etc = work.path().join("etc");
        std::fs::create_dir(&etc)?;
        let target = etc.join("target.conf");
        std::fs::write(&target, b"v1")?;
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o555))?;
        let inode = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&target)?);
        let state = work.path().join("state");
        let allow =
            Allowlist::from_modules(&[descriptor(&target)], &Config::with_state_root(&state))?;
        let mut monitor = greeted(allow, Hooks::default());
        let armed = arm_commit(&mut monitor, None);
        let written = std::fs::read(&target);
        let rolled = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        });
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755))?;
        armed?;
        assert_eq!(written?, b"v2");
        assert!(matches!(rolled?, Response::RolledBack { restored: 1, .. }));
        assert_eq!(std::fs::read(&target)?, b"v1");
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&target)?),
            inode
        );
        assert!(!state.join(super::IN_PLACE_MARKER).exists());
        Ok(())
    }

    /// A fixture with a backup `v1` in the target's backup directory and an
    /// in-place marker naming `path` and `backup`, `v1` → `v2`.
    fn in_place_fixture(
        path: Option<&Path>,
        backup_elsewhere: bool,
    ) -> Result<(Fixture, Allowlist, PathBuf), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let allow = fx.allow()?;
        let entry = allow.target(TargetId(0)).ok_or("target")?;
        let backup_dir = if backup_elsewhere {
            fx.root.join("elsewhere")
        } else {
            entry.backup_dir.clone()
        };
        std::fs::create_dir_all(&backup_dir)?;
        let backup = backup_dir.join("2026-10-06T00:00:00.000000000Z-00000000");
        std::fs::write(&backup, b"v1")?;
        std::fs::create_dir_all(&fx.state_root)?;
        let marker = InPlaceMarker {
            path: path.map_or_else(|| fx.target.clone(), Path::to_path_buf),
            backup: Some(backup),
            prev: Sha256Digest::of(b"v1"),
            new: Sha256Digest::of(b"v2"),
        };
        let marker_path = fx.state_root.join(super::IN_PLACE_MARKER);
        std::fs::write(&marker_path, serde_json::to_vec(&marker)?)?;
        Ok((fx, allow, marker_path))
    }

    #[test]
    fn a_whole_in_place_write_only_loses_its_marker() -> Result<(), Box<dyn std::error::Error>> {
        for contents in [&b"v2"[..], b"v1"] {
            let (fx, allow, marker) = in_place_fixture(None, false)?;
            std::fs::write(&fx.target, contents)?;
            let monitor = Monitor::new(allow, Hooks::default());
            let recovered = monitor.recover_in_place()?.ok_or("a recovery")?;
            assert_eq!(recovered.outcome, InPlaceOutcome::Whole);
            assert_eq!(std::fs::read(&fx.target)?, contents);
            assert!(!marker.exists());
        }
        Ok(())
    }

    /// A start after a crash inside an in-place write restores the backup
    /// (through `recover_pending`, which every start calls).
    #[test]
    fn a_torn_in_place_write_is_restored_at_start() -> Result<(), Box<dyn std::error::Error>> {
        for torn in [&b""[..], b"v"] {
            let (fx, allow, marker) = in_place_fixture(None, false)?;
            std::fs::write(&fx.target, torn)?;
            let monitor = Monitor::new(allow, Hooks::default());
            assert_eq!(monitor.recover_pending()?, None);
            assert_eq!(std::fs::read(&fx.target)?, b"v1");
            assert!(!marker.exists());
        }
        let (fx, allow, _) = in_place_fixture(None, false)?;
        std::fs::write(&fx.target, b"torn")?;
        let recovered = Monitor::new(allow, Hooks::default())
            .recover_in_place()?
            .ok_or("a recovery")?;
        assert_eq!(recovered.outcome, InPlaceOutcome::Restored);
        Ok(())
    }

    #[test]
    fn an_in_place_marker_outside_the_allow_list_touches_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        // A path that is not an allow-listed target.
        let outside = TempDir::new()?;
        let stranger = outside.path().join("passwd");
        std::fs::write(&stranger, b"root:x:0:0")?;
        let (_fx, allow, marker) = in_place_fixture(Some(&stranger), false)?;
        let recovered = Monitor::new(allow, Hooks::default())
            .recover_in_place()?
            .ok_or("a recovery")?;
        assert_eq!(recovered.outcome, InPlaceOutcome::Refused);
        assert_eq!(std::fs::read(&stranger)?, b"root:x:0:0");
        assert!(!marker.exists());

        // An allow-listed target with a backup outside its backup directory.
        let (fx, allow, marker) = in_place_fixture(None, true)?;
        std::fs::write(&fx.target, b"torn")?;
        let recovered = Monitor::new(allow, Hooks::default())
            .recover_in_place()?
            .ok_or("a recovery")?;
        assert_eq!(recovered.outcome, InPlaceOutcome::Refused);
        assert_eq!(std::fs::read(&fx.target)?, b"torn");
        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn a_corrupt_in_place_marker_stops_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let (_fx, allow, marker) = in_place_fixture(None, false)?;
        std::fs::write(&marker, b"not json")?;
        let monitor = Monitor::new(allow, Hooks::default());
        assert!(matches!(
            monitor.recover_in_place(),
            Err(MonitorError::CorruptMarker)
        ));
        assert!(marker.exists());
        Ok(())
    }

    #[test]
    fn a_failed_restore_of_a_torn_write_keeps_the_marker() -> Result<(), Box<dyn std::error::Error>>
    {
        let (fx, allow, marker) = in_place_fixture(None, false)?;
        std::fs::write(&fx.target, b"torn")?;
        let entry = allow.target(TargetId(0)).ok_or("target")?;
        // The backup the marker names is gone.
        std::fs::remove_dir_all(&entry.backup_dir)?;
        std::fs::create_dir_all(&entry.backup_dir)?;
        let recovered = Monitor::new(allow.clone(), Hooks::default())
            .recover_in_place()?
            .ok_or("a recovery")?;
        assert!(matches!(recovered.outcome, InPlaceOutcome::Failed(_)));
        assert!(marker.exists());
        assert_eq!(std::fs::read(&fx.target)?, b"torn");
        Ok(())
    }

    // -- mounts ---------------------------------------------------------------

    fn srv_unit(_previous: &str, _current: &str) -> Vec<MountUnit> {
        vec![MountUnit {
            mountpoint: "/srv".to_owned(),
            unit: "srv.mount".to_owned(),
        }]
    }

    impl Fixture {
        /// The fixture's module as `mounts`: it reloads unit files and
        /// declares mounts. `activate` is `[mounts] activate_new_entries`.
        fn allow_mounting(&self, activate: bool) -> Result<Allowlist, AllowlistError> {
            let module = leak(ModuleDescriptor {
                reload_unit_files: true,
                added_mounts: Some(srv_unit),
                ..*descriptor(&self.target)
            });
            Allowlist::from_modules(
                &[module],
                &Config {
                    activate_mounts: activate,
                    ..Config::with_state_root(&self.state_root)
                },
            )
        }
    }

    #[test]
    fn a_mount_with_activation_off_says_so_and_starts_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow_mounting(false)?, hooks);
        let response = monitor.dispatch(Request::Mount {
            target: TargetId(0),
        })?;
        assert_eq!(
            response,
            Response::Mounted {
                activated: false,
                units: Vec::new()
            }
        );
        assert!(services.mounts.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn a_mount_reaches_the_hook_when_activation_is_on() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow_mounting(true)?, hooks);
        let response = monitor.dispatch(Request::Mount {
            target: TargetId(0),
        })?;
        assert_eq!(
            response,
            Response::Mounted {
                activated: true,
                units: vec![srv_mounted()]
            }
        );
        let unknown = monitor.dispatch(Request::Mount {
            target: TargetId(9),
        })?;
        assert!(
            matches!(
                unknown,
                Response::Error(ProtoError::UnknownId {
                    kind: IdKind::Target,
                    id: 9
                })
            ),
            "{unknown:?}"
        );
        assert_eq!(services.mounts.borrow().len(), 1);
        Ok(())
    }

    #[test]
    fn a_mount_for_a_module_without_mounts_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow_reloading()?, hooks);
        let response = monitor.dispatch(Request::Mount {
            target: TargetId(0),
        })?;
        assert_eq!(response, Response::Error(ProtoError::ActionNotAllowed));
        assert!(services.mounts.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn a_failed_mount_hook_is_an_error_response() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow_mounting(true)?, Hooks::default());
        let response = monitor.dispatch(Request::Mount {
            target: TargetId(0),
        })?;
        assert_eq!(
            response,
            Response::Error(ProtoError::Unavailable(
                "mount units are not available in this build".to_owned()
            ))
        );
        Ok(())
    }

    /// Every way a pending commit of a mounting module rolls back stops the
    /// started mounts once, while the file still has the applied contents,
    /// and reloads after the restore.
    #[test]
    fn every_rollback_of_a_mounting_module_stops_started_mounts_before_the_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        type Roll = fn(&mut Monitor<'_>, &Fixture) -> Result<(), Box<dyn std::error::Error>>;
        let ways: [(&str, Roll); 3] = [
            ("deadline", |monitor, _| {
                if let Some(pending) = monitor.pending.as_mut() {
                    pending.deadline = std::time::Instant::now();
                }
                Ok(monitor.enforce_deadline()?)
            }),
            ("request", |monitor, _| {
                monitor.dispatch(Request::RollbackCommit {
                    commit: CommitId(1),
                })?;
                Ok(())
            }),
            ("exit", |monitor, _| Ok(monitor.rollback_pending_on_exit()?)),
        ];
        for (way, roll) in ways {
            let fx = fixture()?;
            let services = RecordingServices::new(&fx.target);
            let hooks = Hooks {
                checks: &super::NoChecks,
                services: &services,
            };
            let mut monitor = greeted(fx.allow_mounting(true)?, hooks);
            arm_commit(&mut monitor, None)?;
            roll(&mut monitor, &fx)?;
            assert_eq!(
                *services.mounts.borrow(),
                vec![("stop", b"v2".to_vec())],
                "{way}"
            );
            assert_eq!(*services.reloads.borrow(), vec![b"v1".to_vec()], "{way}");
        }
        Ok(())
    }

    #[test]
    fn recover_pending_stops_started_mounts_for_a_mounting_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow_mounting(true)?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let monitor = Monitor::new(fx.allow_mounting(true)?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert!(recovered.failures.is_empty(), "{:?}", recovered.failures);
        assert_eq!(*services.mounts.borrow(), vec![("stop", b"v2".to_vec())]);
        Ok(())
    }

    #[test]
    fn a_failed_mount_stop_is_reported_and_the_rollback_still_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow_mounting(true)?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        let monitor = Monitor::new(fx.allow_mounting(true)?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(
            recovered
                .failures
                .iter()
                .any(|failure| failure.contains("mount units are not available")),
            "{:?}",
            recovered.failures
        );
        Ok(())
    }

    #[test]
    fn a_confirm_forgets_the_started_mounts() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow_mounting(true)?, hooks);
        arm_commit(&mut monitor, None)?;
        let response = monitor.dispatch(Request::ConfirmCommit {
            commit: CommitId(1),
        })?;
        assert!(
            matches!(response, Response::Committed { .. }),
            "{response:?}"
        );
        assert_eq!(*services.mounts.borrow(), vec![("forget", b"v2".to_vec())]);
        Ok(())
    }

    // -- reload_unit_files ----------------------------------------------------

    impl Fixture {
        /// The fixture's module with `reload_unit_files` set, as `mounts`.
        fn allow_reloading(&self) -> Result<Allowlist, AllowlistError> {
            let module = leak(ModuleDescriptor {
                reload_unit_files: true,
                ..*descriptor(&self.target)
            });
            Allowlist::from_modules(&[module], &Config::with_state_root(&self.state_root))
        }
    }

    #[test]
    fn a_reload_reaches_the_hook_for_a_module_that_declares_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow_reloading()?, hooks);
        let response = monitor.dispatch(Request::ReloadUnitFiles {
            module: ModuleId(0),
        })?;
        assert!(
            matches!(&response, Response::UnitFilesReloaded { detail } if detail == "reloaded"),
            "{response:?}"
        );
        let unknown = monitor.dispatch(Request::ReloadUnitFiles {
            module: ModuleId(9),
        })?;
        assert!(
            matches!(
                unknown,
                Response::Error(ProtoError::UnknownId {
                    kind: IdKind::Module,
                    id: 9
                })
            ),
            "{unknown:?}"
        );
        assert_eq!(services.reloads.borrow().len(), 1);
        Ok(())
    }

    #[test]
    fn a_reload_for_a_module_that_does_not_declare_it_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        let response = monitor.dispatch(Request::ReloadUnitFiles {
            module: ModuleId(0),
        })?;
        assert!(
            matches!(response, Response::Error(ProtoError::ActionNotAllowed)),
            "{response:?}"
        );
        assert!(services.reloads.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn a_failed_reload_is_an_error_response() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let cases: [(&dyn ServiceControl, ProtoError); 2] = [
            (&FailingServices, ProtoError::Io("reload boom".to_owned())),
            (
                &super::NoServices,
                ProtoError::Unavailable(
                    "service control is not available in this build".to_owned(),
                ),
            ),
        ];
        for (services, expected) in cases {
            let hooks = Hooks {
                checks: &super::NoChecks,
                services,
            };
            let mut monitor = greeted(fx.allow_reloading()?, hooks);
            let response = monitor.dispatch(Request::ReloadUnitFiles {
                module: ModuleId(0),
            })?;
            assert_eq!(response, Response::Error(expected));
        }
        Ok(())
    }

    /// Every way a pending commit of a reloading module rolls back re-reads
    /// the unit files once, after the file is back to `v1`.
    #[test]
    fn every_rollback_of_a_reloading_module_reloads_unit_files_after_the_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        type Roll = fn(&mut Monitor<'_>, &Fixture) -> Result<(), Box<dyn std::error::Error>>;
        let ways: [(&str, Roll); 3] = [
            ("deadline", |monitor, _| {
                if let Some(pending) = monitor.pending.as_mut() {
                    pending.deadline = std::time::Instant::now();
                }
                Ok(monitor.enforce_deadline()?)
            }),
            ("request", |monitor, _| {
                let response = monitor.dispatch(Request::RollbackCommit {
                    commit: CommitId(1),
                })?;
                assert!(
                    matches!(response, Response::RolledBack { .. }),
                    "{response:?}"
                );
                Ok(())
            }),
            ("exit", |monitor, fx| {
                let (mut monitor_end, worker_end) = Channel::pair()?;
                drop(worker_end);
                let lock = Monitor::lock(&fx.state_root)?;
                assert_eq!(
                    monitor.serve_locked(&mut monitor_end, lock)?,
                    ExitReason::PeerClosed
                );
                Ok(())
            }),
        ];
        for (way, roll) in ways {
            let fx = fixture()?;
            let services = RecordingServices::new(&fx.target);
            let hooks = Hooks {
                checks: &super::NoChecks,
                services: &services,
            };
            let mut monitor = greeted(fx.allow_reloading()?, hooks);
            arm_commit(&mut monitor, None)?;
            assert!(services.reloads.borrow().is_empty(), "{way}");
            roll(&mut monitor, &fx)?;
            assert_eq!(*services.reloads.borrow(), vec![b"v1".to_vec()], "{way}");
        }
        Ok(())
    }

    #[test]
    fn recover_pending_reloads_unit_files_for_a_reloading_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow_reloading()?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let monitor = Monitor::new(fx.allow_reloading()?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert!(recovered.failures.is_empty(), "{:?}", recovered.failures);
        assert_eq!(*services.reloads.borrow(), vec![b"v1".to_vec()]);
        Ok(())
    }

    #[test]
    fn a_rollback_of_a_module_without_the_flag_does_not_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        services.assert_replayed_after_restore();
        assert!(services.reloads.borrow().is_empty());
        assert!(services.mounts.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn a_failed_reload_after_a_rollback_is_reported_and_the_rollback_still_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        install_tracing();
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &FailingServices,
        };
        let mut monitor = greeted(fx.allow_reloading()?, hooks);
        arm_commit(&mut monitor, None)?;
        monitor.rollback_pending_on_exit()?;
        assert!(!monitor.has_pending_commit());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());

        // After a crash the failure is in the recovery report.
        {
            let mut monitor = greeted(fx.allow_reloading()?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &FailingServices,
        };
        let monitor = Monitor::new(fx.allow_reloading()?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.failures, vec!["reload boom".to_owned()]);
        Ok(())
    }

    #[test]
    fn an_expired_commit_replays_the_service_action() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        assert!(services.calls.borrow().is_empty());
        if let Some(pending) = monitor.pending.as_mut() {
            pending.deadline = std::time::Instant::now();
        }
        monitor.enforce_deadline()?;
        assert!(!monitor.has_pending_commit());
        services.assert_replayed_after_restore();
        Ok(())
    }

    #[test]
    fn a_monitor_exit_with_a_pending_commit_replays_the_service_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let mut monitor = greeted(fx.allow()?, hooks);
        arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
        let (mut monitor_end, worker_end) = Channel::pair()?;
        drop(worker_end);
        let lock = Monitor::lock(&fx.state_root)?;
        assert_eq!(
            monitor.serve_locked(&mut monitor_end, lock)?,
            ExitReason::PeerClosed
        );
        services.assert_replayed_after_restore();
        Ok(())
    }

    #[test]
    fn recover_pending_replays_the_service_action_at_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow()?, Hooks::default());
            arm_commit(&mut monitor, Some(RESTART_BINDING_0))?;
            // Dropped without confirming, as if the process died.
        }
        let services = RecordingServices::new(&fx.target);
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &services,
        };
        let monitor = Monitor::new(fx.allow()?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert!(recovered.failures.is_empty(), "{:?}", recovered.failures);
        services.assert_replayed_after_restore();
        Ok(())
    }

    #[test]
    fn rollback_does_not_overwrite_an_edit_made_during_the_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        arm_commit(&mut monitor, None)?;
        std::fs::write(&fx.target, b"operator edit")?;
        let response = monitor.dispatch(Request::RollbackCommit {
            commit: CommitId(1),
        })?;
        assert!(matches!(
            response,
            Response::RolledBack {
                commit: CommitId(1),
                restored: 0
            }
        ));
        assert_eq!(std::fs::read(&fx.target)?, b"operator edit");
        assert!(!monitor.has_pending_commit());
        Ok(())
    }

    #[test]
    fn recover_pending_does_not_overwrite_an_edit_made_during_the_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow()?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        std::fs::write(&fx.target, b"operator edit")?;
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.restored, 0);
        assert!(
            recovered.failures.len() == 1
                && recovered
                    .failures
                    .iter()
                    .all(|failure| failure.starts_with("contents changed on disk")),
            "unexpected failures {:?}",
            recovered.failures
        );
        assert_eq!(std::fs::read(&fx.target)?, b"operator edit");
        Ok(())
    }

    #[test]
    fn a_marker_without_new_digests_still_parses_and_restores()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow()?, Hooks::default());
            arm_commit(&mut monitor, None)?;
        }
        // A marker written before `new_digest` existed has no guard.
        let marker = fx.state_root.join(PENDING_COMMIT_MARKER);
        let mut json: Value = serde_json::from_slice(&std::fs::read(&marker)?)?;
        for entry in json
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .ok_or("entries")?
        {
            entry.as_object_mut().ok_or("entry")?.remove("new_digest");
        }
        std::fs::write(&marker, serde_json::to_vec(&json)?)?;
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.restored, 1);
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        Ok(())
    }

    #[test]
    fn recover_pending_refuses_an_action_the_binding_no_longer_allows()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        // The fixture binding declares only `Restart`.
        plant_marker(
            &fx,
            PendingService {
                binding: BindingId(0),
                action: ServiceAction::Stop,
            },
        )?;
        let hooks = Hooks {
            checks: &super::NoChecks,
            services: &OkServices,
        };
        let monitor = Monitor::new(fx.allow()?, hooks);
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(
            recovered.failures,
            vec!["pending service action is no longer allowed".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn recover_pending_restores_the_writes_a_dead_monitor_left_armed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        {
            let mut monitor = greeted(fx.allow()?, Hooks::default());
            arm_commit(&mut monitor, None)?;
            // Dropped without confirming, as if the process died.
        }
        assert_eq!(std::fs::read(&fx.target)?, b"v2");
        let monitor = Monitor::new(fx.allow()?, Hooks::default());
        let recovered = monitor
            .recover_pending()?
            .ok_or("expected a recovered commit")?;
        assert_eq!(recovered.commit, CommitId(1));
        assert_eq!(recovered.restored, 1);
        assert!(recovered.failures.is_empty());
        assert_eq!(std::fs::read(&fx.target)?, b"v1");
        assert!(!fx.state_root.join(PENDING_COMMIT_MARKER).exists());
        Ok(())
    }

    #[test]
    fn write_target_reports_io_error_when_the_target_is_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        std::fs::remove_file(&fx.target)?;
        std::fs::create_dir(&fx.target)?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let response = write_v2(&mut monitor)?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        assert!(fx.target.is_dir());
        Ok(())
    }

    #[test]
    fn restore_reports_io_error_when_the_target_became_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(matches!(write_v2(&mut monitor)?, Response::Written(_)));
        std::fs::remove_file(&fx.target)?;
        std::fs::create_dir(&fx.target)?;
        let response = monitor.dispatch(Request::Restore {
            module: ModuleId(0),
            backup: BackupId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        assert!(fx.target.is_dir());
        Ok(())
    }

    #[test]
    fn list_backups_reports_io_error_when_the_backup_directory_is_a_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        let backup_dir = monitor
            .allowlist()
            .target(TargetId(0))
            .ok_or("the fixture declares target 0")?
            .backup_dir
            .clone();
        if let Some(parent) = backup_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&backup_dir, b"not a directory")?;
        let response = monitor.dispatch(Request::ListBackups {
            module: ModuleId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
        Ok(())
    }

    #[test]
    fn lock_reports_a_state_error_when_the_state_root_cannot_be_created()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        assert!(matches!(
            Monitor::lock(&fx.target.join("state")),
            Err(super::MonitorError::State {
                op: "create_dir_all",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn lock_reports_a_state_error_when_the_lock_path_is_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        std::fs::create_dir_all(fx.state_root.join(MONITOR_LOCK))?;
        assert!(matches!(
            Monitor::lock(&fx.state_root),
            Err(super::MonitorError::State {
                op: "open lock",
                ..
            })
        ));
        Ok(())
    }

    // -- the state lock: a monitor without it changes nothing (B6 / H1) --------

    /// Every request that changes state, one of each kind. Service `Status`
    /// is not in this list: it changes nothing.
    fn state_changing_requests() -> Vec<Request> {
        vec![
            Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: true,
            },
            Request::Restore {
                module: ModuleId(0),
                backup: BackupId(0),
            },
            Request::StartConfirmTimer {
                commit: CommitId(1),
                timeout_s: 60,
                service: None,
            },
            Request::ConfirmCommit {
                commit: CommitId(1),
            },
            Request::RollbackCommit {
                commit: CommitId(1),
            },
            Request::Service {
                binding: BindingId(0),
                action: ServiceAction::Restart,
            },
            Request::Service {
                binding: BindingId(0),
                action: ServiceAction::Reload,
            },
            Request::Service {
                binding: BindingId(0),
                action: ServiceAction::Start,
            },
            Request::Service {
                binding: BindingId(0),
                action: ServiceAction::Stop,
            },
            Request::Mount {
                target: TargetId(0),
            },
            Request::ReplaceBinary {
                tag: "v9.9.9".to_owned(),
                len: 5,
                sha256: Sha256Digest::of(b"image"),
            },
            Request::ReloadUnitFiles {
                module: ModuleId(0),
            },
        ]
    }

    /// Serve `requests` after a handshake and a trailing `Shutdown`, with the
    /// given lock, and return the responses to `requests` in order.
    fn serve_queued(
        fx: &Fixture,
        lock: StateLock,
        requests: &[Request],
    ) -> Result<Vec<Response>, Box<dyn std::error::Error>> {
        let (mut monitor_end, mut worker_end) = Channel::pair()?;
        worker_end.send(&Request::Hello {
            proto: PROTO_VERSION,
        })?;
        let count = requests.len();
        for request in requests {
            worker_end.send(request)?;
        }
        worker_end.send(&Request::Shutdown)?;
        let allow = fx.allow()?;
        let descriptor = allow
            .module(ModuleId(0))
            .ok_or("the fixture has module 0")?;
        let mut monitor = Monitor::new(allow, Hooks::default());
        monitor.set_module_registry(vec![Box::new(SyntheticModule { descriptor })]);
        assert_eq!(
            monitor.serve_locked(&mut monitor_end, lock)?,
            ExitReason::Shutdown
        );
        assert!(matches!(
            worker_end.recv::<Response>()?,
            Response::HelloAck(_)
        ));
        let mut responses = Vec::with_capacity(count);
        for _ in 0..count {
            responses.push(worker_end.recv::<Response>()?);
        }
        assert!(matches!(
            worker_end.recv::<Response>()?,
            Response::ShuttingDown
        ));
        Ok(responses)
    }

    #[test]
    fn a_monitor_without_the_state_lock_refuses_every_state_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let requests = state_changing_requests();
        let responses = serve_queued(&fx, StateLock::Unavailable, &requests)?;
        for (request, response) in requests.iter().zip(&responses) {
            assert!(
                matches!(response, Response::Error(ProtoError::StateLockUnavailable)),
                "{request:?} was answered {response:?}"
            );
        }
        assert_eq!(std::fs::read(&fx.target)?, b"v1", "the target is untouched");
        assert!(
            !fx.state_root.exists(),
            "no backup, marker or lock file is created"
        );
        Ok(())
    }

    #[test]
    fn a_monitor_without_the_state_lock_still_answers_reads()
    -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let responses = serve_queued(
            &fx,
            StateLock::Unavailable,
            &[
                Request::ReadTarget {
                    target: TargetId(0),
                },
                Request::PendingCommit,
                Request::Service {
                    binding: BindingId(0),
                    action: ServiceAction::Status,
                },
            ],
        )?;
        let [read, pending, status] = responses.as_slice() else {
            return Err("three responses expected".into());
        };
        assert!(
            matches!(read, Response::Target(t) if t.bytes == b"v1"),
            "{read:?}"
        );
        assert!(matches!(pending, Response::Pending(None)), "{pending:?}");
        // `Status` reaches the service hook (absent here); it is not refused
        // for the lock.
        assert!(
            !matches!(status, Response::Error(ProtoError::StateLockUnavailable)),
            "{status:?}"
        );
        Ok(())
    }

    #[test]
    fn a_monitor_with_the_state_lock_writes() -> Result<(), Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let lock = Monitor::lock(&fx.state_root)?;
        assert!(lock.is_held());
        let responses = serve_queued(
            &fx,
            lock,
            &[Request::WriteTarget {
                target: TargetId(0),
                expected_prev: None,
                bytes: b"v2".to_vec(),
                journal: false,
            }],
        )?;
        let [written] = responses.as_slice() else {
            return Err("one response expected".into());
        };
        assert!(matches!(written, Response::Written(_)), "{written:?}");
        assert_eq!(std::fs::read(&fx.target)?, b"v2");
        Ok(())
    }

    #[test]
    fn the_classifier_lists_exactly_the_state_changing_requests() {
        for request in state_changing_requests() {
            assert!(request.changes_state(), "{request:?}");
        }
        for request in [
            Request::Hello { proto: 1 },
            Request::ReadTarget {
                target: TargetId(0),
            },
            Request::RunCheck {
                check: CheckId(0),
                bytes: Vec::new(),
            },
            Request::ListBackups {
                module: ModuleId(0),
            },
            Request::Service {
                binding: BindingId(0),
                action: ServiceAction::Status,
            },
            Request::PendingCommit,
            Request::Shutdown,
        ] {
            assert!(!request.changes_state(), "{request:?}");
        }
    }

    #[test]
    fn a_denied_state_directory_is_an_unavailable_lock_not_an_error() {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        for op in ["create_dir_all", "open lock"] {
            assert!(
                matches!(
                    super::unavailable_when_denied(op, denied()),
                    Ok(StateLock::Unavailable)
                ),
                "{op}"
            );
        }
        assert!(matches!(
            super::unavailable_when_denied(
                "open lock",
                std::io::Error::from(std::io::ErrorKind::NotFound)
            ),
            Err(super::MonitorError::State {
                op: "open lock",
                ..
            })
        ));
    }

    #[test]
    fn lock_exclusive_refuses_an_unavailable_lock_and_keeps_a_held_one()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            StateLock::Unavailable.require_held(),
            Err(super::MonitorError::LockUnavailable)
        ));
        let fx = fixture()?;
        let held = Monitor::lock_exclusive(&fx.state_root)?;
        assert!(held.is_held());
        // A second monitor on the same root is still `Busy`.
        assert!(matches!(
            Monitor::lock_exclusive(&fx.state_root),
            Err(super::MonitorError::Busy)
        ));
        Ok(())
    }

    // -- staged images: verification, materialization and the swap ------------

    /// A monitor-private staging directory holding one image, `image`.
    fn private_staging(work: &TempDir) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let dir = work.path().join("staging");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let image = dir.join("image");
        std::fs::write(&image, b"image")?;
        Ok((dir, image))
    }

    fn io_error_text(result: Result<Vec<u8>, ProtoError>) -> Option<String> {
        match result {
            Err(ProtoError::Io(message)) => Some(message),
            _ => None,
        }
    }

    #[test]
    fn read_staged_verified_returns_the_bytes_of_a_trusted_image()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let (_, image) = private_staging(&work)?;
        let bytes = read_staged_verified(&image, 5, Sha256Digest::of(b"image"))?;
        assert_eq!(bytes, b"image");
        Ok(())
    }

    #[test]
    fn read_staged_verified_refuses_missing_symlinked_and_non_regular_images()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let (dir, image) = private_staging(&work)?;
        let digest = Sha256Digest::of(b"image");
        assert_eq!(
            io_error_text(read_staged_verified(&dir.join("absent"), 5, digest)).as_deref(),
            Some("staged binary is missing")
        );
        let link = dir.join("link");
        std::os::unix::fs::symlink(&image, &link)?;
        assert!(
            io_error_text(read_staged_verified(&link, 5, digest))
                .is_some_and(|message| message.starts_with("open staged binary:"))
        );
        let subdir = dir.join("subdir");
        std::fs::create_dir(&subdir)?;
        assert_eq!(
            io_error_text(read_staged_verified(&subdir, 5, digest)).as_deref(),
            Some("staged binary is not a regular file")
        );
        Ok(())
    }

    #[test]
    fn read_staged_verified_refuses_a_hard_linked_image() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let (dir, image) = private_staging(&work)?;
        std::fs::hard_link(&image, dir.join("second-name"))?;
        assert_eq!(
            io_error_text(read_staged_verified(&image, 5, Sha256Digest::of(b"image"))).as_deref(),
            Some("staged binary is not trusted")
        );
        Ok(())
    }

    #[test]
    fn read_staged_verified_refuses_a_group_writable_staging_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let (dir, image) = private_staging(&work)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))?;
        assert_eq!(
            io_error_text(read_staged_verified(&image, 5, Sha256Digest::of(b"image"))).as_deref(),
            Some("staged binary is not trusted")
        );
        Ok(())
    }

    #[test]
    fn read_staged_verified_refuses_a_wrong_length_or_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let (_, image) = private_staging(&work)?;
        assert_eq!(
            io_error_text(read_staged_verified(&image, 4, Sha256Digest::of(b"image"))).as_deref(),
            Some("staged binary size does not match the request")
        );
        let claimed = Sha256Digest::of(b"other");
        assert!(matches!(
            read_staged_verified(&image, 5, claimed),
            Err(ProtoError::Conflict { expected, actual: Some(actual) })
                if expected == claimed && actual == Sha256Digest::of(b"image")
        ));
        Ok(())
    }

    #[test]
    fn materialize_staged_refuses_a_tag_that_is_not_a_plain_file_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let digest = Sha256Digest::of(b"image");
        for tag in ["", ".", "..", "a/b", "nul\0byte"] {
            assert!(matches!(
                materialize_staged(work.path(), &work.path().join("staging"), tag, 5, digest),
                Err(ProtoError::VerificationFailed)
            ));
        }
        assert!(!work.path().join("staging").exists());
        Ok(())
    }

    #[test]
    fn materialize_staged_reports_io_error_when_staging_cannot_be_created()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let file = work.path().join("file");
        std::fs::write(&file, b"x")?;
        let result = materialize_staged(
            work.path(),
            &file.join("staging"),
            FIXTURE_TAG,
            5,
            Sha256Digest::of(b"image"),
        );
        assert!(matches!(
            result,
            Err(ProtoError::Io(message)) if message.starts_with("create monitor staging directory")
        ));
        Ok(())
    }

    #[test]
    fn materialize_staged_refuses_a_source_that_is_its_own_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let digest = Sha256Digest::of(b"image");
        let tag = digest.to_string();
        let inputs = work.path().join(STAGED_DIR);
        std::fs::create_dir_all(&inputs)?;
        // Private, so the staging trust check passes whatever the umask.
        std::fs::set_permissions(&inputs, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(inputs.join(&tag), b"image")?;
        assert!(matches!(
            materialize_staged(work.path(), &inputs, &tag, 5, digest),
            Err(ProtoError::VerificationFailed)
        ));
        assert_eq!(std::fs::read(inputs.join(&tag))?, b"image");
        Ok(())
    }

    #[test]
    fn materialize_staged_refuses_an_unreadable_or_wrong_sized_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let digest = Sha256Digest::of(b"image");
        let inputs = work.path().join(STAGED_DIR);
        let staging = work.path().join("monitor-staging");
        // A directory is refused by the regular-file check, before any read.
        std::fs::create_dir_all(inputs.join("v1.0.0"))?;
        assert!(matches!(
            materialize_staged(work.path(), &staging, "v1.0.0", 5, digest),
            Err(ProtoError::Io(message)) if message == "staged binary is not a regular file"
        ));
        std::fs::write(inputs.join("v2.0.0"), b"image")?;
        assert!(matches!(
            materialize_staged(work.path(), &staging, "v2.0.0", 6, digest),
            Err(ProtoError::Io(message)) if message == "staged binary size does not match the request"
        ));
        assert!(!staged_path(&staging, digest).exists());
        Ok(())
    }

    #[test]
    fn materialize_staged_refuses_a_fifo_without_blocking() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let inputs = work.path().join(STAGED_DIR);
        std::fs::create_dir_all(&inputs)?;
        // `mkfifo(1)` rather than `mknodat`, which rustix does not offer
        // on macOS.
        let made = std::process::Command::new("mkfifo")
            .arg(inputs.join("v2.0.0"))
            .status()?;
        assert!(made.success(), "mkfifo failed: {made}");
        let state_root = work.path().to_path_buf();
        let staging = work.path().join("monitor-staging");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = materialize_staged(
                &state_root,
                &staging,
                "v2.0.0",
                5,
                Sha256Digest::of(b"image"),
            );
            let _ = sender.send(result);
        });
        // With no writer, a blocking open of the FIFO never returns.
        let result = receiver.recv_timeout(Duration::from_secs(5))?;
        assert!(matches!(
            result,
            Err(ProtoError::Io(message)) if message == "staged binary is not a regular file"
        ));
        Ok(())
    }

    #[test]
    fn materialize_staged_refuses_a_symlinked_staged_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let digest = Sha256Digest::of(b"image");
        let elsewhere = work.path().join("elsewhere");
        std::fs::create_dir(&elsewhere)?;
        std::fs::write(elsewhere.join("v2.0.0"), b"image")?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(state_root.join("update"))?;
        std::os::unix::fs::symlink(&elsewhere, state_root.join(STAGED_DIR))?;
        let staging = work.path().join("monitor-staging");
        assert!(matches!(
            materialize_staged(&state_root, &staging, "v2.0.0", 5, digest),
            Err(ProtoError::Io(message)) if message == "staged input directory is not trusted"
        ));
        assert!(!staged_path(&staging, digest).exists());
        Ok(())
    }

    #[test]
    fn replace_binary_refuses_a_tag_that_is_not_semver() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        let target = swap_target(work.path(), "detent-semver", b"old-binary")?;
        let mut monitor = update_monitor(
            &state_root,
            &work.path().join("monitor-staging"),
            target.clone(),
        )?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: "latest".to_owned(),
            len: 5,
            sha256: Sha256Digest::of(b"image"),
        })?;
        assert_eq!(
            io_message(&response),
            Some("release tag is not a semver version")
        );
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn replace_binary_surfaces_a_missing_staged_input() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-missing", b"old-binary")?;
        let mut monitor = update_monitor(
            &state_root,
            &work.path().join("monitor-staging"),
            target.clone(),
        )?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: "v999.0.0".to_owned(),
            len: 5,
            sha256: Sha256Digest::of(b"image"),
        })?;
        assert!(
            io_message(&response).is_some_and(|message| message.starts_with("open staged binary")),
            "unexpected response {response:?}"
        );
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn replace_binary_refuses_a_missing_or_unparseable_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        for bundle in [None, Some(b"not a sigstore bundle".as_slice())] {
            let work = TempDir::new()?;
            let state_root = work.path().join("state");
            std::fs::create_dir_all(&state_root)?;
            let target = swap_target(work.path(), "detent-bundle", b"old-binary")?;
            let (digest, bytes) = plant_release(&state_root, "valid.json")?;
            let bundle_path = state_root
                .join(STAGED_DIR)
                .join(format!("{FIXTURE_TAG}.sigstore.json"));
            match bundle {
                None => std::fs::remove_file(&bundle_path)?,
                Some(contents) => std::fs::write(&bundle_path, contents)?,
            }
            let mut monitor = update_monitor(
                &state_root,
                &work.path().join("monitor-staging"),
                target.clone(),
            )?;
            let response = monitor.dispatch(Request::ReplaceBinary {
                tag: FIXTURE_TAG.to_owned(),
                len: bytes.len() as u64,
                sha256: digest,
            })?;
            assert!(matches!(
                response,
                Response::Error(ProtoError::VerificationFailed)
            ));
            assert_eq!(std::fs::read(&target)?, b"old-binary");
        }
        Ok(())
    }

    #[test]
    fn replace_binary_refuses_a_symlinked_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-link", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        // The linked file is the valid bundle, so only the open can refuse it.
        let elsewhere = work.path().join("elsewhere.sigstore.json");
        let bundle_path = state_root
            .join(STAGED_DIR)
            .join(format!("{FIXTURE_TAG}.sigstore.json"));
        std::fs::rename(&bundle_path, &elsewhere)?;
        std::os::unix::fs::symlink(&elsewhere, &bundle_path)?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::VerificationFailed)
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        assert!(!staged_path(&staging_dir, digest).exists());
        Ok(())
    }

    #[test]
    fn replace_binary_refuses_a_fifo_bundle_without_blocking()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-fifo", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let bundle_path = state_root
            .join(STAGED_DIR)
            .join(format!("{FIXTURE_TAG}.sigstore.json"));
        std::fs::remove_file(&bundle_path)?;
        let made = std::process::Command::new("mkfifo")
            .arg(&bundle_path)
            .status()?;
        assert!(made.success(), "mkfifo failed: {made}");
        let staging_dir = work.path().join("monitor-staging");
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread_target = target.clone();
        std::thread::spawn(move || {
            let outcome = update_monitor(&state_root, &staging_dir, thread_target)
                .and_then(|mut monitor| {
                    monitor
                        .dispatch(Request::ReplaceBinary {
                            tag: FIXTURE_TAG.to_owned(),
                            len: bytes.len() as u64,
                            sha256: digest,
                        })
                        .map_err(Into::into)
                })
                .map_err(|err| err.to_string());
            let _ = sender.send((outcome, staged_path(&staging_dir, digest).exists()));
        });
        // With no writer, a blocking open of the FIFO never returns.
        let (outcome, copy_left) = receiver.recv_timeout(Duration::from_secs(5))?;
        assert!(matches!(
            outcome,
            Ok(Response::Error(ProtoError::VerificationFailed))
        ));
        assert!(!copy_left);
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn replace_binary_leaves_no_copy_after_a_failed_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-leftover", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "wrong-identity.json")?;
        std::fs::write(
            state_root
                .join(STAGED_DIR)
                .join(format!("{FIXTURE_TAG}.sigstore.json")),
            b"not a sigstore bundle",
        )?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor = update_monitor(&state_root, &staging_dir, target.clone())?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::VerificationFailed)
        ));
        assert!(!staged_path(&staging_dir, digest).exists());
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn replace_binary_leaves_no_copy_after_a_failed_swap() -> Result<(), Box<dyn std::error::Error>>
    {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let staging_dir = work.path().join("monitor-staging");
        let mut monitor =
            update_monitor(&state_root, &staging_dir, work.path().join("detent-gone"))?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert_eq!(io_message(&response), Some("running binary is missing"));
        assert!(!staged_path(&staging_dir, digest).exists());
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn replace_binary_verifies_against_the_embedded_roots_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
        // The fixture bundle is signed by test roots, so without injected
        // trust the embedded production roots must refuse it.
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let target = swap_target(work.path(), "detent-embedded", b"old-binary")?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let config = Config::with_state_root(&state_root);
        let mut monitor = Monitor::new(Allowlist::from_modules(&[], &config)?, Hooks::default());
        monitor.set_staging_dir(work.path().join("monitor-staging"));
        monitor.set_binary_override(target.clone());
        let _ = monitor.dispatch(Request::Hello {
            proto: PROTO_VERSION,
        });
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert!(matches!(
            response,
            Response::Error(ProtoError::VerificationFailed)
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn replace_binary_reports_a_missing_running_binary_after_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root)?;
        let (digest, bytes) = plant_release(&state_root, "valid.json")?;
        let target = work.path().join("detent-gone");
        let mut monitor = update_monitor(
            &state_root,
            &work.path().join("monitor-staging"),
            target.clone(),
        )?;
        let response = monitor.dispatch(Request::ReplaceBinary {
            tag: FIXTURE_TAG.to_owned(),
            len: bytes.len() as u64,
            sha256: digest,
        })?;
        assert_eq!(io_message(&response), Some("running binary is missing"));
        assert!(!target.exists());
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn read_bounded_file_refuses_a_file_over_its_cap() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let path = work.path().join("bundle");
        std::fs::write(&path, b"1234")?;
        let file = std::fs::File::open(&path)?;
        assert_eq!(super::read_bounded_file(&file, 4)?, b"1234");
        assert!(super::read_bounded_file(&std::fs::File::open(&path)?, 3).is_err());
        Ok(())
    }

    #[test]
    fn swap_running_binary_refuses_a_target_that_is_not_a_regular_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let staged = work.path().join("staged");
        let directory = work.path().join("detent-dir");
        std::fs::create_dir(&directory)?;
        assert!(matches!(
            swap_running_binary(b"new", &staged, &directory),
            Err(ProtoError::Io(message)) if message == "running binary is not a regular file"
        ));
        let file = swap_target(work.path(), "detent-file", b"old-binary")?;
        assert!(matches!(
            swap_running_binary(b"new", &staged, &file.join("below-a-file")),
            Err(ProtoError::Io(message)) if message.starts_with("stat running binary")
        ));
        assert_eq!(std::fs::read(&file)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn swap_running_binary_refuses_when_the_previous_name_is_taken_by_a_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let target = swap_target(work.path(), "detent-prev", b"old-binary")?;
        let previous = work.path().join(format!("detent-prev{PREVIOUS_SUFFIX}"));
        std::fs::create_dir(&previous)?;
        std::fs::write(previous.join("keep"), b"x")?;
        assert!(matches!(
            swap_running_binary(b"new", &work.path().join("staged"), &target),
            Err(ProtoError::Io(message)) if message.starts_with("unlink previous binary")
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn swap_running_binary_refuses_to_reuse_a_leftover_temp_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let target = swap_target(work.path(), "detent-tmp", b"old-binary")?;
        // A non-empty directory under the temp name survives the pre-clean
        // `remove_file`, so the `O_EXCL` create must fail.
        let tmp = work
            .path()
            .join(format!("staged.tmp.{}", std::process::id()));
        std::fs::create_dir(&tmp)?;
        std::fs::write(tmp.join("keep"), b"x")?;
        assert!(matches!(
            swap_running_binary(b"new", &work.path().join("staged"), &target),
            Err(ProtoError::Io(message)) if message.starts_with("stage binary in target dir")
        ));
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn copy_file_copies_the_contents_and_the_mode() -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let source = swap_target(work.path(), "detent-src", b"old-binary")?;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o750))?;
        let copy = work.path().join("detent-src.prev");
        super::copy_file(&source, &copy)?;
        assert_eq!(std::fs::read(&copy)?, b"old-binary");
        assert_eq!(
            std::fs::metadata(&copy)?.permissions().mode() & 0o7777,
            0o750
        );
        Ok(())
    }

    #[test]
    fn copy_file_refuses_an_existing_destination_and_a_missing_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let source = swap_target(work.path(), "detent-src", b"new")?;
        let taken = work.path().join("taken");
        std::fs::write(&taken, b"mine")?;
        assert_eq!(
            super::copy_file(&source, &taken).map_err(|err| err.kind()),
            Err(std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&taken)?, b"mine");
        assert_eq!(
            super::copy_file(&work.path().join("absent"), &work.path().join("copy"))
                .map_err(|err| err.kind()),
            Err(std::io::ErrorKind::NotFound)
        );
        assert!(!work.path().join("copy").exists());
        Ok(())
    }

    #[test]
    fn write_temp_and_swap_never_writes_through_a_file_at_the_temp_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let target = swap_target(work.path(), "detent-excl", b"old-binary")?;
        let permissions = std::fs::metadata(&target)?.permissions();
        let victim = work.path().join("victim");
        std::fs::write(&victim, b"victim")?;
        // A symlink and a regular file at the temp name: without `O_EXCL`
        // the first write lands in `victim`, the second reuses the file.
        let symlinked = work.path().join("symlinked.tmp");
        std::os::unix::fs::symlink(&victim, &symlinked)?;
        let regular = work.path().join("regular.tmp");
        std::fs::write(&regular, b"leftover")?;
        for tmp in [&symlinked, &regular] {
            assert!(matches!(
                write_temp_and_swap(
                    b"new",
                    &work.path().join("staged"),
                    &target,
                    work.path(),
                    tmp,
                    &permissions,
                ),
                Err(ProtoError::Io(message)) if message.starts_with("stage binary in target dir")
            ));
        }
        assert_eq!(std::fs::read(&victim)?, b"victim");
        assert_eq!(std::fs::read(&target)?, b"old-binary");
        Ok(())
    }

    #[test]
    fn write_temp_and_swap_reports_a_directory_it_cannot_open_for_fsync()
    -> Result<(), Box<dyn std::error::Error>> {
        let work = TempDir::new()?;
        let target = swap_target(work.path(), "detent-dirsync", b"old-binary")?;
        let permissions = std::fs::metadata(&target)?.permissions();
        let tmp = work.path().join("dirsync.tmp");
        let result = write_temp_and_swap(
            b"new",
            &work.path().join("staged"),
            &target,
            &work.path().join("absent-directory"),
            &tmp,
            &permissions,
        );
        assert!(matches!(
            result,
            Err(ProtoError::Io(message)) if message.starts_with("sync target directory")
        ));
        Ok(())
    }

    // -- misc ---------------------------------------------------------------

    #[test]
    fn the_test_fixtures_backend_detect_always_matches() {
        assert!(always(&HostProfile::default_for_tests()));
    }
}
