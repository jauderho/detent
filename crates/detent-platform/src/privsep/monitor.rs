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
//! [`ProtoError::Unavailable`]. `Mount` answers [`ProtoError::Unsupported`]
//! until the `module-mounts` feature exists.

use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use detent_core::descriptor::{
    ExternalCheck, HostProfile, ServiceAction as CoreServiceAction, ServiceBinding, ValidationCtx,
};
use detent_core::module::DynModule;
use serde::{Deserialize, Serialize};

use super::allowlist::Allowlist;
use super::proto::{
    BackupId, BackupInfo, BindingId, CheckId, CheckOutcome, CommitId, IdKind, ModuleId,
    PendingService, ProtoError, Request, Response, ServiceAction, ServiceOutcome, TargetContents,
    TargetId, WriteReceipt,
};
use super::transport::{Channel, ChannelError};
use crate::fs::atomic::{
    AtomicError, BackupEntry, WriteRequest, list_backups, read_with_digest, restore_backup,
    write_atomic,
};

/// Name of the crash-recovery marker inside the state root.
pub const PENDING_COMMIT_MARKER: &str = "pending-commit.json";

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
        self.recover_pending()?;
        self.serve_locked(channel, state_lock)
    }

    /// Serve after the caller has taken [`MONITOR_LOCK`] and recovered any
    /// leftover marker. The guard is held until every return path completes.
    ///
    /// # Errors
    ///
    /// Returns a channel, protocol, or state error from serving or cleanup.
    pub fn serve_locked(
        &mut self,
        channel: &mut Channel,
        _state_lock: std::fs::File,
    ) -> Result<ExitReason, MonitorError> {
        let result = self.serve_loop(channel);
        let cleanup = self.rollback_pending_on_exit();
        match (result, cleanup) {
            (Ok(reason), Ok(())) => Ok(reason),
            (Err(err), Ok(())) | (Ok(_), Err(err)) => Err(err),
            (Err(_), Err(cleanup)) => Err(cleanup),
        }
    }

    /// Take the exclusive monitor lock without running recovery.
    ///
    /// # Errors
    ///
    /// Returns [`MonitorError::Busy`] when another monitor owns the lock, or
    /// a state error when the lock cannot be opened.
    pub fn lock(state_root: &Path) -> Result<std::fs::File, MonitorError> {
        lock_state(state_root)
    }

    fn serve_loop(&mut self, channel: &mut Channel) -> Result<ExitReason, MonitorError> {
        let idle_timeout = channel.read_timeout();
        loop {
            let want = if self.pending.is_some() {
                PENDING_POLL
            } else {
                idle_timeout
            };
            if channel.read_timeout() != want {
                channel
                    .set_read_timeout(want)
                    .map_err(MonitorError::Channel)?;
            }

            match channel.poll_recv::<Request>() {
                Ok(None) => {}
                Ok(Some(request)) => {
                    let stop = matches!(request, Request::Shutdown);
                    let response = self.dispatch(request)?;
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
        let restored = roll_back(&pending.entries);
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
            Request::Mount { .. } => Response::Error(ProtoError::Unsupported(
                "mount requires the module-mounts feature".to_owned(),
            )),
            Request::ReplaceBinary { tag, len, sha256 } => self.replace_binary(&tag, len, sha256),
            Request::Shutdown => Response::ShuttingDown,
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
        let bytes = match read_staged_verified(&staged, len, sha256) {
            Ok(bytes) => bytes,
            Err(err) => return Response::Error(err),
        };
        let tag_path = match staged_input_path(self.allow.state_root(), tag) {
            Ok(path) => path,
            Err(err) => return Response::Error(err),
        };
        let bundle_path = tag_path.with_file_name(format!("{tag}.sigstore.json"));
        if let Err(err) = self.verify_release(&bundle_path, tag, sha256) {
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
        bundle_path: &Path,
        tag: &str,
        sha256: crate::fs::atomic::Sha256Digest,
    ) -> Result<(), ProtoError> {
        let Ok(bundle) = read_bounded_file(bundle_path, detent_update::bundle::MAX_BUNDLE_BYTES)
        else {
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
        bundle_path: &Path,
        tag: &str,
        _sha256: crate::fs::atomic::Sha256Digest,
    ) -> Result<(), ProtoError> {
        tracing::warn!(
            tag,
            bundle = %bundle_path.display(),
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
        let request = WriteRequest {
            path: &entry.path,
            contents: bytes,
            expected_prev,
            backup_dir: &entry.backup_dir,
            keep_backups: self.allow.keep_backups(),
            create_missing: false,
            create_mode: entry.create_mode,
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
        let dir = self.staging_dir.clone();
        if let Err(err) = std::fs::create_dir_all(&dir) {
            return Err(Response::Error(ProtoError::Io(format!(
                "cannot create the candidate directory: {}",
                err.kind()
            ))));
        }
        let candidate = tempfile::Builder::new()
            .prefix("detent-validate-")
            .tempfile_in(&dir)
            .map_err(|err| {
                Response::Error(ProtoError::Io(format!(
                    "cannot create a candidate file: {}",
                    err.kind()
                )))
            })?;
        write_all_and_sync(candidate.as_file(), bytes).map_err(|err| {
            Response::Error(ProtoError::Io(format!(
                "cannot write the candidate file: {}",
                err.kind()
            )))
        })?;
        for check in descriptor.checks {
            let outcome = self
                .hooks
                .checks
                .run_check(check, candidate.path())
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
    /// execute content. Existing directives remain editable in place.
    fn has_new_forbidden_exec_directive(module: &str, previous: &[u8], candidate: &[u8]) -> bool {
        fn directives(text: &[u8], names: &[&str]) -> usize {
            String::from_utf8_lossy(text)
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                        return None;
                    }
                    line.split_once('=')
                        .map_or_else(
                            || line.split_whitespace().next(),
                            |(key, _)| Some(key.trim()),
                        )
                        .map(str::to_ascii_lowercase)
                })
                .filter(|key| names.iter().any(|name| key == *name))
                .count()
        }

        fn words(text: &[u8], prefix: &str) -> usize {
            String::from_utf8_lossy(text)
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|word| word.starts_with(prefix))
                .count()
        }

        let added = |names: &[&str]| directives(candidate, names) > directives(previous, names);
        match module {
            "samba" => added(&[
                "root preexec",
                "root postexec",
                "preexec",
                "postexec",
                "add user script",
                "include",
            ]),
            "dhcp" => added(&["dhcp-script", "dhcp-luascript", "conf-file", "conf-dir"]),
            "chrony" => added(&["include", "confdir", "sourcedir", "pidfile"]),
            "resolver" => added(&["include:", "python-script:"]),
            "network" => {
                let forbidden = |text: &[u8]| {
                    String::from_utf8_lossy(text)
                        .lines()
                        .filter(|line| {
                            let (key, value) = line
                                .split_once('=')
                                .or_else(|| line.split_once(char::is_whitespace))
                                .unwrap_or((line, ""));
                            match key.trim().to_ascii_lowercase().as_str() {
                                "up" => {
                                    let words: Vec<&str> = value.split_whitespace().collect();
                                    if words.len() < 5 {
                                        return true;
                                    }
                                    !matches!(
                                        words.as_slice(),
                                        ["ip", "route", "add", .., "via", _]
                                    )
                                }
                                "down" | "pre-up" | "post-down" => true,
                                _ => false,
                            }
                        })
                        .count()
                };
                forbidden(candidate) > forbidden(previous)
            }
            "mounts" => words(candidate, "x-systemd.") > words(previous, "x-systemd."),
            "nfs" => words(candidate, "no_root_squash") > words(previous, "no_root_squash"),
            _ => false,
        }
    }

    fn run_check(&self, id: CheckId, bytes: &[u8]) -> Response {
        let Some(entry) = self.allow.check(id) else {
            return unknown(IdKind::Check, u32::from(id.get()));
        };
        let dir = self.staging_dir.clone();
        if let Err(err) = std::fs::create_dir_all(&dir) {
            return Response::Error(ProtoError::Io(format!(
                "cannot create the candidate directory: {}",
                err.kind()
            )));
        }
        let candidate = match tempfile::Builder::new()
            .prefix("detent-candidate-")
            .tempfile_in(&dir)
        {
            Ok(file) => file,
            Err(err) => {
                return Response::Error(ProtoError::Io(format!(
                    "cannot create a candidate file: {}",
                    err.kind()
                )));
            }
        };
        if let Err(err) = write_all_and_sync(candidate.as_file(), bytes) {
            return Response::Error(ProtoError::Io(format!(
                "cannot write the candidate file: {}",
                err.kind()
            )));
        }
        match self.hooks.checks.run_check(entry.check, candidate.path()) {
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
        match restore_backup(source, target_path) {
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
                self.pending = None;
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
        let restored = roll_back(&pending.entries);
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
        let restored = roll_back(&pending.entries);
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
        match std::fs::remove_file(self.marker_path()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(MonitorError::State {
                op: "remove_file",
                source,
            }),
        }
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
        let mut restored = 0_usize;
        for entry in marker.entries.iter().rev() {
            match restore_backup(&entry.backup, &entry.path) {
                Ok(_) => restored = restored.saturating_add(1),
                Err(err) => failures.push(err.to_string()),
            }
        }
        if let Err(err) = self.replay_service(marker.service) {
            failures.push(err.to_string());
        }
        std::fs::remove_file(&path).map_err(|source| MonitorError::State {
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

fn lock_state(state_dir: &Path) -> Result<std::fs::File, MonitorError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Err(source) = std::fs::create_dir_all(state_dir) {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            // `host` and other read-only commands run with the default
            // `state_root` (/var/lib/detent) even when the caller is not root.
            // Creating that directory would require privilege and must not turn
            // a read-only command into a startup failure. Fall back to a dummy
            // lock so the monitor can still serve; mutual exclusion for the
            // real state directory is only needed when it is actually writable.
            return std::fs::File::open("/dev/null").map_err(|source| MonitorError::State {
                op: "open lock",
                source,
            });
        }
        return Err(MonitorError::State {
            op: "create_dir_all",
            source,
        });
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
        Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
            return std::fs::File::open("/dev/null").map_err(|source| MonitorError::State {
                op: "open lock",
                source,
            });
        }
        Err(source) => {
            return Err(MonitorError::State {
                op: "open lock",
                source,
            });
        }
    };
    if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        // A dummy /dev/null fd never contends, so this only fires for the
        // real lock file. A second live monitor is the intended error.
        return Err(MonitorError::Busy);
    }
    Ok(file)
}

/// Restore the recorded backups, newest write first. Failures are logged and
/// counted; one unreadable backup must not abandon the rest.
fn roll_back(entries: &[RollbackEntry]) -> usize {
    let mut restored = 0_usize;
    for entry in entries.iter().rev() {
        match restore_backup(&entry.backup, &entry.path) {
            Ok(_) => restored = restored.saturating_add(1),
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

fn ensure_staging_dir(monitor_staging_dir: &Path) -> Result<PathBuf, ProtoError> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::create_dir_all(monitor_staging_dir).map_err(|err| {
        ProtoError::Io(format!("create monitor staging directory: {}", err.kind()))
    })?;
    let meta = std::fs::symlink_metadata(monitor_staging_dir)
        .map_err(|err| ProtoError::Io(format!("stat monitor staging directory: {}", err.kind())))?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o022 != 0
    {
        return Err(ProtoError::Io(
            "monitor staging directory is not trusted".to_owned(),
        ));
    }
    Ok(monitor_staging_dir.to_path_buf())
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
    let source_fd = rustix::fs::open(
        &source,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| ProtoError::Io(format!("open staged binary: {err}")))?;
    let source_file: std::fs::File = source_fd.into();
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
    write_all_and_sync(&file, &bytes)
        .map_err(|err| ProtoError::Io(format!("materialize staged binary: {}", err.kind())))?;
    std::fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| ProtoError::Io(format!("sync staging directory: {}", err.kind())))?;
    Ok(())
}

#[cfg(feature = "update")]
fn read_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
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
    if meta.uid() != rustix::process::geteuid().as_raw()
        || parent_meta.uid() != rustix::process::geteuid().as_raw()
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

    if let Err(err) = std::fs::remove_file(&previous)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(ProtoError::Io(format!(
            "unlink previous binary: {}",
            err.kind()
        )));
    }
    if let Err(err) = std::fs::hard_link(target, &previous)
        && let Err(copy_err) = std::fs::copy(target, &previous)
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
    let _ = std::fs::remove_file(&tmp);
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
            let _ = std::fs::remove_file(tmp);
            return Err(ProtoError::Io(format!("stage binary in target dir: {err}")));
        }
    };
    let tmp_file: std::fs::File = fd.into();
    if let Err(err) = write_all_and_sync(&tmp_file, bytes) {
        let _ = std::fs::remove_file(tmp);
        return Err(ProtoError::Io(format!(
            "stage binary in target dir: {}",
            err.kind()
        )));
    }
    // The installed binary must keep the *target's* mode, not the staged
    // file's — otherwise the swap installs a non-executable binary and the
    // next `--self-test` fails with EACCES (a58f89c / stage_exec.rs).
    if let Err(err) = tmp_file.set_permissions(permissions.clone()) {
        let _ = std::fs::remove_file(tmp);
        return Err(ProtoError::Io(format!(
            "chmod staged binary: {}",
            err.kind()
        )));
    }
    if let Err(err) = tmp_file.sync_all() {
        let _ = std::fs::remove_file(tmp);
        return Err(ProtoError::Io(format!(
            "sync staged binary: {}",
            err.kind()
        )));
    }
    drop(tmp_file);
    if let Err(err) = std::fs::rename(tmp, target) {
        let _ = std::fs::remove_file(tmp);
        return Err(ProtoError::Io(format!(
            "rename staged binary over target: {}",
            err.kind()
        )));
    }
    // Fsync the target directory so the rename itself is durable.
    if let Ok(dir) = std::fs::File::open(target_dir)
        && let Err(err) = dir.sync_all()
    {
        return Err(ProtoError::Io(format!(
            "sync target directory: {}",
            err.kind()
        )));
    }
    // Staged file consumed: the verified bytes now live at the target.
    let _ = std::fs::remove_file(staged);
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
        CheckRunner, ExitReason, HookError, Hooks, MAX_CONFIRM_TIMEOUT_S, Monitor,
        PENDING_COMMIT_MARKER, STAGED_DIR, ServiceControl, finish_send_error, materialize_staged,
        staged_path,
    };
    use crate::fs::atomic::{AtomicError, Sha256Digest};
    use crate::privsep::allowlist::{Allowlist, AllowlistError, Config};
    use crate::privsep::proto::{
        BackupId, BindingId, CheckId, CheckOutcome, CommitId, IdKind, ModuleId, PROTO_VERSION,
        ProtoError, Request, Response, ServiceAction, ServiceOutcome, TargetId,
    };
    use crate::privsep::transport::{Channel, ChannelError};
    use crate::privsep::worker::Client;
    use detent_core::descriptor::{
        ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, Owner,
        PathSpec, ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind,
        UnitNames, Upstream,
    };
    use detent_core::diag::{Diagnostics, MessageId};
    use detent_core::module::{DynError, DynModule};
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
        let target_path = leak_str(target_path.display().to_string());
        let targets: &'static [Target] = leak(vec![Target {
            path: PathSpec::new(target_path),
            kind: TargetKind::File,
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

    #[test]
    fn run_check_places_the_candidate_in_monitor_staging() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        let allow = fx.allow()?;
        let staging_dir = fx
            .state_root
            .parent()
            .unwrap_or(&fx.root)
            .join("monitor-staging");
        let checks = CandidateChecks(staging_dir.clone());
        let hooks = Hooks {
            checks: &checks,
            services: &super::NoServices,
        };
        let mut monitor = greeted(allow, hooks);
        monitor.set_staging_dir(staging_dir);
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: b"candidate".to_vec(),
        })?;
        assert!(matches!(response, Response::Checked(outcome) if outcome.passed));
        Ok(())
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
        let mut monitor = greeted(fx.allow()?, Hooks::default());
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
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        monitor.set_staging_dir(tmp_dir.clone());
        let response = monitor.dispatch(Request::RunCheck {
            check: CheckId(0),
            bytes: Vec::new(),
        })?;
        assert!(std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o700)).is_ok());
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
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
    fn read_target_reports_io_error_when_the_file_is_gone() -> Result<(), Box<dyn std::error::Error>>
    {
        let fx = fixture()?;
        let mut monitor = greeted(fx.allow()?, Hooks::default());
        assert!(std::fs::remove_file(&fx.target).is_ok());
        let response = monitor.dispatch(Request::ReadTarget {
            target: TargetId(0),
        })?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
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
        let candidate = b"[global]\nworkgroup = EXAMPLE\nroot preexec = /bin/sh\n";

        let response = monitor.dispatch(Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: candidate.to_vec(),
            journal: false,
        })?;

        assert!(matches!(response, Response::Error(_)));
        assert_eq!(std::fs::read(&target)?, original);
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
        assert!(std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o500)).is_ok());
        let response = monitor.dispatch(Request::Restore {
            module: ModuleId(0),
            backup: BackupId(0),
        });
        assert!(std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o700)).is_ok());
        let response = response?;
        assert!(matches!(response, Response::Error(ProtoError::Io(_))));
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

    const FIXTURE_TAG: &str = "v0.0.2";

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../detent-update/tests/fixtures")
    }

    #[cfg(feature = "update")]
    fn fixture_trust() -> Result<detent_update::trust::TrustRoot, Box<dyn std::error::Error>> {
        let root = std::fs::read_to_string(fixture_dir().join("fulcio-root.pem"))?;
        let rekor = std::fs::read_to_string(fixture_dir().join("rekor-pub.pem"))?;
        Ok(detent_update::trust::from_pems(&root, &rekor)?)
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

    // -- misc ---------------------------------------------------------------

    #[test]
    fn the_test_fixtures_backend_detect_always_matches() {
        assert!(always(&HostProfile::default_for_tests()));
    }
}
