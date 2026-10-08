//! The wire protocol between the privileged monitor and the unprivileged
//! worker (PLAN §2.4, Appendix B; ADR-001).
//!
//! # Shape
//!
//! [`Request`] and [`Response`] are **closed** enums on purpose: neither is
//! `#[non_exhaustive]`, because a peer that receives a discriminant it does not
//! know must terminate the connection rather than skip the message. `postcard`
//! gives that for free — an out-of-range enum discriminant fails to decode.
//!
//! # Ids, not names
//!
//! No request names a filesystem path, a systemd unit, or a program. Every
//! request selects one entry of a table the *monitor* built at startup from the
//! compiled-in [`ModuleDescriptor`](detent_core::descriptor::ModuleDescriptor)
//! set. The worker learns which ids exist from [`HelloAck`], which is the only
//! message in the protocol that carries paths at all, and it carries them
//! monitor → worker for display purposes only. A compromised worker can
//! therefore ask for "target 3" but can never ask for `/etc/shadow`.
//!
//! # Framing and size
//!
//! Encoding is `postcard`. [`MAX_FRAME`] bounds a single message at 1 MiB;
//! [`decode`] rejects anything larger *before* it allocates. Framing itself
//! lives in [`transport`](super::transport).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::fs::atomic::Sha256Digest;
use detent_core::descriptor::{ServiceAction as CoreServiceAction, TargetKind};

/// Version of this protocol. Both peers must agree exactly; there is no
/// negotiation, because both sides ship in the same binary.
///
/// # Appending a variant to a closed enum
///
/// [`Request::RollbackCommit`], [`Request::PendingCommit`],
/// [`Response::RolledBack`], and [`Response::Pending`] were added at the
/// end of their enums (see each variant's doc comment) rather than grouped
/// next to the confirm operations, so every existing discriminant keeps its
/// numeric value. That is a backward-incompatible change in exactly one
/// direction: an *old* binary decoding a frame a *new* binary sent would meet
/// an out-of-range discriminant and correctly terminate the connection per
/// this module's closed-enum invariant (see the module docs) — it would not
/// misinterpret the message as something else. The reverse direction is
/// unaffected, because an old peer never emits a discriminant a new peer does
/// not know.
///
/// `Request::WriteTarget::journal` (H3) appends a field inside an existing
/// variant, which changes the wire shape. `PROTO_VERSION` was bumped to `2`
/// for it, so a mismatched pair fails at the `Hello` handshake rather than
/// mis-decoding the frame.
///
/// [`Request::StageBegin`], [`Request::StageUpdate`] and [`Response::Staged`]
/// (C1-b) are appended variants and change no existing field, so the
/// version stays `2`. [`Request::ReplaceBinary`] keeps its fields but now
/// installs only the monitor's own stage, so a worker that does not stage
/// first is refused: it fails closed.
///
/// [`Request::StartUpdate`], [`Response::UpdateStarted`] and
/// [`ProtoError::UpdateRunning`] (E16) are appended variants too; the
/// version stays `2`. E16 also retired [`Request::StageBegin`],
/// [`Request::StageUpdate`] and [`Request::ReplaceBinary`]: the monitor
/// refuses them, and they stay in the enum so no discriminant moves.
pub const PROTO_VERSION: u16 = 2;
/// Largest encoded message accepted in either direction, in bytes.
///
/// The largest legitimate payload is a configuration file, and 1 MiB is far
/// above any file `detent` manages. Enforcing it before allocation makes a
/// length header from a hostile peer harmless.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Longest release tag [`Request::StartUpdate`] carries, in bytes. Real
/// tags are about 15 (`v0.0.1-rc.2`).
pub const MAX_RELEASE_TAG_LEN: usize = 64;

/// True when `tag` is a release tag the update unit may be started for:
/// `v`, then a semver version with an optional pre-release and no build
/// metadata, at most [`MAX_RELEASE_TAG_LEN`] bytes, only `[0-9A-Za-z.-]`.
///
/// The tag becomes one argument of a fixed argv ([`Request::StartUpdate`]),
/// so the charset and the leading `v` keep out spaces, `/`, `..`, shell
/// metacharacters and a leading `-` (an option). The monitor and the runner
/// both check it.
#[must_use]
pub fn is_release_tag(tag: &str) -> bool {
    tag.len() <= MAX_RELEASE_TAG_LEN
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        && tag
            .strip_prefix('v')
            .and_then(|version| semver::Version::parse(version).ok())
            .is_some_and(|version| version.build.is_empty())
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

macro_rules! wire_id {
    ($(#[$meta:meta])* $name:ident, $repr:ty) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        #[serde(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            /// The underlying index.
            #[must_use]
            pub const fn get(self) -> $repr {
                self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

wire_id!(
    /// Index into the monitor's target table.
    TargetId,
    u16
);
wire_id!(
    /// Index into the monitor's external-check table.
    CheckId,
    u16
);
wire_id!(
    /// Index into the monitor's service-binding table.
    BindingId,
    u16
);
wire_id!(
    /// Index into the monitor's module table.
    ModuleId,
    u16
);
wire_id!(
    /// Index into the backup listing most recently produced for a module.
    BackupId,
    u32
);
wire_id!(
    /// Identifier the caller chooses for one commit-confirm cycle.
    CommitId,
    u32
);

// ---------------------------------------------------------------------------
// Wire mirrors of core types
// ---------------------------------------------------------------------------

/// What kind of filesystem object a target is.
///
/// A wire mirror of [`TargetKind`]: the core type is serialize-only and carries
/// no `Arbitrary` implementation, and the protocol must not inherit changes to
/// the core type silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// A single configuration file.
    File,
    /// A directory of drop-in fragments.
    DropInDir,
    /// A directory owned wholesale by the module.
    Directory,
}

impl From<TargetKind> for PathKind {
    fn from(kind: TargetKind) -> Self {
        match kind {
            TargetKind::File => Self::File,
            TargetKind::DropInDir => Self::DropInDir,
            TargetKind::Directory => Self::Directory,
        }
    }
}

/// What may be done to a service.
///
/// A wire mirror of [`CoreServiceAction`], for the same reasons as [`PathKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    /// Full restart.
    Restart,
    /// Reload configuration in place.
    Reload,
    /// Start a stopped service.
    Start,
    /// Stop a running service.
    Stop,
    /// Report status only; never allowed to change state.
    Status,
}

impl ServiceAction {
    /// The core action this maps to, or `None` for [`ServiceAction::Status`],
    /// which has no core counterpart because it mutates nothing.
    #[must_use]
    pub const fn to_core(self) -> Option<CoreServiceAction> {
        match self {
            Self::Restart => Some(CoreServiceAction::Restart),
            Self::Reload => Some(CoreServiceAction::Reload),
            Self::Start => Some(CoreServiceAction::Start),
            Self::Stop => Some(CoreServiceAction::Stop),
            Self::Status => None,
        }
    }
}

impl From<CoreServiceAction> for ServiceAction {
    fn from(action: CoreServiceAction) -> Self {
        match action {
            CoreServiceAction::Restart => Self::Restart,
            CoreServiceAction::Reload => Self::Reload,
            CoreServiceAction::Start => Self::Start,
            CoreServiceAction::Stop => Self::Stop,
        }
    }
}

/// Service mutation to repeat after a pending commit's files are restored.
///
/// The binding is an allow-list id, never a unit name supplied by the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct PendingService {
    /// Which service binding the action applies to.
    pub binding: BindingId,
    /// Which mutating action to replay after restoring the files.
    pub action: ServiceAction,
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Everything the worker may ask the monitor to do. Closed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum Request {
    /// First message on the channel. Any other message before it is a
    /// protocol violation.
    Hello {
        /// The worker's [`PROTO_VERSION`].
        proto: u16,
    },
    /// Read one allow-listed target and its digest.
    ReadTarget {
        /// Which target.
        target: TargetId,
    },
    /// Replace one allow-listed target atomically, with a backup.
    WriteTarget {
        /// Which target.
        target: TargetId,
        /// Optimistic-concurrency guard; `None` disables the check.
        expected_prev: Option<Sha256Digest>,
        /// New contents, at most [`MAX_FRAME`] minus framing overhead.
        bytes: Vec<u8>,
        /// Whether this write should be recorded for commit-confirm rollback.
        /// Plain writes leave `false`; the journal stays empty and an
        /// unrelated earlier write is never rolled back by a later commit (H3).
        journal: bool,
    },
    /// Run an allow-listed upstream validator against candidate bytes.
    RunCheck {
        /// Which check.
        check: CheckId,
        /// Candidate file contents, written to a temporary file by the monitor.
        bytes: Vec<u8>,
    },
    /// Act on an allow-listed service binding.
    Service {
        /// Which binding.
        binding: BindingId,
        /// What to do.
        action: ServiceAction,
    },
    /// List the backups retained for a module's targets.
    ListBackups {
        /// Which module.
        module: ModuleId,
    },
    /// Restore one entry of the listing produced by
    /// [`Request::ListBackups`].
    Restore {
        /// Which module.
        module: ModuleId,
        /// Index into that module's backup listing.
        backup: BackupId,
    },
    /// Arm the commit-confirm timer over every write made since the previous
    /// commit boundary. Only one commit may be pending at a time.
    StartConfirmTimer {
        /// Caller-chosen id, echoed by [`Request::ConfirmCommit`].
        commit: CommitId,
        /// Seconds until automatic rollback.
        timeout_s: u16,
        /// Service action to replay if the commit rolls back.
        service: Option<PendingService>,
    },
    /// Confirm a pending commit; the recorded rollback is discarded.
    ConfirmCommit {
        /// The id passed to [`Request::StartConfirmTimer`].
        commit: CommitId,
    },
    /// Start the mount units of the entries an apply added to allow-listed
    /// target `target` (`mounts`: `/etc/fstab`). The monitor refuses a
    /// target whose module declares no mounts, answers
    /// [`Response::Mounted`] with `activated: false` when `[mounts]
    /// activate_new_entries` is off, and otherwise asks the runner, which
    /// works the units out itself.
    ///
    /// It is defined unconditionally rather than behind `cfg(feature = …)` so
    /// that the discriminant numbering of this enum never depends on which
    /// features a build enabled — two peers built with different feature sets
    /// would otherwise misinterpret each other's messages.
    Mount {
        /// Which target.
        target: TargetId,
    },
    /// Was: replace the running binary with the staged release (C1-b).
    ///
    /// Retired by E16: the monitor installs no release itself and answers
    /// [`ProtoError::Unsupported`]. The CLI updater installs, in the unit
    /// [`Request::StartUpdate`] starts. Kept so no discriminant moves.
    ReplaceBinary {
        /// Release tag.
        tag: String,
        /// Length of the replacement image.
        len: u64,
        /// Digest the staged image must have.
        sha256: Sha256Digest,
    },
    /// Ask the monitor to stop serving and exit.
    Shutdown,
    /// Roll a pending commit back immediately, instead of waiting for its
    /// deadline. Semantics mirror [`Request::ConfirmCommit`], inverted: a
    /// pending commit whose id matches is taken, every recorded write is
    /// restored, and the answer is [`Response::RolledBack`]. If nothing is
    /// pending, or the id does not match — including a second call for a
    /// commit this request already rolled back, or a call after the deadline
    /// already rolled it back on its own — the answer is
    /// [`ProtoError::UnknownId`], identical to [`Request::ConfirmCommit`]'s
    /// miss.
    ///
    /// Appended after [`Request::Shutdown`] rather than grouped with
    /// [`Request::ConfirmCommit`] so every existing discriminant keeps its
    /// value; see [`PROTO_VERSION`]'s doc comment.
    RollbackCommit {
        /// The id passed to [`Request::StartConfirmTimer`].
        commit: CommitId,
    },
    /// Report whether a commit-confirm window is currently pending.
    ///
    /// Appended after [`Request::RollbackCommit`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    PendingCommit,
    /// Ask the init system to re-read its unit files after a write to a
    /// module whose descriptor sets `reload_unit_files` (`mounts`). The
    /// module is an id; the monitor refuses a module that does not declare
    /// the reload, and the platform layer chooses the command
    /// (`systemctl daemon-reload` on systemd, nothing elsewhere).
    ///
    /// Appended after [`Request::PendingCommit`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    ReloadUnitFiles {
        /// Which module was written.
        module: ModuleId,
    },
    /// Was: begin staging a release image in the monitor (C1-b).
    ///
    /// Retired by E16: the monitor installs no release itself and answers
    /// [`ProtoError::Unsupported`]. The CLI updater installs, in the unit
    /// [`Request::StartUpdate`] starts. Kept so no discriminant moves.
    ///
    /// Appended after [`Request::ReloadUnitFiles`] to preserve every
    /// existing discriminant; see [`PROTO_VERSION`]'s doc comment.
    StageBegin {
        /// Release tag, e.g. `v1.2.3`.
        tag: String,
        /// Length of the whole image.
        len: u64,
        /// Digest the whole image must have.
        sha256: Sha256Digest,
        /// The release's Sigstore bundle (`<asset>.sigstore.json`).
        bundle: Vec<u8>,
    },
    /// Was: the next piece of the image begun by [`Request::StageBegin`].
    ///
    /// Retired by E16: the monitor installs no release itself and answers
    /// [`ProtoError::Unsupported`]. The CLI updater installs, in the unit
    /// [`Request::StartUpdate`] starts. Kept so no discriminant moves.
    ///
    /// Appended after [`Request::StageBegin`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    StageUpdate {
        /// Where `chunk` starts in the image.
        offset: u64,
        /// The bytes.
        chunk: Vec<u8>,
    },
    /// Start the CLI updater for release `tag` outside detent's own
    /// service (BUGFIX E16): the runner runs `systemd-run
    /// --unit=detent-update --collect <installed detent> update --tag
    /// <tag>`. The argv is fixed in the runner; only `tag` varies, and the
    /// monitor and the runner both refuse a tag that fails
    /// [`is_release_tag`]. The monitor also refuses a tag that is not newer
    /// than the running version. The answer is
    /// [`Response::UpdateStarted`] as soon as the unit runs: the download,
    /// verification, swap, restart, `/healthz` check and rollback happen in
    /// the unit, and the result is the running version afterwards.
    /// [`ProtoError::UpdateRunning`] when the unit is already there;
    /// [`ProtoError::Unavailable`] on a host without systemd.
    ///
    /// Appended after [`Request::StageUpdate`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    StartUpdate {
        /// Release tag, e.g. `v1.2.3`.
        tag: String,
    },
}

impl Request {
    /// True when serving this request can change state on disk or on the host.
    ///
    /// A monitor without the state lock refuses these. The match is
    /// exhaustive on purpose: a new request must be classified here.
    /// [`Request::Mount`] counts as a change: it may start mount units.
    #[must_use]
    pub const fn changes_state(&self) -> bool {
        match self {
            Self::WriteTarget { .. }
            | Self::Restore { .. }
            | Self::StartConfirmTimer { .. }
            | Self::ConfirmCommit { .. }
            | Self::RollbackCommit { .. }
            | Self::Mount { .. }
            | Self::ReplaceBinary { .. }
            | Self::ReloadUnitFiles { .. }
            | Self::StageBegin { .. }
            | Self::StageUpdate { .. }
            | Self::StartUpdate { .. } => true,
            Self::Service { action, .. } => !matches!(action, ServiceAction::Status),
            Self::Hello { .. }
            | Self::ReadTarget { .. }
            | Self::RunCheck { .. }
            | Self::ListBackups { .. }
            | Self::PendingCommit
            | Self::Shutdown => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// One target as advertised in [`HelloAck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct TargetInfo {
    /// The id to use in requests.
    pub id: TargetId,
    /// The module that owns it.
    pub module: ModuleId,
    /// Absolute path, for display and for the worker to correlate a model with
    /// a file. Never accepted *from* the worker.
    pub path: String,
    /// File, drop-in directory, or directory.
    pub kind: PathKind,
}

/// One external check as advertised in [`HelloAck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct CheckInfo {
    /// The id to use in requests.
    pub id: CheckId,
    /// The module that owns it.
    pub module: ModuleId,
    /// Absolute path of the validator, for display in `detent doctor`.
    pub program: String,
}

/// One service binding as advertised in [`HelloAck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct BindingInfo {
    /// The id to use in requests.
    pub id: BindingId,
    /// The module that owns it.
    pub module: ModuleId,
    /// Preferred unit name for the host's init system, for display.
    pub unit: String,
    /// Actions the module declared, in preference order.
    pub actions: Vec<ServiceAction>,
}

/// One module as advertised in [`HelloAck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct ModuleInfo {
    /// The id to use in requests.
    pub id: ModuleId,
    /// Stable module id, e.g. `hosts`.
    pub name: String,
    /// Whether changes to this module need commit-confirm.
    pub commit_confirm: bool,
}

/// The monitor's answer to [`Request::Hello`]: the complete set of ids the
/// worker is allowed to name for the lifetime of the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct HelloAck {
    /// The monitor's [`PROTO_VERSION`].
    pub proto: u16,
    /// Modules the monitor was built with and the config enabled.
    pub modules: Vec<ModuleInfo>,
    /// Every writable target.
    pub targets: Vec<TargetInfo>,
    /// Every runnable validator.
    pub checks: Vec<CheckInfo>,
    /// Every controllable service.
    pub bindings: Vec<BindingInfo>,
}

/// Contents of a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct TargetContents {
    /// Which target this is.
    pub target: TargetId,
    /// Its current contents.
    pub bytes: Vec<u8>,
    /// Digest of `bytes`, for use as the next `expected_prev`.
    pub digest: Sha256Digest,
}

/// Result of a successful [`Request::WriteTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct WriteReceipt {
    /// Which target was written.
    pub target: TargetId,
    /// Digest of the replaced contents, `None` when the file was created.
    pub prev_digest: Option<Sha256Digest>,
    /// Digest now on disk.
    pub new_digest: Sha256Digest,
    /// True when the target did not exist before.
    pub created: bool,
    /// True when a backup was written and is therefore available to roll back
    /// to under commit-confirm.
    pub backed_up: bool,
    /// False when the monitor is not root and could not restore the previous
    /// owner. Mode and extended attributes are still preserved.
    pub owner_preserved: bool,
}

/// One retained backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BackupInfo {
    /// Index into this listing, for [`Request::Restore`].
    pub id: BackupId,
    /// Which target the backup came from.
    pub target: TargetId,
    /// File name of the backup within the module's backup directory. The
    /// directory itself is never disclosed.
    pub name: String,
    /// Modification time, seconds since the Unix epoch.
    pub created_unix_s: u64,
    /// Digest of the backed-up contents.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub len: u64,
}

/// Result of a [`Request::RunCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct CheckOutcome {
    /// Which check ran.
    pub check: CheckId,
    /// Whether the declared expectation was met.
    pub passed: bool,
    /// Exit status, when the program was actually executed.
    pub exit_code: Option<i32>,
    /// A bounded excerpt of the validator's output, for the UI.
    pub detail: String,
}

/// Result of a [`Request::Service`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct ServiceOutcome {
    /// Which binding was acted on.
    pub binding: BindingId,
    /// Whether the unit is running after the action.
    pub active: bool,
    /// A short human-readable status string.
    pub detail: String,
}

/// What happened to one mount unit after a `mounts` apply, or at a
/// rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum MountState {
    /// Started, and mounted now.
    Mounted,
    /// Already mounted before the apply: not started, and not stopped by a
    /// rollback.
    AlreadyMounted,
    /// Started; the job had not finished when the wait ended (for example
    /// a network share). It goes on in the init system.
    Pending,
    /// The start or the stop failed.
    Failed,
    /// Refused: `/`, or an ancestor of `/etc`, `/usr`, `/boot`, the state
    /// root or the binary's directory. Never started.
    Protected,
    /// Stopped by a rollback.
    Stopped,
}

/// One mount unit and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct MountOutcome {
    /// The fstab entry's mount point.
    pub mountpoint: String,
    /// The unit, as `systemd-fstab-generator` names it.
    pub unit: String,
    /// What happened.
    pub state: MountState,
    /// The init system's message for a failure, or empty.
    pub detail: String,
}

/// Everything the monitor may answer. Closed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum Response {
    /// Answer to [`Request::Hello`].
    HelloAck(HelloAck),
    /// Answer to [`Request::ReadTarget`].
    Target(TargetContents),
    /// Answer to [`Request::WriteTarget`].
    Written(WriteReceipt),
    /// Answer to [`Request::RunCheck`].
    Checked(CheckOutcome),
    /// Answer to [`Request::Service`].
    Serviced(ServiceOutcome),
    /// Answer to [`Request::ListBackups`].
    Backups(Vec<BackupInfo>),
    /// Answer to [`Request::Restore`].
    Restored {
        /// Digest now on disk at the restored target.
        target: TargetId,
        /// Digest now on disk.
        new_digest: Sha256Digest,
    },
    /// Answer to [`Request::StartConfirmTimer`].
    ConfirmTimerStarted {
        /// The armed commit.
        commit: CommitId,
        /// Seconds until rollback, as the monitor clamped them.
        timeout_s: u16,
        /// How many targets will be rolled back if it expires.
        rollback_targets: u16,
    },
    /// Answer to [`Request::ConfirmCommit`].
    Committed {
        /// The commit that is now final.
        commit: CommitId,
    },
    /// Answer to [`Request::Shutdown`]; the monitor exits after sending it.
    ShuttingDown,
    /// Any request may fail this way. Exactly one response is sent per
    /// request, so an error never desynchronizes the channel.
    Error(ProtoError),
    /// Answer to [`Request::RollbackCommit`].
    ///
    /// Appended after [`Response::Error`] for the same discriminant-
    /// stability reason as [`Request::RollbackCommit`]; see
    /// [`PROTO_VERSION`]'s doc comment.
    RolledBack {
        /// The commit that was rolled back.
        commit: CommitId,
        /// How many targets were actually restored.
        restored: u16,
    },
    /// Was the answer to [`Request::ReplaceBinary`]; no monitor sends it
    /// since E16. Kept so no discriminant moves.
    ///
    /// Appended after [`Response::RolledBack`] so every prior discriminant
    /// keeps its value.
    Replaced {
        /// The version that was installed (hex sha256 of the staged image).
        version: String,
    },
    /// Answer to [`Request::PendingCommit`].
    ///
    /// `Some` is the armed commit id; `None` means no commit is pending.
    /// Appended after [`Response::Replaced`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    Pending(Option<CommitId>),
    /// Answer to [`Request::ReloadUnitFiles`].
    ///
    /// Appended after [`Response::Pending`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    UnitFilesReloaded {
        /// A short human-readable result.
        detail: String,
    },
    /// Answer to [`Request::Mount`].
    ///
    /// Appended after [`Response::UnitFilesReloaded`] to preserve every
    /// existing discriminant; see [`PROTO_VERSION`]'s doc comment.
    Mounted {
        /// False when `[mounts] activate_new_entries` is off: nothing was
        /// started, and `units` is empty.
        activated: bool,
        /// What happened to each unit of an added or changed entry.
        units: Vec<MountOutcome>,
    },
    /// Was the answer to [`Request::StageBegin`] and
    /// [`Request::StageUpdate`]; no monitor sends it since E16. Kept so no
    /// discriminant moves.
    ///
    /// Appended after [`Response::Mounted`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    Staged {
        /// Bytes of the image the monitor holds now; the next chunk's
        /// `offset`.
        received: u64,
    },
    /// Answer to [`Request::StartUpdate`]: the update unit runs. It says
    /// nothing about the outcome of the update.
    ///
    /// Appended after [`Response::Staged`] to preserve every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    UpdateStarted {
        /// A short human-readable result.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure the monitor reports to the worker.
///
/// Deliberately coarse: it must never leak a path, a program name, or an OS
/// error string that embeds one, because the worker is the untrusted side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum ProtoError {
    /// The peer speaks a different protocol version.
    #[error("protocol version mismatch: monitor speaks {expected}, worker speaks {got}")]
    VersionMismatch {
        /// The monitor's version.
        expected: u16,
        /// The version the worker announced.
        got: u16,
    },
    /// A message other than `Hello` arrived first, or `Hello` arrived twice.
    #[error("handshake required before any other request")]
    HandshakeRequired,
    /// An id was outside its allow-list table.
    #[error("unknown {kind} id {id}")]
    UnknownId {
        /// Which table was indexed.
        kind: IdKind,
        /// The rejected index.
        id: u32,
    },
    /// The module declared no such action for that binding.
    #[error("service action is not allowed for this binding")]
    ActionNotAllowed,
    /// The target changed on disk since the worker last read it.
    #[error("target changed on disk since it was read")]
    Conflict {
        /// What the worker expected.
        expected: Sha256Digest,
        /// What was actually there, `None` when the file is gone.
        actual: Option<Sha256Digest>,
    },
    /// A commit is already pending; only one is allowed at a time.
    #[error("commit {0} is already pending")]
    CommitPending(CommitId),
    /// A commit-confirm deadline passed; its changes were rolled back.
    #[error("commit {0} confirmation window expired")]
    CommitExpired(CommitId),
    /// The functionality exists in the protocol but is not built or not wired
    /// up in this binary.
    #[error("unsupported request: {0}")]
    Unsupported(String),
    /// The monitor could not perform the request because a collaborator (an
    /// external validator, a service manager) is absent.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// A syscall failed. The message is a short summary with no path in it.
    #[error("i/o error: {0}")]
    Io(String),
    /// The staged release failed authenticity verification. No monitor
    /// sends it since E16 retired `ReplaceBinary`; kept so no discriminant
    /// moves.
    #[error("staged release verification failed")]
    VerificationFailed,
    /// The allow-listed target does not exist. The worker already knows the
    /// target by id, so this reveals no path.
    #[error("target does not exist")]
    NotFound,
    /// The monitor does not hold the state lock, so it refuses every request
    /// that changes state. Reads still work.
    ///
    /// Appended after [`ProtoError::NotFound`] to keep every existing
    /// discriminant; see [`PROTO_VERSION`]'s doc comment.
    #[error("the monitor does not hold the state lock; state changes are refused")]
    StateLockUnavailable,
    /// [`Request::StartUpdate`] was refused because the update unit is
    /// already running.
    ///
    /// Appended after [`ProtoError::StateLockUnavailable`] to keep every
    /// existing discriminant; see [`PROTO_VERSION`]'s doc comment.
    #[error("an update is already running")]
    UpdateRunning,
}

/// Which allow-list table an [`ProtoError::UnknownId`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum IdKind {
    /// The target table.
    Target,
    /// The external-check table.
    Check,
    /// The service-binding table.
    Binding,
    /// The module table.
    Module,
    /// A module's backup listing.
    Backup,
    /// The pending commit.
    Commit,
}

impl core::fmt::Display for IdKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Target => "target",
            Self::Check => "check",
            Self::Binding => "binding",
            Self::Module => "module",
            Self::Backup => "backup",
            Self::Commit => "commit",
        };
        f.write_str(name)
    }
}

/// A failure to turn bytes into a message or back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The frame is larger than [`MAX_FRAME`]. Reported before allocating.
    #[error("frame of {len} bytes exceeds the {MAX_FRAME} byte limit")]
    Oversize {
        /// The advertised or actual length.
        len: usize,
    },
    /// The bytes are not a valid encoding of the expected message: a truncated
    /// frame, trailing garbage, or an enum discriminant this build does not
    /// know.
    #[error("malformed message: {0}")]
    Malformed(String),
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Encode a message.
///
/// # Errors
///
/// [`CodecError::Oversize`] when the encoding exceeds [`MAX_FRAME`], so an
/// over-large payload is rejected by the *sender* too, and
/// [`CodecError::Malformed`] if `postcard` cannot represent the value.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|err| CodecError::Malformed(err.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(CodecError::Oversize { len: bytes.len() });
    }
    Ok(bytes)
}

/// Decode a message from a complete frame.
///
/// The length check happens first and looks only at the slice that was already
/// received, so a hostile length header cannot make this function allocate.
/// This function never panics for any input; `fuzz_privsep_decode` asserts it.
///
/// `postcard::from_bytes` silently ignores any bytes left over after a
/// complete value, which would let a peer append arbitrary data to an
/// otherwise-valid frame. This function uses `take_from_bytes` instead and
/// rejects a non-empty remainder, so a frame either decodes exactly or not at
/// all.
///
/// # Errors
///
/// [`CodecError::Oversize`] when `bytes` is longer than [`MAX_FRAME`], and
/// [`CodecError::Malformed`] for a truncated frame, trailing bytes, or an
/// unknown enum discriminant.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    if bytes.len() > MAX_FRAME {
        return Err(CodecError::Oversize { len: bytes.len() });
    }
    let (value, remainder) =
        postcard::take_from_bytes(bytes).map_err(|err| CodecError::Malformed(err.to_string()))?;
    if !remainder.is_empty() {
        return Err(CodecError::Malformed(format!(
            "{} trailing byte(s) after a complete message",
            remainder.len()
        )));
    }
    Ok(value)
}

#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for Sha256Digest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Every 32-byte digest is a valid `Sha256Digest`, and hashing whatever
        // bytes the fuzzer offers is the cheapest way to get one without
        // reaching into the type's private field from another module.
        let seed = <Vec<u8> as arbitrary::Arbitrary>::arbitrary(u)?;
        Ok(Self::of(&seed))
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <Vec<u8> as arbitrary::Arbitrary>::size_hint(depth)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BackupId, BackupInfo, BindingId, BindingInfo, CheckId, CheckInfo, CheckOutcome, CodecError,
        CommitId, HelloAck, IdKind, MAX_FRAME, MAX_RELEASE_TAG_LEN, ModuleId, ModuleInfo,
        MountOutcome, MountState, PROTO_VERSION, PathKind, PendingService, ProtoError, Request,
        Response, ServiceAction, ServiceOutcome, TargetContents, TargetId, TargetInfo,
        WriteReceipt, decode, encode, is_release_tag,
    };
    use crate::fs::atomic::Sha256Digest;
    use detent_core::descriptor::{ServiceAction as CoreServiceAction, TargetKind};

    fn digest() -> Sha256Digest {
        Sha256Digest::of(b"127.0.0.1 localhost\n")
    }

    fn every_request() -> Vec<Request> {
        vec![
            Request::Hello {
                proto: PROTO_VERSION,
            },
            Request::ReadTarget {
                target: TargetId(0),
            },
            Request::WriteTarget {
                target: TargetId(7),
                expected_prev: Some(digest()),
                bytes: b"new contents".to_vec(),
                journal: false,
            },
            Request::WriteTarget {
                target: TargetId(7),
                expected_prev: None,
                bytes: Vec::new(),
                journal: false,
            },
            Request::RunCheck {
                check: CheckId(1),
                bytes: vec![0_u8; 64],
            },
            Request::Service {
                binding: BindingId(2),
                action: ServiceAction::Restart,
            },
            Request::Service {
                binding: BindingId(2),
                action: ServiceAction::Status,
            },
            Request::ListBackups {
                module: ModuleId(3),
            },
            Request::Restore {
                module: ModuleId(3),
                backup: BackupId(9),
            },
            Request::StartConfirmTimer {
                commit: CommitId(11),
                timeout_s: 90,
                service: Some(PendingService {
                    binding: BindingId(2),
                    action: ServiceAction::Reload,
                }),
            },
            Request::ConfirmCommit {
                commit: CommitId(11),
            },
            Request::Mount {
                target: TargetId(4),
            },
            Request::ReplaceBinary {
                tag: "v1.2.3".to_owned(),
                len: 4_096,
                sha256: digest(),
            },
            Request::Shutdown,
            Request::RollbackCommit {
                commit: CommitId(11),
            },
            Request::PendingCommit,
            Request::ReloadUnitFiles {
                module: ModuleId(2),
            },
            Request::StageBegin {
                tag: "v1.2.3".to_owned(),
                len: 4_096,
                sha256: digest(),
                bundle: b"{}".to_vec(),
            },
            Request::StageUpdate {
                offset: 512,
                chunk: vec![7_u8; 64],
            },
            Request::StartUpdate {
                tag: "v1.2.3".to_owned(),
            },
        ]
    }

    fn hello_ack() -> Response {
        Response::HelloAck(HelloAck {
            proto: PROTO_VERSION,
            modules: vec![ModuleInfo {
                id: ModuleId(0),
                name: "hosts".to_owned(),
                commit_confirm: false,
            }],
            targets: vec![TargetInfo {
                id: TargetId(0),
                module: ModuleId(0),
                path: "/etc/hosts".to_owned(),
                kind: PathKind::File,
            }],
            checks: vec![CheckInfo {
                id: CheckId(0),
                module: ModuleId(0),
                program: "/usr/sbin/chronyd".to_owned(),
            }],
            bindings: vec![BindingInfo {
                id: BindingId(0),
                module: ModuleId(0),
                unit: "chronyd.service".to_owned(),
                actions: vec![ServiceAction::Restart, ServiceAction::Reload],
            }],
        })
    }

    fn every_error_response() -> Vec<Response> {
        vec![
            Response::Error(ProtoError::VersionMismatch {
                expected: 1,
                got: 9,
            }),
            Response::Error(ProtoError::HandshakeRequired),
            Response::Error(ProtoError::UnknownId {
                kind: IdKind::Target,
                id: 42,
            }),
            Response::Error(ProtoError::ActionNotAllowed),
            Response::Error(ProtoError::Conflict {
                expected: digest(),
                actual: None,
            }),
            Response::Error(ProtoError::Conflict {
                expected: digest(),
                actual: Some(digest()),
            }),
            Response::Error(ProtoError::CommitPending(CommitId(3))),
            Response::Error(ProtoError::CommitExpired(CommitId(4))),
            Response::Error(ProtoError::Unsupported("mount".to_owned())),
            Response::Error(ProtoError::Unavailable("no service manager".to_owned())),
            Response::Error(ProtoError::Io("openat failed".to_owned())),
            Response::Error(ProtoError::NotFound),
            Response::Error(ProtoError::StateLockUnavailable),
            Response::Error(ProtoError::UpdateRunning),
        ]
    }

    fn every_response() -> Vec<Response> {
        let mut responses = vec![
            hello_ack(),
            Response::Target(TargetContents {
                target: TargetId(0),
                bytes: b"127.0.0.1 localhost\n".to_vec(),
                digest: digest(),
            }),
            Response::Written(WriteReceipt {
                target: TargetId(0),
                prev_digest: Some(digest()),
                new_digest: digest(),
                created: false,
                backed_up: true,
                owner_preserved: true,
            }),
            Response::Checked(CheckOutcome {
                check: CheckId(0),
                passed: true,
                exit_code: Some(0),
                detail: "ok".to_owned(),
            }),
            Response::Serviced(ServiceOutcome {
                binding: BindingId(0),
                active: true,
                detail: "running".to_owned(),
            }),
            Response::Backups(vec![BackupInfo {
                id: BackupId(0),
                target: TargetId(0),
                name: "2026-09-03T00:00:00Z-deadbeef".to_owned(),
                created_unix_s: 1_788_000_000,
                digest: digest(),
                len: 20,
            }]),
            Response::Backups(Vec::new()),
            Response::Restored {
                target: TargetId(0),
                new_digest: digest(),
            },
            Response::ConfirmTimerStarted {
                commit: CommitId(1),
                timeout_s: 90,
                rollback_targets: 2,
            },
            Response::Committed {
                commit: CommitId(1),
            },
            Response::ShuttingDown,
            Response::RolledBack {
                commit: CommitId(1),
                restored: 2,
            },
            Response::Pending(Some(CommitId(3))),
            Response::Pending(None),
            Response::UnitFilesReloaded {
                detail: "systemctl daemon-reload succeeded".to_owned(),
            },
            Response::Mounted {
                activated: true,
                units: vec![MountOutcome {
                    mountpoint: "/srv".to_owned(),
                    unit: "srv.mount".to_owned(),
                    state: MountState::Pending,
                    detail: "systemctl start timed out".to_owned(),
                }],
            },
            Response::Staged { received: 512 },
            Response::UpdateStarted {
                detail: "started detent-update.service".to_owned(),
            },
        ];
        responses.extend(every_error_response());
        responses
    }

    #[test]
    fn every_request_variant_round_trips() {
        for request in every_request() {
            let bytes = encode(&request).unwrap_or_default();
            assert!(!bytes.is_empty(), "{request:?} encoded to nothing");
            assert_eq!(decode::<Request>(&bytes).ok(), Some(request.clone()));
            assert!(!format!("{request:?}").is_empty());
        }
    }

    #[test]
    fn every_response_variant_round_trips() {
        for response in every_response() {
            let bytes = encode(&response).unwrap_or_default();
            assert_eq!(decode::<Response>(&bytes).ok(), Some(response.clone()));
            // Error variants must render without panicking and must not be
            // empty, since they reach the UI.
            if let Response::Error(err) = &response {
                assert!(!err.to_string().is_empty());
            }
        }
    }

    #[test]
    fn ids_display_and_expose_their_index() {
        assert_eq!(TargetId(3).get(), 3);
        assert_eq!(CheckId(3).to_string(), "3");
        assert_eq!(BindingId(4).get(), 4);
        assert_eq!(ModuleId(5).to_string(), "5");
        assert_eq!(BackupId(6).get(), 6);
        assert_eq!(CommitId(7).to_string(), "7");
        assert!(TargetId(1) < TargetId(2));
        assert_eq!(IdKind::Target.to_string(), "target");
        assert_eq!(IdKind::Check.to_string(), "check");
        assert_eq!(IdKind::Binding.to_string(), "binding");
        assert_eq!(IdKind::Module.to_string(), "module");
        assert_eq!(IdKind::Backup.to_string(), "backup");
        assert_eq!(IdKind::Commit.to_string(), "commit");
    }

    #[test]
    fn wire_mirrors_match_the_core_types() {
        assert_eq!(PathKind::from(TargetKind::File), PathKind::File);
        assert_eq!(PathKind::from(TargetKind::DropInDir), PathKind::DropInDir);
        assert_eq!(PathKind::from(TargetKind::Directory), PathKind::Directory);
        for (core, wire) in [
            (CoreServiceAction::Restart, ServiceAction::Restart),
            (CoreServiceAction::Reload, ServiceAction::Reload),
            (CoreServiceAction::Start, ServiceAction::Start),
            (CoreServiceAction::Stop, ServiceAction::Stop),
        ] {
            assert_eq!(ServiceAction::from(core), wire);
            assert_eq!(wire.to_core(), Some(core));
        }
        assert_eq!(ServiceAction::Status.to_core(), None);
    }

    #[test]
    fn oversize_frames_are_rejected_before_allocating() {
        let huge = vec![0_u8; MAX_FRAME + 1];
        assert_eq!(
            decode::<Request>(&huge),
            Err(CodecError::Oversize { len: MAX_FRAME + 1 })
        );
        let oversize = Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: vec![0_u8; MAX_FRAME + 1],
            journal: false,
        };
        assert!(matches!(
            encode(&oversize),
            Err(CodecError::Oversize { .. })
        ));
        assert!(
            CodecError::Oversize { len: 9 }
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn truncated_and_unknown_frames_are_rejected() {
        let bytes = encode(&Request::WriteTarget {
            target: TargetId(1),
            expected_prev: None,
            bytes: b"abc".to_vec(),
            journal: false,
        })
        .unwrap_or_default();
        for cut in 0..bytes.len() {
            let head = bytes.get(..cut).unwrap_or_default();
            // A prefix must either fail or decode to something else; it must
            // never panic and never yield the original message.
            if let Ok(decoded) = decode::<Request>(head) {
                assert_ne!(
                    decoded,
                    Request::WriteTarget {
                        target: TargetId(1),
                        expected_prev: None,
                        bytes: b"abc".to_vec(),
                        journal: false,
                    }
                );
            }
        }
        // Discriminant 250 is far outside the closed request set.
        let unknown = decode::<Request>(&[250, 0, 0, 0]);
        assert!(matches!(unknown, Err(CodecError::Malformed(_))));
        assert!(decode::<Request>(&[]).is_err());
        assert!(
            CodecError::Malformed("x".to_owned())
                .to_string()
                .contains('x')
        );
    }

    #[test]
    fn rollback_commit_and_rolled_back_are_the_new_terminal_discriminants() {
        // `Request::RollbackCommit` and `Response::RolledBack` were appended
        // after every previously-existing variant precisely so no existing
        // discriminant moved; assert the byte postcard actually assigned
        // them (12 and 11 respectively — zero-based, after 12 and 11 prior
        // variants) so a future reordering that silently renumbers them
        // fails here instead of only on the wire.
        let request = Request::RollbackCommit {
            commit: CommitId(42),
        };
        let request_bytes = encode(&request).unwrap_or_default();
        assert_eq!(request_bytes.first(), Some(&12));
        assert_eq!(decode::<Request>(&request_bytes).ok(), Some(request));

        let response = Response::RolledBack {
            commit: CommitId(42),
            restored: 3,
        };
        let response_bytes = encode(&response).unwrap_or_default();
        assert_eq!(response_bytes.first(), Some(&11));
        assert_eq!(decode::<Response>(&response_bytes).ok(), Some(response));

        let pending = Request::PendingCommit;
        let pending_bytes = encode(&pending).unwrap_or_default();
        assert_eq!(pending_bytes.first(), Some(&13));
        assert_eq!(decode::<Request>(&pending_bytes).ok(), Some(pending));

        let pending = Response::Pending(Some(CommitId(42)));
        let pending_bytes = encode(&pending).unwrap_or_default();
        assert_eq!(pending_bytes.first(), Some(&13));
        assert_eq!(decode::<Response>(&pending_bytes).ok(), Some(pending));

        // No other `Request` variant's encoding decodes as `RollbackCommit`,
        // and vice versa: every prior request either fails to decode as
        // `RollbackCommit` or, if it happens to be `RollbackCommit` itself
        // with different contents, is simply unequal.
        let rollback_for_other_commit = Request::RollbackCommit {
            commit: CommitId(1),
        };
        for other in every_request() {
            if other == rollback_for_other_commit {
                continue;
            }
            let bytes = encode(&other).unwrap_or_default();
            assert_ne!(
                decode::<Request>(&bytes).ok(),
                Some(rollback_for_other_commit.clone())
            );
        }
    }

    #[test]
    fn reload_unit_files_takes_the_next_discriminants() {
        // Appended after `PendingCommit` and `Pending`: no existing
        // discriminant moves.
        let request = Request::ReloadUnitFiles {
            module: ModuleId(3),
        };
        let bytes = encode(&request).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&14));
        assert_eq!(decode::<Request>(&bytes).ok(), Some(request));

        let response = Response::UnitFilesReloaded {
            detail: "ok".to_owned(),
        };
        let bytes = encode(&response).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&14));
        assert_eq!(decode::<Response>(&bytes).ok(), Some(response));
    }

    #[test]
    fn mounted_takes_the_next_response_discriminant() {
        // Appended after `UnitFilesReloaded`: no existing discriminant moves.
        let response = Response::Mounted {
            activated: false,
            units: Vec::new(),
        };
        let bytes = encode(&response).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&15));
        assert_eq!(decode::<Response>(&bytes).ok(), Some(response));
    }

    #[test]
    fn the_stage_requests_take_the_next_discriminants() {
        // Appended after `ReloadUnitFiles` and `Mounted`: no existing
        // discriminant moves.
        let begin = Request::StageBegin {
            tag: "v1.2.3".to_owned(),
            len: 1,
            sha256: digest(),
            bundle: Vec::new(),
        };
        let bytes = encode(&begin).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&15));
        assert_eq!(decode::<Request>(&bytes).ok(), Some(begin));

        let chunk = Request::StageUpdate {
            offset: 0,
            chunk: vec![1],
        };
        let bytes = encode(&chunk).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&16));
        assert_eq!(decode::<Request>(&bytes).ok(), Some(chunk));

        let staged = Response::Staged { received: 1 };
        let bytes = encode(&staged).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&16));
        assert_eq!(decode::<Response>(&bytes).ok(), Some(staged));
    }

    #[test]
    fn start_update_takes_the_next_discriminants() {
        // Appended after `StageUpdate`, `Staged` and `StateLockUnavailable`:
        // no existing discriminant moves.
        let start = Request::StartUpdate {
            tag: "v1.2.3".to_owned(),
        };
        let bytes = encode(&start).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&17));
        assert_eq!(decode::<Request>(&bytes).ok(), Some(start));

        let started = Response::UpdateStarted {
            detail: String::new(),
        };
        let bytes = encode(&started).unwrap_or_default();
        assert_eq!(bytes.first(), Some(&17));
        assert_eq!(decode::<Response>(&bytes).ok(), Some(started));

        let running = Response::Error(ProtoError::UpdateRunning);
        let bytes = encode(&running).unwrap_or_default();
        // `Response::Error` is discriminant 10, `UpdateRunning` the 14th error.
        assert_eq!(bytes.as_slice(), &[10, 13]);
        assert_eq!(decode::<Response>(&bytes).ok(), Some(running));
    }

    #[test]
    fn release_tags_are_v_and_semver_and_nothing_else() {
        for good in [
            "v0.0.1",
            "v1.2.3",
            "v0.0.1-rc.2",
            "v0.1.1-test",
            "v10.20.30-alpha.1.beta-2",
        ] {
            assert!(is_release_tag(good), "{good:?} must be accepted");
        }
        let overlong = format!("v1.2.3-{}", "a".repeat(MAX_RELEASE_TAG_LEN));
        for bad in [
            "",
            "v",
            "1.2.3",
            "-x",
            "--help",
            "v1.2",
            "v1.2.3 ",
            " v1.2.3",
            "v1.2.3 --allow-downgrade",
            "v1.2.3\n",
            "v1..2.3",
            "v1.2.3-..",
            "v1.2.3/../x",
            "/usr/bin/x",
            "v1.2.3+build.1",
            "v01.2.3",
            "v1.2.3;reboot",
            "v1.2.3$(reboot)",
            "v1.2.3`id`",
            "v1.2.3|x",
            "v1.2.3&",
            "V1.2.3",
            overlong.as_str(),
        ] {
            assert!(!is_release_tag(bad), "{bad:?} must be refused");
        }
        let longest = format!("v1.2.3-{}", "a".repeat(MAX_RELEASE_TAG_LEN - 7));
        assert_eq!(longest.len(), MAX_RELEASE_TAG_LEN);
        assert!(is_release_tag(&longest));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encode(&Request::Shutdown).unwrap_or_default();
        bytes.push(0xff);
        assert!(matches!(
            decode::<Request>(&bytes),
            Err(CodecError::Malformed(_))
        ));
    }

    #[test]
    fn digests_survive_the_wire_unchanged() {
        let request = Request::WriteTarget {
            target: TargetId(0),
            expected_prev: Some(digest()),
            bytes: Vec::new(),
            journal: false,
        };
        let bytes = encode(&request).unwrap_or_default();
        let back = match decode::<Request>(&bytes) {
            Ok(Request::WriteTarget { expected_prev, .. }) => expected_prev,
            _ => None,
        };
        assert_eq!(back, Some(digest()));
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn sha256_digest_is_arbitrary_from_any_bytes() {
        use arbitrary::{Arbitrary as _, Unstructured};

        // Every byte string is a valid seed: `Sha256Digest`'s `Arbitrary` impl
        // hashes whatever it is given rather than rejecting anything, and
        // `size_hint` just forwards to `Vec<u8>`'s.
        let bytes = [1_u8, 2, 3, 4, 5];
        let mut unstructured = Unstructured::new(&bytes);
        let digest = Sha256Digest::arbitrary(&mut unstructured);
        assert!(digest.is_ok());
        assert_eq!(
            Sha256Digest::size_hint(0),
            <Vec<u8> as arbitrary::Arbitrary>::size_hint(0)
        );
    }
}
