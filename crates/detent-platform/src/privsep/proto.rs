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
/// [`Request::RollbackCommit`] and [`Response::RolledBack`] were added at the
/// end of their enums (see each variant's doc comment) rather than grouped
/// next to [`Request::ConfirmCommit`]/[`Response::Committed`], so every
/// existing discriminant keeps its numeric value. That is a backward-
/// incompatible change in exactly one direction: an *old* binary decoding a
/// frame a *new* binary sent would meet an out-of-range discriminant and
/// correctly terminate the connection per this module's closed-enum
/// invariant (see the module docs) — it would not misinterpret the message
/// as something else. The reverse direction is unaffected, because an old
/// peer never emits a discriminant a new peer does not know.
///
/// This build does **not** bump `PROTO_VERSION` for the addition, because
/// that failure mode cannot occur in practice yet: `spawn_pair` forks the
/// worker from the monitor's own already-running image, so the two ends of
/// one connection are always the same binary, and the one feature that could
/// introduce a mismatched pair — replacing the running binary underneath a
/// live monitor — is `Request::ReplaceBinary`, which this build still
/// answers `ProtoError::Unsupported`. When binary replacement lands, that
/// change is the right place to decide whether an in-flight connection needs
/// draining before the swap and whether a version bump is warranted then;
/// bumping it now would not protect anything, because there is no path to
/// pairing two different binaries yet.
pub const PROTO_VERSION: u16 = 1;

/// Largest encoded message accepted in either direction, in bytes.
///
/// The largest legitimate payload is a configuration file, and 1 MiB is far
/// above any file `detent` manages. Enforcing it before allocation makes a
/// length header from a hostile peer harmless.
pub const MAX_FRAME: usize = 1024 * 1024;

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
    },
    /// Confirm a pending commit; the recorded rollback is discarded.
    ConfirmCommit {
        /// The id passed to [`Request::StartConfirmTimer`].
        commit: CommitId,
    },
    /// Mount an allow-listed target. Reserved for the `module-mounts` feature;
    /// the monitor answers [`ProtoError::Unsupported`] until that lands.
    ///
    /// It is defined unconditionally rather than behind `cfg(feature = …)` so
    /// that the discriminant numbering of this enum never depends on which
    /// features a build enabled — two peers built with different feature sets
    /// would otherwise misinterpret each other's messages.
    Mount {
        /// Which target.
        target: TargetId,
    },
    /// Replace the running binary. Reserved for the `update` feature; answered
    /// with [`ProtoError::Unsupported`] for now, and defined unconditionally
    /// for the same discriminant-stability reason as [`Request::Mount`].
    ReplaceBinary {
        /// Length of the replacement image, streamed separately.
        len: u64,
        /// Digest the streamed image must have.
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
        CommitId, HelloAck, IdKind, MAX_FRAME, ModuleId, ModuleInfo, PROTO_VERSION, PathKind,
        ProtoError, Request, Response, ServiceAction, ServiceOutcome, TargetContents, TargetId,
        TargetInfo, WriteReceipt, decode, encode,
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
            },
            Request::WriteTarget {
                target: TargetId(7),
                expected_prev: None,
                bytes: Vec::new(),
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
            },
            Request::ConfirmCommit {
                commit: CommitId(11),
            },
            Request::Mount {
                target: TargetId(4),
            },
            Request::ReplaceBinary {
                len: 4_096,
                sha256: digest(),
            },
            Request::Shutdown,
            Request::RollbackCommit {
                commit: CommitId(11),
            },
        ]
    }

    fn every_response() -> Vec<Response> {
        vec![
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
            }),
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
            Response::Error(ProtoError::Unsupported("mount".to_owned())),
            Response::Error(ProtoError::Unavailable("no service manager".to_owned())),
            Response::Error(ProtoError::Io("openat failed".to_owned())),
            Response::RolledBack {
                commit: CommitId(1),
                restored: 2,
            },
        ]
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
