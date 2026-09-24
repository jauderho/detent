//! Failures the operations layer reports.
//!
//! Every variant carries a stable [`MessageId`] so a front end renders a
//! localized sentence rather than a Rust error string, mirroring how
//! `detent-core` treats its own errors (see `detent_core::diag`). The `Display`
//! text exists for logs, never for the UI.

use detent_core::diag::{Diagnostics, MessageId};
use detent_core::module::DynError;
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::privsep::proto::CommitId;
use detent_platform::privsep::worker::ClientError;
use detent_platform::service::ServiceError;

use crate::audit::AuditError;
use crate::authz::Denied;

/// Anything that can stop an [`Operation`](crate::Operation).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpsError {
    /// No module with that id is compiled into this build.
    #[error("unknown module {id:?}")]
    UnknownModule {
        /// The id that was asked for.
        id: String,
    },
    /// The authorization policy refused the operation.
    #[error(transparent)]
    Denied(#[from] Denied),
    /// The candidate model has at least one [`Severity::Error`] diagnostic, so
    /// it must not be applied (PLAN §2.3).
    ///
    /// [`Severity::Error`]: detent_core::diag::Severity::Error
    #[error("the candidate configuration has {} diagnostic(s), at least one an error", .diagnostics.len())]
    Invalid {
        /// Everything validation found, errors included.
        diagnostics: Box<Diagnostics>,
    },
    /// An external validator refused the rendered candidate or could not run.
    #[error("external validator {program:?} did not pass: {detail}")]
    CheckFailed {
        /// The validator executable.
        program: String,
        /// Validator failure detail.
        detail: String,
    },
    /// The target changed since the caller read it. Optimistic concurrency:
    /// the caller must re-read, re-plan and retry.
    #[error("target changed since it was read")]
    HashConflict {
        /// The digest the caller passed as `expected_hash`.
        expected: Sha256Digest,
        /// What is on disk now; `None` when the file is gone.
        actual: Option<Sha256Digest>,
    },
    /// The module could not parse the file, or the JSON model did not match
    /// the module's schema.
    #[error(transparent)]
    Module(#[from] DynError),
    /// The privileged monitor refused or could not perform the request.
    #[error(transparent)]
    Privsep(#[from] ClientError),
    /// The host's service manager failed.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// The module declares no target the monitor advertised, so there is
    /// nothing to read or write. A module/allow-list mismatch, not user error.
    #[error("module {module:?} has no writable target on this host")]
    NoTarget {
        /// The module.
        module: String,
    },
    /// The module declares no service binding, so there is nothing to act on.
    #[error("module {module:?} declares no service")]
    NoService {
        /// The module.
        module: String,
    },
    /// A commit-confirm apply was refused because another commit is pending.
    #[error("commit {0} is already pending")]
    CommitPending(CommitId),
    /// A commit-confirm apply was refused because its write had no backup.
    #[error("commit-confirm requires a retained backup")]
    NoBackup,
    /// The audit log could not be read.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The audit log could not be written before the operation.
    #[error("audit unavailable: {0}")]
    AuditUnavailable(AuditError),
    /// The operation is defined but this build cannot perform it.
    #[error("unsupported operation: {what}")]
    Unsupported {
        /// Which operation, in one short phrase for the log.
        what: &'static str,
    },
}

impl OpsError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::UnknownModule { .. } => MessageId::new("ops-unknown-module"),
            Self::Denied(ref denied) => denied.id,
            Self::Invalid { .. } => MessageId::new("ops-invalid-model"),
            Self::CheckFailed { .. } => MessageId::new("ops-check-failed"),
            Self::HashConflict { .. } => MessageId::new("ops-hash-conflict"),
            Self::Module(ref err) => err.message_id(),
            Self::Privsep(_) => MessageId::new("ops-privsep-failed"),
            Self::Service(_) => MessageId::new("ops-service-failed"),
            Self::NoTarget { .. } => MessageId::new("ops-no-target"),
            Self::NoService { .. } => MessageId::new("ops-no-service"),
            Self::Audit(_) => MessageId::new("ops-audit-failed"),
            Self::AuditUnavailable(_) => MessageId::new("ops-audit-unavailable"),
            Self::CommitPending(_) => MessageId::new("ops-commit-pending"),
            Self::NoBackup => MessageId::new("ops-no-backup"),
            Self::Unsupported { .. } => MessageId::new("ops-unsupported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OpsError;
    use crate::audit::AuditError;
    use crate::authz::Denied;
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use detent_core::module::{DynError, ParseError};
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::privsep::proto::CommitId;
    use detent_platform::privsep::worker::ClientError;
    use detent_platform::service::ServiceError;

    fn diagnostics() -> Diagnostics {
        std::iter::once(Diagnostic::new(
            Severity::Error,
            MessageId::new("hosts-invalid-ip"),
        ))
        .collect()
    }

    #[test]
    fn every_variant_has_a_message_id_and_display_text() {
        let cases: Vec<(OpsError, &str)> = vec![
            (
                OpsError::UnknownModule {
                    id: "nope".to_owned(),
                },
                "ops-unknown-module",
            ),
            (
                OpsError::from(Denied::new(MessageId::new("ops-denied"))),
                "ops-denied",
            ),
            (
                OpsError::Invalid {
                    diagnostics: Box::new(diagnostics()),
                },
                "ops-invalid-model",
            ),
            (
                OpsError::CheckFailed {
                    program: "/usr/sbin/check".to_owned(),
                    detail: "failed".to_owned(),
                },
                "ops-check-failed",
            ),
            (
                OpsError::HashConflict {
                    expected: Sha256Digest::of(b"a"),
                    actual: Some(Sha256Digest::of(b"b")),
                },
                "ops-hash-conflict",
            ),
            (
                OpsError::from(DynError::from(ParseError::Malformed {
                    message: "bad".to_owned(),
                    span: None,
                })),
                "core-parse-malformed",
            ),
            (
                OpsError::from(ClientError::NotGreeted),
                "ops-privsep-failed",
            ),
            (
                OpsError::from(ServiceError::Unavailable("no systemctl".to_owned())),
                "ops-service-failed",
            ),
            (
                OpsError::NoTarget {
                    module: "hosts".to_owned(),
                },
                "ops-no-target",
            ),
            (
                OpsError::NoService {
                    module: "hosts".to_owned(),
                },
                "ops-no-service",
            ),
            (OpsError::CommitPending(CommitId(7)), "ops-commit-pending"),
            (OpsError::NoBackup, "ops-no-backup"),
            (
                OpsError::from(AuditError::Encode("bad".to_owned())),
                "ops-audit-failed",
            ),
            (
                OpsError::AuditUnavailable(AuditError::Encode("bad".to_owned())),
                "ops-audit-unavailable",
            ),
            (
                OpsError::Unsupported {
                    what: "rollback_commit",
                },
                "ops-unsupported",
            ),
        ];
        // user. `detent-i18n`'s parity test compares locales to each other; it
        // cannot see ids that exist only in Rust.
        let catalogue = include_str!("../../../locales/en-US/core.ftl");
        for (error, id) in cases {
            assert_eq!(error.message_id().as_str(), id);
            assert!(!error.to_string().is_empty(), "{error:?} renders empty");
            assert!(!format!("{error:?}").is_empty());
            assert!(
                catalogue
                    .lines()
                    .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id)),
                "`{id}` has no entry in locales/en-US/core.ftl"
            );
        }
    }

    #[test]
    fn the_invalid_variant_reports_how_many_diagnostics_it_carries() {
        let error = OpsError::Invalid {
            diagnostics: Box::new(diagnostics()),
        };
        assert!(error.to_string().contains("1 diagnostic"));
    }
}
