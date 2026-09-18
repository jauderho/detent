//! The one enum every front end constructs (PLAN §2.5).
//!
//! The CLI, the web API, an MCP tool call and an FFI-driven host all build an
//! [`Operation`] and hand it to [`OpsEngine::execute`](crate::OpsEngine::execute).
//! None of them touches a file or a service manager directly; that is what
//! makes adding a front end cheap, and what makes the audit log complete.
//!
//! # Certificate renewal
//!
//! [`Operation::CertRenew`] is the one Phase 6 operation that needs no ACME
//! plumbing to be useful: this build has no `[acme]` config surface yet, so
//! the engine cannot order, install, or hot-swap a certificate. It answers
//! [`OpsError::Unsupported`] with the catalogued `ops-unsupported` id, which
//! the UI renders as a disabled control with a reason rather than a control
//! that looks live until the server answers. A full renewal flow (order,
//! install, `CertStore::replace`) arrives with the ACME wiring, not here.

use std::time::Duration;

use detent_core::descriptor::ServiceAction as CoreServiceAction;
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::privsep::proto::{BackupId, CommitId, ServiceAction as WireServiceAction};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::AuditQuery;

/// Default commit-confirm window (PLAN §2.5, ADR-012).
pub const DEFAULT_CONFIRM: Duration = Duration::from_secs(90);

/// What a caller may ask be done to a service.
///
/// A closed mirror of [`CoreServiceAction`] that, unlike the core type, is
/// `Deserialize` (so it can arrive over an API) and, unlike the wire type,
/// has no `Status` variant — status is [`Operation::ServiceStatus`], which
/// mutates nothing and must not be confusable with an action that does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ServiceCommand {
    /// Full restart.
    Restart,
    /// Reload configuration in place.
    Reload,
    /// Start a stopped service.
    Start,
    /// Stop a running service.
    Stop,
}

impl ServiceCommand {
    /// The core action a module declares in its descriptor.
    #[must_use]
    pub const fn to_core(self) -> CoreServiceAction {
        match self {
            Self::Restart => CoreServiceAction::Restart,
            Self::Reload => CoreServiceAction::Reload,
            Self::Start => CoreServiceAction::Start,
            Self::Stop => CoreServiceAction::Stop,
        }
    }

    /// The privsep wire action.
    #[must_use]
    pub const fn to_wire(self) -> WireServiceAction {
        match self {
            Self::Restart => WireServiceAction::Restart,
            Self::Reload => WireServiceAction::Reload,
            Self::Start => WireServiceAction::Start,
            Self::Stop => WireServiceAction::Stop,
        }
    }
}

impl From<CoreServiceAction> for ServiceCommand {
    fn from(action: CoreServiceAction) -> Self {
        match action {
            CoreServiceAction::Restart => Self::Restart,
            CoreServiceAction::Reload => Self::Reload,
            CoreServiceAction::Start => Self::Start,
            CoreServiceAction::Stop => Self::Stop,
        }
    }
}

/// Everything the operations layer can be asked to do in v1.
///
/// Serialization is externally tagged (`{"get_module": {"id": "hosts"}}`) so
/// that `deny_unknown_fields` applies to every variant; an internal tag would
/// silently drop that guarantee for the newtype variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Every module compiled into this build.
    ListModules,
    /// One module's descriptor, schema, current model and diagnostics.
    GetModule {
        /// Module id, e.g. `hosts`.
        id: String,
    },
    /// Validate a candidate model without touching anything.
    Validate {
        /// Module id.
        id: String,
        /// The candidate model, as the module's JSON schema describes it.
        model: Value,
    },
    /// Render a candidate, diff it against the file on disk, and run the
    /// module's upstream validators. Writes nothing.
    Plan {
        /// Module id.
        id: String,
        /// The candidate model.
        model: Value,
    },
    /// Write a candidate model, optionally act on the module's service, and
    /// optionally arm commit-confirm.
    Apply {
        /// Module id.
        id: String,
        /// The candidate model.
        model: Value,
        /// Digest the caller last read. A mismatch is refused rather than
        /// silently overwriting somebody else's edit.
        expected_hash: Option<Sha256Digest>,
        /// What to do to the module's service afterwards.
        service_action: Option<ServiceCommand>,
        /// Commit-confirm window. `None` uses [`DEFAULT_CONFIRM`] for a module
        /// whose descriptor sets `commit_confirm`, and arms nothing for one
        /// that does not.
        confirm: Option<Duration>,
    },
    /// Confirm a pending commit before its deadline.
    ConfirmCommit {
        /// The id [`Operation::Apply`] returned.
        commit_id: CommitId,
    },
    /// Roll a pending commit back immediately, restoring every write made
    /// since it was armed and clearing the monitor's pending-commit marker,
    /// instead of waiting for the deadline. A second call for the same
    /// commit, or one that arrives after the deadline already rolled it back
    /// on its own, fails the same way
    /// [`Operation::ConfirmCommit`] does once nothing is pending:
    /// [`OpsError::Privsep`](crate::OpsError::Privsep) wrapping a
    /// `ProtoError::UnknownId`.
    RollbackCommit {
        /// The id [`Operation::Apply`] returned.
        commit_id: CommitId,
    },
    /// The backups retained for a module's targets, newest first.
    ListBackups {
        /// Module id.
        id: String,
    },
    /// Put one of those backups back.
    Restore {
        /// Module id.
        id: String,
        /// Index into the listing [`Operation::ListBackups`] returned.
        backup_id: BackupId,
    },
    /// The run state of the module's service.
    ServiceStatus {
        /// Module id.
        id: String,
    },
    /// Start, stop, restart or reload the module's service.
    ServiceAction {
        /// Module id.
        id: String,
        /// What to do.
        action: ServiceCommand,
    },
    /// What was detected about this host.
    HostProfile,
    /// Read back the audit log.
    AuditQuery(AuditQuery),
    /// Read whether a qualifying update exists for this build.
    ///
    /// Not answered by the engine, for the same reason as [`Self::CertStatus`]:
    /// the check fetches a release feed over the network and lives in
    /// `detent-update`, which the operations layer does not depend on. The
    /// variant exists so authorization and the audit label for a refusal are
    /// this operation's own rather than borrowed.
    UpdateStatus,
    /// Read the serving certificate's fingerprint and remaining lifetime.
    ///
    /// Not answered by the engine: the serving certificate belongs to the
    /// front end that owns the TLS listener, and `detent-ops` has no TLS
    /// types. The variant exists so that authorization and the audit record
    /// for a refusal carry this operation's own identity instead of
    /// borrowing [`Operation::HostProfile`]'s.
    CertStatus,
    /// Check whether the serving certificate should renew, and renew it.
    ///
    /// Answered as [`OpsError::Unsupported`] until the ACME wiring lands (see
    /// the module header): the variant exists so the API, authz, audit, and
    /// UI can be built against the real shape instead of a stub that drifts.
    CertRenew,
}

/// The kind of an [`Operation`], with none of its payload.
///
/// This is what the audit log stores: an operation's arguments include the
/// candidate configuration, and PLAN §2.5 forbids the audit log from carrying
/// file bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum OpKind {
    /// [`Operation::ListModules`].
    ListModules,
    /// [`Operation::GetModule`].
    GetModule,
    /// [`Operation::Validate`].
    Validate,
    /// [`Operation::Plan`].
    Plan,
    /// [`Operation::Apply`].
    Apply,
    /// [`Operation::ConfirmCommit`].
    ConfirmCommit,
    /// [`Operation::RollbackCommit`].
    RollbackCommit,
    /// [`Operation::ListBackups`].
    ListBackups,
    /// [`Operation::Restore`].
    Restore,
    /// [`Operation::ServiceStatus`].
    ServiceStatus,
    /// [`Operation::ServiceAction`].
    ServiceAction,
    /// [`Operation::HostProfile`].
    HostProfile,
    /// [`Operation::AuditQuery`].
    AuditQuery,
    /// [`Operation::UpdateStatus`].
    UpdateStatus,
    /// [`Operation::CertStatus`].
    CertStatus,
    /// [`Operation::CertRenew`].
    CertRenew,
}

impl Operation {
    /// This operation's kind.
    #[must_use]
    pub const fn kind(&self) -> OpKind {
        match *self {
            Self::ListModules => OpKind::ListModules,
            Self::GetModule { .. } => OpKind::GetModule,
            Self::Validate { .. } => OpKind::Validate,
            Self::Plan { .. } => OpKind::Plan,
            Self::Apply { .. } => OpKind::Apply,
            Self::ConfirmCommit { .. } => OpKind::ConfirmCommit,
            Self::RollbackCommit { .. } => OpKind::RollbackCommit,
            Self::ListBackups { .. } => OpKind::ListBackups,
            Self::Restore { .. } => OpKind::Restore,
            Self::ServiceStatus { .. } => OpKind::ServiceStatus,
            Self::ServiceAction { .. } => OpKind::ServiceAction,
            Self::HostProfile => OpKind::HostProfile,
            Self::AuditQuery(_) => OpKind::AuditQuery,
            Self::UpdateStatus => OpKind::UpdateStatus,
            Self::CertStatus => OpKind::CertStatus,
            Self::CertRenew => OpKind::CertRenew,
        }
    }

    /// The module this operation is about, when it is about one.
    #[must_use]
    pub fn module(&self) -> Option<&str> {
        match *self {
            Self::GetModule { ref id }
            | Self::Validate { ref id, .. }
            | Self::Plan { ref id, .. }
            | Self::Apply { ref id, .. }
            | Self::ListBackups { ref id }
            | Self::Restore { ref id, .. }
            | Self::ServiceStatus { ref id }
            | Self::ServiceAction { ref id, .. } => Some(id),
            Self::ListModules
            | Self::ConfirmCommit { .. }
            | Self::RollbackCommit { .. }
            | Self::HostProfile
            | Self::UpdateStatus
            | Self::CertStatus
            | Self::CertRenew
            | Self::AuditQuery(_) => None,
        }
    }

    /// Whether this operation can change the host.
    ///
    /// Every mutating operation writes exactly one audit record, success or
    /// failure (PLAN §2.5). Read-only operations are audited only when they
    /// are refused.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(
            *self,
            Self::Apply { .. }
                | Self::ConfirmCommit { .. }
                | Self::RollbackCommit { .. }
                | Self::Restore { .. }
                | Self::ServiceAction { .. }
                | Self::CertRenew
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CONFIRM, OpKind, Operation, ServiceCommand};
    use detent_core::descriptor::ServiceAction as CoreServiceAction;
    use detent_platform::privsep::proto::{BackupId, CommitId, ServiceAction as WireServiceAction};
    use serde_json::json;
    use std::time::Duration;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn every_operation() -> Vec<Operation> {
        vec![
            Operation::ListModules,
            Operation::GetModule {
                id: "hosts".to_owned(),
            },
            Operation::Validate {
                id: "hosts".to_owned(),
                model: json!({}),
            },
            Operation::Plan {
                id: "hosts".to_owned(),
                model: json!({}),
            },
            Operation::Apply {
                id: "hosts".to_owned(),
                model: json!({}),
                expected_hash: None,
                service_action: Some(ServiceCommand::Reload),
                confirm: Some(DEFAULT_CONFIRM),
            },
            Operation::ConfirmCommit {
                commit_id: CommitId(1),
            },
            Operation::RollbackCommit {
                commit_id: CommitId(1),
            },
            Operation::ListBackups {
                id: "hosts".to_owned(),
            },
            Operation::Restore {
                id: "hosts".to_owned(),
                backup_id: BackupId(0),
            },
            Operation::ServiceStatus {
                id: "hosts".to_owned(),
            },
            Operation::ServiceAction {
                id: "hosts".to_owned(),
                action: ServiceCommand::Restart,
            },
            Operation::HostProfile,
            Operation::AuditQuery(crate::audit::AuditQuery::default()),
            Operation::UpdateStatus,
            Operation::CertStatus,
            Operation::CertRenew,
        ]
    }

    #[test]
    fn every_variant_round_trips_and_reports_its_kind() -> R {
        let mut kinds = Vec::new();
        for op in every_operation() {
            let json = serde_json::to_value(&op)?;
            assert_eq!(serde_json::from_value::<Operation>(json)?, op);
            kinds.push(op.kind());
            assert!(!format!("{op:?}").is_empty());
            assert_eq!(op.clone(), op);
        }
        assert_eq!(kinds.len(), 16);
        let unique: std::collections::BTreeSet<_> =
            kinds.iter().map(|kind| format!("{kind:?}")).collect();
        assert_eq!(unique.len(), kinds.len());
        Ok(())
    }

    #[test]
    fn modules_and_mutation_are_classified_per_variant() {
        let mut mutating = 0_usize;
        let mut with_module = 0_usize;
        for op in every_operation() {
            if op.is_mutating() {
                mutating = mutating.saturating_add(1);
            }
            if op.module().is_some() {
                with_module = with_module.saturating_add(1);
            }
        }
        // Apply, ConfirmCommit, RollbackCommit, Restore, ServiceAction, CertRenew.
        assert_eq!(mutating, 6);
        // Everything except ListModules, ConfirmCommit, RollbackCommit,
        // HostProfile, UpdateStatus, CertStatus, CertRenew and AuditQuery.
        assert_eq!(with_module, 8);
        assert_eq!(
            Operation::GetModule {
                id: "hosts".to_owned()
            }
            .module(),
            Some("hosts")
        );
    }

    #[test]
    fn op_kind_serializes_as_snake_case() -> R {
        assert_eq!(
            serde_json::to_value(OpKind::ListModules)?,
            json!("list_modules")
        );
        assert_eq!(
            serde_json::from_value::<OpKind>(json!("service_action"))?,
            OpKind::ServiceAction
        );
        assert_eq!(OpKind::Apply, OpKind::Apply);
        Ok(())
    }

    #[test]
    fn service_commands_convert_both_ways() -> R {
        for (command, core, wire) in [
            (
                ServiceCommand::Restart,
                CoreServiceAction::Restart,
                WireServiceAction::Restart,
            ),
            (
                ServiceCommand::Reload,
                CoreServiceAction::Reload,
                WireServiceAction::Reload,
            ),
            (
                ServiceCommand::Start,
                CoreServiceAction::Start,
                WireServiceAction::Start,
            ),
            (
                ServiceCommand::Stop,
                CoreServiceAction::Stop,
                WireServiceAction::Stop,
            ),
        ] {
            assert_eq!(command.to_core(), core);
            assert_eq!(command.to_wire(), wire);
            assert_eq!(ServiceCommand::from(core), command);
            let json = serde_json::to_value(command)?;
            assert_eq!(serde_json::from_value::<ServiceCommand>(json)?, command);
        }
        assert_eq!(DEFAULT_CONFIRM, Duration::from_secs(90));
        Ok(())
    }

    #[test]
    fn unknown_fields_are_refused() {
        let bad = json!({"get_module": {"id": "hosts", "extra": 1}});
        assert!(serde_json::from_value::<Operation>(bad).is_err());
        assert!(serde_json::from_value::<Operation>(json!("no_such_op")).is_err());
    }
}
