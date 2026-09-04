//! What an [`Operation`](crate::Operation) produces.
//!
//! [`OpOutcome`] mirrors `Operation` one-for-one and is `Serialize`, so the
//! web API, an MCP tool and `detent --json` all emit the same shapes without
//! a per-front-end DTO layer.
//!
//! Only `Serialize` — not `Deserialize`: several payloads come straight from
//! `detent-core` and `detent-platform` (`Diagnostics`, `ModuleDescriptor`,
//! `ServiceStatus`) which are serialize-only by design, and inventing
//! deserializable copies of them here would be a second source of truth.

use detent_core::descriptor::{HostProfile, ModuleDescriptor};
use detent_core::diag::Diagnostics;
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::{Detected, NetworkBackend, ResolverBackend};
use detent_platform::privsep::proto::{BackupInfo, CommitId, TargetId};
use detent_platform::service::ServiceStatus;
use serde::Serialize;
use serde_json::Value;

use crate::audit::AuditRecord;
use crate::diff::Hunk;
use crate::op::ServiceCommand;

/// One module, as [`Operation::GetModule`](crate::Operation::GetModule) sees
/// it.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleView {
    /// The module's static metadata.
    pub descriptor: &'static ModuleDescriptor,
    /// The JSON Schema of its model, with `x-detent` UI hints.
    pub schema: Value,
    /// The model parsed from the file on disk, or `None` when the target
    /// could not be read (e.g. it does not exist yet).
    pub model: Option<Value>,
    /// Digest of the file the model came from.
    pub current_hash: Option<Sha256Digest>,
    /// Validation findings for that model.
    pub diagnostics: Diagnostics,
}

/// A service a change would affect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AffectedService {
    /// The unit name the monitor resolved for this host's init system.
    pub unit: String,
    /// The actions the module declared, most preferred first.
    pub actions: Vec<ServiceCommand>,
}

/// The result of running one of a module's upstream validators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    /// Absolute path of the validator, for display.
    pub program: String,
    /// Whether the validator actually ran. `false` means the binary is not
    /// installed or the monitor has no check runner wired up — informative,
    /// not a plan failure.
    pub ran: bool,
    /// Whether the declared expectation was met.
    pub passed: bool,
    /// Exit status, when the program was executed.
    pub exit_code: Option<i32>,
    /// A bounded excerpt of its output, or the reason it did not run.
    pub detail: String,
}

/// What [`Operation::Plan`](crate::Operation::Plan) found. Nothing was
/// written.
#[derive(Debug, Clone, Serialize)]
pub struct PlanReport {
    /// The module.
    pub module: String,
    /// The target this plan is about.
    pub path: String,
    /// The change, as unified-diff hunks.
    pub diff: Vec<Hunk>,
    /// The candidate file, rendered in full.
    pub rendered: String,
    /// `diff` as unified-diff text, so a front end and the CLI show the same
    /// bytes without each re-implementing the rendering.
    pub unified_diff: String,
    /// Services a subsequent apply could act on.
    pub affected_services: Vec<AffectedService>,
    /// Results of the module's upstream validators, run against the candidate.
    pub checks: Vec<CheckReport>,
    /// Validation findings for the candidate model.
    pub diagnostics: Diagnostics,
    /// Digest of the file as it is now, to pass back as `expected_hash`.
    pub current_hash: Sha256Digest,
    /// Whether applying would change anything at all.
    pub would_change: bool,
}

/// A commit-confirm window that is now running in the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingCommit {
    /// The id to pass to
    /// [`Operation::ConfirmCommit`](crate::Operation::ConfirmCommit).
    pub commit_id: CommitId,
    /// Seconds until automatic rollback, as the monitor clamped them.
    pub timeout_s: u16,
    /// When the window closes, RFC 3339 UTC.
    pub deadline: String,
    /// How many targets the monitor will roll back if it expires.
    pub rollback_targets: u16,
}

/// What happened to a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceReport {
    /// The unit the monitor acted on.
    pub unit: String,
    /// The action that was requested.
    pub action: ServiceCommand,
    /// Whether the unit is running afterwards.
    pub active: bool,
    /// A short human-readable detail string.
    pub detail: String,
}

/// What [`Operation::Apply`](crate::Operation::Apply) did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    /// The module.
    pub module: String,
    /// The target that was written.
    pub path: String,
    /// Digest of the replaced contents; `None` when the file was created.
    pub prev_hash: Option<Sha256Digest>,
    /// Digest now on disk.
    pub new_hash: Sha256Digest,
    /// Whether the target did not exist before.
    pub created: bool,
    /// Whether a backup was retained, and therefore whether commit-confirm
    /// has something to roll back to.
    pub backed_up: bool,
    /// The service action, when one was requested.
    pub service: Option<ServiceReport>,
    /// The armed commit-confirm window, for a module whose descriptor sets
    /// `commit_confirm`.
    pub commit: Option<PendingCommit>,
}

/// What was detected about this host.
///
/// A projection rather than [`Detected`] itself: `HostFacts` and its enums are
/// plain Rust types with no `Serialize`, and adding one there would mean
/// editing `detent-platform`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostReport {
    /// The profile modules see.
    pub profile: HostProfile,
    /// `ID=` from `/etc/os-release`, when the host has one.
    pub distro_id: Option<String>,
    /// `VERSION_ID=` from `/etc/os-release`.
    pub distro_version_id: Option<String>,
    /// The detected network backend.
    pub network_backend: &'static str,
    /// The detected resolver backend.
    pub resolver_backend: &'static str,
    /// Caveats detection surfaced.
    pub notes: Vec<String>,
}

/// The stable wire name of a network backend.
const fn network_backend_name(backend: NetworkBackend) -> &'static str {
    match backend {
        NetworkBackend::SystemdNetworkd => "systemd_networkd",
        NetworkBackend::NetworkManager => "network_manager",
        NetworkBackend::Ifupdown => "ifupdown",
        NetworkBackend::Netplan => "netplan",
        NetworkBackend::Unknown => "unknown",
    }
}

/// The stable wire name of a resolver backend.
const fn resolver_backend_name(backend: ResolverBackend) -> &'static str {
    match backend {
        ResolverBackend::SystemdResolved => "systemd_resolved",
        ResolverBackend::NetworkManager => "network_manager",
        ResolverBackend::Static => "static",
        ResolverBackend::Unbound => "unbound",
        ResolverBackend::Unknown => "unknown",
    }
}

impl From<&Detected> for HostReport {
    fn from(detected: &Detected) -> Self {
        Self {
            profile: detected.profile.clone(),
            distro_id: detected
                .facts
                .distro
                .as_ref()
                .map(|distro| distro.id.clone()),
            distro_version_id: detected
                .facts
                .distro
                .as_ref()
                .and_then(|distro| distro.version_id.clone()),
            network_backend: network_backend_name(detected.facts.network_backend),
            resolver_backend: resolver_backend_name(detected.facts.resolver_backend),
            notes: detected.facts.notes.clone(),
        }
    }
}

/// The result of one [`Operation`](crate::Operation).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    /// Answer to `ListModules`.
    Modules(Vec<&'static ModuleDescriptor>),
    /// Answer to `GetModule`.
    Module(Box<ModuleView>),
    /// Answer to `Validate`.
    Validated(Diagnostics),
    /// Answer to `Plan`.
    Planned(Box<PlanReport>),
    /// Answer to `Apply`.
    Applied(Box<ApplyReport>),
    /// Answer to `ConfirmCommit`.
    CommitConfirmed {
        /// The commit that is now final.
        commit_id: CommitId,
    },
    /// Answer to `RollbackCommit`. A sibling of [`OpOutcome::CommitConfirmed`]
    /// rather than a reuse of it: a rollback also reports how many targets
    /// were restored, which a confirmation — nothing was written back — has
    /// no counterpart for.
    RolledBack {
        /// The commit that was rolled back.
        commit_id: CommitId,
        /// How many targets were actually restored.
        restored: u16,
    },
    /// Answer to `ListBackups`.
    Backups(Vec<BackupInfo>),
    /// Answer to `Restore`.
    Restored {
        /// The target that was put back.
        target: TargetId,
        /// Digest now on disk.
        new_hash: Sha256Digest,
    },
    /// Answer to `ServiceStatus`.
    Status(ServiceStatus),
    /// Answer to `ServiceAction`.
    Serviced(ServiceReport),
    /// Answer to `HostProfile`.
    Host(Box<HostReport>),
    /// Answer to `AuditQuery`.
    Audit(Vec<AuditRecord>),
}

#[cfg(test)]
mod tests {
    use super::{
        AffectedService, CheckReport, HostReport, OpOutcome, PendingCommit, ServiceReport,
        network_backend_name, resolver_backend_name,
    };
    use crate::op::ServiceCommand;
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::host::{Detected, Distro, NetworkBackend, ResolverBackend};
    use detent_platform::privsep::proto::{CommitId, TargetId};

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn backend_names_are_stable_for_every_variant() {
        assert_eq!(
            [
                NetworkBackend::SystemdNetworkd,
                NetworkBackend::NetworkManager,
                NetworkBackend::Ifupdown,
                NetworkBackend::Netplan,
                NetworkBackend::Unknown,
            ]
            .map(network_backend_name),
            [
                "systemd_networkd",
                "network_manager",
                "ifupdown",
                "netplan",
                "unknown"
            ]
        );
        assert_eq!(
            [
                ResolverBackend::SystemdResolved,
                ResolverBackend::NetworkManager,
                ResolverBackend::Static,
                ResolverBackend::Unbound,
                ResolverBackend::Unknown,
            ]
            .map(resolver_backend_name),
            [
                "systemd_resolved",
                "network_manager",
                "static",
                "unbound",
                "unknown"
            ]
        );
    }

    #[test]
    fn a_host_report_projects_the_detected_facts() -> R {
        let mut detected = Detected::default();
        let report = HostReport::from(&detected);
        assert_eq!(report.distro_id, None);
        assert_eq!(report.distro_version_id, None);
        assert_eq!(report.network_backend, "unknown");

        detected.facts.distro = Some(Distro {
            id: "debian".to_owned(),
            id_like: vec![],
            version_id: Some("12".to_owned()),
        });
        detected.facts.network_backend = NetworkBackend::Ifupdown;
        detected.facts.resolver_backend = ResolverBackend::Static;
        detected.facts.notes = vec!["a note".to_owned()];
        let report = HostReport::from(&detected);
        assert_eq!(report.distro_id.as_deref(), Some("debian"));
        assert_eq!(report.distro_version_id.as_deref(), Some("12"));
        assert_eq!(report.network_backend, "ifupdown");
        assert_eq!(report.resolver_backend, "static");
        assert_eq!(report.notes.len(), 1);
        assert_eq!(report.clone(), report);

        let json = serde_json::to_value(&report)?;
        assert_eq!(
            json.pointer("/distro_id").and_then(|v| v.as_str()),
            Some("debian")
        );
        assert!(format!("{report:?}").contains("debian"));
        Ok(())
    }

    #[test]
    fn outcome_payloads_serialize_with_their_variant_name() -> R {
        let outcome = OpOutcome::CommitConfirmed {
            commit_id: CommitId(4),
        };
        let json = serde_json::to_value(&outcome)?;
        assert_eq!(
            json.pointer("/commit_confirmed/commit_id")
                .and_then(serde_json::Value::as_u64),
            Some(4)
        );

        let restored = OpOutcome::Restored {
            target: TargetId(0),
            new_hash: Sha256Digest::of(b"x"),
        };
        assert!(
            serde_json::to_value(&restored)?
                .pointer("/restored/new_hash")
                .is_some()
        );
        assert!(format!("{outcome:?}").contains("CommitConfirmed"));
        assert!(format!("{:?}", outcome.clone()).contains('4'));

        let rolled_back = OpOutcome::RolledBack {
            commit_id: CommitId(5),
            restored: 2,
        };
        let json = serde_json::to_value(&rolled_back)?;
        assert_eq!(
            json.pointer("/rolled_back/commit_id")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
        assert_eq!(
            json.pointer("/rolled_back/restored")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert!(format!("{rolled_back:?}").contains("RolledBack"));
        Ok(())
    }

    #[test]
    fn plan_and_apply_side_types_serialize() -> R {
        let affected = AffectedService {
            unit: "chronyd.service".to_owned(),
            actions: vec![ServiceCommand::Restart],
        };
        assert_eq!(
            serde_json::to_value(&affected)?
                .pointer("/actions/0")
                .and_then(|v| v.as_str()),
            Some("restart")
        );
        assert_eq!(affected.clone(), affected);

        let check = CheckReport {
            program: "/usr/sbin/chronyd".to_owned(),
            ran: false,
            passed: false,
            exit_code: None,
            detail: "not installed".to_owned(),
        };
        assert!(serde_json::to_value(&check)?.pointer("/ran").is_some());
        assert_eq!(check.clone(), check);

        let pending = PendingCommit {
            commit_id: CommitId(1),
            timeout_s: 90,
            deadline: "2026-09-04T00:00:00Z".to_owned(),
            rollback_targets: 1,
        };
        assert!(
            serde_json::to_value(&pending)?
                .pointer("/deadline")
                .is_some()
        );
        assert_eq!(pending.clone(), pending);

        let service = ServiceReport {
            unit: "chronyd.service".to_owned(),
            action: ServiceCommand::Reload,
            active: true,
            detail: "running".to_owned(),
        };
        assert!(serde_json::to_value(&service)?.pointer("/active").is_some());
        assert_eq!(service.clone(), service);
        assert!(format!("{check:?}").contains("chronyd"));
        Ok(())
    }
}
