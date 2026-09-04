//! [`OpsEngine`]: the one place an [`Operation`] turns into privileged work.
//!
//! The engine owns four collaborators and nothing else:
//!
//! * a **module registry** (`Vec<Box<dyn DynModule>>`), passed in rather than
//!   fetched from `detent-modules`, so a test can inject a fake module and the
//!   binary can inject exactly the modules its features compiled;
//! * a **privsep [`Client`]**, which is the *only* route to anything under
//!   `/etc` or to service control (ADR-001);
//! * the **detected host** (`HostProfile` + platform facts), used to pick a
//!   module's backend target and to validate against the installed versions;
//! * an **[`AuditSink`]** and an **[`Authz`]** policy.
//!
//! # Two deliberate deviations, both documented at their call sites
//!
//! * [`Operation::ServiceStatus`] does **not** go through the monitor. The
//!   privsep protocol answers `ProtoError::Unsupported` for
//!   `ServiceAction::Status` (`privsep::monitor`), and querying a unit's state
//!   needs no privilege, so the engine asks a [`ServiceManager`] directly.
//!   Every *mutating* service action still goes through the monitor.
//! * [`Operation::RollbackCommit`] reports
//!   [`OpsError::Unsupported`]. The protocol has `StartConfirmTimer` and
//!   `ConfirmCommit` but no "roll back now" request, and PLAN §2.5 is explicit
//!   that the monitor owns rollback — reimplementing it here out of the backup
//!   listing would duplicate the state machine that keeps a headless box
//!   recoverable. An unconfirmed commit still rolls back on its own deadline.

use std::time::Duration;

use detent_core::descriptor::{ModuleDescriptor, ValidationCtx};
use detent_core::module::{DynModule, ParseError};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::Detected;
use detent_platform::privsep::proto::{
    BackupId, BindingId, CheckId, CommitId, ProtoError, ServiceAction as WireServiceAction,
    TargetId,
};
use detent_platform::privsep::worker::{Client, ClientError};
use detent_platform::service::ServiceManager;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::{AuditRecord, AuditResult, AuditSink};
use crate::authz::Authz;
use crate::diff::{DEFAULT_CONTEXT, diff, render_unified};
use crate::error::OpsError;
use crate::identity::Identity;
use crate::op::{DEFAULT_CONFIRM, Operation, ServiceCommand};
use crate::report::{
    AffectedService, ApplyReport, CheckReport, HostReport, ModuleView, OpOutcome, PendingCommit,
    PlanReport, ServiceReport,
};

/// The digests one mutating operation observed, for the audit record.
#[derive(Debug, Clone, Copy, Default)]
struct Hashes {
    prev: Option<Sha256Digest>,
    new: Option<Sha256Digest>,
}

/// Everything the monitor advertised about one module, resolved once so the
/// rest of an operation can borrow the client mutably.
#[derive(Debug, Clone)]
struct Wiring {
    target: TargetId,
    path: String,
    checks: Vec<(CheckId, String)>,
    binding: Option<(BindingId, AffectedService)>,
}

/// Executes [`Operation`]s against one host.
pub struct OpsEngine {
    modules: Vec<Box<dyn DynModule>>,
    client: Client,
    host: Detected,
    audit: Box<dyn AuditSink>,
    authz: Box<dyn Authz>,
    services: Box<dyn ServiceManager>,
    next_commit: u32,
}

impl std::fmt::Debug for OpsEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsEngine")
            .field("modules", &self.modules.len())
            .field("host", &self.host.profile.os)
            .finish_non_exhaustive()
    }
}

impl OpsEngine {
    /// Assemble an engine.
    ///
    /// `client` must already have completed its handshake
    /// ([`Client::hello`]); the engine reads the allow-list tables it cached
    /// and never repeats the handshake.
    #[must_use]
    pub fn new(
        modules: Vec<Box<dyn DynModule>>,
        client: Client,
        host: Detected,
        audit: Box<dyn AuditSink>,
        authz: Box<dyn Authz>,
        services: Box<dyn ServiceManager>,
    ) -> Self {
        Self {
            modules,
            client,
            host,
            audit,
            authz,
            services,
            next_commit: 1,
        }
    }

    /// What was detected about this host.
    #[must_use]
    pub const fn host(&self) -> &Detected {
        &self.host
    }

    /// Ask the monitor to exit. The engine is unusable afterwards.
    ///
    /// # Errors
    ///
    /// [`OpsError::Privsep`] when the monitor cannot be reached.
    pub fn shutdown(&mut self) -> Result<(), OpsError> {
        self.client.shutdown().map_err(OpsError::from)
    }

    /// Run one operation on behalf of `who`.
    ///
    /// Authorization happens first: a refusal writes an audit record and
    /// touches nothing else. Every mutating operation then writes exactly one
    /// further record, whether it succeeded or failed.
    ///
    /// # Errors
    ///
    /// [`OpsError`] — see its variants; [`OpsError::Denied`] when the policy
    /// refused.
    pub fn execute(&mut self, op: Operation, who: &Identity) -> Result<OpOutcome, OpsError> {
        let module = op.module().map(ToOwned::to_owned);
        let kind = op.kind();
        let mutating = op.is_mutating();
        if let Err(denied) = self.authz.permit(who, &op) {
            let record =
                AuditRecord::new(who, kind, module, AuditResult::Denied).with_error(denied.id);
            self.emit(&record);
            return Err(OpsError::Denied(denied));
        }

        let mut hashes = Hashes::default();
        let result = self.dispatch(op, &mut hashes);
        if !mutating {
            return result;
        }

        let outcome = match result {
            Ok(_) => AuditResult::Ok,
            Err(_) => AuditResult::Error,
        };
        let mut record =
            AuditRecord::new(who, kind, module, outcome).with_hashes(hashes.prev, hashes.new);
        if let Err(ref err) = result {
            record = record.with_error(err.message_id());
        }
        self.emit(&record);
        result
    }

    /// Write one audit record to the sink and to `tracing`.
    ///
    /// A sink failure is logged, not propagated: a file that has already been
    /// written must not be reported to the caller as a failed operation.
    fn emit(&self, record: &AuditRecord) {
        tracing::info!(
            op = ?record.op,
            who = %record.who,
            module = ?record.module,
            result = ?record.result,
            error_id = ?record.error_id,
            "detent audit"
        );
        if let Err(err) = self.audit.record(record) {
            tracing::error!(error = %err, "the audit record could not be persisted");
        }
    }

    /// Perform one operation, without auditing.
    fn dispatch(&mut self, op: Operation, hashes: &mut Hashes) -> Result<OpOutcome, OpsError> {
        match op {
            Operation::ListModules => Ok(OpOutcome::Modules(
                self.modules.iter().map(|m| m.descriptor()).collect(),
            )),
            Operation::GetModule { id } => self.get_module(&id),
            Operation::Validate { id, model } => {
                let module = find_module(&self.modules, &id)?;
                let ctx = ValidationCtx::new(&self.host.profile);
                Ok(OpOutcome::Validated(module.validate_json(&model, &ctx)?))
            }
            Operation::Plan { id, model } => self
                .plan(&id, &model)
                .map(|plan| OpOutcome::Planned(Box::new(plan))),
            Operation::Apply {
                id,
                model,
                expected_hash,
                service_action,
                confirm,
            } => self
                .apply(&id, &model, expected_hash, service_action, confirm, hashes)
                .map(|report| OpOutcome::Applied(Box::new(report))),
            Operation::ConfirmCommit { commit_id } => {
                let commit = self.client.confirm_commit(commit_id).map_err(map_client)?;
                Ok(OpOutcome::CommitConfirmed { commit_id: commit })
            }
            Operation::RollbackCommit { .. } => Err(OpsError::Unsupported {
                what: "rollback_commit: the privsep protocol has no immediate-rollback request; \
                       an unconfirmed commit rolls back at its deadline",
            }),
            Operation::ListBackups { id } => {
                let module = module_id(&self.client, find_module(&self.modules, &id)?)?;
                let backups = self.client.list_backups(module).map_err(map_client)?;
                Ok(OpOutcome::Backups(backups))
            }
            Operation::Restore { id, backup_id } => self.restore(&id, backup_id, hashes),
            Operation::ServiceStatus { id } => self.service_status(&id),
            Operation::ServiceAction { id, action } => self.service_action(&id, action),
            Operation::HostProfile => Ok(OpOutcome::Host(Box::new(HostReport::from(&self.host)))),
            Operation::AuditQuery(query) => Ok(OpOutcome::Audit(
                self.audit.query(&query).map_err(OpsError::from)?,
            )),
        }
    }

    // -- read-only operations ------------------------------------------------

    fn get_module(&mut self, id: &str) -> Result<OpOutcome, OpsError> {
        let module = find_module(&self.modules, id)?;
        let descriptor = module.descriptor();
        let schema = module.schema_json();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        let contents = self.client.read_target(wiring.target).ok();

        let module = find_module(&self.modules, id)?;
        let (model, current_hash) = match contents {
            Some(contents) => {
                let text = decode(&contents.bytes, &wiring.path)?;
                (
                    Some(module.parse_to_model_json(&text)?),
                    Some(contents.digest),
                )
            }
            None => (None, None),
        };
        let ctx = ValidationCtx::new(&self.host.profile);
        let diagnostics = match model {
            Some(ref model) => module.validate_json(model, &ctx)?,
            None => detent_core::diag::Diagnostics::new(),
        };
        Ok(OpOutcome::Module(Box::new(ModuleView {
            descriptor,
            schema,
            model,
            current_hash,
            diagnostics,
        })))
    }

    fn plan(&mut self, id: &str, model: &Value) -> Result<PlanReport, OpsError> {
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        let contents = self.client.read_target(wiring.target).map_err(map_client)?;
        let current = decode(&contents.bytes, &wiring.path)?;

        let module = find_module(&self.modules, id)?;
        let rendered = module.apply_json(&current, model)?;
        let ctx = ValidationCtx::new(&self.host.profile);
        let diagnostics = module.validate_json(model, &ctx)?;

        let hunks = diff(&current, &rendered, DEFAULT_CONTEXT);
        let unified_diff = render_unified(&wiring.path, &wiring.path, &hunks);
        let checks = self.run_checks(&wiring, rendered.as_bytes());

        Ok(PlanReport {
            module: descriptor.id.to_owned(),
            path: wiring.path,
            would_change: current != rendered,
            diff: hunks,
            unified_diff,
            rendered,
            affected_services: wiring
                .binding
                .map(|(_, service)| vec![service])
                .unwrap_or_default(),
            checks,
            diagnostics,
            current_hash: contents.digest,
        })
    }

    /// Run every validator the module declared. A validator that cannot run
    /// (not installed, no check runner wired up) is reported, not fatal: a
    /// plan preview is more useful than an error.
    fn run_checks(&mut self, wiring: &Wiring, candidate: &[u8]) -> Vec<CheckReport> {
        let mut out = Vec::with_capacity(wiring.checks.len());
        for (id, program) in &wiring.checks {
            let report = match self.client.run_check(*id, candidate.to_vec()) {
                Ok(outcome) => CheckReport {
                    program: program.clone(),
                    ran: true,
                    passed: outcome.passed,
                    exit_code: outcome.exit_code,
                    detail: outcome.detail,
                },
                Err(err) => CheckReport {
                    program: program.clone(),
                    ran: false,
                    passed: false,
                    exit_code: None,
                    detail: err.to_string(),
                },
            };
            out.push(report);
        }
        out
    }

    fn service_status(&mut self, id: &str) -> Result<OpOutcome, OpsError> {
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let binding = descriptor
            .services
            .first()
            .ok_or_else(|| OpsError::NoService {
                module: descriptor.id.to_owned(),
            })?;
        Ok(OpOutcome::Status(self.services.status(&binding.units)?))
    }

    // -- mutating operations -------------------------------------------------

    fn apply(
        &mut self,
        id: &str,
        model: &Value,
        expected_hash: Option<Sha256Digest>,
        service_action: Option<ServiceCommand>,
        confirm: Option<Duration>,
        hashes: &mut Hashes,
    ) -> Result<ApplyReport, OpsError> {
        let descriptor = find_module(&self.modules, id)?.descriptor();

        // 1. Validate, and refuse outright on any error diagnostic.
        let ctx = ValidationCtx::new(&self.host.profile);
        let diagnostics = find_module(&self.modules, id)?.validate_json(model, &ctx)?;
        if diagnostics.has_errors() {
            return Err(OpsError::Invalid {
                diagnostics: Box::new(diagnostics),
            });
        }

        // 2. Resolve the wiring, and refuse a service action the module has no
        //    binding for *before* writing: a half-applied change (file written,
        //    service never touched) is worse than no change at all.
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        if service_action.is_some() && wiring.binding.is_none() {
            return Err(OpsError::NoService {
                module: descriptor.id.to_owned(),
            });
        }

        // 3. Read the current file and check the caller's expectation.
        let contents = self.client.read_target(wiring.target).map_err(map_client)?;
        hashes.prev = Some(contents.digest);
        if let Some(expected) = expected_hash
            && expected != contents.digest
        {
            return Err(OpsError::HashConflict {
                expected,
                actual: Some(contents.digest),
            });
        }

        // 4. Render and write.
        let current = decode(&contents.bytes, &wiring.path)?;
        let rendered = find_module(&self.modules, id)?.apply_json(&current, model)?;
        let receipt = self
            .client
            .write_target(wiring.target, Some(contents.digest), rendered.into_bytes())
            .map_err(map_client)?;
        hashes.prev = receipt.prev_digest;
        hashes.new = Some(receipt.new_digest);

        // 5. Act on the service. Step 2 established that a binding exists
        //    whenever an action was asked for.
        let service = match (service_action, wiring.binding.as_ref()) {
            (Some(action), Some(&(binding, ref affected))) => {
                Some(self.act(binding, &affected.unit, action)?)
            }
            _ => None,
        };

        // 6. Arm commit-confirm. The descriptor decides; an explicit `confirm`
        //    additionally opts a module in, which is never less safe.
        let commit = if descriptor.commit_confirm || confirm.is_some() {
            Some(self.arm_commit(confirm)?)
        } else {
            None
        };

        Ok(ApplyReport {
            module: descriptor.id.to_owned(),
            path: wiring.path,
            prev_hash: receipt.prev_digest,
            new_hash: receipt.new_digest,
            created: receipt.created,
            backed_up: receipt.backed_up,
            service,
            commit,
        })
    }

    /// Start the monitor's commit-confirm timer and describe the window.
    fn arm_commit(&mut self, confirm: Option<Duration>) -> Result<PendingCommit, OpsError> {
        let commit_id = CommitId(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);
        let requested =
            u16::try_from(confirm.unwrap_or(DEFAULT_CONFIRM).as_secs()).unwrap_or(u16::MAX);
        let (timeout_s, rollback_targets) = self
            .client
            .start_confirm_timer(commit_id, requested)
            .map_err(map_client)?;
        Ok(PendingCommit {
            commit_id,
            timeout_s,
            deadline: deadline_rfc3339(timeout_s),
            rollback_targets,
        })
    }

    fn restore(
        &mut self,
        id: &str,
        backup_id: BackupId,
        hashes: &mut Hashes,
    ) -> Result<OpOutcome, OpsError> {
        let module = module_id(&self.client, find_module(&self.modules, id)?)?;
        let (target, new_hash) = self.client.restore(module, backup_id).map_err(map_client)?;
        hashes.new = Some(new_hash);
        Ok(OpOutcome::Restored { target, new_hash })
    }

    fn service_action(&mut self, id: &str, action: ServiceCommand) -> Result<OpOutcome, OpsError> {
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        let (binding, affected) = wiring.binding.ok_or_else(|| OpsError::NoService {
            module: descriptor.id.to_owned(),
        })?;
        let unit = affected.unit;
        Ok(OpOutcome::Serviced(self.act(binding, &unit, action)?))
    }

    /// Ask the monitor to act on a service binding.
    fn act(
        &mut self,
        binding: BindingId,
        unit: &str,
        action: ServiceCommand,
    ) -> Result<ServiceReport, OpsError> {
        let outcome = self
            .client
            .service(binding, action.to_wire())
            .map_err(map_client)?;
        Ok(ServiceReport {
            unit: unit.to_owned(),
            action,
            active: outcome.active,
            detail: outcome.detail,
        })
    }
}

/// Look one module up in the injected registry.
fn find_module<'a>(
    modules: &'a [Box<dyn DynModule>],
    id: &str,
) -> Result<&'a dyn DynModule, OpsError> {
    modules
        .iter()
        .find(|module| module.id() == id)
        .map(AsRef::as_ref)
        .ok_or_else(|| OpsError::UnknownModule { id: id.to_owned() })
}

/// The monitor's id for a module, which is also the proof that the monitor
/// knows about it at all.
fn module_id(
    client: &Client,
    module: &dyn DynModule,
) -> Result<detent_platform::privsep::proto::ModuleId, OpsError> {
    client
        .module_id(module.id())
        .ok_or_else(|| OpsError::UnknownModule {
            id: module.id().to_owned(),
        })
}

/// Resolve, in one read-only pass over the handshake tables, everything a
/// module operation needs: which target to read and write, which validators to
/// run, and which service binding to act on.
///
/// The target is the first one the module's own `backend_detect` accepts for
/// this host — that is how a module with several backends (resolver, network)
/// selects the file that actually applies — falling back to the first target
/// the monitor advertised.
fn wiring(
    client: &Client,
    descriptor: &'static ModuleDescriptor,
    profile: &detent_core::descriptor::HostProfile,
) -> Result<Wiring, OpsError> {
    let no_target = || OpsError::NoTarget {
        module: descriptor.id.to_owned(),
    };
    let module = client
        .module_id(descriptor.id)
        .ok_or_else(|| OpsError::UnknownModule {
            id: descriptor.id.to_owned(),
        })?;

    let advertised: Vec<_> = client
        .targets()?
        .iter()
        .filter(|target| target.module == module)
        .collect();
    let preferred = descriptor
        .targets
        .iter()
        .filter(|target| (target.backend_detect)(profile))
        .find_map(|target| {
            advertised
                .iter()
                .find(|info| info.path == target.path.as_str())
                .copied()
        });
    let chosen = preferred
        .or_else(|| advertised.first().copied())
        .ok_or_else(no_target)?;

    let checks = client
        .tables()
        .map(|ack| ack.checks.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|check| check.module == module)
        .map(|check| (check.id, check.program.clone()))
        .collect();

    let binding = client
        .bindings()?
        .iter()
        .find(|binding| binding.module == module)
        .map(|binding| {
            (
                binding.id,
                AffectedService {
                    unit: binding.unit.clone(),
                    actions: binding
                        .actions
                        .iter()
                        .copied()
                        .filter_map(command)
                        .collect(),
                },
            )
        });

    Ok(Wiring {
        target: chosen.id,
        path: chosen.path.clone(),
        checks,
        binding,
    })
}

/// The [`ServiceCommand`] a wire action corresponds to; `None` for `Status`,
/// which is a query, not an action a module declares.
const fn command(action: WireServiceAction) -> Option<ServiceCommand> {
    match action {
        WireServiceAction::Restart => Some(ServiceCommand::Restart),
        WireServiceAction::Reload => Some(ServiceCommand::Reload),
        WireServiceAction::Start => Some(ServiceCommand::Start),
        WireServiceAction::Stop => Some(ServiceCommand::Stop),
        WireServiceAction::Status => None,
    }
}

/// Configuration files are text. Refuse a target that is not valid UTF-8
/// rather than lossily rewriting bytes the admin put there on purpose.
fn decode(bytes: &[u8], path: &str) -> Result<String, OpsError> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_owned()),
        Err(err) => Err(OpsError::Module(
            ParseError::Malformed {
                message: format!("{path} is not valid UTF-8 at byte {}", err.valid_up_to()),
                span: None,
            }
            .into(),
        )),
    }
}

/// Turn a `ProtoError::Conflict` into the typed conflict error and everything
/// else into [`OpsError::Privsep`].
fn map_client(err: ClientError) -> OpsError {
    match err {
        ClientError::Remote(ProtoError::Conflict { expected, actual }) => {
            OpsError::HashConflict { expected, actual }
        }
        other => OpsError::Privsep(other),
    }
}

/// `timeout_s` from now, as RFC 3339 UTC.
fn deadline_rfc3339(timeout_s: u16) -> String {
    OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(i64::from(timeout_s)))
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{Hashes, command, deadline_rfc3339, decode, map_client};
    use crate::op::ServiceCommand;
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::privsep::proto::{IdKind, ProtoError, ServiceAction as WireServiceAction};
    use detent_platform::privsep::worker::ClientError;

    use crate::error::OpsError;

    #[test]
    fn wire_actions_map_to_commands_except_status() {
        assert_eq!(
            command(WireServiceAction::Restart),
            Some(ServiceCommand::Restart)
        );
        assert_eq!(
            command(WireServiceAction::Reload),
            Some(ServiceCommand::Reload)
        );
        assert_eq!(
            command(WireServiceAction::Start),
            Some(ServiceCommand::Start)
        );
        assert_eq!(command(WireServiceAction::Stop), Some(ServiceCommand::Stop));
        assert_eq!(command(WireServiceAction::Status), None);
    }

    #[test]
    fn decoding_refuses_non_utf8_content() {
        assert_eq!(decode(b"ok\n", "/etc/hosts").ok(), Some("ok\n".to_owned()));
        let err = decode(b"\xff\xfe", "/etc/hosts");
        assert!(matches!(err, Err(OpsError::Module(_))));
        assert!(
            err.err()
                .map(|err| err.to_string())
                .unwrap_or_default()
                .contains("not valid UTF-8")
        );
    }

    #[test]
    fn a_remote_conflict_becomes_the_typed_conflict_error() {
        let expected = Sha256Digest::of(b"a");
        let actual = Sha256Digest::of(b"b");
        let mapped = map_client(ClientError::Remote(ProtoError::Conflict {
            expected,
            actual: Some(actual),
        }));
        assert!(matches!(
            mapped,
            OpsError::HashConflict {
                expected: got_expected,
                actual: Some(got_actual),
            } if got_expected == expected && got_actual == actual
        ));

        let other = map_client(ClientError::Remote(ProtoError::UnknownId {
            kind: IdKind::Target,
            id: 9,
        }));
        assert!(matches!(other, OpsError::Privsep(_)));
        assert!(matches!(
            map_client(ClientError::NotGreeted),
            OpsError::Privsep(_)
        ));
    }

    #[test]
    fn a_deadline_is_rfc3339_utc() {
        let deadline = deadline_rfc3339(90);
        assert!(deadline.ends_with('Z'), "{deadline} is not UTC RFC 3339");
        assert!(!deadline_rfc3339(0).is_empty());
    }

    #[test]
    fn hashes_default_to_nothing_observed() {
        let hashes = Hashes::default();
        assert_eq!(hashes.prev, None);
        assert_eq!(hashes.new, None);
        assert!(format!("{hashes:?}").contains("Hashes"));
    }
}
