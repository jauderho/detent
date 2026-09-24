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
//! # One deliberate deviation, documented at its call site
//!
//! * [`Operation::ServiceStatus`] does **not** go through the monitor. The
//!   privsep protocol answers `ProtoError::Unsupported` for
//!   `ServiceAction::Status` (`privsep::monitor`), and querying a unit's state
//!   needs no privilege, so the engine asks a [`ServiceManager`] directly.
//!   Every *mutating* service action still goes through the monitor.
//!
//! [`Operation::RollbackCommit`] is not a deviation: it forwards to the
//! monitor's `Request::RollbackCommit` exactly as [`Operation::ConfirmCommit`]
//! forwards to `Request::ConfirmCommit`. PLAN §2.5 is explicit that the
//! monitor owns rollback, so the engine never reimplements the restore out of
//! the backup listing here — it only relays the request. An unconfirmed
//! commit still rolls back on its own deadline whether or not anything ever
//! calls [`Operation::RollbackCommit`].

use std::path::PathBuf;
use std::time::Duration;

use detent_core::descriptor::{ModuleDescriptor, ValidationCtx};
use detent_core::module::{DynModule, ParseError};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::Detected;
use detent_platform::privsep::proto::{
    BackupId, BindingId, CheckId, CommitId, PendingService, ProtoError,
    ServiceAction as WireServiceAction, TargetId,
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
    commit_id: Option<u32>,
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
    /// Root of the monitor's mutable state. `None` means the engine cannot
    /// derive paths the request asks for (e.g. `UpdateApply`'s staged
    /// binary) — set via [`OpsEngine::set_state_root`] from the binary's
    /// settings before issuing those operations.
    state_root: Option<PathBuf>,
    next_commit: u32,
    /// Last commit-confirm window armed by this engine, used to rehydrate its
    /// full report without inventing fields from the protocol's id-only query.
    pending_commit: Option<PendingCommit>,
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
            state_root: None,
            next_commit: 1,
            pending_commit: None,
        }
    }

    /// Tell the engine where the monitor's state directory lives.
    ///
    /// `UpdateApply` reads the release tag from
    /// `<state_root>/update/staged/<tag>` to compute the `(len, sha256)` it
    /// sends via [`Client::replace_binary`]; without this set, the operation
    /// is refused up front as `Unsupported`.
    pub fn set_state_root(&mut self, state_root: impl Into<PathBuf>) {
        self.state_root = Some(state_root.into());
    }

    /// What was detected about this host.
    #[must_use]
    pub const fn host(&self) -> &Detected {
        &self.host
    }

    /// Return the full pending-commit report, after checking the monitor's
    /// authoritative id.
    ///
    /// # Errors
    ///
    /// [`OpsError::Privsep`] when the monitor cannot be reached, or
    /// [`OpsError::CommitPending`] if the monitor is pending a commit this
    /// engine did not arm and therefore has no complete report for.
    pub fn pending_commit(&mut self) -> Result<Option<PendingCommit>, OpsError> {
        let active = self.client.pending_commit().map_err(map_client)?;
        let Some(active) = active else {
            self.pending_commit = None;
            return Ok(None);
        };
        self.pending_commit
            .clone()
            .filter(|pending| pending.commit_id == active)
            .map(Some)
            .ok_or(OpsError::CommitPending(active))
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
        let module = op.module().and_then(|id| {
            self.modules
                .iter()
                .find(|module| module.id() == id)
                .map(|module| module.descriptor().id.to_owned())
        });
        let kind = op.kind();
        let mutating = op.is_mutating();
        if let Err(denied) = self.authz.permit(who, &op) {
            let record =
                AuditRecord::new(who, kind, module, AuditResult::Denied).with_error(denied.id);
            // Best-effort: a denial must not be hidden by an audit write failure.
            let _ = self.emit(&record);
            return Err(OpsError::Denied(denied));
        }
        let no_op = mutating && self.apply_is_noop(&op).unwrap_or(false);
        if mutating && !no_op {
            let started = AuditRecord::new(who, kind, module.clone(), AuditResult::Started);
            if let Err(err) = self.emit(&started) {
                return Err(OpsError::AuditUnavailable(err));
            }
        }

        let mut hashes = Hashes::default();
        let result = self.dispatch(op, &mut hashes);
        if !mutating || no_op {
            return result;
        }

        let outcome = match &result {
            Ok(_) => AuditResult::Ok,
            Err(_) => AuditResult::Error,
        };
        let mut record =
            AuditRecord::new(who, kind, module, outcome).with_hashes(hashes.prev, hashes.new);
        if let Some(commit_id) = hashes.commit_id {
            record = record.with_commit_id(commit_id);
        }
        if let Err(err) = &result {
            record = record.with_error(err.message_id());
        }
        // Outcome record is best-effort: the intent record already exists, so
        // a failure here must not hide the operation's own result. `emit`
        // logs the error at `error` level; journald (after M12) is the
        // unrewritable copy.
        let _ = self.emit(&record);
        result
    }

    /// Write one audit record to the sink and to `tracing`.
    ///
    /// Returns `Ok` when the record was persisted. On failure the error is
    /// logged at `error` level and returned so the caller can decide whether
    /// to fail the operation (intent record) or merely log (outcome record).
    /// `tracing` is the unrewritable copy that reaches journald/syslog.
    fn emit(&self, record: &AuditRecord) -> Result<(), crate::audit::AuditError> {
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
            return Err(err);
        }
        Ok(())
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
                hashes.commit_id = Some(commit_id.get());
                let commit = self.client.confirm_commit(commit_id).map_err(map_client)?;
                self.pending_commit = None;
                Ok(OpOutcome::CommitConfirmed { commit_id: commit })
            }
            Operation::RollbackCommit { commit_id } => {
                hashes.commit_id = Some(commit_id.get());
                let (commit, restored) =
                    self.client.rollback_commit(commit_id).map_err(map_client)?;
                self.pending_commit = None;
                Ok(OpOutcome::RolledBack {
                    commit_id: commit,
                    restored,
                })
            }
            Operation::ListBackups { id } => {
                let module = module_id(&self.client, find_module(&self.modules, &id)?)?;
                let backups = self.client.list_backups(module).map_err(map_client)?;
                Ok(OpOutcome::Backups(backups))
            }
            Operation::Restore {
                id,
                backup_id,
                expected_hash,
            } => self.restore(&id, backup_id, expected_hash, hashes),
            Operation::ServiceStatus { id } => self.service_status(&id),
            Operation::ServiceAction { id, action } => self.service_action(&id, action),
            Operation::HostProfile => Ok(OpOutcome::Host(Box::new(HostReport::from(&self.host)))),
            Operation::AuditQuery(query) => Ok(OpOutcome::Audit(
                self.audit.query(&query).map_err(OpsError::from)?,
            )),
            // No `[acme]` config surface yet: cannot order, install, or
            // hot-swap a certificate. Answered as `Unsupported` (`ops-unsupported`)
            // so the API renders a disabled control with a reason; full renewal
            // arrives with the ACME wiring, not here.
            // The front end that owns the TLS listener answers this one from
            // its own resolver; it reaches the engine only if something routes
            // it here by mistake, and then it must fail loudly.
            Operation::CertStatus => Err(OpsError::Unsupported {
                what: "cert_status",
            }),
            Operation::UpdateStatus => Err(OpsError::Unsupported {
                what: "update_status",
            }),
            Operation::CertRenew => Err(OpsError::Unsupported { what: "cert_renew" }),
            // The worker cannot swap a binary it does not own, so this goes
            // through the monitor's `ReplaceBinary` (`ops-unsupported` when
            // the staged file is missing or refused, like `CertRenew`).
            Operation::UpdateApply { version } => self
                .update_apply(&version)
                .map(|()| OpOutcome::UpdateApplied { version }),
        }
    }

    // -- read-only operations ------------------------------------------------

    fn get_module(&mut self, id: &str) -> Result<OpOutcome, OpsError> {
        let module = find_module(&self.modules, id)?;
        let descriptor = module.descriptor();
        let schema = module.schema_json();
        let secret_pointers = module.secret_pointers();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        let contents = self.client.read_target(wiring.target).ok();

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
            secret_pointers,
        })))
    }

    /// Ask the monitor to bridge the tag-named staged release into the
    /// digest-named path, authenticate it, and swap it over the running binary.
    /// The worker only hashes the bytes it asks the monitor to install; the
    /// monitor owns materialization and performs the authenticity gate.
    fn update_apply(&mut self, version: &str) -> Result<(), OpsError> {
        let Some(state_root) = self.state_root.as_ref() else {
            return Err(OpsError::Unsupported {
                what: "update_apply",
            });
        };
        if !is_staged_name(version) {
            tracing::warn!("staged version refused");
            return Err(OpsError::Unsupported {
                what: "update_apply",
            });
        }
        let tag_path = state_root.join("update").join("staged").join(version);
        let bytes = std::fs::read(&tag_path).map_err(|err| {
            tracing::warn!(path = %tag_path.display(), error = %err, "staged binary missing");
            OpsError::Unsupported {
                what: "update_apply",
            }
        })?;
        let len = bytes.len() as u64;
        let sha256 = Sha256Digest::of(&bytes);
        self.client
            .replace_binary(version, len, sha256)
            .map_err(map_client)?;
        Ok(())
    }

    fn plan(&mut self, id: &str, model: &Value) -> Result<PlanReport, OpsError> {
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        let contents = self.client.read_target(wiring.target).map_err(map_client)?;
        let current = decode(&contents.bytes, &wiring.path)?;

        let module = find_module(&self.modules, id)?;
        let ctx = ValidationCtx::new(&self.host.profile);
        let diagnostics = module.validate_json(model, &ctx)?;
        if diagnostics.has_errors() {
            return Err(OpsError::Invalid {
                diagnostics: Box::new(diagnostics),
            });
        }
        let rendered = module.apply_json(&current, model)?;

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

    fn apply_is_noop(&mut self, op: &Operation) -> Result<bool, OpsError> {
        let Operation::Apply {
            id,
            model,
            expected_hash,
            service_action,
            ..
        } = op
        else {
            return Ok(false);
        };
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let ctx = ValidationCtx::new(&self.host.profile);
        if find_module(&self.modules, id)?
            .validate_json(model, &ctx)?
            .has_errors()
        {
            return Ok(false);
        }
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
        if service_action.is_some() && wiring.binding.is_none() {
            return Ok(false);
        }
        let contents = self.client.read_target(wiring.target).map_err(map_client)?;
        if expected_hash.is_some_and(|expected| expected != contents.digest) {
            return Ok(false);
        }
        let current = decode(&contents.bytes, &wiring.path)?;
        let rendered = find_module(&self.modules, id)?.apply_json(&current, model)?;
        Ok(current == rendered)
    }

    // -- mutating operations -------------------------------------------------

    #[allow(clippy::too_many_lines)]
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

        // 4. Render, then run every declared external validator against the
        // exact bytes that would be written. Apply fails closed on refusal or
        // validator execution failure; no target or service is touched.
        let current = decode(&contents.bytes, &wiring.path)?;
        let rendered = find_module(&self.modules, id)?.apply_json(&current, model)?;
        if current == rendered {
            return Ok(ApplyReport {
                module: descriptor.id.to_owned(),
                path: wiring.path,
                prev_hash: Some(contents.digest),
                new_hash: contents.digest,
                created: false,
                backed_up: false,
                service: None,
                commit: None,
            });
        }
        let checks = self.run_checks(&wiring, rendered.as_bytes());

        let commit_required = descriptor.commit_confirm || confirm.is_some();
        if commit_required && let Some(commit) = self.client.pending_commit().map_err(map_client)? {
            return Err(OpsError::CommitPending(commit));
        }
        if let Some(report) = checks.iter().find(|report| !report.ran || !report.passed) {
            return Err(OpsError::CheckFailed {
                program: report.program.clone(),
                detail: report.detail.clone(),
            });
        }
        let receipt = self
            .client
            .write_target(wiring.target, Some(contents.digest), rendered.into_bytes())
            .map_err(map_client)?;
        hashes.prev = receipt.prev_digest;
        hashes.new = Some(receipt.new_digest);
        let pending_service = match (service_action, wiring.binding.as_ref()) {
            (Some(action), Some(&(binding, _))) => Some(PendingService {
                binding,
                action: action.to_wire(),
            }),
            _ => None,
        };

        // 5. Arm commit-confirm immediately after the successful write and
        //    before touching the service, including when the monitor made no
        //    backup so the no-backup refusal below can clear the window.
        let commit = if commit_required {
            let commit = self.arm_commit(confirm, pending_service)?;
            hashes.commit_id = Some(commit.commit_id.get());
            self.pending_commit = Some(commit.clone());
            Some(commit)
        } else {
            None
        };
        if commit_required && !receipt.backed_up {
            if let Some(commit) = commit.as_ref()
                && self.client.rollback_commit(commit.commit_id).is_ok()
            {
                self.pending_commit = None;
            }
            return Err(OpsError::NoBackup);
        }

        // 6. Act on the service. Step 2 established that a binding exists
        //    whenever an action was asked for.
        let service = match (service_action, wiring.binding.as_ref()) {
            (Some(action), Some(&(binding, ref affected))) => {
                match self.act(binding, &affected.unit, action) {
                    Ok(service) => Some(service),
                    Err(err) => {
                        if let Some(commit) = commit.as_ref()
                            && self.client.rollback_commit(commit.commit_id).is_ok()
                        {
                            self.pending_commit = None;
                        }
                        return Err(err);
                    }
                }
            }
            _ => None,
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
    fn arm_commit(
        &mut self,
        confirm: Option<Duration>,
        service: Option<PendingService>,
    ) -> Result<PendingCommit, OpsError> {
        let commit_id = CommitId(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);
        let requested =
            u16::try_from(confirm.unwrap_or(DEFAULT_CONFIRM).as_secs()).unwrap_or(u16::MAX);
        let (timeout_s, rollback_targets) = self
            .client
            .start_confirm_timer(commit_id, requested, service)
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
        expected_hash: Option<Sha256Digest>,
        hashes: &mut Hashes,
    ) -> Result<OpOutcome, OpsError> {
        let module = module_id(&self.client, find_module(&self.modules, id)?)?;
        let descriptor = find_module(&self.modules, id)?.descriptor();
        let wiring = wiring(&self.client, descriptor, &self.host.profile)?;
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

/// True when `name` is a safe single path component for the staged layout:
/// a release tag (`v1.2.3`) or a hex digest — never a path.
fn is_staged_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.bytes().all(|b| b == b'.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
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
    use super::{Hashes, command, deadline_rfc3339, decode, is_staged_name, map_client};
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

    #[test]
    fn staged_names_are_single_components_never_dots() {
        assert!(is_staged_name("v1.2.3"));
        assert!(is_staged_name(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_staged_name(""));
        assert!(!is_staged_name("."));
        assert!(!is_staged_name(".."));
        assert!(!is_staged_name("..."));
        assert!(!is_staged_name("../../etc/shadow"));
        assert!(!is_staged_name("v1.2.3/.."));
    }
}
