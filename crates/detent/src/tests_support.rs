//! Fixtures shared by this crate's unit tests: a fake module, a leaked
//! descriptor pointing at a temporary file, one value of every [`OpOutcome`]
//! variant, and a live [`Session`] over a real monitor.
//!
//! The module registry's real descriptors name real absolute paths
//! (`/etc/hosts`), and a test must never write those, so anything that mutates
//! is driven through a descriptor built here instead — the pattern
//! `crates/detent-ops/tests/engine.rs` established.

use std::path::{Path, PathBuf};

use detent_core::descriptor::{
    ExternalCheck, HostProfile, InitSystem, ModuleDescriptor, Os, Owner, PathSpec,
    ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind, UnitNames, Upstream,
    ValidationCtx,
};
use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
use detent_core::module::{DynError, DynModule, ModelError};
use detent_ops::report::{
    AffectedService, ApplyReport, CheckReport, HostReport, ModuleView, OpOutcome, PendingCommit,
    PlanReport, ServiceReport,
};
use detent_ops::{AuditRecord, AuditResult, Identity, OpKind, ServiceCommand};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::Detected;
use detent_platform::privsep::proto::{BackupId, BackupInfo, CommitId, TargetId};
use detent_platform::service::{ServiceStatus, State};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::run::{Session, Settings};

/// The id every fixture module uses.
pub const MODULE: &str = "fake";

/// A module whose model is `{"text": "<the whole file>"}`.
pub struct FakeModule {
    /// The descriptor this module answers with.
    pub descriptor: &'static ModuleDescriptor,
    /// When true, `defaults_json` fails, which is otherwise unreachable.
    pub broken: bool,
}

impl DynModule for FakeModule {
    fn id(&self) -> &'static str {
        self.descriptor.id
    }
    fn clone_box(&self) -> Box<dyn DynModule> {
        Box::new(Self {
            descriptor: self.descriptor,
            broken: self.broken,
        })
    }

    fn descriptor(&self) -> &'static ModuleDescriptor {
        self.descriptor
    }

    fn schema_json(&self) -> Value {
        json!({"type": "object", "properties": {"text": {"type": "string"}}})
    }

    fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError> {
        Ok(json!({ "text": src }))
    }

    fn apply_json(&self, _src: &str, model: &Value) -> Result<String, DynError> {
        model
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                DynError::Model(ModelError::Shape {
                    message: "missing field `text`".to_owned(),
                })
            })
    }

    fn validate_json(
        &self,
        model: &Value,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<Diagnostics, DynError> {
        let text = model
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut out = Diagnostics::new();
        if text.contains("BAD") {
            out.push(Diagnostic::new(
                Severity::Error,
                MessageId::new("hosts-no-hostnames"),
            ));
        }
        Ok(out)
    }

    fn defaults_json(&self, _profile: &HostProfile) -> Result<Value, DynError> {
        if self.broken {
            return Err(DynError::Model(ModelError::Shape {
                message: "this module has no defaults".to_owned(),
            }));
        }
        Ok(json!({"text": "default\n"}))
    }
}

/// Leaks `value` so a descriptor can hold it for the process lifetime.
fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// A descriptor with one target at `path`, one service and one validator.
pub fn descriptor(path: &Path) -> &'static ModuleDescriptor {
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
    static SERVICES: &[ServiceBinding] = &[ServiceBinding {
        units: UnitNames {
            systemd: &["fake.service"],
            openrc: &["fake"],
            bsdrc: &["fake"],
        },
        actions: &[CoreServiceAction::Restart],
    }];
    static CHECKS: &[ExternalCheck] = &[];

    let targets: &'static [Target] = leak(vec![Target {
        path: PathSpec::new(Box::leak(path.display().to_string().into_boxed_str())),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }])
    .as_slice();

    leak(ModuleDescriptor {
        id: MODULE,
        display_name_id: MessageId::new("hosts-name"),
        targets,
        upstream: UPSTREAM,
        services: SERVICES,
        checks: CHECKS,
        commit_confirm: false,
        security_notes: &[],
    })
}

/// A live session over a real monitor thread, rooted in a temporary directory.
pub struct Harness {
    /// The session under test.
    pub session: Session,
    /// The file the fixture module manages.
    pub target: PathBuf,
    /// The state root the monitor was given.
    pub state_root: PathBuf,
    /// Kept so the directory outlives the harness.
    _dir: TempDir,
}

impl Harness {
    /// Starts a monitor and an engine over one fixture module.
    ///
    /// # Errors
    ///
    /// Whatever the temporary directory or the session start reports.
    pub fn start(initial: &[u8], dryrun: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let target = dir.path().join("target.conf");
        std::fs::write(&target, initial)?;
        let state_root = dir.path().join("state");
        let settings = Settings {
            state_root: state_root.clone(),
            config_path: dir.path().join("detent.toml"),
        };
        let descriptor = descriptor(&target);
        let registry = registry(descriptor, false);
        let session = Session::start(
            &settings,
            Detected::default(),
            registry,
            &[descriptor],
            dryrun,
        )?;
        Ok(Self {
            session,
            target,
            state_root,
            _dir: dir,
        })
    }

    /// The bytes currently on disk.
    ///
    /// # Errors
    ///
    /// Whatever the read reports.
    pub fn contents(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.target)
    }
}

/// A one-module registry over `descriptor`.
pub fn registry(descriptor: &'static ModuleDescriptor, broken: bool) -> Vec<Box<dyn DynModule>> {
    vec![Box::new(FakeModule { descriptor, broken })]
}

/// A digest of some bytes, for a fixture.
fn digest() -> Sha256Digest {
    Sha256Digest::of(b"fixture")
}

/// A `Planned` report, changed or unchanged: the `OpOutcome` wrapper is
/// built by the caller, so `dry_run` needs no `unreachable!` arm and this
/// file's error paths stay at zero.
pub fn planned(would_change: bool) -> PlanReport {
    let old = "old\n";
    let new = if would_change { "new\n" } else { old };
    let hunks = detent_ops::diff::diff(old, new, detent_ops::diff::DEFAULT_CONTEXT);
    PlanReport {
        module: MODULE.to_owned(),
        path: "/etc/fake.conf".to_owned(),
        unified_diff: detent_ops::diff::render_unified("/etc/fake.conf", "/etc/fake.conf", &hunks),
        diff: hunks,
        rendered: new.to_owned(),
        affected_services: vec![AffectedService {
            unit: "fake.service".to_owned(),
            actions: vec![ServiceCommand::Restart],
        }],
        checks: vec![
            CheckReport {
                program: "/nonexistent/check".to_owned(),
                ran: false,
                passed: false,
                exit_code: None,
                detail: "not installed".to_owned(),
            },
            CheckReport {
                program: "/nonexistent/check2".to_owned(),
                ran: true,
                passed: true,
                exit_code: Some(0),
                detail: "ok".to_owned(),
            },
        ],
        diagnostics: diagnostics(),
        current_hash: digest(),
        would_change,
    }
}

/// One warning diagnostic.
fn diagnostics() -> Diagnostics {
    std::iter::once(Diagnostic::new(
        Severity::Warning,
        MessageId::new("hosts-no-hostnames"),
    ))
    .collect()
}

/// A `Module` outcome, with or without a parsed model.
pub fn module_view(with_model: bool) -> OpOutcome {
    let descriptor = descriptor(Path::new("/etc/fake.conf"));
    OpOutcome::Module(Box::new(ModuleView {
        descriptor,
        schema: json!({"type": "object"}),
        model: with_model.then(|| json!({"text": "a\n"})),
        current_hash: with_model.then(digest),
        diagnostics: diagnostics(),
        secret_pointers: &[],
    }))
}

/// An `Applied` outcome with no service action and no armed commit: the
/// skip-branches of `output::applied` that `every_outcome` never takes.
pub fn applied_without_commit() -> OpOutcome {
    OpOutcome::Applied(Box::new(ApplyReport {
        module: MODULE.to_owned(),
        path: "/etc/fake.conf".to_owned(),
        prev_hash: None,
        new_hash: digest(),
        created: true,
        backed_up: false,
        service: None,
        commit: None,
    }))
}

/// The host profile `every_outcome` renders: Linux/systemd, no probed
/// service versions (add some for the service-version line).
pub fn host_profile() -> HostProfile {
    HostProfile {
        os: Os::Linux,
        init: InitSystem::Systemd,
        hostname: "box".to_owned(),
        service_versions: std::collections::BTreeMap::new(),
        ram_mib: 512,
    }
}

pub fn every_outcome() -> Vec<OpOutcome> {
    let descriptor = descriptor(Path::new("/etc/fake.conf"));
    let host = Detected {
        profile: host_profile(),
        facts: detent_platform::host::HostFacts {
            notes: vec!["a note".to_owned()],
            ..detent_platform::host::HostFacts::default()
        },
    };

    vec![
        OpOutcome::Modules(vec![descriptor]),
        module_view(true),
        OpOutcome::Validated(diagnostics()),
        OpOutcome::Planned(Box::new(planned(true))),
        OpOutcome::Applied(Box::new(ApplyReport {
            module: MODULE.to_owned(),
            path: "/etc/fake.conf".to_owned(),
            prev_hash: Some(digest()),
            new_hash: digest(),
            created: false,
            backed_up: true,
            service: Some(ServiceReport {
                unit: "fake.service".to_owned(),
                action: ServiceCommand::Restart,
                active: true,
                detail: "running".to_owned(),
            }),
            commit: Some(PendingCommit {
                commit_id: CommitId(1),
                timeout_s: 90,
                deadline: "2026-09-04T00:00:00Z".to_owned(),
                rollback_targets: 1,
            }),
        })),
        OpOutcome::CommitConfirmed {
            commit_id: CommitId(1),
        },
        OpOutcome::RolledBack {
            commit_id: CommitId(1),
            restored: 2,
        },
        OpOutcome::Backups(vec![BackupInfo {
            id: BackupId(0),
            target: TargetId(0),
            name: "20260904T000000Z-abcdef12".to_owned(),
            created_unix_s: 1_772_000_000,
            digest: digest(),
            len: 42,
        }]),
        OpOutcome::Restored {
            target: TargetId(0),
            new_hash: digest(),
        },
        OpOutcome::Status(ServiceStatus {
            unit: "fake.service".to_owned(),
            state: State::Active,
            enabled: Some(true),
            since: None,
        }),
        OpOutcome::Serviced(ServiceReport {
            unit: "fake.service".to_owned(),
            action: ServiceCommand::Reload,
            active: false,
            detail: "stopped".to_owned(),
        }),
        OpOutcome::Host(Box::new(HostReport::from(&host))),
        OpOutcome::Audit(vec![
            AuditRecord::new(
                &Identity::local("root"),
                OpKind::Apply,
                Some(MODULE.to_owned()),
                AuditResult::Ok,
            ),
            AuditRecord::new(
                &Identity::local("root"),
                OpKind::Restore,
                None,
                AuditResult::Error,
            )
            .with_error(MessageId::new("ops-privsep-failed")),
        ]),
    ]
}

/// A withheld mutation, with or without the plan an `Apply` would have shown.
pub fn dry_run(with_plan: bool) -> crate::run::DryRun {
    crate::run::DryRun {
        dryrun: true,
        operation: if with_plan {
            OpKind::Apply
        } else {
            OpKind::Restore
        },
        module: Some(MODULE.to_owned()),
        plan: with_plan.then(|| planned(true)),
    }
}
/// A withheld mutation carrying an explicit plan (which `dry_run(bool)`
/// cannot build for the no-change branch: its fixture always changes).
pub fn dry_run_plan(plan: PlanReport) -> crate::run::DryRun {
    crate::run::DryRun {
        dryrun: true,
        operation: OpKind::Apply,
        module: Some(MODULE.to_owned()),
        plan: Some(plan),
    }
}

/// A writer that fails only after `allow` successful writes, so a renderer's
/// *second* and later `?` are reachable — a writer that fails immediately only
/// ever exercises the first one.
#[derive(Debug)]
pub struct FailAfter {
    remaining: std::cell::Cell<usize>,
}

impl FailAfter {
    /// Fails on write number `allow + 1`.
    pub const fn new(allow: usize) -> Self {
        Self {
            remaining: std::cell::Cell::new(allow),
        }
    }
}

impl std::io::Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.remaining.get().checked_sub(1) {
            Some(left) => {
                self.remaining.set(left);
                Ok(buf.len())
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The module view an outcome carries, or `None` for any other outcome.
pub fn module_of(outcome: OpOutcome) -> Option<Box<ModuleView>> {
    match outcome {
        OpOutcome::Module(view) => Some(view),
        _ => None,
    }
}

/// The plan an outcome carries, or `None` for any other outcome.
pub fn plan_of(outcome: OpOutcome) -> Option<Box<PlanReport>> {
    match outcome {
        OpOutcome::Planned(plan) => Some(plan),
        _ => None,
    }
}

/// The backup listing an outcome carries, or `None` for any other outcome.
pub fn backups_of(outcome: OpOutcome) -> Option<Vec<BackupInfo>> {
    match outcome {
        OpOutcome::Backups(backups) => Some(backups),
        _ => None,
    }
}

/// The audit records an outcome carries, or `None` for any other outcome.
pub fn records_of(outcome: OpOutcome) -> Option<Vec<AuditRecord>> {
    match outcome {
        OpOutcome::Audit(records) => Some(records),
        _ => None,
    }
}

/// The outcome an execution produced, or `None` when `--dryrun` withheld it.
pub fn ran_of(executed: crate::run::Executed) -> Option<OpOutcome> {
    match executed {
        crate::run::Executed::Ran(outcome) => Some(outcome),
        crate::run::Executed::WouldRun(_) => None,
    }
}

/// What a dry run withheld, or `None` when the operation really ran.
pub fn withheld_of(executed: crate::run::Executed) -> Option<Box<crate::run::DryRun>> {
    match executed {
        crate::run::Executed::WouldRun(report) => Some(report),
        crate::run::Executed::Ran(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FailAfter, backups_of, dry_run, module_of, plan_of, ran_of, records_of, withheld_of,
    };
    use detent_ops::report::OpOutcome;
    use detent_platform::privsep::proto::CommitId;
    use std::io::Write as _;

    /// Each extractor answers `None` for an outcome that is not its own, which
    /// is the arm every positive use of it skips.
    #[test]
    fn the_extractors_only_match_their_own_outcome() {
        let other = || OpOutcome::CommitConfirmed {
            commit_id: CommitId(1),
        };
        assert!(module_of(other()).is_none());
        assert!(plan_of(other()).is_none());
        assert!(backups_of(other()).is_none());
        assert!(records_of(other()).is_none());
        assert!(ran_of(crate::run::Executed::WouldRun(Box::new(dry_run(false)))).is_none());
        assert!(withheld_of(crate::run::Executed::Ran(other())).is_none());
    }

    #[test]
    fn the_partial_writer_fails_only_after_its_allowance() {
        let mut writer = FailAfter::new(1);
        assert!(writer.write_all(b"first").is_ok());
        assert!(writer.write_all(b"second").is_err());
        assert!(writer.flush().is_ok());
        assert!(format!("{writer:?}").contains("FailAfter"));
    }
}
