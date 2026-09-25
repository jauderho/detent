//! End-to-end tests for [`OpsEngine`] (PLAN §2.5, Phase 3 tasks 1-2).
//!
//! Every test drives a **real** `privsep::monitor` in a background thread over
//! a real `Channel::pair`, rooted in a `TempDir` — the pattern
//! `crates/detent-platform/tests/privsep_e2e.rs` established. Mocking the
//! `Client` would test the engine against a fiction; this way an `Apply`
//! really writes a file, a backup really appears, and the commit-confirm timer
//! really expires.
//!
//! The module is a fake whose model is `{"text": "<the whole file>"}`, so a
//! test controls parse/render/validate outcomes by choosing the text: a body
//! containing `BAD` produces an error diagnostic, `WARN` a warning, and
//! `UNPARSEABLE` makes `parse` fail.
//!
//! The crate denies `unwrap`/`expect`/`panic` in every target, tests included,
//! so each test returns [`TestResult`] and propagates with `?`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, InitSystem, ModuleDescriptor, Os,
    Owner, PathSpec, ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind,
    UnitNames, Upstream, ValidationCtx,
};
use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
use detent_core::module::{DynError, DynModule, ModelError, ParseError};
use detent_ops::audit::{AuditError, AuditRecord, AuditSink};
use detent_ops::{
    AllowAll, AuditQuery, AuditResult, Authz, CaptureAudit, Denied, FileAudit, Identity,
    IdentityKind, OpKind, OpOutcome, Operation, OpsEngine, OpsError, ServiceCommand,
};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::{Detected, Distro, HostFacts, NetworkBackend};
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{
    CheckRunner, ExitReason, HookError, Hooks, Monitor, MonitorError, ServiceControl,
};
use detent_platform::privsep::proto::{
    BackupId, CheckId, CheckOutcome, CommitId, ProtoError, ServiceOutcome,
};
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::{Client, ClientError};
use detent_platform::service::{ActionOutcome, ServiceError, ServiceManager, ServiceStatus, State};
use serde_json::{Value, json};
use tempfile::TempDir;

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// What a background monitor thread returns.
type ServeResult = Result<ExitReason, MonitorError>;

// ---------------------------------------------------------------------------
// A fake module
// ---------------------------------------------------------------------------

struct FakeModule {
    descriptor: &'static ModuleDescriptor,
}

impl DynModule for FakeModule {
    fn id(&self) -> &'static str {
        self.descriptor.id
    }
    fn clone_box(&self) -> Box<dyn DynModule> {
        Box::new(Self {
            descriptor: self.descriptor,
        })
    }

    fn descriptor(&self) -> &'static ModuleDescriptor {
        self.descriptor
    }

    fn schema_json(&self) -> Value {
        json!({"type": "object", "properties": {"text": {"type": "string"}}})
    }

    fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError> {
        if src.contains("UNPARSEABLE") {
            return Err(DynError::Parse(ParseError::Malformed {
                message: "planted parse failure".to_owned(),
                span: None,
            }));
        }
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
                MessageId::new("fake-bad-value"),
            ));
        }
        if text.contains("WARN") {
            out.push(Diagnostic::new(
                Severity::Warning,
                MessageId::new("fake-warn-value"),
            ));
        }
        Ok(out)
    }

    fn defaults_json(&self, _profile: &HostProfile) -> Result<Value, DynError> {
        Ok(json!({"text": "default\n"}))
    }
}

// ---------------------------------------------------------------------------
// Descriptor fixture
// ---------------------------------------------------------------------------

const fn always(_: &HostProfile) -> bool {
    true
}

const fn never(_: &HostProfile) -> bool {
    false
}

static UPSTREAM: Upstream = Upstream {
    project: "test",
    repo_url: "https://example.invalid/test",
    tracked_version: "1.0",
    release_feed: None,
    docs: &[],
};

fn leak_str(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// Which targets the descriptor under test declares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Targets {
    /// One real target.
    #[default]
    One,
    /// A decoy first target whose `backend_detect` is false, then the real
    /// one, so the engine must select on the detector rather than on order.
    DecoyThenReal,
    /// None at all.
    None,
}

/// How the descriptor under test is shaped.
#[derive(Debug, Clone, Copy, Default)]
struct Shape {
    commit_confirm: bool,
    /// Declare a service binding (restart only).
    service: bool,
    /// Declare one external check.
    check: bool,
    /// Which targets to declare.
    targets: Targets,
}

fn build_descriptor(id: &'static str, target: &Path, shape: Shape) -> &'static ModuleDescriptor {
    let real = Target {
        path: PathSpec::new(leak_str(target.display().to_string())),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    };
    let mut list = Vec::new();
    if shape.targets == Targets::DecoyThenReal {
        list.push(Target {
            path: PathSpec::new(leak_str(
                target.with_extension("decoy").display().to_string(),
            )),
            backend_detect: never,
            ..real
        });
    }
    if shape.targets != Targets::None {
        list.push(real);
    }
    let targets: &'static [Target] = leak(list).as_slice();

    let services: &'static [ServiceBinding] = if shape.service {
        leak(vec![ServiceBinding {
            units: UnitNames {
                systemd: &["fake.service"],
                openrc: &["fake"],
                bsdrc: &["fake"],
            },
            actions: leak(vec![CoreServiceAction::Restart]).as_slice(),
        }])
        .as_slice()
    } else {
        &[]
    };

    let checks: &'static [ExternalCheck] = if shape.check {
        leak(vec![ExternalCheck {
            program: PathSpec::new("/nonexistent/detent-ops-check"),
            args: leak(vec![ArgTemplate::Literal("-p"), ArgTemplate::TempFile]).as_slice(),
            expects: CheckExpectation::ExitZero,
        }])
        .as_slice()
    } else {
        &[]
    };

    leak(ModuleDescriptor {
        id,
        display_name_id: MessageId::new("fake-name"),
        targets,
        upstream: UPSTREAM,
        services,
        checks,
        commit_confirm: shape.commit_confirm,
        security_notes: &[],
    })
}

// ---------------------------------------------------------------------------
// Collaborators
// ---------------------------------------------------------------------------

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

struct OkServices;
impl ServiceControl for OkServices {
    fn service(
        &self,
        _binding: &ServiceBinding,
        _action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        Ok(ServiceOutcome {
            binding: detent_platform::privsep::proto::BindingId(0),
            active: true,
            detail: "running".to_owned(),
        })
    }
}

static OK_CHECKS: OkChecks = OkChecks;
static OK_SERVICES: OkServices = OkServices;

/// A [`ServiceManager`] that reports a fixed status and refuses mutation, so
/// `ServiceStatus` is testable without an init system.
struct FakeServices {
    status: Result<ServiceStatus, ServiceError>,
}

impl ServiceManager for FakeServices {
    fn status(&self, _units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
        self.status.clone()
    }

    fn act(
        &self,
        _units: &UnitNames,
        _action: CoreServiceAction,
    ) -> Result<ActionOutcome, ServiceError> {
        Err(ServiceError::Unsupported(
            "the engine never mutates through a ServiceManager".to_owned(),
        ))
    }
}

fn fake_services() -> Box<dyn ServiceManager> {
    Box::new(FakeServices {
        status: Ok(ServiceStatus {
            unit: "fake.service".to_owned(),
            state: State::Active,
            enabled: Some(true),
            since: None,
        }),
    })
}

/// A manager that reports the backend as absent, which is what a host with no
/// `systemctl` looks like.
fn broken_services() -> Box<dyn ServiceManager> {
    Box::new(FakeServices {
        status: Err(ServiceError::Unavailable("no systemctl".to_owned())),
    })
}

/// Refuses everything, to exercise the denial path.
struct DenyAll;
impl Authz for DenyAll {
    fn permit(&self, _who: &Identity, _op: &Operation) -> Result<(), Denied> {
        Err(Denied::with_scope(
            MessageId::new("ops-denied-test"),
            "write",
        ))
    }
}

/// Shares one [`CaptureAudit`] between the engine and the test.
struct SharedAudit(Arc<CaptureAudit>);

impl AuditSink for SharedAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.record(record)
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        self.0.query(query)
    }
}

fn host() -> Detected {
    Detected {
        profile: HostProfile {
            os: Os::Linux,
            init: InitSystem::Systemd,
            hostname: "detent-test".to_owned(),
            service_versions: std::collections::BTreeMap::new(),
            ram_mib: 1024,
        },
        facts: HostFacts {
            distro: Some(Distro {
                id: "debian".to_owned(),
                id_like: Vec::new(),
                version_id: Some("12".to_owned()),
            }),
            network_backend: NetworkBackend::Ifupdown,
            ..HostFacts::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// How the harness is wired.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Setup {
    shape: Shape,
    /// Give the monitor working check/service collaborators.
    hooks: bool,
    /// Refuse every operation.
    deny: bool,
    /// Register the module under a name the allow-list does not know.
    registry_mismatch: bool,
    /// Which service manager the engine gets.
    services: Services,
    /// Disable retained backups, leaving commit-confirm nothing to restore.
    disable_backups: bool,
}

/// Which [`ServiceManager`] the engine is built with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Services {
    /// Reports a running unit.
    #[default]
    Running,
    /// Reports the backend as absent, as a host with no `systemctl` would.
    Unavailable,
}

struct Harness {
    engine: OpsEngine,
    audit: Arc<CaptureAudit>,
    handle: Option<thread::JoinHandle<ServeResult>>,
    target: PathBuf,
    _dir: TempDir,
}

/// The caller every harness test acts as.
fn who() -> Identity {
    Identity::local("root")
}

impl Harness {
    fn run(&mut self, op: Operation) -> Result<OpOutcome, OpsError> {
        self.engine.execute(op, &who())
    }

    fn contents(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(std::fs::read_to_string(&self.target)?)
    }

    fn digest(&self) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        Ok(Sha256Digest::of(&std::fs::read(&self.target)?))
    }

    fn records(&self) -> Vec<AuditRecord> {
        self.audit.records()
    }

    /// Shut the monitor down and confirm it exited cleanly.
    fn finish(mut self) -> TestResult {
        self.engine.shutdown()?;
        if let Some(handle) = self.handle.take() {
            let joined = handle.join().map_err(|_| "the monitor thread panicked")?;
            assert_eq!(joined.ok(), Some(ExitReason::Shutdown));
        }
        Ok(())
    }
}

fn harness(initial: &[u8], setup: Setup) -> Result<Harness, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, initial)?;

    let allow_descriptor = build_descriptor("fake", &target, setup.shape);
    let mut config = Config::with_state_root(root.join("state"));
    let staging_dir = root.join("monitor-staging");
    if setup.disable_backups {
        config.keep_backups = 0;
    }
    let allow = Allowlist::from_modules(&[allow_descriptor], &config)?;

    let (monitor_end, worker_end) = Channel::pair()?;
    // Point the in-test swap at this harness's own temp target instead of the
    // real test binary: the monitor swaps `current_exe` by default, and these
    // tests run in parallel, so a global override would steer every monitor
    // at once. A per-monitor field keeps each swap inside its own tempdir.
    let binary_target = target.clone();
    let trust = update_trust()?;
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let hooks = if setup.hooks {
            Hooks {
                checks: &OK_CHECKS,
                services: &OK_SERVICES,
            }
        } else {
            Hooks::default()
        };
        let mut monitor = Monitor::new(allow, hooks);
        monitor.set_module_registry(vec![Box::new(FakeModule {
            descriptor: allow_descriptor,
        })]);
        monitor.set_staging_dir(staging_dir);
        monitor.set_binary_override(binary_target);
        monitor.set_update_trust(trust);
        monitor.serve(&mut channel)
    });

    let mut client = Client::new(worker_end);
    client.hello()?;

    // The registry may deliberately advertise a module the monitor's
    // allow-list has never heard of, which is how "the module exists but the
    // monitor does not know it" is reachable.
    let registered = if setup.registry_mismatch {
        build_descriptor("stranger", &target, setup.shape)
    } else {
        allow_descriptor
    };
    let modules: Vec<Box<dyn DynModule>> = vec![Box::new(FakeModule {
        descriptor: registered,
    })];

    let audit = Arc::new(CaptureAudit::new());
    let authz: Box<dyn Authz> = if setup.deny {
        Box::new(DenyAll)
    } else {
        Box::new(AllowAll)
    };
    let services = match setup.services {
        Services::Running => fake_services(),
        Services::Unavailable => broken_services(),
    };
    let engine = OpsEngine::new(
        modules,
        client,
        host(),
        Box::new(SharedAudit(Arc::clone(&audit))),
        authz,
        services,
    );

    Ok(Harness {
        engine,
        audit,
        handle: Some(handle),
        target,
        _dir: dir,
    })
}

/// The id the registry advertises, which is `fake` unless the setup asked for
/// a mismatch.
const MODULE: &str = "fake";

const UPDATE_FIXTURE_TAG: &str = "v0.0.2";

fn update_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../detent-update/tests/fixtures")
}

fn update_trust() -> Result<detent_update::trust::TrustRoot, Box<dyn std::error::Error>> {
    let root = std::fs::read_to_string(update_fixtures().join("fulcio-root.pem"))?;
    let rekor = std::fs::read_to_string(update_fixtures().join("rekor-pub.pem"))?;
    Ok(detent_update::trust::from_pems(&root, &rekor)?)
}

fn plant_update(state_root: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(update_fixtures().join("binary.bin"))?;
    let dir = state_root.join("update").join("staged");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(UPDATE_FIXTURE_TAG), &bytes)?;
    std::fs::copy(
        update_fixtures().join("valid.json"),
        dir.join(format!("{UPDATE_FIXTURE_TAG}.sigstore.json")),
    )?;
    Ok(bytes)
}

fn apply(text: &str, expected: Option<Sha256Digest>) -> Operation {
    Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({ "text": text }),
        expected_hash: expected,
        service_action: None,
        confirm: None,
    }
}

// ---------------------------------------------------------------------------
// Read-only operations
// ---------------------------------------------------------------------------

#[test]
fn list_modules_returns_every_registered_descriptor() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let outcome = fx.run(Operation::ListModules)?;
    let ids = match outcome {
        OpOutcome::Modules(ref modules) => modules.iter().map(|m| m.id).collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    assert_eq!(ids, vec!["fake"]);
    // Read-only operations are not audited.
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn get_module_returns_the_schema_model_and_diagnostics() -> TestResult {
    let mut fx = harness(b"WARN me\n", Setup::default())?;
    let outcome = fx.run(Operation::GetModule {
        id: MODULE.to_owned(),
    })?;
    let OpOutcome::Module(view) = outcome else {
        return Err("GetModule must answer with a module view".into());
    };
    assert_eq!(view.descriptor.id, "fake");
    assert!(!view.schema.is_null());
    assert_eq!(
        view.model
            .as_ref()
            .and_then(|model| model.pointer("/text"))
            .and_then(Value::as_str),
        Some("WARN me\n")
    );
    assert_eq!(view.current_hash, Some(fx.digest()?));
    assert_eq!(view.diagnostics.len(), 1);
    assert!(!view.diagnostics.has_errors());
    fx.finish()
}

#[test]
fn get_module_reports_no_model_when_the_target_is_missing() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    std::fs::remove_file(&fx.target)?;
    let outcome = fx.run(Operation::GetModule {
        id: MODULE.to_owned(),
    })?;
    let OpOutcome::Module(view) = outcome else {
        return Err("GetModule must answer with a module view".into());
    };
    assert_eq!(view.model, None);
    assert_eq!(view.current_hash, None);
    assert!(view.diagnostics.is_empty());
    fx.finish()
}

#[test]
fn get_module_surfaces_a_parse_failure() -> TestResult {
    let mut fx = harness(b"UNPARSEABLE\n", Setup::default())?;
    let err = fx.run(Operation::GetModule {
        id: MODULE.to_owned(),
    });
    assert!(matches!(err, Err(OpsError::Module(_))));
    fx.finish()
}

#[test]
fn an_unknown_module_id_is_refused_before_any_io() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    for op in [
        Operation::GetModule {
            id: "nope".to_owned(),
        },
        Operation::Validate {
            id: "nope".to_owned(),
            model: json!({}),
        },
        Operation::Plan {
            id: "nope".to_owned(),
            model: json!({}),
        },
        Operation::ListBackups {
            id: "nope".to_owned(),
        },
        Operation::ServiceStatus {
            id: "nope".to_owned(),
        },
        Operation::ServiceAction {
            id: "nope".to_owned(),
            action: ServiceCommand::Restart,
        },
        Operation::Restore {
            id: "nope".to_owned(),
            backup_id: BackupId(0),
            expected_hash: None,
        },
        Operation::Apply {
            id: "nope".to_owned(),
            model: json!({}),
            expected_hash: None,
            service_action: None,
            confirm: None,
        },
    ] {
        assert!(matches!(fx.run(op), Err(OpsError::UnknownModule { .. })));
    }
    assert_eq!(fx.contents()?, "v1\n");
    fx.finish()
}

#[test]
fn an_unknown_module_is_sanitized_in_audit_records() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::Apply {
        id: "private/module id\nforged".to_owned(),
        model: json!({}),
        expected_hash: None,
        service_action: None,
        confirm: None,
    });
    assert!(matches!(err, Err(OpsError::UnknownModule { .. })));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.module.is_none()));
    fx.finish()
}

#[test]
fn a_module_the_monitor_does_not_know_is_reported_as_unknown() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            registry_mismatch: true,
            ..Setup::default()
        },
    )?;
    for op in [
        Operation::GetModule {
            id: "stranger".to_owned(),
        },
        Operation::ListBackups {
            id: "stranger".to_owned(),
        },
    ] {
        assert!(matches!(fx.run(op), Err(OpsError::UnknownModule { .. })));
    }
    fx.finish()
}

#[test]
fn a_module_with_no_target_cannot_be_planned() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                targets: Targets::None,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "v2\n"}),
        }),
        Err(OpsError::NoTarget { .. })
    ));
    fx.finish()
}

#[test]
fn validate_reports_diagnostics_without_touching_the_file() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let outcome = fx.run(Operation::Validate {
        id: MODULE.to_owned(),
        model: json!({"text": "BAD and WARN\n"}),
    })?;
    let OpOutcome::Validated(diagnostics) = outcome else {
        return Err("Validate must answer with diagnostics".into());
    };
    assert_eq!(diagnostics.len(), 2);
    assert!(diagnostics.has_errors());
    assert_eq!(fx.contents()?, "v1\n");
    fx.finish()
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

#[test]
fn plan_diffs_the_candidate_and_writes_nothing() -> TestResult {
    let mut fx = harness(
        b"a\nb\n",
        Setup {
            shape: Shape {
                service: true,
                check: true,
                targets: Targets::DecoyThenReal,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let before = fx.digest()?;
    let outcome = fx.run(Operation::Plan {
        id: MODULE.to_owned(),
        model: json!({"text": "a\nWARN\nb\n"}),
    })?;
    let OpOutcome::Planned(plan) = outcome else {
        return Err("Plan must answer with a plan report".into());
    };

    assert_eq!(plan.module, "fake");
    assert_eq!(plan.path, fx.target.display().to_string());
    assert!(plan.would_change);
    assert_eq!(plan.rendered, "a\nWARN\nb\n");
    assert_eq!(plan.current_hash, before);
    assert_eq!(plan.diff.len(), 1);
    assert!(plan.unified_diff.contains("+WARN\n"));
    assert_eq!(plan.diagnostics.len(), 1);
    assert_eq!(
        plan.affected_services
            .first()
            .map(|service| service.unit.as_str()),
        Some("fake.service")
    );
    assert_eq!(
        plan.affected_services
            .first()
            .map(|service| service.actions.clone()),
        Some(vec![ServiceCommand::Restart])
    );

    // No check runner is wired up, so the validator is reported as not run
    // rather than failing the plan.
    assert_eq!(plan.checks.len(), 1);
    assert_eq!(plan.checks.first().map(|check| check.ran), Some(false));
    assert_eq!(
        plan.checks.first().map(|check| check.program.as_str()),
        Some("/nonexistent/detent-ops-check")
    );

    assert_eq!(fx.contents()?, "a\nb\n");
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn plan_reports_no_change_for_an_identical_candidate() -> TestResult {
    let mut fx = harness(b"a\nb\n", Setup::default())?;
    let outcome = fx.run(Operation::Plan {
        id: MODULE.to_owned(),
        model: json!({"text": "a\nb\n"}),
    })?;
    let OpOutcome::Planned(plan) = outcome else {
        return Err("Plan must answer with a plan report".into());
    };
    assert!(!plan.would_change);
    assert!(plan.diff.is_empty());
    assert_eq!(plan.unified_diff, "");
    assert!(plan.affected_services.is_empty());
    assert!(plan.checks.is_empty());
    fx.finish()
}

#[test]
fn plan_runs_the_upstream_validator_through_the_monitor() -> TestResult {
    let mut fx = harness(
        b"a\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Plan {
        id: MODULE.to_owned(),
        model: json!({"text": "b\n"}),
    })?;
    let OpOutcome::Planned(plan) = outcome else {
        return Err("Plan must answer with a plan report".into());
    };
    assert_eq!(plan.checks.first().map(|check| check.ran), Some(true));
    assert_eq!(plan.checks.first().map(|check| check.passed), Some(true));
    assert_eq!(
        plan.checks.first().and_then(|check| check.exit_code),
        Some(0)
    );
    fx.finish()
}

#[test]
fn plan_refuses_a_model_the_module_cannot_render() -> TestResult {
    let mut fx = harness(b"a\n", Setup::default())?;
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"wrong": "shape"}),
        }),
        Err(OpsError::Module(_))
    ));
    fx.finish()
}

#[test]
fn plan_rejects_invalid_model_before_reporting_checks() -> TestResult {
    let mut fx = harness(
        b"a\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    // `BAD` triggers a validation Error diagnostic (`Invalid`), not a missing-field `Module`
    // error. The wrong shape `{\"wrong\": \"shape\"}` would fail in `apply_json` as `Module`,
    // which is a different rejection reason. Using `BAD` isolates the plan's validate-before-checks gate.
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "BAD"}),
        }),
        Err(OpsError::Invalid { .. })
    ));
    fx.finish()
}

#[test]
fn plan_refuses_a_target_that_is_not_utf8() -> TestResult {
    let mut fx = harness(&[0xff, 0xfe], Setup::default())?;
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "a\n"}),
        }),
        Err(OpsError::Module(_))
    ));
    fx.finish()
}

#[test]
fn plan_reports_a_target_that_cannot_be_read() -> TestResult {
    let mut fx = harness(b"a\n", Setup::default())?;
    std::fs::remove_file(&fx.target)?;
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "a\n"}),
        }),
        Err(OpsError::Privsep(_))
    ));
    fx.finish()
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

#[test]
fn apply_writes_the_candidate_and_audits_exactly_once() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let before = fx.digest()?;
    let outcome = fx.run(apply("v2\n", Some(before)))?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };

    assert_eq!(fx.contents()?, "v2\n");
    assert_eq!(report.prev_hash, Some(before));
    assert_eq!(report.new_hash, fx.digest()?);
    assert!(!report.created);
    assert!(report.backed_up);
    assert_eq!(report.service, None);
    assert_eq!(report.commit, None);

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let record = records.get(1).ok_or("one audit record was written")?;
    assert_eq!(record.op, OpKind::Apply);
    assert_eq!(record.result, AuditResult::Ok);
    assert_eq!(record.module.as_deref(), Some("fake"));
    assert_eq!(record.who, "root");
    assert_eq!(record.kind, IdentityKind::LocalUser);
    assert_eq!(record.prev_hash, Some(before.to_string()));
    assert_eq!(record.new_hash, Some(fx.digest()?.to_string()));
    assert_eq!(record.before_hash, record.prev_hash);
    assert_eq!(record.after_hash, record.new_hash);
    assert_eq!(record.error_id, None);
    fx.finish()
}

#[test]
fn no_op_apply_skips_write_commit_and_audit() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({ "text": "v1\n" }),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("no-op Apply must answer with an apply report".into());
    };
    assert_eq!(fx.contents()?, "v1\n");
    assert_eq!(report.prev_hash, Some(fx.digest()?));
    assert_eq!(report.new_hash, fx.digest()?);
    assert!(!report.created);
    assert!(!report.backed_up);
    assert!(report.commit.is_none());
    let OpOutcome::Backups(backups) = fx.run(Operation::ListBackups {
        id: MODULE.to_owned(),
    })?
    else {
        return Err("ListBackups must answer with a listing".into());
    };
    assert!(backups.is_empty(), "a no-op apply created a backup");
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn apply_refuses_a_candidate_with_an_error_diagnostic() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(apply("BAD\n", None));
    assert!(matches!(err, Err(OpsError::Invalid { .. })));
    assert_eq!(fx.contents()?, "v1\n");

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let record = records.get(1).ok_or("the refusal was audited")?;
    assert_eq!(record.result, AuditResult::Error);
    assert_eq!(record.error_id.as_deref(), Some("ops-invalid-model"));
    // Nothing was read, so no digests were observed.
    assert_eq!(record.prev_hash, None);
    assert_eq!(record.new_hash, None);
    fx.finish()
}

#[test]
fn apply_refuses_a_stale_expected_hash() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let actual = fx.digest()?;
    let stale = Sha256Digest::of(b"somebody else's idea of the file");
    let err = fx.run(apply("v2\n", Some(stale)));
    assert!(matches!(
        err,
        Err(OpsError::HashConflict {
            expected,
            actual: Some(found),
        }) if expected == stale && found == actual
    ));
    assert_eq!(fx.contents()?, "v1\n");

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(
        records.get(1).and_then(|r| r.error_id.clone()),
        Some("ops-hash-conflict".to_owned())
    );
    // The digest that *was* on disk is recorded, which is what an operator
    // needs to reconcile the two edits.
    assert_eq!(
        records.get(1).and_then(|r| r.prev_hash.clone()),
        Some(actual.to_string())
    );
    fx.finish()
}

#[test]
fn apply_fails_when_the_target_cannot_be_read() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    std::fs::remove_file(&fx.target)?;
    // Reading is what fails first when the file is gone.
    assert!(matches!(
        fx.run(apply("v2\n", None)),
        Err(OpsError::Privsep(_))
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Error));
    fx.finish()
}

#[test]
fn apply_acts_on_the_service_through_the_monitor() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                service: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: Some(ServiceCommand::Restart),
        confirm: None,
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let service = report.service.ok_or("a service action was requested")?;
    assert_eq!(service.unit, "fake.service");
    assert_eq!(service.action, ServiceCommand::Restart);
    assert!(service.active);
    fx.finish()
}

#[test]
fn apply_refuses_a_service_action_the_module_never_declared() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                service: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    // The descriptor declares Restart only.
    let err = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: Some(ServiceCommand::Reload),
        confirm: None,
    });
    assert!(matches!(
        err,
        Err(OpsError::Privsep(ClientError::Remote(
            ProtoError::ActionNotAllowed
        )))
    ));
    // The write happened before the service action, and is recorded.
    assert_eq!(fx.contents()?, "v2\n");
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(
        records.get(1).and_then(|r| r.new_hash.clone()),
        Some(fx.digest()?.to_string())
    );
    fx.finish()
}

#[test]
fn apply_refuses_a_service_action_when_the_module_declares_no_service() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: Some(ServiceCommand::Restart),
        confirm: None,
    });
    assert!(matches!(err, Err(OpsError::NoService { .. })));
    // The refusal happens before the write, so nothing was half-applied.
    assert_eq!(fx.contents()?, "v1\n");
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

// ---------------------------------------------------------------------------
// Commit-confirm
// ---------------------------------------------------------------------------

/// The wire protocol's timeout is whole seconds and the monitor clamps it to a
/// minimum of one, so one second is the shortest reachable window; the poll
/// interval is 20 ms, hence the margin.
const CONFIRM_WINDOW: Duration = Duration::from_secs(1);
const PAST_DEADLINE: Duration = Duration::from_millis(1300);

#[test]
fn a_commit_confirm_module_arms_a_window_that_confirm_closes() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let commit = report.commit.ok_or("a commit-confirm window was armed")?;
    assert_eq!(commit.commit_id, CommitId(1));
    assert_eq!(commit.timeout_s, 1);
    assert_eq!(commit.rollback_targets, 1);
    assert!(commit.deadline.ends_with('Z'));
    assert_eq!(fx.engine.pending_commit()?.as_ref(), Some(&commit));

    let confirmed = fx.run(Operation::ConfirmCommit {
        commit_id: commit.commit_id,
    })?;
    assert!(matches!(
        confirmed,
        OpOutcome::CommitConfirmed { commit_id } if commit_id == CommitId(1)
    ));
    assert!(fx.engine.pending_commit()?.is_none());

    std::thread::sleep(PAST_DEADLINE);
    assert_eq!(fx.contents()?, "v2\n");

    // Apply and ConfirmCommit are both mutating, so both were audited. H7: Started+outcome each.
    let records = fx.records();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    ); // Apply Started
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::Apply));
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Ok));
    assert_eq!(records.get(2).map(|r| r.result), Some(AuditResult::Started)); // Confirm Started
    assert_eq!(records.get(3).map(|r| r.op), Some(OpKind::ConfirmCommit));
    assert_eq!(records.get(3).map(|r| r.result), Some(AuditResult::Ok));
    assert_eq!(records.get(3).and_then(|r| r.commit_id), Some(1));
    assert_eq!(records.get(1).and_then(|r| r.commit_id), Some(1));
    fx.finish()
}

#[test]
fn an_unconfirmed_commit_rolls_back_when_the_timer_fires() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    assert_eq!(fx.contents()?, "v2\n");

    std::thread::sleep(PAST_DEADLINE);
    assert_eq!(fx.contents()?, "v1\n");

    // Confirming after the deadline is refused: nothing is armed any more.
    assert!(matches!(
        fx.run(Operation::ConfirmCommit {
            commit_id: CommitId(1),
        }),
        Err(OpsError::Privsep(ClientError::Remote(
            ProtoError::UnknownId { .. }
        )))
    ));
    let records = fx.records();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    ); // Apply Started
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Ok));
    assert_eq!(records.get(2).map(|r| r.result), Some(AuditResult::Started)); // Confirm Started
    assert_eq!(records.get(3).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(
        records.get(3).and_then(|r| r.error_id.clone()),
        Some("ops-privsep-failed".to_owned())
    );
    fx.finish()
}

#[test]
fn an_explicit_confirm_window_opts_a_plain_module_in() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    assert!(report.commit.is_some());
    fx.finish()
}

#[test]
fn an_unrelated_earlier_write_is_not_rolled_back_by_a_later_commit() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({ "text": "v2\n" }),
        expected_hash: None,
        service_action: None,
        confirm: None,
    })?;
    assert_eq!(fx.contents()?, "v2\n");
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({ "text": "v3\n" }),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let commit = report.commit.ok_or("a commit-confirm window was armed")?;
    assert_eq!(commit.rollback_targets, 1);
    assert_eq!(fx.contents()?, "v3\n");
    std::thread::sleep(PAST_DEADLINE);
    assert_eq!(fx.contents()?, "v2\n");
    fx.finish()
}

#[test]
fn a_commit_confirm_apply_without_a_backup_is_refused() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            disable_backups: true,
            ..Setup::default()
        },
    )?;
    assert!(matches!(
        fx.run(Operation::Apply {
            id: MODULE.to_owned(),
            model: json!({"text": "v2\n"}),
            expected_hash: None,
            service_action: None,
            confirm: Some(CONFIRM_WINDOW),
        }),
        Err(OpsError::NoBackup)
    ));
    fx.finish()
}

#[test]
fn a_second_commit_confirm_apply_while_one_is_pending_writes_nothing() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    assert_eq!(fx.contents()?, "v2\n");

    assert!(matches!(
        fx.run(Operation::Apply {
            id: MODULE.to_owned(),
            model: json!({"text": "v3\n"}),
            expected_hash: None,
            service_action: None,
            confirm: Some(CONFIRM_WINDOW),
        }),
        Err(OpsError::CommitPending(CommitId(1)))
    ));
    assert_eq!(fx.contents()?, "v2\n");

    fx.run(Operation::RollbackCommit {
        commit_id: CommitId(1),
    })?;
    fx.finish()
}

#[test]
fn a_failed_service_action_on_a_commit_confirm_module_restores_the_file() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                service: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    let result = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: Some(ServiceCommand::Reload),
        confirm: None,
    });
    assert!(matches!(
        result,
        Err(OpsError::Privsep(ClientError::Remote(
            ProtoError::ActionNotAllowed
        )))
    ));
    assert_eq!(fx.contents()?, "v1\n");
    fx.finish()
}

#[test]
fn rollback_commit_restores_the_file_and_is_audited() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let commit = report.commit.ok_or("a commit-confirm window was armed")?;
    assert_eq!(fx.contents()?, "v2\n");

    let rolled_back = fx.run(Operation::RollbackCommit {
        commit_id: commit.commit_id,
    })?;
    assert!(matches!(
        rolled_back,
        OpOutcome::RolledBack { commit_id, restored }
            if commit_id == commit.commit_id && restored == 1
    ));
    assert_eq!(fx.contents()?, "v1\n");

    // A second rollback for the same id finds nothing pending.
    assert!(matches!(
        fx.run(Operation::RollbackCommit {
            commit_id: commit.commit_id,
        }),
        Err(OpsError::Privsep(ClientError::Remote(
            ProtoError::UnknownId { .. }
        )))
    ));

    // Apply, the successful rollback, and the failed repeat are all
    // mutating, so all six (Started+outcome x3) were audited. H7.
    let records = fx.records();
    assert_eq!(records.len(), 6);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    ); // Apply Started
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Ok)); // Apply Ok
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::Apply));
    assert_eq!(records.get(2).map(|r| r.result), Some(AuditResult::Started)); // Rollback1 Started
    assert_eq!(records.get(3).map(|r| r.op), Some(OpKind::RollbackCommit));
    assert_eq!(records.get(3).map(|r| r.result), Some(AuditResult::Ok));
    assert_eq!(records.get(3).and_then(|r| r.commit_id), Some(1));
    assert_eq!(records.get(4).map(|r| r.result), Some(AuditResult::Started)); // Rollback2 Started
    assert_eq!(records.get(5).map(|r| r.op), Some(OpKind::RollbackCommit));
    assert_eq!(records.get(5).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(
        records.get(5).and_then(|r| r.error_id.clone()),
        Some("ops-privsep-failed".to_owned())
    );
    fx.finish()
}

#[test]
fn rollback_commit_rejects_an_id_that_was_never_armed() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::RollbackCommit {
        commit_id: CommitId(1),
    });
    assert!(matches!(
        err,
        Err(OpsError::Privsep(ClientError::Remote(
            ProtoError::UnknownId { .. }
        )))
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::RollbackCommit));
    assert_eq!(
        records.get(1).and_then(|r| r.error_id.clone()),
        Some("ops-privsep-failed".to_owned())
    );
    fx.finish()
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

#[test]
fn backups_are_listed_and_restored() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    fx.run(apply("v2\n", None))?;
    assert_eq!(fx.contents()?, "v2\n");

    let outcome = fx.run(Operation::ListBackups {
        id: MODULE.to_owned(),
    })?;
    let OpOutcome::Backups(backups) = outcome else {
        return Err("ListBackups must answer with a listing".into());
    };
    assert_eq!(backups.len(), 1);
    let backup_id = backups.first().map(|entry| entry.id).ok_or("one backup")?;

    let outcome = fx.run(Operation::Restore {
        id: MODULE.to_owned(),
        backup_id,
        expected_hash: None,
    })?;
    let OpOutcome::Restored { new_hash, .. } = outcome else {
        return Err("Restore must answer with the restored digest".into());
    };
    assert_eq!(fx.contents()?, "v1\n");
    assert_eq!(new_hash, fx.digest()?);

    // Apply and Restore are mutating; ListBackups is not. H7: Started+outcome per op.
    let records = fx.records();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    ); // Apply Started
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::Apply));
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Ok));
    assert_eq!(records.get(2).map(|r| r.result), Some(AuditResult::Started)); // Restore Started
    assert_eq!(records.get(3).map(|r| r.op), Some(OpKind::Restore));
    assert_eq!(
        records.get(3).and_then(|r| r.new_hash.clone()),
        Some(new_hash.to_string())
    );
    fx.finish()
}

#[test]
fn restore_rejects_a_stale_target_hash() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    fx.run(apply("v2\n", None))?;
    let OpOutcome::Backups(backups) = fx.run(Operation::ListBackups {
        id: MODULE.to_owned(),
    })?
    else {
        return Err("ListBackups must answer with a listing".into());
    };
    let stale = fx.digest()?;
    fx.run(apply("v3\n", None))?;
    assert!(matches!(
        fx.run(Operation::Restore {
            id: MODULE.to_owned(),
            backup_id: backups.first().ok_or("one backup")?.id,
            expected_hash: Some(stale),
        }),
        Err(OpsError::HashConflict { .. })
    ));
    assert_eq!(fx.contents()?, "v3\n");
    fx.finish()
}

#[test]
fn restoring_an_id_that_does_not_exist_fails_and_is_audited() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    assert!(matches!(
        fx.run(Operation::Restore {
            id: MODULE.to_owned(),
            backup_id: BackupId(99),
            expected_hash: None,
        }),
        Err(OpsError::Privsep(_))
    ));
    assert_eq!(fx.contents()?, "v1\n");
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

#[test]
fn service_status_comes_from_the_service_manager() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                service: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::ServiceStatus {
        id: MODULE.to_owned(),
    })?;
    let OpOutcome::Status(status) = outcome else {
        return Err("ServiceStatus must answer with a status".into());
    };
    assert_eq!(status.unit, "fake.service");
    assert_eq!(status.state, State::Active);
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn service_status_needs_a_declared_service() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    assert!(matches!(
        fx.run(Operation::ServiceStatus {
            id: MODULE.to_owned(),
        }),
        Err(OpsError::NoService { .. })
    ));
    fx.finish()
}

#[test]
fn service_status_surfaces_a_service_manager_failure() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                service: true,
                ..Shape::default()
            },
            services: Services::Unavailable,
            ..Setup::default()
        },
    )?;
    assert!(matches!(
        fx.run(Operation::ServiceStatus {
            id: MODULE.to_owned(),
        }),
        Err(OpsError::Service(_))
    ));
    fx.finish()
}

#[test]
fn a_service_action_goes_through_the_monitor_and_is_audited() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                service: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::ServiceAction {
        id: MODULE.to_owned(),
        action: ServiceCommand::Restart,
    })?;
    let OpOutcome::Serviced(report) = outcome else {
        return Err("ServiceAction must answer with a service report".into());
    };
    assert_eq!(report.unit, "fake.service");
    assert!(report.active);
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::ServiceAction));
    fx.finish()
}

#[test]
fn a_service_action_needs_a_declared_service() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    assert!(matches!(
        fx.run(Operation::ServiceAction {
            id: MODULE.to_owned(),
            action: ServiceCommand::Restart,
        }),
        Err(OpsError::NoService { .. })
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

// ---------------------------------------------------------------------------
// Host profile and audit
// ---------------------------------------------------------------------------

#[test]
fn the_host_profile_is_reported_from_detection() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let outcome = fx.run(Operation::HostProfile)?;
    let OpOutcome::Host(report) = outcome else {
        return Err("HostProfile must answer with a host report".into());
    };
    assert_eq!(report.profile.hostname, "detent-test");
    assert_eq!(report.distro_id.as_deref(), Some("debian"));
    assert_eq!(report.network_backend, "ifupdown");
    assert_eq!(fx.engine.host().profile.os, Os::Linux);
    assert!(format!("{:?}", fx.engine).contains("OpsEngine"));
    fx.finish()
}

#[test]
fn cert_renew_is_unsupported_until_acme_lands_and_writes_one_audit_record() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::CertRenew);
    assert!(matches!(
        err,
        Err(OpsError::Unsupported { what: "cert_renew" })
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let first = records.get(1).ok_or("the failure was audited")?;
    assert_eq!(first.op, OpKind::CertRenew);
    assert_eq!(first.result, AuditResult::Error);
    assert_eq!(first.error_id.as_deref(), Some("ops-unsupported"));
    fx.finish()
}

#[test]
fn cert_status_is_unsupported_in_the_engine_and_writes_no_audit_record() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::CertStatus);
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "cert_status"
        })
    ));
    // Read-only ops return before auditing (engine.rs `!mutating` early
    // return); CertRenew above is the mutating contrast that writes one.
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn update_status_is_unsupported_in_the_engine_and_writes_no_audit_record() -> TestResult {
    // The update check fetches a release feed and lives in `detent-update`,
    // which the operations layer does not depend on, so the engine cannot
    // answer it. The variant exists for authorization and the audit label;
    // reaching the engine with it means something routed it wrong, and that
    // must fail loudly rather than silently answer "no update".
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::UpdateStatus);
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_status"
        })
    ));
    // Read-only, so the `!mutating` early return skips auditing, exactly as
    // for CertStatus above.
    assert!(fx.records().is_empty());
    fx.finish()
}
#[test]
fn update_apply_returns_unsupported_when_state_root_is_not_set() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::UpdateApply {
        version: "v1.2.3".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    // Mutating, so the failure is audited exactly once (PLAN §2.5) — the
    // contrast to `UpdateStatus` above, which is read-only and skips audit.
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let first = records.get(1).ok_or("the failure was audited")?;
    assert_eq!(first.op, OpKind::UpdateApply);
    assert_eq!(first.result, AuditResult::Error);
    assert_eq!(first.error_id.as_deref(), Some("ops-unsupported"));
    fx.finish()
}

#[test]
fn update_apply_is_swapped_through_the_monitor_and_audited_once() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    // The harness's tempdir is `_dir`; we need a state_root the engine can
    // hand to the monitor via `set_state_root`. The harness already built a
    // state root at `<root>/state`, which we now reuse.
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);

    plant_update(&state_root)?;

    let outcome = fx.run(Operation::UpdateApply {
        version: UPDATE_FIXTURE_TAG.to_owned(),
    })?;
    let OpOutcome::UpdateApplied { version } = outcome else {
        return Err("expected UpdateApplied outcome".into());
    };
    assert_eq!(version, UPDATE_FIXTURE_TAG);

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let first = records.get(1).ok_or("the success was audited")?;
    assert_eq!(first.op, OpKind::UpdateApply);
    assert_eq!(first.result, AuditResult::Ok);
    fx.finish()
}
#[test]
fn update_apply_refuses_a_path_traversal_version() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    // A caller-controlled `version` must never escape `update/staged`: the
    // engine answers Unsupported instead of reading `../../…` as root.
    let err = fx.run(Operation::UpdateApply {
        version: "../../etc/shadow".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    // Mutating, so the refusal is audited exactly once.
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

#[test]
fn update_apply_refuses_a_valid_name_with_no_staged_file() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    // A well-formed tag with nothing staged under it must fail the same way
    // as traversal: Unsupported, audited once, target untouched.
    let err = fx.run(Operation::UpdateApply {
        version: "v9.9.9".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

#[test]
fn update_apply_refuses_dot_only_versions() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    // "." and ".." pass a naive char filter but are never staged names;
    // joined they resolve to the staged dir itself / its parent.
    for version in [".", ".."] {
        let err = fx.run(Operation::UpdateApply {
            version: version.to_owned(),
        });
        assert!(
            matches!(
                err,
                Err(OpsError::Unsupported {
                    what: "update_apply"
                })
            ),
            "dot-only version must be refused: {version}"
        );
    }
    // Mutating, so each refusal is audited Started+Error. Two versions => 4 records. H7
    let records = fx.records();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(records.get(2).map(|r| r.result), Some(AuditResult::Started));
    assert_eq!(records.get(3).map(|r| r.result), Some(AuditResult::Error));
    fx.finish()
}

#[test]
fn update_apply_bridges_a_tag_inside_the_monitor() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    let bytes = plant_update(&state_root)?;
    let digest = Sha256Digest::of(&bytes);
    let staged_dir = state_root.join("update").join("staged");

    let outcome = fx.run(Operation::UpdateApply {
        version: UPDATE_FIXTURE_TAG.to_owned(),
    })?;
    let OpOutcome::UpdateApplied { version } = outcome else {
        return Err("expected UpdateApplied outcome".into());
    };
    assert_eq!(version, UPDATE_FIXTURE_TAG);
    assert!(!staged_dir.join(digest.to_string()).exists());
    assert_eq!(std::fs::read(&fx.target)?, bytes);
    let file_name = fx
        .target
        .file_name()
        .map_or_else(|| "target".to_owned(), |n| n.to_string_lossy().into_owned());
    let prev = fx.target.with_file_name(format!("{file_name}.prev"));
    assert_eq!(std::fs::read(prev)?, b"v1\n");
    fx.finish()
}

#[test]
fn update_apply_refuses_a_preexisting_digest_path() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    let bytes = plant_update(&state_root)?;
    let digest = Sha256Digest::of(&bytes);
    let staging_dir = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("monitor-staging");
    std::fs::create_dir_all(&staging_dir)?;
    std::fs::write(staging_dir.join(digest.to_string()), b"worker-planted")?;

    let err = fx.run(Operation::UpdateApply {
        version: UPDATE_FIXTURE_TAG.to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Privsep(ClientError::Remote(ProtoError::Io(_))))
    ));
    assert_eq!(std::fs::read(&fx.target)?, b"v1\n");
    fx.finish()
}

#[test]
fn update_apply_refuses_when_the_digest_file_cannot_be_written() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let state_root = fx
        .target
        .parent()
        .ok_or("harness missing parent")?
        .join("state");
    fx.engine.set_state_root(&state_root);
    let bytes = b"unwritable-digest-bytes";
    let staged_dir = state_root.join("update").join("staged");
    std::fs::create_dir_all(&staged_dir)?;
    std::fs::write(staged_dir.join("v9.9.11"), bytes)?;
    // A regular file where the staged directory must be: the tag read fails,
    // so the run refuses without reaching the monitor.
    let _ = std::fs::remove_dir_all(&staged_dir);
    std::fs::write(&staged_dir, b"not-a-directory")?;
    let err = fx.run(Operation::UpdateApply {
        version: "v9.9.11".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    fx.finish()
}

#[test]
fn the_audit_log_can_be_queried_back_through_an_operation() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;

    fx.run(apply("v2\n", None))?;
    fx.run(apply("v3\n", None))?;

    let outcome = fx.run(Operation::AuditQuery(AuditQuery {
        module: Some("fake".to_owned()),
        who: Some("root".to_owned()),
        limit: Some(1),
    }))?;
    let OpOutcome::Audit(records) = outcome else {
        return Err("AuditQuery must answer with records".into());
    };
    assert_eq!(records.len(), 1);
    assert_eq!(
        records.first().and_then(|r| r.new_hash.clone()),
        Some(fx.digest()?.to_string())
    );
    fx.finish()
}

#[test]
fn a_denied_operation_is_audited_and_changes_nothing() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            deny: true,
            ..Setup::default()
        },
    )?;
    let err = fx.run(apply("v2\n", None));
    assert!(matches!(err, Err(OpsError::Denied(_))));
    assert_eq!(fx.contents()?, "v1\n");

    // A read-only operation is refused, and audited, too.
    assert!(matches!(
        fx.run(Operation::ListModules),
        Err(OpsError::Denied(_))
    ));

    let records = fx.records();
    assert_eq!(records.len(), 2);
    let first = records.first().ok_or("the denial was audited")?;
    assert_eq!(first.result, AuditResult::Denied);
    assert_eq!(first.error_id.as_deref(), Some("ops-denied-test"));
    assert_eq!(first.op, OpKind::Apply);
    assert_eq!(first.prev_hash, None);
    assert_eq!(first.new_hash, None);
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::ListModules));
    fx.finish()
}

/// PLAN §2.5: the audit log carries hashes and ids, never file bodies. A
/// marker planted inside an applied configuration must not survive into the
/// log.
#[test]
fn the_audit_log_never_contains_the_configuration_body() -> TestResult {
    const MARKER: &str = "s3cr3t-marker-do-not-log";

    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, b"v1\n")?;
    let descriptor = build_descriptor("fake", &target, Shape::default());
    let config = Config::with_state_root(root.join("state"));
    let allow = Allowlist::from_modules(&[descriptor], &config)?;

    let (monitor_end, worker_end) = Channel::pair()?;
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let mut monitor = Monitor::new(allow, Hooks::default());
        monitor.set_module_registry(vec![Box::new(FakeModule { descriptor })]);
        monitor.serve(&mut channel)
    });
    let mut client = Client::new(worker_end);
    client.hello()?;

    let audit_file = FileAudit::under_state_root(&root.join("state"));
    let mut engine = OpsEngine::new(
        vec![Box::new(FakeModule { descriptor })],
        client,
        host(),
        Box::new(audit_file.clone()),
        Box::new(AllowAll),
        fake_services(),
    );
    let who = Identity::new("operator", IdentityKind::Session);
    engine.execute(
        Operation::Apply {
            id: MODULE.to_owned(),
            model: json!({ "text": format!("token = {MARKER}\n") }),
            expected_hash: None,
            service_action: None,
            confirm: None,
        },
        &who,
    )?;
    // Also drive a failing apply, so the failure path is checked too.
    let _ = engine.execute(apply("BAD\n", None), &who);

    let contents = std::fs::read_to_string(audit_file.path())?;
    assert_eq!(contents.lines().count(), 4);
    assert!(
        !contents.contains(MARKER),
        "the audit log leaked the configuration body: {contents}"
    );
    assert!(contents.contains("\"who\":\"operator\""));
    assert!(contents.contains(&format!("\"{}\"", Sha256Digest::of(b"v1\n"))));

    engine.shutdown()?;
    let joined = handle.join().map_err(|_| "the monitor thread panicked")?;
    assert_eq!(joined.ok(), Some(ExitReason::Shutdown));
    Ok(())
}

/// H7 reversal: a mutation whose intent record cannot be persisted must be
/// refused without dispatch. Previously this was enforced as fail-open
/// (`an_unwritable_audit_sink_does_not_fail_the_operation` asserted the write
/// still landed as `v2`); that left writes unaudited and was reversed — an
/// unwritable sink now returns `OpsError::AuditUnavailable` and the target
/// stays at `v1`.
#[test]
fn an_unwritable_audit_sink_refuses_the_mutation() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, b"v1\n")?;
    let descriptor = build_descriptor("fake", &target, Shape::default());
    let config = Config::with_state_root(root.join("state"));
    let allow = Allowlist::from_modules(&[descriptor], &config)?;

    let (monitor_end, worker_end) = Channel::pair()?;
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        Monitor::new(allow, Hooks::default()).serve(&mut channel)
    });
    let mut client = Client::new(worker_end);
    client.hello()?;

    // A regular file where the audit log's parent directory would have to be.
    let blocker = root.join("blocked");
    std::fs::write(&blocker, b"x")?;
    let mut engine = OpsEngine::new(
        vec![Box::new(FakeModule { descriptor })],
        client,
        host(),
        Box::new(FileAudit::new(blocker.join("audit.jsonl"))),
        Box::new(AllowAll),
        fake_services(),
    );
    let Err(err) = engine.execute(apply("v2\n", None), &Identity::local("root")) else {
        return Err("audit-unavailable must refuse the mutation".into());
    };
    assert!(
        matches!(&err, OpsError::AuditUnavailable(_)),
        "expected AuditUnavailable, got {err:?} ({})",
        err.message_id().as_str()
    );
    assert_eq!(err.message_id().as_str(), "ops-audit-unavailable");
    assert_eq!(std::fs::read_to_string(&target)?, "v1\n");

    engine.shutdown()?;
    let joined = handle.join().map_err(|_| "the monitor thread panicked")?;
    assert_eq!(joined.ok(), Some(ExitReason::Shutdown));
    Ok(())
}

#[test]
fn a_module_defaults_to_its_own_model() -> TestResult {
    let dir = TempDir::new()?;
    let target = dir.path().join("target.conf");
    let module = FakeModule {
        descriptor: build_descriptor("fake", &target, Shape::default()),
    };
    let profile = host().profile;
    assert_eq!(
        module
            .defaults_json(&profile)?
            .pointer("/text")
            .and_then(Value::as_str),
        Some("default\n")
    );
    assert_eq!(module.id(), "fake");
    Ok(())
}
