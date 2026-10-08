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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use detent_core::descriptor::{
    AddedMounts, ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, InitSystem,
    ModuleDescriptor, MountUnit, Os, Owner, PathSpec, ServiceAction as CoreServiceAction,
    ServiceBinding, Target, TargetKind, UnitNames, Upstream, ValidationCtx,
};
use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
use detent_core::module::{DynError, DynModule, ModelError, ParseError};
use detent_ops::audit::{AuditError, AuditRecord, AuditSink};
use detent_ops::report::{MountReport, MountReportState, MountsReport};
use detent_ops::{
    AllowAll, AuditQuery, AuditResult, Authz, CaptureAudit, CertFrontEnd, CertReport, Denied,
    FileAudit, Identity, IdentityKind, OpKind, OpOutcome, Operation, OpsEngine, OpsError,
    ServiceCommand,
};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::{Detected, Distro, HostFacts, NetworkBackend};
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{
    CheckRunner, ExitReason, HookError, Hooks, Monitor, MonitorError, ServiceControl,
};
use detent_platform::privsep::proto::{
    BackupId, CheckId, CheckOutcome, CommitId, MountOutcome, MountState, ProtoError, Request,
    Response, ServiceOutcome, TargetId,
};
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::{Client, ClientError};
use detent_platform::service::{
    ActionOutcome, ServiceError, ServiceManager, ServiceStatus, State, UpdateStart,
};
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
        reload_unit_files: false,
        added_mounts: None,
        security_notes: &[],
    })
}

// ---------------------------------------------------------------------------
// Collaborators
// ---------------------------------------------------------------------------

/// How the fake validator answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CheckMode {
    /// It runs and accepts the candidate.
    #[default]
    Pass,
    /// It runs and rejects the candidate.
    Fail,
    /// It cannot run, and says so at length.
    Broken,
}

/// A validator that answers as `mode` says and counts its runs.
struct FakeChecks {
    mode: CheckMode,
    runs: AtomicUsize,
}

/// A failure message longer than any check detail may be.
const LONG_CHECK_ERROR: usize = 4096;

impl CheckRunner for FakeChecks {
    fn run_check(
        &self,
        _check: &ExternalCheck,
        _candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let (passed, exit_code, detail) = match self.mode {
            CheckMode::Pass => (true, 0, "ok"),
            CheckMode::Fail => (false, 1, "line 1: bad directive"),
            CheckMode::Broken => return Err(HookError::Failed("x".repeat(LONG_CHECK_ERROR))),
        };
        Ok(CheckOutcome {
            check: CheckId(0),
            passed,
            exit_code: Some(exit_code),
            detail: detail.to_owned(),
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

static OK_SERVICES: OkServices = OkServices;

/// Answers service actions as [`OkServices`] does, and counts unit-file
/// reloads and mount starts; with `fail_reload` every reload fails, with
/// `fail_mounts` every mount start.
struct ReloadingServices {
    reloads: AtomicUsize,
    fail_reload: bool,
    mount_starts: AtomicUsize,
    fail_mounts: bool,
    /// Every tag `start_update` was asked for.
    update_starts: std::sync::Mutex<Vec<String>>,
}

impl ServiceControl for ReloadingServices {
    fn service(
        &self,
        binding: &ServiceBinding,
        action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        OK_SERVICES.service(binding, action)
    }

    fn reload_unit_files(&self) -> Result<String, HookError> {
        self.reloads.fetch_add(1, Ordering::SeqCst);
        if self.fail_reload {
            Err(HookError::Failed("daemon-reload exited 1".to_owned()))
        } else {
            Ok("daemon-reload succeeded".to_owned())
        }
    }

    fn start_added_mounts(&self, _target: TargetId) -> Result<Vec<MountOutcome>, HookError> {
        self.mount_starts.fetch_add(1, Ordering::SeqCst);
        if self.fail_mounts {
            return Err(HookError::Unavailable(
                "mount units need systemd".to_owned(),
            ));
        }
        Ok(vec![MountOutcome {
            mountpoint: "/srv".to_owned(),
            unit: "srv.mount".to_owned(),
            state: MountState::Mounted,
            detail: String::new(),
        }])
    }

    /// `v98.0.0` is already running and `v97.0.0` finds no systemd; every
    /// other tag starts.
    fn start_update(&self, tag: &str) -> Result<UpdateStart, HookError> {
        if let Ok(mut starts) = self.update_starts.lock() {
            starts.push(tag.to_owned());
        }
        match tag {
            "v98.0.0" => Ok(UpdateStart::AlreadyRunning),
            "v97.0.0" => Err(HookError::Unavailable(
                "starting an update needs systemd".to_owned(),
            )),
            _ => Ok(UpdateStart::Started(format!("started {tag}"))),
        }
    }

    fn stop_started_mounts(&self) -> Result<Vec<MountOutcome>, HookError> {
        Ok(Vec::new())
    }

    fn forget_started_mounts(&self) -> Result<(), HookError> {
        Ok(())
    }
}

/// The units the harness's mounting module lists for any change.
fn srv_unit(_previous: &str, _current: &str) -> Vec<MountUnit> {
    vec![MountUnit {
        mountpoint: "/srv".to_owned(),
        unit: "srv.mount".to_owned(),
    }]
}

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

    fn reload_unit_files(&self) -> Result<String, ServiceError> {
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
    /// With `hooks`, how the monitor's check runner answers.
    checks: CheckMode,
    /// Refuse every operation.
    deny: bool,
    /// Register the module under a name the allow-list does not know.
    registry_mismatch: bool,
    /// Which service manager the engine gets.
    services: Services,
    /// Disable retained backups, leaving commit-confirm nothing to restore.
    disable_backups: bool,
    /// Answer every `StartConfirmTimer` with a planted error, as a monitor
    /// that cannot write its marker would.
    fail_arm: bool,
    /// Answer every `Restore` with a planted error.
    fail_restore: bool,
    /// With `hooks`, fail every unit-file reload.
    fail_reload: bool,
    /// Set `reload_unit_files` on the module, as `mounts` does.
    reload: bool,
    /// Declare `added_mounts` on the module, as `mounts` does.
    mounts: bool,
    /// `[mounts] activate_new_entries`.
    activate: bool,
    /// With `hooks`, fail every mount start.
    fail_mounts: bool,
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
    /// The monitor's check runner, when `Setup::hooks` wired it up.
    checks: &'static FakeChecks,
    /// The monitor's service hook, when `Setup::hooks` wired it up.
    services: &'static ReloadingServices,
    /// The policy every operation runs under.
    authz: Box<dyn Authz>,
    _dir: TempDir,
}

/// The caller every harness test acts as.
fn who() -> Identity {
    Identity::local("root")
}

impl Harness {
    fn run(&mut self, op: Operation) -> Result<OpOutcome, OpsError> {
        self.engine.execute(op, &who(), self.authz.as_ref())
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

    /// How often the monitor ran a check.
    fn check_runs(&self) -> usize {
        self.checks.runs.load(Ordering::SeqCst)
    }

    /// How often the monitor asked for a unit-file reload.
    fn reloads(&self) -> usize {
        self.services.reloads.load(Ordering::SeqCst)
    }

    /// Every tag the monitor asked the runner hook to start an update for.
    fn update_starts(&self) -> Vec<String> {
        self.services
            .update_starts
            .lock()
            .map(|starts| starts.clone())
            .unwrap_or_default()
    }

    /// How often the monitor asked the runner hook to start mounts.
    fn mount_starts(&self) -> usize {
        self.services.mount_starts.load(Ordering::SeqCst)
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

/// The module under test, shaped by `setup`.
fn harness_descriptor(target: &Path, setup: Setup) -> &'static ModuleDescriptor {
    let descriptor = build_descriptor("fake", target, setup.shape);
    leak(ModuleDescriptor {
        reload_unit_files: setup.reload,
        added_mounts: setup.mounts.then_some(srv_unit as AddedMounts),
        ..*descriptor
    })
}

fn harness(initial: &[u8], setup: Setup) -> Result<Harness, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, initial)?;

    let allow_descriptor = harness_descriptor(&target, setup);
    let mut config = Config::with_state_root(root.join("state"));
    config.activate_mounts = setup.activate;
    let staging_dir = root.join("monitor-staging");
    if setup.disable_backups {
        config.keep_backups = 0;
    }
    let allow = Allowlist::from_modules(&[allow_descriptor], &config)?;

    let (monitor_end, worker_end) = Channel::pair()?;
    // Leaked so the monitor thread can borrow it for `'static`, one per
    // harness so parallel tests do not share a run count.
    let checks: &'static FakeChecks = leak(FakeChecks {
        mode: setup.checks,
        runs: AtomicUsize::new(0),
    });
    let monitor_services: &'static ReloadingServices = leak(ReloadingServices {
        reloads: AtomicUsize::new(0),
        fail_reload: setup.fail_reload,
        mount_starts: AtomicUsize::new(0),
        fail_mounts: setup.fail_mounts,
        update_starts: std::sync::Mutex::new(Vec::new()),
    });
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let hooks = if setup.hooks {
            Hooks {
                checks,
                services: monitor_services,
            }
        } else {
            Hooks::default()
        };
        let mut monitor = Monitor::new(allow, hooks);
        monitor.set_module_registry(vec![Box::new(FakeModule {
            descriptor: allow_descriptor,
        })]);
        monitor.set_staging_dir(staging_dir);
        monitor.serve(&mut channel)
    });

    let worker_end = if setup.fail_arm || setup.fail_restore {
        let (engine_end, proxy_end) = Channel::pair()?;
        thread::spawn(move || {
            proxy(proxy_end, worker_end, setup.fail_arm, setup.fail_restore);
        });
        engine_end
    } else {
        worker_end
    };
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
        services,
    );

    Ok(Harness {
        engine,
        audit,
        handle: Some(handle),
        target,
        checks,
        services: monitor_services,
        authz,
        _dir: dir,
    })
}

/// Sit between the engine and the real monitor and forward every frame, except
/// that `StartConfirmTimer` (with `fail_arm`) and `Restore` (with
/// `fail_restore`) get a planted error instead of reaching the monitor. Ends
/// when either side closes.
fn proxy(mut engine: Channel, mut monitor: Channel, fail_arm: bool, fail_restore: bool) {
    loop {
        let request = match engine.poll_recv::<Request>() {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(_) => return,
        };
        let planted = match request {
            Request::StartConfirmTimer { .. } if fail_arm => Some("planted arming failure"),
            Request::Restore { .. } if fail_restore => Some("planted restore failure"),
            _ => None,
        };
        let response = if let Some(reason) = planted {
            Response::Error(ProtoError::Io(reason.to_owned()))
        } else {
            if monitor.send(&request).is_err() {
                return;
            }
            match monitor.recv::<Response>() {
                Ok(response) => response,
                Err(_) => return,
            }
        };
        if engine.send(&response).is_err() {
            return;
        }
    }
}

/// The id the registry advertises, which is `fake` unless the setup asked for
/// a mismatch.
const MODULE: &str = "fake";

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

/// Records the candidate path a check ran on and whether it held bytes.
struct SeenCandidate(std::sync::Mutex<Option<(PathBuf, Vec<u8>)>>);

impl CheckRunner for SeenCandidate {
    fn run_check(
        &self,
        _check: &ExternalCheck,
        candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        let bytes = std::fs::read(candidate).map_err(|err| HookError::Failed(err.to_string()))?;
        *self
            .0
            .lock()
            .map_err(|_| HookError::Failed("poisoned".to_owned()))? =
            Some((candidate.to_path_buf(), bytes));
        Ok(CheckOutcome {
            check: CheckId(0),
            passed: true,
            exit_code: Some(0),
            detail: "ok".to_owned(),
        })
    }
}

/// Entries of `dir` named like a check candidate.
fn candidates_in(dir: &Path) -> Result<usize, std::io::Error> {
    let names = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names
        .iter()
        .filter(|name| name.to_string_lossy().starts_with(".detent-candidate-"))
        .count())
}

/// The `fake` module with one check and two file targets: `target`, and
/// before it a never-detected decoy of the same name in `decoy_dir`.
fn decoy_first_descriptor(
    decoy_dir: &Path,
    target: &Path,
) -> Result<&'static ModuleDescriptor, &'static str> {
    let base = build_descriptor(
        "fake",
        target,
        Shape {
            check: true,
            ..Shape::default()
        },
    );
    let real = *base.targets.first().ok_or("the descriptor has a target")?;
    let decoy = Target {
        path: PathSpec::new(leak_str(
            decoy_dir.join("target.conf").display().to_string(),
        )),
        backend_detect: never,
        ..real
    };
    let targets: &'static [Target] = leak(vec![decoy, real]).as_slice();
    Ok(leak(ModuleDescriptor { targets, ..*base }))
}

/// The runner thread, the monitor thread, and the worker's end of the
/// monitor channel.
type Served = (
    thread::JoinHandle<()>,
    thread::JoinHandle<ServeResult>,
    Channel,
);

/// A runner thread serving `seen` and a monitor thread whose checks go
/// through it, as `detent serve` wires them, both with [`host`]'s profile.
fn serve_with_a_runner(
    allow: Allowlist,
    descriptor: &'static ModuleDescriptor,
    staging_dir: PathBuf,
    seen: &'static SeenCandidate,
) -> Result<Served, Box<dyn std::error::Error>> {
    use detent_platform::privsep::runner::{RunnerClient, serve_runner};
    let (runner_client_end, mut runner_end) = Channel::pair()?;
    let runner_allow = allow.clone();
    let runner_staging = staging_dir.clone();
    let runner = thread::spawn(move || {
        let hooks = Hooks {
            checks: seen,
            services: &OK_SERVICES,
        };
        serve_runner(
            &runner_allow,
            &runner_staging,
            &host().profile,
            &hooks,
            &mut runner_end,
        );
    });
    let (monitor_end, worker_end) = Channel::pair()?;
    let monitor = thread::spawn(move || {
        let checks = RunnerClient::new(runner_client_end, &allow);
        let mut channel = monitor_end;
        let mut monitor = Monitor::new(
            allow,
            Hooks {
                checks: &checks,
                services: &OK_SERVICES,
            },
        );
        monitor.set_module_registry(vec![Box::new(FakeModule { descriptor })]);
        monitor.set_staging_dir(staging_dir);
        monitor.set_host_profile(host().profile);
        monitor.serve(&mut channel)
    });
    Ok((runner, monitor, worker_end))
}

/// The engine plans against the module's primary target, the monitor writes
/// the candidate beside it, and the runner, which gets only a file name,
/// finds it there on its own: all three agree even when the module's first
/// target is not detected on this host and lives in another directory.
#[test]
fn engine_monitor_and_runner_agree_on_the_candidate_directory() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new()?;
    let decoy_dir = dir.path().join("decoy");
    let real_dir = dir.path().join("real");
    for made in [&decoy_dir, &real_dir] {
        std::fs::create_dir(made)?;
        std::fs::set_permissions(made, std::fs::Permissions::from_mode(0o755))?;
    }
    let target = real_dir.join("target.conf");
    std::fs::write(&target, b"a\n")?;
    let descriptor = decoy_first_descriptor(&decoy_dir, &target)?;
    let allow = Allowlist::from_modules(
        &[descriptor],
        &Config::with_state_root(dir.path().join("state")),
    )?;
    let seen: &'static SeenCandidate = leak(SeenCandidate(std::sync::Mutex::new(None)));
    let (runner, monitor, worker_end) =
        serve_with_a_runner(allow, descriptor, dir.path().join("monitor-staging"), seen)?;

    let mut client = Client::new(worker_end);
    client.hello()?;
    let mut engine = OpsEngine::new(
        vec![Box::new(FakeModule { descriptor })],
        client,
        host(),
        Box::new(CaptureAudit::new()),
        fake_services(),
    );
    let outcome = engine.execute(
        Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "b\n"}),
        },
        &who(),
        &AllowAll,
    )?;
    let OpOutcome::Planned(plan) = outcome else {
        return Err("Plan must answer with a plan report".into());
    };
    assert_eq!(plan.path, target.display().to_string());
    let check = plan.checks.first().ok_or("the plan ran no check")?;
    assert!(check.ran && check.passed, "check report {check:?}");
    let (path, bytes) = seen
        .0
        .lock()
        .map_err(|_| "poisoned")?
        .clone()
        .ok_or("the runner ran no check")?;
    assert_eq!(path.parent(), Some(real_dir.as_path()));
    assert!(
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".detent-candidate-")),
        "candidate at {path:?}"
    );
    assert_eq!(bytes, b"b\n");
    assert_eq!(candidates_in(&real_dir)?, 0);
    assert_eq!(candidates_in(&decoy_dir)?, 0);
    assert!(!dir.path().join("monitor-staging").exists());

    engine.shutdown()?;
    let served = monitor.join().map_err(|_| "the monitor thread panicked")?;
    assert_eq!(served.ok(), Some(ExitReason::Shutdown));
    runner.join().map_err(|_| "the runner thread panicked")?;
    Ok(())
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

/// A harness whose module declares one check that the monitor can run.
fn checked_harness(mode: CheckMode) -> Result<Harness, Box<dyn std::error::Error>> {
    harness(
        b"a\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            hooks: true,
            checks: mode,
            ..Setup::default()
        },
    )
}

fn plan(text: &str) -> Operation {
    Operation::Plan {
        id: MODULE.to_owned(),
        model: json!({ "text": text }),
    }
}

#[test]
fn plan_does_not_run_checks_for_a_model_with_errors() -> TestResult {
    let mut fx = checked_harness(CheckMode::Pass)?;
    // `BAD` triggers a validation Error diagnostic (`Invalid`), not a
    // missing-field `Module` error, so this isolates the plan's
    // validate-before-checks gate.
    assert!(matches!(fx.run(plan("BAD")), Err(OpsError::Invalid { .. })));
    assert_eq!(fx.check_runs(), 0, "a root validator ran on invalid input");
    assert!(fx.records().is_empty());

    // The same harness does run the check for a valid model.
    fx.run(plan("b\n"))?;
    assert_eq!(fx.check_runs(), 1);
    fx.finish()
}

#[test]
fn a_plan_that_ran_checks_is_audited() -> TestResult {
    let mut fx = checked_harness(CheckMode::Fail)?;
    let before = fx.digest()?;
    let OpOutcome::Planned(report) = fx.run(plan("b\n"))? else {
        return Err("Plan must answer with a plan report".into());
    };
    assert!(report.checks.iter().all(|check| check.ran && !check.passed));
    let records = fx.records();
    assert_eq!(records.len(), 1, "{records:?}");
    let record = records.first().ok_or("one audit record")?;
    assert_eq!(record.op, OpKind::Plan);
    assert_eq!(record.result, AuditResult::Ok);
    assert_eq!(record.module.as_deref(), Some(MODULE));
    assert_eq!(record.prev_hash, Some(before.to_string()));
    assert_eq!(record.new_hash, None);
    fx.finish()
}

#[test]
fn a_plan_without_checks_is_not_audited() -> TestResult {
    let mut fx = harness(b"a\n", Setup::default())?;
    fx.run(plan("b\n"))?;
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn a_plan_truncates_the_error_of_a_check_that_could_not_run() -> TestResult {
    let mut fx = checked_harness(CheckMode::Broken)?;
    let OpOutcome::Planned(report) = fx.run(plan("b\n"))? else {
        return Err("Plan must answer with a plan report".into());
    };
    let check = report.checks.first().ok_or("one check report")?;
    assert!(!check.ran);
    assert!(check.detail.contains("xxxx"), "{}", check.detail);
    assert!(
        check.detail.len() <= 512,
        "check detail is {} bytes",
        check.detail.len()
    );
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
fn plan_reports_a_missing_target_clearly() -> TestResult {
    let mut fx = harness(b"a\n", Setup::default())?;
    std::fs::remove_file(&fx.target)?;
    assert!(matches!(
        fx.run(Operation::Plan {
            id: MODULE.to_owned(),
            model: json!({"text": "a\n"}),
        }),
        Err(OpsError::TargetMissing)
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
fn apply_refuses_a_candidate_a_declared_check_rejects() -> TestResult {
    // No hooks are wired up, so the declared check cannot run at all: `apply`
    // must fail closed on that, exactly as it does on an outright failure.
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            ..Setup::default()
        },
    )?;
    let err = fx.run(apply("v2\n", None));
    assert!(matches!(
        err,
        Err(OpsError::CheckFailed { ref program, .. }) if program == "/nonexistent/detent-ops-check"
    ));
    // Nothing was written: the target and its content are untouched.
    assert_eq!(fx.contents()?, "v1\n");
    assert_no_backups(&mut fx)?;

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(
        records.get(1).and_then(|r| r.error_id.clone()),
        Some("ops-check-failed".to_owned())
    );
    fx.finish()
}

/// No backup of the module's target exists.
fn assert_no_backups(fx: &mut Harness) -> TestResult {
    let OpOutcome::Backups(backups) = fx.run(Operation::ListBackups {
        id: MODULE.to_owned(),
    })?
    else {
        return Err("ListBackups must answer with a listing".into());
    };
    assert!(backups.is_empty(), "a refused apply created a backup");
    Ok(())
}

#[test]
fn apply_refuses_when_an_external_check_fails() -> TestResult {
    // The validator runs and rejects the candidate.
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            hooks: true,
            checks: CheckMode::Fail,
            ..Setup::default()
        },
    )?;
    let err = fx.run(apply("v2\n", None));
    assert!(
        matches!(
            err,
            Err(OpsError::CheckFailed { ref program, ref detail })
                if program == "/nonexistent/detent-ops-check" && detail.contains("bad directive")
        ),
        "{err:?}"
    );
    assert_eq!(fx.contents()?, "v1\n");
    assert_no_backups(&mut fx)?;

    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(
        records.get(1).and_then(|r| r.error_id.clone()),
        Some("ops-check-failed".to_owned())
    );
    assert_eq!(records.get(1).and_then(|r| r.new_hash.clone()), None);
    fx.finish()
}

#[test]
fn apply_reports_the_checks_that_passed() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                check: true,
                ..Shape::default()
            },
            hooks: true,
            ..Setup::default()
        },
    )?;
    let OpOutcome::Applied(report) = fx.run(apply("v2\n", None))? else {
        return Err("Apply must answer with an apply report".into());
    };
    assert_eq!(fx.contents()?, "v2\n");
    assert_eq!(report.checks.len(), 1);
    let check = report.checks.first().ok_or("one check report")?;
    assert_eq!(check.program, "/nonexistent/detent-ops-check");
    assert!(check.ran && check.passed);
    assert_eq!(check.exit_code, Some(0));
    fx.finish()
}

#[test]
fn apply_refuses_a_missing_target_clearly() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    std::fs::remove_file(&fx.target)?;
    // Apply never creates a target: a missing file is refused with its own
    // error, not a generic privsep failure. STAGE3 L-OPS17.
    assert!(matches!(
        fx.run(apply("v2\n", None)),
        Err(OpsError::TargetMissing)
    ));
    assert!(!fx.target.exists());
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    assert_eq!(records.get(1).map(|r| r.result), Some(AuditResult::Error));
    assert_eq!(
        records.get(1).and_then(|r| r.error_id.clone()),
        Some("ops-target-missing".to_owned())
    );
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
    // The refusal must disarm the window it just armed.
    assert!(fx.engine.pending_commit()?.is_none());
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
fn a_failed_arming_restores_the_previous_contents() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            fail_arm: true,
            ..Setup::default()
        },
    )?;
    let result = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    });
    assert!(
        matches!(
            result,
            Err(OpsError::ArmFailed {
                restore_error: None,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(fx.contents()?, "v1\n");
    assert!(fx.engine.pending_commit()?.is_none());
    fx.finish()
}

#[test]
fn a_failed_arming_reports_a_failed_restore_too() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            fail_arm: true,
            fail_restore: true,
            ..Setup::default()
        },
    )?;
    let result = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    });
    let Err(error @ OpsError::ArmFailed { .. }) = result else {
        return Err(format!("expected ArmFailed, got {result:?}").into());
    };
    assert_eq!(error.message_id().as_str(), "ops-arm-failed-unrestored");
    let text = error.to_string();
    assert!(text.contains("planted arming failure"), "{text}");
    assert!(text.contains("planted restore failure"), "{text}");
    // The restore failed, so the new contents are still there: the error above
    // is the only thing that tells the operator so.
    assert_eq!(fx.contents()?, "v2\n");
    fx.finish()
}

#[test]
fn a_failed_arming_after_a_write_with_no_backup_cannot_restore() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            disable_backups: true,
            fail_arm: true,
            ..Setup::default()
        },
    )?;
    let result = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: Some(CONFIRM_WINDOW),
    });
    assert!(
        matches!(
            result,
            Err(OpsError::ArmFailed {
                restore_error: Some(ref restore),
                ..
            }) if matches!(**restore, OpsError::NoBackup)
        ),
        "{result:?}"
    );
    // No backup was made, so nothing can be put back: the new contents stay.
    assert_eq!(fx.contents()?, "v2\n");
    assert!(fx.engine.pending_commit()?.is_none());
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
fn a_reloading_module_apply_reloads_unit_files_once() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            hooks: true,
            reload: true,
            ..Setup::default()
        },
    )?;
    let apply = || Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: None,
    };
    fx.run(apply())?;
    assert_eq!(fx.contents()?, "v2\n");
    assert_eq!(fx.reloads(), 1);
    // An apply that changes nothing writes nothing and reloads nothing.
    fx.run(apply())?;
    assert_eq!(fx.reloads(), 1);
    fx.finish()
}

#[test]
fn a_module_without_the_flag_never_reloads_unit_files() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
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
        service_action: None,
        confirm: None,
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let commit = report.commit.ok_or("a commit-confirm window was armed")?;
    fx.run(Operation::RollbackCommit {
        commit_id: commit.commit_id,
    })?;
    assert_eq!(fx.contents()?, "v1\n");
    assert_eq!(fx.reloads(), 0);
    fx.finish()
}

#[test]
fn a_reloading_commit_confirm_apply_reloads_and_its_rollback_reloads_again() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            hooks: true,
            reload: true,
            ..Setup::default()
        },
    )?;
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: None,
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    let commit = report.commit.ok_or("a commit-confirm window was armed")?;
    assert_eq!(fx.reloads(), 1);
    fx.run(Operation::RollbackCommit {
        commit_id: commit.commit_id,
    })?;
    assert_eq!(fx.contents()?, "v1\n");
    assert_eq!(fx.reloads(), 2);
    fx.finish()
}

/// A harness whose module behaves as `mounts`: commit-confirm, unit-file
/// reload, `added_mounts`.
fn mounting(activate: bool, fail_mounts: bool) -> Result<Harness, Box<dyn std::error::Error>> {
    harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            hooks: true,
            reload: true,
            mounts: true,
            activate,
            fail_mounts,
            ..Setup::default()
        },
    )
}

fn apply_v2(
    fx: &mut Harness,
) -> Result<Box<detent_ops::report::ApplyReport>, Box<dyn std::error::Error>> {
    let outcome = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: None,
    })?;
    let OpOutcome::Applied(report) = outcome else {
        return Err("Apply must answer with an apply report".into());
    };
    Ok(report)
}

#[test]
fn a_mounting_apply_reports_the_units_it_started() -> TestResult {
    let mut fx = mounting(true, false)?;
    let report = apply_v2(&mut fx)?;
    assert_eq!(
        report.mounts,
        Some(MountsReport {
            activated: true,
            units: vec![MountReport {
                mountpoint: "/srv".to_owned(),
                unit: "srv.mount".to_owned(),
                state: MountReportState::Mounted,
                detail: String::new(),
            }],
            error: None,
        })
    );
    assert_eq!(fx.mount_starts(), 1);
    assert_eq!(fx.reloads(), 1);
    assert!(fx.engine.pending_commit()?.is_some());
    fx.finish()
}

#[test]
fn a_mounting_apply_with_activation_off_says_so_and_starts_nothing() -> TestResult {
    let mut fx = mounting(false, false)?;
    let report = apply_v2(&mut fx)?;
    assert_eq!(
        report.mounts,
        Some(MountsReport {
            activated: false,
            units: Vec::new(),
            error: None,
        })
    );
    assert_eq!(fx.mount_starts(), 0);
    fx.finish()
}

/// Owner decision (D1): a mount that cannot start is reported; the write and
/// the commit-confirm window stay.
#[test]
fn a_failed_mount_start_is_reported_and_the_commit_stays_pending() -> TestResult {
    let mut fx = mounting(true, true)?;
    let report = apply_v2(&mut fx)?;
    let mounts = report.mounts.ok_or("a mounts report")?;
    assert!(mounts.activated);
    assert!(mounts.units.is_empty());
    assert!(
        mounts
            .error
            .as_deref()
            .is_some_and(|error| error.contains("mount units need systemd")),
        "{mounts:?}"
    );
    assert_eq!(fx.contents()?, "v2\n");
    assert!(fx.engine.pending_commit()?.is_some());
    fx.finish()
}

#[test]
fn an_apply_of_a_module_without_mounts_has_no_mounts_report() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            hooks: true,
            activate: true,
            ..Setup::default()
        },
    )?;
    let report = apply_v2(&mut fx)?;
    assert_eq!(report.mounts, None);
    assert_eq!(fx.mount_starts(), 0);
    fx.finish()
}

#[test]
fn a_failed_reload_fails_the_apply_and_rolls_the_commit_back() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            shape: Shape {
                commit_confirm: true,
                ..Shape::default()
            },
            hooks: true,
            reload: true,
            fail_reload: true,
            ..Setup::default()
        },
    )?;
    let result = fx.run(Operation::Apply {
        id: MODULE.to_owned(),
        model: json!({"text": "v2\n"}),
        expected_hash: None,
        service_action: None,
        confirm: None,
    });
    assert!(
        matches!(
            &result,
            Err(OpsError::Privsep(ClientError::Remote(ProtoError::Io(message))))
                if message.contains("daemon-reload")
        ),
        "{result:?}"
    );
    assert_eq!(fx.contents()?, "v1\n");
    assert!(fx.engine.pending_commit()?.is_none());
    // The apply's reload, then the rollback's.
    assert_eq!(fx.reloads(), 2);
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

/// A certificate hook that counts its calls and fails each one when `fail`.
struct FakeCert {
    status_calls: Arc<AtomicUsize>,
    renew_calls: Arc<AtomicUsize>,
    fail: bool,
}

/// The id a failing [`FakeCert`] reports.
const CERT_FAILED: &str = "cli-cert-renew-unreachable";

impl FakeCert {
    /// A hook and the two counters it shares with the test.
    fn new(fail: bool) -> (Box<Self>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let status_calls = Arc::new(AtomicUsize::new(0));
        let renew_calls = Arc::new(AtomicUsize::new(0));
        let hook = Box::new(Self {
            status_calls: Arc::clone(&status_calls),
            renew_calls: Arc::clone(&renew_calls),
            fail,
        });
        (hook, status_calls, renew_calls)
    }

    fn outcome(&self) -> Result<(), OpsError> {
        if self.fail {
            return Err(OpsError::Cert {
                id: MessageId::new(CERT_FAILED),
                reason: "could not talk to the server at 127.0.0.1:1".to_owned(),
            });
        }
        Ok(())
    }
}

impl CertFrontEnd for FakeCert {
    fn status(&self) -> Result<CertReport, OpsError> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        self.outcome()?;
        Ok(CertReport {
            fingerprint: "AA:BB".to_owned(),
            not_after_unix: Some(1_900_000_000),
            lifetime_used_percent: Some(40),
            renewal_due: Some(false),
            expiry_warning: None,
        })
    }

    fn renew(&self) -> Result<(), OpsError> {
        self.renew_calls.fetch_add(1, Ordering::SeqCst);
        self.outcome()
    }
}

#[test]
fn cert_status_answers_from_the_hook_and_writes_no_audit_record() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let (hook, status_calls, renew_calls) = FakeCert::new(false);
    fx.engine.set_cert_front_end(hook);
    let OpOutcome::CertStatus(report) = fx.run(Operation::CertStatus)? else {
        return Err("CertStatus must answer with a certificate report".into());
    };
    assert_eq!(report.fingerprint, "AA:BB");
    assert_eq!(report.not_after_unix, Some(1_900_000_000));
    assert_eq!(status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(renew_calls.load(Ordering::SeqCst), 0);
    // Read-only: no record, exactly as for `HostProfile`.
    assert!(fx.records().is_empty());
    fx.finish()
}

#[test]
fn cert_renew_calls_the_hook_once_and_audits_started_then_ok() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let (hook, status_calls, renew_calls) = FakeCert::new(false);
    fx.engine.set_cert_front_end(hook);
    let outcome = fx.run(Operation::CertRenew)?;
    assert!(
        matches!(outcome, OpOutcome::CertRenewRequested),
        "{outcome:?}"
    );
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);
    assert_eq!(status_calls.load(Ordering::SeqCst), 0);
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| (r.op, r.result)),
        Some((OpKind::CertRenew, AuditResult::Started))
    );
    let last = records.get(1).ok_or("the outcome was audited")?;
    assert_eq!((last.op, last.result), (OpKind::CertRenew, AuditResult::Ok));
    assert_eq!(last.error_id, None);
    fx.finish()
}

#[test]
fn a_failing_cert_hook_keeps_its_message_id_in_the_answer_and_the_audit_record() -> TestResult {
    let mut fx = harness(b"v1\n", Setup::default())?;
    let (hook, _, renew_calls) = FakeCert::new(true);
    fx.engine.set_cert_front_end(hook);

    let err = fx.run(Operation::CertRenew);
    let Err(OpsError::Cert { id, reason }) = err else {
        return Err(format!("CertRenew must pass the hook's error on: {err:?}").into());
    };
    assert_eq!(id.as_str(), CERT_FAILED);
    assert!(reason.contains("127.0.0.1:1"), "{reason}");
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let last = records.get(1).ok_or("the failure was audited")?;
    assert_eq!(last.result, AuditResult::Error);
    assert_eq!(last.error_id.as_deref(), Some(CERT_FAILED));

    // A failed read is returned as it is, and is not audited.
    let err = fx.run(Operation::CertStatus);
    assert!(
        matches!(&err, Err(OpsError::Cert { id, .. }) if id.as_str() == CERT_FAILED),
        "{err:?}"
    );
    assert_eq!(fx.records().len(), 2);
    fx.finish()
}

#[test]
fn a_denied_cert_caller_never_reaches_the_hook() -> TestResult {
    let mut fx = harness(
        b"v1\n",
        Setup {
            deny: true,
            ..Setup::default()
        },
    )?;
    let (hook, status_calls, renew_calls) = FakeCert::new(false);
    fx.engine.set_cert_front_end(hook);
    assert!(matches!(
        fx.run(Operation::CertRenew),
        Err(OpsError::Denied(_))
    ));
    assert!(matches!(
        fx.run(Operation::CertStatus),
        Err(OpsError::Denied(_))
    ));
    assert_eq!(status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(renew_calls.load(Ordering::SeqCst), 0);
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.result == AuditResult::Denied));
    assert_eq!(records.first().map(|r| r.op), Some(OpKind::CertRenew));
    assert_eq!(records.get(1).map(|r| r.op), Some(OpKind::CertStatus));
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
/// The two audit records of one `UpdateApply`: started, then `result`
/// with `error_id`.
fn assert_update_audited(fx: &Harness, result: AuditResult, error_id: Option<&str>) -> TestResult {
    let records = fx.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.first().map(|r| r.result),
        Some(AuditResult::Started)
    );
    let last = records.get(1).ok_or("the outcome was audited")?;
    assert_eq!(last.op, OpKind::UpdateApply);
    assert_eq!(last.result, result);
    assert_eq!(last.error_id.as_deref(), error_id);
    Ok(())
}

fn hooked() -> Setup {
    Setup {
        hooks: true,
        ..Setup::default()
    }
}

#[test]
fn update_apply_starts_the_update_unit_and_is_audited_once() -> TestResult {
    let mut fx = harness(b"v1\n", hooked())?;
    let outcome = fx.run(Operation::UpdateApply {
        version: "v99.0.0".to_owned(),
    })?;
    let OpOutcome::UpdateStarted { version } = outcome else {
        return Err("expected UpdateStarted outcome".into());
    };
    assert_eq!(version, "v99.0.0");
    assert_eq!(fx.update_starts(), ["v99.0.0"]);
    assert_update_audited(&fx, AuditResult::Ok, None)?;
    // Nothing is swapped here: the unit does that, later.
    assert_eq!(fx.contents()?, "v1\n");
    fx.finish()
}

#[test]
fn update_apply_refuses_while_an_update_runs() -> TestResult {
    let mut fx = harness(b"v1\n", hooked())?;
    let err = fx.run(Operation::UpdateApply {
        version: "v98.0.0".to_owned(),
    });
    assert!(matches!(err, Err(OpsError::UpdateRunning)));
    assert_update_audited(&fx, AuditResult::Error, Some("ops-update-running"))?;
    fx.finish()
}

#[test]
fn update_apply_is_unsupported_without_systemd_or_a_runner() -> TestResult {
    // A host without systemd: the runner's answer.
    let mut fx = harness(b"v1\n", hooked())?;
    let err = fx.run(Operation::UpdateApply {
        version: "v97.0.0".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    assert_update_audited(&fx, AuditResult::Error, Some("ops-unsupported"))?;
    fx.finish()?;
    // No service hook at all (the monitor's default).
    let mut fx = harness(b"v1\n", Setup::default())?;
    let err = fx.run(Operation::UpdateApply {
        version: "v99.0.0".to_owned(),
    });
    assert!(matches!(
        err,
        Err(OpsError::Unsupported {
            what: "update_apply"
        })
    ));
    assert_update_audited(&fx, AuditResult::Error, Some("ops-unsupported"))?;
    fx.finish()
}

#[test]
fn update_apply_refuses_a_version_that_is_not_a_newer_release_tag() -> TestResult {
    let mut fx = harness(b"v1\n", hooked())?;
    for version in [
        "../../etc/shadow",
        ".",
        "..",
        "",
        "-x",
        "v99.0.0 x",
        "v0.0.1",
    ] {
        let err = fx.run(Operation::UpdateApply {
            version: version.to_owned(),
        });
        assert!(
            matches!(
                err,
                Err(OpsError::Privsep(ClientError::Remote(ProtoError::Io(_))))
            ),
            "{version:?} must be refused: {err:?}"
        );
    }
    assert!(
        fx.update_starts().is_empty(),
        "the runner must not be asked"
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
        &AllowAll,
    )?;
    // Also drive a failing apply, so the failure path is checked too.
    let _ = engine.execute(apply("BAD\n", None), &who, &AllowAll);

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
        fake_services(),
    );
    let Err(err) = engine.execute(apply("v2\n", None), &Identity::local("root"), &AllowAll) else {
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
