//! End-to-end proof that a real [`Monitor`] can be built with
//! [`checks::ExternalCheckRunner`] and a [`ServiceManager`] (via
//! [`ServiceControlAdapter`]) instead of the default `NoChecks`/`NoServices`
//! (PLAN §2.3, §2.4; Phase 2 task 4).
//!
//! Structured like `tests/privsep_e2e.rs`'s
//! `run_check_and_service_succeed_through_working_collaborators`, but with
//! this subtask's real collaborators — `ExternalCheckRunner` and
//! `SystemdManager` — driven by a fake `ProcessRunner` instead of stub
//! `CheckRunner`/`ServiceControl` implementations.

use std::path::Path;
use std::thread;
use std::time::Duration;

use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, Owner, PathSpec,
    ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind, UnitNames, Upstream,
};
use detent_core::diag::MessageId;
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{ExitReason, Hooks, Monitor};
use detent_platform::privsep::proto::ServiceAction;
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::Client;
use detent_platform::service::checks::ExternalCheckRunner;
use detent_platform::service::exec::{ProcessError, ProcessOutput, ProcessRunner};
use detent_platform::service::{ServiceControlAdapter, SystemdManager};
use tempfile::TempDir;

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Fake process runner, shared by the check and the service manager under test
// ---------------------------------------------------------------------------

/// Returns a fixed, scripted response to every call, regardless of argv:
/// this file is about proving the *wiring*, not re-testing per-backend argv
/// (covered by `tests/service_manager.rs` and `tests/service_checks.rs`).
#[derive(Clone)]
struct AlwaysOk;

impl ProcessRunner for AlwaysOk {
    fn exists(&self, _path: &'static str) -> bool {
        true
    }

    fn run(
        &self,
        _program: &'static str,
        _args: &[String],
        _timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        Ok(ProcessOutput {
            status: Some(0),
            stdout: b"LoadState=loaded\nActiveState=active\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Fixture, mirroring tests/privsep_e2e.rs's shape
// ---------------------------------------------------------------------------

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

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

fn build_descriptor(target_path: &Path) -> &'static ModuleDescriptor {
    let target_path = leak_str(target_path.display().to_string());
    let targets: &'static [Target] = leak(vec![Target {
        path: PathSpec::new(target_path),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }])
    .as_slice();
    let actions: &'static [CoreServiceAction] = leak(vec![CoreServiceAction::Restart]).as_slice();
    let services: &'static [ServiceBinding] = leak(vec![ServiceBinding {
        units: UnitNames {
            systemd: &["chronyd.service"],
            openrc: &[],
            bsdrc: &[],
        },
        actions,
    }])
    .as_slice();
    let args: &'static [ArgTemplate] =
        leak(vec![ArgTemplate::Literal("-p"), ArgTemplate::TempFile]).as_slice();
    let checks: &'static [ExternalCheck] = leak(vec![ExternalCheck {
        program: PathSpec::new("/usr/sbin/chronyd"),
        args,
        expects: CheckExpectation::ExitZero,
    }])
    .as_slice();
    leak(ModuleDescriptor {
        id: "samba",
        display_name_id: MessageId::new("fake-name"),
        targets,
        upstream: UPSTREAM,
        services,
        checks,
        commit_confirm: false,
        security_notes: &[],
    })
}

struct Fixture {
    _dir: TempDir,
    root: std::path::PathBuf,
    module: &'static ModuleDescriptor,
}

impl Fixture {
    fn allow(&self) -> Result<Allowlist, Box<dyn std::error::Error>> {
        let config = Config::with_state_root(self.root.join("state"));
        Ok(Allowlist::from_modules(&[self.module], &config)?)
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, b"v1")?;
    let module = build_descriptor(&target);
    Ok(Fixture {
        _dir: dir,
        root,
        module,
    })
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Builds a [`Monitor`] with real [`ExternalCheckRunner`] and
/// [`ServiceControlAdapter`]-wrapped [`SystemdManager`] hooks (both backed
/// by a fake, always-succeeding [`ProcessRunner`]), drives it over a real
/// [`Channel::pair`] exactly as a worker would, and confirms both
/// `RunCheck` and `Service` succeed end to end instead of answering
/// `Unavailable` the way `NoChecks`/`NoServices` would.
#[test]
fn monitor_runs_with_real_check_and_service_hooks() -> TestResult {
    let fx = fixture()?;
    let allow = fx.allow()?;
    let staging_dir = allow.state_root().with_file_name("monitor-staging");

    let checks = ExternalCheckRunner::with_runner(Box::new(AlwaysOk));
    let services = ServiceControlAdapter(Box::new(SystemdManager::with_runner(Box::new(AlwaysOk))));

    let (monitor_end, worker_end) = Channel::pair()?;
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let hooks = Hooks {
            checks: &checks,
            services: &services,
        };
        let mut monitor = Monitor::new(allow, hooks);
        monitor.set_staging_dir(staging_dir);
        monitor.serve(&mut channel)
    });

    let mut client = Client::new(worker_end);
    client.hello()?;
    let check = client
        .check_id("samba")
        .ok_or("the fixture's own module must advertise its own check")?;
    let binding = client
        .binding_id("samba")
        .ok_or("the fixture's own module must advertise its own binding")?;

    let checked = client.run_check(check, b"candidate".to_vec())?;
    assert!(
        checked.passed,
        "ExternalCheckRunner should report ExitZero as passed"
    );

    let service_outcome = client.service(binding, ServiceAction::Restart)?;
    assert!(
        service_outcome.active,
        "SystemdManager's restart should report the unit active afterwards"
    );

    client.shutdown()?;
    let Ok(result) = handle.join() else {
        return Err("the monitor thread must not panic".into());
    };
    assert_eq!(result.ok(), Some(ExitReason::Shutdown));
    Ok(())
}
