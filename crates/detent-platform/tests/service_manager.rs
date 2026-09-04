//! `SystemdManager`/`OpenRcManager`/`LaunchdManager` behaviour (PLAN §1.6,
//! §2.3, §2.4; Phase 2 task 4): exact argv per backend/action, unit-name
//! alternatives resolution, status parsing, and unit-name validation
//! happening before any process spawn.
//!
//! Every test below injects [`FakeRunner`] instead of touching the real
//! system, except the `real_*_smoke_test` functions at the bottom, which
//! auto-skip (rather than `#[ignore]`) when the backend's program is absent
//! from this host — matching the CI convention used elsewhere in this crate
//! (`detent_platform::host::tests::detect_real_smoke_test`).

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use detent_core::descriptor::{ServiceAction, UnitNames};
use detent_platform::service::exec::{ACTION_TIMEOUT, ProcessError, ProcessOutput, ProcessRunner};
use detent_platform::service::{
    LaunchdManager, OpenRcManager, ServiceError, ServiceManager, State, SystemdManager,
};

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Fake process runner
// ---------------------------------------------------------------------------

/// Records the exact `(program, argv, timeout)` of every [`ProcessRunner::run`]
/// call and replays scripted responses in order, so a test can assert the
/// exact argv a backend produced without touching the real system.
///
/// `exists` is never recorded as a "call": it is a filesystem check, not a
/// process spawn, which is exactly the distinction the unit-name-validation
/// tests below rely on.
#[derive(Default)]
struct FakeRunner {
    existing: Vec<&'static str>,
    responses: Mutex<VecDeque<Result<ProcessOutput, ProcessError>>>,
    calls: Mutex<Vec<(String, Vec<String>, Duration)>>,
}

impl FakeRunner {
    fn new() -> Self {
        Self::default()
    }

    fn existing(mut self, paths: &[&'static str]) -> Self {
        self.existing = paths.to_vec();
        self
    }

    fn respond(self, output: ProcessOutput) -> Self {
        if let Ok(mut queue) = self.responses.lock() {
            queue.push_back(Ok(output));
        }
        self
    }

    fn calls(&self) -> Vec<(String, Vec<String>, Duration)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn exists_inner(&self, path: &'static str) -> bool {
        self.existing.contains(&path)
    }

    fn run_inner(
        &self,
        program: &'static str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((program.to_owned(), args.to_vec(), timeout));
        }
        let next = self
            .responses
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front());
        next.unwrap_or_else(|| Ok(output_ok("")))
    }
}

/// A cloneable, `ProcessRunner`-implementing handle to a shared
/// [`FakeRunner`]. Needed because the orphan rule forbids implementing an
/// upstream trait ([`ProcessRunner`]) directly on an upstream type
/// (`Arc<FakeRunner>`) from an integration-test crate; this local newtype
/// lets each test keep an `Arc<FakeRunner>` for assertions while also
/// handing a `Box<dyn ProcessRunner>` to the manager under test.
#[derive(Clone)]
struct SharedFake(Arc<FakeRunner>);

impl ProcessRunner for SharedFake {
    fn exists(&self, path: &'static str) -> bool {
        self.0.exists_inner(path)
    }

    fn run(
        &self,
        program: &'static str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        self.0.run_inner(program, args, timeout)
    }
}

/// Leaks `items` to `'static`, for constructing a [`UnitNames`] alternatives
/// list from runtime (e.g. loop-bound) strings in tests. Production code
/// never does this: every real [`UnitNames`] is a compile-time constant.
fn leak_slice(items: Vec<&'static str>) -> &'static [&'static str] {
    Box::leak(items.into_boxed_slice())
}

fn output_ok(stdout: &str) -> ProcessOutput {
    ProcessOutput {
        status: Some(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        timed_out: false,
    }
}

fn output_fail(code: i32) -> ProcessOutput {
    ProcessOutput {
        status: Some(code),
        stdout: Vec::new(),
        stderr: b"boom".to_vec(),
        timed_out: false,
    }
}

fn output_timeout() -> ProcessOutput {
    ProcessOutput {
        status: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: true,
    }
}

/// `systemctl show` output for a unit that is loaded and active.
fn systemd_loaded_active() -> ProcessOutput {
    output_ok("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n")
}

/// `systemctl show` output for a unit systemd has never heard of.
fn systemd_not_found() -> ProcessOutput {
    output_ok("LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n")
}

// ---------------------------------------------------------------------------
// systemd: argv per action
// ---------------------------------------------------------------------------

/// A literal, not a `let` binding, so `&[UNIT]` below is a constant
/// expression eligible for `'static` rvalue promotion.
const UNIT: &str = "chronyd.service";

#[test]
fn systemd_act_produces_exact_argv_for_every_action() -> TestResult {
    let unit = UNIT;
    let units = UnitNames {
        systemd: &[UNIT],
        openrc: &[],
        bsdrc: &[],
    };
    for (action, verb) in [
        (ServiceAction::Restart, "restart"),
        (ServiceAction::Reload, "reload"),
        (ServiceAction::Start, "start"),
        (ServiceAction::Stop, "stop"),
    ] {
        let fake = Arc::new(
            FakeRunner::new()
                .existing(&["/usr/bin/systemctl"])
                .respond(systemd_loaded_active()) // resolve() probe
                .respond(output_ok("")), // the action itself
        );
        let mgr = SystemdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
        let outcome = mgr.act(&units, action)?;
        assert_eq!(outcome.unit, unit);
        assert!(outcome.succeeded, "action {action:?} should have succeeded");
        assert_eq!(outcome.active, !matches!(action, ServiceAction::Stop));

        let calls = fake.calls();
        let last = calls.last().ok_or("expected at least one recorded call")?;
        assert_eq!(last.0, "/usr/bin/systemctl");
        assert_eq!(last.1, vec![verb.to_owned(), unit.to_owned()]);
        assert_eq!(last.2, ACTION_TIMEOUT);
    }
    Ok(())
}

#[test]
fn systemd_act_reports_a_nonzero_exit_as_failure_without_panicking() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(systemd_loaded_active())
            .respond(output_fail(1)),
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    let outcome = mgr.act(&units, ServiceAction::Restart)?;
    assert!(!outcome.succeeded);
    assert!(!outcome.active);
    assert!(outcome.detail.contains("boom"));
    Ok(())
}

#[test]
fn systemd_act_reports_a_timeout_without_panicking() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(systemd_loaded_active())
            .respond(output_timeout()),
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    let outcome = mgr.act(&units, ServiceAction::Restart)?;
    assert!(!outcome.succeeded);
    assert!(outcome.detail.contains("timed out"));
    Ok(())
}

// ---------------------------------------------------------------------------
// systemd: alternatives resolution
// ---------------------------------------------------------------------------

#[test]
fn systemd_resolution_skips_a_missing_first_alternative() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service", "chrony.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(systemd_not_found()) // chronyd.service: absent
            .respond(systemd_loaded_active()), // chrony.service: present
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let status = mgr.status(&units)?;
    assert_eq!(status.unit, "chrony.service");

    let calls = fake.calls();
    // The successful second probe doubles as the status query: no separate
    // "status show" call follows it.
    assert_eq!(calls.len(), 2, "1 failed probe + 1 successful probe");
    let first = calls.first().ok_or("expected a first call")?;
    let second = calls.get(1).ok_or("expected a second call")?;
    assert_eq!(first.1.get(1), Some(&"chronyd.service".to_owned()));
    assert_eq!(second.1.get(1), Some(&"chrony.service".to_owned()));
    Ok(())
}

#[test]
fn systemd_resolution_caches_across_calls() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(systemd_loaded_active()) // resolution, first status()
            .respond(systemd_loaded_active()) // second status() query
            .respond(systemd_loaded_active()), // third status() query
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    mgr.status(&units)?;
    mgr.status(&units)?;
    mgr.status(&units)?;
    // The first status() call's resolution probe doubles as its status
    // query (1 call); the second and third are cache hits, each needing
    // one fresh `systemctl show` (1 call apiece) — 3 total, never a
    // resolution probe per call.
    assert_eq!(fake.calls().len(), 3);
    Ok(())
}

#[test]
fn systemd_resolution_reports_every_alternative_tried_when_none_exist() -> TestResult {
    let units = UnitNames {
        systemd: &["a.service", "b.service", "c.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(systemd_not_found())
            .respond(systemd_not_found())
            .respond(systemd_not_found()),
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    let err = mgr.status(&units).err().ok_or("expected NoKnownUnit")?;
    match err {
        ServiceError::NoKnownUnit { tried } => {
            assert_eq!(tried, vec!["a.service", "b.service", "c.service"]);
        }
        other => return Err(format!("expected NoKnownUnit, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn systemd_reports_unavailable_when_systemctl_is_absent() {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(FakeRunner::new()); // nothing exists
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    assert!(matches!(
        mgr.status(&units),
        Err(ServiceError::Unavailable(_))
    ));
}

#[test]
fn systemd_show_timeout_during_resolution_is_reported_as_failed() {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            .respond(output_timeout()),
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    let result = mgr.status(&units);
    assert!(matches!(result, Err(ServiceError::Failed(_))));
    if let Err(ServiceError::Failed(message)) = result {
        assert!(message.contains("timed out"));
    }
}

// ---------------------------------------------------------------------------
// systemd: status parsing
// ---------------------------------------------------------------------------

#[test]
fn systemd_status_parses_every_active_state() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    for (wire, expected) in [
        ("active", State::Active),
        ("inactive", State::Inactive),
        ("failed", State::Failed),
        ("activating", State::Activating),
        ("deactivating", State::Deactivating),
    ] {
        let show = output_ok(&format!(
            "LoadState=loaded\nActiveState={wire}\nUnitFileState=enabled\n"
        ));
        let fake = Arc::new(
            FakeRunner::new()
                .existing(&["/usr/bin/systemctl"])
                .respond(show),
        );
        let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
        let status = mgr.status(&units)?;
        assert_eq!(status.state, expected, "ActiveState={wire}");
        assert_eq!(status.enabled, Some(true));
    }
    Ok(())
}

#[test]
fn systemd_status_reports_unknown_rather_than_erroring_on_malformed_output() -> TestResult {
    let units = UnitNames {
        systemd: &["chronyd.service"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/usr/bin/systemctl"])
            // `LoadState=loaded` so resolution succeeds; everything after
            // it is garbage, exercising the "can't parse ActiveState"
            // path rather than the "unit doesn't exist" path.
            .respond(output_ok(
                "LoadState=loaded\nthis is not key=value output at all",
            )),
    );
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(fake)));
    let status = mgr.status(&units)?;
    assert_eq!(status.state, State::Unknown);
    assert_eq!(status.enabled, None);
    Ok(())
}

// ---------------------------------------------------------------------------
// unit-name validation happens before any process spawn
// ---------------------------------------------------------------------------

#[test]
fn invalid_unit_names_are_rejected_before_any_process_is_run() {
    for bad in ["../evil", "a/b", "", "a;rm -rf /", "a\nb", "a b"] {
        let units = UnitNames {
            systemd: leak_slice(vec![bad]),
            openrc: leak_slice(vec![bad]),
            bsdrc: &[],
        };
        let fake =
            Arc::new(FakeRunner::new().existing(&["/usr/bin/systemctl", "/sbin/rc-service"]));
        let systemd = SystemdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
        assert!(
            matches!(
                systemd.status(&units),
                Err(ServiceError::InvalidUnitName(_))
            ),
            "expected {bad:?} to be rejected by SystemdManager"
        );
        assert!(
            fake.calls().is_empty(),
            "no process should have been run for invalid unit {bad:?}, but got {:?}",
            fake.calls()
        );

        let openrc = OpenRcManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
        assert!(
            matches!(openrc.status(&units), Err(ServiceError::InvalidUnitName(_))),
            "expected {bad:?} to be rejected by OpenRcManager"
        );
        assert!(fake.calls().is_empty());
    }
}

#[test]
fn overlong_unit_name_is_rejected() {
    let long = "a".repeat(300);
    let leaked: &'static str = Box::leak(long.into_boxed_str());
    let units = UnitNames {
        systemd: leak_slice(vec![leaked]),
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(FakeRunner::new().existing(&["/usr/bin/systemctl"]));
    let mgr = SystemdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    assert!(matches!(
        mgr.status(&units),
        Err(ServiceError::InvalidUnitName(_))
    ));
    assert!(fake.calls().is_empty());
}

// ---------------------------------------------------------------------------
// OpenRC: argv per action and alternatives resolution
// ---------------------------------------------------------------------------

/// A literal, not a `let` binding, so `&[OPENRC_UNIT]` below is a constant
/// expression eligible for `'static` rvalue promotion.
const OPENRC_UNIT: &str = "chronyd";

#[test]
fn openrc_act_produces_exact_argv_for_every_action() -> TestResult {
    let unit = OPENRC_UNIT;
    let units = UnitNames {
        systemd: &[],
        openrc: &[OPENRC_UNIT],
        bsdrc: &[],
    };
    for (action, verb) in [
        (ServiceAction::Restart, "restart"),
        (ServiceAction::Reload, "reload"),
        (ServiceAction::Start, "start"),
        (ServiceAction::Stop, "stop"),
    ] {
        let fake = Arc::new(
            FakeRunner::new()
                .existing(&["/sbin/rc-service"])
                .respond(output_ok("")) // -e resolution probe: exit 0 => exists
                .respond(output_ok("")), // the action itself
        );
        let mgr = OpenRcManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
        let outcome = mgr.act(&units, action)?;
        assert_eq!(outcome.unit, unit);
        assert!(outcome.succeeded);

        let calls = fake.calls();
        let last = calls.last().ok_or("expected at least one recorded call")?;
        assert_eq!(last.0, "/sbin/rc-service");
        assert_eq!(last.1, vec![unit.to_owned(), verb.to_owned()]);
        assert_eq!(last.2, ACTION_TIMEOUT);
    }
    Ok(())
}

#[test]
fn openrc_resolution_probes_with_the_exists_flag() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd", "chrony"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_fail(1)) // "chronyd" does not exist
            .respond(output_ok("")) // "chrony" exists
            .respond(output_ok(" * status:  started")),
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let status = mgr.status(&units)?;
    assert_eq!(status.unit, "chrony");
    assert_eq!(status.state, State::Active);

    let calls = fake.calls();
    let first = calls.first().ok_or("expected a first call")?;
    let second = calls.get(1).ok_or("expected a second call")?;
    assert_eq!(first.1, vec!["-e".to_owned(), "chronyd".to_owned()]);
    assert_eq!(second.1, vec!["-e".to_owned(), "chrony".to_owned()]);
    Ok(())
}

#[test]
fn openrc_reports_every_status_keyword_through_the_manager() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    for (text, expected) in [
        (" * status:  started", State::Active),
        (" * status:  stopped", State::Inactive),
        (" * status:  crashed", State::Failed),
    ] {
        let fake = Arc::new(
            FakeRunner::new()
                .existing(&["/sbin/rc-service"])
                .respond(output_ok(""))
                .respond(output_ok(text)),
        );
        let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
        let status = mgr.status(&units)?;
        assert_eq!(status.state, expected, "text={text:?}");
        assert_eq!(status.enabled, None);
    }
    Ok(())
}

#[test]
fn openrc_status_reports_unknown_on_a_status_query_timeout() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_ok("")) // -e probe: exists
            .respond(output_timeout()), // status query: times out
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
    let status = mgr.status(&units)?;
    assert_eq!(status.state, State::Unknown);
    Ok(())
}

#[test]
fn openrc_resolution_reports_every_alternative_tried_when_none_exist() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd", "chrony"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_fail(1))
            .respond(output_fail(1)),
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
    let err = mgr.status(&units).err().ok_or("expected NoKnownUnit")?;
    match err {
        ServiceError::NoKnownUnit { tried } => {
            assert_eq!(tried, vec!["chronyd", "chrony"]);
        }
        other => return Err(format!("expected NoKnownUnit, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn openrc_reports_unavailable_when_rc_service_is_absent() {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    let fake = Arc::new(FakeRunner::new()); // nothing exists
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
    assert!(matches!(
        mgr.status(&units),
        Err(ServiceError::Unavailable(_))
    ));
}

#[test]
fn openrc_resolution_caches_across_calls() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_ok("")) // -e probe, first status()
            .respond(output_ok(" * status:  started")) // first status() query
            .respond(output_ok(" * status:  started")), // second status() query
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    mgr.status(&units)?;
    mgr.status(&units)?;
    // 1 resolution probe + 2 status queries, never a second resolution probe.
    assert_eq!(fake.calls().len(), 3);
    Ok(())
}

#[test]
fn openrc_act_reports_a_nonzero_exit_as_failure_without_panicking() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_ok("")) // -e probe: exists
            .respond(output_fail(1)), // the action itself fails
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
    let outcome = mgr.act(&units, ServiceAction::Restart)?;
    assert!(!outcome.succeeded);
    assert!(!outcome.active);
    assert!(outcome.detail.contains("boom"));
    Ok(())
}

#[test]
fn openrc_act_reports_a_timeout_without_panicking() -> TestResult {
    let units = UnitNames {
        systemd: &[],
        openrc: &["chronyd"],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/sbin/rc-service"])
            .respond(output_ok(""))
            .respond(output_timeout()),
    );
    let mgr = OpenRcManager::with_runner(Box::new(SharedFake(fake)));
    let outcome = mgr.act(&units, ServiceAction::Restart)?;
    assert!(!outcome.succeeded);
    assert!(outcome.detail.contains("timed out"));
    Ok(())
}

// ---------------------------------------------------------------------------
// launchd: status-only, act is unsupported
// ---------------------------------------------------------------------------

#[test]
fn launchd_act_is_unsupported_and_never_spawns_a_process() {
    let units = UnitNames {
        systemd: &["org.example.thing"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(FakeRunner::new().existing(&["/bin/launchctl"]));
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    assert!(matches!(
        mgr.act(&units, ServiceAction::Restart),
        Err(ServiceError::Unsupported(_))
    ));
    assert!(fake.calls().is_empty());
}

#[test]
fn launchd_status_reports_active_when_a_pid_is_present() -> TestResult {
    let units = UnitNames {
        systemd: &["org.example.thing"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/bin/launchctl"])
            .respond(output_ok(
                "{\n\t\"PID\" = 123;\n\t\"Label\" = \"org.example.thing\";\n}",
            )),
    );
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let status = mgr.status(&units)?;
    assert_eq!(status.state, State::Active);
    assert_eq!(status.unit, "org.example.thing");

    let calls = fake.calls();
    let call = calls.first().ok_or("expected one call")?;
    assert_eq!(call.0, "/bin/launchctl");
    assert_eq!(
        call.1,
        vec!["list".to_owned(), "org.example.thing".to_owned()]
    );
    Ok(())
}

#[test]
fn launchd_status_reports_inactive_without_a_pid() -> TestResult {
    let units = UnitNames {
        systemd: &["org.example.thing"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/bin/launchctl"])
            .respond(output_ok("{\n\t\"Label\" = \"org.example.thing\";\n}")),
    );
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(fake)));
    let status = mgr.status(&units)?;
    assert_eq!(status.state, State::Inactive);
    Ok(())
}

#[test]
fn launchd_reports_unavailable_when_launchctl_is_absent() {
    let units = UnitNames {
        systemd: &["org.example.thing"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(FakeRunner::new()); // nothing exists
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(fake)));
    assert!(matches!(
        mgr.status(&units),
        Err(ServiceError::Unavailable(_))
    ));
}

#[test]
fn launchd_resolution_reports_every_label_tried_when_none_load() -> TestResult {
    let units = UnitNames {
        systemd: &["org.example.a", "org.example.b"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/bin/launchctl"])
            .respond(output_fail(1))
            .respond(output_fail(1)),
    );
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(fake)));
    let err = mgr.status(&units).err().ok_or("expected NoKnownUnit")?;
    match err {
        ServiceError::NoKnownUnit { tried } => {
            assert_eq!(tried, vec!["org.example.a", "org.example.b"]);
        }
        other => return Err(format!("expected NoKnownUnit, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn launchd_resolution_caches_across_calls() -> TestResult {
    let units = UnitNames {
        systemd: &["org.example.thing"],
        openrc: &[],
        bsdrc: &[],
    };
    let fake = Arc::new(
        FakeRunner::new()
            .existing(&["/bin/launchctl"])
            .respond(output_ok("{\n\t\"PID\" = 1;\n}")) // resolution, first status()
            .respond(output_ok("{\n\t\"PID\" = 1;\n}")), // second status() query
    );
    let mgr = LaunchdManager::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    mgr.status(&units)?;
    mgr.status(&units)?;
    // 1 resolution probe (doubling as the first status) + 1 fresh query for
    // the cache-hit second call, never a second resolution probe.
    assert_eq!(fake.calls().len(), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// Real-system smoke tests. Auto-skip when the backend's program is absent.
// ---------------------------------------------------------------------------

#[test]
fn real_systemctl_show_smoke_test() -> TestResult {
    if !Path::new("/usr/bin/systemctl").exists() && !Path::new("/bin/systemctl").exists() {
        eprintln!("skipping real_systemctl_show_smoke_test: systemctl not present");
        return Ok(());
    }
    let mgr = SystemdManager::new();
    // `init.scope` always exists under a *running* systemd (PID 1's own
    // cgroup scope). A container that has the `systemd` package installed
    // but is not actually booted with systemd as PID 1 (common for `apt-get
    // install systemd` inside `docker run`) legitimately reports it as
    // `not-found` instead: `systemctl` itself still ran correctly, so
    // `NoKnownUnit` is accepted here alongside success. Only `Unavailable`
    // (the binary could not be resolved, contradicting the `Path::exists`
    // check above) or `Failed` (the process itself misbehaved) fail the
    // test.
    let units = UnitNames {
        systemd: &["init.scope"],
        openrc: &[],
        bsdrc: &[],
    };
    match mgr.status(&units) {
        Ok(status) => assert_eq!(status.unit, "init.scope"),
        Err(ServiceError::NoKnownUnit { .. }) => {}
        Err(other) => return Err(format!("unexpected error: {other}").into()),
    }
    Ok(())
}

#[test]
fn real_rc_service_smoke_test() -> TestResult {
    if !Path::new("/sbin/rc-service").exists() {
        eprintln!("skipping real_rc_service_smoke_test: rc-service not present");
        return Ok(());
    }
    let mgr = OpenRcManager::new();
    // If OpenRC is present, at least one of these is virtually guaranteed;
    // if none resolve, `NoKnownUnit` is still a well-formed, non-panicking
    // result, which is what this smoke test actually verifies.
    let units = UnitNames {
        systemd: &[],
        openrc: &["sshd", "networking", "hostname"],
        bsdrc: &[],
    };
    match mgr.status(&units) {
        Ok(status) => assert!(!status.unit.is_empty()),
        Err(ServiceError::NoKnownUnit { .. }) => {}
        Err(other) => return Err(format!("unexpected error: {other}").into()),
    }
    Ok(())
}

#[test]
fn real_launchctl_list_smoke_test() -> TestResult {
    if !Path::new("/bin/launchctl").exists() {
        eprintln!("skipping real_launchctl_list_smoke_test: launchctl not present");
        return Ok(());
    }
    let mgr = LaunchdManager::new();
    // `com.apple.Finder` is loaded on every real macOS session.
    let units = UnitNames {
        systemd: &["com.apple.Finder"],
        openrc: &[],
        bsdrc: &[],
    };
    let status = mgr.status(&units)?;
    assert_eq!(status.unit, "com.apple.Finder");
    Ok(())
}
