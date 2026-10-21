//! `ExternalCheckRunner` behaviour (PLAN §2.3, §2.4; Phase 2 task 4):
//! `ExitZero` pass/fail, `StdoutContains` match/miss, temp-file substitution
//! landing at the right argv position, and real-binary smoke tests.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use detent_core::descriptor::{ArgTemplate, CheckExpectation, ExternalCheck, PathSpec};
use detent_platform::privsep::monitor::CheckRunner;
use detent_platform::service::checks::ExternalCheckRunner;
use detent_platform::service::exec::{CHECK_TIMEOUT, ProcessError, ProcessOutput, ProcessRunner};

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Records the exact `(program, argv, timeout)` of every call and returns a
/// single scripted response, so a test can assert exactly what
/// [`ExternalCheckRunner`] ran without touching the real system.
#[derive(Default)]
struct FakeRunner {
    response: Mutex<Option<Result<ProcessOutput, ProcessError>>>,
    call: Mutex<Option<(String, Vec<String>, Duration)>>,
}

impl FakeRunner {
    fn with_response(self, output: ProcessOutput) -> Self {
        if let Ok(mut slot) = self.response.lock() {
            *slot = Some(Ok(output));
        }
        self
    }

    fn call(&self) -> Option<(String, Vec<String>, Duration)> {
        self.call.lock().ok().and_then(|guard| guard.clone())
    }
}

/// Local newtype around `Arc<FakeRunner>`: the orphan rule forbids
/// implementing the upstream [`ProcessRunner`] trait directly on the
/// upstream `Arc` type from this integration-test crate.
#[derive(Clone)]
struct SharedFake(Arc<FakeRunner>);

impl ProcessRunner for SharedFake {
    fn exists(&self, _path: &'static str) -> bool {
        true
    }

    fn run(
        &self,
        program: &'static str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        if let Ok(mut call) = self.0.call.lock() {
            *call = Some((program.to_owned(), args.to_vec(), timeout));
        }
        self.0
            .response
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or_else(|| {
                Ok(ProcessOutput {
                    status: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: false,
                })
            })
    }
}

fn output(status: i32, stdout: &str) -> ProcessOutput {
    ProcessOutput {
        status: Some(status),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
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

const PROGRAM: PathSpec = PathSpec::new("/usr/sbin/chronyd");

// ---------------------------------------------------------------------------
// ExitZero
// ---------------------------------------------------------------------------

#[test]
fn exit_zero_check_passes_on_a_zero_exit() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::Literal("-p"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output(0, "")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let outcome = runner
        .run_check(&check, Path::new("/tmp/detent-candidate-test"))
        .map_err(|err| err.to_string())?;
    assert!(outcome.passed);
    assert_eq!(outcome.exit_code, Some(0));
    Ok(())
}

#[test]
fn exit_zero_check_fails_on_a_nonzero_exit() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::Literal("-p"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output(1, "parse error")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let outcome = runner
        .run_check(&check, Path::new("/tmp/detent-candidate-test"))
        .map_err(|err| err.to_string())?;
    assert!(!outcome.passed);
    assert_eq!(outcome.exit_code, Some(1));
    Ok(())
}

#[test]
fn a_timed_out_check_fails_without_an_exit_code() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::Literal("-p"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output_timeout()));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let outcome = runner
        .run_check(&check, Path::new("/tmp/detent-candidate-test"))
        .map_err(|err| err.to_string())?;
    assert!(!outcome.passed);
    assert_eq!(outcome.exit_code, None);
    assert!(outcome.detail.contains("timed out"));
    Ok(())
}

// ---------------------------------------------------------------------------
// StdoutContains (plain substring — see ExternalCheckRunner's doc comment for
// why this is not a real regex match)
// ---------------------------------------------------------------------------

#[test]
fn stdout_pattern_check_passes_on_a_substring_match() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::Literal("-s")],
        expects: CheckExpectation::StdoutContains("Loaded services"),
        applies_to: &[],
        stage_as: None,
    };
    let fake =
        Arc::new(FakeRunner::default().with_response(output(0, "Loaded services file OK\n")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let outcome = runner
        .run_check(&check, Path::new("/tmp/detent-candidate-test"))
        .map_err(|err| err.to_string())?;
    assert!(outcome.passed);
    Ok(())
}

#[test]
fn stdout_pattern_check_fails_when_the_substring_is_absent() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::Literal("-s")],
        expects: CheckExpectation::StdoutContains("Loaded services"),
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output(0, "nothing relevant here")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let outcome = runner
        .run_check(&check, Path::new("/tmp/detent-candidate-test"))
        .map_err(|err| err.to_string())?;
    assert!(!outcome.passed);
    Ok(())
}

// ---------------------------------------------------------------------------
// Argv assembly: literals and TempFile substitution land at the right
// position, in order.
// ---------------------------------------------------------------------------

#[test]
fn temp_file_is_substituted_at_the_declared_position() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[
            ArgTemplate::Literal("-p"),
            ArgTemplate::Literal("-f"),
            ArgTemplate::TempFile,
        ],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output(0, "")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    runner
        .run_check(&check, Path::new("/tmp/detent-candidate-xyz"))
        .map_err(|err| err.to_string())?;

    let (program, args, timeout) = fake.call().ok_or("expected exactly one call")?;
    assert_eq!(program, "/usr/sbin/chronyd");
    assert_eq!(
        args,
        vec![
            "-p".to_owned(),
            "-f".to_owned(),
            "/tmp/detent-candidate-xyz".to_owned(),
        ]
    );
    assert_eq!(timeout, CHECK_TIMEOUT);
    Ok(())
}

#[test]
fn temp_file_may_appear_before_trailing_literals() -> TestResult {
    let check = ExternalCheck {
        program: PROGRAM,
        args: &[ArgTemplate::TempFile, ArgTemplate::Literal("--strict")],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default().with_response(output(0, "")));
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    runner
        .run_check(&check, Path::new("/tmp/candidate-abc"))
        .map_err(|err| err.to_string())?;

    let (_, args, _) = fake.call().ok_or("expected exactly one call")?;
    assert_eq!(
        args,
        vec!["/tmp/candidate-abc".to_owned(), "--strict".to_owned()]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-absolute program paths are rejected before any process is run.
// ---------------------------------------------------------------------------

#[test]
fn a_relative_program_path_is_rejected_without_spawning() {
    let check = ExternalCheck {
        program: PathSpec::new("chronyd"),
        args: &[ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let fake = Arc::new(FakeRunner::default());
    let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
    let result = runner.run_check(&check, Path::new("/tmp/x"));
    assert!(result.is_err());
    assert!(fake.call().is_none());
}

// ---------------------------------------------------------------------------
// Real-system smoke test. Auto-skips when the tool is absent.
// ---------------------------------------------------------------------------

#[test]
fn real_true_and_false_smoke_test() -> TestResult {
    let true_path = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let Some(true_path) = true_path else {
        eprintln!("skipping real_true_and_false_smoke_test: no /usr/bin/true or /bin/true");
        return Ok(());
    };
    let false_path = ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or("expected a false binary alongside a true binary")?;

    let true_leaked: &'static str = Box::leak(true_path.to_owned().into_boxed_str());
    let false_leaked: &'static str = Box::leak(false_path.to_owned().into_boxed_str());

    let passing = ExternalCheck {
        program: PathSpec::new(true_leaked),
        args: &[],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let failing = ExternalCheck {
        program: PathSpec::new(false_leaked),
        args: &[],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
    };
    let runner = ExternalCheckRunner::new();
    let ok = runner
        .run_check(&passing, Path::new("/tmp/unused"))
        .map_err(|err| err.to_string())?;
    assert!(ok.passed);
    let bad = runner
        .run_check(&failing, Path::new("/tmp/unused"))
        .map_err(|err| err.to_string())?;
    assert!(!bad.passed);
    Ok(())
}

// ---------------------------------------------------------------------------
// A validator that reads a tree: the candidate is staged under a fresh root
// (`ExternalCheck::stage_as`, netplan).
// ---------------------------------------------------------------------------

/// What [`TreeReader`] saw during its one run: the argv, and the staged file
/// read through the root it was given.
type Seen = Mutex<Option<(Vec<String>, Option<String>)>>;

/// Reads `<last argument>/etc/netplan/90-detent.yaml` while it runs, as
/// `netplan generate --root-dir` reads its tree.
struct TreeReader(Arc<Seen>);

impl ProcessRunner for TreeReader {
    fn exists(&self, _path: &'static str) -> bool {
        true
    }

    fn run(
        &self,
        _program: &'static str,
        args: &[String],
        _timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        let staged = args
            .last()
            .and_then(|root| std::fs::read_to_string(Path::new(root).join(NETPLAN_STAGE)).ok());
        if let Ok(mut seen) = self.0.lock() {
            *seen = Some((args.to_vec(), staged));
        }
        Ok(output(0, ""))
    }
}

const NETPLAN_STAGE: &str = "etc/netplan/90-detent.yaml";

const NETPLAN_CHECK: ExternalCheck = ExternalCheck {
    program: PathSpec::new("/usr/sbin/netplan"),
    args: &[
        ArgTemplate::Literal("generate"),
        ArgTemplate::Literal("--root-dir"),
        ArgTemplate::TempFile,
    ],
    expects: CheckExpectation::ExitZero,
    applies_to: &[],
    stage_as: Some(NETPLAN_STAGE),
};

#[test]
fn a_tree_validator_reads_the_candidate_staged_under_a_fresh_root() -> TestResult {
    let dir = tempfile::tempdir()?;
    let candidate = dir.path().join(".detent-candidate-abc");
    std::fs::write(&candidate, "network:\n  version: 2\n")?;
    let seen = Arc::new(Seen::default());
    let runner = ExternalCheckRunner::with_runner(Box::new(TreeReader(Arc::clone(&seen))));
    let outcome = runner
        .run_check(&NETPLAN_CHECK, &candidate)
        .map_err(|err| err.to_string())?;
    assert!(outcome.passed);
    let (args, staged) = seen
        .lock()
        .map_err(|_| "poisoned")?
        .clone()
        .ok_or("the validator never ran")?;
    let root = args.last().ok_or("no root argument")?;
    assert_eq!(
        args.get(..2),
        Some(&["generate".to_owned(), "--root-dir".to_owned()][..])
    );
    // The root is a fresh directory beside the candidate, not the candidate.
    assert_eq!(Path::new(root).parent(), Some(dir.path()));
    assert_ne!(Path::new(root), candidate);
    assert_eq!(staged.as_deref(), Some("network:\n  version: 2\n"));
    // Nothing is left behind but the candidate.
    let left: Vec<_> = std::fs::read_dir(dir.path())?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()?;
    assert_eq!(left, [std::ffi::OsString::from(".detent-candidate-abc")]);
    Ok(())
}

#[test]
fn a_tree_validator_never_runs_on_a_root_it_cannot_make() -> TestResult {
    let seen = Arc::new(Seen::default());
    let runner = ExternalCheckRunner::with_runner(Box::new(TreeReader(Arc::clone(&seen))));
    // The candidate's directory does not exist, so no root can be made.
    let result = runner.run_check(
        &NETPLAN_CHECK,
        Path::new("/nonexistent/detent/.detent-candidate-abc"),
    );
    assert!(result.is_err());
    // No file name, a stage path that leaves the root, a candidate that is
    // gone: refused, and the half-made root is removed.
    assert!(runner.run_check(&NETPLAN_CHECK, Path::new("/")).is_err());
    let escaping = ExternalCheck {
        stage_as: Some("../escape.yaml"),
        ..NETPLAN_CHECK
    };
    assert!(
        runner
            .run_check(&escaping, Path::new("/tmp/.detent-candidate-x"))
            .is_err()
    );
    let dir = tempfile::tempdir()?;
    assert!(
        runner
            .run_check(&NETPLAN_CHECK, &dir.path().join(".detent-candidate-gone"))
            .is_err()
    );
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 0);
    assert!(seen.lock().is_ok_and(|seen| seen.is_none()));
    Ok(())
}

/// The real `netplan`, when installed: a valid file passes, a broken one
/// fails, so the check judges the candidate.
#[test]
fn real_netplan_judges_the_staged_candidate() -> TestResult {
    if !Path::new("/usr/sbin/netplan").exists() {
        eprintln!("skipping real_netplan_judges_the_staged_candidate: no /usr/sbin/netplan");
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let candidate = dir.path().join(".detent-candidate-real");
    let runner = ExternalCheckRunner::new();
    std::fs::write(
        &candidate,
        "network:\n  version: 2\n  ethernets:\n    eth9:\n      addresses: [192.0.2.1/24]\n",
    )?;
    let good = runner
        .run_check(&NETPLAN_CHECK, &candidate)
        .map_err(|err| err.to_string())?;
    assert!(good.passed, "{}", good.detail);
    std::fs::write(
        &candidate,
        "network:\n  version: 2\n  ethernets: [unclosed\n",
    )?;
    let bad = runner
        .run_check(&NETPLAN_CHECK, &candidate)
        .map_err(|err| err.to_string())?;
    assert!(!bad.passed, "{}", bad.detail);
    Ok(())
}
