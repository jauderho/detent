//! `RealProcessRunner` execution discipline (PLAN §2.4; Phase 2 task 4):
//! environment clearing, output capping, and timeout/kill/reap, all against
//! real absolute-path binaries (no shell, matching production discipline).
//! Every test auto-skips when the binary it needs is absent from this host.

use std::path::Path;
use std::time::{Duration, Instant};

use detent_platform::service::exec::{OUTPUT_CAP, ProcessRunner, RealProcessRunner};

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn find(candidates: &[&'static str]) -> Option<&'static str> {
    candidates.iter().copied().find(|p| Path::new(p).exists())
}

#[test]
fn real_command_environment_is_cleared_except_lc_all() -> TestResult {
    let Some(env_bin) = find(&["/usr/bin/env", "/bin/env"]) else {
        eprintln!("skipping: no /usr/bin/env or /bin/env on this host");
        return Ok(());
    };
    let output = RealProcessRunner.run(env_bin, &[], Duration::from_secs(5))?;
    assert!(!output.timed_out);
    assert_eq!(output.status, Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.lines().any(|line| line == "LC_ALL=C"),
        "expected LC_ALL=C in child env, got: {text:?}"
    );
    assert!(
        !text.contains("PATH="),
        "PATH should have been cleared, got: {text:?}"
    );
    assert!(
        !text.contains("HOME="),
        "HOME should have been cleared, got: {text:?}"
    );
    Ok(())
}

#[test]
fn real_timeout_kills_and_reaps_a_slow_child() -> TestResult {
    let Some(sleep_bin) = find(&["/bin/sleep", "/usr/bin/sleep"]) else {
        eprintln!("skipping: no /bin/sleep or /usr/bin/sleep on this host");
        return Ok(());
    };
    let started = Instant::now();
    let output = RealProcessRunner.run(sleep_bin, &["5".to_owned()], Duration::from_millis(150))?;
    let elapsed = started.elapsed();
    assert!(output.timed_out);
    assert_eq!(output.status, None);
    assert!(
        elapsed < Duration::from_secs(3),
        "expected the child to be killed well before its 5s sleep completed, took {elapsed:?}"
    );
    Ok(())
}

#[test]
fn real_output_cap_limits_captured_stdout() -> TestResult {
    let Some(dd_bin) = find(&["/bin/dd", "/usr/bin/dd"]) else {
        eprintln!("skipping: no /bin/dd or /usr/bin/dd on this host");
        return Ok(());
    };
    // 200 KiB of zero bytes, well over the 64 KiB cap.
    let args = vec![
        "if=/dev/zero".to_owned(),
        "bs=1024".to_owned(),
        "count=200".to_owned(),
    ];
    let output = RealProcessRunner.run(dd_bin, &args, Duration::from_secs(10))?;
    assert!(!output.timed_out);
    assert_eq!(output.status, Some(0));
    assert_eq!(
        output.stdout.len(),
        OUTPUT_CAP,
        "captured stdout should be capped at exactly OUTPUT_CAP bytes"
    );
    Ok(())
}

#[test]
fn real_spawn_of_a_nonexistent_absolute_path_is_an_error() {
    let result = RealProcessRunner.run(
        "/nonexistent/detent-service-exec-integration-test",
        &[],
        Duration::from_secs(1),
    );
    assert!(result.is_err());
}
