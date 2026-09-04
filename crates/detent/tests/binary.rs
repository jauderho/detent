//! The binary itself: argv in, streams and an exit status out.
//!
//! The unit tests in `src/` drive `run` directly with injected streams, which
//! covers everything except `main` — the clap error path, the stdio locks and
//! the mapping from [`detent::output::Exit`] to a process status. Only a real
//! subprocess proves those, so this file spawns `CARGO_BIN_EXE_detent`.
//!
//! Every command here is read-only: a test must never write `/etc`.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Runs the binary with `args` and `stdin`, returning its output.
fn run(args: &[&str], stdin: &str) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

/// The exit status as a number, or `None` when a signal killed the process.
fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn help_and_version_succeed() -> TestResult {
    let help = run(&["--help"], "")?;
    assert_eq!(code(&help), Some(0));
    let text = String::from_utf8(help.stdout)?;
    assert!(text.contains("Exit codes"), "{text}");
    assert!(text.contains("--dryrun"), "{text}");

    let version = run(&["--version"], "")?;
    assert_eq!(code(&version), Some(0));
    assert!(String::from_utf8(version.stdout)?.contains("detent"));
    Ok(())
}

#[test]
fn a_usage_error_exits_two_and_says_so_on_stderr() -> TestResult {
    for args in [
        vec!["no-such-command"],
        vec!["config", "hosts"],
        vec!["completions", "csh"],
    ] {
        let output = run(&args, "")?;
        assert_eq!(code(&output), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
        assert!(!output.stderr.is_empty(), "{args:?} said nothing");
    }
    Ok(())
}

#[test]
fn malformed_stdin_is_a_usage_error_too() -> TestResult {
    let output = run(&["config", "hosts", "validate"], "not json")?;
    assert_eq!(code(&output), Some(2));
    assert!(String::from_utf8(output.stderr)?.contains("json"));
    Ok(())
}

#[test]
fn an_unknown_module_exits_one() -> TestResult {
    let output = run(&["config", "no-such-module", "defaults"], "")?;
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    Ok(())
}

#[test]
fn host_and_completions_write_to_stdout_and_exit_zero() -> TestResult {
    let host = run(&["host", "--json"], "")?;
    assert_eq!(
        code(&host),
        Some(0),
        "{}",
        String::from_utf8_lossy(&host.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&host.stdout)?;
    assert!(
        parsed.pointer("/host/profile/hostname").is_some(),
        "{parsed}"
    );

    let completions = run(&["completions", "bash"], "")?;
    assert_eq!(code(&completions), Some(0));
    assert!(String::from_utf8(completions.stdout)?.contains("complete -F _detent detent"));
    Ok(())
}

#[test]
fn verbose_notes_go_to_stderr_and_leave_stdout_machine_readable() -> TestResult {
    let output = run(&["--verbose", "--json", "host"], "")?;
    assert_eq!(code(&output), Some(0));
    let _: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let notes = String::from_utf8(output.stderr)?;
    assert!(notes.contains("locale"), "{notes}");
    Ok(())
}

#[test]
fn a_dry_run_serve_starts_nothing() -> TestResult {
    let output = run(&["serve", "--dryrun"], "")?;
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("dry run"), "{text}");
    Ok(())
}
