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

#[cfg(feature = "mcp")]
#[test]
fn mcp_stdio_answers_initialize() -> TestResult {
    use std::io::{BufRead, BufReader};
    use std::time::Duration;

    let tmp = tempfile::tempdir()?;
    let state_root = tmp.path().join("state-root");
    std::fs::create_dir_all(&state_root)?;
    let state_arg = state_root.to_string_lossy().to_string();

    let create = run(
        &[
            "--state-root",
            &state_arg,
            "token",
            "create",
            "test-token",
            "--json",
        ],
        "",
    )?;
    if create.status.code() != Some(0) {
        return Err(format!(
            "token create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        )
        .into());
    }
    let created: serde_json::Value = serde_json::from_slice(&create.stdout)?;
    let token = created
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("missing token field")?
        .to_owned();

    let mut child = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(["--state-root", &state_arg, "mcp"])
        .env("DETENT_MCP_TOKEN", &token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    let mut stdin_thread = Some(std::thread::spawn(move || {
        use std::io::Write as _;
        let mut stdin = stdin;
        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.0"}
            }
        });
        let _ = writeln!(stdin, "{line}");
        let _ = stdin.flush();
    }));

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            let _ = tx.send(line);
        }
    });

    let reply =
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| -> Box<dyn std::error::Error> {
                let _ = child.kill();
                "mcp stdio did not answer initialize within 10s (deadlocked stdio?)".into()
            })?;

    let _ = child.kill();
    let _ = child.wait();
    if let Some(h) = stdin_thread.take() {
        let _ = h.join();
    }

    if !(reply.contains("\"id\":1") || reply.contains("\"id\": 1")) {
        return Err(format!("reply missing id 1: {reply}").into());
    }
    if !reply.contains("\"result\"") {
        return Err(format!("reply missing result: {reply}").into());
    }
    Ok(())
}
