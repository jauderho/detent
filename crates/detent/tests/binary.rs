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

/// STAGE3 M12: refused mcp startup leaves stdout empty with tracing on.
#[cfg(feature = "mcp")]
#[test]
fn mcp_refused_startup_writes_nothing_to_stdout() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("state-root").to_string_lossy().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(["--state-root", &root, "mcp"])
        .env("DETENT_MCP_TOKEN", "bad-token")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("mcp startup refused"), "{stderr}");
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

    let token = mint_token(&state_arg, false)?;

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

/// Mints a token in `state` through the binary itself, write-scoped when
/// `write`, and returns its secret.
///
/// As root the binary refuses `token create` (exit 3; it must run as the
/// service account), which this checks before minting through the token
/// store directly, so the MCP tests still run when the suite does as root.
#[cfg(feature = "mcp")]
fn mint_token(state: &str, write: bool) -> Result<String, Box<dyn std::error::Error>> {
    if rustix::process::geteuid().is_root() {
        let refused = run(
            &[
                "--locale",
                "en-US",
                "--state-root",
                state,
                "token",
                "create",
                "mcp-test",
            ],
            "",
        )?;
        assert_eq!(code(&refused), Some(3));
        let notes = String::from_utf8(refused.stderr)?;
        assert!(notes.contains("sudo -u detent detent token"), "{notes}");
        let scope = if write {
            detent_web::authz::Scope::Write
        } else {
            detent_web::authz::Scope::Read
        };
        let store = detent_web::auth::TokenStore::load(std::path::Path::new(state))?;
        let (secret, _) = store.issue("mcp-test", scope, None)?;
        return Ok(secret.expose().to_owned());
    }
    let mut args = vec![
        "--state-root",
        state,
        "token",
        "create",
        "mcp-test",
        "--json",
    ];
    if write {
        args.push("--write");
    }
    let create = run(&args, "")?;
    if code(&create) != Some(0) {
        return Err(format!(
            "token create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        )
        .into());
    }
    let created: serde_json::Value = serde_json::from_slice(&create.stdout)?;
    Ok(created
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing token field")?
        .to_owned())
}

/// Runs `detent --locale en-US --state-root <state> <args>` with `token` (or
/// no token at all) in `DETENT_MCP_TOKEN`, stdin closed.
#[cfg(feature = "mcp")]
fn run_mcp(
    state: &str,
    token: Option<&str>,
    args: &[&str],
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_detent"));
    command
        .args(["--locale", "en-US", "--state-root", state])
        .args(args)
        .env_remove("DETENT_MCP_TOKEN")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = token {
        command.env("DETENT_MCP_TOKEN", token);
    }
    Ok(command.output()?)
}

/// The JSON-RPC message with `id` from `lines`, read from the child's
/// stdout; every line gets 30 s to arrive.
#[cfg(feature = "mcp")]
fn reply_with_id(
    lines: &std::sync::mpsc::Receiver<String>,
    id: u64,
    seen: &mut String,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    loop {
        let line = lines
            .recv_timeout(std::time::Duration::from_secs(30))
            .map_err(|_| format!("no reply with id {id} within 30 s; stdout so far: {seen}"))?;
        seen.push_str(&line);
        let value: serde_json::Value = serde_json::from_str(line.trim())?;
        if value.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
            return Ok(value);
        }
    }
}

/// `detent mcp` over stdio, as a client runs it: `cert_status` answers with
/// the certificate in `tls.cert_dir`, and `cert_renew` against a port where
/// nothing listens is a tool error that names the address. Neither stdout
/// nor the TRACE log on stderr holds the bearer token.
#[cfg(feature = "mcp")]
#[test]
fn mcp_cert_tools_answer_over_stdio_without_leaking_the_token() -> TestResult {
    use std::io::{BufRead as _, BufReader, Read as _};

    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root");
    let state_arg = state.to_string_lossy().to_string();
    let token = mint_token(&state_arg, true)?;
    let cert_dir = tmp.path().join("certs");
    let pair = detent_web::load_or_bootstrap(&cert_dir, &["box.example".to_owned()], false)?;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let config = tmp.path().join("detent.toml");
    std::fs::write(
        &config,
        format!(
            "[listen]\naddr = \"{closed}\"\n[tls]\ncert_dir = {:?}\n",
            cert_dir.display().to_string()
        ),
    )?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(["--locale", "en-US", "--state-root", &state_arg, "--config"])
        .arg(&config)
        .arg("mcp")
        .env("DETENT_MCP_TOKEN", &token)
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    let (tx, lines) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let logs = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    let request = |id: u64, method: &str, params: serde_json::Value| serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let call = |id: u64, tool: &str| {
        request(
            id,
            "tools/call",
            serde_json::json!({"name": tool, "arguments": {}}),
        )
    };
    let mut stdout_text = String::new();
    let mut exchange =
        || -> Result<(serde_json::Value, serde_json::Value), Box<dyn std::error::Error>> {
            let init = request(
                1,
                "initialize",
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0.0"}
                }),
            );
            writeln!(stdin, "{init}")?;
            reply_with_id(&lines, 1, &mut stdout_text)?;
            writeln!(
                stdin,
                "{}",
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
            )?;
            writeln!(stdin, "{}", call(2, "cert_status"))?;
            let status = reply_with_id(&lines, 2, &mut stdout_text)?;
            writeln!(stdin, "{}", call(3, "cert_renew"))?;
            let renew = reply_with_id(&lines, 3, &mut stdout_text)?;
            Ok((status, renew))
        };
    let answers = exchange();
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let stderr_text = logs.join().map_err(|_| "the stderr reader panicked")?;
    let (status, renew) = answers?;

    let status_text = status.to_string();
    assert!(status_text.contains(&pair.fingerprint()), "{status_text}");
    let renew_text = renew.to_string();
    assert!(renew_text.contains("error"), "{renew_text}");
    assert!(renew_text.contains(&closed.to_string()), "{renew_text}");

    // The renewal was audited, and the audit line reached the log being
    // checked below.
    assert!(stderr_text.contains("detent audit"), "{stderr_text}");
    let tail = token.rsplit('-').next().unwrap_or(&token).to_lowercase();
    for (what, text) in [("stdout", &stdout_text), ("stderr", &stderr_text)] {
        let lowered = text.to_lowercase();
        assert!(
            !lowered.contains(&token.to_lowercase()),
            "{what} holds the token"
        );
        assert!(!lowered.contains(&tail), "{what} holds the token's tail");
    }
    Ok(())
}

/// A pending-commit marker a crashed monitor could have left under `state`:
/// commit 7, which rolls `target` back to `backup`.
#[cfg(feature = "mcp")]
fn leave_pending_commit(
    state: &std::path::Path,
    target: &std::path::Path,
    backup: &std::path::Path,
) -> TestResult {
    std::fs::create_dir_all(state)?;
    let marker = serde_json::json!({
        "commit": 7,
        "deadline_unix_ms": 0,
        "entries": [{"target": 0, "path": target, "backup": backup}],
        "service": null,
    });
    std::fs::write(
        state.join("pending-commit.json"),
        serde_json::to_vec(&marker)?,
    )?;
    Ok(())
}

/// No `DETENT_MCP_TOKEN` refuses startup before a monitor or a listener
/// exists, and names the variable the operator has to set.
#[cfg(feature = "mcp")]
#[test]
fn mcp_without_a_token_refuses_to_start() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root").to_string_lossy().to_string();
    for token in [None, Some("")] {
        let output = run_mcp(&state, token, &["mcp"])?;
        assert_eq!(code(&output), Some(1), "{token:?}");
        assert!(output.stdout.is_empty(), "{token:?}");
        let notes = String::from_utf8(output.stderr)?;
        assert!(notes.contains("DETENT_MCP_TOKEN is not set"), "{notes}");
    }
    assert!(
        !tmp.path().join("state-root").join("monitor.lock").exists(),
        "a refused startup must not take the monitor lock"
    );
    Ok(())
}

/// A credential store that cannot be parsed refuses startup as a credential
/// failure, whatever the presented token is.
#[cfg(feature = "mcp")]
#[test]
fn mcp_with_an_unreadable_token_store_refuses_to_start() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("state-root");
    std::fs::create_dir_all(root.join("state"))?;
    std::fs::write(root.join("state").join("tokens.json"), b"not json")?;
    let output = run_mcp(&root.to_string_lossy(), Some("any"), &["mcp"])?;
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    let notes = String::from_utf8(output.stderr)?;
    assert!(
        notes.contains("the request could not be completed"),
        "{notes}"
    );
    Ok(())
}

/// `--dryrun mcp` resolves the token, starts and stops the monitor, and
/// reports the shape it would serve — the scope the token really holds —
/// without listening on anything.
#[cfg(feature = "mcp")]
#[test]
fn a_dry_run_mcp_reports_transport_address_and_scope() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root").to_string_lossy().to_string();
    let read = mint_token(&state, false)?;
    let write = mint_token(&state, true)?;

    let output = run_mcp(&state, Some(&read), &["--dryrun", "mcp"])?;
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(
        text.contains("dry run: mcp would serve stdio on 127.0.0.1:3334 with scope read."),
        "{text}"
    );

    let output = run_mcp(&state, Some(&write), &["--dryrun", "mcp"])?;
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("with scope read,write."), "{text}");
    Ok(())
}

/// A commit left pending by a crashed monitor is rolled back when `mcp`
/// starts its session, and the operator is told which commit it was.
#[cfg(feature = "mcp")]
#[test]
fn mcp_startup_recovers_a_pending_commit_and_says_so() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("state-root");
    let state = root.to_string_lossy().to_string();
    let token = mint_token(&state, false)?;
    let target = tmp.path().join("target.conf");
    let backup = tmp.path().join("target.conf.v1");
    std::fs::write(&target, b"v2")?;
    std::fs::write(&backup, b"v1")?;
    leave_pending_commit(&root, &target, &backup)?;

    let output = run_mcp(&state, Some(&token), &["--dryrun", "mcp"])?;
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&target)?, b"v1");
    assert!(!root.join("pending-commit.json").exists());
    let notes = String::from_utf8(output.stderr)?;
    assert!(
        notes.contains("recovered unconfirmed commit 7; restored 1 targets with 0 failures."),
        "{notes}"
    );
    Ok(())
}

/// A marker the monitor cannot parse stops the session from starting at
/// all: `mcp` exits 1 before serving, and the marker is left for a human.
#[cfg(feature = "mcp")]
#[test]
fn mcp_refuses_to_start_over_a_corrupt_commit_marker() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("state-root");
    let state = root.to_string_lossy().to_string();
    let token = mint_token(&state, false)?;
    std::fs::write(root.join("pending-commit.json"), b"{")?;

    let output = run_mcp(&state, Some(&token), &["--dryrun", "mcp"])?;
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    let notes = String::from_utf8(output.stderr)?;
    assert!(
        notes.contains("the privileged helper could not be started"),
        "{notes}"
    );
    assert_eq!(std::fs::read(root.join("pending-commit.json"))?, b"{");
    Ok(())
}

/// One JSON-RPC line out of the child's stdout, or an error after `wait`.
#[cfg(feature = "mcp")]
fn next_reply(
    replies: &std::sync::mpsc::Receiver<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let line = replies
        .recv_timeout(std::time::Duration::from_secs(20))
        .map_err(|_| "mcp stdio did not answer within 20s")?;
    Ok(serde_json::from_str(&line)?)
}

/// A full stdio session: `initialize`, a read tool that runs through the
/// real engine, then EOF on stdin ends the server cleanly with exit 0. While
/// it runs it owns the monitor lock, so a second `mcp` on the same state
/// root is refused as busy instead of racing it.
#[cfg(feature = "mcp")]
#[test]
fn mcp_stdio_serves_tools_until_stdin_closes() -> TestResult {
    use std::io::{BufRead as _, BufReader};

    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root").to_string_lossy().to_string();
    let token = mint_token(&state, false)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(["--locale", "en-US", "--state-root", &state, "mcp"])
        .env("DETENT_MCP_TOKEN", &token)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (tx, replies) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let outcome = (|| -> TestResult {
        let initialize = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.0"}
            }
        });
        writeln!(stdin, "{initialize}")?;
        let reply = next_reply(&replies)?;
        assert_eq!(reply.get("id"), Some(&serde_json::json!(1)), "{reply}");
        assert!(reply.get("result").is_some(), "{reply}");

        let initialized = serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        });
        let call = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_modules", "arguments": {}}
        });
        writeln!(stdin, "{initialized}")?;
        writeln!(stdin, "{call}")?;
        stdin.flush()?;
        let reply = next_reply(&replies)?;
        assert_eq!(reply.get("id"), Some(&serde_json::json!(2)), "{reply}");
        let text = reply
            .pointer("/result/content/0/text")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("no tool text in {reply}"))?;
        assert!(text.contains("hosts"), "{text}");
        assert_ne!(
            reply.pointer("/result/isError"),
            Some(&serde_json::json!(true)),
            "{reply}"
        );

        // The live server holds the state root: a second one must not start.
        let busy = run_mcp(&state, Some(&token), &["--dryrun", "mcp"])?;
        assert_eq!(code(&busy), Some(1));
        let notes = String::from_utf8(busy.stderr)?;
        assert!(
            notes.contains("another detent monitor already owns this state root"),
            "{notes}"
        );
        Ok(())
    })();

    drop(stdin);
    let status = if outcome.is_ok() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if std::time::Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    } else {
        None
    };
    if status.is_none() {
        child.kill()?;
        child.wait()?;
    }
    reader.join().map_err(|_| "stdout reader panicked")?;
    outcome?;
    let status = status.ok_or("mcp stdio did not exit after stdin closed")?;
    assert_eq!(status.code(), Some(0));
    let mut notes = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().ok_or("no stderr")?, &mut notes)?;
    assert!(notes.contains("mcp serving stdio"), "{notes}");
    Ok(())
}

/// The status code of one raw HTTP/1.1 `POST /mcp` to `addr`, with
/// `bearer` in `Authorization` when given.
#[cfg(feature = "mcp")]
fn post_mcp(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
) -> Result<u16, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.0"}
        }
    })
    .to_string();
    let auth = bearer.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n{auth}Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head)?;
    let status = std::str::from_utf8(&head)?
        .split(' ')
        .nth(1)
        .ok_or("no status code")?
        .parse()?;
    Ok(status)
}

/// `--transport http` never runs as root (STAGE3 H12): exit 3, nothing
/// bound. Unprivileged it refuses a non-loopback `--bind` (STAGE3 M11), and
/// a served endpoint answers 401 to a missing or wrong bearer before MCP
/// runs, admits the startup token, and stops cleanly on `SIGTERM`.
#[cfg(feature = "mcp")]
#[test]
fn mcp_http_refuses_root_and_gates_every_request_on_the_bearer() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("state-root");
    let state = root.to_string_lossy().to_string();
    let token = mint_token(&state, false)?;

    if rustix::process::geteuid().is_root() {
        let output = run_mcp(&state, Some(&token), &["mcp", "--transport", "http"])?;
        assert_eq!(code(&output), Some(3));
        assert!(output.stdout.is_empty());
        let notes = String::from_utf8(output.stderr)?;
        assert!(
            notes.contains("mcp http transport cannot run as root"),
            "{notes}"
        );
        assert!(!root.join("monitor.lock").exists());
        return Ok(());
    }

    let output = run_mcp(
        &state,
        Some(&token),
        &["mcp", "--transport", "http", "--bind", "0.0.0.0:3334"],
    )?;
    assert_eq!(code(&output), Some(2));
    let notes = String::from_utf8(output.stderr)?;
    assert!(notes.contains("mcp http bind must be loopback"), "{notes}");

    // A port that was free a moment ago; the server binds it itself.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let child = Command::new(env!("CARGO_BIN_EXE_detent"))
        .args(["--locale", "en-US", "--state-root", &state, "mcp"])
        .args(["--transport", "http", "--bind", &addr.to_string()])
        .env("DETENT_MCP_TOKEN", &token)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let outcome = (|| -> TestResult {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::net::TcpStream::connect(addr).is_err() {
            if std::time::Instant::now() > deadline {
                return Err("mcp http never started listening".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(post_mcp(addr, None)?, 401);
        assert_eq!(post_mcp(addr, Some("not-the-token"))?, 401);
        assert_eq!(post_mcp(addr, Some(&token))?, 200);
        Ok(())
    })();
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::TERM,
    )?;
    let output = child.wait_with_output()?;
    outcome?;
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Runs `detent setup` in a new session whose controlling terminal is a
/// fresh pseudo-terminal (via `setsid --ctty`, since a test process has none
/// of its own), types each of `answers` after the prompt for it appears, and
/// returns the exit code, everything the terminal showed, and stderr.
#[cfg(all(feature = "web", target_os = "linux"))]
fn setup_on_a_terminal(
    state: &std::path::Path,
    config: &std::path::Path,
    answers: &[&str],
) -> Result<(Option<i32>, String, String), Box<dyn std::error::Error>> {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::io::Read as _;
    use std::os::unix::ffi::OsStrExt as _;

    let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    grantpt(&controller)?;
    unlockpt(&controller)?;
    let name = ptsname(&controller, Vec::new())?;
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::ffi::OsStr::from_bytes(name.as_bytes()))?;
    let mut controller = std::fs::File::from(controller);

    let child = Command::new("setsid")
        .arg("--ctty")
        .arg(env!("CARGO_BIN_EXE_detent"))
        .arg("--locale")
        .arg("en-US")
        .arg("--state-root")
        .arg(state)
        .arg("--config")
        .arg(config)
        .arg("setup")
        .stdin(terminal)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Each answer is typed only once its prompt is on screen: typed any
    // earlier, the terminal would still be echoing.
    let mut shown = Vec::new();
    let mut chunk = [0_u8; 256];
    for (index, answer) in answers.iter().enumerate() {
        while String::from_utf8_lossy(&shown).matches("password:").count() <= index {
            let read = controller.read(&mut chunk)?;
            shown.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        writeln!(controller, "{answer}")?;
    }
    let output = child.wait_with_output()?;
    // The rest of what the terminal showed; the child has exited, so the pty
    // is hung up and a read ends in EIO once the buffer is drained.
    while let Ok(read) = controller.read(&mut chunk) {
        if read == 0 {
            break;
        }
        shown.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
    Ok((
        code(&output),
        String::from_utf8(shown)?,
        String::from_utf8(output.stderr)?,
    ))
}

/// With a controlling terminal, `setup` prompts for the password twice on
/// that terminal with echo off — the typed password never appears on it —
/// and refuses (exit 2) when the two entries differ, creating nothing. A
/// matching pair creates the account.
#[cfg(all(feature = "web", target_os = "linux"))]
#[test]
fn setup_prompts_twice_on_the_terminal_without_echo() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root");
    let config = tmp.path().join("detent.toml");
    std::fs::write(&config, "[auth.argon2]\nm_kib = 19456\nt = 1\np = 1\n")?;

    // As root `setup` prompts for nothing: it is refused (exit 3) before the
    // state root is touched, since it must run as the service account.
    if rustix::process::geteuid().is_root() {
        let state_arg = state.to_string_lossy();
        let config_arg = config.to_string_lossy();
        let output = run(
            &[
                "--locale",
                "en-US",
                "--state-root",
                &state_arg,
                "--config",
                &config_arg,
                "setup",
            ],
            "",
        )?;
        assert_eq!(code(&output), Some(3));
        let notes = String::from_utf8(output.stderr)?;
        assert!(notes.contains("sudo -u detent detent setup"), "{notes}");
        assert!(!state.exists());
        return Ok(());
    }

    let (exit, shown, notes) =
        setup_on_a_terminal(&state, &config, &["first-pass", "second-pass"])?;
    assert_eq!(exit, Some(2), "{notes}");
    assert!(notes.contains("the passwords did not match."), "{notes}");
    assert!(shown.contains("password:"), "{shown:?}");
    assert!(shown.contains("confirm password:"), "{shown:?}");
    assert!(!shown.contains("first-pass"), "echoed: {shown:?}");
    assert!(!state.join("state").join("users.json").exists());

    let (exit, shown, notes) =
        setup_on_a_terminal(&state, &config, &["correct-horse", "correct-horse"])?;
    assert_eq!(exit, Some(0), "{notes}");
    assert!(!shown.contains("correct-horse"), "echoed: {shown:?}");
    assert!(state.join("state").join("users.json").exists());
    Ok(())
}

/// A stdio client that hangs up before `initialize` never gets a session:
/// the server reports a failed run (exit 1) instead of serving nothing and
/// claiming success.
#[cfg(feature = "mcp")]
#[test]
fn mcp_stdio_fails_when_the_client_hangs_up_before_initialize() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state-root").to_string_lossy().to_string();
    let token = mint_token(&state, false)?;
    let output = run_mcp(&state, Some(&token), &["mcp"])?;
    assert_eq!(
        code(&output),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    Ok(())
}
