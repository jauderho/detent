//! Process execution discipline shared by every [`super::ServiceManager`]
//! backend and [`super::checks::ExternalCheckRunner`] (PLAN §2.4).
//!
//! Every external command `detent` runs goes through [`ProcessRunner::run`]:
//! an absolute program path chosen from a compile-time candidate list (never
//! a `PATH` lookup — see `resolve_program` in the parent module), a fixed
//! argv assembled from static literals plus a validated unit name or a
//! monitor-owned temp-file path, an environment cleared except `LC_ALL=C`,
//! stdout/stderr captured up to [`OUTPUT_CAP`] bytes per stream, and a
//! wall-clock timeout after which the child is killed and reaped. There is
//! no shell anywhere in this module.
//!
//! [`RealProcessRunner`] is the production implementation, built on
//! [`std::process::Command`]. Every backend accepts a boxed
//! [`ProcessRunner`] so tests can inject a fake that records the exact argv
//! it was asked to run instead of touching the real system.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on captured stdout/stderr, per stream. The child is never
/// blocked once this is exceeded: excess bytes are read and discarded so a
/// chatty process cannot stall on a full pipe buffer.
pub const OUTPUT_CAP: usize = 64 * 1024;

/// How long a service status query may run before being killed.
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a service action (start/stop/restart/reload) may run before
/// being killed.
pub const ACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an external validator ([`super::checks::ExternalCheckRunner`])
/// may run before being killed. Matches [`ACTION_TIMEOUT`] rather than
/// [`STATUS_TIMEOUT`]: validators do real parsing work (e.g.
/// `named-checkconf`), unlike a quick status query, and PLAN §2.3 gives no
/// separate figure for checks.
pub const CHECK_TIMEOUT: Duration = ACTION_TIMEOUT;

/// How often the timeout loop polls the child for exit.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The result of running one external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// The child's exit code, when it exited normally. `None` if it was
    /// killed (including after a timeout) or its status could not be read.
    pub status: Option<i32>,
    /// Captured stdout, truncated to [`OUTPUT_CAP`] bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr, truncated to [`OUTPUT_CAP`] bytes.
    pub stderr: Vec<u8>,
    /// True when the child was killed because it exceeded its timeout.
    pub timed_out: bool,
}

/// A command could not be run at all: `fork`/`exec` (or the platform
/// equivalent) failed.
///
/// A struct, not an enum: starting the child is the only thing that can fail
/// *before* there is an outcome to report. Everything after it — a non-zero
/// exit, a timeout, output past [`OUTPUT_CAP`] — is a successful run with a
/// bad result, and lives in [`ProcessOutput`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("failed to start {program}: {message}")]
pub struct ProcessError {
    /// The program that could not be started.
    pub program: String,
    /// The underlying OS error message.
    pub message: String,
}

/// Runs one external command under the discipline described in the module
/// docs. Implemented for real by [`RealProcessRunner`]; tests inject a fake
/// that records the call instead.
pub trait ProcessRunner: Send + Sync {
    /// Whether `path` exists and should be considered a usable candidate
    /// program. Never resolves a bare command name through `PATH` — `path`
    /// is always one entry of a compile-time candidate list.
    fn exists(&self, path: &'static str) -> bool;

    /// Runs `program` with `args`, killing and reaping the child if it is
    /// still running after `timeout`.
    ///
    /// # Errors
    ///
    /// [`ProcessError`] when the child could not be started at all.
    fn run(
        &self,
        program: &'static str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError>;
}

/// Picks the first candidate in `candidates` that [`ProcessRunner::exists`]
/// reports present, or `None` if none are. The only place a candidate list
/// is turned into a single program path; every backend's argv assembly
/// happens after this, on the resolved `&'static str`.
#[must_use]
pub(crate) fn resolve_program(
    runner: &dyn ProcessRunner,
    candidates: &'static [&'static str],
) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|candidate| runner.exists(candidate))
}

/// The production [`ProcessRunner`]: real `fork`/`exec` via
/// [`std::process::Command`], no shell involved.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealProcessRunner;

impl ProcessRunner for RealProcessRunner {
    fn exists(&self, path: &'static str) -> bool {
        std::path::Path::new(path).is_file()
    }

    fn run(
        &self,
        program: &'static str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, ProcessError> {
        run_confined(program, args, timeout)
    }
}

fn run_confined(
    program: &'static str,
    args: &[String],
    timeout: Duration,
) -> Result<ProcessOutput, ProcessError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|source| ProcessError {
        program: program.to_owned(),
        message: source.to_string(),
    })?;

    let stdout_reader = child.stdout.take().map(spawn_capped_reader);
    let stderr_reader = child.stderr.take().map(spawn_capped_reader);

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => break None,
        }
    };

    let stdout = stdout_reader.map(join_capped_reader).unwrap_or_default();
    let stderr = stderr_reader.map(join_capped_reader).unwrap_or_default();

    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

/// Reads `pipe` to completion on a dedicated thread, retaining only the
/// first [`OUTPUT_CAP`] bytes but continuing to drain everything after that
/// so a chatty child never blocks on a full pipe buffer while the timeout
/// loop is deciding whether to kill it.
fn spawn_capped_reader<R>(mut pipe: R) -> std::thread::JoinHandle<Vec<u8>>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let take = OUTPUT_CAP.saturating_sub(buf.len()).min(n);
                    if let Some(slice) = chunk.get(..take) {
                        buf.extend_from_slice(slice);
                    }
                }
            }
        }
        buf
    })
}

fn join_capped_reader(handle: std::thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{ACTION_TIMEOUT, CHECK_TIMEOUT, OUTPUT_CAP, ProcessRunner, RealProcessRunner};
    use std::time::Duration;

    #[test]
    fn check_timeout_matches_action_timeout() {
        assert_eq!(CHECK_TIMEOUT, ACTION_TIMEOUT);
    }

    #[test]
    fn real_runner_reports_a_binary_that_certainly_exists() {
        assert!(RealProcessRunner.exists("/bin/sh") || RealProcessRunner.exists("/usr/bin/env"));
    }

    #[test]
    fn real_runner_reports_a_path_that_certainly_does_not_exist() {
        assert!(!RealProcessRunner.exists("/nonexistent/detent-exec-test-binary"));
    }

    #[test]
    fn real_runner_spawn_failure_is_reported_as_an_error() {
        let result = RealProcessRunner.run(
            "/nonexistent/detent-exec-test-binary",
            &[],
            Duration::from_secs(1),
        );
        assert!(result.is_err());
    }

    #[test]
    fn output_cap_is_64_kib() {
        assert_eq!(OUTPUT_CAP, 64 * 1024);
    }
}
