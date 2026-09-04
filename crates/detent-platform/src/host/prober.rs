//! Command execution trait for version probes: a timeout-bounded real
//! implementation (no shell, absolute program paths only) and a fake for
//! tests.

use std::io::Read as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Maximum time a probed process is given before it's killed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Interval between `try_wait` polls while waiting for a probed process.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Why a [`Prober::run`] call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The program could not be spawned (not found, not executable, ...).
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// The program did not exit within the timeout and was killed.
    #[error("probe timed out")]
    Timeout,
    /// The program exited with a non-zero (or signal-terminated) status.
    #[error("exited with status: {0}")]
    NonZero(String),
}

/// Runs external commands to probe installed service versions.
///
/// Implementations must not invoke a shell and must treat `program` as an
/// absolute path, executed as-is.
pub trait Prober {
    /// Run `program` with `args` and return its captured output (stdout
    /// followed by stderr, since version flags commonly write to either).
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError::Spawn`] if `program` couldn't be started,
    /// [`ProbeError::Timeout`] if it didn't exit within the implementation's
    /// timeout, or [`ProbeError::NonZero`] if it exited with a failure
    /// status.
    fn run(&self, program: &str, args: &[&str]) -> Result<String, ProbeError>;
}

/// [`Prober`] backed by `std::process::Command`, bounded by a fixed 2-second
/// timeout.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealProber;

impl Prober for RealProber {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, ProbeError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| ProbeError::Spawn(err.to_string()))?;

        let status = wait_with_timeout(&mut child, PROBE_TIMEOUT)?;

        // Probe output (version strings) is tiny, so reading each pipe to
        // completion after the process has exited is safe: the OS buffers
        // hold the (already-written, already-flushed) bytes.
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            drop(pipe.read_to_string(&mut stdout));
        }
        if let Some(mut pipe) = child.stderr.take() {
            drop(pipe.read_to_string(&mut stderr));
        }

        if !status.success() {
            return Err(ProbeError::NonZero(status.to_string()));
        }
        stdout.push_str(&stderr);
        Ok(stdout)
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus, ProbeError> {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            drop(child.kill());
            drop(child.wait());
            return Err(ProbeError::Timeout);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fakes::FakeProber;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn fake_prober_returns_configured_response() {
        let prober = FakeProber::new().with("/usr/bin/foo", &["-V"], Ok("foo 1.2.3"));
        assert_eq!(
            prober.run("/usr/bin/foo", &["-V"]),
            Ok("foo 1.2.3".to_string())
        );
        assert!(prober.run("/usr/bin/bar", &[]).is_err());
    }

    #[test]
    fn real_prober_captures_stdout() -> TestResult {
        // `/bin/echo` exists on both macOS and Debian/most Linux distros
        // (Debian's merged-`/usr` symlinks `/bin` to `/usr/bin`).
        let out = RealProber.run("/bin/echo", &["hello"])?;
        assert_eq!(out.trim(), "hello");
        Ok(())
    }

    #[test]
    fn real_prober_reports_spawn_failure_for_missing_binary() {
        let result = RealProber.run("/nonexistent/detent-test-binary", &[]);
        assert!(matches!(result, Err(ProbeError::Spawn(_))));
    }

    #[test]
    fn real_prober_reports_non_zero_exit() {
        // macOS ships `false` only at `/usr/bin/false`; Debian/most Linux
        // distros ship (or symlink) it at `/bin/false`.
        let false_bin = if cfg!(target_os = "macos") {
            "/usr/bin/false"
        } else {
            "/bin/false"
        };
        let result = RealProber.run(false_bin, &[]);
        assert!(matches!(result, Err(ProbeError::NonZero(_))));
    }

    #[test]
    fn real_prober_times_out_on_a_hanging_process() {
        // `/bin/sleep` exists on both macOS and Debian/most Linux distros.
        let start = Instant::now();
        let result = RealProber.run("/bin/sleep", &["5"]);
        let elapsed = start.elapsed();
        assert_eq!(result, Err(ProbeError::Timeout));
        assert!(elapsed >= PROBE_TIMEOUT);
        assert!(elapsed < Duration::from_secs(4));
    }
}
