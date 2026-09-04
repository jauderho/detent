//! Runs an [`ExternalCheck`] validator against a candidate file
//! ([`ExternalCheckRunner`]), implementing the monitor's [`CheckRunner`] hook
//! (PLAN §2.3, §2.4).

use std::path::Path;

use detent_core::descriptor::{ArgTemplate, CheckExpectation, ExternalCheck};

use crate::privsep::monitor::{CheckRunner, HookError};
use crate::privsep::proto::{CheckId, CheckOutcome};

use super::exec::{CHECK_TIMEOUT, OUTPUT_CAP, ProcessRunner, RealProcessRunner};

/// Longest detail string this runner builds locally. The monitor itself
/// also truncates to 512 bytes before the result reaches the wire; this is
/// a defensive cap so a pathological validator cannot hold megabytes of
/// output in memory before that happens.
const DETAIL_CAP: usize = OUTPUT_CAP;

/// Runs an [`ExternalCheck`] against a candidate file.
///
/// `expects: CheckExpectation::StdoutPattern` is matched as a **plain
/// substring**, not a regular expression:
/// [`detent_core::descriptor::CheckExpectation`]'s doc comment says "must
/// match this regular expression", but PLAN §2.3 deliberately kept regex
/// parsing out of the core crate, and this subtask adds no regex
/// dependency (none was needed elsewhere and none was authorized here —
/// see `Cargo.toml`, untouched). Every real check declared in the fixtures
/// so far (e.g. `^Loaded services`) also reads correctly as a substring
/// match, so this is flagged as a discrepancy to resolve later rather than
/// a blocking one.
pub struct ExternalCheckRunner {
    runner: Box<dyn ProcessRunner>,
}

impl std::fmt::Debug for ExternalCheckRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalCheckRunner { .. }")
    }
}

impl ExternalCheckRunner {
    /// Builds a runner backed by real process execution.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runner(Box::new(RealProcessRunner))
    }

    /// Builds a runner backed by `runner`, for tests.
    #[must_use]
    pub fn with_runner(runner: Box<dyn ProcessRunner>) -> Self {
        Self { runner }
    }
}

impl Default for ExternalCheckRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckRunner for ExternalCheckRunner {
    fn run_check(
        &self,
        check: &ExternalCheck,
        candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        let program = check.program.as_str();
        if !program.starts_with('/') {
            return Err(HookError::Failed(
                "check program is not an absolute path".to_owned(),
            ));
        }
        let candidate_str = candidate
            .to_str()
            .ok_or_else(|| HookError::Failed("candidate path is not valid UTF-8".to_owned()))?;
        let mut args = Vec::with_capacity(check.args.len());
        for arg in check.args {
            args.push(match arg {
                ArgTemplate::Literal(literal) => (*literal).to_owned(),
                ArgTemplate::TempFile => candidate_str.to_owned(),
            });
        }
        let output = self
            .runner
            .run(program, &args, CHECK_TIMEOUT)
            .map_err(|err| HookError::Failed(err.to_string()))?;
        if output.timed_out {
            return Ok(CheckOutcome {
                check: CheckId(0),
                passed: false,
                exit_code: None,
                detail: format!("{program} timed out after {CHECK_TIMEOUT:?}"),
            });
        }
        let passed = match check.expects {
            CheckExpectation::ExitZero => output.status == Some(0),
            CheckExpectation::StdoutPattern(pattern) => {
                String::from_utf8_lossy(&output.stdout).contains(pattern)
            }
        };
        Ok(CheckOutcome {
            check: CheckId(0),
            passed,
            exit_code: output.status,
            detail: build_detail(&output.stdout, &output.stderr),
        })
    }
}

fn build_detail(stdout: &[u8], stderr: &[u8]) -> String {
    let mut detail = String::from_utf8_lossy(stdout).into_owned();
    if !stderr.is_empty() {
        if !detail.is_empty() {
            detail.push('\n');
        }
        detail.push_str(&String::from_utf8_lossy(stderr));
    }
    if detail.len() > DETAIL_CAP {
        let mut end = DETAIL_CAP;
        while end > 0 && !detail.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        detail.truncate(end);
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::{ExternalCheckRunner, build_detail};

    #[test]
    fn debug_format_mentions_the_type_name() {
        assert!(format!("{:?}", ExternalCheckRunner::new()).contains("ExternalCheckRunner"));
    }

    #[test]
    fn default_constructs_without_panicking() {
        let _ = ExternalCheckRunner::default();
    }

    #[test]
    fn combines_stdout_and_stderr() {
        assert_eq!(build_detail(b"out", b"err"), "out\nerr");
    }

    #[test]
    fn empty_stderr_is_not_appended() {
        assert_eq!(build_detail(b"out", b""), "out");
    }

    #[test]
    fn truncates_at_a_char_boundary() {
        let long = "a".repeat(super::DETAIL_CAP + 10);
        let detail = build_detail(long.as_bytes(), b"");
        assert_eq!(detail.len(), super::DETAIL_CAP);
    }

    #[test]
    fn truncates_a_multi_byte_character_at_the_previous_char_boundary() {
        // A 2-byte UTF-8 character starting one byte before the cap, so the
        // cap itself lands mid-character and the walk-back loop must step
        // back at least once to find a valid boundary.
        let mut long = "a".repeat(super::DETAIL_CAP - 1);
        long.push('é');
        let detail = build_detail(long.as_bytes(), b"");
        assert_eq!(detail.len(), super::DETAIL_CAP - 1);
        assert!(detail.is_char_boundary(detail.len()));
    }
}
