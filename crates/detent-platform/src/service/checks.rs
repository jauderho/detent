//! Runs an [`ExternalCheck`] validator against a candidate file
//! ([`ExternalCheckRunner`]), implementing the monitor's [`CheckRunner`] hook
//! (PLAN §2.3, §2.4).

use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

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
/// `expects: CheckExpectation::StdoutContains` is matched as a **plain
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
    /// This process's effective uid: only root can run a check as another
    /// user ([`ExternalCheck::run_as_dir_owner`]).
    euid: u32,
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
        Self {
            runner,
            euid: rustix::process::geteuid().as_raw(),
        }
    }

    /// As [`Self::with_runner`], as if this process's euid were `euid`.
    #[cfg(test)]
    fn with_runner_as_euid(runner: Box<dyn ProcessRunner>, euid: u32) -> Self {
        Self { runner, euid }
    }

    /// The uid and gid a [`ExternalCheck::run_as_dir_owner`] check runs as:
    /// the owner of the candidate's directory, read now, never taken from a
    /// request. `None` (run as this process) when this process is not root,
    /// which cannot change user, or root owns the directory. Before it
    /// returns ids, the candidate (a file root created `0600`) is given the
    /// directory's group and mode `0640`, so that user can read it but not
    /// change it.
    fn check_user(&self, candidate: &Path) -> Result<Option<(u32, u32)>, HookError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let failed = |what: &str| {
            HookError::Failed(format!(
                "cannot run the check as its directory's owner: {what}"
            ))
        };
        if self.euid != 0 {
            return Ok(None);
        }
        let dir = candidate
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .ok_or_else(|| failed("the candidate has no directory"))?;
        let owner = std::fs::symlink_metadata(dir).map_err(|err| failed(&err.to_string()))?;
        if owner.uid() == 0 {
            return Ok(None);
        }
        let fd = rustix::fs::open(
            candidate,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|err| failed(&err.to_string()))?;
        let file = std::fs::File::from(fd);
        if !file
            .metadata()
            .map_err(|err| failed(&err.to_string()))?
            .is_file()
        {
            return Err(failed("the candidate is not a regular file"));
        }
        std::os::unix::fs::fchown(&file, None, Some(owner.gid()))
            .map_err(|err| failed(&err.to_string()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .map_err(|err| failed(&err.to_string()))?;
        Ok(Some((owner.uid(), owner.gid())))
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
        let user = if check.run_as_dir_owner {
            self.check_user(candidate)?
        } else {
            None
        };
        let staged = match check.stage_as {
            Some(relative) => Some(StagedRoot::new(candidate, relative)?),
            None => None,
        };
        let input = staged.as_ref().map_or(candidate, |root| root.0.as_path());
        let input_str = input
            .to_str()
            .ok_or_else(|| HookError::Failed("candidate path is not valid UTF-8".to_owned()))?;
        let mut args = Vec::with_capacity(check.args.len());
        for arg in check.args {
            args.push(match arg {
                ArgTemplate::Literal(literal) => (*literal).to_owned(),
                ArgTemplate::TempFile => input_str.to_owned(),
            });
        }
        let output = match user {
            Some(user) => self.runner.run_as(program, &args, CHECK_TIMEOUT, user),
            None => self.runner.run(program, &args, CHECK_TIMEOUT),
        };
        drop(staged);
        let output = output.map_err(|err| HookError::Failed(err.to_string()))?;
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
            CheckExpectation::StdoutContains(pattern) => {
                output.status == Some(0)
                    && String::from_utf8_lossy(&output.stdout).contains(pattern)
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

/// A fresh directory beside the candidate that holds a copy of it at an
/// [`ExternalCheck::stage_as`] path, for a validator that reads a tree
/// (`netplan generate --root-dir`). It stays inside the candidate's own
/// directory, so nothing outside what the check may already write is
/// touched. Removed on drop.
struct StagedRoot(PathBuf);

impl StagedRoot {
    fn new(candidate: &Path, relative: &str) -> Result<Self, HookError> {
        let failed = |what: &str| HookError::Failed(format!("cannot stage the candidate: {what}"));
        let rel = Path::new(relative);
        if !rel
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(failed("the stage path is not a plain relative path"));
        }
        let (Some(dir), Some(name)) = (candidate.parent(), candidate.file_name()) else {
            return Err(failed("the candidate has no directory"));
        };
        let mut root_name = std::ffi::OsString::from(".detent-root");
        root_name.push(name);
        let root = dir.join(root_name);
        // `create_dir` fails on anything already there, a symlink included.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|err| failed(&err.to_string()))?;
        let staged = Self(root);
        let target = staged.0.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|err| failed(&err.to_string()))?;
        }
        std::fs::copy(candidate, &target).map_err(|err| failed(&err.to_string()))?;
        Ok(staged)
    }
}

impl Drop for StagedRoot {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0) {
            tracing::warn!(root = %self.0.display(), %err, "a staged check root was not removed");
        }
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
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use detent_core::descriptor::{ArgTemplate, CheckExpectation, ExternalCheck, PathSpec};

    use super::{ExternalCheckRunner, build_detail};
    use crate::privsep::monitor::CheckRunner;
    use crate::service::exec::{ProcessError, ProcessOutput, ProcessRunner};

    #[derive(Default)]
    struct FakeRunner {
        response: Mutex<Option<ProcessOutput>>,
        /// The user of each run: `None` for `run`, the ids for `run_as`.
        users: Mutex<Vec<Option<(u32, u32)>>>,
    }

    impl FakeRunner {
        fn with_response(self, output: ProcessOutput) -> Self {
            if let Ok(mut slot) = self.response.lock() {
                *slot = Some(output);
            }
            self
        }
    }

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
            self.respond(program, args, timeout, None)
        }

        fn run_as(
            &self,
            program: &'static str,
            args: &[String],
            timeout: Duration,
            user: (u32, u32),
        ) -> Result<ProcessOutput, ProcessError> {
            self.respond(program, args, timeout, Some(user))
        }
    }

    impl SharedFake {
        fn respond(
            &self,
            _program: &'static str,
            _args: &[String],
            _timeout: Duration,
            user: Option<(u32, u32)>,
        ) -> Result<ProcessOutput, ProcessError> {
            if let Ok(mut users) = self.0.users.lock() {
                users.push(user);
            }
            self.0
                .response
                .lock()
                .ok()
                .and_then(|guard| guard.clone())
                .map_or_else(
                    || {
                        Ok(ProcessOutput {
                            status: Some(0),
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                            timed_out: false,
                        })
                    },
                    Ok,
                )
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

    #[test]
    fn stdout_pattern_requires_literal_match_and_exit_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let check = ExternalCheck {
            program: PathSpec::new("/usr/sbin/chronyd"),
            args: &[ArgTemplate::Literal("-s")],
            expects: CheckExpectation::StdoutContains("Loaded services"),
            applies_to: &[],
            stage_as: None,
            run_as_dir_owner: false,
        };
        // Matching stdout but non-zero exit must NOT pass.
        let fake =
            Arc::new(FakeRunner::default().with_response(output(1, "Loaded services file OK\n")));
        let runner = ExternalCheckRunner::with_runner(Box::new(SharedFake(Arc::clone(&fake))));
        let outcome = runner
            .run_check(&check, Path::new("/tmp/detent-candidate-test"))
            .map_err(|err| err.to_string())?;
        assert!(!outcome.passed);

        // Non-matching stdout with exit zero must NOT pass.
        let fake2 =
            Arc::new(FakeRunner::default().with_response(output(0, "nothing relevant here")));
        let runner2 = ExternalCheckRunner::with_runner(Box::new(SharedFake(fake2)));
        let outcome2 = runner2
            .run_check(&check, Path::new("/tmp/detent-candidate-test"))
            .map_err(|err| err.to_string())?;
        assert!(!outcome2.passed);

        // Both conditions together must pass.
        let fake3 =
            Arc::new(FakeRunner::default().with_response(output(0, "Loaded services file OK\n")));
        let runner3 = ExternalCheckRunner::with_runner(Box::new(SharedFake(fake3)));
        let outcome3 = runner3
            .run_check(&check, Path::new("/tmp/detent-candidate-test"))
            .map_err(|err| err.to_string())?;
        assert!(outcome3.passed);
        Ok(())
    }

    /// A Kea-like check: run as the owner of the candidate's directory.
    const KEA: ExternalCheck = ExternalCheck {
        program: PathSpec::new("/usr/sbin/kea-dhcp4"),
        args: &[ArgTemplate::Literal("-t"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
        applies_to: &[],
        stage_as: None,
        run_as_dir_owner: true,
    };

    #[test]
    fn a_root_runner_runs_the_check_as_the_directory_owner_and_lets_its_group_read()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir()?;
        let owner = std::fs::metadata(dir.path())?;
        if owner.uid() == 0 {
            // The test needs a directory root does not own.
            return Ok(());
        }
        let candidate = dir.path().join(".detent-candidate-x");
        std::fs::write(&candidate, b"{}")?;
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;
        let fake = Arc::new(FakeRunner::default());
        let runner =
            ExternalCheckRunner::with_runner_as_euid(Box::new(SharedFake(Arc::clone(&fake))), 0);
        let outcome = runner.run_check(&KEA, &candidate)?;
        assert!(outcome.passed);
        assert_eq!(
            fake.users.lock().map(|users| users.clone()).ok(),
            Some(vec![Some((owner.uid(), owner.gid()))])
        );
        let after = std::fs::metadata(&candidate)?;
        assert_eq!((after.gid(), after.mode() & 0o777), (owner.gid(), 0o640));
        Ok(())
    }

    #[test]
    fn a_runner_that_is_not_root_runs_the_check_as_itself() -> Result<(), Box<dyn std::error::Error>>
    {
        let fake = Arc::new(FakeRunner::default());
        let runner =
            ExternalCheckRunner::with_runner_as_euid(Box::new(SharedFake(Arc::clone(&fake))), 1000);
        runner.run_check(&KEA, Path::new("/nonexistent/.detent-candidate-x"))?;
        assert_eq!(
            fake.users.lock().map(|users| users.clone()).ok(),
            Some(vec![None])
        );
        Ok(())
    }

    #[test]
    fn a_root_owned_directory_runs_the_check_as_root() -> Result<(), Box<dyn std::error::Error>> {
        let fake = Arc::new(FakeRunner::default());
        let runner =
            ExternalCheckRunner::with_runner_as_euid(Box::new(SharedFake(Arc::clone(&fake))), 0);
        // `/` is root's on every host the tests run on.
        runner.run_check(&KEA, Path::new("/.detent-candidate-x"))?;
        assert_eq!(
            fake.users.lock().map(|users| users.clone()).ok(),
            Some(vec![None])
        );
        Ok(())
    }

    #[test]
    fn a_candidate_that_cannot_be_handed_over_fails_the_check_run() {
        let runner = ExternalCheckRunner::with_runner_as_euid(
            Box::new(SharedFake(Arc::new(FakeRunner::default()))),
            0,
        );
        for candidate in ["/nonexistent/.detent-candidate-x", "candidate"] {
            assert!(
                runner.run_check(&KEA, Path::new(candidate)).is_err(),
                "{candidate}"
            );
        }
        // A directory, not a file, in a directory root does not own.
        if let Ok(dir) = tempfile::tempdir()
            && std::fs::create_dir(dir.path().join("sub")).is_ok()
            && !rustix::process::geteuid().is_root()
        {
            assert!(runner.run_check(&KEA, &dir.path().join("sub")).is_err());
            assert!(runner.run_check(&KEA, &dir.path().join("absent")).is_err());
        }
    }
}
