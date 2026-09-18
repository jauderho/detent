//! The atomic binary swap (PLAN §2.9 step 5): put a verified candidate in
//! place of the running binary, keeping the one it replaces.
//!
//! Every write happens in the *target's own* directory, so the one step that
//! changes what the target path names is a same-filesystem `rename(2)` —
//! atomic on POSIX, and atomic over an existing path. A reader of the target
//! therefore never sees it missing or half-written: it sees the old binary or
//! the new one. Any failure before that rename leaves the original binary in
//! place and removes what this module staged.
//!
//! The previous binary is kept at `<target>.prev` so [`Installed::rollback`]
//! can put it back after a failed restart or health check (the later halves
//! of step 5, not implemented here).

use std::path::{Path, PathBuf};

use crate::update::UpdateError;

/// The suffix the replaced binary is kept under, next to the target.
const PREVIOUS_SUFFIX: &str = ".prev";

/// A completed swap that can still be undone: the target now holds the
/// candidate, and the binary it replaced is at [`Installed::previous`].
#[derive(Debug)]
pub struct Installed {
    /// The binary path that was replaced.
    target: PathBuf,
    /// Where the replaced binary was kept (`<target>.prev`).
    previous: PathBuf,
}

impl Installed {
    /// The path the previous binary was kept at.
    #[must_use]
    pub fn previous(&self) -> &Path {
        &self.previous
    }

    /// Puts the previous binary back, by the same atomic rename.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Install`] when the rename fails; the target then still
    /// holds the new binary and the previous one is still at
    /// [`Installed::previous`].
    pub fn rollback(self) -> Result<(), UpdateError> {
        std::fs::rename(&self.previous, &self.target).map_err(|err| failed("rollback", &err))
    }
}

/// Atomically replaces `target` with the bytes of `candidate`, keeping the
/// old binary at `<target>.prev`.
///
/// `target` must already be a regular file: `detent update` replaces a
/// binary, it never creates one, and a missing or non-file target is a
/// misconfiguration. The installed binary keeps the *target's* mode, not the
/// staged candidate's.
///
/// # Errors
///
/// [`UpdateError::BadTarget`] when `target` is missing or is not a regular
/// file, [`UpdateError::Install`] when a step of the swap fails. On every
/// error the target still holds the original binary.
pub fn swap(candidate: &Path, target: &Path) -> Result<Installed, UpdateError> {
    // `symlink_metadata`, not `metadata`: a symlink is refused rather than
    // silently replaced by a regular file. `current_exe` already resolves
    // symlinks, so the real install target is a regular file.
    let meta = std::fs::symlink_metadata(target).map_err(|_| bad_target(target))?;
    if !meta.is_file() {
        return Err(bad_target(target));
    }
    let previous = previous_path(target)?;
    let staged = stage(candidate, directory_of(target), meta.permissions())?;

    match keep_previous(target, &previous).and_then(|()| persist(staged, target)) {
        Ok(()) => Ok(Installed {
            target: target.to_path_buf(),
            previous,
        }),
        Err(err) => {
            // Neither step changed the target, so take back the copy that
            // may have been kept: a failed swap leaves nothing behind.
            remove_best_effort(&previous);
            Err(err)
        }
    }
}

/// Copies `candidate` to a fresh temporary name in `dir` — the target's own
/// directory, so the later rename stays on one filesystem — gives it the
/// target's `mode`, and flushes it to disk.
///
/// The temporary file is removed when the returned handle is dropped, so
/// every failure after this point leaves no litter.
fn stage(
    candidate: &Path,
    dir: &Path,
    mode: std::fs::Permissions,
) -> Result<tempfile::NamedTempFile, UpdateError> {
    let mut staged = tempfile::NamedTempFile::new_in(dir).map_err(|err| failed("stage", &err))?;
    let mut source = std::fs::File::open(candidate).map_err(|err| failed("read", &err))?;
    std::io::copy(&mut source, staged.as_file_mut()).map_err(|err| failed("copy", &err))?;
    // Mode before the rename, never after: the target must be executable the
    // instant the rename makes it visible.
    staged
        .as_file()
        .set_permissions(mode)
        .map_err(|err| failed("mode", &err))?;
    staged
        .as_file()
        .sync_all()
        .map_err(|err| failed("sync", &err))?;
    Ok(staged)
}

/// Keeps the current target at `previous`.
///
/// A hard link is preferred: it is O(1), copies none of the binary's bytes,
/// and it survives the rename below because the old inode stays referenced
/// by this second name. Filesystems without hard links — and a `previous`
/// that could not be replaced — fall back to a byte copy, which carries the
/// mode bits with it so the kept binary stays runnable.
fn keep_previous(target: &Path, previous: &Path) -> Result<(), UpdateError> {
    remove_best_effort(previous);
    if std::fs::hard_link(target, previous).is_ok() {
        return Ok(());
    }
    std::fs::copy(target, previous)
        .map(|_| ())
        .map_err(|err| failed("keep", &err))
}

/// Renames the staged file over the target: the atomic step.
fn persist(staged: tempfile::NamedTempFile, target: &Path) -> Result<(), UpdateError> {
    // On failure the staged file travels inside the error and is removed
    // when it is dropped.
    staged
        .persist(target)
        .map(|_| ())
        .map_err(|err| failed("install", &err.error))
}

/// `<target>.prev`, next to the target.
fn previous_path(target: &Path) -> Result<PathBuf, UpdateError> {
    let mut name = target
        .file_name()
        .ok_or_else(|| bad_target(target))?
        .to_os_string();
    name.push(PREVIOUS_SUFFIX);
    Ok(target.with_file_name(name))
}

/// The directory holding `target`; the working directory for a bare name.
fn directory_of(target: &Path) -> &Path {
    match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Removes `path` when it is there. Best effort by design: the callers are
/// already reporting the failure that matters, or replacing the file anyway.
fn remove_best_effort(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// One swap step's failure, carrying the OS reason but no file contents.
fn failed(step: &'static str, err: &std::io::Error) -> UpdateError {
    UpdateError::Install {
        step,
        reason: err.to_string(),
    }
}

/// The refusal for a target that is not a regular file.
fn bad_target(target: &Path) -> UpdateError {
    UpdateError::BadTarget {
        path: target.display().to_string(),
    }
}

// The swap is POSIX semantics end to end — mode bits, hard links, rename over
// an existing path — and detent ships on Linux and macOS, so the tests are
// written against those rather than abstracted over a platform the product
// does not target.
#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const OLD: &[u8] = b"#!/bin/sh\necho old\n";
    const NEW: &[u8] = b"#!/bin/sh\necho new and rather longer\n";

    /// A target file with the mode a deployed binary has.
    fn target_in(dir: &Path, bytes: &[u8]) -> PathBuf {
        let path = dir.join("detent");
        std::fs::write(&path, bytes).expect("write target");
        set_mode(&path, 0o755);
        path
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// The candidate as `prepare` leaves it: staged elsewhere, mode 0o600.
    fn candidate_in(dir: &Path, bytes: &[u8]) -> PathBuf {
        let path = dir.join("candidate");
        std::fs::write(&path, bytes).expect("write candidate");
        set_mode(&path, 0o600);
        path
    }

    fn read(path: &Path) -> Vec<u8> {
        std::fs::read(path).expect("read back")
    }

    /// Whether this process can still create a file in a directory it has
    /// just made read-only — true only for root, which ignores DAC.
    fn writes_anyway(dir: &Path) -> bool {
        let probe = dir.join("dac-probe");
        if std::fs::write(&probe, b"").is_ok() {
            std::fs::remove_file(&probe).expect("remove probe");
            return true;
        }
        false
    }

    /// Every entry in `dir`, sorted, for the no-litter assertions.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn swap_installs_the_candidate_and_keeps_the_previous_binary() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);

        let installed = swap(&candidate, &target).expect("swap");

        assert_eq!(read(&target), NEW, "the target must hold the candidate");
        assert_eq!(
            read(installed.previous()),
            OLD,
            "the previous binary must be kept byte for byte"
        );
        assert_eq!(
            installed.previous().file_name().and_then(|n| n.to_str()),
            Some("detent.prev"),
        );
        assert_eq!(
            entries(home.path()),
            vec!["detent".to_owned(), "detent.prev".to_owned()],
            "no temporary file may be left behind"
        );
    }

    #[test]
    fn the_installed_binary_keeps_the_targets_mode() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);
        assert_eq!(mode_of(&candidate), 0o600, "the candidate is not 0o755");

        let installed = swap(&candidate, &target).expect("swap");

        assert_eq!(
            mode_of(&target),
            0o755,
            "the target's own mode must survive the swap"
        );
        assert_eq!(
            mode_of(installed.previous()),
            0o755,
            "the kept binary must stay runnable"
        );
    }

    #[test]
    fn rollback_restores_the_previous_binary_byte_for_byte() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);

        let installed = swap(&candidate, &target).expect("swap");
        let kept = installed.previous().to_path_buf();
        installed.rollback().expect("rollback");

        assert_eq!(read(&target), OLD, "the original bytes must be back");
        assert!(!kept.exists(), "the rename consumes the kept binary");
        assert_eq!(entries(home.path()), vec!["detent".to_owned()]);
    }

    #[test]
    fn rollback_reports_a_missing_previous_binary() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);

        let installed = swap(&candidate, &target).expect("swap");
        std::fs::remove_file(installed.previous()).expect("drop the kept binary");

        assert!(
            matches!(
                installed.rollback(),
                Err(UpdateError::Install {
                    step: "rollback",
                    ..
                })
            ),
            "a rollback with nothing to restore must refuse"
        );
        assert_eq!(read(&target), NEW, "the new binary stays in place");
    }

    #[test]
    fn a_missing_or_non_file_target_is_refused_not_created() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let candidate = candidate_in(staging.path(), NEW);

        let missing = home.path().join("detent");
        assert!(
            matches!(
                swap(&candidate, &missing),
                Err(UpdateError::BadTarget { .. })
            ),
            "a missing target is a misconfiguration"
        );
        assert!(!missing.exists(), "the swap must not create the target");

        let directory = home.path().join("dir");
        std::fs::create_dir(&directory).expect("create dir");
        assert!(
            matches!(
                swap(&candidate, &directory),
                Err(UpdateError::BadTarget { .. })
            ),
            "a directory is not an install target"
        );
        assert!(directory.is_dir(), "the directory must be untouched");
        assert_eq!(entries(home.path()), vec!["dir".to_owned()]);
    }

    #[test]
    fn a_symlinked_target_is_refused() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let real = target_in(home.path(), OLD);
        let link = home.path().join("detent-link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let candidate = candidate_in(staging.path(), NEW);

        assert!(
            matches!(swap(&candidate, &link), Err(UpdateError::BadTarget { .. })),
            "a symlink must be refused, never replaced by a regular file"
        );
        assert_eq!(read(&real), OLD, "the real binary is untouched");
    }

    #[test]
    fn a_missing_candidate_leaves_the_target_intact() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);

        let err = swap(&staging.path().join("absent"), &target).expect_err("no candidate");

        assert!(
            matches!(err, UpdateError::Install { step: "read", .. }),
            "unexpected error: {err}"
        );
        assert_eq!(read(&target), OLD, "the original binary must remain");
        assert_eq!(
            entries(home.path()),
            vec!["detent".to_owned()],
            "a failed swap leaves neither a temporary file nor a .prev"
        );
    }

    #[test]
    fn a_read_only_directory_fails_before_anything_is_touched() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);
        set_mode(home.path(), 0o500);
        if writes_anyway(home.path()) {
            // root ignores DAC, so the failure cannot be provoked this way.
            set_mode(home.path(), 0o700);
            return;
        }

        let outcome = swap(&candidate, &target);
        set_mode(home.path(), 0o700);

        let err = outcome.expect_err("a read-only directory cannot be staged into");
        assert!(
            matches!(err, UpdateError::Install { step: "stage", .. }),
            "unexpected error: {err}"
        );
        assert_eq!(read(&target), OLD, "the original binary must remain");
        assert_eq!(entries(home.path()), vec!["detent".to_owned()]);
    }

    #[test]
    fn an_unusable_previous_path_refuses_and_leaves_no_litter() {
        // `<target>.prev` is a non-empty directory: it can be neither removed
        // nor linked over, so the swap must refuse before the rename.
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);
        let candidate = candidate_in(staging.path(), NEW);
        let blocked = home.path().join("detent.prev");
        std::fs::create_dir(&blocked).expect("create blocking dir");
        std::fs::write(blocked.join("occupant"), b"x").expect("occupy");

        let err = swap(&candidate, &target).expect_err("the previous path is unusable");

        assert!(
            matches!(err, UpdateError::Install { step: "keep", .. }),
            "unexpected error: {err}"
        );
        assert_eq!(read(&target), OLD, "the original binary must remain");
        assert_eq!(
            entries(home.path()),
            vec!["detent".to_owned(), "detent.prev".to_owned()],
            "only the pre-existing entries remain"
        );
        assert!(blocked.is_dir());
    }

    #[test]
    fn a_second_swap_replaces_the_previous_binary() {
        let home = tempfile::TempDir::new().expect("home");
        let staging = tempfile::TempDir::new().expect("staging");
        let target = target_in(home.path(), OLD);

        let first = candidate_in(staging.path(), NEW);
        let earlier = swap(&first, &target).expect("first swap");
        assert_eq!(read(earlier.previous()), OLD);
        let third = staging.path().join("third");
        std::fs::write(&third, b"#!/bin/sh\necho third\n").expect("write third");
        let installed = swap(&third, &target).expect("second swap");

        assert_eq!(read(&target), b"#!/bin/sh\necho third\n");
        assert_eq!(
            read(installed.previous()),
            NEW,
            "the .prev must hold the binary the second swap replaced"
        );
        assert_eq!(
            entries(home.path()),
            vec!["detent".to_owned(), "detent.prev".to_owned()]
        );
    }

    #[test]
    fn the_previous_path_is_the_target_plus_a_suffix() {
        assert_eq!(
            previous_path(Path::new("/usr/local/bin/detent")).expect("named"),
            PathBuf::from("/usr/local/bin/detent.prev")
        );
        assert_eq!(
            previous_path(Path::new("detent")).expect("bare name"),
            PathBuf::from("detent.prev")
        );
        assert!(
            matches!(
                previous_path(Path::new("/")),
                Err(UpdateError::BadTarget { .. })
            ),
            "a path with no file name is no install target"
        );
        assert_eq!(directory_of(Path::new("detent")), Path::new("."));
        assert_eq!(
            directory_of(Path::new("/usr/bin/detent")),
            Path::new("/usr/bin")
        );
    }
}
