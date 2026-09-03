//! Tests for `detent_platform::fs::atomic`.
//!
//! Run with `cargo test -p detent-platform`. The crash-consistency test
//! re-executes this same binary as a child (the `#[ignore]`d
//! `crash_child_worker`) and kills it with `SIGKILL`.
//!
//! The crate denies `clippy::unwrap_used`/`expect_used`/`panic` in every
//! target, tests included, so each test returns `TestResult` and propagates
//! with `?`.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use detent_platform::fs::atomic::{
    AtomicError, DEFAULT_KEEP_BACKUPS, Sha256Digest, WriteRequest, list_backups, read_with_digest,
    restore_backup, write_atomic,
};
use tempfile::TempDir;

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Env var naming the target file for the crash-consistency child.
const CRASH_TARGET: &str = "DETENT_CRASH_TARGET";
/// Env var naming the backup directory for the crash-consistency child.
const CRASH_BACKUPS: &str = "DETENT_CRASH_BACKUPS";
/// Payload size for the crash-consistency child: big enough that the write and
/// fsync span a window the parent can kill in.
const CRASH_PAYLOAD_LEN: usize = 48 * 1024 * 1024;

/// Permission bits of `path`, without following symlinks.
fn mode_of(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

fn request<'a>(path: &'a Path, contents: &'a [u8], backups: &'a Path) -> WriteRequest<'a> {
    WriteRequest::new(path, contents, backups)
}

/// A temp dir plus the `target` / `backups` paths used by most tests.
struct Fixture {
    _dir: TempDir,
    dir: PathBuf,
    target: PathBuf,
    backups: PathBuf,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    Ok(Fixture {
        _dir: dir,
        target: root.join("conf"),
        backups: root.join("backups"),
        dir: root,
    })
}

/// Count leftover temp files in `dir`.
fn temp_debris(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".detent-tmp-"))
                })
                .count()
        })
        .unwrap_or_default()
}

// --- digest ---------------------------------------------------------------

#[test]
fn digest_hex_round_trip() -> TestResult {
    let digest = Sha256Digest::of(b"hello");
    let text = digest.to_string();
    assert_eq!(
        text,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(digest.short_hex(), "2cf24dba");
    assert_eq!(digest.as_bytes().len(), 32);
    assert_eq!(text.parse::<Sha256Digest>()?, digest);
    assert_eq!(format!("{digest:?}"), format!("Sha256Digest({text})"));
    Ok(())
}

#[test]
fn digest_serde_is_hex() -> TestResult {
    let digest = Sha256Digest::of(b"hello");
    let json = serde_json::to_string(&digest)?;
    assert_eq!(json, format!("\"{digest}\""));
    assert_eq!(serde_json::from_str::<Sha256Digest>(&json)?, digest);
    assert!(serde_json::from_str::<Sha256Digest>("\"nope\"").is_err());
    Ok(())
}

#[test]
fn digest_rejects_bad_hex() {
    let long_g = "g".repeat(64);
    let short_a = "a".repeat(63);
    for bad in ["", "zz", long_g.as_str(), short_a.as_str()] {
        assert!(
            matches!(bad.parse::<Sha256Digest>(), Err(AtomicError::BadDigest)),
            "{bad} was accepted"
        );
    }
    assert_eq!(
        AtomicError::BadDigest.to_string(),
        "not a valid sha-256 hex digest"
    );
}

// --- create / overwrite ---------------------------------------------------

#[test]
fn creates_new_file_with_create_mode() -> TestResult {
    let fx = fixture()?;
    let mut req = request(&fx.target, b"one\n", &fx.backups);
    req.create_mode = 0o600;
    let out = write_atomic(&req)?;

    assert!(out.created);
    assert!(out.prev_digest.is_none());
    assert!(out.backup.is_none());
    assert!(out.owner_preserved);
    assert_eq!(out.new_digest, Sha256Digest::of(b"one\n"));
    assert_eq!(fs::read(&fx.target)?, b"one\n");
    assert_eq!(mode_of(&fx.target)?, 0o600);
    // No backup directory is created when there is nothing to back up.
    assert!(!fx.backups.exists());
    assert_eq!(temp_debris(&fx.dir), 0);
    Ok(())
}

#[test]
fn overwrite_backs_up_and_preserves_mode() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    fs::set_permissions(&fx.target, fs::Permissions::from_mode(0o640))?;

    let mut req = request(&fx.target, b"new\n", &fx.backups);
    // create_mode must be ignored for a file that already exists.
    req.create_mode = 0o600;
    let out = write_atomic(&req)?;

    assert!(!out.created);
    assert_eq!(out.prev_digest, Some(Sha256Digest::of(b"old\n")));
    assert_eq!(out.new_digest, Sha256Digest::of(b"new\n"));
    assert_eq!(fs::read(&fx.target)?, b"new\n");
    assert_eq!(mode_of(&fx.target)?, 0o640);

    let backup = out.backup.ok_or("expected a backup")?;
    assert_eq!(fs::read(&backup)?, b"old\n");
    assert_eq!(mode_of(&backup)?, 0o600);
    assert_eq!(mode_of(&fx.backups)?, 0o700);
    assert_eq!(temp_debris(&fx.dir), 0);
    Ok(())
}

#[test]
fn keep_backups_zero_disables_backups() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    let mut req = request(&fx.target, b"new\n", &fx.backups);
    req.keep_backups = 0;
    let out = write_atomic(&req)?;
    assert!(out.backup.is_none());
    assert!(!fx.backups.exists());
    assert!(list_backups(&fx.backups)?.is_empty());
    Ok(())
}

// --- optimistic concurrency ----------------------------------------------

#[test]
fn conflict_leaves_file_and_backups_untouched() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;

    let mut req = request(&fx.target, b"new\n", &fx.backups);
    req.expected_prev = Some(Sha256Digest::of(b"something else"));
    let err = write_atomic(&req).err().ok_or("expected a conflict")?;

    let AtomicError::Conflict { expected, actual } = &err else {
        return Err(format!("expected Conflict, got {err:?}").into());
    };
    assert_eq!(*expected, Sha256Digest::of(b"something else"));
    assert_eq!(*actual, Some(Sha256Digest::of(b"old\n")));
    assert!(err.to_string().contains("contents changed on disk"));

    assert_eq!(fs::read(&fx.target)?, b"old\n");
    assert!(!fx.backups.exists());
    assert_eq!(temp_debris(&fx.dir), 0);
    Ok(())
}

#[test]
fn conflict_when_file_is_missing() -> TestResult {
    let fx = fixture()?;
    let mut req = request(&fx.target, b"new\n", &fx.backups);
    req.expected_prev = Some(Sha256Digest::of(b"old\n"));
    let err = write_atomic(&req).err().ok_or("expected a conflict")?;
    assert!(matches!(err, AtomicError::Conflict { actual: None, .. }));
    assert!(err.to_string().contains("no file"));
    assert!(!fx.target.exists());
    Ok(())
}

#[test]
fn matching_expected_prev_is_accepted() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    let mut req = request(&fx.target, b"new\n", &fx.backups);
    req.expected_prev = Some(Sha256Digest::of(b"old\n"));
    write_atomic(&req)?;
    assert_eq!(fs::read(&fx.target)?, b"new\n");
    Ok(())
}

// --- path safety ----------------------------------------------------------

#[test]
fn symlink_target_is_refused() -> TestResult {
    let fx = fixture()?;
    let real = fx.dir.join("real");
    fs::write(&real, b"real\n")?;
    std::os::unix::fs::symlink(&real, &fx.target)?;

    let err = write_atomic(&request(&fx.target, b"new\n", &fx.backups))
        .err()
        .ok_or("expected a symlink refusal")?;
    assert!(matches!(err, AtomicError::Symlink { .. }));
    assert!(matches!(
        read_with_digest(&fx.target),
        Err(AtomicError::Symlink { .. })
    ));
    assert!(err.to_string().contains("refusing to follow symlink"));
    assert_eq!(fs::read(&real)?, b"real\n");
    Ok(())
}

#[test]
fn dangling_symlink_is_refused() -> TestResult {
    let fx = fixture()?;
    std::os::unix::fs::symlink(fx.dir.join("nowhere"), &fx.target)?;
    assert!(matches!(
        write_atomic(&request(&fx.target, b"new\n", &fx.backups)),
        Err(AtomicError::Symlink { .. })
    ));
    Ok(())
}

#[test]
fn non_regular_targets_are_refused() -> TestResult {
    let fx = fixture()?;
    fs::create_dir(&fx.target)?;
    assert!(matches!(
        write_atomic(&request(&fx.target, b"new\n", &fx.backups)),
        Err(AtomicError::NotRegularFile { .. })
    ));
    assert!(matches!(
        read_with_digest(&fx.target),
        Err(AtomicError::NotRegularFile { .. })
    ));

    // A FIFO is the dangerous case: opening one would block a privileged
    // writer indefinitely, so it must be rejected before the open. `rustix`
    // does not expose `mkfifoat` on Apple platforms, so shell out instead.
    let fifo = fx.dir.join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(made.success(), "mkfifo failed: {made}");
    let err = write_atomic(&request(&fifo, b"new\n", &fx.backups))
        .err()
        .ok_or("expected a refusal")?;
    assert!(matches!(err, AtomicError::NotRegularFile { .. }));
    assert!(err.to_string().contains("not a regular file"));
    Ok(())
}

#[test]
fn relative_paths_are_refused() -> TestResult {
    let fx = fixture()?;
    for bad in [Path::new("conf"), Path::new("a/b"), Path::new("/")] {
        assert!(
            matches!(
                write_atomic(&request(bad, b"x", &fx.backups)),
                Err(AtomicError::RelativePath { .. })
            ),
            "{bad:?} was accepted"
        );
        assert!(matches!(
            read_with_digest(bad),
            Err(AtomicError::RelativePath { .. })
        ));
    }
    assert!(matches!(
        restore_backup(Path::new("rel"), &fx.target),
        Err(AtomicError::RelativePath { .. })
    ));
    Ok(())
}

#[test]
fn missing_file_reads_as_io_error() -> TestResult {
    let fx = fixture()?;
    let err = read_with_digest(&fx.target)
        .err()
        .ok_or("expected a not-found error")?;
    let AtomicError::Io { source, path, .. } = &err else {
        return Err(format!("expected Io, got {err:?}").into());
    };
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(*path, fx.target);
    Ok(())
}

#[test]
fn missing_parent_directory_is_an_io_error() -> TestResult {
    let fx = fixture()?;
    let path = fx.dir.join("deeper").join("conf");
    assert!(matches!(
        write_atomic(&request(&path, b"x", &fx.backups)),
        Err(AtomicError::Io { .. })
    ));
    Ok(())
}

#[test]
fn read_only_directory_leaves_no_debris() -> TestResult {
    if rustix::process::geteuid().is_root() {
        // root ignores DAC, so the failure cannot be provoked this way.
        return Ok(());
    }
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    fs::set_permissions(&fx.dir, fs::Permissions::from_mode(0o500))?;

    let mut req = request(&fx.target, b"new\n", &fx.backups);
    req.keep_backups = 0;
    let result = write_atomic(&req);

    fs::set_permissions(&fx.dir, fs::Permissions::from_mode(0o700))?;
    assert!(matches!(result, Err(AtomicError::Io { .. })));
    assert_eq!(fs::read(&fx.target)?, b"old\n");
    assert_eq!(temp_debris(&fx.dir), 0);
    Ok(())
}

// --- xattrs ---------------------------------------------------------------

#[cfg(target_os = "macos")]
const TEST_XATTR: &str = "com.apple.test";
#[cfg(not(target_os = "macos"))]
const TEST_XATTR: &str = "user.test";

#[test]
fn xattrs_are_preserved() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    // Detect xattr support rather than assuming it: tmpfs and some CI
    // filesystems do not have it.
    if xattr::set(&fx.target, TEST_XATTR, b"value").is_err() {
        eprintln!("skipping: no usable extended attributes on this filesystem");
        return Ok(());
    }
    write_atomic(&request(&fx.target, b"new\n", &fx.backups))?;
    assert_eq!(
        xattr::get(&fx.target, TEST_XATTR)?.as_deref(),
        Some(&b"value"[..])
    );
    Ok(())
}

// --- backups --------------------------------------------------------------

#[test]
fn backups_rotate_to_keep_count() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"gen0\n")?;
    for generation in 1..=5_u32 {
        let contents = format!("gen{generation}\n");
        let mut req = request(&fx.target, contents.as_bytes(), &fx.backups);
        req.keep_backups = 3;
        write_atomic(&req)?;
    }

    let entries = list_backups(&fx.backups)?;
    assert_eq!(entries.len(), 3);
    // Newest first: the newest backup holds gen4, the contents replaced by the
    // final gen5 write.
    let mut contents = Vec::new();
    for entry in &entries {
        let bytes = fs::read(&entry.path)?;
        assert_eq!(entry.original_len, 5);
        assert_eq!(entry.digest, Sha256Digest::of(&bytes));
        assert!(entry.created_utc <= std::time::SystemTime::now());
        contents.push(bytes);
    }
    assert_eq!(
        contents,
        vec![b"gen4\n".to_vec(), b"gen3\n".to_vec(), b"gen2\n".to_vec()]
    );
    Ok(())
}

#[test]
fn backup_names_are_sortable_timestamps() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    let out = write_atomic(&request(&fx.target, b"new\n", &fx.backups))?;
    let backup = out.backup.ok_or("expected a backup")?;
    let name = backup
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("backup has no name")?;

    let (stamp, short) = name.rsplit_once('-').ok_or("malformed backup name")?;
    assert_eq!(short, Sha256Digest::of(b"old\n").short_hex());
    // YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ, fixed width so that lexicographic order
    // is chronological order.
    assert_eq!(stamp.len(), 30, "{stamp}");
    assert!(stamp.ends_with('Z'));
    assert_eq!(stamp.matches(':').count(), 2);
    assert_eq!(stamp.get(4..5), Some("-"));
    assert_eq!(stamp.get(10..11), Some("T"));
    Ok(())
}

#[test]
fn list_backups_ignores_foreign_entries() -> TestResult {
    let fx = fixture()?;
    fs::create_dir_all(&fx.backups)?;
    fs::write(fx.backups.join("README"), b"not a backup")?;
    fs::write(
        fx.backups.join("2026-01-01T00:00:00.000000000Z-nothex!"),
        b"x",
    )?;
    fs::write(fx.backups.join("plain-aabbccdd"), b"x")?;
    fs::create_dir(fx.backups.join("2026-01-01T00:00:00.000000000Z-aabbccdd"))?;
    std::os::unix::fs::symlink(
        fx.backups.join("README"),
        fx.backups.join("2026-01-02T00:00:00.000000000Z-aabbccdd"),
    )?;
    assert!(list_backups(&fx.backups)?.is_empty());

    fs::write(&fx.target, b"old\n")?;
    write_atomic(&request(&fx.target, b"new\n", &fx.backups))?;
    assert_eq!(list_backups(&fx.backups)?.len(), 1);
    Ok(())
}

#[test]
fn backup_failure_aborts_the_write() -> TestResult {
    if rustix::process::geteuid().is_root() {
        // root ignores DAC, so the failure cannot be provoked this way.
        return Ok(());
    }
    let fx = fixture()?;
    fs::write(&fx.target, b"old\n")?;
    let vault = fx.dir.join("vault");
    fs::create_dir(&vault)?;
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o500))?;

    let result = write_atomic(&request(&fx.target, b"new\n", &vault.join("backups")));

    fs::set_permissions(&vault, fs::Permissions::from_mode(0o700))?;
    assert!(matches!(result, Err(AtomicError::Io { .. })));
    // The target is untouched: no backup means no write.
    assert_eq!(fs::read(&fx.target)?, b"old\n");
    assert_eq!(temp_debris(&fx.dir), 0);
    Ok(())
}

#[test]
fn list_backups_on_missing_directory_is_empty() -> TestResult {
    let fx = fixture()?;
    assert!(list_backups(&fx.backups)?.is_empty());
    Ok(())
}

#[test]
fn restore_round_trip() -> TestResult {
    let fx = fixture()?;
    fs::write(&fx.target, b"good\n")?;
    fs::set_permissions(&fx.target, fs::Permissions::from_mode(0o640))?;
    write_atomic(&request(&fx.target, b"bad\n", &fx.backups))?;
    assert_eq!(fs::read(&fx.target)?, b"bad\n");

    let backups = list_backups(&fx.backups)?;
    let newest = backups.first().ok_or("expected a backup")?;
    let out = restore_backup(&newest.path, &fx.target)?;

    assert_eq!(fs::read(&fx.target)?, b"good\n");
    assert_eq!(out.prev_digest, Some(Sha256Digest::of(b"bad\n")));
    assert_eq!(out.new_digest, Sha256Digest::of(b"good\n"));
    assert!(!out.created);
    assert_eq!(mode_of(&fx.target)?, 0o640);
    // The restore is itself backed up, so the replaced contents stay reachable.
    assert_eq!(list_backups(&fx.backups)?.len(), 2);
    Ok(())
}

#[test]
fn default_request_uses_documented_defaults() -> TestResult {
    assert_eq!(DEFAULT_KEEP_BACKUPS, 20);
    let fx = fixture()?;
    let req = request(&fx.target, b"x", &fx.backups);
    assert_eq!(req.keep_backups, DEFAULT_KEEP_BACKUPS);
    assert_eq!(req.create_mode, 0o644);
    assert!(req.expected_prev.is_none());
    write_atomic(&req)?;
    assert_eq!(mode_of(&fx.target)?, 0o644);
    Ok(())
}

// --- crash consistency ----------------------------------------------------

/// The child half of `crash_during_write_leaves_original_intact`. It is
/// `#[ignore]`d so it only runs when the parent invokes it explicitly.
#[test]
#[ignore = "child process worker for the crash-consistency test"]
fn crash_child_worker() {
    let (Ok(target), Ok(backups)) = (std::env::var(CRASH_TARGET), std::env::var(CRASH_BACKUPS))
    else {
        return;
    };
    let contents = vec![b'N'; CRASH_PAYLOAD_LEN];
    let mut req = request(Path::new(&target), &contents, Path::new(&backups));
    req.keep_backups = 0;
    let _ = write_atomic(&req);
}

#[test]
fn crash_during_write_leaves_original_intact() -> TestResult {
    let old: &[u8] = b"original contents\n";
    let new_digest = Sha256Digest::of(&vec![b'N'; CRASH_PAYLOAD_LEN]);
    let exe = std::env::current_exe()?;

    for delay_ms in [1_u64, 2, 5, 10, 20] {
        let fx = fixture()?;
        fs::write(&fx.target, old)?;

        let mut child = std::process::Command::new(&exe)
            .args(["--exact", "crash_child_worker", "--ignored"])
            .env(CRASH_TARGET, &fx.target)
            .env(CRASH_BACKUPS, &fx.backups)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = child.kill();
        let _ = child.wait();

        // The target is either untouched or fully replaced, never partial.
        let (contents, digest) = read_with_digest(&fx.target)?;
        assert!(
            contents.as_slice() == old || digest == new_digest,
            "partial target after a kill at {delay_ms}ms ({} bytes)",
            contents.len()
        );
    }
    Ok(())
}

/// A killed writer can leave a temp file behind, since no process survives to
/// unlink it. The recognizable `.detent-tmp-` prefix is what makes that debris
/// collectable, and it must never be mistaken for a backup.
#[test]
fn temp_files_are_recognizable() -> TestResult {
    let fx = fixture()?;
    write_atomic(&request(&fx.target, b"x", &fx.backups))?;
    let mut junk = fs::File::create(fx.dir.join(".detent-tmp-0123456789abcdef"))?;
    junk.write_all(b"junk")?;
    assert_eq!(temp_debris(&fx.dir), 1);
    Ok(())
}
