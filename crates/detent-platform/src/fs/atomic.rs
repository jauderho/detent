//! Atomic write protocol with backups (PLAN §2.4).
//!
//! The protocol, in order:
//!
//! 1. Open the parent directory; refuse relative paths, symlinks, and any
//!    target that exists but is not a regular file.
//! 2. Read the current file and hash it (SHA-256).
//! 3. If [`WriteRequest::expected_prev`] is set and differs, fail with
//!    [`AtomicError::Conflict`] without writing anything.
//! 4. Copy the current contents to
//!    `<backup_dir>/<rfc3339-utc-nanos>-<8 hex of digest>` (`0600`), creating
//!    `backup_dir` `0700` when missing, then rotate to `keep_backups`.
//! 5. Create a temp file in the *same* directory (`O_EXCL | O_NOFOLLOW`) with
//!    the original mode, owner (when running as root) and extended attributes
//!    (which carries the `SELinux` label on Linux, since `security.selinux` is
//!    a plain xattr — no libselinux is linked).
//! 6. Write, `fsync` the file, `rename` over the target, `fsync` the directory.
//!
//! Any failure after the temp file exists unlinks it.

use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use rustix::fs::{
    AtFlags, FileType, Gid, Mode, OFlags, RawMode, Uid, fchmod, fchown, fstat, fsync, open, openat,
    renameat, statat, unlinkat,
};
use rustix::io::Errno;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use xattr::FileExt as _;

/// Number of backups retained per target when the caller has no preference.
pub const DEFAULT_KEEP_BACKUPS: usize = 20;

/// Mode of a backup file: readable only by its owner.
const BACKUP_FILE_MODE: u32 = 0o600;
/// Mode of the backup directory when this module creates it.
const BACKUP_DIR_MODE: u32 = 0o700;
/// Attempts made to find an unused temp / backup file name before giving up.
const NAME_ATTEMPTS: u32 = 32;
/// Length of the digest prefix embedded in a backup file name.
const BACKUP_DIGEST_HEX_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/// A SHA-256 digest of a file's contents.
///
/// Displays, parses and (de)serializes as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Hash `contents`.
    #[must_use]
    pub fn of(contents: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(contents);
        Self(hasher.finalize().into())
    }

    /// The raw 32 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first eight hex characters, as used in backup file names.
    #[must_use]
    pub fn short_hex(&self) -> String {
        self.to_string()
            .chars()
            .take(BACKUP_DIGEST_HEX_LEN)
            .collect()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

impl FromStr for Sha256Digest {
    type Err = AtomicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(AtomicError::BadDigest);
        }
        let mut out = [0_u8; 32];
        let (pairs, _rest) = bytes.as_chunks::<2>();
        for (slot, pair) in out.iter_mut().zip(pairs) {
            let text = std::str::from_utf8(pair).map_err(|_| AtomicError::BadDigest)?;
            *slot = u8::from_str_radix(text, 16).map_err(|_| AtomicError::BadDigest)?;
        }
        Ok(Self(out))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong in this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AtomicError {
    /// The caller passed a path that is not absolute, has no final component
    /// (`/`, `..`), or whose final component is not valid UTF-8.
    #[error("path must be absolute and name a file: {path}")]
    RelativePath {
        /// The offending path.
        path: PathBuf,
    },
    /// The target, or a backup entry, is a symbolic link. This module never
    /// writes or reads through one.
    #[error("refusing to follow symlink: {path}")]
    Symlink {
        /// The offending path.
        path: PathBuf,
    },
    /// The target exists but is not a regular file. Opening a planted FIFO
    /// would block the privileged writer, and a directory or device node is
    /// never a config file, so both are refused up front.
    #[error("refusing to write {path}: not a regular file")]
    NotRegularFile {
        /// The offending path.
        path: PathBuf,
    },
    /// The file changed since the caller last read it; nothing was written.
    #[error("contents changed on disk: expected {expected}, found {}", match .actual {
        Some(digest) => digest.to_string(),
        None => "no file".to_owned(),
    })]
    Conflict {
        /// Digest the caller expected the current file to have.
        expected: Sha256Digest,
        /// Digest actually found, or `None` when the file does not exist.
        actual: Option<Sha256Digest>,
    },
    /// A syscall failed.
    #[error("{op} failed on {path}: {source}")]
    Io {
        /// Short name of the operation that failed, for example `openat`.
        op: &'static str,
        /// Path the operation was applied to.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A string that should have been 64 hex characters was not.
    #[error("not a valid sha-256 hex digest")]
    BadDigest,
    /// The system clock could not be formatted as a UTC timestamp.
    #[error("system clock is out of range for an rfc3339 timestamp")]
    Clock,
}

/// Build an [`AtomicError::Io`] from anything convertible to an `io::Error`.
fn io_error(op: &'static str, path: &Path, source: impl Into<std::io::Error>) -> AtomicError {
    AtomicError::Io {
        op,
        path: path.to_path_buf(),
        source: source.into(),
    }
}

/// True for errors that mean "this filesystem or this caller cannot do
/// extended attributes", which are ignored rather than propagated.
fn xattr_unsupported(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error().map(Errno::from_raw_os_error),
        Some(
            Errno::NOTSUP
                | Errno::PERM
                | Errno::ACCESS
                | Errno::NOSYS
                | Errno::INVAL
                | Errno::RANGE
        )
    ) || err.raw_os_error().is_none()
        || err.raw_os_error() == Some(libc_enodata())
}

/// `ENODATA` (Linux) / `ENOATTR` (macOS) is not exposed by `rustix::io::Errno`
/// under one portable name, so it is spelled out per platform.
const fn libc_enodata() -> i32 {
    #[cfg(target_os = "linux")]
    {
        61
    }
    #[cfg(not(target_os = "linux"))]
    {
        93
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One atomic write.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WriteRequest<'a> {
    /// Absolute path of the file to write. Must not be a symlink.
    pub path: &'a Path,
    /// New contents.
    pub contents: &'a [u8],
    /// Optimistic-concurrency guard: the digest the caller believes the file
    /// currently has. `None` disables the check.
    pub expected_prev: Option<Sha256Digest>,
    /// Directory holding the rotated backups for this target.
    pub backup_dir: &'a Path,
    /// How many backups to retain. `0` disables backups entirely.
    pub keep_backups: usize,
    /// Mode applied when the file did not exist yet, for example `0o644`.
    /// Ignored when the file exists: its mode is preserved.
    pub create_mode: u32,
}

impl<'a> WriteRequest<'a> {
    /// A request with [`DEFAULT_KEEP_BACKUPS`], mode `0o644` and no
    /// concurrency guard.
    #[must_use]
    pub const fn new(path: &'a Path, contents: &'a [u8], backup_dir: &'a Path) -> Self {
        Self {
            path,
            contents,
            expected_prev: None,
            backup_dir,
            keep_backups: DEFAULT_KEEP_BACKUPS,
            create_mode: 0o644,
        }
    }
}

/// What [`write_atomic`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteOutcome {
    /// Digest of the contents that were replaced, `None` if the file was new.
    pub prev_digest: Option<Sha256Digest>,
    /// Digest of the contents now on disk.
    pub new_digest: Sha256Digest,
    /// Backup that was written, if any.
    pub backup: Option<PathBuf>,
    /// True when the target did not exist before this call.
    pub created: bool,
    /// False when the previous owner could not be restored on the replacement
    /// file because the process is not root. Mode and xattrs are still copied.
    pub owner_preserved: bool,
}

/// One file in a backup directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackupEntry {
    /// Absolute path of the backup file.
    pub path: PathBuf,
    /// Modification time of the backup file.
    pub created_utc: SystemTime,
    /// Digest of the backup contents.
    pub digest: Sha256Digest,
    /// Size in bytes of the backed-up contents.
    pub original_len: u64,
}

/// Read a file without following symlinks and hash its contents.
///
/// # Errors
///
/// [`AtomicError::RelativePath`] for a non-absolute path,
/// [`AtomicError::Symlink`] when `path` is a symlink,
/// [`AtomicError::NotRegularFile`] when it is not a regular file, and
/// [`AtomicError::Io`] for any syscall failure including a missing file.
pub fn read_with_digest(path: &Path) -> Result<(Vec<u8>, Sha256Digest), AtomicError> {
    let (dir, name) = split_path(path)?;
    let dir_fd = open_dir(dir)?;
    match read_existing(&dir_fd, &name, path)? {
        Some(found) => Ok((found.contents, found.digest)),
        None => Err(io_error("openat", path, Errno::NOENT)),
    }
}

/// Write `req.contents` to `req.path` following the protocol in the module
/// documentation.
///
/// # Errors
///
/// [`AtomicError::Conflict`] when `expected_prev` does not match what is on
/// disk (nothing is written), [`AtomicError::Symlink`] when the target is a
/// symlink, [`AtomicError::NotRegularFile`] when it exists but is a directory,
/// FIFO or device node, [`AtomicError::RelativePath`] for a non-absolute
/// target, and [`AtomicError::Io`] for syscall failures.
pub fn write_atomic(req: &WriteRequest<'_>) -> Result<WriteOutcome, AtomicError> {
    let (dir, name) = split_path(req.path)?;
    let dir_fd = open_dir(dir)?;
    let existing = read_existing(&dir_fd, &name, req.path)?;

    if let Some(expected) = req.expected_prev {
        let actual = existing.as_ref().map(|found| found.digest);
        if actual != Some(expected) {
            return Err(AtomicError::Conflict { expected, actual });
        }
    }

    let backup = match existing.as_ref() {
        Some(found) if req.keep_backups > 0 => {
            let path = write_backup(
                req.backup_dir,
                &found.contents,
                found.digest,
                SystemTime::now(),
            )?;
            rotate_backups(req.backup_dir, req.keep_backups)?;
            Some(path)
        }
        _ => None,
    };

    let mode = existing
        .as_ref()
        .map_or(req.create_mode, |found| found.mode);
    let owner = existing.as_ref().map(|found| (found.uid, found.gid));
    let owner_preserved = replace_contents(
        &dir_fd,
        &name,
        req.path,
        req.contents,
        mode,
        owner,
        existing.as_ref().map(|found| &found.file),
    )?;

    Ok(WriteOutcome {
        prev_digest: existing.as_ref().map(|found| found.digest),
        new_digest: Sha256Digest::of(req.contents),
        backup,
        created: existing.is_none(),
        owner_preserved,
    })
}

/// List the backups in `backup_dir`, newest first.
///
/// Files whose name does not match the backup naming scheme, and symlinks, are
/// ignored. A missing directory yields an empty list.
///
/// # Errors
///
/// [`AtomicError::Io`] when the directory exists but cannot be read, or when a
/// backup file cannot be read.
pub fn list_backups(backup_dir: &Path) -> Result<Vec<BackupEntry>, AtomicError> {
    let mut names = match backup_names(backup_dir) {
        Ok(names) => names,
        Err(AtomicError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(err) => return Err(err),
    };
    names.sort_unstable();
    names.reverse();

    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let path = backup_dir.join(&name);
        let (contents, digest) = read_with_digest(&path)?;
        let created_utc = std::fs::symlink_metadata(&path)
            .and_then(|meta| meta.modified())
            .map_err(|err| io_error("stat", &path, err))?;
        entries.push(BackupEntry {
            path,
            created_utc,
            digest,
            original_len: contents.len() as u64,
        });
    }
    Ok(entries)
}

/// Restore `backup` over `target`.
///
/// This is itself an atomic write: the current contents of `target` are backed
/// up first, into the directory holding `backup`.
///
/// # Errors
///
/// Same as [`write_atomic`], plus [`AtomicError::Io`] if `backup` cannot be
/// read.
pub fn restore_backup(backup: &Path, target: &Path) -> Result<WriteOutcome, AtomicError> {
    let backup_dir = backup.parent().ok_or_else(|| AtomicError::RelativePath {
        path: backup.to_path_buf(),
    })?;
    let (contents, _) = read_with_digest(backup)?;
    write_atomic(&WriteRequest::new(target, &contents, backup_dir))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// The current state of the target file.
struct Existing {
    file: File,
    contents: Vec<u8>,
    digest: Sha256Digest,
    mode: u32,
    uid: u32,
    gid: u32,
}

/// Split an absolute path into its parent directory and final component.
fn split_path(path: &Path) -> Result<(&Path, String), AtomicError> {
    let relative = || AtomicError::RelativePath {
        path: path.to_path_buf(),
    };
    if !path.is_absolute() {
        return Err(relative());
    }
    let name = path.file_name().ok_or_else(relative)?;
    let name = name.to_str().ok_or_else(relative)?;
    let dir = path.parent().ok_or_else(relative)?;
    Ok((dir, name.to_owned()))
}

/// Open a directory for `*at` syscalls.
fn open_dir(dir: &Path) -> Result<OwnedFd, AtomicError> {
    open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| io_error("open", dir, err))
}

/// Convert a raw `st_mode` to the permission bits this module carries around.
fn perm_bits(raw: RawMode) -> u32 {
    widen_mode(Mode::from_raw_mode(raw).bits()) & 0o7777
}

/// Widen a platform raw mode to `u32`. `RawMode` is already `u32` on Linux and
/// `u16` on macOS, so the conversion has to be selected per platform.
#[cfg(target_os = "linux")]
const fn widen_mode(bits: RawMode) -> u32 {
    bits
}

/// See the Linux variant above.
#[cfg(not(target_os = "linux"))]
const fn widen_mode(bits: RawMode) -> u32 {
    bits as u32
}

/// Convert permission bits back to a [`Mode`], defaulting to `0o600` when the
/// value does not fit the platform's raw mode type.
fn to_mode(bits: u32) -> Mode {
    Mode::from_bits_truncate(RawMode::try_from(bits).unwrap_or(BACKUP_FILE_MODE as RawMode))
}

/// Read the target file, refusing symlinks. `Ok(None)` means "does not exist".
fn read_existing(
    dir_fd: &OwnedFd,
    name: &str,
    path: &Path,
) -> Result<Option<Existing>, AtomicError> {
    match statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {}
            FileType::Symlink => {
                return Err(AtomicError::Symlink {
                    path: path.to_path_buf(),
                });
            }
            // A FIFO would block the `openat` below; a directory or device
            // node is never a config file.
            _ => {
                return Err(AtomicError::NotRegularFile {
                    path: path.to_path_buf(),
                });
            }
        },
        Err(Errno::NOENT) => return Ok(None),
        Err(err) => return Err(io_error("statat", path, err)),
    }

    let fd = openat(
        dir_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| io_error("openat", path, err))?;
    let mut file = File::from(fd);
    let stat = fstat(&file).map_err(|err| io_error("fstat", path, err))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|err| io_error("read", path, err))?;
    let digest = Sha256Digest::of(&contents);
    Ok(Some(Existing {
        file,
        contents,
        digest,
        mode: perm_bits(stat.st_mode),
        uid: stat.st_uid,
        gid: stat.st_gid,
    }))
}

/// Unlinks the temp file unless disarmed.
struct TempGuard<'a> {
    dir_fd: &'a OwnedFd,
    name: String,
    armed: bool,
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.dir_fd, self.name.as_str(), AtFlags::empty());
        }
    }
}

/// Generate a temp-file name that is unlikely to collide. `O_EXCL` is what
/// actually guarantees exclusivity; this only avoids needless retries.
fn temp_name(attempt: u32) -> String {
    use std::hash::{BuildHasher as _, RandomState};
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let token = RandomState::new().hash_one((std::process::id(), nanos, attempt));
    format!(".detent-tmp-{token:016x}")
}

/// Create the temp file, write, fsync, rename, fsync the directory.
/// Returns whether the previous owner was preserved.
fn replace_contents(
    dir_fd: &OwnedFd,
    name: &str,
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    source: Option<&File>,
) -> Result<bool, AtomicError> {
    let (temp, mut file) = create_exclusive(dir_fd, path, mode, temp_name)?;
    let mut guard = TempGuard {
        dir_fd,
        name: temp.clone(),
        armed: true,
    };

    fchmod(&file, to_mode(mode)).map_err(|err| io_error("fchmod", path, err))?;

    let mut owner_preserved = true;
    if let Some((uid, gid)) = owner {
        match fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))) {
            Ok(()) => {}
            // Not root: mode and xattrs still apply, ownership does not.
            Err(Errno::PERM) => owner_preserved = false,
            Err(err) => return Err(io_error("fchown", path, err)),
        }
    }

    if let Some(source) = source {
        copy_xattrs(source, &file, path)?;
    }

    file.write_all(contents)
        .map_err(|err| io_error("write", path, err))?;
    fsync(&file).map_err(|err| io_error("fsync", path, err))?;
    drop(file);

    renameat(dir_fd, temp.as_str(), dir_fd, name).map_err(|err| io_error("renameat", path, err))?;
    guard.armed = false;

    fsync(dir_fd).map_err(|err| io_error("fsync", path, err))?;
    Ok(owner_preserved)
}

/// Create a file with `O_EXCL | O_NOFOLLOW`, retrying on name collisions.
fn create_exclusive(
    dir_fd: &OwnedFd,
    path: &Path,
    mode: u32,
    mut name_for: impl FnMut(u32) -> String,
) -> Result<(String, File), AtomicError> {
    let mut last = Errno::EXIST;
    for attempt in 0..NAME_ATTEMPTS {
        let candidate = name_for(attempt);
        match openat(
            dir_fd,
            candidate.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            to_mode(mode),
        ) {
            Ok(fd) => return Ok((candidate, File::from(fd))),
            Err(Errno::EXIST) => last = Errno::EXIST,
            Err(err) => return Err(io_error("openat", path, err)),
        }
    }
    Err(io_error("openat", path, last))
}

/// Copy every extended attribute from `source` to `dest`. On Linux this
/// carries `security.selinux`, which is how the `SELinux` label is preserved
/// without linking libselinux.
fn copy_xattrs(source: &File, dest: &File, path: &Path) -> Result<(), AtomicError> {
    let names = match source.list_xattr() {
        Ok(names) => names,
        Err(err) if xattr_unsupported(&err) => return Ok(()),
        Err(err) => return Err(io_error("flistxattr", path, err)),
    };
    for name in names {
        let value = match source.get_xattr(&name) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(err) if xattr_unsupported(&err) => continue,
            Err(err) => return Err(io_error("fgetxattr", path, err)),
        };
        match dest.set_xattr(&name, &value) {
            Ok(()) => {}
            Err(err) if xattr_unsupported(&err) => {}
            Err(err) => return Err(io_error("fsetxattr", path, err)),
        }
    }
    Ok(())
}

// --- backups ---------------------------------------------------------------

/// Format `now` as `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`. Fixed width, so
/// lexicographic order on names is chronological order.
fn utc_stamp(now: SystemTime) -> Result<String, AtomicError> {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z"
    );
    time::OffsetDateTime::from(now)
        .format(&format)
        .map_err(|_| AtomicError::Clock)
}

/// Create `backup_dir` with mode `0700` if it does not exist yet.
fn ensure_backup_dir(backup_dir: &Path) -> Result<(), AtomicError> {
    if backup_dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(backup_dir).map_err(|err| io_error("mkdir", backup_dir, err))?;
    std::fs::set_permissions(backup_dir, std::fs::Permissions::from_mode(BACKUP_DIR_MODE))
        .map_err(|err| io_error("chmod", backup_dir, err))
}

/// Write `contents` into a fresh `0600` backup file and return its path.
fn write_backup(
    backup_dir: &Path,
    contents: &[u8],
    digest: Sha256Digest,
    now: SystemTime,
) -> Result<PathBuf, AtomicError> {
    ensure_backup_dir(backup_dir)?;
    let stamp = utc_stamp(now)?;
    let short = digest.short_hex();
    let dir_fd = open_dir(backup_dir)?;

    // Two backups can land in the same nanosecond. Nudging the timestamp by
    // one nanosecond per attempt keeps every name well-formed and still
    // sortable, which a `.1` suffix would not.
    let (name, mut file) = create_exclusive(&dir_fd, backup_dir, BACKUP_FILE_MODE, |attempt| {
        now.checked_add(Duration::from_nanos(u64::from(attempt)))
            .and_then(|shifted| utc_stamp(shifted).ok())
            .map_or_else(|| format!("{stamp}-{short}"), |s| format!("{s}-{short}"))
    })?;
    let path = backup_dir.join(&name);

    let mut guard = TempGuard {
        dir_fd: &dir_fd,
        name: name.clone(),
        armed: true,
    };
    fchmod(&file, to_mode(BACKUP_FILE_MODE)).map_err(|err| io_error("fchmod", &path, err))?;
    file.write_all(contents)
        .map_err(|err| io_error("write", &path, err))?;
    fsync(&file).map_err(|err| io_error("fsync", &path, err))?;
    drop(file);
    guard.armed = false;

    fsync(&dir_fd).map_err(|err| io_error("fsync", backup_dir, err))?;
    Ok(path)
}

/// True when `name` looks like `<stamp>-<8 hex>` and is not a temp file.
fn is_backup_name(name: &str) -> bool {
    let Some((stamp, short)) = name.rsplit_once('-') else {
        return false;
    };
    short.len() == BACKUP_DIGEST_HEX_LEN
        && short.bytes().all(|byte| byte.is_ascii_hexdigit())
        && stamp.contains('T')
        && stamp.ends_with('Z')
}

/// Names of the backup files in `backup_dir`, unsorted, symlinks excluded.
fn backup_names(backup_dir: &Path) -> Result<Vec<String>, AtomicError> {
    let mut names = Vec::new();
    let entries =
        std::fs::read_dir(backup_dir).map_err(|err| io_error("readdir", backup_dir, err))?;
    for entry in entries {
        let entry = entry.map_err(|err| io_error("readdir", backup_dir, err))?;
        let file_type = entry
            .file_type()
            .map_err(|err| io_error("readdir", backup_dir, err))?;
        if !file_type.is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && is_backup_name(name)
        {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Delete all but the `keep` newest backups.
fn rotate_backups(backup_dir: &Path, keep: usize) -> Result<(), AtomicError> {
    let mut names = backup_names(backup_dir)?;
    if names.len() <= keep {
        return Ok(());
    }
    names.sort_unstable();
    names.reverse();
    let dir_fd = open_dir(backup_dir)?;
    for name in names.into_iter().skip(keep) {
        unlinkat(&dir_fd, name.as_str(), AtFlags::empty())
            .map_err(|err| io_error("unlinkat", &backup_dir.join(&name), err))?;
    }
    fsync(&dir_fd).map_err(|err| io_error("fsync", backup_dir, err))
}

#[cfg(test)]
mod tests {
    use super::{
        AtomicError, Sha256Digest, TempGuard, create_exclusive, libc_enodata, list_backups,
        open_dir, restore_backup, write_backup, xattr_unsupported,
    };
    use std::io::Error;
    use std::path::Path;
    use std::time::SystemTime;

    /// `Errno::NOTSUP` and friends mean "no xattrs here"; anything else is a
    /// real failure that must be propagated.
    #[test]
    fn xattr_unsupported_classifies_errnos() {
        for code in [
            rustix::io::Errno::NOTSUP.raw_os_error(),
            rustix::io::Errno::PERM.raw_os_error(),
            rustix::io::Errno::ACCESS.raw_os_error(),
            rustix::io::Errno::NOSYS.raw_os_error(),
            rustix::io::Errno::INVAL.raw_os_error(),
            rustix::io::Errno::RANGE.raw_os_error(),
            libc_enodata(),
        ] {
            assert!(xattr_unsupported(&Error::from_raw_os_error(code)), "{code}");
        }
        assert!(xattr_unsupported(&Error::other("no errno")));
        assert!(!xattr_unsupported(&Error::from_raw_os_error(
            rustix::io::Errno::NOSPC.raw_os_error()
        )));
    }

    /// An armed guard unlinks the temp file when it is dropped; that is what
    /// keeps a failed write from leaving debris behind.
    #[test]
    fn temp_guard_unlinks_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let dir_fd = open_dir(dir.path())?;
        let (name, _file) = create_exclusive(&dir_fd, dir.path(), 0o600, |_| {
            ".detent-tmp-guarded".to_owned()
        })?;
        assert!(dir.path().join(&name).exists());
        drop(TempGuard {
            dir_fd: &dir_fd,
            name: name.clone(),
            armed: true,
        });
        assert!(!dir.path().join(&name).exists());
        Ok(())
    }

    /// `O_EXCL` never overwrites: a name generator that always returns the same
    /// existing name exhausts its attempts instead.
    #[test]
    fn create_exclusive_gives_up_on_a_permanently_taken_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("taken"), b"mine")?;
        let dir_fd = open_dir(dir.path())?;
        let result = create_exclusive(&dir_fd, dir.path(), 0o600, |_| "taken".to_owned());
        assert!(matches!(result, Err(AtomicError::Io { .. })));
        assert_eq!(std::fs::read(dir.path().join("taken"))?, b"mine");
        Ok(())
    }

    /// Two backups taken within the same nanosecond must not collide.
    #[test]
    fn backup_names_disambiguate_identical_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let backups = dir.path().join("backups");
        let digest = Sha256Digest::of(b"x");
        let now = SystemTime::UNIX_EPOCH;
        let first = write_backup(&backups, b"x", digest, now)?;
        let second = write_backup(&backups, b"x", digest, now)?;
        assert_ne!(first, second);
        assert_eq!(list_backups(&backups)?.len(), 2);
        Ok(())
    }

    /// A backup directory that is really a file is a hard error, not an empty
    /// listing: only a missing directory means "no backups yet".
    #[test]
    fn list_backups_propagates_non_not_found_errors() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"x")?;
        assert!(matches!(
            list_backups(&not_a_dir),
            Err(AtomicError::Io { .. })
        ));
        Ok(())
    }

    /// `/` has no parent, so it can never name a backup file.
    #[test]
    fn restore_rejects_a_backup_without_a_parent() {
        assert!(matches!(
            restore_backup(Path::new("/"), Path::new("/tmp/target")),
            Err(AtomicError::RelativePath { .. })
        ));
    }

    /// `statat` failures other than `ENOENT` are reported, not treated as
    /// "file does not exist".
    #[test]
    fn oversized_names_surface_the_statat_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let long = dir.path().join("x".repeat(512));
        let dir_fd = open_dir(dir.path())?;
        let result = super::read_existing(&dir_fd, &"x".repeat(512), &long);
        assert!(matches!(result, Err(AtomicError::Io { op: "statat", .. })));
        Ok(())
    }
}
