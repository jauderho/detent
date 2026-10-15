//! Make an existing directory private to the process that owns it.
//!
//! `DirBuilder::mode` only applies to a directory it creates. A directory that
//! an older version made `0755` keeps that mode. [`ensure_private`] closes the
//! gap without a check-then-`chmod` race: it opens the directory with
//! `O_DIRECTORY | O_NOFOLLOW` and does `fstat` and `fchmod` on the descriptor.
//!
//! The state root belongs to the worker account, but a root command-line run
//! writes the audit log in it too (BUGFIX D4). [`ensure_private_as_parent`]
//! and [`open_append_as`] give what that run makes, or what an older version
//! left root-owned, the owner of the state root, so the worker can use it.

use std::fs::File;
use std::io;
use std::path::Path;

use rustix::fs::{
    CWD, FileType, Gid, Mode, OFlags, RawMode, Stat, Uid, fchmod, fchown, fstat, open, openat,
};
use rustix::process::geteuid;

/// The mode of a private directory.
const PRIVATE_DIR_MODE: RawMode = 0o700;
/// Mask of the permission bits, without the file type.
const PERMISSION_BITS: RawMode = 0o7777;

/// Set `dir` to `0700` when this process owns it.
///
/// A symlink is not followed. A directory that another user owns is not
/// changed. An empty path is the parent of a bare file name: there is no
/// directory to change, so it is left alone.
///
/// # Errors
///
/// - [`io::ErrorKind::PermissionDenied`] when the effective user does not own
///   `dir`.
/// - The OS error when `dir` is a symlink, is not a directory, or cannot be
///   opened or changed.
pub fn ensure_private(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    let fd = open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fstat(&fd)?;
    let euid = geteuid().as_raw();
    if stat.st_uid != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by uid {euid}",
                dir.display(),
                stat.st_uid
            ),
        ));
    }
    if stat.st_mode & PERMISSION_BITS != PRIVATE_DIR_MODE {
        fchmod(&fd, Mode::from_bits_truncate(PRIVATE_DIR_MODE))?;
    }
    Ok(())
}

/// The user and group a directory or file must belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOwner {
    /// The user id.
    pub uid: u32,
    /// The group id.
    pub gid: u32,
}

impl FileOwner {
    const fn of(stat: &Stat) -> Self {
        Self {
            uid: stat.st_uid,
            gid: stat.st_gid,
        }
    }

    fn give_to(self, fd: &impl rustix::fd::AsFd) -> io::Result<()> {
        fchown(
            fd,
            Some(Uid::from_raw(self.uid)),
            Some(Gid::from_raw(self.gid)),
        )
        .map_err(io::Error::from)
    }
}

/// Set `dir` to `0700`, give it the owner of its parent directory, and return
/// that owner.
///
/// Only a process that is not that owner (root) calls `fchown`: the worker
/// owns what it makes, and its seccomp table has no `fchown`. Neither `dir`
/// nor its parent is followed through a symlink; the owner and the mode are
/// set through the open descriptor.
///
/// # Errors
///
/// - [`io::ErrorKind::InvalidInput`] when `dir` has no file name.
/// - The OS error when `dir` or its parent is a symlink, is not a directory,
///   or cannot be opened or changed (`PermissionDenied` when this process may
///   not give `dir` that owner).
pub fn ensure_private_as_parent(dir: &Path) -> io::Result<FileOwner> {
    let name = dir.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let parent = dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    // `openat(CWD, …)`, not `open`: rustix issues `open(2)` for `open` on
    // x86_64, and the worker's seccomp table allows only `openat`.
    let parent = openat(CWD, parent, flags, Mode::empty())?;
    let fd = openat(&parent, name, flags, Mode::empty())?;
    let owner = FileOwner::of(&fstat(&parent)?);
    let stat = fstat(&fd)?;
    if FileOwner::of(&stat) != owner {
        owner.give_to(&fd)?;
    }
    if stat.st_mode & PERMISSION_BITS != PRIVATE_DIR_MODE {
        fchmod(&fd, Mode::from_bits_truncate(PRIVATE_DIR_MODE))?;
    }
    Ok(owner)
}

/// Open `path` for appending, creating it with `mode`, and give it `owner`
/// when it has another one.
///
/// A symlink is not followed. Only a regular file with one link gets a new
/// owner: a hard link that the owner of the directory put there can name a
/// file elsewhere (with `fs.protected_hardlinks` off), and root must not give
/// that file away.
///
/// # Errors
///
/// - [`io::ErrorKind::PermissionDenied`] when the owner differs and `path` is
///   not a regular file with one link, or this process may not change it.
/// - The OS error when `path` is a symlink or cannot be opened.
pub fn open_append_as(path: &Path, mode: u32, owner: FileOwner) -> io::Result<File> {
    let fd = openat(
        CWD,
        path,
        OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        super::atomic::to_mode(mode),
    )?;
    let stat = fstat(&fd)?;
    if FileOwner::of(&stat) != owner {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not a regular file with one link", path.display()),
            ));
        }
        owner.give_to(&fd)?;
    }
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, chown, symlink};
    use std::path::PathBuf;

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The uid of `nobody`, a user that is not the test user.
    const NOBODY_UID: u32 = 65534;

    fn mode_of(path: &Path) -> Result<u32, std::io::Error> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o7777)
    }

    #[test]
    fn a_wider_directory_that_we_own_becomes_0700() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("audit");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        ensure_private(&dir)?;
        assert_eq!(mode_of(&dir)?, 0o700);
        Ok(())
    }

    #[test]
    fn a_private_directory_stays_as_it_is() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("audit");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        ensure_private(&dir)?;
        assert_eq!(mode_of(&dir)?, 0o700);
        Ok(())
    }

    #[test]
    fn a_symlinked_directory_is_refused_and_its_target_is_not_changed() -> R {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        std::fs::create_dir(&target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        let link = root.path().join("audit");
        symlink(&target, &link)?;
        assert!(ensure_private(&link).is_err());
        assert_eq!(mode_of(&target)?, 0o755);
        Ok(())
    }

    #[test]
    fn an_empty_path_is_left_alone() -> R {
        ensure_private(Path::new(""))?;
        Ok(())
    }

    #[test]
    fn a_file_is_refused() -> R {
        let root = tempfile::tempdir()?;
        let file = root.path().join("audit");
        std::fs::write(&file, b"")?;
        assert!(ensure_private(&file).is_err());
        Ok(())
    }

    #[test]
    fn a_directory_owned_by_another_user_is_refused_and_not_changed() -> R {
        let root = tempfile::tempdir()?;
        let dir = if geteuid().is_root() {
            let dir = root.path().join("audit");
            std::fs::create_dir(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
            chown(&dir, Some(NOBODY_UID), None)?;
            dir
        } else {
            // Unprivileged: an existing directory that root owns.
            PathBuf::from("/usr")
        };
        let mode_before = mode_of(&dir)?;
        let err = ensure_private(&dir).err().ok_or("no error")?;
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(mode_of(&dir)?, mode_before);
        Ok(())
    }

    fn owner_of(path: &Path) -> Result<FileOwner, std::io::Error> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path)?;
        Ok(FileOwner {
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    #[test]
    fn a_directory_becomes_0700_and_names_the_owner_of_its_parent() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("audit");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let owner = ensure_private_as_parent(&dir)?;
        assert_eq!(owner, owner_of(root.path())?);
        assert_eq!(owner_of(&dir)?, owner);
        assert_eq!(mode_of(&dir)?, 0o700);
        Ok(())
    }

    #[test]
    fn the_parent_owner_check_refuses_a_symlinked_directory() -> R {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        std::fs::create_dir(&target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        let link = root.path().join("audit");
        symlink(&target, &link)?;
        assert!(ensure_private_as_parent(&link).is_err());
        assert_eq!(mode_of(&target)?, 0o755);
        Ok(())
    }

    #[test]
    fn a_new_file_is_created_with_the_mode_and_appended_to() -> R {
        use std::io::Write as _;
        let root = tempfile::tempdir()?;
        let path = root.path().join("log.jsonl");
        let owner = owner_of(root.path())?;
        open_append_as(&path, 0o600, owner)?.write_all(b"one\n")?;
        open_append_as(&path, 0o600, owner)?.write_all(b"two\n")?;
        assert_eq!(std::fs::read(&path)?, b"one\ntwo\n");
        assert_eq!(mode_of(&path)?, 0o600);
        assert_eq!(owner_of(&path)?, owner);
        Ok(())
    }

    #[test]
    fn a_symlinked_file_is_refused_and_its_target_is_not_written() -> R {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        std::fs::write(&target, b"kept\n")?;
        let link = root.path().join("log.jsonl");
        symlink(&target, &link)?;
        assert!(open_append_as(&link, 0o600, owner_of(root.path())?).is_err());
        assert_eq!(std::fs::read(&target)?, b"kept\n");
        Ok(())
    }

    /// Root gives a file with one link the owner it is asked for; any other
    /// process is refused and the owner stays.
    #[test]
    fn a_file_with_one_link_gets_the_owner_only_from_root() -> R {
        let root = tempfile::tempdir()?;
        let path = root.path().join("log.jsonl");
        std::fs::write(&path, b"")?;
        let before = owner_of(&path)?;
        let other = FileOwner {
            uid: NOBODY_UID,
            gid: NOBODY_UID,
        };
        match open_append_as(&path, 0o600, other) {
            Ok(_) => {
                assert!(geteuid().is_root());
                assert_eq!(owner_of(&path)?, other);
            }
            Err(err) => {
                assert!(!geteuid().is_root(), "{err}");
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(owner_of(&path)?, before);
            }
        }
        Ok(())
    }

    #[test]
    fn a_path_without_a_file_name_is_refused() {
        let err = ensure_private_as_parent(Path::new("/")).err();
        assert_eq!(err.map(|err| err.kind()), Some(io::ErrorKind::InvalidInput));
    }

    /// A hard link can name a file elsewhere; it never gets a new owner.
    #[test]
    fn a_file_with_two_links_is_not_given_another_owner() -> R {
        let root = tempfile::tempdir()?;
        let path = root.path().join("log.jsonl");
        std::fs::write(&path, b"")?;
        std::fs::hard_link(&path, root.path().join("elsewhere"))?;
        let before = owner_of(&path)?;
        let other = FileOwner {
            uid: NOBODY_UID,
            gid: NOBODY_UID,
        };
        let err = open_append_as(&path, 0o600, other)
            .err()
            .ok_or("no error")?;
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner_of(&path)?, before);
        Ok(())
    }
}
