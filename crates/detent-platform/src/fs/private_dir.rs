//! Make an existing directory private to the process that owns it.
//!
//! `DirBuilder::mode` only applies to a directory it creates. A directory that
//! an older version made `0755` keeps that mode. [`ensure_private`] closes the
//! gap without a check-then-`chmod` race: it opens the directory with
//! `O_DIRECTORY | O_NOFOLLOW` and does `fstat` and `fchmod` on the descriptor.

use std::io;
use std::path::Path;

use rustix::fs::{Mode, OFlags, RawMode, fchmod, fstat, open};
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
}
