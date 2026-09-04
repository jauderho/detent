//! Resolving a user name to a uid/gid pair without libc's NSS.
//!
//! `detent` ships as a statically linked musl binary (PLAN §1.6, §4.1). A
//! static musl build has no working `getpwnam`: NSS modules are dynamic
//! objects, so `getpwnam` in a static binary either returns nothing or drags
//! `dlopen` back in. `detent` only ever needs to resolve **its own service
//! account**, which `sysusers.d` creates as a local entry in `/etc/passwd`
//! (PLAN §2.10), so parsing those files directly is both sufficient and more
//! predictable than NSS.
//!
//! # Portability note
//!
//! On macOS, local users live in Directory Services and `/etc/passwd` holds
//! only the system accounts. That is acceptable: privilege dropping only runs
//! when the monitor is root, and macOS is a host/dev platform where `detent`
//! does not run as a system daemon (PLAN §1.6).

use std::path::{Path, PathBuf};

/// Canonical location of the local user database.
pub const PASSWD_PATH: &str = "/etc/passwd";

/// Canonical location of the local group database.
pub const GROUP_PATH: &str = "/etc/group";

/// The account the worker drops to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIds {
    /// Numeric user id.
    pub uid: u32,
    /// Numeric primary group id.
    pub gid: u32,
}

/// Resolving an account failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The database file could not be read.
    #[error("cannot read {path}")]
    Unreadable {
        /// Which file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// No entry with that name.
    #[error("no such account: {0}")]
    NotFound(String),
}

/// Resolve `name` in the local user database.
///
/// # Errors
///
/// [`LookupError::Unreadable`] when `/etc/passwd` cannot be read, and
/// [`LookupError::NotFound`] when it holds no such account.
pub fn lookup_user(name: &str) -> Result<UserIds, LookupError> {
    lookup_user_in(Path::new(PASSWD_PATH), name)
}

/// Resolve `name` in the local group database.
///
/// # Errors
///
/// [`LookupError::Unreadable`] when `/etc/group` cannot be read, and
/// [`LookupError::NotFound`] when it holds no such group.
pub fn lookup_group(name: &str) -> Result<u32, LookupError> {
    lookup_group_in(Path::new(GROUP_PATH), name)
}

/// As [`lookup_user`], against an explicit file. Exposed for tests.
///
/// # Errors
///
/// As [`lookup_user`].
pub fn lookup_user_in(passwd: &Path, name: &str) -> Result<UserIds, LookupError> {
    let contents = read(passwd)?;
    parse_passwd(&contents, name).ok_or_else(|| LookupError::NotFound(name.to_owned()))
}

/// As [`lookup_group`], against an explicit file. Exposed for tests.
///
/// # Errors
///
/// As [`lookup_group`].
pub fn lookup_group_in(group: &Path, name: &str) -> Result<u32, LookupError> {
    let contents = read(group)?;
    parse_group(&contents, name).ok_or_else(|| LookupError::NotFound(name.to_owned()))
}

fn read(path: &Path) -> Result<String, LookupError> {
    // The databases are ASCII by definition; a stray non-UTF-8 byte in a GECOS
    // field must not make the lookup fail, so decode lossily.
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|source| LookupError::Unreadable {
            path: path.to_path_buf(),
            source,
        })
}

/// `name:passwd:uid:gid:gecos:dir:shell`
fn parse_passwd(contents: &str, name: &str) -> Option<UserIds> {
    for line in contents.lines() {
        let line = line.trim_end_matches(['\r']);
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let _password = fields.next()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        return Some(UserIds { uid, gid });
    }
    None
}

/// `name:passwd:gid:members`
fn parse_group(contents: &str, name: &str) -> Option<u32> {
    for line in contents.lines() {
        let line = line.trim_end_matches(['\r']);
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let _password = fields.next()?;
        return fields.next()?.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        GROUP_PATH, LookupError, PASSWD_PATH, UserIds, lookup_group_in, lookup_user_in,
        parse_group, parse_passwd,
    };
    use std::path::Path;

    const PASSWD: &str = "\
# a comment
root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r
detent:!:998:997:detent service:/var/lib/detent:/usr/sbin/nologin
broken:x:notanumber:5::/:/bin/false
short:x:
";

    const GROUP: &str = "\
# a comment
root:x:0:
detent:x:997:
broken:x:nope:
short:x
";

    #[test]
    fn a_normal_entry_resolves() {
        assert_eq!(
            parse_passwd(PASSWD, "detent"),
            Some(UserIds { uid: 998, gid: 997 })
        );
        assert_eq!(
            parse_passwd(PASSWD, "root"),
            Some(UserIds { uid: 0, gid: 0 })
        );
        assert_eq!(
            parse_passwd(PASSWD, "daemon"),
            Some(UserIds { uid: 1, gid: 1 })
        );
        assert_eq!(parse_group(GROUP, "detent"), Some(997));
        assert_eq!(parse_group(GROUP, "root"), Some(0));
    }

    #[test]
    fn malformed_and_missing_entries_resolve_to_nothing() {
        assert_eq!(parse_passwd(PASSWD, "nobody"), None);
        assert_eq!(parse_passwd(PASSWD, "broken"), None);
        assert_eq!(parse_passwd(PASSWD, "short"), None);
        assert_eq!(parse_passwd(PASSWD, "#"), None);
        assert_eq!(parse_passwd("", "root"), None);
        assert_eq!(parse_group(GROUP, "nobody"), None);
        assert_eq!(parse_group(GROUP, "broken"), None);
        assert_eq!(parse_group(GROUP, "short"), None);
        assert_eq!(parse_group("", "root"), None);
    }

    #[test]
    fn lookups_read_the_files_they_are_given() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let passwd = dir.path().join("passwd");
        let group = dir.path().join("group");
        assert!(std::fs::write(&passwd, PASSWD).is_ok());
        assert!(std::fs::write(&group, GROUP).is_ok());

        assert_eq!(
            lookup_user_in(&passwd, "detent").ok(),
            Some(UserIds { uid: 998, gid: 997 })
        );
        assert_eq!(lookup_group_in(&group, "detent").ok(), Some(997));

        assert!(matches!(
            lookup_user_in(&passwd, "absent"),
            Err(LookupError::NotFound(name)) if name == "absent"
        ));
        assert!(matches!(
            lookup_group_in(&group, "absent"),
            Err(LookupError::NotFound(_))
        ));
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            lookup_user_in(&missing, "detent"),
            Err(LookupError::Unreadable { .. })
        ));
        assert!(matches!(
            lookup_group_in(&missing, "detent"),
            Err(LookupError::Unreadable { .. })
        ));
        assert!(
            LookupError::NotFound("x".to_owned())
                .to_string()
                .contains('x')
        );
        assert!(
            !LookupError::Unreadable {
                path: missing,
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            }
            .to_string()
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn non_utf8_bytes_do_not_break_the_parse() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let passwd = dir.path().join("passwd");
        let mut bytes = b"detent:x:998:997:".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b":/var/lib/detent:/sbin/nologin\n");
        assert!(std::fs::write(&passwd, bytes).is_ok());
        assert_eq!(
            lookup_user_in(&passwd, "detent").ok(),
            Some(UserIds { uid: 998, gid: 997 })
        );
        Ok(())
    }

    #[test]
    fn the_system_databases_resolve_root() {
        use super::{lookup_group, lookup_user};
        assert_eq!(lookup_user("root").ok().map(|ids| ids.uid), Some(0));
        // The gid-0 group is `root` on Linux and `wheel` on macOS.
        let gid = lookup_group("root")
            .ok()
            .or_else(|| lookup_group("wheel").ok());
        assert_eq!(gid, Some(0));
    }

    #[test]
    fn the_documented_database_paths_are_the_posix_ones() {
        assert_eq!(Path::new(PASSWD_PATH), Path::new("/etc/passwd"));
        assert_eq!(Path::new(GROUP_PATH), Path::new("/etc/group"));
    }
}
