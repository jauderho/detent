//! `/etc/detent/secrets.toml`: the secret a dns-01 provider needs (PLAN
//! §2.8, §2.10).
//!
//! ```toml
//! [acme]
//! dns_provider = "<secret>"
//! ```
//!
//! The one secret is the Cloudflare or deSEC API token, the acme-dns
//! password, or the RFC 2136 TSIG key (base64). Which one it is follows from
//! `[acme.provider] kind` in `detent.toml` ([`crate::DnsProviderConfig`]).
//!
//! [`load`] runs in the privileged `detent serve` parent, before the fork.
//! It refuses a file that another user could have written or can read:
//!
//! * a symlink (the file is opened `O_NOFOLLOW`), or anything that is not a
//!   regular file;
//! * a file larger than [`MAX_SECRETS_BYTES`];
//! * a mode with any group or other bit (`mode & 0o077 != 0`);
//! * an owner other than the effective uid.
//!
//! No error carries secret bytes. A TOML error names only the line and the
//! column: the parser's own text can quote the line, and that line can hold
//! the secret.

use std::fmt;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// The largest `secrets.toml` [`load`] reads, in bytes (64 KiB).
pub const MAX_SECRETS_BYTES: u64 = 64 * 1024;

/// Permission bits for group and other. Any of them set is refused.
const GROUP_OTHER_BITS: u32 = 0o077;

/// One secret value. Zeroed on drop; `Debug` prints `[redacted]`.
///
/// There is no `Display`, `Serialize` or `Clone`: the only way to the bytes
/// is [`expose`](Self::expose), so each use is explicit.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// The secret text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

/// The contents of `secrets.toml`. Empty when the file does not exist.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Secrets {
    /// `[acme]`.
    acme: AcmeSecrets,
}

/// `[acme]` of `secrets.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct AcmeSecrets {
    /// The secret of the configured dns-01 provider.
    dns_provider: Option<Secret>,
}

impl Secrets {
    /// `[acme] dns_provider`: the secret of the configured dns-01 provider.
    #[must_use]
    pub const fn dns_provider(&self) -> Option<&Secret> {
        self.acme.dns_provider.as_ref()
    }
}

/// Why `secrets.toml` was refused. No variant carries secret bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsError {
    /// The file exists but could not be opened or read.
    #[error("{path} could not be read: {source}")]
    Io {
        /// The path that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The path is a symlink.
    #[error("{path} is a symlink; it must be a regular file")]
    Symlink {
        /// The path that was tried.
        path: PathBuf,
    },
    /// The path is a directory, a device, a FIFO or a socket.
    #[error("{path} is not a regular file")]
    NotRegular {
        /// The path that was tried.
        path: PathBuf,
    },
    /// The file is larger than [`MAX_SECRETS_BYTES`].
    #[error("{path} is larger than {MAX_SECRETS_BYTES} bytes")]
    TooLarge {
        /// The path that was tried.
        path: PathBuf,
    },
    /// Group or other has a permission bit.
    #[error("{path} has mode {mode:o}; group and other must have no access (use 0600)")]
    Mode {
        /// The path that was tried.
        path: PathBuf,
        /// The permission bits found.
        mode: u32,
    },
    /// The file belongs to another user.
    #[error("{path} is owned by uid {owner}; it must be owned by uid {expected}")]
    Owner {
        /// The path that was tried.
        path: PathBuf,
        /// The owner found.
        owner: u32,
        /// The effective uid of this process.
        expected: u32,
    },
    /// The file is not UTF-8 text.
    #[error("{path} is not UTF-8 text")]
    NotUtf8 {
        /// The path that was tried.
        path: PathBuf,
    },
    /// The file is not valid TOML, or has an unknown table or key.
    #[error(
        "{path} is not a valid secrets file (line {line}, column {column}); \
         expected only [acme] dns_provider"
    )]
    Parse {
        /// The path that was tried.
        path: PathBuf,
        /// 1-based line of the error (line 1 when the parser gives none).
        line: usize,
        /// 1-based column of the error, in characters.
        column: usize,
    },
}

/// Read and check `secrets.toml` at `path`.
///
/// A **missing file is [`Secrets::default()`]**: no secrets. Anything else
/// that is wrong is an error, see the module docs.
///
/// # Errors
///
/// A [`SecretsError`] for each refusal.
pub fn load(path: &Path) -> Result<Secrets, SecretsError> {
    load_owned_by(path, rustix::process::geteuid().as_raw())
}

/// [`load`], with the owner the file must have given as `uid`.
fn load_owned_by(path: &Path, uid: u32) -> Result<Secrets, SecretsError> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;

    let owned = || path.to_path_buf();
    let io = |source: std::io::Error| SecretsError::Io {
        path: owned(),
        source,
    };
    // `NONBLOCK`: opening a FIFO must not hang; it is refused below.
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Secrets::default()),
        Err(Errno::LOOP) => return Err(SecretsError::Symlink { path: owned() }),
        Err(err) => return Err(io(err.into())),
    };
    let file = std::fs::File::from(fd);
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(SecretsError::NotRegular { path: owned() });
    }
    if meta.uid() != uid {
        return Err(SecretsError::Owner {
            path: owned(),
            owner: meta.uid(),
            expected: uid,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & GROUP_OTHER_BITS != 0 {
        return Err(SecretsError::Mode {
            path: owned(),
            mode,
        });
    }
    if meta.len() > MAX_SECRETS_BYTES {
        return Err(SecretsError::TooLarge { path: owned() });
    }
    // One allocation, never grown, so no copy of the secret is left behind
    // in a freed buffer. One byte over the cap tells a file that grew after
    // the `fstat` from one that is exactly at the cap.
    let limit = MAX_SECRETS_BYTES.saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(limit).unwrap_or(usize::MAX),
    ));
    file.take(limit).read_to_end(&mut bytes).map_err(io)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SECRETS_BYTES {
        return Err(SecretsError::TooLarge { path: owned() });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| SecretsError::NotUtf8 { path: owned() })?;
    toml::from_str(text).map_err(|err| {
        let (line, column) = line_column(text, err.span().map_or(0, |span| span.start));
        SecretsError::Parse {
            path: owned(),
            line,
            column,
        }
    })
}

/// The 1-based line and character column of byte `offset` in `text`.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let before = text.get(..offset).unwrap_or(text);
    let line = before.matches('\n').count().saturating_add(1);
    let start = before.rfind('\n').map_or(0, |at| at.saturating_add(1));
    let column = before
        .get(start..)
        .map_or(0, |tail| tail.chars().count())
        .saturating_add(1);
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::{MAX_SECRETS_BYTES, Secrets, SecretsError, load, load_owned_by};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The fixture secret. It must never appear in an error or a dump.
    const VALUE: &str = "not-a-real-token";

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// Write `bytes` to `dir/secrets.toml` with `mode`.
    fn write(dir: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf, std::io::Error> {
        let path = dir.join("secrets.toml");
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        Ok(path)
    }

    fn good() -> String {
        format!("[acme]\ndns_provider = \"{VALUE}\"\n")
    }

    /// Neither the text nor the `Debug` form of `err` holds the secret.
    fn assert_no_secret(err: &SecretsError) {
        let (text, debug) = (err.to_string(), format!("{err:?}"));
        assert!(!text.contains(VALUE), "{text}");
        assert!(!debug.contains(VALUE), "{debug}");
        assert!(!text.is_empty());
    }

    #[test]
    fn a_missing_file_is_no_secrets() -> R {
        let dir = tempfile::tempdir()?;
        let secrets = load(&dir.path().join("secrets.toml"))?;
        assert!(secrets.dns_provider().is_none());
        Ok(())
    }

    #[test]
    fn a_private_file_owned_by_this_user_yields_the_secret() -> R {
        let dir = tempfile::tempdir()?;
        for mode in [0o600, 0o400] {
            let path = write(dir.path(), good().as_bytes(), mode)?;
            let secrets = load(&path)?;
            assert_eq!(
                secrets.dns_provider().map(super::Secret::expose),
                Some(VALUE)
            );
        }
        Ok(())
    }

    #[test]
    fn an_empty_file_or_table_holds_no_secret() -> R {
        let dir = tempfile::tempdir()?;
        for text in ["", "[acme]\n"] {
            let path = write(dir.path(), text.as_bytes(), 0o600)?;
            assert!(load(&path)?.dns_provider().is_none(), "{text:?}");
        }
        Ok(())
    }

    #[test]
    fn debug_output_redacts_the_secret() -> R {
        let dir = tempfile::tempdir()?;
        let path = write(dir.path(), good().as_bytes(), 0o600)?;
        let secrets: Secrets = load(&path)?;
        for dump in [
            format!("{secrets:?}"),
            format!("{:?}", secrets.dns_provider()),
        ] {
            assert!(!dump.contains(VALUE), "{dump}");
            assert!(dump.contains("[redacted]"), "{dump}");
        }
        Ok(())
    }

    #[test]
    fn a_symlink_is_refused_even_to_a_good_file() -> R {
        let dir = tempfile::tempdir()?;
        let target = write(dir.path(), good().as_bytes(), 0o600)?;
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link)?;
        let dangling = dir.path().join("dangling.toml");
        std::os::unix::fs::symlink(dir.path().join("absent"), &dangling)?;
        for path in [link, dangling] {
            match load(&path) {
                Err(err @ SecretsError::Symlink { .. }) => assert_no_secret(&err),
                other => return Err(format!("{path:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn a_file_that_is_not_regular_is_refused() -> R {
        let dir = tempfile::tempdir()?;
        let sub = dir.path().join("secrets.toml");
        std::fs::create_dir(&sub)?;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700))?;
        match load(&sub) {
            Err(err @ SecretsError::NotRegular { .. }) => assert_no_secret(&err),
            other => return Err(format!("gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_path_that_cannot_be_opened_is_an_error_not_a_default() -> R {
        let dir = tempfile::tempdir()?;
        let file = write(dir.path(), good().as_bytes(), 0o600)?;
        // A regular file used as a directory: ENOTDIR, not ENOENT.
        match load(&file.join("secrets.toml")) {
            Err(err @ SecretsError::Io { .. }) => assert_no_secret(&err),
            other => return Err(format!("gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_file_over_64_kib_is_refused_and_64_kib_is_accepted() -> R {
        let dir = tempfile::tempdir()?;
        let body = good();
        let cap = usize::try_from(MAX_SECRETS_BYTES)?;
        // A comment line pads the good document to exactly the cap.
        let pad = cap.saturating_sub(body.len()).saturating_sub(2);
        let exact = format!("#{}\n{body}", "x".repeat(pad));
        assert_eq!(exact.len(), cap);
        let path = write(dir.path(), exact.as_bytes(), 0o600)?;
        assert_eq!(
            load(&path)?.dns_provider().map(super::Secret::expose),
            Some(VALUE)
        );

        let over = format!("#{}\n{body}", "x".repeat(pad.saturating_add(1)));
        let path = write(dir.path(), over.as_bytes(), 0o600)?;
        match load(&path) {
            Err(err @ SecretsError::TooLarge { .. }) => assert_no_secret(&err),
            other => return Err(format!("gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn any_group_or_other_permission_bit_is_refused() -> R {
        let dir = tempfile::tempdir()?;
        for mode in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o666] {
            let path = write(dir.path(), good().as_bytes(), mode)?;
            match load(&path) {
                Err(err @ SecretsError::Mode { mode: got, .. }) => {
                    assert_eq!(got, mode);
                    assert_no_secret(&err);
                }
                other => return Err(format!("{mode:o} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn a_file_owned_by_another_user_is_refused() -> R {
        let dir = tempfile::tempdir()?;
        let path = write(dir.path(), good().as_bytes(), 0o600)?;
        let other = euid().wrapping_add(1);
        match load_owned_by(&path, other) {
            Err(
                err @ SecretsError::Owner {
                    owner, expected, ..
                },
            ) => {
                assert_eq!((owner, expected), (euid(), other));
                assert_no_secret(&err);
            }
            other => return Err(format!("gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn unknown_tables_and_keys_are_refused() -> R {
        let dir = tempfile::tempdir()?;
        for text in [
            format!("[acme]\ntoken = \"{VALUE}\"\n"),
            format!("[dns]\ndns_provider = \"{VALUE}\"\n"),
            format!("dns_provider = \"{VALUE}\"\n"),
            format!("[acme]\ndns_provider = \"{VALUE}\"\nother = \"{VALUE}\"\n"),
        ] {
            let path = write(dir.path(), text.as_bytes(), 0o600)?;
            match load(&path) {
                Err(err @ SecretsError::Parse { .. }) => assert_no_secret(&err),
                other => return Err(format!("{text:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn a_parse_error_names_the_place_but_never_quotes_the_file() -> R {
        let dir = tempfile::tempdir()?;
        let cases = [
            // Unterminated string: the parser would quote the line.
            (format!("[acme]\ndns_provider = \"{VALUE}\n"), 2),
            // A value of the wrong type: the parser would quote the value.
            ("\n\n[acme]\ndns_provider = 123456789\n".to_owned(), 4),
            // An unknown key on line 3.
            (format!("[acme]\ndns_provider = \"x\"\n{VALUE} = 1\n"), 3),
        ];
        for (text, line) in cases {
            let path = write(dir.path(), text.as_bytes(), 0o600)?;
            match load(&path) {
                Err(
                    err @ SecretsError::Parse {
                        line: got, column, ..
                    },
                ) => {
                    assert_eq!(got, line, "{text:?}: {err}");
                    assert!(column >= 1, "{err}");
                    assert_no_secret(&err);
                    assert!(!err.to_string().contains("123456789"), "{err}");
                }
                other => return Err(format!("{text:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn a_file_that_is_not_utf8_is_refused() -> R {
        let dir = tempfile::tempdir()?;
        let path = write(dir.path(), b"[acme]\ndns_provider = \"\xff\"\n", 0o600)?;
        match load(&path) {
            Err(err @ SecretsError::NotUtf8 { .. }) => assert_no_secret(&err),
            other => return Err(format!("gave {other:?}").into()),
        }
        Ok(())
    }
}
