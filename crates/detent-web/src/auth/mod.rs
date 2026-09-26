//! Who the caller is, and what it took to prove it (PLAN §2.7, "Auth").
//!
//! ```text
//!   POST /auth/login ─▶ ratelimit ─▶ UserStore ─▶ password::Hasher (Argon2id)
//!                          │             │              │
//!                          │             └─ totp (RFC 6238, replay-guarded)
//!                          │                          │
//!                          └── audit ◀────────────────┘
//!                                        │
//!                          SessionStore ─┴─▶ __Host-detent_session cookie
//!
//!   Authorization: Bearer ─▶ TokenStore ─▶ Scopes         (no cookie, no CSRF)
//! ```
//!
//! # Guarantees
//!
//! * **Nothing here renders a secret.** Passwords, PHC hashes, session ids,
//!   CSRF tokens, API tokens and TOTP secrets all live behind
//!   [`Secret`](secret::Secret) or a hand-written `Debug`, and every module in
//!   this tree has a test that says so.
//! * **A failed login tells the caller one thing.** Unknown user, wrong
//!   password, missing TOTP code and replayed TOTP code all produce
//!   [`AuthError::InvalidCredentials`] — one status, one message id, and (via
//!   [`password::Hasher::verify_dummy`]) one cost. The audit log records
//!   which it actually was; the client is told nothing.
//! * **Restart is logout.** Sessions live in memory only; users, tokens and
//!   TOTP enrolments persist `0600` under the state root.
//! * **Every auth event is audited**, success and failure alike — see
//!   [`audit`].

pub mod audit;
pub mod base32;
pub mod extract;
pub mod password;
pub mod ratelimit;
pub mod routes;
pub mod secret;
pub mod session;
pub mod token;
pub mod totp;
pub mod users;

use std::path::PathBuf;

use detent_core::diag::MessageId;
use detent_platform::fs::atomic::AtomicError;

pub use audit::{AuthAudit, AuthEvent, AuthRecord, CaptureAuthAudit, FileAuthAudit};
pub use extract::{Caller, ClientIp, WriteCaller};
pub use password::Hasher;
pub use ratelimit::{Principal, RateLimiter};
pub use routes::{LoginRequest, Route};
pub use secret::Secret;
pub use session::{COOKIE_NAME, Session, SessionStore, SessionView, set_cookie_value};
pub use token::{TokenIdentity, TokenRecord, TokenStore, TokenView};
pub use totp::{OtpAuthUri, TotpSecret};
pub use users::{UserStore, UserView, VerifiedUser};

/// Directory under the state root that holds `users.json` and `tokens.json`
/// (PLAN §2.10).
pub const STATE_SUBDIR: &str = "state";

/// Mode of every credential file this module writes.
pub const CREDENTIAL_FILE_MODE: u32 = 0o600;

/// Mode of the directory those files live in.
pub const STATE_DIR_MODE: u32 = 0o700;

/// Permission bits that must be clear on the state directory.
const GROUP_AND_OTHER: u32 = 0o077;

/// Everything that can go wrong while authenticating somebody, or while
/// keeping the records authentication depends on.
///
/// The variants are deliberately lumpy at the credential end:
/// [`InvalidCredentials`](Self::InvalidCredentials) is the *only* answer a
/// failed login produces, so no caller can tell an unknown user from a wrong
/// password, a missing TOTP code from a replayed one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The system refused to produce random bytes, so no session id, CSRF
    /// token, API token or salt could be made.
    #[error("the system random number generator failed: {0}")]
    Entropy(#[from] getrandom::Error),
    /// Argon2 refused the configured cost parameters.
    #[error("the argon2 parameters are not usable: {0}")]
    Params(#[source] argon2::Error),
    /// Hashing or parsing a PHC string failed. Never carries the password.
    #[error("a password hash could not be computed or parsed")]
    Hash,
    /// A user name is not `[a-z0-9._-]{1,32}` starting with an alphanumeric.
    #[error("`{name}` is not a usable user name")]
    NameInvalid {
        /// The rejected name, already known to be printable ASCII because the
        /// check that rejected it is a character allow-list.
        name: String,
    },
    /// A user by that name is already on file.
    #[error("that user already exists")]
    UserExists,
    /// No user by that name is on file. Only ever returned to an
    /// already-authenticated administrator, never to a login attempt.
    #[error("no such user")]
    UnknownUser,
    /// The credentials presented did not authenticate anybody. The single
    /// answer to every failed login.
    #[error("the credentials were refused")]
    InvalidCredentials,
    /// Too many failures from this address or for this user.
    #[error("too many attempts; wait {retry_after_secs}s")]
    RateLimited {
        /// Seconds the caller should wait before trying again.
        retry_after_secs: u64,
    },
    /// The session table is full. Refusing is the point: an unbounded table
    /// is a memory-exhaustion primitive.
    #[error("no more sessions can be established right now")]
    SessionLimit,
    /// Every password-hashing slot is taken. The login is refused rather than
    /// queued, so a flood of logins cannot hold requests open (L-WEB12).
    #[error("too many logins are being checked right now")]
    Busy,
    /// The request carried no credential at all.
    #[error("authentication is required")]
    Unauthenticated,
    /// The request carried both a session cookie and a bearer token. Refused
    /// rather than resolved, so neither can silently upgrade the other.
    #[error("a session cookie and a bearer token were both presented")]
    AmbiguousCredentials,
    /// A state-changing request failed one of the three §2.7 CSRF checks.
    #[error("the request failed its cross-site checks")]
    CsrfRejected,
    /// No API token matches, or the one that matches has expired.
    #[error("that api token is not usable")]
    UnknownToken,
    /// The token store already holds as many tokens as it will.
    #[error("no more api tokens can be issued")]
    TokenLimit,
    /// A TOTP secret was not valid base32.
    #[error("that totp secret is not valid base32")]
    TotpSecretInvalid,
    /// A credential file could not be read.
    #[error("{path} could not be read: {source}")]
    StoreRead {
        /// The file that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The state directory could not be created or confined.
    #[error("{path} could not be prepared: {source}")]
    StorePrepare {
        /// The directory that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// A credential file could not be written.
    #[error("{path} could not be written: {source}")]
    StoreWrite {
        /// The file that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: AtomicError,
    },
    /// A credential file exists but is not what this build expects.
    #[error("{path} is not a valid detent credential file: {source}")]
    StoreMalformed {
        /// The file that was tried.
        path: PathBuf,
        /// The parser's own report.
        source: serde_json::Error,
    },
}

impl AuthError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Entropy(_) => MessageId::new("web-auth-entropy-unavailable"),
            Self::Params(_) => MessageId::new("web-auth-argon2-params"),
            Self::Hash => MessageId::new("web-auth-hash-failed"),
            Self::NameInvalid { .. } => MessageId::new("web-auth-user-name-invalid"),
            Self::UserExists => MessageId::new("web-auth-user-exists"),
            Self::UnknownUser => MessageId::new("web-auth-user-unknown"),
            Self::InvalidCredentials => MessageId::new("web-auth-invalid-credentials"),
            Self::RateLimited { .. } => MessageId::new("web-auth-rate-limited"),
            Self::SessionLimit => MessageId::new("web-auth-session-limit"),
            Self::Busy => MessageId::new("web-auth-busy"),
            Self::Unauthenticated => MessageId::new("web-auth-unauthenticated"),
            Self::AmbiguousCredentials => MessageId::new("web-auth-ambiguous-credentials"),
            Self::CsrfRejected => MessageId::new("web-auth-csrf-rejected"),
            Self::UnknownToken => MessageId::new("web-auth-token-unknown"),
            Self::TokenLimit => MessageId::new("web-auth-token-limit"),
            Self::TotpSecretInvalid => MessageId::new("web-auth-totp-secret-invalid"),
            Self::StoreRead { .. } => MessageId::new("web-auth-store-unreadable"),
            Self::StorePrepare { .. } => MessageId::new("web-auth-store-unwritable"),
            Self::StoreWrite { .. } => MessageId::new("web-auth-store-write-failed"),
            Self::StoreMalformed { .. } => MessageId::new("web-auth-store-malformed"),
        }
    }

    /// The HTTP status this failure answers with.
    ///
    /// The credential failures all answer 401 with the same body; the store
    /// failures answer 500 because they are the operator's problem, not the
    /// caller's.
    #[must_use]
    pub const fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode as S;
        match *self {
            Self::InvalidCredentials | Self::Unauthenticated => S::UNAUTHORIZED,
            Self::RateLimited { .. } => S::TOO_MANY_REQUESTS,
            Self::SessionLimit | Self::Busy => S::SERVICE_UNAVAILABLE,
            Self::CsrfRejected => S::FORBIDDEN,
            Self::UserExists | Self::TokenLimit => S::CONFLICT,
            Self::UnknownUser | Self::UnknownToken => S::NOT_FOUND,
            Self::NameInvalid { .. }
            | Self::AmbiguousCredentials
            | Self::TotpSecretInvalid
            | Self::StoreMalformed { .. } => S::BAD_REQUEST,
            Self::Entropy(_)
            | Self::Params(_)
            | Self::Hash
            | Self::StoreRead { .. }
            | Self::StorePrepare { .. }
            | Self::StoreWrite { .. } => S::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Create `dir` if it is absent and make sure it grants nothing to group or
/// other, exactly as `tls::confine_cert_dir` does for the certificate store.
///
/// A directory that already existed is the interesting case: `tmpfiles.d`
/// creates `/var/lib/detent/state` `0700` in a packaged install, but a
/// hand-made one inherits the umask, and a `0755` directory around a `0600`
/// `users.json` still lets any local account watch the file change.
///
/// # Errors
///
/// [`AuthError::StorePrepare`] when the directory cannot be created, its
/// metadata read, or its mode narrowed.
pub fn confine_state_dir(dir: &std::path::Path) -> Result<(), AuthError> {
    use std::os::unix::fs::PermissionsExt as _;

    let prepare = |source| AuthError::StorePrepare {
        path: dir.to_path_buf(),
        source,
    };
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(prepare)?;
    }
    let mode = std::fs::metadata(dir)
        .map_err(prepare)?
        .permissions()
        .mode();
    if mode & GROUP_AND_OTHER != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(STATE_DIR_MODE))
            .map_err(prepare)?;
    }
    Ok(())
}

/// Write one credential file `0600`, atomically and without backups.
///
/// Rotated copies of a credential file are exactly what nobody wants on disk,
/// so `keep_backups` is zero — the same choice `tls::write_key_file` makes for
/// the private key.
///
/// # Errors
///
/// [`AuthError::StoreWrite`] when the write fails,
/// [`AuthError::StorePrepare`] when the mode cannot be asserted afterwards.
pub fn write_credential_file(path: &std::path::Path, contents: &[u8]) -> Result<(), AuthError> {
    use detent_platform::fs::atomic::{WriteRequest, write_atomic};
    use std::os::unix::fs::PermissionsExt as _;

    let parent = path.parent().unwrap_or(path);
    let mut request = WriteRequest::new(path, contents, parent);
    request.keep_backups = 0;
    request.create_mode = CREDENTIAL_FILE_MODE;
    let _outcome = write_atomic(&request).map_err(|source| AuthError::StoreWrite {
        path: path.to_path_buf(),
        source,
    })?;
    // `write_atomic` preserves the mode of a file that already existed, so a
    // file created too permissively once would stay that way. Assert it.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(CREDENTIAL_FILE_MODE)).map_err(
        |source| AuthError::StorePrepare {
            path: path.to_path_buf(),
            source,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{AuthError, CREDENTIAL_FILE_MODE, confine_state_dir, write_credential_file};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../../locales/en-US/core.ftl");

    fn catalogue_has(id: &str) -> bool {
        CATALOGUE
            .lines()
            .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id))
    }

    /// One value of every variant, so `message_id` and `status` are both
    /// exercised for all of them and every id is checked against the
    /// catalogue.
    fn every_error() -> Vec<AuthError> {
        let mut errors = vec![
            AuthError::Entropy(getrandom::Error::UNSUPPORTED),
            AuthError::Params(argon2::Error::MemoryTooLittle),
            AuthError::Hash,
            AuthError::NameInvalid {
                name: "Bad Name".to_owned(),
            },
            AuthError::UserExists,
            AuthError::UnknownUser,
            AuthError::InvalidCredentials,
            AuthError::RateLimited {
                retry_after_secs: 4,
            },
            AuthError::SessionLimit,
            AuthError::Busy,
            AuthError::Unauthenticated,
            AuthError::AmbiguousCredentials,
            AuthError::CsrfRejected,
            AuthError::UnknownToken,
            AuthError::TokenLimit,
            AuthError::TotpSecretInvalid,
            AuthError::StoreRead {
                path: PathBuf::from("/var/lib/detent/state/users.json"),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
            AuthError::StorePrepare {
                path: PathBuf::from("/var/lib/detent/state"),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
        ];
        // `serde_json::Error` has no public constructor, so the malformed
        // variant is reached through a real malformed document.
        if let Err(source) = serde_json::from_str::<serde_json::Value>("{") {
            errors.push(AuthError::StoreMalformed {
                path: PathBuf::from("/var/lib/detent/state/users.json"),
                source,
            });
        }
        errors
    }

    #[test]
    fn every_variant_has_a_catalogued_message_id_and_a_status() {
        for error in every_error() {
            let id = error.message_id();
            assert!(
                catalogue_has(id.as_str()),
                "`{id:?}` is missing from core.ftl"
            );
            assert!(!error.to_string().is_empty(), "{error:?} renders empty");
            assert!(error.status().is_client_error() || error.status().is_server_error());
        }
    }

    #[test]
    fn a_new_state_directory_is_confined_and_an_open_one_is_narrowed() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        confine_state_dir(&dir)?;
        assert_eq!(std::fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        confine_state_dir(&dir)?;
        assert_eq!(std::fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn a_credential_file_is_written_0600_and_rewritten_in_place() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        confine_state_dir(&dir)?;
        let path = dir.join("users.json");

        write_credential_file(&path, b"first")?;
        assert_eq!(std::fs::read(&path)?, b"first");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            CREDENTIAL_FILE_MODE
        );

        // A file left too permissive by something else is tightened, and no
        // rotated copy of the previous contents is left behind.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        write_credential_file(&path, b"second")?;
        assert_eq!(std::fs::read(&path)?, b"second");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            CREDENTIAL_FILE_MODE
        );
        let names: Vec<String> = std::fs::read_dir(&dir)?
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
            })
            .collect();
        assert_eq!(names, vec!["users.json".to_owned()], "{names:?}");
        Ok(())
    }

    #[test]
    fn an_unwritable_path_is_a_typed_failure() -> R {
        let root = tempfile::tempdir()?;
        // The parent does not exist, so the atomic writer cannot open it.
        let path = root.path().join("absent").join("users.json");
        match write_credential_file(&path, b"x") {
            Err(err @ AuthError::StoreWrite { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-auth-store-write-failed");
            }
            other => return Err(format!("expected a write failure, got {other:?}").into()),
        }
        assert!(catalogue_has("web-auth-store-write-failed"));
        Ok(())
    }

    #[test]
    fn a_state_directory_that_cannot_be_created_is_reported() -> R {
        let root = tempfile::tempdir()?;
        let file = root.path().join("not-a-directory");
        std::fs::write(&file, b"")?;
        match confine_state_dir(&file.join("state")) {
            Err(err @ AuthError::StorePrepare { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-auth-store-unwritable");
            }
            other => return Err(format!("expected a prepare failure, got {other:?}").into()),
        }
        assert!(Path::new(&file).is_file());
        Ok(())
    }
}
