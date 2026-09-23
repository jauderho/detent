//! The state every handler shares.
//!
//! ```text
//!   AppState (Clone, cheap) ─┬─ EngineHandle   → privileged operations
//!                            ├─ Arc<AuthState> → users, sessions, tokens,
//!                            │                   hasher, rate limiter, audit
//!                            ├─ Arc<Config>    → the parsed detent.toml
//!                            ├─ Arc<Origin>    → what CSRF compares against
//!                            └─ Arc<CertStore> → the live TLS cert (renew swaps it)
//! ```
//!
//! Phase 4c adds the `/api/v1` handlers on top of exactly this type, so it is
//! deliberately small and deliberately `Clone`: axum clones the state for
//! every request, and everything expensive inside it is behind an [`Arc`].
//!
//! # Guarantees
//! * **Cloning is four pointer bumps and a channel handle.** Nothing here
//!   copies a store, a hasher, or a configuration.
//! * **One store, one truth.** The user, session and token stores are shared
//!   rather than copied, so a token revoked by one request stops working for
//!   the request already in flight beside it.
//! * **The `Debug` prints no secret and no name**, because every component's
//!   own `Debug` is written that way.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::auth::AuthError;
use crate::auth::audit::{AuthAudit, AuthRecord, FileAuthAudit, emit};
use crate::auth::password::Hasher;
use crate::auth::ratelimit::RateLimiter;
use crate::auth::session::SessionStore;
use crate::auth::token::TokenStore;
use crate::auth::users::UserStore;
use crate::config::{AuthConfig, Config};
use crate::csrf::Origin;
use crate::engine::EngineHandle;
use crate::tls::CertStore;

/// Everything authentication needs, assembled once at startup.
#[derive(Debug)]
pub struct AuthState {
    /// Accounts and password hashes.
    pub users: UserStore,
    /// Live sessions. In memory: restart is logout.
    pub sessions: std::sync::Arc<SessionStore>,
    /// API tokens.
    pub tokens: TokenStore,
    /// Argon2id at the configured cost, with its dummy hash.
    pub hasher: Hasher,
    /// Login throttling, per address and per user.
    pub limiter: RateLimiter,
    /// Where auth events go.
    pub audit: Box<dyn AuthAudit>,
    /// Whether a second factor is required of every account
    /// (`auth.totp_required`).
    pub totp_required: bool,
}

impl AuthState {
    /// Open every store under `state_root` and build the hasher for a host
    /// with `ram_mib` of RAM.
    ///
    /// # Errors
    ///
    /// Whatever the stores and the hasher report: a state directory that
    /// cannot be confined, a credential file that cannot be read or parsed,
    /// or Argon2 parameters it will not accept.
    pub fn open(state_root: &Path, auth: &AuthConfig, ram_mib: u64) -> Result<Self, AuthError> {
        let users = UserStore::load(state_root)?;
        let sessions = std::sync::Arc::new(SessionStore::from_config(auth));
        users.attach_sessions(std::sync::Arc::clone(&sessions));
        Ok(Self {
            users,
            sessions,
            tokens: TokenStore::load(state_root)?,
            hasher: Hasher::new(auth.argon2, ram_mib)?,
            limiter: RateLimiter::new(auth.max_failures),
            audit: Box::new(FileAuthAudit::under_state_root(state_root)),
            totp_required: auth.totp_required,
        })
    }

    /// The same, with a caller-supplied audit sink.
    ///
    /// # Errors
    ///
    /// As [`AuthState::open`].
    pub fn open_with_audit(
        state_root: &Path,
        auth: &AuthConfig,
        ram_mib: u64,
        audit: Box<dyn AuthAudit>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            audit,
            ..Self::open(state_root, auth, ram_mib)?
        })
    }

    /// Write one auth event to `tracing` and to the sink.
    pub fn record(&self, record: &AuthRecord) {
        emit(self.audit.as_ref(), record);
    }
}

/// The application state every handler receives.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The bridge to the operations engine.
    pub engine: EngineHandle,
    /// Users, sessions, tokens, hashing, throttling, auditing.
    pub auth: Arc<AuthState>,
    /// The parsed configuration.
    pub config: Arc<Config>,
    /// The origin `Origin:` headers are compared against.
    pub origin: Arc<Origin>,
    /// The resolver the listener answers from; `CertStore::replace` swaps it live.
    pub cert_store: Arc<CertStore>,
    /// Root of `detent`'s mutable state (PLAN §2.10), so the update-status
    /// endpoint can read the interval-guarded stamp written by `detent
    /// update --check` without reaching the network on the request path
    /// (PLAN §2.9 steps 5a and 6).
    pub state_root: Arc<PathBuf>,
}

impl AppState {
    /// Assemble the state.
    #[must_use]
    pub fn new(
        engine: EngineHandle,
        auth: AuthState,
        config: Config,
        origin: Origin,
        cert_store: Arc<CertStore>,
        state_root: PathBuf,
    ) -> Self {
        Self {
            engine,
            auth: Arc::new(auth),
            config: Arc::new(config),
            origin: Arc::new(origin),
            cert_store,
            state_root: Arc::new(state_root),
        }
    }

    /// The interval-guarded update stamp (PLAN §2.9 step 6): the on-disk
    /// `CachedReport` the read-only `GET /api/v1/system/update` prefers over
    /// reaching the release feed on every request.
    #[must_use]
    pub fn update_stamp(&self) -> std::path::PathBuf {
        detent_update::update::stamp_path(&self.state_root)
    }

    /// The bad-release list (PLAN §2.9 step 5c): tags that failed health and
    /// were rolled back, so the next check skips them.
    #[must_use]
    pub fn bad_stamp(&self) -> std::path::PathBuf {
        detent_update::update::bad_path(&self.state_root)
    }
}

/// A whole test fixture: the state, the capture sink behind its audit, and
/// the temporary directory its stores live in.
///
/// The directory is a field rather than a detail because dropping it removes
/// the stores, so it has to outlive the state.
#[cfg(test)]
pub(crate) struct TestState {
    /// The state under test.
    pub state: AppState,
    /// What its audit sink captured.
    pub audit: Arc<crate::auth::audit::CaptureAuthAudit>,
    /// The state root, removed when this is dropped.
    dir: tempfile::TempDir,
}

#[cfg(test)]
impl TestState {
    /// The directory the stores live in, so a test can open a second state
    /// over the same accounts.
    pub(crate) fn state_root(&self) -> &Path {
        self.dir.path()
    }
}

/// A state whose engine thread does not exist, for tests of the layers above
/// it: the stores are real, on a temporary directory, and the audit sink
/// captures instead of writing.
#[cfg(test)]
pub(crate) fn test_state() -> Result<TestState, Box<dyn std::error::Error>> {
    use crate::config::{Argon2Params, TlsConfig};

    let dir = tempfile::tempdir()?;
    let audit = Arc::new(crate::auth::audit::CaptureAuthAudit::new());
    let auth_config = AuthConfig {
        // The cheapest parameters Argon2 accepts: these tests are about the
        // logic around the hash, not about its cost.
        argon2: Argon2Params {
            m_kib: Some(8),
            t: 1,
            p: 1,
        },
        ..AuthConfig::default()
    };
    let config = Config {
        auth: auth_config.clone(),
        tls: TlsConfig {
            hostnames: vec!["box.example".to_owned()],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let state = AppState::new(
        EngineHandle::detached(),
        AuthState::open_with_audit(
            dir.path(),
            &auth_config,
            4096,
            Box::new(SharedCapture(Arc::clone(&audit))),
        )?,
        config.clone(),
        Origin::for_config(&config),
        // ponytail: throwaway bootstrap cert; tests never handshake through it.
        test_cert_store()?,
        dir.path().to_path_buf(),
    );
    Ok(TestState { state, audit, dir })
}

/// A throwaway [`CertStore`] for tests that need an `AppState` but never
/// handshake through it.
#[cfg(test)]
pub(crate) fn test_cert_store() -> Result<Arc<CertStore>, Box<dyn std::error::Error>> {
    let pair = crate::tls::bootstrap_self_signed(&["box.example".to_owned()])?;
    Ok(Arc::new(CertStore::new(&pair)?))
}

/// A capture sink shared between the state and the test that inspects it.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct SharedCapture(pub Arc<crate::auth::audit::CaptureAuthAudit>);

#[cfg(test)]
impl AuthAudit for SharedCapture {
    fn record(&self, record: &AuthRecord) {
        self.0.record(record);
    }

    fn query(&self, limit: Option<usize>) -> Vec<AuthRecord> {
        self.0.query(limit)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, AuthState, test_cert_store, test_state};
    use crate::auth::audit::{AuthEvent, AuthRecord};
    use crate::authz::Scopes;
    use crate::config::{AuthConfig, Config};
    use crate::csrf::Origin;
    use crate::engine::EngineHandle;
    use detent_ops::audit::AuditResult;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_state_is_cheap_to_clone_and_shares_its_stores() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let copy = state.clone();

        let (id, _session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        // The clone sees the session the original made: one store, not two.
        assert!(
            copy.auth
                .sessions
                .lookup(id.expose(), std::time::Instant::now())
                .is_some()
        );
        assert_eq!(copy.origin.as_str(), "https://box.example:3333");
        assert_eq!(copy.config.auth.max_failures, 5);
        Ok(())
    }

    #[test]
    fn the_debug_output_carries_no_secret_and_no_name() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let rendered = format!("{state:?}");
        assert!(!rendered.contains(id.expose()), "{rendered}");
        assert!(
            !rendered.contains(session.csrf_token.expose()),
            "{rendered}"
        );
        assert!(!rendered.contains("alice"), "{rendered}");
        assert!(rendered.contains("AppState"), "{rendered}");
        Ok(())
    }

    #[test]
    fn events_reach_the_sink_the_state_was_built_with() -> R {
        let fixture = test_state()?;
        fixture.state.auth.record(&AuthRecord::new(
            AuthEvent::LoginSucceeded,
            "alice",
            AuditResult::Ok,
        ));
        assert_eq!(fixture.audit.events(), vec![AuthEvent::LoginSucceeded]);
        Ok(())
    }

    #[test]
    fn the_default_state_writes_its_audit_to_a_file_under_the_state_root() -> R {
        let dir = tempfile::tempdir()?;
        let auth = AuthConfig {
            argon2: crate::config::Argon2Params {
                m_kib: Some(8),
                t: 1,
                p: 1,
            },
            ..AuthConfig::default()
        };
        let state = AuthState::open(dir.path(), &auth, 4096)?;
        state.record(&AuthRecord::new(
            AuthEvent::LoginFailed,
            "alice",
            AuditResult::Error,
        ));
        let log = dir.path().join("audit").join("detent-auth.jsonl");
        assert!(std::fs::read_to_string(&log)?.contains("login_failed"));
        assert!(!state.totp_required);
        assert!(state.users.is_empty());
        // And it plugs into an `AppState` unchanged.
        let config = Config::default();
        let app = AppState::new(
            EngineHandle::detached(),
            state,
            config.clone(),
            Origin::for_config(&config),
            test_cert_store()?,
            dir.path().to_path_buf(),
        );
        assert!(app.auth.tokens.list().is_empty());
        Ok(())
    }

    #[test]
    fn a_state_root_that_cannot_be_confined_is_reported() -> R {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, b"")?;
        assert!(AuthState::open(&file, &AuthConfig::default(), 4096).is_err());
        // And the shorthand still works on a good root.
        assert!(test_state().is_ok());
        Ok(())
    }
}
