//! Sessions: in memory, so a restart is a logout (PLAN §2.7, "Sessions").
//!
//! ```text
//!   login ──▶ Secret (32 B) ──┬─ sha256 ──▶ HashMap key
//!                             └─ stored ──▶ ct_eq against what the browser sent
//!
//!   every lookup: idle 15 min?  absolute 8 h?  ──▶ remove, not merely refuse
//!   privilege change / login:   rotate id and CSRF token, old id dies at once
//! ```
//!
//! # Guarantees
//!
//! * **Nothing is persisted.** There is no file, so a restart invalidates
//!   every session, which is what PLAN §2.7 asks for.
//! * **The map is not keyed on the secret.** The key is the SHA-256 of the
//!   session id; the id itself is then compared with
//!   [`Secret::ct_eq`]. A `HashMap` lookup is not constant time, and hashing
//!   first means the timing an attacker can observe is over a digest they
//!   cannot steer.
//! * **An expired session is removed, not refused.** Both timeouts are checked
//!   on every lookup, and a periodic [`sweep`](SessionStore::sweep) collects
//!   the ones nobody comes back for.
//! * **Rotation is immediate.** [`SessionStore::rotate`] removes the old id
//!   before it returns the new one, so a stolen pre-login id is worthless.
//! * **The table is capped.** [`MAX_SESSIONS`] live sessions is the limit;
//!   past it, logins are refused (and audited) rather than allowed to grow the
//!   map without bound.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::authz::Scopes;

use super::AuthError;
use super::ratelimit::RateLimiter;
use super::secret::Secret;
use super::token::TokenStore;

/// Cookie the session id travels in.
///
/// The `__Host-` prefix is not decoration: a conforming browser refuses the
/// cookie unless it is `Secure`, has `Path=/`, and carries **no** `Domain`,
/// which together stop a sibling host on the same registrable domain from
/// planting or reading it.
pub const COOKIE_NAME: &str = "__Host-detent_session";

/// Live sessions allowed at once.
pub const MAX_SESSIONS: usize = 256;

/// How often the background sweeper runs.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// One authenticated browser session.
#[derive(Clone)]
pub struct Session {
    /// The user this session belongs to.
    pub subject: String,
    /// What it may do.
    pub scopes: Scopes,
    /// The per-session CSRF token, delivered by `/api/v1/auth/session`.
    pub csrf_token: Secret,
    /// When it was established.
    pub created: Instant,
    /// When it was last used.
    pub last_seen: Instant,
    /// Whether a second factor was presented.
    pub totp_satisfied: bool,
}

impl fmt::Debug for Session {
    /// The CSRF token is a credential; it never renders.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .field("totp_satisfied", &self.totp_satisfied)
            .finish_non_exhaustive()
    }
}

/// What `GET /api/v1/auth/session` answers.
///
/// The session **id** is deliberately absent: the browser already holds it in
/// a `HttpOnly` cookie, and a copy of it in a readable response body would
/// undo that.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct SessionView {
    /// The user this session belongs to.
    pub subject: String,
    /// Scope names, `["read"]` or `["read", "write"]`.
    pub scopes: Vec<&'static str>,
    /// The token to echo in `X-Detent-CSRF`.
    pub csrf_token: String,
    /// Seconds until the session expires, idle and absolute limits combined.
    pub expires_in_secs: u64,
    /// Whether a second factor was presented.
    pub totp_satisfied: bool,
}

impl fmt::Debug for SessionView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionView")
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .field("expires_in_secs", &self.expires_in_secs)
            .field("totp_satisfied", &self.totp_satisfied)
            .finish_non_exhaustive()
    }
}

/// The `Set-Cookie` value that establishes a session.
///
/// `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and no `Domain` — the
/// three the `__Host-` prefix requires plus the two that keep script and
/// cross-site navigation away from it.
#[must_use]
pub fn set_cookie_value(id: &Secret) -> String {
    format!(
        "{COOKIE_NAME}={}; Secure; HttpOnly; SameSite=Strict; Path=/",
        id.expose()
    )
}

/// The `Set-Cookie` value that removes it.
#[must_use]
pub fn clear_cookie_value() -> String {
    format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// The session id out of a `Cookie` header, if it carries one.
///
/// Hand-parsed rather than pulled from a cookie crate: one name, one value,
/// and the parsing rules for the rest of RFC 6265 are attack surface this
/// crate does not need.
#[must_use]
pub fn cookie_value(header: &str) -> Option<Secret> {
    header.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE_NAME).then(|| Secret::from_presented(value.trim()))
    })
}

/// One stored session: the id it is reached by, and the session itself.
struct Entry {
    /// The id, kept so a presented one can be compared in constant time.
    id: Secret,
    /// The session.
    session: Session,
}

/// The in-memory session table.
pub struct SessionStore {
    /// Keyed by SHA-256 of the id.
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    /// Inactivity limit (`auth.idle_timeout_secs`).
    idle: Duration,
    /// Lifetime limit (`auth.absolute_timeout_secs`).
    absolute: Duration,
    /// Live sessions allowed at once.
    capacity: usize,
}

impl fmt::Debug for SessionStore {
    /// Counts and limits; never a subject, never an id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStore")
            .field("live", &self.len())
            .field("capacity", &self.capacity)
            .field("idle", &self.idle)
            .field("absolute", &self.absolute)
            .finish_non_exhaustive()
    }
}

/// The SHA-256 of a presented id, which is what the map is keyed on.
fn key_of(presented: &str) -> [u8; 32] {
    Sha256::digest(presented.as_bytes()).into()
}

impl SessionStore {
    /// A store with the configured timeouts and [`MAX_SESSIONS`] capacity.
    #[must_use]
    pub fn new(idle: Duration, absolute: Duration) -> Self {
        Self::with_capacity(idle, absolute, MAX_SESSIONS)
    }

    /// A store with an explicit capacity, so a test can fill it.
    #[must_use]
    pub fn with_capacity(idle: Duration, absolute: Duration, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            idle,
            absolute,
            capacity: capacity.max(1),
        }
    }

    /// A store configured from `[auth]`.
    #[must_use]
    pub fn from_config(auth: &crate::config::AuthConfig) -> Self {
        Self::new(
            Duration::from_secs(auth.idle_timeout_secs),
            Duration::from_secs(auth.absolute_timeout_secs),
        )
    }

    /// Live sessions right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }

    /// Whether no session is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Establish a session and return the id the cookie carries.
    ///
    /// # Errors
    ///
    /// [`AuthError::SessionLimit`] when the table is full — an attacker who
    /// can log in must not be able to grow it without bound.
    /// [`AuthError::Entropy`] when the id or the CSRF token cannot be
    /// generated.
    pub fn create(
        &self,
        subject: &str,
        scopes: Scopes,
        totp_satisfied: bool,
        now: Instant,
    ) -> Result<(Secret, Session), AuthError> {
        let id = Secret::random()?;
        let session = Session {
            subject: subject.to_owned(),
            scopes,
            csrf_token: Secret::random()?,
            created: now,
            last_seen: now,
            totp_satisfied,
        };
        let mut entries = self
            .entries
            .lock()
            .map_err(|_poisoned| AuthError::SessionLimit)?;
        Self::evict_expired(&mut entries, self.idle, self.absolute, now);
        if entries.len() >= self.capacity {
            return Err(AuthError::SessionLimit);
        }
        entries.insert(
            key_of(id.expose()),
            Entry {
                id: Secret::from_presented(id.expose()),
                session: session.clone(),
            },
        );
        Ok((id, session))
    }

    /// The session `presented` names, if it is live; expired ones are removed
    /// on the way past.
    ///
    /// Touching the session updates `last_seen`, which is what makes the idle
    /// timeout an *idle* timeout.
    #[must_use]
    pub fn lookup(&self, presented: &str, now: Instant) -> Option<Session> {
        let mut entries = self.entries.lock().ok()?;
        let key = key_of(presented);
        let entry = entries.get_mut(&key)?;
        // The map found something under this digest; make sure it is really
        // the same id, in constant time.
        if !entry.id.ct_eq(presented) {
            return None;
        }
        if expired(&entry.session, self.idle, self.absolute, now) {
            entries.remove(&key);
            return None;
        }
        entry.session.last_seen = now;
        Some(entry.session.clone())
    }

    /// Replace the id and the CSRF token of a live session, optionally
    /// changing what it may do.
    ///
    /// Called on login and on any privilege change. The old id stops working
    /// before this returns.
    ///
    /// # Errors
    ///
    /// [`AuthError::Entropy`] when the new id cannot be generated.
    pub fn rotate(
        &self,
        presented: &str,
        scopes: Option<Scopes>,
        totp_satisfied: Option<bool>,
        now: Instant,
    ) -> Result<Option<(Secret, Session)>, AuthError> {
        let fresh = Secret::random()?;
        let csrf = Secret::random()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_poisoned| AuthError::SessionLimit)?;
        let key = key_of(presented);
        let Some(entry) = entries.get(&key) else {
            return Ok(None);
        };
        if !entry.id.ct_eq(presented) || expired(&entry.session, self.idle, self.absolute, now) {
            entries.remove(&key);
            return Ok(None);
        }
        let Some(old) = entries.remove(&key) else {
            return Ok(None);
        };
        let session = Session {
            subject: old.session.subject,
            scopes: scopes.unwrap_or(old.session.scopes),
            csrf_token: csrf,
            created: old.session.created,
            last_seen: now,
            totp_satisfied: totp_satisfied.unwrap_or(old.session.totp_satisfied),
        };
        entries.insert(
            key_of(fresh.expose()),
            Entry {
                id: Secret::from_presented(fresh.expose()),
                session: session.clone(),
            },
        );
        Ok(Some((fresh, session)))
    }

    /// Invalidate every session belonging to `subject`.
    pub fn revoke_subject(&self, subject: &str) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, e| e.session.subject != subject);
    }
    /// Invalidate a session. Answers whether one was actually removed.
    pub fn logout(&self, presented: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let key = key_of(presented);
        match entries.get(&key) {
            Some(entry) if entry.id.ct_eq(presented) => entries.remove(&key).is_some(),
            _ => false,
        }
    }

    /// Drop every expired session. Answers how many went.
    pub fn sweep(&self, now: Instant) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let before = entries.len();
        Self::evict_expired(&mut entries, self.idle, self.absolute, now);
        before.saturating_sub(entries.len())
    }

    /// How long `session` has left, idle and absolute limits combined.
    #[must_use]
    pub fn expires_in(&self, session: &Session, now: Instant) -> Duration {
        let idle_left = self
            .idle
            .saturating_sub(now.saturating_duration_since(session.last_seen));
        let absolute_left = self
            .absolute
            .saturating_sub(now.saturating_duration_since(session.created));
        idle_left.min(absolute_left)
    }

    /// The response body for `/api/v1/auth/session`.
    #[must_use]
    pub fn view(&self, session: &Session, now: Instant) -> SessionView {
        SessionView {
            subject: session.subject.clone(),
            scopes: session.scopes.names(),
            csrf_token: session.csrf_token.expose().to_owned(),
            expires_in_secs: self.expires_in(session, now).as_secs(),
            totp_satisfied: session.totp_satisfied,
        }
    }

    /// Remove every expired entry from `entries`.
    fn evict_expired(
        entries: &mut HashMap<[u8; 32], Entry>,
        idle: Duration,
        absolute: Duration,
        now: Instant,
    ) {
        entries.retain(|_key, entry| !expired(&entry.session, idle, absolute, now));
    }
}

/// Whether `session` has passed either limit.
fn expired(session: &Session, idle: Duration, absolute: Duration, now: Instant) -> bool {
    now.saturating_duration_since(session.last_seen) >= idle
        || now.saturating_duration_since(session.created) >= absolute
}

/// Run periodic maintenance for sessions, expired API tokens and idle login
/// limiter buckets until all three stores are dropped.
///
/// Lazy eviction on lookup is enough for credential correctness; this is what
/// keeps memory of sessions and principals nobody returns to from accumulating.
pub fn spawn_sweeper(
    store: &Arc<SessionStore>,
    tokens: &Arc<TokenStore>,
    limiter: &Arc<RateLimiter>,
    period: Duration,
) -> tokio::task::JoinHandle<()> {
    let store_wk = Arc::downgrade(store);
    let tokens_wk = Arc::downgrade(tokens);
    let limiter_wk = Arc::downgrade(limiter);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // The first tick completes immediately; skip it so the task does not
        // sweep empty stores the moment it starts.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = now_from_tick();
            let sessions = store_wk.upgrade().map_or(0, |s| s.sweep(now));
            let token_count = tokens_wk
                .upgrade()
                .and_then(|t| {
                    t.sweep_expired(time::OffsetDateTime::now_utc().unix_timestamp())
                        .ok()
                })
                .unwrap_or(0);
            if let Some(l) = limiter_wk.upgrade() {
                l.sweep(now);
            }
            if sessions != 0 || token_count != 0 {
                tracing::debug!(sessions, tokens = token_count, "expired auth state swept");
            }
            if store_wk.strong_count() == 0
                && tokens_wk.strong_count() == 0
                && limiter_wk.strong_count() == 0
            {
                break;
            }
        }
    })
}

fn now_from_tick() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

#[cfg(test)]
mod tests {
    use super::{
        COOKIE_NAME, SessionStore, clear_cookie_value, cookie_value, set_cookie_value,
        spawn_sweeper,
    };
    use crate::auth::AuthError;
    use crate::auth::RateLimiter;
    use crate::auth::Secret;
    use crate::auth::token::TokenStore;
    use crate::authz::Scopes;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    type R = Result<(), Box<dyn std::error::Error>>;

    const IDLE: Duration = Duration::from_mins(15);
    const ABSOLUTE: Duration = Duration::from_secs(28800);

    fn store() -> SessionStore {
        SessionStore::new(IDLE, ABSOLUTE)
    }

    fn at(base: Instant, secs: u64) -> Instant {
        base.checked_add(Duration::from_secs(secs)).unwrap_or(base)
    }

    #[test]
    fn a_new_session_is_found_by_its_id_and_by_nothing_else() -> R {
        let store = store();
        let now = Instant::now();
        let (id, session) = store.create("alice", Scopes::read_write(), false, now)?;
        assert_eq!(id.expose().len(), 64);
        assert_eq!(session.subject, "alice");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        let found = store.lookup(id.expose(), now).ok_or("session not found")?;
        assert_eq!(found.subject, "alice");
        assert!(found.scopes.allows(crate::authz::Scope::Write));
        assert!(!found.totp_satisfied);

        assert!(store.lookup("", now).is_none());
        assert!(store.lookup(&"0".repeat(64), now).is_none());
        Ok(())
    }

    #[test]
    fn an_id_that_hashes_to_a_live_entry_still_has_to_match_it() -> R {
        // The map is keyed on the digest and the id is then compared; this
        // exercises the second check by planting a mismatched entry under a
        // known digest.
        let store = store();
        let now = Instant::now();
        let (id, _session) = store.create("alice", Scopes::read_write(), false, now)?;
        if let Ok(mut entries) = store.entries.lock() {
            for entry in entries.values_mut() {
                entry.id = Secret::from_presented("not the id that was issued");
            }
        }
        assert!(store.lookup(id.expose(), now).is_none());
        assert!(!store.logout(id.expose()));
        assert!(store.rotate(id.expose(), None, None, now)?.is_none());
        Ok(())
    }

    #[test]
    fn the_idle_timeout_removes_the_session_rather_than_refusing_it() -> R {
        let store = store();
        let start = Instant::now();
        let (id, _session) = store.create("alice", Scopes::read_only(), false, start)?;

        // Just inside the window, and the clock restarts.
        assert!(store.lookup(id.expose(), at(start, 899)).is_some());
        assert!(store.lookup(id.expose(), at(start, 1798)).is_some());

        // Then a gap longer than the idle limit.
        assert!(store.lookup(id.expose(), at(start, 2699)).is_none());
        assert_eq!(store.len(), 0, "the expired session was left in the map");
        Ok(())
    }

    #[test]
    fn the_absolute_timeout_ends_a_session_that_is_still_being_used() -> R {
        let store = store();
        let start = Instant::now();
        let (id, _session) = store.create("alice", Scopes::read_only(), false, start)?;
        // Touched every ten minutes, so the idle timer never fires.
        let mut when = start;
        for _ in 0_u32..47 {
            when = at(when, 600);
            assert!(store.lookup(id.expose(), when).is_some(), "at {when:?}");
        }
        // 48 × 10 min = 8 h.
        assert!(store.lookup(id.expose(), at(when, 600)).is_none());
        assert_eq!(store.len(), 0);
        Ok(())
    }

    #[test]
    fn rotation_replaces_the_id_and_the_csrf_token_at_once() -> R {
        let store = store();
        let now = Instant::now();
        let (first, before) = store.create("alice", Scopes::read_only(), false, now)?;
        let (second, after) = store
            .rotate(first.expose(), Some(Scopes::read_write()), Some(true), now)?
            .ok_or("nothing was rotated")?;

        assert_ne!(first.expose(), second.expose());
        assert!(!after.csrf_token.ct_eq(before.csrf_token.expose()));
        assert!(store.lookup(first.expose(), now).is_none());
        let found = store.lookup(second.expose(), now).ok_or("no session")?;
        assert_eq!(found.subject, "alice");
        assert!(found.scopes.allows(crate::authz::Scope::Write));
        assert!(found.totp_satisfied);
        // The absolute timer is not reset by rotation.
        assert_eq!(found.created, before.created);
        assert_eq!(store.len(), 1);

        // Rotating something that is not a session changes nothing.
        assert!(store.rotate("nope", None, None, now)?.is_none());
        Ok(())
    }

    #[test]
    fn rotation_keeps_the_scopes_when_it_is_not_asked_to_change_them() -> R {
        let store = store();
        let now = Instant::now();
        let (first, _session) = store.create("alice", Scopes::read_only(), true, now)?;
        let (second, rotated) = store
            .rotate(first.expose(), None, None, now)?
            .ok_or("nothing was rotated")?;
        assert!(!rotated.scopes.allows(crate::authz::Scope::Write));
        assert!(rotated.totp_satisfied);
        assert!(store.lookup(second.expose(), now).is_some());
        Ok(())
    }

    #[test]
    fn an_expired_session_cannot_be_rotated_and_is_dropped() -> R {
        let store = store();
        let start = Instant::now();
        let (id, _session) = store.create("alice", Scopes::read_only(), false, start)?;
        assert!(
            store
                .rotate(id.expose(), None, None, at(start, 901))?
                .is_none()
        );
        assert_eq!(store.len(), 0);
        Ok(())
    }

    #[test]
    fn logout_invalidates_immediately_and_only_once() -> R {
        let store = store();
        let now = Instant::now();
        let (id, _session) = store.create("alice", Scopes::read_write(), false, now)?;
        assert!(store.logout(id.expose()));
        assert!(!store.logout(id.expose()));
        assert!(store.lookup(id.expose(), now).is_none());
        assert!(store.is_empty());
        Ok(())
    }

    #[test]
    fn the_table_is_capped_and_expired_entries_make_room() -> R {
        let store = SessionStore::with_capacity(IDLE, ABSOLUTE, 2);
        let start = Instant::now();
        let (first, _s) = store.create("alice", Scopes::read_write(), false, start)?;
        let (_second, _s) = store.create("bob", Scopes::read_write(), false, start)?;
        match store.create("carol", Scopes::read_write(), false, start) {
            Err(err @ AuthError::SessionLimit) => {
                assert_eq!(err.message_id().as_str(), "web-auth-session-limit");
            }
            other => return Err(format!("expected the cap to bite, got {other:?}").into()),
        }
        assert!(store.lookup(first.expose(), start).is_some());

        // Once the two are stale, a new login is admitted again.
        let later = at(start, 901);
        let (_carol, _s) = store.create("carol", Scopes::read_write(), false, later)?;
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[test]
    fn a_sweep_drops_exactly_the_expired_sessions() -> R {
        let store = store();
        let start = Instant::now();
        let (old, _s) = store.create("alice", Scopes::read_write(), false, start)?;
        let later = at(start, 800);
        let (fresh, _s) = store.create("bob", Scopes::read_write(), false, later)?;

        assert_eq!(store.sweep(later), 0);
        assert_eq!(store.sweep(at(start, 901)), 1);
        assert_eq!(store.len(), 1);
        assert!(store.lookup(old.expose(), at(start, 901)).is_none());
        assert!(store.lookup(fresh.expose(), at(start, 901)).is_some());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_background_sweeper_runs_until_the_store_is_dropped() -> R {
        let store = Arc::new(SessionStore::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
        ));
        let (_id, _session) = store.create("alice", Scopes::read_write(), false, Instant::now())?;
        assert_eq!(store.len(), 1);

        let root = tempfile::tempdir()?;
        let tokens = Arc::new(TokenStore::load(root.path())?);
        let limiter = Arc::new(RateLimiter::new(5));
        let handle = spawn_sweeper(&store, &tokens, &limiter, Duration::from_millis(50));
        // Paused time: sleeping advances the clock past both the session's
        // idle limit and several sweep intervals.
        tokio::time::sleep(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.len(), 0, "the sweeper did not run");

        drop((store, tokens, limiter));
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The task notices the store is gone and ends.
        assert!(handle.await.is_ok());
        Ok(())
    }

    #[test]
    fn the_view_says_when_it_expires_and_never_carries_the_id() -> R {
        let store = store();
        let start = Instant::now();
        let (id, session) = store.create("alice", Scopes::read_only(), true, start)?;
        let view = store.view(&session, start);
        assert_eq!(view.subject, "alice");
        assert_eq!(view.scopes, vec!["read"]);
        assert!(view.totp_satisfied);
        assert_eq!(view.expires_in_secs, IDLE.as_secs());
        assert_eq!(view.csrf_token, session.csrf_token.expose());

        let json = serde_json::to_string(&view)?;
        assert!(!json.contains(id.expose()), "{json}");
        assert!(json.contains("csrf_token"), "{json}");

        // Late in a session that is still being used, the absolute limit is
        // the binding one.
        let late = at(start, 28500);
        let ongoing = super::Session {
            last_seen: late,
            ..session.clone()
        };
        let view = store.view(&ongoing, late);
        assert_eq!(
            view.expires_in_secs,
            ABSOLUTE.as_secs().saturating_sub(28500)
        );
        Ok(())
    }

    #[test]
    fn nothing_here_prints_a_secret() -> R {
        let store = store();
        let now = Instant::now();
        let (id, session) = store.create("alice", Scopes::read_write(), false, now)?;
        let view = store.view(&session, now);
        let rendered = format!("{store:?} {session:?} {view:?} {id:?}");
        assert!(!rendered.contains(id.expose()), "{rendered}");
        assert!(
            !rendered.contains(session.csrf_token.expose()),
            "{rendered}"
        );
        assert!(rendered.contains("live: 1"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
        Ok(())
    }

    #[test]
    fn the_cookie_carries_the_three_attributes_the_host_prefix_requires() -> R {
        let id = Secret::random()?;
        let value = set_cookie_value(&id);
        assert!(value.starts_with(&format!("{COOKIE_NAME}={}", id.expose())));
        // `__Host-` requires Secure and Path=/, and forbids Domain.
        assert!(value.contains("; Secure"), "{value}");
        assert!(value.contains("; Path=/"), "{value}");
        assert!(!value.contains("Domain"), "{value}");
        // And PLAN §2.7 adds these two.
        assert!(value.contains("; HttpOnly"), "{value}");
        assert!(value.contains("; SameSite=Strict"), "{value}");

        let cleared = clear_cookie_value();
        assert!(cleared.starts_with(&format!("{COOKIE_NAME}=;")));
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(cleared.contains("; Secure"), "{cleared}");
        assert!(!cleared.contains("Domain"), "{cleared}");
        Ok(())
    }

    #[test]
    fn a_cookie_header_is_parsed_only_for_this_name() -> R {
        let extracted = cookie_value(&format!("theme=dark; {COOKIE_NAME}=abc123; other=x"))
            .ok_or("the cookie was not found")?;
        assert!(extracted.ct_eq("abc123"));
        assert!(cookie_value(&format!("{COOKIE_NAME}=only")).is_some_and(|v| v.ct_eq("only")));
        // Whitespace around the pair is tolerated; a different name is not.
        assert!(
            cookie_value(&format!("  {COOKIE_NAME}  =  spaced  "))
                .is_some_and(|v| v.ct_eq("spaced"))
        );
        assert!(cookie_value("detent_session=abc").is_none());
        assert!(cookie_value("__Host-detent_session_x=abc").is_none());
        assert!(cookie_value("no-equals-sign").is_none());
        assert!(cookie_value("").is_none());
        Ok(())
    }
}
