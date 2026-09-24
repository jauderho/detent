//! Resolving a request to exactly one caller (PLAN §2.7, "Auth", "API tokens").
//!
//! ```text
//!   Cookie: __Host-detent_session ─┐
//!                                  ├─ both ────▶ 400 ambiguous-credentials
//!   Authorization: Bearer <token> ─┘
//!
//!   cookie only ──▶ SessionStore::lookup ──▶ Identity(Session, "alice")
//!   token only  ──▶ TokenStore::authenticate ─▶ Identity(Token, "token:<id>")
//!   neither / bad ─────────────────────────────▶ 401 unauthenticated
//!
//!   Caller ──▶ WriteCaller (the same, with `write` already checked)
//! ```
//!
//! # Guarantees
//!
//! * **One credential per request.** A cookie and a bearer token together are
//!   refused rather than resolved, so a token can never silently upgrade a
//!   session's authority and a cookie can never silently upgrade a token's.
//!   That is also what makes [`crate::csrf`]'s bearer exemption safe: a
//!   request that skipped the CSRF checks provably carried no cookie.
//! * **An invalid credential is indistinguishable from none.** An unknown
//!   session id, an unknown token and an expired token all answer
//!   [`AuthError::Unauthenticated`] — one status, one message id — so a caller
//!   cannot learn that a credential *used* to be valid.
//! * **Both session timeouts are honoured**, because the lookup goes through
//!   [`SessionStore::lookup`], which removes an idle or aged-out session
//!   instead of refusing it.
//! * **A missing scope is a type error, not a forgotten check.** A handler that
//!   takes [`WriteCaller`] cannot be reached without `write`; there is no
//!   `if caller.scopes()…` for a reviewer to miss.
//! * **Nothing here renders a credential.** The session id and the CSRF token
//!   live behind [`Secret`], whose `Debug` is `<redacted>`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use detent_core::diag::MessageId;
use detent_ops::identity::{Identity, IdentityKind};
use time::OffsetDateTime;

use crate::authz::{DENIED_SCOPE_ID, Scope, ScopedAuthz, Scopes};
use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::secret::Secret;
use super::session::{self, Session};

/// The authentication scheme `Authorization` must name, compared without
/// regard to case as RFC 9110 §11.1 requires.
pub const BEARER_SCHEME: &str = "bearer";

/// Prefix of the audit subject an API token authenticates as, so a token and a
/// user of the same name can never be confused in the log.
pub const TOKEN_SUBJECT_PREFIX: &str = "token:";

/// The address recorded when the connection's peer is not known — which is the
/// case whenever the router is driven without connection information, as every
/// `tower` test does.
pub const UNKNOWN_CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The current instant as Unix seconds, or zero if the clock is before the
/// epoch. Token expiry and TOTP both need wall-clock time, which [`Instant`]
/// deliberately does not provide.
#[must_use]
pub fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// The bearer token an `Authorization` header carries, if it carries a
/// non-empty one.
///
/// Hand-parsed for the same reason [`session::cookie_value`] is: one scheme,
/// one value, and the rest of RFC 9110's authentication grammar is attack
/// surface this crate does not need.
#[must_use]
pub fn bearer(headers: &HeaderMap) -> Option<Secret> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| Secret::from_presented(token))
}

/// The session id carried by all `Cookie` header field lines.
///
/// HTTP/2 may split one logical cookie field across repeated field lines.
/// Joining them with `; ` matches RFC 9110 field-line combination and lets
/// the existing RFC 6265 pair parser see every cookie exactly once.
#[must_use]
pub(crate) fn cookie_id(headers: &HeaderMap) -> Option<Secret> {
    let cookies = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    session::cookie_value(&cookies)
}

/// Who is making this request, and what they may do.
///
/// Obtained by taking it as a handler argument; a handler that does not take
/// one is unauthenticated by construction, which is what `/healthz` wants.
#[derive(Debug)]
pub struct Caller {
    /// Who, for [`detent_ops::authz::Authz`] and for the audit log.
    identity: Identity,
    /// What they hold.
    scopes: Scopes,
    /// The session, when a cookie is how they authenticated.
    session: Option<Session>,
    /// The id that session was reached by, kept so it can be invalidated.
    session_id: Option<Secret>,
}

impl Caller {
    /// Who this is, for the operations layer and the audit log.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// What this caller may do.
    #[must_use]
    pub const fn scopes(&self) -> Scopes {
        self.scopes
    }

    /// The per-request authorization policy built from those scopes.
    #[must_use]
    pub const fn authz(&self) -> ScopedAuthz {
        ScopedAuthz::new(self.scopes)
    }

    /// The cookie session, when this caller has one. A bearer token does not.
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The session and the id it was reached by.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthenticated`] for a caller that authenticated with a
    /// bearer token. A token establishes no session, so there is nothing for
    /// `/auth/session` to describe and nothing for `/auth/logout` to end;
    /// answering 401 keeps the two credential kinds from being confused.
    pub fn require_session(&self) -> Result<(&Secret, &Session), AuthError> {
        match (self.session_id.as_ref(), self.session.as_ref()) {
            (Some(id), Some(session)) => Ok((id, session)),
            _ => Err(AuthError::Unauthenticated),
        }
    }

    /// Resolve `headers` against the stores in `state`.
    ///
    /// The clocks are parameters so a test can drive a session past its
    /// timeout or a token past its expiry without waiting.
    ///
    /// # Errors
    ///
    /// [`AuthError::AmbiguousCredentials`] when both a cookie and a bearer
    /// token are presented, and [`AuthError::Unauthenticated`] when neither is,
    /// or when the one that is does not resolve.
    pub fn resolve(
        state: &AppState,
        headers: &HeaderMap,
        now: Instant,
        now_unix: i64,
    ) -> Result<Self, AuthError> {
        match (cookie_id(headers), bearer(headers)) {
            (Some(_cookie), Some(_token)) => Err(AuthError::AmbiguousCredentials),
            (Some(id), None) => {
                let session = state
                    .auth
                    .sessions
                    .lookup(id.expose(), now)
                    .ok_or(AuthError::Unauthenticated)?;
                Ok(Self {
                    identity: Identity::new(session.subject.clone(), IdentityKind::Session),
                    scopes: session.scopes,
                    session: Some(session),
                    session_id: Some(id),
                })
            }
            (None, Some(token)) => {
                let holder = state
                    .auth
                    .tokens
                    .authenticate(token.expose(), now_unix)
                    // An unknown or expired token is refused exactly like no
                    // token at all: 401, not the 404 the token *management*
                    // endpoints answer for an id that is not on file.
                    .map_err(|error| match error {
                        AuthError::UnknownToken => AuthError::Unauthenticated,
                        other => other,
                    })?;
                Ok(Self {
                    identity: Identity::new(
                        format!("{TOKEN_SUBJECT_PREFIX}{}", holder.id),
                        IdentityKind::Token,
                    ),
                    scopes: holder.scopes,
                    session: None,
                    session_id: None,
                })
            }
            (None, None) => Err(AuthError::Unauthenticated),
        }
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    /// Not an `async fn`: resolving a caller is pure computation over headers
    /// and two in-memory stores, so a ready future is both the honest shape
    /// and one less state machine per request.
    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            Self::resolve(state, &parts.headers, Instant::now(), unix_now())
                .map_err(ApiError::from),
        )
    }
}

/// A [`Caller`] that holds [`Scope::Write`].
///
/// A handler that mutates the host takes this instead of a [`Caller`], so the
/// scope check happens in the extractor rather than in a line of the handler
/// that a later change could drop.
#[derive(Debug)]
pub struct WriteCaller(Caller);

impl WriteCaller {
    /// The caller underneath, for the identity and the audit record.
    #[must_use]
    pub const fn caller(&self) -> &Caller {
        &self.0
    }
}

impl FromRequestParts<AppState> for WriteCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let caller = Caller::from_request_parts(parts, state).await?;
        if !caller.scopes().allows(Scope::Write) {
            state.auth.record(
                &crate::auth::audit::AuthRecord::new(
                    crate::auth::audit::AuthEvent::ScopeDenied,
                    caller.identity().subject.clone(),
                    detent_ops::audit::AuditResult::Denied,
                )
                .with_kind(caller.identity().kind)
                .with_detail(MessageId::new(DENIED_SCOPE_ID)),
            );
        }
        if caller.scopes().allows(Scope::Write) {
            return Ok(Self(caller));
        }
        Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            MessageId::new(DENIED_SCOPE_ID),
        ))
    }
}

/// The address the request came from, for the login rate limiter.
///
/// Read from [`ConnectInfo`] when the listener supplied it, and
/// [`UNKNOWN_CLIENT_IP`] otherwise. Falling back rather than failing is
/// deliberate: an attempt whose source is unknown must still be counted, and
/// counting it against one shared bucket errs towards throttling too much,
/// never too little. The per-user bucket is unaffected either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    /// The peer address these request parts carry, or [`UNKNOWN_CLIENT_IP`].
    #[must_use]
    pub fn of(parts: &Parts) -> Self {
        parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(Self(UNKNOWN_CLIENT_IP), |info| Self(info.0.ip()))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    /// Not an `async fn`, for the same reason [`Caller`]'s is not: reading the
    /// peer address out of the request extensions never waits on anything.
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self::of(parts)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Caller, ClientIp, UNKNOWN_CLIENT_IP, WriteCaller, bearer, cookie_id, unix_now};
    use crate::auth::AuthError;
    use crate::auth::session::COOKIE_NAME;
    use crate::authz::{Scope, Scopes};
    use crate::state::{AppState, TestState, test_state};
    use axum::body::Body;
    use axum::extract::{ConnectInfo, FromRequestParts as _};
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use detent_ops::identity::IdentityKind;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Headers carrying just a session cookie.
    fn with_cookie(id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&format!("{COOKIE_NAME}={id}")) {
            headers.insert(header::COOKIE, value);
        }
        headers
    }

    /// Headers carrying just a bearer token.
    fn with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(header::AUTHORIZATION, value);
        }
        headers
    }

    /// Resolve against a fixture's state at the current instant.
    fn resolve(fixture: &TestState, headers: &HeaderMap) -> Result<Caller, AuthError> {
        Caller::resolve(&fixture.state, headers, Instant::now(), unix_now())
    }

    #[test]
    fn split_cookie_header_lines_are_combined_before_parsing() -> R {
        let fixture = test_state()?;
        let (id, _session) = fixture.state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            Instant::now(),
        )?;
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE_NAME}={}", id.expose()))?,
        );
        assert!(cookie_id(&headers).is_some_and(|presented| presented.ct_eq(id.expose())));
        Ok(())
    }

    #[test]
    fn a_cookie_session_resolves_to_a_session_identity() -> R {
        let fixture = test_state()?;
        let (id, _session) = fixture.state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            true,
            Instant::now(),
        )?;

        let caller = resolve(&fixture, &with_cookie(id.expose()))?;
        assert_eq!(caller.identity().subject, "alice");
        assert_eq!(caller.identity().kind, IdentityKind::Session);
        assert_eq!(caller.scopes(), Scopes::read_write());
        assert!(caller.authz().scopes().allows(Scope::Write));
        let (held, session) = caller.require_session()?;
        assert!(held.ct_eq(id.expose()));
        assert!(session.totp_satisfied);
        assert_eq!(caller.session().map(|s| s.subject.as_str()), Some("alice"));
        Ok(())
    }

    #[test]
    fn a_bearer_token_resolves_to_a_token_identity_with_its_scope() -> R {
        let fixture = test_state()?;
        let (token, view) = fixture.state.auth.tokens.issue("ci", Scope::Read, None)?;

        let caller = resolve(&fixture, &with_bearer(token.expose()))?;
        assert_eq!(caller.identity().subject, format!("token:{}", view.id));
        assert_eq!(caller.identity().kind, IdentityKind::Token);
        assert_eq!(caller.scopes(), Scopes::read_only());
        // A token establishes no session, so there is nothing to end.
        assert!(matches!(
            caller.require_session(),
            Err(AuthError::Unauthenticated)
        ));
        assert!(caller.session().is_none());
        Ok(())
    }

    #[test]
    fn a_cookie_and_a_token_together_are_refused_rather_than_resolved() -> R {
        let fixture = test_state()?;
        let (id, _session) = fixture.state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            Instant::now(),
        )?;
        let (token, _view) = fixture.state.auth.tokens.issue("ci", Scope::Read, None)?;

        // Neither direction upgrades the other: read-only token plus a
        // read-write cookie, and the reverse, are both refused.
        let mut headers = with_cookie(id.expose());
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token.expose())) {
            headers.insert(header::AUTHORIZATION, value);
        }
        match resolve(&fixture, &headers) {
            Err(err @ AuthError::AmbiguousCredentials) => {
                assert_eq!(err.message_id().as_str(), "web-auth-ambiguous-credentials");
                assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }

        // Even a *nonsense* second credential is enough to refuse: the rule is
        // about ambiguity, not about which one would have won.
        let mut both = with_cookie(id.expose());
        both.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert!(matches!(
            resolve(&fixture, &both),
            Err(AuthError::AmbiguousCredentials)
        ));
        Ok(())
    }

    #[test]
    fn no_credential_and_a_bad_credential_answer_the_same() -> R {
        let fixture = test_state()?;
        let (_token, _view) = fixture.state.auth.tokens.issue("ci", Scope::Read, None)?;
        let cases = [
            ("nothing at all", HeaderMap::new()),
            ("an unknown session", with_cookie(&"0".repeat(64))),
            ("an empty session id", with_cookie("")),
            ("an unknown token", with_bearer(&"0".repeat(64))),
            ("a truncated token", with_bearer("short")),
        ];
        for (name, headers) in cases {
            match resolve(&fixture, &headers) {
                Err(err @ AuthError::Unauthenticated) => {
                    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
                    assert_eq!(err.message_id().as_str(), "web-auth-unauthenticated");
                }
                other => return Err(format!("{name} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn an_expired_token_is_refused_like_an_unknown_one() -> R {
        let fixture = test_state()?;
        let (token, _view) =
            fixture
                .state
                .auth
                .tokens
                .issue("temporary", Scope::Write, Some(1000))?;
        let headers = with_bearer(token.expose());
        assert!(Caller::resolve(&fixture.state, &headers, Instant::now(), 999).is_ok());
        assert!(matches!(
            Caller::resolve(&fixture.state, &headers, Instant::now(), 1000),
            Err(AuthError::Unauthenticated)
        ));
        Ok(())
    }

    #[test]
    fn a_session_past_either_timeout_no_longer_resolves() -> R {
        let fixture = test_state()?;
        let start = Instant::now();
        let (id, _session) =
            fixture
                .state
                .auth
                .sessions
                .create("alice", Scopes::read_write(), false, start)?;
        let headers = with_cookie(id.expose());
        let at = |secs: u64| {
            start
                .checked_add(Duration::from_secs(secs))
                .unwrap_or(start)
        };

        // Inside the idle window it resolves, and the touch restarts the clock.
        assert!(Caller::resolve(&fixture.state, &headers, at(899), 0).is_ok());
        assert!(Caller::resolve(&fixture.state, &headers, at(1798), 0).is_ok());
        // Then a gap longer than `auth.idle_timeout_secs`.
        assert!(matches!(
            Caller::resolve(&fixture.state, &headers, at(2699), 0),
            Err(AuthError::Unauthenticated)
        ));
        assert!(fixture.state.auth.sessions.is_empty(), "it was not removed");

        // And the absolute limit ends a session that is being used throughout.
        let (id, _session) =
            fixture
                .state
                .auth
                .sessions
                .create("alice", Scopes::read_write(), false, start)?;
        let headers = with_cookie(id.expose());
        let mut when = 0_u64;
        for _ in 0_u32..47 {
            when = when.saturating_add(600);
            assert!(Caller::resolve(&fixture.state, &headers, at(when), 0).is_ok());
        }
        assert!(matches!(
            Caller::resolve(&fixture.state, &headers, at(when.saturating_add(600)), 0),
            Err(AuthError::Unauthenticated)
        ));
        Ok(())
    }

    #[test]
    fn only_a_well_formed_bearer_header_is_a_token() -> R {
        for good in ["Bearer abc", "bearer abc", "BEARER abc", "Bearer   abc  "] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(good)?);
            assert!(
                bearer(&headers).is_some_and(|token| token.ct_eq("abc")),
                "{good:?} was not read as a token"
            );
        }
        for bad in ["", "abc", "Basic abc", "Bearer", "Bearer ", "Bearer    "] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(bad)?);
            assert!(bearer(&headers).is_none(), "{bad:?} was read as a token");
        }
        assert!(bearer(&HeaderMap::new()).is_none());

        // A header that is not UTF-8 cannot be a token either.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff\xfe")?,
        );
        assert!(bearer(&headers).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn the_write_extractor_admits_write_and_refuses_read() -> R {
        let fixture = test_state()?;
        let state: AppState = fixture.state.clone();
        let (write_token, _view) = state.auth.tokens.issue("ci", Scope::Write, None)?;
        let (read_token, _view) = state.auth.tokens.issue("laptop", Scope::Read, None)?;

        let parts_for = |token: &str| -> Result<_, Box<dyn std::error::Error>> {
            let request = Request::builder()
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?;
            Ok(request.into_parts().0)
        };

        let mut parts = parts_for(write_token.expose())?;
        let allowed = WriteCaller::from_request_parts(&mut parts, &state)
            .await
            .map_err(|error| format!("a write token was refused: {error:?}"))?;
        assert_eq!(allowed.caller().scopes(), Scopes::read_write());

        let mut parts = parts_for(read_token.expose())?;
        let refused = WriteCaller::from_request_parts(&mut parts, &state)
            .await
            .err()
            .ok_or("a read-only token was admitted")?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(refused.message_id().as_str(), "web-denied-scope");
        assert!(
            fixture
                .audit
                .events()
                .contains(&crate::auth::audit::AuthEvent::ScopeDenied)
        );

        // And with no credential the write extractor answers 401, not 403:
        // the scope check is never reached.
        let mut parts = Request::builder().body(Body::empty())?.into_parts().0;
        let refused = WriteCaller::from_request_parts(&mut parts, &state)
            .await
            .err()
            .ok_or("an anonymous caller was admitted")?;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn the_caller_extractor_answers_the_api_error_body() -> R {
        let fixture = test_state()?;
        let mut parts = Request::builder().body(Body::empty())?.into_parts().0;
        let refused = Caller::from_request_parts(&mut parts, &fixture.state)
            .await
            .err()
            .ok_or("an anonymous caller was admitted")?;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(refused.body().code, "unauthorized");

        // And a good credential goes through the extractor, not only through
        // `resolve`.
        let (id, _session) = fixture.state.auth.sessions.create(
            "alice",
            Scopes::read_only(),
            false,
            Instant::now(),
        )?;
        let mut parts = Request::builder()
            .header(header::COOKIE, format!("{COOKIE_NAME}={}", id.expose()))
            .body(Body::empty())?
            .into_parts()
            .0;
        let caller = Caller::from_request_parts(&mut parts, &fixture.state)
            .await
            .map_err(|error| format!("a live session was refused: {error:?}"))?;
        assert_eq!(caller.scopes(), Scopes::read_only());
        Ok(())
    }

    #[tokio::test]
    async fn the_client_address_comes_from_the_connection_when_there_is_one() -> R {
        let mut parts = Request::builder().body(Body::empty())?.into_parts().0;
        assert_eq!(
            ClientIp::from_request_parts(&mut parts, &()).await?,
            ClientIp(UNKNOWN_CLIENT_IP)
        );

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 4444);
        parts.extensions.insert(ConnectInfo(peer));
        assert_eq!(
            ClientIp::from_request_parts(&mut parts, &()).await?,
            ClientIp(peer.ip())
        );
        assert_eq!(ClientIp::of(&parts).0, peer.ip());
        Ok(())
    }

    #[test]
    fn the_clock_helper_is_the_current_unix_time() {
        // 2020-01-01 and 2100-01-01: any plausible test host sits between them.
        let now = unix_now();
        assert!(now > 1_577_836_800, "{now}");
        assert!(now < 4_102_444_800, "{now}");
    }

    #[test]
    fn nothing_here_renders_a_session_id_or_a_csrf_token() -> R {
        let fixture = test_state()?;
        let (id, session) = fixture.state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            Instant::now(),
        )?;
        let caller = resolve(&fixture, &with_cookie(id.expose()))?;
        let write = WriteCaller(caller);
        let rendered = format!("{write:?} {:?}", write.caller());
        assert!(!rendered.contains(id.expose()), "{rendered}");
        assert!(
            !rendered.contains(session.csrf_token.expose()),
            "{rendered}"
        );
        assert!(rendered.contains("Secret(<redacted>)"), "{rendered}");
        Ok(())
    }
}
