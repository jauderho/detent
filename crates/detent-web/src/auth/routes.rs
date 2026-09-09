//! `/api/v1/auth/*`: sign in, sign out, and describe the session.
//!
//! ```text
//!   POST /auth/login ─▶ limiter.check ─▶ verify_password ─▶ totp ─▶ session
//!            │              │                  │             │        │
//!            │              └── 429            └─ dummy hash │        │
//!            │                                   on a miss   │  Set-Cookie
//!            └──────────────── audit ◀───────────────────────┴────────┘
//!
//!   POST /auth/logout ─▶ SessionStore::logout ─▶ Set-Cookie Max-Age=0 ─▶ 204
//!   GET  /auth/session ─▶ SessionView (csrf token, subject, scopes, expiry)
//! ```
//!
//! Phase 4c owns the rest of `/api/v1`; this module registers the three routes
//! that must exist before anything else can be authenticated.
//!
//! # Guarantees
//!
//! * **A failed login says one thing.** Unknown user, wrong password, missing
//!   TOTP code and replayed TOTP code all answer 401 with
//!   `web-auth-invalid-credentials`, and all cost one Argon2id pass — the miss
//!   branch runs [`Hasher::verify_dummy`](super::password::Hasher::verify_dummy).
//!   The audit log records which it really was; the client is told nothing.
//! * **Every outcome is audited**, success, failure and lockout alike, through
//!   the sink [`AppState`] was built with.
//! * **The session id is never in a body.** [`SessionView`] carries the CSRF
//!   token, the subject, the scopes and the expiry; the id travels only in the
//!   `__Host-` cookie, which script cannot read.
//! * **Signing in cannot reuse an id.** Any session the request arrived with is
//!   invalidated before the new one is issued, so a planted pre-login id is
//!   worthless.
//! * **A submitted name is never written raw.** Anything that is not a usable
//!   user name becomes [`MALFORMED_SUBJECT`] before it reaches the audit log or
//!   the rate limiter's keys, so a 256 KiB body cannot become a 256 KiB map key
//!   and a control character cannot reach a log line.
//!
//! # Cost of a login
//!
//! Argon2id runs on the request's own task rather than on
//! `tokio::task::spawn_blocking`. At the configured cost that is tens of
//! milliseconds of a runtime worker per attempt; the bounds on it are
//! `listen.max_connections` and the per-address and per-user limiters in front.
//! Moving it to the blocking pool would mean copying the password into another
//! task, and is a change to make deliberately with a measurement, not in
//! passing.

use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use detent_core::diag::MessageId;
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::Deserialize;

use crate::authz::Scopes;
use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::audit::{AuthEvent, AuthRecord};
use super::extract::{Caller, ClientIp, unix_now};
use super::secret::Secret;
use super::session::{self, SessionView};
use super::users::{self, MAX_NAME_LEN, VerifiedUser};

/// Where a caller exchanges credentials for a session.
pub const LOGIN_PATH: &str = "/api/v1/auth/login";

/// Where a caller ends one.
pub const LOGOUT_PATH: &str = "/api/v1/auth/logout";

/// Where the front end reads its CSRF token and its remaining time.
pub const SESSION_PATH: &str = "/api/v1/auth/session";

/// Fluent id of a request body that is not the shape the endpoint expects.
pub const MALFORMED_BODY_ID: &str = "web-request-malformed";

/// Audit subject and rate-limit key standing in for a submitted name that
/// could not be a user name at all.
///
/// `<` is outside the user-name allow-list, so this can never collide with a
/// real account.
pub const MALFORMED_SUBJECT: &str = "<malformed>";

/// Longest password accepted. Well past any passphrase and far short of the
/// 256 KiB body limit, so a hostile body cannot turn into Argon2 work.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Longest TOTP code accepted. RFC 6238 codes are six digits.
pub const MAX_TOTP_CODE_LEN: usize = 16;

// ---------------------------------------------------------------------------
// The route table
// ---------------------------------------------------------------------------

/// One registered route.
///
/// The table exists so that "GET never mutates" (PLAN §2.7) can be *checked*
/// rather than asserted: [`crate::csrf`]'s test walks this list, and
/// [`routes`] is built from the same three entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The method it is registered for.
    pub method: Method,
    /// The path it is registered at.
    pub path: &'static str,
    /// Whether reaching it changes server state.
    pub mutating: bool,
}

/// Every route this module registers.
#[must_use]
pub fn table() -> &'static [Route] {
    static TABLE: [Route; 3] = [
        Route {
            method: Method::POST,
            path: LOGIN_PATH,
            mutating: true,
        },
        Route {
            method: Method::POST,
            path: LOGOUT_PATH,
            mutating: true,
        },
        Route {
            method: Method::GET,
            path: SESSION_PATH,
            mutating: false,
        },
    ];
    &TABLE
}

/// The auth routes, ready to be given [`AppState`] and wrapped in
/// [`crate::csrf::csrf_guard`].
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(LOGIN_PATH, post(login))
        .route(LOGOUT_PATH, post(logout))
        .route(SESSION_PATH, get(session))
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// The body of `POST /api/v1/auth/login`.
#[derive(Clone, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// The account name.
    pub username: String,
    /// The password, in the clear over TLS 1.3 and nowhere else.
    pub password: String,
    /// The six-digit TOTP code, when the account has a second factor enrolled
    /// or `auth.totp_required` is set.
    #[serde(default)]
    pub totp_code: Option<String>,
}

impl fmt::Debug for LoginRequest {
    /// The name only. A password and a one-time code are both credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl LoginRequest {
    /// Whether every field is inside its length bound (PLAN §2.7, "Input").
    #[must_use]
    fn within_limits(&self) -> bool {
        self.username.len() <= MAX_NAME_LEN
            && self.password.len() <= MAX_PASSWORD_LEN
            && self
                .totp_code
                .as_ref()
                .is_none_or(|code| code.len() <= MAX_TOTP_CODE_LEN)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/login`.
async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        // Never serde's own message: it quotes the body back at the caller.
        return ApiError::new(StatusCode::BAD_REQUEST, MessageId::new(MALFORMED_BODY_ID))
            .into_response();
    };
    let now = Instant::now();
    let subject = principal_name(&request.username);

    match attempt(&state, &request, subject, &headers, ip, now) {
        Ok((id, view)) => {
            state.auth.limiter.record_success(ip, subject);
            state.auth.record(
                &AuthRecord::new(AuthEvent::LoginSucceeded, &view.subject, AuditResult::Ok)
                    .with_kind(IdentityKind::Session)
                    .with_client_ip(ip),
            );
            established(&id, &view)
        }
        Err(error) => {
            audit_failure(&state, &error, subject, ip, now);
            ApiError::from(error).into_response()
        }
    }
}

/// `POST /api/v1/auth/logout`.
async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: Caller,
) -> Result<Response, ApiError> {
    let (id, session) = caller.require_session()?;
    let ended = state.auth.sessions.logout(id.expose());
    state.auth.record(
        &AuthRecord::new(
            AuthEvent::LoggedOut,
            &session.subject,
            if ended {
                AuditResult::Ok
            } else {
                AuditResult::Error
            },
        )
        .with_kind(IdentityKind::Session)
        .with_client_ip(ip),
    );

    let mut response = StatusCode::NO_CONTENT.into_response();
    set_cookie(&mut response, &session::clear_cookie_value());
    Ok(response)
}

/// `GET /api/v1/auth/session`.
async fn session(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<SessionView>, ApiError> {
    let (_id, session) = caller.require_session()?;
    Ok(Json(state.auth.sessions.view(session, Instant::now())))
}

// ---------------------------------------------------------------------------
// The login decision
// ---------------------------------------------------------------------------

/// The name a submitted one is throttled and audited under.
///
/// A body may carry any string at all. [`users::name_is_valid`] bounds it to 32
/// characters of `[a-z0-9._-]`, so passing the check means the value is safe as
/// a map key and as a log field; failing it means no account could have that
/// name anyway, and one shared bucket for every such attempt is neither an
/// enumeration oracle nor a way to grow the limiter's maps.
fn principal_name(submitted: &str) -> &str {
    if users::name_is_valid(submitted) {
        submitted
    } else {
        MALFORMED_SUBJECT
    }
}

/// Everything a successful login has to produce: the id for the cookie and the
/// body for the response.
type Established = (Secret, SessionView);

/// Decide one login attempt.
///
/// # Errors
///
/// [`AuthError::RateLimited`] when this address or this name is locked out,
/// [`AuthError::InvalidCredentials`] for every credential failure, and the
/// store variants when the session or the replay counter cannot be recorded.
fn attempt(
    state: &AppState,
    request: &LoginRequest,
    subject: &str,
    headers: &HeaderMap,
    ip: IpAddr,
    now: Instant,
) -> Result<Established, AuthError> {
    state.auth.limiter.check(ip, subject, now)?;
    if !request.within_limits() {
        return Err(AuthError::InvalidCredentials);
    }
    let verified =
        state
            .auth
            .users
            .verify_password(&state.auth.hasher, subject, &request.password)?;
    let totp_satisfied = check_totp(state, &verified, request.totp_code.as_deref())?;

    // Session fixation: whatever id the request arrived with stops working
    // before the new one is issued. A fresh id also restarts the absolute
    // timer, which `SessionStore::rotate` deliberately does not.
    if let Some(presented) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(session::cookie_value)
    {
        state.auth.sessions.logout(presented.expose());
    }
    // Every account this build knows is an administrator: `users.json` carries
    // no per-user scopes, and `read` alone would make the UI useless. Scoping
    // down is what API tokens are for.
    let (id, session) =
        state
            .auth
            .sessions
            .create(&verified.name, Scopes::read_write(), totp_satisfied, now)?;
    let view = state.auth.sessions.view(&session, now);
    Ok((id, view))
}

/// Whether the second factor is satisfied, when there is one to satisfy.
///
/// # Errors
///
/// [`AuthError::InvalidCredentials`] for a missing, wrong, expired or replayed
/// code, and for an account with no enrolment on a host that requires one.
/// [`AuthError::UnknownUser`] or a store variant when the accepted counter
/// cannot be recorded — a code that cannot be marked used is refused rather
/// than accepted, because accepting it would leave it replayable.
fn check_totp(
    state: &AppState,
    verified: &VerifiedUser,
    code: Option<&str>,
) -> Result<bool, AuthError> {
    let Some(secret) = verified.totp.as_ref() else {
        // `auth.totp_required` with nobody enrolled locks the host rather than
        // waving the requirement through. `detent user` enrols; PLAN Phase 5
        // gives it a UI.
        return if state.auth.totp_required {
            Err(AuthError::InvalidCredentials)
        } else {
            Ok(false)
        };
    };
    let code = code.ok_or(AuthError::InvalidCredentials)?;
    let seconds = u64::try_from(unix_now()).unwrap_or_default();
    let counter = secret
        .verify(code, seconds, verified.totp_last_counter)
        .ok_or(AuthError::InvalidCredentials)?;
    state
        .auth
        .users
        .note_totp_counter(&verified.name, counter)?;
    Ok(true)
}

/// Record a refused attempt, and the lockouts it caused.
fn audit_failure(state: &AppState, error: &AuthError, subject: &str, ip: IpAddr, now: Instant) {
    state.auth.record(
        &AuthRecord::new(AuthEvent::LoginFailed, subject, AuditResult::Error)
            .with_kind(IdentityKind::Session)
            .with_client_ip(ip)
            .with_detail(error.message_id()),
    );
    // Only a credential failure feeds the limiter. Counting an attempt that
    // was already refused for being rate limited would ratchet the lockout
    // for as long as an attacker kept knocking, which locks the operator out
    // of their own appliance; a store or entropy failure is not the caller's
    // doing at all.
    if !matches!(*error, AuthError::InvalidCredentials) {
        return;
    }
    for principal in state.auth.limiter.record_failure(ip, subject, now) {
        state.auth.record(
            &AuthRecord::new(
                AuthEvent::LockedOut,
                principal.to_string(),
                AuditResult::Error,
            )
            .with_kind(IdentityKind::Session)
            .with_client_ip(ip),
        );
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// The 200 a successful login answers: the session view, and the cookie.
fn established(id: &Secret, view: &SessionView) -> Response {
    let mut response = Json(view).into_response();
    set_cookie(&mut response, &session::set_cookie_value(id));
    response
}

/// Put `value` in `Set-Cookie`.
///
/// `HeaderValue::from_str` can only fail on a value that is not visible ASCII,
/// and both cookie values are a fixed name and lowercase hex. Skipping rather
/// than panicking keeps the `panic = "deny"` posture, exactly as
/// [`crate::headers::security_headers`] does.
fn set_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LOGIN_PATH, LOGOUT_PATH, LoginRequest, MALFORMED_SUBJECT, MAX_PASSWORD_LEN, SESSION_PATH,
        principal_name, routes, table,
    };
    use crate::auth::audit::AuthEvent;
    use crate::auth::session::COOKIE_NAME;
    use crate::authz::Scope;
    use crate::csrf::{CSRF_HEADER, SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
    use crate::server::harden;
    use crate::state::{AppState, TestState, test_state};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use std::time::Duration;
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../../locales/en-US/core.ftl");

    const ORIGIN: &str = "https://box.example:3333";

    /// The whole Phase 4b stack: state, the auth routes, the CSRF guard, and
    /// the §2.7 middleware `Server::bind` would wrap them in.
    fn app(state: &AppState) -> Router {
        harden(
            routes()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    csrf_guard,
                ))
                .with_state(state.clone()),
            Duration::from_secs(30),
        )
    }

    /// A fixture with one account.
    fn fixture_with_alice() -> Result<TestState, Box<dyn std::error::Error>> {
        let fixture = test_state()?;
        fixture
            .state
            .auth
            .users
            .create(&fixture.state.auth.hasher, "alice", "hunter2", false)?;
        Ok(fixture)
    }

    /// A login request body.
    fn credentials(username: &str, password: &str) -> String {
        format!("{{\"username\":\"{username}\",\"password\":\"{password}\"}}")
    }

    /// `POST LOGIN_PATH` with `body`.
    fn login_request(body: &str) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        Ok(Request::builder()
            .method(Method::POST)
            .uri(LOGIN_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))?)
    }

    /// The JSON of a response body.
    async fn json(
        response: axum::response::Response,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The session id out of a `Set-Cookie` header.
    fn cookie_id(
        response: &axum::response::Response,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let value = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("no Set-Cookie")?
            .to_str()?;
        Ok(value
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .ok_or("no cookie value")?
            .1
            .to_owned())
    }

    // -- the table -----------------------------------------------------------

    #[test]
    fn the_table_and_the_router_describe_the_same_three_routes() {
        let paths: Vec<&str> = table().iter().map(|route| route.path).collect();
        assert_eq!(paths, vec![LOGIN_PATH, LOGOUT_PATH, SESSION_PATH]);
        assert_eq!(
            table().iter().filter(|route| route.mutating).count(),
            2,
            "{:?}",
            table()
        );
        assert!(
            table()
                .iter()
                .all(|route| route.path.starts_with("/api/v1/auth/"))
        );
        // `Route` is a plain record; the derives are used by the csrf tests.
        assert_eq!(table().first(), table().first());
        assert!(format!("{:?}", table()).contains("Route"));
    }

    #[test]
    fn the_malformed_body_id_is_in_the_catalogue() {
        assert!(
            CATALOGUE.lines().any(|line| {
                line.split('=')
                    .next()
                    .is_some_and(|key| key.trim() == super::MALFORMED_BODY_ID)
            }),
            "`{}` is missing from core.ftl",
            super::MALFORMED_BODY_ID
        );
    }

    // -- login ---------------------------------------------------------------

    #[tokio::test]
    async fn a_good_login_sets_the_host_cookie_and_answers_the_session_view() -> R {
        let fixture = fixture_with_alice()?;
        let response = app(&fixture.state)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("no Set-Cookie")?
            .to_str()?
            .to_owned();
        assert!(cookie.starts_with(&format!("{COOKIE_NAME}=")), "{cookie}");
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(cookie.contains("; HttpOnly"), "{cookie}");
        assert!(cookie.contains("; SameSite=Strict"), "{cookie}");
        assert!(!cookie.contains("Domain"), "{cookie}");

        let id = cookie_id(&response)?;
        let body = json(response).await?;
        assert_eq!(
            body.pointer("/subject").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            body.pointer("/scopes")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            body.pointer("/totp_satisfied")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(body.pointer("/csrf_token").is_some());
        assert!(
            body.pointer("/expires_in_secs")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|secs| secs > 0)
        );
        // The id is in the cookie and in no readable field of the body.
        assert!(!body.to_string().contains(&id), "{body}");
        assert_eq!(fixture.audit.events(), vec![AuthEvent::LoginSucceeded]);
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_user_and_a_wrong_password_are_indistinguishable() -> R {
        let fixture = fixture_with_alice()?;
        let mut answers = Vec::new();
        for (username, password) in [("alice", "wrong"), ("mallory", "hunter2")] {
            let response = app(&fixture.state)
                .oneshot(login_request(&credentials(username, password))?)
                .await?;
            answers.push((
                response.status(),
                response.headers().get(header::SET_COOKIE).cloned(),
                json(response).await?,
            ));
        }
        let (first, rest) = answers.split_first().ok_or("no answers")?;
        assert_eq!(first.0, StatusCode::UNAUTHORIZED);
        assert!(first.1.is_none(), "a refused login set a cookie");
        assert_eq!(
            first.2,
            serde_json::json!({
                "code": "unauthorized",
                "message_id": "web-auth-invalid-credentials",
            })
        );
        for answer in rest {
            assert_eq!(answer, first, "the two refusals differ");
        }
        // Both were audited as failures, with the same detail.
        assert_eq!(
            fixture.audit.events(),
            vec![AuthEvent::LoginFailed, AuthEvent::LoginFailed]
        );
        for record in fixture.audit.records() {
            assert_eq!(
                record.detail.as_deref(),
                Some("web-auth-invalid-credentials")
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn repeated_failures_lock_the_account_out_and_the_lockout_is_audited() -> R {
        let fixture = fixture_with_alice()?;
        // `auth.max_failures` is 5, so the fifth attempt is the one that locks.
        for _ in 0_u32..5 {
            let response = app(&fixture.state)
                .oneshot(login_request(&credentials("alice", "wrong"))?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let locked = app(&fixture.state)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            locked
                .headers()
                .get(header::RETRY_AFTER)
                .map(|value| value.to_str())
                .transpose()?,
            Some("2")
        );
        let body = json(locked).await?;
        assert_eq!(
            body.pointer("/message_id").and_then(|v| v.as_str()),
            Some("web-auth-rate-limited")
        );

        let events = fixture.audit.events();
        assert_eq!(
            events
                .iter()
                .filter(|e| **e == AuthEvent::LockedOut)
                .count(),
            2,
            "the address and the name are both locked: {events:?}"
        );
        // The refused-because-locked attempt was audited but did not extend
        // the lockout: still exactly the two records the fifth failure made.
        assert_eq!(
            events
                .iter()
                .filter(|e| **e == AuthEvent::LoginFailed)
                .count(),
            6
        );
        assert_eq!(fixture.state.auth.limiter.tracked(), (1, 1));
        Ok(())
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_login_request_is_a_bad_request() -> R {
        let fixture = fixture_with_alice()?;
        for body in [
            "",
            "not json",
            "{}",
            "{\"username\":\"alice\"}",
            "{\"username\":\"alice\",\"password\":\"hunter2\",\"extra\":1}",
            "{\"username\":1,\"password\":\"hunter2\"}",
        ] {
            let response = app(&fixture.state).oneshot(login_request(body)?).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body:?}");
            let json = json(response).await?;
            assert_eq!(
                json.pointer("/message_id").and_then(|v| v.as_str()),
                Some("web-request-malformed"),
                "{body:?}"
            );
        }
        // A body with no JSON content type is refused the same way, and
        // nothing was audited: no attempt was made.
        let response = app(&fixture.state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGIN_PATH)
                    .body(Body::from(credentials("alice", "hunter2")))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(fixture.audit.events().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn an_oversized_field_is_refused_as_a_credential_failure() -> R {
        let fixture = fixture_with_alice()?;
        let cases = [
            credentials("alice", &"x".repeat(MAX_PASSWORD_LEN.saturating_add(1))),
            format!(
                "{{\"username\":\"alice\",\"password\":\"hunter2\",\"totp_code\":\"{}\"}}",
                "1".repeat(17)
            ),
        ];
        for body in cases {
            let response = app(&fixture.state).oneshot(login_request(&body)?).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                json(response)
                    .await?
                    .pointer("/message_id")
                    .and_then(|v| v.as_str()),
                Some("web-auth-invalid-credentials")
            );
        }
        assert_eq!(fixture.state.auth.users.list().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_name_that_could_never_be_a_user_is_throttled_under_one_key() -> R {
        let fixture = fixture_with_alice()?;
        // A name outside the allow-list, and a very long one: both are
        // audited and throttled as `<malformed>`.
        for username in ["Alice", &"z".repeat(200)] {
            let response = app(&fixture.state)
                .oneshot(login_request(&credentials(username, "hunter2"))?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        for record in fixture.audit.records() {
            assert_eq!(record.subject, MALFORMED_SUBJECT);
        }
        // One name key, not two, and nothing 200 characters long in it.
        assert_eq!(fixture.state.auth.limiter.tracked(), (1, 1));

        assert_eq!(principal_name("alice"), "alice");
        assert_eq!(principal_name("Alice"), MALFORMED_SUBJECT);
        assert_eq!(principal_name(""), MALFORMED_SUBJECT);
        assert_eq!(principal_name("ali\nce"), MALFORMED_SUBJECT);
        assert!(!crate::auth::users::name_is_valid(MALFORMED_SUBJECT));
        Ok(())
    }

    #[tokio::test]
    async fn signing_in_again_invalidates_the_session_the_request_arrived_with() -> R {
        let fixture = fixture_with_alice()?;
        let first = app(&fixture.state)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        let old = cookie_id(&first)?;
        let old_csrf = json(first)
            .await?
            .pointer("/csrf_token")
            .and_then(|v| v.as_str())
            .ok_or("no csrf token")?
            .to_owned();

        // A second login carrying the first session's cookie. The CSRF guard
        // applies, because the request *is* cookie-authenticated.
        let second = app(&fixture.state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGIN_PATH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, format!("{COOKIE_NAME}={old}"))
                    .header(SEC_FETCH_SITE, SAME_ORIGIN)
                    .header(header::ORIGIN, ORIGIN)
                    .header(CSRF_HEADER, &old_csrf)
                    .body(Body::from(credentials("alice", "hunter2")))?,
            )
            .await?;
        assert_eq!(second.status(), StatusCode::OK);
        let fresh = cookie_id(&second)?;
        assert_ne!(fresh, old);

        // Exactly one session survives, and it is the new one.
        assert_eq!(fixture.state.auth.sessions.len(), 1);
        assert!(
            fixture
                .state
                .auth
                .sessions
                .lookup(&old, std::time::Instant::now())
                .is_none()
        );
        assert!(
            fixture
                .state
                .auth
                .sessions
                .lookup(&fresh, std::time::Instant::now())
                .is_some()
        );
        Ok(())
    }

    // -- totp ----------------------------------------------------------------

    #[tokio::test]
    async fn an_enrolled_account_must_present_a_fresh_code() -> R {
        use crate::auth::totp::{STEP_SECS, TotpSecret};

        let fixture = fixture_with_alice()?;
        let secret = TotpSecret::generate()?;
        fixture.state.auth.users.set_totp("alice", Some(&secret))?;
        let counter = u64::try_from(super::unix_now()).unwrap_or_default() / STEP_SECS;
        let code = secret.code_at(counter);

        let body = |code: &str| {
            format!("{{\"username\":\"alice\",\"password\":\"hunter2\",\"totp_code\":\"{code}\"}}")
        };

        // No code at all, and a wrong one: the same refusal a wrong password
        // gets.
        for attempt in [credentials("alice", "hunter2"), body("000000")] {
            let response = app(&fixture.state)
                .oneshot(login_request(&attempt)?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                json(response)
                    .await?
                    .pointer("/message_id")
                    .and_then(|v| v.as_str()),
                Some("web-auth-invalid-credentials")
            );
        }

        let response = app(&fixture.state)
            .oneshot(login_request(&body(code.expose()))?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json(response)
                .await?
                .pointer("/totp_satisfied")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );

        // The same code again is a replay, and is refused.
        let replay = app(&fixture.state)
            .oneshot(login_request(&body(code.expose()))?)
            .await?;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn a_host_that_requires_totp_refuses_an_account_without_one() -> R {
        let fixture = test_state()?;
        // `totp_required` is fixed at construction, so a second state is built
        // with it set rather than mutated in place.
        let mut config = (*fixture.state.config).clone();
        config.auth.totp_required = true;
        let required = AppState::new(
            crate::engine::EngineHandle::detached(),
            crate::state::AuthState::open_with_audit(
                fixture.state_root(),
                &config.auth,
                4096,
                Box::new(crate::state::SharedCapture(std::sync::Arc::clone(
                    &fixture.audit,
                ))),
            )?,
            config.clone(),
            crate::csrf::Origin::for_config(&config),
        );
        required
            .auth
            .users
            .create(&required.auth.hasher, "alice", "hunter2", false)?;

        let response = app(&required)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(required.auth.sessions.is_empty());
        assert_eq!(fixture.audit.events(), vec![AuthEvent::LoginFailed]);
        Ok(())
    }

    // -- session and logout --------------------------------------------------

    #[tokio::test]
    async fn the_session_endpoint_answers_the_token_and_never_the_id() -> R {
        let fixture = fixture_with_alice()?;
        let login = app(&fixture.state)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        let id = cookie_id(&login)?;

        let response = app(&fixture.state)
            .oneshot(
                Request::builder()
                    .uri(SESSION_PATH)
                    .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .map(|value| value.to_str())
                .transpose()?,
            Some("no-store"),
            "the api must not be cached"
        );
        let body = json(response).await?;
        assert_eq!(
            body.pointer("/subject").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert!(!body.to_string().contains(&id), "{body}");
        assert!(
            body.pointer("/csrf_token")
                .and_then(|v| v.as_str())
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_session_endpoint_needs_a_session() -> R {
        let fixture = fixture_with_alice()?;
        let (token, _view) = fixture.state.auth.tokens.issue("ci", Scope::Write, None)?;
        // No credential, and a bearer token: 401 either way, because a token
        // establishes no session.
        for header_pair in [
            None,
            Some((header::AUTHORIZATION, format!("Bearer {}", token.expose()))),
        ] {
            let mut request = Request::builder().uri(SESSION_PATH);
            if let Some((name, value)) = header_pair {
                request = request.header(name, value);
            }
            let response = app(&fixture.state)
                .oneshot(request.body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                json(response)
                    .await?
                    .pointer("/message_id")
                    .and_then(|v| v.as_str()),
                Some("web-auth-unauthenticated")
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn logging_out_ends_the_session_and_clears_the_cookie() -> R {
        let fixture = fixture_with_alice()?;
        let login = app(&fixture.state)
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        let id = cookie_id(&login)?;
        let csrf = json(login)
            .await?
            .pointer("/csrf_token")
            .and_then(|v| v.as_str())
            .ok_or("no csrf token")?
            .to_owned();

        let response = app(&fixture.state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGOUT_PATH)
                    .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                    .header(SEC_FETCH_SITE, SAME_ORIGIN)
                    .header(header::ORIGIN, ORIGIN)
                    .header(CSRF_HEADER, &csrf)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("no Set-Cookie")?
            .to_str()?;
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
        assert!(!cookie.contains(&id), "{cookie}");
        assert!(fixture.state.auth.sessions.is_empty());
        assert_eq!(
            fixture.audit.events(),
            vec![AuthEvent::LoginSucceeded, AuthEvent::LoggedOut]
        );
        Ok(())
    }

    #[tokio::test]
    async fn logging_out_without_a_session_is_refused() -> R {
        let fixture = fixture_with_alice()?;
        let response = app(&fixture.state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGOUT_PATH)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(fixture.audit.events().is_empty());
        Ok(())
    }

    // -- the assembled stack -------------------------------------------------

    /// PLAN §2.7 end to end: sign in, read the session, make a mutating
    /// request with and without the CSRF header, sign out — through
    /// `harden(csrf_guard(routes()))`, which is what `Server::bind` serves.
    #[tokio::test]
    async fn the_assembled_stack_carries_a_browser_through_a_whole_session() -> R {
        let fixture = fixture_with_alice()?;
        let stack = app(&fixture.state);

        // 1. Sign in. No cookie yet, so the CSRF guard has nothing to check.
        let login = stack
            .clone()
            .oneshot(login_request(&credentials("alice", "hunter2"))?)
            .await?;
        assert_eq!(login.status(), StatusCode::OK);
        assert!(
            login
                .headers()
                .contains_key(axum::http::header::CONTENT_SECURITY_POLICY),
            "harden() did not wrap the router"
        );
        assert!(login.headers().contains_key(crate::server::X_REQUEST_ID));
        let id = cookie_id(&login)?;
        let csrf = json(login)
            .await?
            .pointer("/csrf_token")
            .and_then(|v| v.as_str())
            .ok_or("no csrf token")?
            .to_owned();

        // 2. Read the session back with the cookie the browser now holds.
        let view = stack
            .clone()
            .oneshot(
                Request::builder()
                    .uri(SESSION_PATH)
                    .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                    .header(SEC_FETCH_SITE, SAME_ORIGIN)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(view.status(), StatusCode::OK);
        assert_eq!(
            json(view)
                .await?
                .pointer("/csrf_token")
                .and_then(|v| v.as_str()),
            Some(csrf.as_str())
        );

        // 3. A mutating request without the CSRF header is refused by the
        //    guard, and the session is untouched.
        let refused = stack
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGOUT_PATH)
                    .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                    .header(SEC_FETCH_SITE, SAME_ORIGIN)
                    .header(header::ORIGIN, ORIGIN)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json(refused)
                .await?
                .pointer("/message_id")
                .and_then(|v| v.as_str()),
            Some("web-auth-csrf-rejected")
        );
        assert_eq!(fixture.state.auth.sessions.len(), 1);

        // 4. The same request with the header goes through.
        let accepted = stack
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGOUT_PATH)
                    .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                    .header(SEC_FETCH_SITE, SAME_ORIGIN)
                    .header(header::ORIGIN, ORIGIN)
                    .header(CSRF_HEADER, &csrf)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
        assert!(fixture.state.auth.sessions.is_empty());
        assert_eq!(
            fixture.audit.events(),
            vec![AuthEvent::LoginSucceeded, AuthEvent::LoggedOut]
        );
        Ok(())
    }

    #[test]
    fn the_request_body_never_renders_its_password() {
        let request = LoginRequest {
            username: "alice".to_owned(),
            password: "hunter2".to_owned(),
            totp_code: Some("123456".to_owned()),
        };
        let rendered = format!("{request:?} {:?}", request.clone());
        assert!(rendered.contains("alice"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("123456"), "{rendered}");
    }
}
