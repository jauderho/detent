//! `/api/v1/auth/totp*`: a signed-in user turns its own second factor on
//! and off from the web console (TM-G1).
//!
//! ```text
//!   GET  /auth/totp          ─▶ { enrolled, required }
//!   POST /auth/totp/enrol    ─▶ password ─▶ new key, pending in this session ─▶ uri + key
//!   POST /auth/totp/confirm  ─▶ code against the pending key ─▶ stored ─▶ new session
//!   POST /auth/totp/disable  ─▶ password + code ─▶ cleared ─▶ new session
//! ```

use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use detent_core::diag::MessageId;
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::{Deserialize, Serialize};

use crate::authz::Scopes;
use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::audit::{AuthEvent, AuthRecord};
use super::extract::{Caller, ClientIp, WriteCaller, unix_now};
use super::routes::{
    Established, MALFORMED_BODY_ID, MAX_PASSWORD_LEN, MAX_TOTP_CODE_LEN, audit_failure, established,
};
#[cfg(test)]
use super::routes::{TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH, TOTP_ENROL_PATH, TOTP_PATH};
use super::secret::Secret;
use super::session::PENDING_TOTP_TTL;
use super::totp::TotpSecret;
use super::users::VerifiedUser;

/// What `GET /api/v1/auth/totp` answers.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct TotpStatus {
    /// Whether this account has a second factor.
    pub enrolled: bool,
    /// Whether this host requires one (`auth.totp_required`).
    pub required: bool,
}

/// The body of `POST /api/v1/auth/totp/enrol`.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TotpEnrolRequest {
    /// The password in force now.
    pub current_password: String,
}

/// The body of `POST /api/v1/auth/totp/confirm`.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TotpConfirmRequest {
    /// A current six-digit code from the new key.
    pub code: String,
}

/// The body of `POST /api/v1/auth/totp/disable`.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TotpDisableRequest {
    /// The password in force now.
    pub current_password: String,
    /// A current six-digit code from the enrolled key.
    pub code: String,
}

impl fmt::Debug for TotpEnrolRequest {
    /// The password never renders.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrolRequest").finish_non_exhaustive()
    }
}

impl fmt::Debug for TotpConfirmRequest {
    /// The code never renders.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfirmRequest").finish_non_exhaustive()
    }
}

impl fmt::Debug for TotpDisableRequest {
    /// Neither the password nor the code renders.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpDisableRequest").finish_non_exhaustive()
    }
}

/// What `POST /api/v1/auth/totp/enrol` answers, once.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct TotpEnrolment {
    /// The `otpauth://totp/...` URI an authenticator application scans.
    pub uri: String,
    /// The same key in base32, for typing in by hand.
    pub secret: String,
    /// Seconds left to confirm the key with a code.
    pub expires_in_secs: u64,
}

impl fmt::Debug for TotpEnrolment {
    /// The key is a credential; neither form of it renders.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrolment")
            .field("expires_in_secs", &self.expires_in_secs)
            .finish_non_exhaustive()
    }
}

/// `GET /api/v1/auth/totp`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a session that owes a
/// password change, 500 when the user store cannot be read.
#[cfg_attr(test, utoipa::path(
    get,
    path = TOTP_PATH,
    operation_id = "totp_status",
    tag = "auth",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Whether this account has a second factor, and whether the host requires one", body = TotpStatus),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first", body = crate::error::ErrorBody),
    ),
))]
pub async fn status(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<TotpStatus>, ApiError> {
    let (_id, session) = caller.require_session()?;
    // The command line may have changed the file since this process read it.
    state.auth.users.refresh()?;
    Ok(Json(TotpStatus {
        enrolled: is_enrolled(&state, &session.subject),
        required: state.auth.totp_required,
    }))
}

/// `POST /api/v1/auth/totp/enrol`.
///
/// Needs the current password. Makes a new key and keeps it in this session
/// only, for [`PENDING_TOTP_TTL`]; nothing is stored until
/// `POST /api/v1/auth/totp/confirm` proves a code from it. The key is in this
/// answer and in no other.
///
/// # Errors
///
/// 401 for no session, a bearer token or a refused password, 403 for a
/// session that owes a password change, 409 when the account already has a
/// key, 429, 503 and 500 as for login.
#[cfg_attr(test, utoipa::path(
    post,
    path = TOTP_ENROL_PATH,
    operation_id = "totp_enrol",
    tag = "auth",
    security(("session_cookie" = [])),
    request_body = TotpEnrolRequest,
    responses(
        (status = 200, description = "A new key, pending in this session until a code confirms it", body = TotpEnrolment),
        (status = 400, description = "The body is not the expected shape", body = crate::error::ErrorBody),
        (status = 401, description = "No session, a bearer token, or the current password was refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first, or the CSRF checks failed", body = crate::error::ErrorBody),
        (status = 409, description = "The account already has a key", body = crate::error::ErrorBody),
        (status = 429, description = "Too many attempts", body = crate::error::ErrorBody),
        (status = 503, description = "The hashing cap is reached", body = crate::error::ErrorBody),
    ),
))]
pub async fn enrol(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    body: Result<Json<TotpEnrolRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (id, session) = caller.caller().require_session()?;
    let Ok(Json(request)) = body else {
        return Ok(malformed());
    };
    let subject = session.subject.clone();
    let now = Instant::now();
    match start_enrolment(&state, id, &subject, &request, ip, now).await {
        Ok(enrolment) => {
            state.auth.limiter.record_success(ip, &subject);
            Ok(Json(enrolment).into_response())
        }
        Err(error) => Err(refused(
            &state,
            error,
            &subject,
            ip,
            now,
            AuthEvent::TotpEnabled,
        )),
    }
}

/// `POST /api/v1/auth/totp/confirm`.
///
/// Checks a code against the key this session started. Only a valid code
/// stores the key; that code is then used up, exactly as a sign-in uses one
/// up. Every session of the account is ended and a new one is answered, with
/// the second factor satisfied.
///
/// # Errors
///
/// 401 for no session, a bearer token or a wrong code, 403 for a session
/// that owes a password change, 409 when no key is pending or the account
/// has a key already, 429 and 500 as for login.
#[cfg_attr(test, utoipa::path(
    post,
    path = TOTP_CONFIRM_PATH,
    operation_id = "totp_confirm",
    tag = "auth",
    security(("session_cookie" = [])),
    request_body = TotpConfirmRequest,
    responses(
        (status = 200, description = "The key is stored; every older session is ended and a new one is set", body = crate::auth::session::SessionView),
        (status = 400, description = "The body is not the expected shape", body = crate::error::ErrorBody),
        (status = 401, description = "No session, a bearer token, or the code was refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first, or the CSRF checks failed", body = crate::error::ErrorBody),
        (status = 409, description = "No key is pending in this session, or the account already has one", body = crate::error::ErrorBody),
        (status = 429, description = "Too many attempts", body = crate::error::ErrorBody),
    ),
))]
pub async fn confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    body: Result<Json<TotpConfirmRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (id, session) = caller.caller().require_session()?;
    let Ok(Json(request)) = body else {
        return Ok(malformed());
    };
    let subject = session.subject.clone();
    let now = Instant::now();
    match confirm_enrolment(&state, id, &subject, &request.code, ip, now) {
        Ok((id, view)) => {
            state.auth.limiter.record_success(ip, &subject);
            state.auth.record(
                &AuthRecord::new(AuthEvent::TotpEnabled, &subject, AuditResult::Ok)
                    .with_kind(IdentityKind::Session)
                    .with_client_ip(ip),
            );
            Ok(established(&id, &view))
        }
        Err(error) => Err(refused(
            &state,
            error,
            &subject,
            ip,
            now,
            AuthEvent::TotpEnabled,
        )),
    }
}

/// `POST /api/v1/auth/totp/disable`.
///
/// Needs the current password and a current code; the code is used up.
/// Refused on a host with `auth.totp_required`, where the account could not
/// sign in again. Every session of the account is ended and a new one is
/// answered.
///
/// # Errors
///
/// 401 for no session, a bearer token, a refused password or a wrong code,
/// 403 for a session that owes a password change, 409 when the account has no
/// key or the host requires one, 429, 503 and 500 as for login.
#[cfg_attr(test, utoipa::path(
    post,
    path = TOTP_DISABLE_PATH,
    operation_id = "totp_disable",
    tag = "auth",
    security(("session_cookie" = [])),
    request_body = TotpDisableRequest,
    responses(
        (status = 200, description = "The key is cleared; every older session is ended and a new one is set", body = crate::auth::session::SessionView),
        (status = 400, description = "The body is not the expected shape", body = crate::error::ErrorBody),
        (status = 401, description = "No session, a bearer token, or the password or code was refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first, or the CSRF checks failed", body = crate::error::ErrorBody),
        (status = 409, description = "The account has no key, or the host requires one", body = crate::error::ErrorBody),
        (status = 429, description = "Too many attempts", body = crate::error::ErrorBody),
        (status = 503, description = "The hashing cap is reached or the session table is full", body = crate::error::ErrorBody),
    ),
))]
pub async fn disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    body: Result<Json<TotpDisableRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (_id, session) = caller.caller().require_session()?;
    let Ok(Json(request)) = body else {
        return Ok(malformed());
    };
    let subject = session.subject.clone();
    let now = Instant::now();
    match turn_off(&state, &subject, &request, ip, now).await {
        Ok((id, view)) => {
            state.auth.limiter.record_success(ip, &subject);
            state.auth.record(
                &AuthRecord::new(AuthEvent::TotpDisabled, &subject, AuditResult::Ok)
                    .with_kind(IdentityKind::Session)
                    .with_client_ip(ip),
            );
            Ok(established(&id, &view))
        }
        Err(error) => Err(refused(
            &state,
            error,
            &subject,
            ip,
            now,
            AuthEvent::TotpDisabled,
        )),
    }
}

// ---------------------------------------------------------------------------
// The decisions
// ---------------------------------------------------------------------------

/// Verify the password, make a key and keep it pending in session `id`.
///
/// # Errors
///
/// [`AuthError::RateLimited`], [`AuthError::InvalidCredentials`],
/// [`AuthError::Busy`], [`AuthError::TotpEnrolled`], and
/// [`AuthError::Unauthenticated`] when the session ended meanwhile.
async fn start_enrolment(
    state: &AppState,
    id: &Secret,
    subject: &str,
    request: &TotpEnrolRequest,
    ip: IpAddr,
    now: Instant,
) -> Result<TotpEnrolment, AuthError> {
    state.auth.limiter.check(ip, subject, now)?;
    let verified = verify_current(state, subject, &request.current_password).await?;
    if verified.totp.is_some() {
        return Err(AuthError::TotpEnrolled);
    }
    let secret = TotpSecret::generate()?;
    let uri = secret.otpauth_uri(subject);
    let base32 = secret.to_base32();
    if !state
        .auth
        .sessions
        .set_pending_totp(id.expose(), secret, now)
    {
        return Err(AuthError::Unauthenticated);
    }
    Ok(TotpEnrolment {
        uri: uri.expose().to_owned(),
        secret: base32.expose().to_owned(),
        expires_in_secs: PENDING_TOTP_TTL.as_secs(),
    })
}

/// Check `code` against the key pending in session `id`, store the key, use
/// the code up and answer a new session.
///
/// # Errors
///
/// [`AuthError::RateLimited`], [`AuthError::InvalidCredentials`] for a wrong
/// code, [`AuthError::TotpEnrolled`], [`AuthError::TotpNoPending`], and the
/// store variants.
fn confirm_enrolment(
    state: &AppState,
    id: &Secret,
    subject: &str,
    code: &str,
    ip: IpAddr,
    now: Instant,
) -> Result<Established, AuthError> {
    state.auth.limiter.check(ip, subject, now)?;
    if code.len() > MAX_TOTP_CODE_LEN {
        return Err(AuthError::InvalidCredentials);
    }
    state.auth.users.refresh()?;
    if is_enrolled(state, subject) {
        return Err(AuthError::TotpEnrolled);
    }
    let secret = state
        .auth
        .sessions
        .pending_totp(id.expose(), now)
        .ok_or(AuthError::TotpNoPending)?;
    let seconds = u64::try_from(unix_now()).unwrap_or_default();
    let counter = secret
        .verify(code, seconds, None)
        .ok_or(AuthError::InvalidCredentials)?;
    // Of two requests that confirm the same key, only one stores it.
    if !state.auth.sessions.take_pending_totp(id.expose()) {
        return Err(AuthError::TotpNoPending);
    }
    state.auth.users.set_totp(subject, Some(&secret))?;
    state.auth.users.note_totp_counter(subject, counter)?;
    renew_session(state, subject, true, now)
}

/// Verify the password and a fresh code, clear the key and answer a new
/// session.
///
/// # Errors
///
/// [`AuthError::RateLimited`], [`AuthError::TotpRequired`],
/// [`AuthError::InvalidCredentials`] for a wrong password or code,
/// [`AuthError::Busy`], [`AuthError::TotpNotEnrolled`], and the store
/// variants.
async fn turn_off(
    state: &AppState,
    subject: &str,
    request: &TotpDisableRequest,
    ip: IpAddr,
    now: Instant,
) -> Result<Established, AuthError> {
    state.auth.limiter.check(ip, subject, now)?;
    if state.auth.totp_required {
        return Err(AuthError::TotpRequired);
    }
    if request.code.len() > MAX_TOTP_CODE_LEN {
        return Err(AuthError::InvalidCredentials);
    }
    let verified = verify_current(state, subject, &request.current_password).await?;
    let secret = verified.totp.ok_or(AuthError::TotpNotEnrolled)?;
    let seconds = u64::try_from(unix_now()).unwrap_or_default();
    let counter = secret
        .verify(&request.code, seconds, verified.totp_last_counter)
        .ok_or(AuthError::InvalidCredentials)?;
    // Recorded before the key is cleared, so of two requests racing with one
    // code only one gets past this line.
    state.auth.users.note_totp_counter(subject, counter)?;
    state.auth.users.set_totp(subject, None)?;
    renew_session(state, subject, false, now)
}

/// The password check login makes, on the blocking pool behind the same cap.
///
/// # Errors
///
/// [`AuthError::InvalidCredentials`] for a wrong or over-long password,
/// [`AuthError::Busy`] when every hashing slot is taken, and the store
/// variants.
async fn verify_current(
    state: &AppState,
    subject: &str,
    password: &str,
) -> Result<VerifiedUser, AuthError> {
    if password.chars().count() > MAX_PASSWORD_LEN {
        return Err(AuthError::InvalidCredentials);
    }
    let permit = state
        .auth
        .argon2_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| AuthError::Busy)?;
    let auth = state.auth.clone();
    let name = subject.to_owned();
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth.users.verify_password(&auth.hasher, &name, &password)
    })
    .await
    .map_err(|_| AuthError::Hash)?
}

/// End every session of `subject` and create a new one. A second factor
/// added or removed is a privilege change: a session established before it
/// must not outlive it.
///
/// # Errors
///
/// [`AuthError::SessionLimit`] or [`AuthError::Entropy`].
fn renew_session(
    state: &AppState,
    subject: &str,
    totp_satisfied: bool,
    now: Instant,
) -> Result<Established, AuthError> {
    state.auth.sessions.revoke_subject(subject);
    let (id, session) =
        state
            .auth
            .sessions
            .create(subject, Scopes::read_write(), totp_satisfied, now)?;
    let view = state.auth.sessions.view(&session, now);
    Ok((id, view))
}

/// Whether `subject` has a key stored.
fn is_enrolled(state: &AppState, subject: &str) -> bool {
    state
        .auth
        .users
        .list()
        .iter()
        .any(|user| user.name == subject && user.totp_enrolled)
}

/// Audit a refusal as login does, and turn it into the answer.
///
/// A state conflict (409) is not audited: no credential was checked, and the
/// caller is already signed in.
fn refused(
    state: &AppState,
    error: AuthError,
    subject: &str,
    ip: IpAddr,
    now: Instant,
    event: AuthEvent,
) -> ApiError {
    if error.status() != StatusCode::CONFLICT {
        audit_failure(state, &error, subject, ip, now, event);
    }
    ApiError::from(error)
}

/// The 400 for a body that is not the expected shape.
fn malformed() -> Response {
    ApiError::new(StatusCode::BAD_REQUEST, MessageId::new(MALFORMED_BODY_ID)).into_response()
}

#[cfg(test)]
#[path = "enrolment_tests.rs"]
mod tests;
