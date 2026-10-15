//! `POST /api/v1/auth/reauth`: step-up re-authentication (ASVS 3.7.1,
//! 4.3.3).
//!
//! ```text
//!   POST /auth/reauth ─▶ limiter.check ─▶ verify_password ─▶ totp ─▶ SessionStore::step_up
//!            │              │                                   │            │
//!            │              └── 429                             │      {step_up_expires_in_secs}
//!            └──────────────── audit ◀──────────────────────────┴────────────┘
//!
//!   apply / restore / update / cert renew from a session ─▶ api::authorize
//!            └─ no step-up in the last 5 min ─▶ 403 web-auth-step-up-required
//! ```
//!
//! # Design
//!
//! * **Sessions only.** A bearer token has no session to step up: 401, as for
//!   `/auth/session`. Bearer tokens are not asked for a step-up either: the
//!   gate in [`crate::api::authorize`] looks at sessions only.
//! * **The login's checks, the login's limits.** The password is checked for
//!   the session's own user with the same Argon2 permit cap; when the account
//!   has a second factor, a fresh code is needed and a spent code is a replay
//!   ([`super::routes::check_totp`]). A failure feeds the login
//!   [`RateLimiter`](super::RateLimiter), so five wrong passwords lock the
//!   user and the address out of both sign-in and step-up.
//! * **A write.** The route takes [`WriteCaller`], so the CSRF guard applies
//!   and a session that owes a password change is refused (403).
//! * **Audited.** `step_up_succeeded` or `step_up_failed` (a replayed code is
//!   `totp_replayed`, a lockout `locked_out`), never with a credential.

use std::fmt;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use detent_core::diag::MessageId;
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::audit::{AuthEvent, AuthRecord};
use super::extract::{ClientIp, WriteCaller};
#[cfg(test)]
use super::routes::REAUTH_PATH;
use super::routes::{MALFORMED_BODY_ID, MAX_PASSWORD_LEN, MAX_TOTP_CODE_LEN};
use super::session::STEP_UP_TTL;

/// [`STEP_UP_TTL`] in seconds, as a successful step-up answers it.
pub const STEP_UP_SECS: u64 = STEP_UP_TTL.as_secs();

/// The body of `POST /api/v1/auth/reauth`.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReauthRequest {
    /// The password of the signed-in user.
    pub password: String,
    /// The six-digit TOTP code, when the account has a second factor.
    #[serde(default)]
    pub totp_code: Option<String>,
}

impl fmt::Debug for ReauthRequest {
    /// Nothing renders: a password and a one-time code are both credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReauthRequest").finish_non_exhaustive()
    }
}

impl ReauthRequest {
    /// Whether every field is inside its length bound, as for a login.
    fn within_limits(&self) -> bool {
        self.password.chars().count() <= MAX_PASSWORD_LEN
            && self
                .totp_code
                .as_ref()
                .is_none_or(|code| code.len() <= MAX_TOTP_CODE_LEN)
    }
}

/// What a successful step-up answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct StepUp {
    /// Seconds the step-up holds: [`STEP_UP_SECS`].
    pub step_up_expires_in_secs: u64,
}

/// `POST /api/v1/auth/reauth`.
///
/// # Errors
///
/// 400 for a malformed body, 401 for no session, a bearer token or refused
/// credentials, 403 for a failed CSRF check or a session that owes a password
/// change, 429 while the user or the address is locked out, 503 when every
/// hashing slot is taken.
#[cfg_attr(test, utoipa::path(
    post,
    path = REAUTH_PATH,
    operation_id = "auth_reauth",
    tag = "auth",
    security(("session_cookie" = [])),
    request_body = ReauthRequest,
    responses(
        (status = 200, description = "The session stepped up: for the next five minutes it may apply, restore, update and renew the certificate", body = StepUp),
        (status = 400, description = "The body is not the expected shape", body = crate::error::ErrorBody),
        (status = 401, description = "No session (a bearer token is refused), or the password or code was refused", body = crate::error::ErrorBody),
        (status = 403, description = "The CSRF check failed, or the session must change its password first", body = crate::error::ErrorBody),
        (status = 429, description = "Too many failed sign-ins or step-ups", body = crate::error::ErrorBody),
        (status = 503, description = "The hashing cap is reached", body = crate::error::ErrorBody),
    ),
))]
pub async fn reauth(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    body: Result<Json<ReauthRequest>, JsonRejection>,
) -> Result<Json<StepUp>, ApiError> {
    let (id, session) = caller.caller().require_session()?;
    let Ok(Json(request)) = body else {
        // Never serde's own message: it quotes the body back at the caller.
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            MessageId::new(MALFORMED_BODY_ID),
        ));
    };
    let subject = session.subject.clone();
    let now = Instant::now();
    if let Err(error) = verify(&state, &subject, &request, ip, now).await {
        super::routes::audit_failure(&state, &error, &subject, ip, now, AuthEvent::StepUpFailed);
        return Err(error.into());
    }
    // The session can have ended while the password was hashed.
    if !state.auth.sessions.step_up(id.expose(), now) {
        return Err(AuthError::Unauthenticated.into());
    }
    state.auth.limiter.record_success(ip, &subject);
    state.auth.record(
        &AuthRecord::new(AuthEvent::StepUpSucceeded, &subject, AuditResult::Ok)
            .with_kind(IdentityKind::Session)
            .with_client_ip(ip),
    );
    Ok(Json(StepUp {
        step_up_expires_in_secs: STEP_UP_SECS,
    }))
}

/// Check the password of `subject`, and its code when it has a second
/// factor, under the login's rate limit and hashing cap.
///
/// # Errors
///
/// [`AuthError::RateLimited`], [`AuthError::Busy`],
/// [`AuthError::InvalidCredentials`] for a wrong or over-long password or a
/// missing or wrong code, [`AuthError::TotpReplayed`], and the store
/// variants.
async fn verify(
    state: &AppState,
    subject: &str,
    request: &ReauthRequest,
    ip: std::net::IpAddr,
    now: Instant,
) -> Result<(), AuthError> {
    state.auth.limiter.check(ip, subject, now)?;
    if !request.within_limits() {
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
    let password = request.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth.users.verify_password(&auth.hasher, &name, &password)
    })
    .await
    .map_err(|_| AuthError::Hash)??;
    super::routes::check_totp(state, &verified, request.totp_code.as_deref())?;
    Ok(())
}

#[cfg(test)]
#[path = "stepup_tests.rs"]
mod tests;
