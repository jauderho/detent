//! `/api/v1/auth/tokens`: list, mint and revoke API tokens from the console
//! (ASVS 1.2.4).
//!
//! ```text
//!   GET  /auth/tokens             ─▶ TokenStore::refresh ─▶ list ─▶ [TokenView]
//!   POST /auth/tokens             ─▶ label, expiry ─▶ totp ─▶ step-up ─▶ TokenStore::issue ─▶ 201 {token, …view}
//!   POST /auth/tokens/{id}/revoke ─▶ step-up ─▶ TokenStore::revoke ─▶ 204 (or 404)
//! ```
//!
//! # Design
//!
//! * **Sessions only.** A bearer token can never list, mint or revoke a
//!   token: 401, as for `/auth/sessions`. The two POSTs take
//!   [`WriteCaller`], so the CSRF guard applies, a session without `write`
//!   gets 403 (so no session mints a scope wider than its own), and a
//!   session that owes a password change gets 403.
//! * **A fresh step-up.** Both POSTs need a step-up younger than
//!   [`super::session::STEP_UP_TTL`], with the same answer as the gated
//!   operations (`403 web-auth-step-up-required`), so the console's step-up
//!   dialog handles it.
//! * **The second factor, when the host requires one.** With
//!   `auth.totp_required`, a session that did not present a code at sign-in
//!   may not mint a token (`403 web-auth-token-totp-required`).
//! * **Shown once.** The token is in the 201 answer and nowhere else: the
//!   store keeps its SHA-256 only, the list has no field for it, and
//!   [`IssuedToken`]'s `Debug` does not render it.
//! * **One store.** The routes use the [`super::TokenStore`] that
//!   authenticates bearer tokens, so a change works at once. Each write
//!   re-reads `tokens.json` first under the store's lock, so a token the CLI
//!   minted or revoked in the meantime is kept or stays revoked.
//! * **Audited.** `token_issued` and `token_revoked`, subject `token:<id>`,
//!   kind `session`, the user as `actor`, and the client address. A refusal
//!   writes nothing.

use std::fmt;
use std::time::Instant;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use detent_core::diag::MessageId;
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::{Deserialize, Serialize};

use crate::authz::Scope;
use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::audit::{AuthEvent, AuthRecord};
use super::extract::{Caller, ClientIp, TOKEN_SUBJECT_PREFIX, WriteCaller, unix_now};
use super::routes::MALFORMED_BODY_ID;
#[cfg(test)]
use super::routes::{TOKEN_REVOKE_PATH, TOKENS_PATH};
use super::session::Session;
use super::token::{TokenView, label_is_valid};

/// The body of `POST /api/v1/auth/tokens`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// What to call the token: 1 to 64 printable ASCII characters.
    pub label: String,
    /// `read`, or `write` (which includes `read`).
    pub scope: Scope,
    /// Seconds from now until the token stops working; absent for a token
    /// that does not expire. At least 1.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// What `POST /api/v1/auth/tokens` answers: the token, once, and its entry.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct IssuedToken {
    /// The bearer token. This is the only time it is shown.
    pub token: String,
    /// The entry the list shows for it.
    #[serde(flatten)]
    pub view: TokenView,
}

impl fmt::Debug for IssuedToken {
    /// The entry only: the token is a credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedToken")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

/// `GET /api/v1/auth/tokens`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a session that owes a
/// password change, 500 when `tokens.json` cannot be read.
#[cfg_attr(test, utoipa::path(
    get,
    path = TOKENS_PATH,
    operation_id = "auth_tokens",
    tag = "auth",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Every API token on this host, without its value", body = Vec<TokenView>),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first", body = crate::error::ErrorBody),
        (status = 500, description = "The token file cannot be read", body = crate::error::ErrorBody),
    ),
))]
pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<TokenView>>, ApiError> {
    let _session = caller.require_session()?;
    state.auth.tokens.refresh()?;
    Ok(Json(state.auth.tokens.list()))
}

/// `POST /api/v1/auth/tokens`.
///
/// # Errors
///
/// 400 for a malformed body, an unusable label or expiry; 401 for no
/// session or a bearer token; 403 for a failed CSRF check, a session
/// without `write`, a session that owes a password change, a session
/// without a fresh step-up, or a session without a second factor on a host
/// that requires one; 409 when the host holds the most tokens it may; 500
/// when the token file cannot be written.
#[cfg_attr(test, utoipa::path(
    post,
    path = TOKENS_PATH,
    operation_id = "auth_token_create",
    tag = "auth",
    security(("session_cookie" = [])),
    request_body = TokenRequest,
    responses(
        (status = 201, description = "The token was issued. `token` is shown here once and never again", body = IssuedToken),
        (status = 400, description = "The body is not the expected shape, or the label or the expiry is not usable", body = crate::error::ErrorBody),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The CSRF check failed; the session lacks `write`, must change its password, needs a step-up, or did not present a second factor on a host that requires one", body = crate::error::ErrorBody),
        (status = 409, description = "The host already holds the most tokens it may", body = crate::error::ErrorBody),
        (status = 500, description = "The token file cannot be read or written", body = crate::error::ErrorBody),
    ),
))]
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    body: Result<Json<TokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (_id, session) = caller.caller().require_session()?;
    let Ok(Json(request)) = body else {
        // Never serde's own message: it quotes the body back at the caller.
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            MessageId::new(MALFORMED_BODY_ID),
        ));
    };
    if !label_is_valid(&request.label) {
        return Err(AuthError::TokenLabelInvalid.into());
    }
    let expires_at = match request.expires_in_secs {
        None => None,
        Some(secs) => Some(expiry(unix_now(), secs)?),
    };
    if state.auth.totp_required && !session.totp_satisfied {
        return Err(AuthError::TokenTotpRequired.into());
    }
    require_fresh_step_up(session)?;
    let (token, view) = state
        .auth
        .tokens
        .issue(&request.label, request.scope, expires_at)?;
    record(&state, AuthEvent::TokenIssued, &view.id, session, ip);
    let issued = IssuedToken {
        token: token.expose().to_owned(),
        view,
    };
    Ok((StatusCode::CREATED, Json(issued)).into_response())
}

/// `POST /api/v1/auth/tokens/{id}/revoke`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a failed CSRF check, a
/// session without `write`, a session that owes a password change or one
/// without a fresh step-up, 404 when no token has that id, 500 when the
/// token file cannot be written.
#[cfg_attr(test, utoipa::path(
    post,
    path = TOKEN_REVOKE_PATH,
    operation_id = "auth_token_revoke",
    tag = "auth",
    security(("session_cookie" = [])),
    params(("id" = String, Path, description = "The id from `GET /api/v1/auth/tokens`")),
    responses(
        (status = 204, description = "The token is revoked and stops working at once"),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The CSRF check failed; the session lacks `write`, must change its password, or needs a step-up", body = crate::error::ErrorBody),
        (status = 404, description = "No token has that id", body = crate::error::ErrorBody),
        (status = 500, description = "The token file cannot be read or written", body = crate::error::ErrorBody),
    ),
))]
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (_id, session) = caller.caller().require_session()?;
    require_fresh_step_up(session)?;
    state.auth.tokens.revoke(&id)?;
    record(&state, AuthEvent::TokenRevoked, &id, session, ip);
    Ok(StatusCode::NO_CONTENT)
}

/// The Unix second `secs` after `now`.
///
/// # Errors
///
/// [`AuthError::TokenExpiryInvalid`] for zero, and for a sum past
/// [`i64::MAX`], the limit the command line has too.
fn expiry(now: i64, secs: u64) -> Result<i64, AuthError> {
    if secs == 0 {
        return Err(AuthError::TokenExpiryInvalid);
    }
    i64::try_from(secs)
        .ok()
        .and_then(|secs| now.checked_add(secs))
        .ok_or(AuthError::TokenExpiryInvalid)
}

/// Refuse a session whose step-up is missing or older than
/// [`super::session::STEP_UP_TTL`], as [`Caller::require_step_up`] does for
/// the gated operations.
///
/// # Errors
///
/// [`AuthError::StepUpRequired`].
fn require_fresh_step_up(session: &Session) -> Result<(), AuthError> {
    session
        .step_up_left(Instant::now())
        .map(|_left| ())
        .ok_or(AuthError::StepUpRequired)
}

/// Write one record for a change to the token `id` made by `session`.
fn record(state: &AppState, event: AuthEvent, id: &str, session: &Session, ip: std::net::IpAddr) {
    state.auth.record(
        &AuthRecord::new(
            event,
            format!("{TOKEN_SUBJECT_PREFIX}{id}"),
            AuditResult::Ok,
        )
        .with_kind(IdentityKind::Session)
        .with_actor(session.subject.clone())
        .with_client_ip(ip),
    );
}

#[cfg(test)]
#[path = "tokens_tests.rs"]
mod tests;
