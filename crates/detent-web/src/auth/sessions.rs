//! `/api/v1/auth/sessions`: list and end the caller's own sessions
//! (ASVS 3.3.4).
//!
//! ```text
//!   GET  /auth/sessions                 ─▶ SessionStore::list          ─▶ [SessionSummary]
//!   POST /auth/sessions/{handle}/revoke ─▶ SessionStore::revoke_handle ─▶ 204 (or 404)
//!   POST /auth/sessions/revoke-others   ─▶ SessionStore::revoke_others ─▶ {"ended": n}
//! ```
//!
//! # Design
//!
//! * **Own sessions only.** Every call is scoped to the subject of the
//!   session that makes it. All accounts are administrators, but one account
//!   cannot see or end the sessions of another here.
//! * **A handle, never the id.** A session is named by its random handle
//!   ([`super::session::HANDLE_BYTES`] bytes, drawn apart from the id). The
//!   answer has no id, no digest of one and no CSRF token.
//! * **One 404 for every miss.** An unknown handle, an ended session and a
//!   handle of another account answer the same 404 body, so a handle cannot
//!   be probed. A miss is not audited, so probing cannot grow the log.
//! * **Session only.** A bearer token has no session to list or end: 401, as
//!   for `/auth/session`.
//! * **The ends are writes.** Both POSTs take [`WriteCaller`], so the CSRF
//!   guard applies and a session that owes a password change is refused
//!   (403); the list takes [`Caller`], which refuses that session too.
//! * **Ending the current session is a sign-out.** The answer clears the
//!   cookie, as `/auth/logout` does.
//! * **Audited.** One `session_revoked` record per ended session.

use std::time::Instant;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

use super::AuthError;
use super::audit::{AuthEvent, AuthRecord};
use super::extract::{Caller, ClientIp, WriteCaller, unix_now};
#[cfg(test)]
use super::routes::{SESSION_REVOKE_PATH, SESSIONS_PATH, SESSIONS_REVOKE_OTHERS_PATH};
use super::session::{self, SessionSummary};

/// What `POST /api/v1/auth/sessions/revoke-others` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct RevokedSessions {
    /// How many sessions were ended.
    pub ended: usize,
}

/// `GET /api/v1/auth/sessions`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a session that owes a
/// password change.
#[cfg_attr(test, utoipa::path(
    get,
    path = SESSIONS_PATH,
    operation_id = "auth_sessions",
    tag = "auth",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "The live sessions of the signed-in user, newest first; the one the request came with has `current` set", body = Vec<SessionSummary>),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first", body = crate::error::ErrorBody),
    ),
))]
pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<SessionSummary>>, ApiError> {
    let (_id, session) = caller.require_session()?;
    Ok(Json(state.auth.sessions.list(
        &session.subject,
        &session.handle,
        Instant::now(),
        unix_now(),
    )))
}

/// `POST /api/v1/auth/sessions/{handle}/revoke`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a failed CSRF check or a
/// session that owes a password change, 404 when no session of the caller
/// has that handle.
#[cfg_attr(test, utoipa::path(
    post,
    path = SESSION_REVOKE_PATH,
    operation_id = "auth_session_revoke",
    tag = "auth",
    security(("session_cookie" = [])),
    params(("handle" = String, Path, description = "The handle from `GET /api/v1/auth/sessions`")),
    responses(
        (status = 204, description = "The session is ended; when it was the current one, the cookie is cleared"),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The CSRF check failed, or the session must change its password first", body = crate::error::ErrorBody),
        (status = 404, description = "No session of this user has that handle", body = crate::error::ErrorBody),
    ),
))]
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let (_id, session) = caller.caller().require_session()?;
    if !state.auth.sessions.revoke_handle(&session.subject, &handle) {
        return Err(AuthError::UnknownSession.into());
    }
    record_revoked(&state, &session.subject, ip, 1);
    let mut response = StatusCode::NO_CONTENT.into_response();
    if handle == session.handle {
        super::routes::set_cookie(&mut response, &session::clear_cookie_value());
    }
    Ok(response)
}

/// `POST /api/v1/auth/sessions/revoke-others`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a failed CSRF check or a
/// session that owes a password change.
#[cfg_attr(test, utoipa::path(
    post,
    path = SESSIONS_REVOKE_OTHERS_PATH,
    operation_id = "auth_sessions_revoke_others",
    tag = "auth",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Every other session of this user is ended; the current one stays", body = RevokedSessions),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The CSRF check failed, or the session must change its password first", body = crate::error::ErrorBody),
    ),
))]
pub async fn revoke_others(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    caller: WriteCaller,
) -> Result<Json<RevokedSessions>, ApiError> {
    let (_id, session) = caller.caller().require_session()?;
    let ended = state
        .auth
        .sessions
        .revoke_others(&session.subject, &session.handle);
    record_revoked(&state, &session.subject, ip, ended);
    Ok(Json(RevokedSessions { ended }))
}

/// Write one `session_revoked` record for each of `count` ended sessions.
fn record_revoked(state: &AppState, subject: &str, ip: std::net::IpAddr, count: usize) {
    for _ in 0..count {
        state.auth.record(
            &AuthRecord::new(AuthEvent::SessionRevoked, subject, AuditResult::Ok)
                .with_kind(IdentityKind::Session)
                .with_client_ip(ip),
        );
    }
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
