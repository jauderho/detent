//! `GET /api/v1/auth/notices`: what changed on this account since the last
//! sign-in (ASVS 2.2.3, 2.5.5).
//!
//! ```text
//!   detent-auth.jsonl ─▶ newest first ─▶ skip this sign-in ─▶ stop at the one before
//!                              │
//!                              └─▶ keep the subject's credential changes (cap 10)
//!                                  and count its refused sign-ins
//! ```
//!
//! # Design
//!
//! * **No new store.** The answer is read from the auth log the process
//!   already writes ([`AuthAudit::query`]); the worker has read access to the
//!   state root, so confinement does not change.
//! * **The window is the previous sign-in.** The newest `login_succeeded`
//!   record of the subject is the sign-in that is asking; the one before it
//!   starts the window. A first sign-in has no window: the answer is empty
//!   and `since` is absent. The window is by log order, not by clock, so a
//!   clock step cannot move it. A log rotated away loses its history, and the
//!   answer is then empty.
//! * **Own records only.** A password or second-factor record is kept only
//!   when its subject is the caller. API tokens have no owner (the command
//!   line mints them for the host, and every account is an administrator), so
//!   token records are kept for every caller; they name no account.
//! * **Session only.** A bearer token is refused (401), as for `/auth/totp`.
//! * **Failed sign-ins** are counted from `login_failed` records whose subject
//!   is the caller. A lockout record names a rate-limit principal and a
//!   suppressed `credential_rejected` record names no subject, so neither is
//!   attributable and neither is counted.
//! * **Nothing secret.** Every field is already in the auth log: a time, a
//!   kind and an address.

use axum::Json;
use axum::extract::State;
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

use super::audit::{AuthEvent, AuthRecord};
use super::extract::Caller;
#[cfg(test)]
use super::routes::NOTICES_PATH;

/// Most changes one answer lists.
pub const MAX_CHANGES: usize = 10;

/// Prefix of the subject of a token record (`token:<id>`).
const TOKEN_SUBJECT_PREFIX: &str = "token:";

/// One credential change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct Change {
    /// When, as RFC 3339 in UTC.
    pub at: String,
    /// What changed: `password_changed`, `totp_enabled`, `totp_disabled`,
    /// `token_issued` or `token_revoked`.
    pub change: &'static str,
    /// Where it was made: `cli` or `session`.
    pub source: &'static str,
    /// The address it came from, when the log has one.
    pub client_ip: Option<String>,
}

/// What `GET /api/v1/auth/notices` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct Notices {
    /// When the previous sign-in was; absent on the first one.
    pub since: Option<String>,
    /// Refused sign-ins for this account since then.
    pub failed_sign_ins: u32,
    /// Credential changes since then, newest first, at most [`MAX_CHANGES`].
    pub changes: Vec<Change>,
}

/// `GET /api/v1/auth/notices`.
///
/// # Errors
///
/// 401 for no session or a bearer token, 403 for a session that owes a
/// password change.
#[cfg_attr(test, utoipa::path(
    get,
    path = NOTICES_PATH,
    operation_id = "auth_notices",
    tag = "auth",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Changes and refused sign-ins since the previous sign-in", body = Notices),
        (status = 401, description = "No session; a bearer token is refused", body = crate::error::ErrorBody),
        (status = 403, description = "The session must change its password first", body = crate::error::ErrorBody),
    ),
))]
pub async fn notices(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Notices>, ApiError> {
    let (_id, session) = caller.require_session()?;
    Ok(Json(collect(
        &state.auth.audit.query(None),
        &session.subject,
    )))
}

/// The change `record` reports, when it is one the caller should hear about.
fn change_of(record: &AuthRecord, subject: &str) -> Option<Change> {
    let (change, own) = match record.event {
        AuthEvent::PasswordChanged => ("password_changed", true),
        AuthEvent::TotpEnabled => ("totp_enabled", true),
        AuthEvent::TotpDisabled => ("totp_disabled", true),
        AuthEvent::TokenIssued => ("token_issued", false),
        AuthEvent::TokenRevoked => ("token_revoked", false),
        _ => return None,
    };
    let mine = record.result == AuditResult::Ok
        && if own {
            record.subject == subject
        } else {
            record.subject.starts_with(TOKEN_SUBJECT_PREFIX)
        };
    mine.then(|| Change {
        at: record.ts.clone(),
        change,
        source: if record.kind == IdentityKind::LocalUser {
            "cli"
        } else {
            "session"
        },
        client_ip: record.client_ip.clone(),
    })
}

/// The notices for `subject` out of `newest_first`.
fn collect(newest_first: &[AuthRecord], subject: &str) -> Notices {
    let mut notices = Notices::default();
    let mut current_seen = false;
    for record in newest_first {
        if record.event == AuthEvent::LoginSucceeded && record.subject == subject {
            if current_seen {
                notices.since = Some(record.ts.clone());
                return notices;
            }
            current_seen = true;
        } else if record.event == AuthEvent::LoginFailed && record.subject == subject {
            notices.failed_sign_ins = notices.failed_sign_ins.saturating_add(1);
        } else if notices.changes.len() < MAX_CHANGES
            && let Some(change) = change_of(record, subject)
        {
            notices.changes.push(change);
        }
    }
    // No previous sign-in: there is no window to report.
    Notices::default()
}

#[cfg(test)]
#[path = "notices_tests.rs"]
mod tests;
