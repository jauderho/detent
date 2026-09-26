//! `/api/v1/commits/pending` and `/api/v1/commits/{id}/confirm|rollback`:
//! inspect and settle a commit-confirm window before its deadline (PLAN §2.5,
//! ADR-012).
//!
//! ```text
//!   GET  /commits/pending       ─▶ the current window, if any
//!   POST /commits/{id}/confirm  ─▶ ConfirmCommit  ─▶ the write stays
//!   POST /commits/{id}/rollback ─▶ RollbackCommit ─▶ every write since is undone
//! ```
//!
//! The mutation routes take no body: the id in the path is the whole request.
//! A commit that was already confirmed, already rolled back on its own
//! deadline, or never armed answers 409 — see `is_unknown_wire_id` in
//! [`crate::error`].

use axum::Json;
use axum::Router;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use detent_ops::report::PendingCommit;
use detent_ops::{OpOutcome, Operation};
use detent_platform::privsep::proto::CommitId;
use serde::Serialize;

use crate::auth::extract::{Caller, WriteCaller};
use crate::error::ApiError;
use crate::state::AppState;

use super::{authorize, path_rejection, unexpected_outcome};

/// `GET /api/v1/commits/pending`.
pub const PENDING_PATH: &str = "/api/v1/commits/pending";

/// The path of the commit-confirm mutation.
pub const CONFIRM_PATH: &str = "/api/v1/commits/{id}/confirm";

/// `POST /api/v1/commits/{id}/rollback`.
pub const ROLLBACK_PATH: &str = "/api/v1/commits/{id}/rollback";

/// This module's routes.
#[must_use]
pub fn table() -> Vec<crate::auth::routes::Route> {
    use crate::auth::routes::Route;
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: PENDING_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: CONFIRM_PATH,
            mutating: true,
        },
        Route {
            method: Method::POST,
            path: ROLLBACK_PATH,
            mutating: true,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PENDING_PATH, get(pending))
        .route(CONFIRM_PATH, post(confirm))
        .route(ROLLBACK_PATH, post(rollback))
}

/// `GET /api/v1/commits/pending`.
#[cfg_attr(test, utoipa::path(
    get,
    path = PENDING_PATH,
    tag = "commits",
    responses(
        (status = 200, description = "The active commit-confirm window, if any", body = Option<PendingCommit>),
        (status = 401, description = "No credential", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn pending(
    State(state): State<AppState>,
    _caller: Caller,
) -> Result<Json<Option<PendingCommit>>, ApiError> {
    Ok(Json(state.engine.pending_commit().await?))
}

/// Answer to `ConfirmCommit`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct CommitConfirmedView {
    /// The commit that is now final.
    pub commit_id: u32,
}

/// Answer to `RollbackCommit`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct RolledBackView {
    /// The commit that was rolled back.
    pub commit_id: u32,
    /// How many targets were actually restored.
    pub restored: u16,
}

/// `POST /api/v1/commits/{id}/confirm`.
#[cfg_attr(test, utoipa::path(
    post,
    path = CONFIRM_PATH,
    tag = "commits",
    params(("id" = u32, Path, description = "Commit id `Apply` returned")),
    responses(
        (status = 200, description = "The commit is now final", body = CommitConfirmedView),
        (status = 409, description = "No such commit is pending", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn confirm(
    State(state): State<AppState>,
    caller: WriteCaller,
    id: Result<Path<u32>, PathRejection>,
) -> Result<Json<CommitConfirmedView>, ApiError> {
    let Path(raw) = id.map_err(path_rejection)?;
    let op = Operation::ConfirmCommit {
        commit_id: CommitId(raw),
    };
    authorize(&state, caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(
            op,
            caller.caller().identity().clone(),
            caller.caller().authz(),
        )
        .await?;
    render_confirmed(&outcome)
}

/// The `OpOutcome::CommitConfirmed` branch, pulled out of [`confirm`] so it
/// can be exercised with a synthetic outcome: the fixture this crate's own
/// tests use never has a commit pending, so a real `CommitConfirmed` outcome
/// never reaches [`confirm`] itself.
fn render_confirmed(outcome: &OpOutcome) -> Result<Json<CommitConfirmedView>, ApiError> {
    match outcome {
        OpOutcome::CommitConfirmed { commit_id } => Ok(Json(CommitConfirmedView {
            commit_id: commit_id.get(),
        })),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/commits/{id}/rollback`.
#[cfg_attr(test, utoipa::path(
    post,
    path = ROLLBACK_PATH,
    tag = "commits",
    params(("id" = u32, Path, description = "Commit id `Apply` returned")),
    responses(
        (status = 200, description = "Every write since the commit was armed is undone", body = RolledBackView),
        (status = 409, description = "No such commit is pending", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn rollback(
    State(state): State<AppState>,
    caller: WriteCaller,
    id: Result<Path<u32>, PathRejection>,
) -> Result<Json<RolledBackView>, ApiError> {
    let Path(raw) = id.map_err(path_rejection)?;
    let op = Operation::RollbackCommit {
        commit_id: CommitId(raw),
    };
    authorize(&state, caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(
            op,
            caller.caller().identity().clone(),
            caller.caller().authz(),
        )
        .await?;
    render_rolled_back(&outcome)
}

/// The `OpOutcome::RolledBack` branch, pulled out of [`rollback`] for the
/// same reason [`render_confirmed`] is pulled out of [`confirm`].
fn render_rolled_back(outcome: &OpOutcome) -> Result<Json<RolledBackView>, ApiError> {
    match outcome {
        OpOutcome::RolledBack {
            commit_id,
            restored,
        } => Ok(Json(RolledBackView {
            commit_id: commit_id.get(),
            restored: *restored,
        })),
        _ => Err(unexpected_outcome()),
    }
}

#[cfg(test)]
mod tests {
    use super::{PENDING_PATH, render_confirmed, render_rolled_back, table};
    use axum::http::Method;
    use detent_ops::OpOutcome;
    use detent_platform::privsep::proto::CommitId;

    #[test]
    fn the_pending_route_is_a_read_only_get() -> Result<(), Box<dyn std::error::Error>> {
        let route = table()
            .into_iter()
            .find(|route| route.path == PENDING_PATH)
            .ok_or("pending route must be registered")?;
        assert_eq!(route.method, Method::GET);
        assert!(!route.mutating);
        Ok(())
    }

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::Modules(Vec::new())
    }

    #[test]
    fn render_confirmed_maps_the_matching_outcome_and_rejects_any_other() {
        let outcome = OpOutcome::CommitConfirmed {
            commit_id: CommitId(7),
        };
        let result = render_confirmed(&outcome);
        assert!(result.is_ok(), "expected the matching outcome to render");
        if let Ok(axum::Json(view)) = result {
            assert_eq!(view.commit_id, 7);
        }
        assert!(
            render_confirmed(&wrong_outcome()).is_err(),
            "a mismatched outcome must not be rendered"
        );
    }

    #[test]
    fn render_rolled_back_maps_the_matching_outcome_and_rejects_any_other() {
        let outcome = OpOutcome::RolledBack {
            commit_id: CommitId(9),
            restored: 2,
        };
        let result = render_rolled_back(&outcome);
        assert!(result.is_ok(), "expected the matching outcome to render");
        if let Ok(axum::Json(view)) = result {
            assert_eq!(view.commit_id, 9);
            assert_eq!(view.restored, 2);
        }
        assert!(
            render_rolled_back(&wrong_outcome()).is_err(),
            "a mismatched outcome must not be rendered"
        );
    }
}
