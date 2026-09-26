//! `/api/v1/modules/{id}/backups[/{backup_id}/restore]`.
//!
//! ```text
//!   GET  /modules/{id}/backups                    ─▶ ListBackups ─▶ newest first
//!   POST /modules/{id}/backups/{backup_id}/restore ─▶ Restore    ─▶ writes the target
//! ```

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use detent_ops::{OpOutcome, Operation};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::privsep::proto::{BackupId, BackupInfo};
use serde::{Deserialize, Serialize};

use crate::auth::extract::{Caller, WriteCaller};
use crate::error::ApiError;
use crate::state::AppState;

use super::modules::parse_hash;
use super::{
    authorize, json_rejection, path_rejection, unexpected_outcome, unknown_module, well_formed_id,
};

/// `GET /api/v1/modules/{id}/backups`.
pub const LIST_PATH: &str = "/api/v1/modules/{id}/backups";

/// `POST /api/v1/modules/{id}/backups/{backup_id}/restore`.
pub const RESTORE_PATH: &str = "/api/v1/modules/{id}/backups/{backup_id}/restore";

/// This module's routes.
#[must_use]
pub fn table() -> Vec<crate::auth::routes::Route> {
    use crate::auth::routes::Route;
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: LIST_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: RESTORE_PATH,
            mutating: true,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(LIST_PATH, get(list))
        .route(RESTORE_PATH, post(restore))
}

/// Answer to `Restore`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct RestoredView {
    /// The target that was put back, as the monitor's index for it.
    pub target: u16,
    /// Digest now on disk, 64 lowercase hex characters.
    pub new_hash: String,
}

/// The body of `POST /api/v1/modules/{id}/backups/{backup_id}/restore`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    /// Digest the caller last read, as 64 lowercase hex characters.
    #[cfg_attr(test, schema(min_length = 64, max_length = 64))]
    pub expected_hash: String,
}

/// `GET /api/v1/modules/{id}/backups`.
#[cfg_attr(test, utoipa::path(
    get,
    path = LIST_PATH,
    tag = "backups",
    // Explicit: see the note on `modules::list`.
    operation_id = "list_backups",
    params(("id" = String, Path, description = "Module id")),
    responses(
        (status = 200, description = "The module's retained backups, newest first", body = Vec<BackupInfo>),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn list(
    State(state): State<AppState>,
    caller: Caller,
    id: Result<Path<String>, PathRejection>,
) -> Result<Json<Vec<BackupInfo>>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    let op = Operation::ListBackups { id };
    authorize(&state, &caller, &op)?;
    let outcome = state
        .engine
        .execute(op, caller.identity().clone(), caller.authz())
        .await?;
    render_backups(outcome)
}

/// The `OpOutcome::Backups` branch, pulled out of [`list`] so it can be
/// exercised with a synthetic outcome: the fixture this crate's own tests
/// use registers no module, so a real `Backups` outcome never reaches
/// [`list`] itself (`ListBackups` always fails `find_module` first).
fn render_backups(outcome: OpOutcome) -> Result<Json<Vec<BackupInfo>>, ApiError> {
    match outcome {
        OpOutcome::Backups(backups) => Ok(Json(backups)),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/modules/{id}/backups/{backup_id}/restore`.
#[cfg_attr(test, utoipa::path(
    post,
    path = RESTORE_PATH,
    tag = "backups",
    params(
        ("id" = String, Path, description = "Module id"),
        ("backup_id" = u32, Path, description = "Index into `GET .../backups`"),
    ),
    request_body = RestoreRequest,
    responses(
        (status = 200, description = "The backup was put back", body = RestoredView),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
        (status = 409, description = "The target changed since `expected_hash` was read", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn restore(
    State(state): State<AppState>,
    caller: WriteCaller,
    path: Result<Path<(String, u32)>, PathRejection>,
    body: Result<Json<RestoreRequest>, JsonRejection>,
) -> Result<Json<RestoredView>, ApiError> {
    let Path((id, backup_id)) = path.map_err(path_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    let Json(request) = body.map_err(json_rejection)?;
    let expected_hash = Some(parse_hash(&request.expected_hash)?);
    let op = Operation::Restore {
        id,
        backup_id: BackupId(backup_id),
        expected_hash,
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
    render_restored(&outcome)
}

/// The `OpOutcome::Restored` branch, pulled out of [`restore`] for the same
/// reason [`render_backups`] is pulled out of [`list`].
fn render_restored(outcome: &OpOutcome) -> Result<Json<RestoredView>, ApiError> {
    match outcome {
        OpOutcome::Restored { target, new_hash } => Ok(Json(RestoredView {
            target: target.get(),
            new_hash: render_hash(new_hash),
        })),
        _ => Err(unexpected_outcome()),
    }
}

fn render_hash(hash: &Sha256Digest) -> String {
    hash.to_string()
}

#[cfg(test)]
mod tests {
    use super::{render_backups, render_restored};
    use detent_ops::OpOutcome;
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::privsep::proto::{BackupId, BackupInfo, TargetId};

    fn a_backup() -> BackupInfo {
        BackupInfo {
            id: BackupId(0),
            target: TargetId(0),
            name: "hosts.20260101".to_owned(),
            created_unix_s: 0,
            digest: Sha256Digest::of(b"x"),
            len: 1,
        }
    }

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::Modules(Vec::new())
    }

    #[test]
    fn render_backups_maps_the_matching_outcome_and_rejects_any_other() {
        let backups = vec![a_backup()];
        let result = render_backups(OpOutcome::Backups(backups.clone()));
        assert!(result.is_ok(), "expected the matching outcome to render");
        if let Ok(axum::Json(rendered)) = result {
            assert_eq!(rendered, backups);
        }
        assert!(
            render_backups(wrong_outcome()).is_err(),
            "a mismatched outcome must not be rendered"
        );
    }

    #[test]
    fn render_restored_maps_the_matching_outcome_and_rejects_any_other() {
        let digest = Sha256Digest::of(b"y");
        let outcome = OpOutcome::Restored {
            target: TargetId(3),
            new_hash: digest,
        };
        let result = render_restored(&outcome);
        assert!(result.is_ok(), "expected the matching outcome to render");
        if let Ok(axum::Json(view)) = result {
            assert_eq!(view.target, 3);
            assert_eq!(view.new_hash, digest.to_string());
        }
        assert!(
            render_restored(&wrong_outcome()).is_err(),
            "a mismatched outcome must not be rendered"
        );
    }
}
