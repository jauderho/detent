//! `/api/v1/services/{id}`: read or act on a module's service.
//!
//! ```text
//!   GET  /services/{id} ─▶ ServiceStatus ─▶ run state, never mutates
//!   POST /services/{id} ─▶ ServiceAction ─▶ start/stop/restart/reload
//! ```
//!
//! `{id}` is a module id, not a separate service id: PLAN §2.3 binds at most
//! one service per module, so the module id is what the registry advertises.

use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::routing::get;
use detent_ops::report::ServiceReport;
use detent_ops::{OpOutcome, Operation};
use detent_platform::service::ServiceStatus;
use serde::Deserialize;

use crate::auth::extract::{Caller, WriteCaller};
use crate::error::ApiError;
use crate::state::AppState;

use super::{
    ApiServiceCommand, authorize, json_rejection, path_rejection, unexpected_outcome,
    unknown_module, well_formed_id,
};

/// `GET|POST /api/v1/services/{id}`.
pub const PATH: &str = "/api/v1/services/{id}";

/// This module's routes.
#[must_use]
pub fn table() -> Vec<crate::auth::routes::Route> {
    use crate::auth::routes::Route;
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: PATH,
            mutating: true,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new().route(PATH, get(status).post(action))
}

/// The body of `POST /api/v1/services/{id}`.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceActionRequest {
    /// What to do.
    pub action: ApiServiceCommand,
}

/// `GET /api/v1/services/{id}`.
#[utoipa::path(
    get,
    path = PATH,
    tag = "services",
    params(("id" = String, Path, description = "Module id")),
    responses(
        (status = 200, description = "The service's run state", body = ServiceStatus),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
        (status = 409, description = "The module declares no service", body = crate::error::ErrorBody),
    ),
)]
pub(super) async fn status(
    State(state): State<AppState>,
    caller: Caller,
    id: Result<Path<String>, PathRejection>,
) -> Result<Json<ServiceStatus>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    let op = Operation::ServiceStatus { id };
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_status(outcome)
}

/// The `OpOutcome::Status` branch, pulled out of [`status`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_status(outcome: OpOutcome) -> Result<Json<ServiceStatus>, ApiError> {
    match outcome {
        OpOutcome::Status(status) => Ok(Json(status)),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/services/{id}`.
#[utoipa::path(
    post,
    path = PATH,
    tag = "services",
    params(("id" = String, Path, description = "Module id")),
    request_body = ServiceActionRequest,
    responses(
        (status = 200, description = "What happened to the service", body = ServiceReport),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
        (status = 409, description = "The module declares no service", body = crate::error::ErrorBody),
    ),
)]
pub(super) async fn action(
    State(state): State<AppState>,
    caller: WriteCaller,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ServiceActionRequest>, JsonRejection>,
) -> Result<Json<ServiceReport>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    let Json(request) = body.map_err(json_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    let op = Operation::ServiceAction {
        id,
        action: request.action.into(),
    };
    authorize(caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(op, caller.caller().identity().clone())
        .await?;
    render_serviced(outcome)
}

/// The `OpOutcome::Serviced` branch, pulled out of [`action`] so the
/// mismatch arm can be exercised with a synthetic outcome.
fn render_serviced(outcome: OpOutcome) -> Result<Json<ServiceReport>, ApiError> {
    match outcome {
        OpOutcome::Serviced(report) => Ok(Json(report)),
        _ => Err(unexpected_outcome()),
    }
}

#[cfg(test)]
mod tests {
    use super::{render_serviced, render_status};
    use detent_ops::OpOutcome;
    use detent_ops::op::ServiceCommand;
    use detent_ops::report::ServiceReport;
    use detent_platform::privsep::proto::CommitId;
    use detent_platform::service::{ServiceStatus, State};

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::CommitConfirmed {
            commit_id: CommitId(0),
        }
    }

    #[test]
    fn render_status_maps_the_matching_outcome_and_rejects_any_other() {
        let status = ServiceStatus {
            unit: "chronyd.service".to_owned(),
            state: State::Active,
            enabled: Some(true),
            since: None,
        };
        assert!(render_status(OpOutcome::Status(status)).is_ok());
        assert!(render_status(wrong_outcome()).is_err());
    }

    #[test]
    fn render_serviced_maps_the_matching_outcome_and_rejects_any_other() {
        let report = ServiceReport {
            unit: "chronyd.service".to_owned(),
            action: ServiceCommand::Restart,
            active: true,
            detail: "running".to_owned(),
        };
        assert!(render_serviced(OpOutcome::Serviced(report)).is_ok());
        assert!(render_serviced(wrong_outcome()).is_err());
    }
}
