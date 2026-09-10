//! `/api/v1/system/profile` and `/api/v1/audit`: read-only host and history
//! views. Neither route ever mutates.

use axum::Json;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::routing::get;
use detent_ops::audit::{AuditQuery, AuditRecord};
use detent_ops::report::HostReport;
use detent_ops::{OpOutcome, Operation};
use serde::Deserialize;

use crate::auth::extract::Caller;
use crate::error::ApiError;
use crate::state::AppState;

use super::{authorize, bad_request, query_rejection, unexpected_outcome};

/// `GET /api/v1/system/profile`.
pub const PROFILE_PATH: &str = "/api/v1/system/profile";

/// `GET /api/v1/audit`.
pub const AUDIT_PATH: &str = "/api/v1/audit";

/// Longest `module` or `who` filter accepted in the audit query string.
pub const MAX_FILTER_LEN: usize = 128;

/// Most records `?limit=` may ask for in one answer.
pub const MAX_AUDIT_LIMIT: usize = 1000;

/// This module's routes.
#[must_use]
pub fn table() -> Vec<crate::auth::routes::Route> {
    use crate::auth::routes::Route;
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: PROFILE_PATH,
            mutating: false,
        },
        Route {
            method: Method::GET,
            path: AUDIT_PATH,
            mutating: false,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PROFILE_PATH, get(profile))
        .route(AUDIT_PATH, get(audit))
}

/// The query string of `GET /api/v1/audit`.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[serde(default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AuditQueryParams {
    /// Only records about this module. At most [`MAX_FILTER_LEN`] bytes.
    pub module: Option<String>,
    /// Only records from this subject. At most [`MAX_FILTER_LEN`] bytes.
    pub who: Option<String>,
    /// At most this many records, newest first, capped at
    /// [`MAX_AUDIT_LIMIT`].
    pub limit: Option<usize>,
}

impl AuditQueryParams {
    /// Whether every field is inside its bound.
    fn within_limits(&self) -> bool {
        self.module
            .as_ref()
            .is_none_or(|m| m.len() <= MAX_FILTER_LEN)
            && self.who.as_ref().is_none_or(|w| w.len() <= MAX_FILTER_LEN)
            && self.limit.is_none_or(|limit| limit <= MAX_AUDIT_LIMIT)
    }
}

impl From<AuditQueryParams> for AuditQuery {
    fn from(params: AuditQueryParams) -> Self {
        Self {
            module: params.module,
            who: params.who,
            limit: params.limit,
        }
    }
}

/// `GET /api/v1/system/profile`.
#[utoipa::path(
    get,
    path = PROFILE_PATH,
    tag = "system",
    responses((status = 200, description = "What was detected about this host", body = HostReport)),
)]
pub(super) async fn profile(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Box<HostReport>>, ApiError> {
    let op = Operation::HostProfile;
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_host(outcome)
}

/// The `OpOutcome::Host` branch, pulled out of [`profile`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_host(outcome: OpOutcome) -> Result<Json<Box<HostReport>>, ApiError> {
    match outcome {
        OpOutcome::Host(report) => Ok(Json(report)),
        _ => Err(unexpected_outcome()),
    }
}

/// `GET /api/v1/audit`.
#[utoipa::path(
    get,
    path = AUDIT_PATH,
    tag = "system",
    params(AuditQueryParams),
    responses((status = 200, description = "Matching audit records, newest first", body = Vec<AuditRecord>)),
)]
pub(super) async fn audit(
    State(state): State<AppState>,
    caller: Caller,
    query: Result<Query<AuditQueryParams>, QueryRejection>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    let Query(params) = query.map_err(query_rejection)?;
    if !params.within_limits() {
        return Err(bad_request());
    }
    let op = Operation::AuditQuery(params.into());
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_audit(outcome)
}

/// The `OpOutcome::Audit` branch, pulled out of [`audit`] so the mismatch arm
/// can be exercised with a synthetic outcome.
fn render_audit(outcome: OpOutcome) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    match outcome {
        OpOutcome::Audit(records) => Ok(Json(records)),
        _ => Err(unexpected_outcome()),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditQueryParams, MAX_AUDIT_LIMIT, MAX_FILTER_LEN, render_audit, render_host};
    use detent_core::descriptor::HostProfile;
    use detent_ops::OpOutcome;
    use detent_ops::audit::AuditQuery;
    use detent_ops::report::HostReport;
    use detent_platform::privsep::proto::CommitId;

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::CommitConfirmed {
            commit_id: CommitId(0),
        }
    }

    #[test]
    fn render_host_maps_the_matching_outcome_and_rejects_any_other() {
        let report = HostReport {
            profile: HostProfile::default(),
            distro_id: None,
            distro_version_id: None,
            network_backend: "unknown",
            resolver_backend: "unknown",
            notes: Vec::new(),
        };
        assert!(render_host(OpOutcome::Host(Box::new(report))).is_ok());
        assert!(render_host(wrong_outcome()).is_err());
    }

    #[test]
    fn render_audit_maps_the_matching_outcome_and_rejects_any_other() {
        assert!(render_audit(OpOutcome::Audit(Vec::new())).is_ok());
        assert!(render_audit(wrong_outcome()).is_err());
    }

    #[test]
    fn query_params_are_bounded() {
        let within = AuditQueryParams {
            module: Some("hosts".to_owned()),
            who: Some("alice".to_owned()),
            limit: Some(10),
        };
        assert_eq!(
            AuditQuery::from(within.clone()),
            AuditQuery {
                module: Some("hosts".to_owned()),
                who: Some("alice".to_owned()),
                limit: Some(10),
            }
        );
        assert!(within.within_limits());

        let oversized_module = AuditQueryParams {
            module: Some("x".repeat(MAX_FILTER_LEN + 1)),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_module.within_limits());

        let oversized_who = AuditQueryParams {
            who: Some("x".repeat(MAX_FILTER_LEN + 1)),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_who.within_limits());

        let oversized_limit = AuditQueryParams {
            limit: Some(MAX_AUDIT_LIMIT + 1),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_limit.within_limits());
    }
}
