//! `/api/v1/modules` and `/api/v1/modules/{id}[/validate|plan|apply]`.
//!
//! ```text
//!   GET  /modules             ─▶ ListModules  ─▶ every compiled-in descriptor
//!   GET  /modules/{id}        ─▶ GetModule    ─▶ descriptor, schema, model, diagnostics
//!   POST /modules/{id}/validate ─▶ Validate   ─▶ diagnostics only, writes nothing
//!   POST /modules/{id}/plan     ─▶ Plan       ─▶ diff + checks, writes nothing
//!   POST /modules/{id}/apply    ─▶ Apply      ─▶ writes the target (WriteCaller)
//! ```
//!
//! # Guarantees
//!
//! * **`validate` and `plan` never write.** Both take a plain [`Caller`]
//!   (read scope), matching [`crate::authz::ScopedAuthz::required_scope`];
//!   only `apply` takes [`WriteCaller`].
//! * **A rejected apply carries its diagnostics.** [`OpsError::Invalid`]
//!   answers 422 with the findings attached, via
//!   `ApiError::from(OpsError::Invalid { .. })` — see [`crate::error`].

use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use detent_core::descriptor::ModuleDescriptor;
use detent_ops::report::{ApplyReport, ModuleView, PlanReport};
use detent_ops::{OpOutcome, Operation};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::routes::Route;
use crate::error::ApiError;
use crate::state::AppState;

use super::{
    ApiServiceCommand, authorize, bad_request, check_depth, json_rejection, path_rejection,
    unexpected_outcome, unknown_module, well_formed_id,
};

/// `GET /api/v1/modules`.
pub const LIST_PATH: &str = "/api/v1/modules";

/// `GET /api/v1/modules/{id}`.
pub const GET_PATH: &str = "/api/v1/modules/{id}";

/// `POST /api/v1/modules/{id}/validate`.
pub const VALIDATE_PATH: &str = "/api/v1/modules/{id}/validate";

/// `POST /api/v1/modules/{id}/plan`.
pub const PLAN_PATH: &str = "/api/v1/modules/{id}/plan";

/// `POST /api/v1/modules/{id}/apply`.
pub const APPLY_PATH: &str = "/api/v1/modules/{id}/apply";

/// Longest hex-encoded digest this endpoint accepts: exactly a SHA-256 in
/// lowercase hex, no more and no less.
pub const HASH_HEX_LEN: usize = 64;

/// This module's routes.
#[must_use]
pub fn table() -> Vec<Route> {
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: LIST_PATH,
            mutating: false,
        },
        Route {
            method: Method::GET,
            path: GET_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: VALIDATE_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: PLAN_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: APPLY_PATH,
            mutating: true,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(LIST_PATH, get(list))
        .route(GET_PATH, get(get_one))
        .route(VALIDATE_PATH, post(validate))
        .route(PLAN_PATH, post(plan))
        .route(APPLY_PATH, post(apply))
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// The body of `POST /api/v1/modules/{id}/validate` and `.../plan`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    /// The candidate model, exactly as the shape `GET /modules/{id}`'s
    /// `schema` field describes.
    #[cfg_attr(test, schema(value_type = Object))]
    pub model: Value,
}

/// The body of `POST /api/v1/modules/{id}/apply`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    /// The candidate model.
    #[cfg_attr(test, schema(value_type = Object))]
    pub model: Value,
    /// Digest the caller last read, as 64 lowercase hex characters. A
    /// mismatch is refused (409) rather than silently overwriting somebody
    /// else's edit.
    #[serde(default)]
    #[cfg_attr(test, schema(max_length = 64))]
    pub expected_hash: Option<String>,
    /// What to do to the module's service afterwards.
    #[serde(default)]
    pub service_action: Option<ApiServiceCommand>,
    /// Commit-confirm window, in seconds. Omitted uses the module's default;
    /// the monitor clamps whatever is armed either way.
    #[serde(default)]
    pub confirm_secs: Option<u64>,
}

/// Parse and check `hex` as a lowercase SHA-256 digest.
///
/// # Errors
///
/// A 400 [`ApiError`] when `hex` is not exactly [`HASH_HEX_LEN`] hex digits.
fn parse_hash(hex: &str) -> Result<detent_platform::fs::atomic::Sha256Digest, ApiError> {
    use std::str::FromStr as _;
    if hex.len() != HASH_HEX_LEN {
        return Err(bad_request());
    }
    detent_platform::fs::atomic::Sha256Digest::from_str(hex).map_err(|_| bad_request())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/modules`.
#[cfg_attr(test, utoipa::path(
    get,
    path = LIST_PATH,
    tag = "modules",
    // Explicit because utoipa derives the operationId from the function name,
    // and `backups::list` is also called `list`. Two operations sharing an
    // operationId is invalid OpenAPI, and a generated client collapses them
    // into one mistyped call.
    operation_id = "list_modules",
    responses((status = 200, description = "Every module compiled into this build", body = Vec<ModuleDescriptor>)),
))]
pub(super) async fn list(
    State(state): State<AppState>,
    caller: crate::auth::extract::Caller,
) -> Result<Json<Vec<&'static ModuleDescriptor>>, ApiError> {
    let op = Operation::ListModules;
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_modules(outcome)
}

/// The `OpOutcome::Modules` branch, pulled out of [`list`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_modules(outcome: OpOutcome) -> Result<Json<Vec<&'static ModuleDescriptor>>, ApiError> {
    match outcome {
        OpOutcome::Modules(modules) => Ok(Json(modules)),
        _ => Err(unexpected_outcome()),
    }
}

/// `GET /api/v1/modules/{id}`.
#[cfg_attr(test, utoipa::path(
    get,
    path = GET_PATH,
    tag = "modules",
    params(("id" = String, Path, description = "Module id")),
    responses(
        (status = 200, description = "The module's descriptor, schema, current model and diagnostics", body = ModuleView),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn get_one(
    State(state): State<AppState>,
    caller: crate::auth::extract::Caller,
    id: Result<Path<String>, PathRejection>,
) -> Result<Json<Box<ModuleView>>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    let op = Operation::GetModule { id };
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_module(outcome)
}

/// The `OpOutcome::Module` branch, pulled out of [`get_one`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_module(outcome: OpOutcome) -> Result<Json<Box<ModuleView>>, ApiError> {
    match outcome {
        OpOutcome::Module(view) => Ok(Json(view)),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/modules/{id}/validate`.
#[cfg_attr(test, utoipa::path(
    post,
    path = VALIDATE_PATH,
    tag = "modules",
    params(("id" = String, Path, description = "Module id")),
    request_body = ModelRequest,
    responses(
        (status = 200, description = "Validation findings for the candidate model", body = detent_core::diag::Diagnostics),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn validate(
    State(state): State<AppState>,
    caller: crate::auth::extract::Caller,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ModelRequest>, JsonRejection>,
) -> Result<Json<detent_core::diag::Diagnostics>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    let Json(request) = body.map_err(json_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    check_depth(&request.model)?;
    let op = Operation::Validate {
        id,
        model: request.model,
    };
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_validated(outcome)
}

/// The `OpOutcome::Validated` branch, pulled out of [`validate`] so the
/// mismatch arm can be exercised with a synthetic outcome.
fn render_validated(outcome: OpOutcome) -> Result<Json<detent_core::diag::Diagnostics>, ApiError> {
    match outcome {
        OpOutcome::Validated(diagnostics) => Ok(Json(diagnostics)),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/modules/{id}/plan`.
#[cfg_attr(test, utoipa::path(
    post,
    path = PLAN_PATH,
    tag = "modules",
    params(("id" = String, Path, description = "Module id")),
    request_body = ModelRequest,
    responses(
        (status = 200, description = "Diff and validator results; nothing is written", body = PlanReport),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn plan(
    State(state): State<AppState>,
    caller: crate::auth::extract::Caller,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ModelRequest>, JsonRejection>,
) -> Result<Json<Box<PlanReport>>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    let Json(request) = body.map_err(json_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    check_depth(&request.model)?;
    let op = Operation::Plan {
        id,
        model: request.model,
    };
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
    render_planned(outcome)
}

/// The `OpOutcome::Planned` branch, pulled out of [`plan`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_planned(outcome: OpOutcome) -> Result<Json<Box<PlanReport>>, ApiError> {
    match outcome {
        OpOutcome::Planned(report) => Ok(Json(report)),
        _ => Err(unexpected_outcome()),
    }
}

/// `POST /api/v1/modules/{id}/apply`.
#[cfg_attr(test, utoipa::path(
    post,
    path = APPLY_PATH,
    tag = "modules",
    params(("id" = String, Path, description = "Module id")),
    request_body = ApplyRequest,
    responses(
        (status = 200, description = "What was written, and any service action or commit-confirm window", body = ApplyReport),
        (status = 404, description = "No such module", body = crate::error::ErrorBody),
        (status = 409, description = "The target changed since `expected_hash` was read", body = crate::error::ErrorBody),
        (status = 422, description = "The candidate has at least one error diagnostic", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn apply(
    State(state): State<AppState>,
    caller: crate::auth::extract::WriteCaller,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ApplyRequest>, JsonRejection>,
) -> Result<Json<Box<ApplyReport>>, ApiError> {
    let Path(id) = id.map_err(path_rejection)?;
    let Json(request) = body.map_err(json_rejection)?;
    if !well_formed_id(&id) {
        return Err(unknown_module(&id));
    }
    check_depth(&request.model)?;
    let expected_hash = request
        .expected_hash
        .as_deref()
        .map(parse_hash)
        .transpose()?;
    let op = Operation::Apply {
        id,
        model: request.model,
        expected_hash,
        service_action: request.service_action.map(Into::into),
        confirm: request.confirm_secs.map(std::time::Duration::from_secs),
    };
    authorize(caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(op, caller.caller().identity().clone())
        .await?;
    render_applied(outcome)
}

/// The `OpOutcome::Applied` branch, pulled out of [`apply`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_applied(outcome: OpOutcome) -> Result<Json<Box<ApplyReport>>, ApiError> {
    match outcome {
        OpOutcome::Applied(report) => Ok(Json(report)),
        _ => Err(unexpected_outcome()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HASH_HEX_LEN, parse_hash, render_applied, render_module, render_modules, render_planned,
        render_validated,
    };
    use detent_core::descriptor::{ModuleDescriptor, Upstream};
    use detent_core::diag::{Diagnostics, MessageId};
    use detent_ops::OpOutcome;
    use detent_ops::report::{AffectedService, ApplyReport, ModuleView, PlanReport};
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::privsep::proto::CommitId;

    /// A minimal descriptor for tests that need `&'static ModuleDescriptor`
    /// but not a real, compiled-in module.
    static TEST_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
        id: "test",
        display_name_id: MessageId::new("web-request-malformed"),
        targets: &[],
        upstream: Upstream {
            project: "test",
            repo_url: "https://example.invalid",
            tracked_version: "0",
            release_feed: None,
            docs: &[],
        },
        services: &[],
        checks: &[],
        commit_confirm: false,
        security_notes: &[],
    };

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::CommitConfirmed {
            commit_id: CommitId(0),
        }
    }

    #[test]
    fn render_modules_maps_the_matching_outcome_and_rejects_any_other() {
        assert!(render_modules(OpOutcome::Modules(Vec::new())).is_ok());
        assert!(render_modules(wrong_outcome()).is_err());
    }

    #[test]
    fn render_module_maps_the_matching_outcome_and_rejects_any_other() {
        let view = ModuleView {
            descriptor: &TEST_DESCRIPTOR,
            schema: serde_json::json!({}),
            model: None,
            current_hash: None,
            diagnostics: Diagnostics::default(),
        };
        assert!(render_module(OpOutcome::Module(Box::new(view))).is_ok());
        assert!(render_module(wrong_outcome()).is_err());
    }

    #[test]
    fn render_validated_maps_the_matching_outcome_and_rejects_any_other() {
        assert!(render_validated(OpOutcome::Validated(Diagnostics::default())).is_ok());
        assert!(render_validated(wrong_outcome()).is_err());
    }

    #[test]
    fn render_planned_maps_the_matching_outcome_and_rejects_any_other() {
        let report = PlanReport {
            module: "hosts".to_owned(),
            path: "/etc/hosts".to_owned(),
            diff: Vec::new(),
            rendered: String::new(),
            unified_diff: String::new(),
            affected_services: Vec::<AffectedService>::new(),
            checks: Vec::new(),
            diagnostics: Diagnostics::default(),
            current_hash: Sha256Digest::of(b"x"),
            would_change: false,
        };
        assert!(render_planned(OpOutcome::Planned(Box::new(report))).is_ok());
        assert!(render_planned(wrong_outcome()).is_err());
    }

    #[test]
    fn render_applied_maps_the_matching_outcome_and_rejects_any_other() {
        let report = ApplyReport {
            module: "hosts".to_owned(),
            path: "/etc/hosts".to_owned(),
            prev_hash: None,
            new_hash: Sha256Digest::of(b"x"),
            created: true,
            backed_up: false,
            service: None,
            commit: None,
        };
        assert!(render_applied(OpOutcome::Applied(Box::new(report))).is_ok());
        assert!(render_applied(wrong_outcome()).is_err());
    }

    #[test]
    fn parse_hash_accepts_exactly_64_lowercase_hex_and_rejects_everything_else() {
        let good = Sha256Digest::of(b"x").to_string();
        assert_eq!(good.len(), HASH_HEX_LEN);
        assert!(parse_hash(&good).is_ok());
        assert!(parse_hash("too-short").is_err());
        assert!(parse_hash(&"g".repeat(HASH_HEX_LEN)).is_err());
    }
}
