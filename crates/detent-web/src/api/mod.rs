//! `/api/v1`: the thirteen `Operation` endpoints (PLAN §2.6, §2.7, Phase 4).
//!
//! ```text
//!   Path/Query/Json extractor ──▶ typed, bounded, deny_unknown_fields
//!            │
//!            ▼
//!   id shape checked against the registry's own charset ──▶ 404 early
//!            │
//!            ▼
//!   one Operation ──▶ caller.authz().permit() ──▶ engine.execute() ──▶ OpOutcome
//!            │                  │                        │
//!         403 Denied      (already enforced by       ApiError::from
//!                          WriteCaller/Caller too;    (never a raw 500 for a
//!                          this is the belt to its    client mistake — see
//!                          type-level braces)         `crate::error`)
//! ```
//!
//! Every handler here is thin by design (PLAN Phase 4 task 4): extract,
//! validate the shape of what arrived, build exactly one [`Operation`],
//! authorize it explicitly, hand it to [`EngineHandle::execute`], and map the
//! [`OpOutcome`] variant the engine is contractually guaranteed to answer with
//! back to a typed JSON body. No handler touches a file or a service manager;
//! that is [`detent_ops::OpsEngine`]'s job alone.
//!
//! # Guarantees
//!
//! * **A `GET` route never mutates.** [`table`] merges every submodule's
//!   table, and the test in [`crate::csrf`] walks the merged result.
//! * **A malformed or oversized id never reaches the engine.** A module or
//!   service id is checked against the same charset every compiled-in id
//!   satisfies before it is put in an [`Operation`]; a shape mismatch answers
//!   404 exactly like an id that is well-formed but unregistered — both cases
//!   are "no such module" from the caller's point of view, and neither one
//!   spends an audit-log write on a string the caller invented. See
//!   [`well_formed_id`].
//! * **Every mutating handler authorizes twice, on purpose.** It takes a
//!   [`crate::auth::WriteCaller`] (the type-level guard) *and* calls
//!   [`crate::authz::ScopedAuthz::permit`] itself, so a mismatch between the
//!   route table and the scope policy is a test failure, not a silent grant.
//! * **A JSON body over 256 KiB, with an unknown field, of the wrong type, or
//!   nested past [`MAX_JSON_DEPTH`] is a 400**, never a 500 and never a raw
//!   serde message — see [`json_rejection`] and [`too_deep`].

pub mod backups;
pub mod commits;
#[cfg(test)]
mod integration_tests;
pub mod modules;
pub mod openapi;
pub mod services;
pub mod system;

use axum::Router;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use detent_core::diag::MessageId;
use detent_ops::authz::Authz as _;
use detent_ops::{Operation, OpsError};
use serde::{Deserialize, Serialize};

use crate::auth::extract::Caller;
use crate::auth::routes::Route;
use crate::error::ApiError;
use crate::state::AppState;

/// Fluent id of a request whose shape this endpoint refuses, independent of
/// *why*: an unparsable body, a bad path segment, an unknown query key, or a
/// value past a length or depth bound. Mirrors
/// [`crate::auth::routes::MALFORMED_BODY_ID`], which owns the same id for the
/// auth routes.
pub const MALFORMED_ID: &str = "web-request-malformed";

/// Fluent id of a JSON body nested past [`MAX_JSON_DEPTH`].
pub const TOO_DEEP_ID: &str = "web-request-too-deep";

/// Fluent id answered when the engine's outcome does not match the operation
/// that was sent — unreachable in practice, because each handler sends
/// exactly one [`Operation`] variant, but the match still has to go somewhere
/// if the engine's contract is ever violated.
pub const UNEXPECTED_OUTCOME_ID: &str = "web-api-unexpected-outcome";

/// Longest a module or service id may be, in UTF-8 bytes.
///
/// Every id [`detent_core::descriptor::ModuleDescriptor`] declares is a short
/// static string (`"hosts"`, …); this is a ceiling on a *client-supplied*
/// path segment, generous enough for any id this build ships and nowhere near
/// large enough to be useful as a denial-of-service payload or an audit-log
/// nuisance.
pub const MAX_ID_LEN: usize = 64;

/// How many levels deep a request body's JSON may nest (PLAN §2.7, "Input").
///
/// Bounds the cost of walking a candidate model recursively (rendering,
/// validating, diffing) and keeps a maliciously deep-but-small payload from
/// becoming asymptotically expensive downstream.
pub const MAX_JSON_DEPTH: usize = 32;

/// Whether `id` is shaped like a value [`ModuleDescriptor::id`] could hold:
/// 1 to [`MAX_ID_LEN`] bytes of `[a-z0-9_-]`, first byte alphanumeric.
///
/// This is a **shape** check, not a membership check — the engine's own
/// module table is the only authority on which ids actually exist, and it is
/// asked via [`Operation`] regardless. Rejecting an ill-shaped id here means
/// one that could never have named a module (a path-traversal attempt, a
/// multi-kilobyte string, a control character) never becomes an
/// [`Operation`], never crosses to the engine thread, and — for a mutating
/// operation — never ends up copied into an audit record.
///
/// [`ModuleDescriptor::id`]: detent_core::descriptor::ModuleDescriptor::id
#[must_use]
pub fn well_formed_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_ID_LEN
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// The refusal a malformed or unregistered module/service id answers with:
/// 404, [`OpsError::UnknownModule`]'s own catalogued id, exactly as an id
/// that is well-formed but simply not compiled into this build would.
#[must_use]
pub fn unknown_module(id: &str) -> ApiError {
    ApiError::from(OpsError::UnknownModule { id: id.to_owned() })
}

/// The 400 a malformed request (body, path segment, query string, or a field
/// such as a hex digest that fails its own parse) answers with.
#[must_use]
pub fn bad_request() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, MessageId::new(MALFORMED_ID))
}

/// Turn a [`JsonRejection`] into the one shape a client ever sees: never
/// serde's own message, which quotes the offending bytes back at the caller.
#[must_use]
pub fn json_rejection(_rejection: JsonRejection) -> ApiError {
    bad_request()
}

/// Turn a [`PathRejection`] into the same 400.
#[must_use]
pub fn path_rejection(_rejection: PathRejection) -> ApiError {
    bad_request()
}

/// Turn a [`QueryRejection`] into the same 400.
#[must_use]
pub fn query_rejection(_rejection: QueryRejection) -> ApiError {
    bad_request()
}

/// The 400 a JSON body nested past [`MAX_JSON_DEPTH`] answers with.
#[must_use]
pub fn too_deep() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, MessageId::new(TOO_DEEP_ID))
}

/// The 500 answered when the engine's [`OpOutcome`](detent_ops::OpOutcome)
/// does not match the [`Operation`] that produced it.
#[must_use]
pub fn unexpected_outcome() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MessageId::new(UNEXPECTED_OUTCOME_ID),
    )
}

/// How deeply `value` nests, computed without recursion so that measuring the
/// depth of a hostile payload cannot itself overflow the stack.
#[must_use]
pub fn json_depth(value: &serde_json::Value) -> usize {
    let mut deepest = 0_usize;
    let mut stack: Vec<(&serde_json::Value, usize)> = vec![(value, 1)];
    while let Some((node, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        match node {
            serde_json::Value::Array(items) => {
                stack.extend(items.iter().map(|item| (item, depth.saturating_add(1))));
            }
            serde_json::Value::Object(map) => {
                stack.extend(map.values().map(|item| (item, depth.saturating_add(1))));
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    deepest
}

/// Refuse `model` if it nests past [`MAX_JSON_DEPTH`].
///
/// # Errors
///
/// [`too_deep`] when the bound is exceeded.
pub fn check_depth(model: &serde_json::Value) -> Result<(), ApiError> {
    if json_depth(model) > MAX_JSON_DEPTH {
        return Err(too_deep());
    }
    Ok(())
}

/// Ask the per-request policy about `op`, on top of whatever
/// [`crate::auth::WriteCaller`] already enforced at the type level.
///
/// Every mutating handler calls this before
/// [`EngineHandle::execute`](crate::engine::EngineHandle::execute), so the
/// scope decision always comes from [`crate::authz::ScopedAuthz`] rather than
/// from the route table alone: a mismatch between the two is a test failure,
/// not a silent grant.
///
/// # Errors
///
/// [`ApiError`] (403) when the policy refuses.
pub fn authorize(caller: &Caller, op: &Operation) -> Result<(), ApiError> {
    caller
        .authz()
        .permit(caller.identity(), op)
        .map_err(|denied| ApiError::from(OpsError::Denied(denied)))
}

/// A [`ServiceCommand`](detent_ops::ServiceCommand), as a request body may
/// name it.
///
/// [`detent_ops::ServiceCommand`] cannot derive [`utoipa::ToSchema`] without
/// giving `detent-ops` a dependency on `utoipa`, which PLAN §2.1 forbids: the
/// operations layer stays front-end agnostic. This is the thin mirror that
/// lets a request body have a precise, documented schema anyway; it converts
/// straight to the real type and carries no behaviour of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ApiServiceCommand {
    /// Full restart.
    Restart,
    /// Reload configuration in place.
    Reload,
    /// Start a stopped service.
    Start,
    /// Stop a running service.
    Stop,
}

impl From<ApiServiceCommand> for detent_ops::ServiceCommand {
    fn from(command: ApiServiceCommand) -> Self {
        match command {
            ApiServiceCommand::Restart => Self::Restart,
            ApiServiceCommand::Reload => Self::Reload,
            ApiServiceCommand::Start => Self::Start,
            ApiServiceCommand::Stop => Self::Stop,
        }
    }
}

/// Every route this crate registers under `/api/v1` other than `/auth/*`
/// (owned by [`crate::auth::routes`]).
#[must_use]
pub fn table() -> &'static [Route] {
    static TABLE: std::sync::OnceLock<Vec<Route>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            modules::table(),
            commits::table(),
            backups::table(),
            services::table(),
            system::table(),
            openapi::table(),
        ]
        .concat()
    })
}

/// The whole `/api/v1` surface, ready to be given [`AppState`] and wrapped in
/// [`crate::csrf::csrf_guard`], exactly as [`crate::auth::routes::routes`] is.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(modules::routes())
        .merge(commits::routes())
        .merge(backups::routes())
        .merge(services::routes())
        .merge(system::routes())
        .merge(openapi::routes())
}

#[cfg(test)]
mod tests {
    use super::{
        ApiServiceCommand, MALFORMED_ID, MAX_ID_LEN, TOO_DEEP_ID, UNEXPECTED_OUTCOME_ID,
        check_depth, json_depth, table, unknown_module, well_formed_id,
    };
    use axum::http::{Method, StatusCode};
    use serde_json::json;

    const CATALOGUE: &str = include_str!("../../../../locales/en-US/core.ftl");

    fn catalogue_has(id: &str) -> bool {
        CATALOGUE
            .lines()
            .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id))
    }

    #[test]
    fn every_id_this_module_answers_with_is_catalogued() {
        for id in [
            MALFORMED_ID,
            TOO_DEEP_ID,
            UNEXPECTED_OUTCOME_ID,
            "ops-unknown-module",
        ] {
            assert!(catalogue_has(id), "`{id}` is missing from core.ftl");
        }
    }

    #[test]
    fn well_formed_ids_are_exactly_the_registrys_own_charset() {
        for good in ["hosts", "a", "z9", "a-b_c", &"a".repeat(MAX_ID_LEN)] {
            assert!(well_formed_id(good), "{good:?} was rejected");
        }
        for bad in [
            "",
            "Hosts",
            "-hosts",
            "_hosts",
            "host s",
            "host/s",
            "../../etc/passwd",
            "host\n",
            &"a".repeat(MAX_ID_LEN + 1),
        ] {
            assert!(!well_formed_id(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn an_unknown_module_answers_404_with_the_ops_layer_id() {
        let error = unknown_module("nope");
        assert_eq!(error.status(), StatusCode::NOT_FOUND);
        assert_eq!(error.message_id().as_str(), "ops-unknown-module");
    }

    #[test]
    fn every_api_service_command_converts_to_its_ops_layer_counterpart() {
        use detent_ops::ServiceCommand;
        for (api, ops) in [
            (ApiServiceCommand::Restart, ServiceCommand::Restart),
            (ApiServiceCommand::Reload, ServiceCommand::Reload),
            (ApiServiceCommand::Start, ServiceCommand::Start),
            (ApiServiceCommand::Stop, ServiceCommand::Stop),
        ] {
            assert_eq!(ServiceCommand::from(api), ops);
        }
    }

    #[test]
    fn json_depth_counts_nesting_without_recursing() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(json_depth(&json!(1)), 1);
        // The leaf value is its own level: `[1, [2, [3]]]` bottoms out at the
        // `3` inside two nested arrays inside the outer one — four levels.
        assert_eq!(json_depth(&json!([1, [2, [3]]])), 4);
        assert_eq!(json_depth(&json!({"a": {"b": {"c": 1}}})), 4);
        assert!(check_depth(&json!({"a": 1})).is_ok());

        // A payload nested past the bound, built iteratively so the *test*
        // does not recurse either.
        let mut deep = json!(0);
        for _ in 0..super::MAX_JSON_DEPTH {
            deep = json!([deep]);
        }
        assert!(json_depth(&deep) > super::MAX_JSON_DEPTH);
        let rejected = check_depth(&deep).err().ok_or("expected a refusal")?;
        assert_eq!(rejected.message_id().as_str(), TOO_DEEP_ID);
        Ok(())
    }

    #[test]
    fn the_merged_table_registers_every_endpoint_and_no_get_mutates() {
        // The 13 `Operation` endpoints PLAN Phase 4 lists, plus cert status
        // (read-only, served from the live `CertStore`), the update check
        // (read-only, served from `detent-update`), the update install
        // (`POST`, `Unsupported` until the monitor wiring lands), and
        // `/api/v1/openapi.json` itself.
        assert_eq!(table().len(), 17, "{:?}", table());
        assert!(
            table()
                .iter()
                .all(|route| !(route.method == Method::GET && route.mutating))
        );
        assert!(table().iter().any(|route| route.mutating));
        assert!(
            table()
                .iter()
                .all(|route| route.path.starts_with("/api/v1/"))
        );
    }
}
