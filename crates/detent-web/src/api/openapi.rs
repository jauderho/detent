//! The `OpenAPI` document (PLAN §2.6) and where it is served.
//!
//! ```text
//!   #[utoipa::path] on every api::* handler ──┐
//!   doc-only shadow fns for /auth/* and /healthz ─┼─▶ #[derive(OpenApi)] ──▶ docs/openapi.json
//!   (those two live in auth::routes / server,      │      (checked in, byte-for-byte tested)
//!    which this crate does not modify)             │
//!                                                   ▼
//!                                          GET /api/v1/openapi.json (unauthenticated)
//! ```
//!
//! # Why the auth and healthz routes get shadow functions
//!
//! `#[utoipa::path]` has to sit on a function utoipa's macro can see, and the
//! real `login`/`logout`/`session` handlers live in [`crate::auth::routes`]
//! and [`crate::server`]. [`login_doc`], [`logout_doc`], [`session_doc`] and
//! [`healthz_doc`] are never called — they exist only so [`ApiDoc`]'s
//! `paths(...)` list has something to point at for those four routes. They are
//! `#[allow(dead_code)]` for exactly that reason.
//!
//! Their *schemas*, though, are the real types: `LoginRequest` and
//! `SessionView` derive `ToSchema` where they are defined. Hand-copied mirrors
//! were the first attempt and had already drifted — the copy of `SessionView`
//! typed `scopes` as `Vec<String>` where the real one is `Vec<&'static str>`
//! — which is the whole argument against them.
//!
//! # Guarantees
//!
//! * **`/api/v1/openapi.json` is unauthenticated**, matching the plan's own
//!   description of it as a discovery document, not a protected resource: PLAN
//!   §2.6 lists it in the same breath as the API surface it describes, with no
//!   auth requirement called out, and the SPA needs it before a session
//!   exists. See the module doc for the tradeoff this implies.
//! * **The checked-in document and the one this build generates never
//!   drift.** [`tests::the_checked_in_document_matches_what_this_build_generates`]
//!   regenerates it and fails, naming the regeneration command, the moment
//!   they differ.

use axum::Json;
use axum::Router;
use axum::routing::get;
use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};

use crate::auth::routes::Route;
use crate::state::AppState;

/// `GET /api/v1/openapi.json`.
pub const PATH: &str = "/api/v1/openapi.json";

/// This module's routes.
#[must_use]
pub fn table() -> Vec<Route> {
    use axum::http::Method;
    vec![Route {
        method: Method::GET,
        path: PATH,
        mutating: false,
    }]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new().route(PATH, get(serve))
}

/// `GET /api/v1/openapi.json`.
#[utoipa::path(
    get,
    path = PATH,
    tag = "system",
    responses((status = 200, description = "This document")),
)]
async fn serve() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// `POST /api/v1/auth/login`. The real handler is `crate::auth::routes::login`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = crate::auth::routes::LoginRequest,
    responses(
        (status = 200, description = "Signed in; the session cookie is set", body = crate::auth::session::SessionView),
        (status = 401, description = "The credentials were refused", body = crate::error::ErrorBody),
        (status = 429, description = "Too many attempts", body = crate::error::ErrorBody),
    ),
)]
#[allow(dead_code)]
fn login_doc() {}

/// `POST /api/v1/auth/logout`. The real handler is `crate::auth::routes::logout`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Session ended; the cookie is cleared"),
        (status = 401, description = "No session to end", body = crate::error::ErrorBody),
    ),
)]
#[allow(dead_code)]
fn logout_doc() {}

/// `GET /api/v1/auth/session`. The real handler is `crate::auth::routes::session`.
#[utoipa::path(
    get,
    path = "/api/v1/auth/session",
    tag = "auth",
    responses(
        (status = 200, description = "The current session's CSRF token, scopes and expiry", body = crate::auth::session::SessionView),
        (status = 401, description = "No session", body = crate::error::ErrorBody),
    ),
)]
#[allow(dead_code)]
fn session_doc() {}

/// `GET /healthz`. The real handler is `crate::server::healthz`.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses((status = 200, description = "The process is serving", body = String, content_type = "text/plain")),
)]
#[allow(dead_code)]
fn healthz_doc() {}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Adds the two credential schemes PLAN §2.7 defines, so `security(...)`
/// requirements elsewhere in the document resolve to something.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(crate::auth::COOKIE_NAME))),
        );
        components.add_security_scheme(
            "bearer_token",
            SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .build(),
            ),
        );
    }
}

/// Every path this build documents.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "detent API",
        description = "PLAN §2.6/§2.7: the detent-web `/api/v1` surface.",
    ),
    paths(
        login_doc,
        logout_doc,
        session_doc,
        healthz_doc,
        super::modules::list,
        super::modules::get_one,
        super::modules::validate,
        super::modules::plan,
        super::modules::apply,
        super::commits::confirm,
        super::commits::rollback,
        super::backups::list,
        super::backups::restore,
        super::services::status,
        super::services::action,
        super::system::profile,
        super::system::audit,
        serve,
    ),
    tags(
        (name = "auth", description = "Sign in, sign out, describe the session"),
        (name = "modules", description = "List, read, validate, plan and apply module configuration"),
        (name = "commits", description = "Confirm or roll back a commit-confirm window"),
        (name = "backups", description = "List and restore a module's retained backups"),
        (name = "services", description = "Read or act on a module's service"),
        (name = "system", description = "Host profile, audit log, and liveness"),
    ),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Where the checked-in document lives, relative to this crate.
    const CHECKED_IN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/openapi.json");

    /// Read `path`, or explain which command regenerates it.
    fn read_checked_in(path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|error| {
            format!(
                "{path} could not be read ({error}); generate it with: \
                 cargo test -p detent-web api::openapi -- --ignored write_openapi_json"
            )
        })
    }

    /// `docs/openapi.json` is generated, not maintained by hand — see
    /// `docs/API.md`.
    #[test]
    fn the_checked_in_document_matches_what_this_build_generates() -> R {
        let generated = ApiDoc::openapi().to_pretty_json()?;
        let checked_in = read_checked_in(CHECKED_IN)?;
        assert_eq!(
            generated.trim_end(),
            checked_in.trim_end(),
            "docs/openapi.json is stale; regenerate it with: \
             cargo test -p detent-web api::openapi -- --ignored write_openapi_json"
        );
        Ok(())
    }

    #[test]
    fn a_missing_checked_in_document_names_the_regeneration_command() -> R {
        let message = read_checked_in("/nonexistent/openapi.json")
            .err()
            .ok_or("expected the read to fail")?;
        assert!(message.contains("write_openapi_json"), "{message}");
        Ok(())
    }

    /// Not run by default. `cargo test -p detent-web api::openapi -- \
    /// --ignored write_openapi_json` regenerates `docs/openapi.json`.
    #[test]
    #[ignore = "run explicitly to regenerate docs/openapi.json"]
    fn write_openapi_json() -> R {
        let generated = ApiDoc::openapi().to_pretty_json()?;
        std::fs::write(CHECKED_IN, format!("{generated}\n"))?;
        Ok(())
    }

    /// The shadow doc functions have no behaviour to test — they exist only
    /// to give `#[utoipa::path]` something to attach to (see the module
    /// doc) — but calling them proves they are not, in fact, unreachable.
    #[test]
    fn the_doc_only_shadow_functions_do_nothing_and_are_callable() {
        super::login_doc();
        super::logout_doc();
        super::session_doc();
        super::healthz_doc();
    }

    #[test]
    fn the_document_names_every_endpoint_this_task_lists() -> R {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc)?;
        let paths = json
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or("no paths object")?;
        for path in [
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/auth/session",
            "/healthz",
        ] {
            assert!(paths.contains_key(path), "{path} is missing from the doc");
        }
        Ok(())
    }

    /// The list above is hand-written, so it can only catch a route somebody
    /// remembered to add to it. This one is driven off the route tables the
    /// routers are actually built from, so a new endpoint that nobody
    /// documented fails the build instead of shipping undescribed.
    #[test]
    fn every_registered_route_appears_in_the_document() -> R {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc)?;
        let paths = json
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or("no paths object")?;
        for route in crate::api::table() {
            let entry = paths
                .get(route.path)
                .ok_or_else(|| format!("{} is registered but undocumented", route.path))?;
            let method = route.method.as_str().to_ascii_lowercase();
            assert!(
                entry.get(&method).is_some(),
                "{} {} is registered but the document describes no such operation",
                route.method,
                route.path
            );
        }
        for route in crate::auth::routes::table() {
            assert!(
                paths.contains_key(route.path),
                "{} is registered but undocumented",
                route.path
            );
        }
        Ok(())
    }
}
