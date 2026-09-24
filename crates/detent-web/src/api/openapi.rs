//! The `OpenAPI` document (PLAN §2.6) and where it is served.
//!
//! ```text
//!   at TEST time only:
//!     #[cfg_attr(test, utoipa::path)] on every api::* handler ──┐
//!     doc-only shadow fns for /auth/* and /healthz ─────────────┼─▶ #[derive(OpenApi)]
//!                                                               │        │
//!                                                               │        ▼
//!                                                               │  docs/openapi.json
//!                                                               │  (checked in, and this
//!                                                               │   module's test fails if
//!                                                               │   it drifts by one byte)
//!   at RUN time:                                                │
//!     include_str!(docs/openapi.json) ──▶ DOCUMENT ─────────────┘
//!                                             │
//!                                             ▼
//!                                GET /api/v1/openapi.json (authenticated)
//! ```
//!
//! # Why the document is built by tests and served as a constant
//!
//! `utoipa` generates a runtime schema builder for every component — 54 of
//! them — and calling `ApiDoc::openapi()` from the handler dragged all of that
//! code into the shipped binary: about 280 KiB, measured. Since the checked-in
//! document is already proven byte-identical to what this build generates, the
//! handler can serve those bytes directly and the builders can stay in the
//! test profile. `utoipa` is a dev-dependency for that reason, so this is
//! structural rather than something the linker has to notice.
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
//! * **`/api/v1/openapi.json` needs a credential**, like every other
//!   `/api/v1` route. It is a map of the whole attack surface — every path,
//!   every parameter, every body shape — and nothing needs it before sign-in:
//!   the SPA's client is generated from the checked-in copy at build time
//!   (`web/scripts/api-check.ts`), never fetched at runtime. `/healthz` is the
//!   only route in this document that stays open, because a liveness probe has
//!   no credential to present and its body is a constant that reveals nothing.
//! * **The checked-in document and the one this build generates never
//!   drift.** [`tests::the_checked_in_document_matches_what_this_build_generates`]
//!   regenerates it and fails, naming the regeneration command, the moment
//!   they differ.

use axum::Router;
use axum::routing::get;
#[cfg(test)]
use utoipa::OpenApi;
#[cfg(test)]
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

/// The document as bytes, baked in at compile time.
///
/// Serving this rather than `ApiDoc::openapi()` is what keeps utoipa's
/// runtime schema builders — 280 KiB of generated code across the 54
/// component schemas, measured — out of the shipped binary. It is sound
/// because
/// [`tests::the_checked_in_document_matches_what_this_build_generates`]
/// already fails the build if this file and the document this build would
/// generate differ by a single byte, so the constant cannot go stale.
const DOCUMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/openapi.json"
));

/// `GET /api/v1/openapi.json`.
///
/// The one response body in this document that is not named by a schema: it
/// *is* the document, and describing it would mean carrying a copy of the
/// `OpenAPI` meta-schema.
///
/// The `Caller` is taken and dropped: it is not used, but taking it is what
/// makes this route authenticated — a handler that takes no `Caller` is open
/// by construction (see [`crate::auth::extract::Caller`]).
#[cfg_attr(test, utoipa::path(
    get,
    path = PATH,
    tag = "system",
    responses(
        (status = 200, description = "This document", body = Object),
        (status = 401, description = "No credential", body = crate::error::ErrorBody),
    ),
))]
async fn serve(_caller: crate::auth::extract::Caller) -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        DOCUMENT,
    )
}

/// `POST /api/v1/auth/login`. The real handler is `crate::auth::routes::login`.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    // Unauthenticated: a liveness probe has no credential to present.
    security(),
    responses((status = 200, description = "The process is serving", body = String, content_type = "text/plain")),
)]
#[allow(dead_code)]
fn healthz_doc() {}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Adds the two credential schemes PLAN §2.7 defines, so `security(...)`
/// requirements elsewhere in the document resolve to something.
#[cfg(test)]
struct SecurityAddon;

#[cfg(test)]
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

        // State the default the prose in docs/API.md already describes: every
        // endpoint needs one of the two credentials. Without this the document
        // defines two schemes and then never requires either, so a reader --
        // or a generated client -- cannot tell the API is authenticated at
        // all. The two endpoints that are deliberately open override it with
        // an empty requirement on their own operation.
        openapi.security = Some(vec![
            utoipa::openapi::security::SecurityRequirement::new::<_, [&str; 0], _>(
                "session_cookie",
                [],
            ),
            utoipa::openapi::security::SecurityRequirement::new::<_, [&str; 0], _>(
                "bearer_token",
                [],
            ),
        ]);
    }
}

/// Every path this build documents.
///
/// Test-only: the document it builds is compared against `docs/openapi.json`,
/// which is what actually gets served.
#[cfg(test)]
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
        super::commits::pending,
        super::commits::rollback,
        super::backups::list,
        super::backups::restore,
        super::services::status,
        super::services::action,
        super::system::profile,
        super::system::cert,
        super::system::update,
        super::system::apply_update,
        super::system::audit,
        serve,
    ),
    tags(
        (name = "auth", description = "Sign in, sign out, describe the session"),
        (name = "modules", description = "List, read, validate, plan and apply module configuration"),
        (name = "commits", description = "Read, confirm or roll back a commit-confirm window"),
        (name = "backups", description = "List and restore a module's retained backups"),
        (name = "system", description = "Host profile, certificate status, update status, audit log, and liveness"),
    ),
    modifiers(&SecurityAddon),
)]
pub(super) struct ApiDoc;

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

    /// A client is generated from this document, so an untyped `{}` body is
    /// not a small imprecision — it erases the response type. Every JSON
    /// answer must name a schema.
    #[test]
    fn no_json_response_body_is_an_untyped_object() -> R {
        let json = serde_json::to_value(ApiDoc::openapi())?;
        let paths = json
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or("no paths object")?;
        let empty = serde_json::Map::new();
        for (path, item) in paths {
            for (method, operation) in item.as_object().unwrap_or(&empty) {
                let responses = operation
                    .get("responses")
                    .and_then(|r| r.as_object())
                    .unwrap_or(&empty);
                for (status, response) in responses {
                    let Some(schema) = response.pointer("/content/application~1json/schema") else {
                        continue;
                    };
                    assert_ne!(
                        schema,
                        &serde_json::json!({}),
                        "{method} {path} answers {status} with an untyped JSON body"
                    );
                }
            }
        }
        Ok(())
    }

    /// `operationId` must be unique across the whole document.
    ///
    /// utoipa derives it from the handler's function name, so two modules
    /// that both call a handler `list` silently produce two operations with
    /// the same id. That is invalid `OpenAPI`, and a `TypeScript` client
    /// generated from it declares the member twice — the second operation
    /// ends up typed as the first, so a call compiles and then sends the
    /// wrong shape. `modules::list` and `backups::list` did exactly this.
    #[test]
    fn every_operation_id_is_unique() -> R {
        let json = serde_json::to_value(ApiDoc::openapi())?;
        let paths = json
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or("no paths object")?;

        let mut seen: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let empty = serde_json::Map::new();
        for (path, item) in paths {
            for (method, operation) in item.as_object().unwrap_or(&empty) {
                let Some(id) = operation.get("operationId").and_then(|v| v.as_str()) else {
                    continue;
                };
                seen.entry(id.to_owned())
                    .or_default()
                    .push(format!("{} {path}", method.to_uppercase()));
            }
        }

        let clashes: Vec<_> = seen.iter().filter(|(_, uses)| uses.len() > 1).collect();
        assert!(
            clashes.is_empty(),
            "operationId is not unique: {clashes:?} — give the handlers an explicit \
             `operation_id` in their `#[utoipa::path]`"
        );
        Ok(())
    }

    /// Every `$ref` this document writes must resolve inside it, or a
    /// generated client has a dangling type.
    #[test]
    fn every_schema_reference_resolves() -> R {
        let json = serde_json::to_value(ApiDoc::openapi())?;
        let schemas = json
            .pointer("/components/schemas")
            .and_then(|s| s.as_object())
            .ok_or("no components/schemas object")?;
        let mut stack = vec![&json];
        while let Some(node) = stack.pop() {
            match node {
                serde_json::Value::Object(map) => {
                    if let Some(reference) = map.get("$ref").and_then(|r| r.as_str()) {
                        let name =
                            reference
                                .strip_prefix("#/components/schemas/")
                                .ok_or_else(|| {
                                    format!("{reference} is not a local schema reference")
                                })?;
                        assert!(
                            schemas.contains_key(name),
                            "{reference} resolves to nothing"
                        );
                    }
                    stack.extend(map.values());
                }
                serde_json::Value::Array(items) => stack.extend(items),
                _ => {}
            }
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
