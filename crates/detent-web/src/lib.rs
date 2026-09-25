//! Axum server: TLS, auth, sessions, CSRF, API v1, embedded SPA (PLAN §2.6,
//! §2.7).
//!
//! This crate is the web front end's *foundation*: configuration, a TLS 1.3
//! listener with a reloadable certificate, the §2.7 security headers, and the
//! bridge from async handlers to the synchronous operations engine.
//! Authentication, sessions, CSRF, the `/api/v1` surface and the embedded SPA
//! build on top of it.
//!
//! ```text
//!   detent.toml ──▶ Config ─┬─▶ tls::load_or_bootstrap ──▶ CertStore ──┐
//!                           │                                (reload)  │
//!                           └─▶ listen limits ──────────────────┐      │
//!                                                               ▼      ▼
//!   OpsEngine ──▶ engine::spawn ──▶ EngineHandle ──▶ Router ──▶ Server::serve
//!    (one thread, one privsep socket)      │              (TLS 1.3, h2/http1.1)
//!                                          └─ harden(): request id, §2.7
//!                                             headers, timeout, 256 KiB limit
//! ```
//!
//! # Guarantees
//!
//! * **TLS 1.3 or nothing.** The listener is built over `&[&TLS13]`, and the
//!   shipped binary does not compile rustls' `tls12` feature at all. See
//!   [`tls`].
//! * **A missing configuration file is the secure default**, not a startup
//!   failure; a malformed one is a failure, not a silent default. See
//!   [`config`].
//! * **Every response carries the §2.7 header set**, error responses included,
//!   because the middleware wraps the router rather than the handlers. See
//!   [`headers`].
//! * **Privileged work is serialized through one thread** that owns the single
//!   privsep socket, so no runtime worker ever blocks on it. See [`engine`].
//! * **`/healthz` reveals nothing.** Unauthenticated, constant body, no
//!   version string. See [`server::healthz`].
//! * **The SPA never serves a path outside its embedded set**, because no
//!   path is ever joined to a directory — there is nothing to traverse out
//!   of. See [`spa`].
//!
//! # Crypto provider
//!
//! Exactly one rustls provider is used at run time. `crypto-aws-lc` (the
//! default) and `crypto-ring` are both offered; at least one must be enabled,
//! and when both are — which is what `--all-features` does — aws-lc-rs wins.
//! TLS configurations receive a local provider and never mutate rustls
//! process-global state.

#[cfg(not(any(feature = "crypto-aws-lc", feature = "crypto-ring")))]
compile_error!(
    "detent-web needs a rustls crypto provider: enable `crypto-aws-lc` (default) or `crypto-ring`"
);

pub mod api;
pub mod auth;
pub mod authz;
pub mod config;
pub mod csrf;
pub mod engine;
pub mod error;
pub mod headers;
pub mod server;
pub mod spa;
pub mod state;
pub mod tls;

use axum::Router;

/// Assemble the whole HTTP surface: `/healthz`, `/api/v1/auth/*` and the rest
/// of `/api/v1/*` behind the CSRF guard, and the embedded SPA behind
/// everything else.
///
/// Deliberately **not** wrapped in [`server::harden`]: [`server::Server::bind`]
/// applies that layer itself, once, around whatever router it is given.
/// Wrapping here too would double the request-id, security-header, timeout
/// and body-limit layers. A test that drives this router directly with
/// `tower::ServiceExt::oneshot` — rather than through `Server::bind` — should
/// apply [`server::harden`] itself, exactly as the fixtures in
/// [`auth::routes`] and [`csrf`] do.
///
/// [`spa::routes`] is merged last: it is the only piece here with a
/// [`axum::Router::fallback`], and it must sit after `/healthz` and
/// `/api/**` in matching order so a reader can see, by the order they are
/// merged, that either of those wins over the app shell for any path they
/// register — even though axum matches an exact route over a fallback
/// regardless of merge order.
pub fn router(state: state::AppState) -> Router {
    server::healthz()
        .merge(
            auth::routes::routes()
                .merge(api::routes())
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    csrf::csrf_guard,
                ))
                .with_state(state),
        )
        .merge(spa::routes())
}

pub use config::{
    AcmeConfig, Argon2Params, AuthConfig, Bootstrap, Config, ConfigError, ListenConfig,
    ModulesConfig, TlsConfig, UiConfig, UpdateConfig,
};
pub use csrf::{CSRF_HEADER, Origin, SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
pub use engine::{EngineError, EngineHandle, EngineThread, spawn as spawn_engine};
pub use headers::{THEME_SCRIPT_SHA256, security_headers};
pub use server::{Server, ServerError, harden, healthz};
pub use state::{AppState, AuthState};
pub use tls::{
    ACME_PAIR_FILE, BOOTSTRAP_PAIR_FILE, CertStore, CertifiedKeyPair, TlsError,
    bootstrap_self_signed, crypto_provider, fingerprint, install_acme, load_acme, load_bootstrap,
    load_or_bootstrap, renewal_due_at, server_config, server_config_from_store, serving_pair,
    store_acme,
};

#[cfg(test)]
mod tests {
    use super::router;
    use crate::state::test_state;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// `/healthz` and the SPA fallback coexist in the assembled router, and
    /// an unregistered `/api/**` path is refused rather than handed the app
    /// shell — [`spa::routes`](crate::spa) is merged in after both.
    ///
    /// Written to hold regardless of the `ui` feature: it asks for an
    /// asset-shaped path no real build would ever emit, rather than assuming
    /// the embedded set is empty (true without the feature) or nonempty
    /// (true with it, once Phase 5 has built `web/dist`).
    #[tokio::test]
    async fn healthz_and_the_spa_coexist_in_the_assembled_router() -> R {
        let fixture = test_state()?;
        let app = router(fixture.state.clone());

        let health = app
            .clone()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);

        let unmatched = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/definitely-not-a-real-asset-name.js")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);

        let unknown_api = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/does-not-exist")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unknown_api.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}
