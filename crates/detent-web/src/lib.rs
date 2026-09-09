//! Axum server: TLS, auth, sessions, CSRF, API v1, embedded SPA (PLAN §2.6,
//! §2.7).
//!
//! This crate is the web front end's *foundation*: configuration, a TLS 1.3
//! listener with a reloadable certificate, the §2.7 security headers, and the
//! bridge from async handlers to the synchronous operations engine.
//! Authentication, sessions, CSRF and the `/api/v1` surface build on top of it.
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
//!
//! # Crypto provider
//!
//! Exactly one rustls provider is used at run time. `crypto-aws-lc` (the
//! default) and `crypto-ring` are both offered; at least one must be enabled,
//! and when both are — which is what `--all-features` does — aws-lc-rs wins.
//! [`tls::install_crypto_provider`] is idempotent and safe to call from
//! anywhere, including tests.

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
pub mod state;
pub mod tls;

use axum::Router;

/// Assemble the whole HTTP surface: `/healthz`, `/api/v1/auth/*` and the rest
/// of `/api/v1/*`, behind the CSRF guard.
///
/// Deliberately **not** wrapped in [`server::harden`]: [`server::Server::bind`]
/// applies that layer itself, once, around whatever router it is given.
/// Wrapping here too would double the request-id, security-header, timeout
/// and body-limit layers. A test that drives this router directly with
/// `tower::ServiceExt::oneshot` — rather than through `Server::bind` — should
/// apply [`server::harden`] itself, exactly as the fixtures in
/// [`auth::routes`] and [`csrf`] do.
pub fn router(state: state::AppState) -> Router {
    server::healthz().merge(
        auth::routes::routes()
            .merge(api::routes())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf::csrf_guard,
            ))
            .with_state(state),
    )
}

pub use config::{
    Argon2Params, AuthConfig, Bootstrap, Config, ConfigError, ListenConfig, ModulesConfig,
    TlsConfig, UiConfig, UpdateConfig,
};
pub use csrf::{CSRF_HEADER, Origin, SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
pub use engine::{EngineError, EngineHandle, EngineThread, spawn as spawn_engine};
pub use headers::{THEME_SCRIPT_SHA256, security_headers};
pub use server::{Server, ServerError, harden, healthz};
pub use state::{AppState, AuthState};
pub use tls::{
    CertStore, CertifiedKeyPair, TlsError, bootstrap_self_signed, fingerprint,
    install_crypto_provider, load_or_bootstrap, server_config, server_config_from_store,
};
