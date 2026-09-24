//! MCP server over the operations layer (PLAN §2.6, Phase 10).
//!
//! `detent-mcp` is an **optional** crate: the `mcp` Cargo feature pulls in
//! `rmcp` and its transport deps; the default build contains no MCP code,
//! no `rmcp` in its dep graph, and re-exports nothing but `detent-core`.
//!
//! # Schema parity (`OpenAPI` ↔ MCP)
//!
//! Each MCP tool corresponds to one [`detent_ops::Operation`] variant and
//! uses the same field shapes the REST API does. The input structs in this
//! crate are local mirrors of the wire types `detent-web/src/api/*` parses
//! — `model`, `expected_hash` (64 lowercase hex), `service_action`,
//! `confirm_secs`, `commit_id`, `backup_id`, `audit_query` — so the JSON
//! Schema a client sees over MCP and the one it sees over REST come from
//! the same set of fields. The [`detent_ops::Operation`] enum is the shared
//! truth; nothing here re-declares it.
//!
//! Drift detection is the responsibility of the consuming binary
//! (`crates/detent`): a snapshot test that compares the list of registered
//! tools against `docs/openapi.json`'s paths and component schemas, run on
//! every `cargo test -p detent`, is the cheapest invariant. See
//! `docs/API.md#openapi--mcp-schema-parity` for the documented invariant.
//!
//! # Authentication
//!
//! The REST API authenticates with sessions or bearer tokens; the MCP
//! server only accepts **API tokens** (PLAN §2.6). Two transports are
//! supported:
//!
//! * **stdio** — for `claude-desktop`-style local clients. The token is
//!   read from `DETENT_MCP_TOKEN` in the child process's environment, set
//!   by the operator when starting the server.
//! * **streamable HTTP** — for remote clients. Tokens arrive on every
//!   request as `Authorization: Bearer <token>`; the SHA-256 verifier here
//!   uses the same storage the web layer does, so MCP and the REST API
//!   draw from the same credential file.
//!
//! The verifier is a trait object passed at construction; the default is to
//! refuse every call until one is set, so a server built without an
//! authentication policy fails closed.
//!
//! # Transports
//!
//! Both transports are documented in
//! `docs/API.md`. Stdio uses `tokio::io::stdin`/`stdout`; streamable HTTP
//! uses `rmcp::transport::streamable_http_server::tower::StreamableHttpService`.
//! The token check on HTTP is **not** an `rmcp` extension; it is the
//! operator's axum/tower middleware, applied before the Streamable HTTP
//! service runs.
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "mcp")]
mod mcp;

#[cfg(feature = "mcp")]
pub use mcp::{
    AuthError, AuthOutcome, Authz, ConstantTimeTokenVerifier, EngineExecutor, McpServer,
    TokenVerifier, Transport,
};

/// What the owning binary needs to serve [`McpServer`] itself: `stdio` for
/// the local transport, the `StreamableHttp*` pieces plus
/// [`LocalSessionManager`] for the remote one, and [`ServiceExt`] (for
/// `serve`) with [`RunningService`] (for `waiting`/`close`). Re-exported so
/// the `rmcp` version is pinned in exactly one crate.
#[cfg(feature = "mcp")]
pub use rmcp::service::{RunningService, ServiceExt};
#[cfg(feature = "mcp")]
pub use rmcp::transport::io::stdio;
#[cfg(feature = "mcp")]
pub use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
