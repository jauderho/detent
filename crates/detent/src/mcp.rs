//! `detent mcp`: serve every `Operation` as an MCP tool (PLAN §2.6, Phase 10).
//!
//! Two transports, one auth gate. **stdio** is the default: a local client
//! (Claude Desktop-style) spawns `detent mcp`, speaks MCP over stdin/stdout,
//! and the bearer comes from `DETENT_MCP_TOKEN` in the child's own env.
//! **HTTP** (`--transport http`) binds streamable HTTP on loopback
//! (`127.0.0.1:3334` unless `--bind` overrides); each request's
//! `Authorization: Bearer` is constant-time compared against the same startup
//! value in axum middleware before the rmcp service runs. No
//! `std::env::set_var` anywhere: the token is read once at startup into an
//! `Arc`, so rotation is a process restart.
//!
//! Authz reuses the web layer's `ScopedAuthz`: the startup token's scopes are
//! resolved once from the on-disk `TokenStore` shared with the REST API, and
//! every tool call is checked against them. A failed authn/authz inside a
//! tool maps to a JSON-RPC error (the wire never distinguishes "unknown
//! token" from "expired token"); a startup failure (missing/unknown token,
//! unreadable store) is an `Exit` before anything listens.
//!
//! `--dryrun` starts no server: mutating tools would short-circuit to their
//! `Plan` the way one-shot commands do, so dry-run shape reporting would
//! need a live engine to mean anything. It reports the resolved shape and
//! exits `Ok` instead.

use axum::response::IntoResponse as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use detent_core::diag::MessageId;
use detent_mcp::{
    AuthOutcome, ConstantTimeTokenVerifier, EngineExecutor, LocalSessionManager, McpServer,
    ServiceExt as _, StreamableHttpServerConfig, StreamableHttpService, TokenVerifier, stdio,
};
use detent_ops::authz::Authz as _;
use detent_ops::{Identity, IdentityKind, OpOutcome, Operation, OpsError};
use detent_web::auth::TokenStore;
use detent_web::auth::extract::unix_now;
use detent_web::authz::{Scope, ScopedAuthz};

use crate::cli::{McpArgs, McpTransport};
use crate::output::{Exit, Renderer};
use crate::run::{Session, Settings, Streams};

/// Loopback default for `--transport http`; `--bind` overrides.
pub const DEFAULT_HTTP_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3334);

/// Name of the env var holding the MCP bearer.
pub const TOKEN_ENV: &str = "DETENT_MCP_TOKEN";

/// Serves the MCP transports, or explains why they could not start.
pub fn run(
    args: &McpArgs,
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    if matches!(args.transport, McpTransport::Http)
        && !http_transport_allowed(rustix::process::geteuid().is_root())
    {
        renderer.line(
            streams.notes,
            MessageId::new("cli-mcp-http-needs-privsep"),
            &[],
        )?;
        return Ok(Exit::Privilege);
    }
    let Some((presented, scopes, who)) = resolve_identity(settings, renderer, streams)? else {
        return Ok(Exit::Failed);
    };
    let Some(mut session) = start_session(settings, dryrun, renderer, streams)? else {
        return Ok(Exit::Failed);
    };
    let bind = args.bind.unwrap_or(DEFAULT_HTTP_ADDR);

    if matches!(args.transport, McpTransport::Http) && !check_bind(bind) {
        renderer.line(
            streams.notes,
            MessageId::new("cli-mcp-bind-not-loopback"),
            &[],
        )?;
        return Ok(Exit::Usage);
    }
    if dryrun {
        renderer.line(
            streams.out,
            MessageId::new("cli-dryrun-mcp"),
            &[
                ("transport", transport_name(args.transport)),
                ("addr", &bind.to_string()),
                ("scope", scope_name(scopes)),
            ],
        )?;
        session.finish().map_err(std::io::Error::other)?;
        return Ok(Exit::Ok);
    }

    let verifier = Arc::new(ConstantTimeTokenVerifier::from_token(&presented));
    let authz: Arc<dyn detent_mcp::Authz> = Arc::new(ScopeAuthz::new(scopes));
    let executor: Arc<dyn EngineExecutor> = Arc::new(SessionExecutor::new(session, dryrun, who));
    let server = McpServer::new(executor.clone(), authz, verifier.clone());

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-mcp-serve-failed"),
                &[("reason", &err.to_string())],
            )?;
            return Ok(Exit::Failed);
        }
    };
    let exit = match args.transport {
        McpTransport::Stdio => {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-mcp-listening"),
                &[("transport", "stdio")],
            );
            runtime.block_on(serve_stdio(server))
        }
        McpTransport::Http => {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-mcp-listening"),
                &[("transport", &bind.to_string())],
            );
            runtime.block_on(serve_http(server, verifier, bind))
        }
    };
    // The session (engine + monitor thread) is owned by the executor the
    // server just drove; dropping it here closes the privsep channel, which
    // lets the monitor thread exit on its own. A failed shutdown would be
    // operational, never usage.
    drop(executor);
    Ok(exit)
}

/// The startup bearer, its scopes, and the audit identity tools run as.
///
/// `None` after reporting: a missing/unknown token or an unreadable store
/// refuses startup with exit 1 before anything listens (Jev-routed).
fn resolve_identity(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Option<(String, detent_web::authz::Scopes, Identity)>> {
    let presented = match std::env::var(TOKEN_ENV) {
        Ok(token) if !token.is_empty() => token,
        _ => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-mcp-missing-token"),
                &[("var", TOKEN_ENV)],
            )?;
            return Ok(None);
        }
    };
    let store = match TokenStore::load(&settings.state_root) {
        Ok(store) => store,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-credential-failed"),
                &[("reason", &err.to_string())],
            )?;
            return Ok(None);
        }
    };
    let identity = match store.authenticate(&presented, unix_now()) {
        Ok(found) => found,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-credential-failed"),
                &[("reason", &err.to_string())],
            )?;
            return Ok(None);
        }
    };
    // ponytail: read-only tokens authenticate as write-capable here only via
    // the scope check below; the identity itself carries no authority.
    let scopes = identity.scopes;
    let who = Identity::new(format!("token:{}", identity.id), IdentityKind::Token);
    Ok(Some((presented, scopes, who)))
}

/// Starts the monitor-backed session the tools execute through.
///
/// `None` after reporting when the helper cannot start.
fn start_session(
    settings: &Settings,
    dryrun: bool,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Option<Session>> {
    let host = detent_platform::host::detect_real();
    let registry = detent_modules::modules();
    let descriptors: Vec<_> = registry.iter().map(|entry| entry.descriptor()).collect();
    match Session::start(settings, host, registry, &descriptors, dryrun) {
        Ok(session) => Ok(Some(session)),
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-start-failed"),
                &[("reason", &err)],
            )?;
            Ok(None)
        }
    }
}

/// The scope one token holds, as the policy the tools check.
struct ScopeAuthz(ScopedAuthz);

impl ScopeAuthz {
    const fn new(scopes: detent_web::authz::Scopes) -> Self {
        Self(ScopedAuthz::new(scopes))
    }
}

impl detent_mcp::Authz for ScopeAuthz {
    fn permit(&self, who: &Identity, op: &Operation) -> Result<(), detent_mcp::AuthError> {
        self.0
            .permit(who, op)
            .map_err(|_| detent_mcp::AuthError::Denied)
    }
}

/// Runs one [`Operation`] through the [`Session`] the CLI already uses for
/// one-shot commands, so MCP tools take the same engine path.
struct SessionExecutor {
    session: std::sync::Mutex<Session>,
    dryrun: bool,
    who: Identity,
}

impl SessionExecutor {
    fn new(session: Session, dryrun: bool, who: Identity) -> Self {
        Self {
            session: std::sync::Mutex::new(session),
            dryrun,
            who,
        }
    }
}

impl EngineExecutor for SessionExecutor {
    fn execute(&self, op: Operation) -> Result<OpOutcome, OpsError> {
        let mut guard = self.session.lock().map_err(|_| OpsError::Unsupported {
            what: "engine_locked",
        })?;
        // MCP has no plan-preview rendering; a dry run refuses the mutation
        // the way `Session::execute` would, without the diff wrapper.
        if self.dryrun && op.is_mutating() {
            return Err(OpsError::Unsupported {
                what: "dryrun_mutation",
            });
        }
        // The engine audits under this identity; authz already ran in
        // `McpServer::check_auth` against the same scopes.
        match guard.execute_as(op, false, &self.who) {
            Ok(crate::run::Executed::Ran(outcome)) => Ok(outcome),
            Ok(crate::run::Executed::WouldRun(_)) => Err(OpsError::Unsupported {
                what: "dryrun_mutation",
            }),
            Err(err) => Err(err),
        }
    }
}

/// Stdio transport: MCP over this process's stdin/stdout.
async fn serve_stdio(server: McpServer) -> Exit {
    let (stdin, stdout) = stdio();
    match server.serve((stdin, stdout)).await {
        Ok(running) => match running.waiting().await {
            Ok(_) => Exit::Ok,
            Err(_) => Exit::Failed,
        },
        Err(_) => Exit::Failed,
    }
}

/// Streamable-HTTP transport: axum listener with a bearer gate in front of
/// the rmcp service. A wrong or missing token is 401 before MCP runs.
async fn serve_http(
    server: McpServer,
    verifier: Arc<ConstantTimeTokenVerifier>,
    bind: SocketAddr,
) -> Exit {
    let make_server = move || Ok(server.clone());
    let config = http_config();
    let http = StreamableHttpService::new(
        make_server,
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let gate = verifier.clone();
    let app = axum::Router::new()
        .route_service("/mcp", http)
        .layer(axum::middleware::from_fn(move |req, next| {
            check_bearer(req, next, gate.clone())
        }));
    let Ok(listener) = tokio::net::TcpListener::bind(bind).await else {
        return Exit::Failed;
    };
    if axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .is_err()
    {
        return Exit::Failed;
    }
    Exit::Ok
}

/// Bearer gate for HTTP: constant-time match against the startup token.
async fn check_bearer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    verifier: Arc<ConstantTimeTokenVerifier>,
) -> axum::response::Response {
    let presented = bearer_of(req.headers());
    if presented.is_empty()
        || !matches!(
            verifier.authenticate(presented),
            AuthOutcome::Authenticated(_)
        )
    {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

/// The bearer token an `Authorization` header carries, or `""`.
///
/// Pure so a unit test can pin the parsing without a listener: one scheme,
/// one value, case-insensitive like the REST extractor it mirrors
/// (`detent_web::auth::extract::bearer`).
fn bearer_of(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .filter(|token| !token.is_empty())
        .unwrap_or_default()
}

/// Resolves on `SIGTERM` or `SIGINT`, mirroring [`crate::serve`].
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut terminate), Ok(mut interrupt)) => {
            tokio::select! {
                () = async { let _ = terminate.recv().await; } => {},
                () = async { let _ = interrupt.recv().await; } => {},
            }
        }
        _ => std::future::pending::<()>().await,
    }
}

fn transport_name(transport: McpTransport) -> &'static str {
    match transport {
        McpTransport::Stdio => "stdio",
        McpTransport::Http => "http",
    }
}

fn scope_name(scopes: detent_web::authz::Scopes) -> &'static str {
    if scopes.allows(Scope::Write) {
        "read,write"
    } else {
        "read"
    }
}
/// Whether an HTTP `--bind` may serve: loopback only, so the plaintext
/// bearer never crosses the network (STAGE3 M11).
fn check_bind(bind: std::net::SocketAddr) -> bool {
    bind.ip().is_loopback()
}
/// Whether `--transport http` may start: never as root, where the network
/// parser would run in the same process as the root monitor (STAGE3 H12).
fn http_transport_allowed(euid_is_root: bool) -> bool {
    !euid_is_root
}
/// Streamable-HTTP config: default loopback hosts plus enforced `Origin`
/// validation (STAGE3 M11). Empty allow-list + enforced flag rejects every
/// present `Origin` value; missing `Origin` (non-browser clients) passes.
fn http_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default().enforce_origin_validation()
}

#[cfg(test)]
mod tests {
    use super::{bearer_of, check_bind, http_config, http_transport_allowed};
    fn headers(
        value: Option<&str>,
    ) -> Result<axum::http::HeaderMap, axum::http::header::InvalidHeaderValue> {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(axum::http::header::AUTHORIZATION, value.parse()?);
        }
        Ok(headers)
    }

    #[test]
    fn bearer_parsing_accepts_one_scheme_and_value()
    -> Result<(), axum::http::header::InvalidHeaderValue> {
        assert_eq!(bearer_of(&headers(Some("Bearer abc"))?), "abc");
        assert_eq!(bearer_of(&headers(Some("bearer  abc  "))?), "abc");
        assert_eq!(bearer_of(&headers(None)?), "");
        assert_eq!(bearer_of(&headers(Some("Basic abc"))?), "");
        assert_eq!(bearer_of(&headers(Some("Bearer "))?), "");
        assert_eq!(bearer_of(&headers(Some("Bearer"))?), "");
        Ok(())
    }
    #[test]
    fn http_transport_refused_for_root() {
        assert!(http_transport_allowed(false));
        assert!(!http_transport_allowed(true));
    }
    #[test]
    fn bind_table_keeps_bearer_on_loopback() -> Result<(), std::net::AddrParseError> {
        for ok in ["127.0.0.1:3334", "[::1]:3334"] {
            assert!(check_bind(ok.parse()?), "{ok}");
        }
        for bad in ["0.0.0.0:3334", "192.168.1.10:3334", "[::]:3334"] {
            assert!(!check_bind(bad.parse()?), "{bad}");
        }
        Ok(())
    }
    #[test]
    fn http_config_enforces_origin_validation() {
        let debug = format!("{:?}", http_config());
        assert!(
            debug.contains("validate_empty_origin_allowlist: true"),
            "{debug}"
        );
    }
}
