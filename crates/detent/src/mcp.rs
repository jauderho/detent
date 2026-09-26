//! `detent mcp`: serve every `Operation` as an MCP tool (PLAN §2.6, Phase 10).
//!
//! Two transports, one auth gate. **stdio** is the default: a local client
//! (Claude Desktop-style) spawns `detent mcp`, speaks MCP over stdin/stdout,
//! and the bearer comes from `DETENT_MCP_TOKEN` in the child's own env.
//! **HTTP** (`--transport http`) binds streamable HTTP on loopback
//! (`127.0.0.1:3334` unless `--bind` overrides); each request's
//! `Authorization: Bearer` must be that startup token — constant-time
//! compared — *and* still be live in the on-disk `TokenStore`. No
//! `std::env::set_var` anywhere: the token is read once at startup into an
//! `Arc`, so rotation is a process restart, and nothing reads the
//! environment again per request.
//!
//! Liveness is [`StoreVerifier`]: `TokenStore::load` + `authenticate` on
//! every check, so `detent token revoke` in another process (or a passed
//! deadline) is refused on the next call without a restart (STAGE3 H10).
//! Both the HTTP middleware and every tool call go through it, and the
//! identity it authenticates is labelled `token:<id>` — the record's public
//! id, never a slice of the secret.
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
use std::path::PathBuf;
use std::sync::Arc;

use detent_core::diag::MessageId;
use detent_mcp::{
    AuthError, AuthOutcome, ConstantTimeTokenVerifier, EngineExecutor, LocalSessionManager,
    McpServer, ServiceExt as _, StreamableHttpServerConfig, StreamableHttpService, TokenVerifier,
    stdio,
};
use detent_ops::{Identity, IdentityKind, OpOutcome, Operation, OpsError};
use detent_web::auth::TokenStore;
use detent_web::auth::extract::unix_now;
use detent_web::authz::{Scope, ScopedAuthz};

use crate::cli::{McpArgs, McpTransport};
use crate::output::{Exit, Renderer};
use crate::run::{Session, SessionStartError, Settings, Streams};

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
    crate::run::init_tracing();
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

    let store = Arc::new(StoreVerifier::new(settings.state_root.clone()));
    let authz: Arc<dyn detent_mcp::Authz> = Arc::new(EngineDecides);
    let executor: Arc<dyn EngineExecutor> =
        Arc::new(SessionExecutor::new(session, dryrun, who, scopes));
    let server = McpServer::new(
        executor.clone(),
        authz,
        store.clone(),
        Some(Arc::from(presented.as_str())),
    );

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
            let gate = Arc::new(BearerGate::new(&presented, store));
            runtime.block_on(serve_http(server, gate, bind))
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
/// refuses startup with exit 1 before anything listens.
fn resolve_identity(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Option<(String, detent_web::authz::Scopes, Identity)>> {
    let presented = match std::env::var(TOKEN_ENV) {
        Ok(token) if !token.is_empty() => token,
        _ => {
            tracing::warn!(var = TOKEN_ENV, "mcp startup refused: token missing");
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
            tracing::warn!(reason = %err, "mcp startup refused: credential store failed");
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
            tracing::warn!(reason = %err, "mcp startup refused: credential failed");
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
        Ok(mut session) => {
            if let Some(recovered) = session.take_recovery() {
                renderer.line(
                    streams.notes,
                    MessageId::new("cli-commit-recovered"),
                    &[
                        ("commit", &recovered.commit.get().to_string()),
                        ("restored", &recovered.restored.to_string()),
                        ("failures", &recovered.failures.len().to_string()),
                    ],
                )?;
            }
            Ok(Some(session))
        }
        Err(SessionStartError::Busy) => {
            renderer.line(streams.notes, MessageId::new("cli-monitor-busy"), &[])?;
            Ok(None)
        }
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-start-failed"),
                &[("reason", &err.to_string())],
            )?;
            Ok(None)
        }
    }
}

/// The tool-level policy: permit, and leave the scope check to the engine.
///
/// [`SessionExecutor`] runs every operation under the token's
/// [`ScopedAuthz`], so the engine refuses what the scopes do not permit and
/// writes a `denied` audit record (STAGE3 M4). A check here as well would
/// refuse first and leave no record.
struct EngineDecides;

impl detent_mcp::Authz for EngineDecides {
    fn permit(&self, _who: &Identity, _op: &Operation) -> Result<(), detent_mcp::AuthError> {
        Ok(())
    }
}

/// Runs one [`Operation`] through the [`Session`] the CLI already uses for
/// one-shot commands, so MCP tools take the same engine path.
struct SessionExecutor {
    session: std::sync::Mutex<Session>,
    dryrun: bool,
    who: Identity,
    /// The token's scopes, which the engine checks for every operation.
    authz: ScopedAuthz,
}

impl SessionExecutor {
    fn new(
        session: Session,
        dryrun: bool,
        who: Identity,
        scopes: detent_web::authz::Scopes,
    ) -> Self {
        Self {
            session: std::sync::Mutex::new(session),
            dryrun,
            who,
            authz: ScopedAuthz::new(scopes),
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
        // The engine checks the token's scopes and audits under this
        // identity, a refusal included.
        match guard.execute_as(op, false, &self.who, &self.authz) {
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

/// Per-request credential check: `tokens.json`, re-read from disk on every
/// authentication.
///
/// This is what makes revocation real for MCP (STAGE3 H10). The startup
/// value was only ever a digest compared once, so a token revoked or
/// expired in another process kept working until a restart; here every
/// check is `TokenStore::load(..)?.authenticate(token, now)`, and the
/// identity that comes back is labelled `token:<id>` — the record's public
/// id, never a slice of the presented secret.
struct StoreVerifier {
    state_root: PathBuf,
}

impl StoreVerifier {
    const fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }
}

impl TokenVerifier for StoreVerifier {
    fn authenticate(&self, token: &str) -> AuthOutcome {
        match TokenStore::load(&self.state_root)
            .and_then(|store| store.authenticate(token, unix_now()))
        {
            Ok(found) => AuthOutcome::Authenticated(Identity::new(
                format!("token:{}", found.id),
                IdentityKind::Token,
            )),
            // Unknown, revoked and expired share one answer, so the wire
            // cannot learn which token was once valid.
            Err(_) => AuthOutcome::Denied(AuthError::Invalid),
        }
    }
}

/// The bearer gate for one HTTP request: the presented token must be the
/// startup token — constant-time, so a read-scoped REST token cannot borrow
/// this one's scopes — *and* still be live in the store, re-read for this
/// request rather than trusted from startup.
struct BearerGate {
    startup: ConstantTimeTokenVerifier,
    store: Arc<StoreVerifier>,
}

impl BearerGate {
    fn new(presented: &str, store: Arc<StoreVerifier>) -> Self {
        Self {
            startup: ConstantTimeTokenVerifier::from_token(presented),
            store,
        }
    }

    /// Whether `presented` may pass into the rmcp service.
    fn admits(&self, presented: &str) -> bool {
        !presented.is_empty()
            && matches!(
                self.startup.authenticate(presented),
                AuthOutcome::Authenticated(_)
            )
            && matches!(
                self.store.authenticate(presented),
                AuthOutcome::Authenticated(_)
            )
    }
}

/// Streamable-HTTP transport: axum listener with a bearer gate in front of
/// the rmcp service. A wrong, missing or no-longer-valid token is 401
/// before MCP runs.
async fn serve_http(server: McpServer, gate: Arc<BearerGate>, bind: SocketAddr) -> Exit {
    let make_server = move || Ok(server.clone());
    let config = http_config();
    let http = StreamableHttpService::new(
        make_server,
        Arc::new(LocalSessionManager::default()),
        config,
    );
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

/// Bearer gate for HTTP: constant-time match against the startup token,
/// then a fresh read of the credential store for this request.
async fn check_bearer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    gate: Arc<BearerGate>,
) -> axum::response::Response {
    if !gate.admits(bearer_of(req.headers())) {
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
    use super::{
        BearerGate, EngineDecides, EngineExecutor, Exit, Identity, IdentityKind, McpServer,
        OpOutcome, Operation, OpsError, Scope, SessionExecutor, StoreVerifier, TokenStore,
        TokenVerifier, bearer_of, check_bind, http_config, http_transport_allowed, serve_http,
        unix_now,
    };
    use std::sync::Arc;

    /// The engine stand-in: these tests exercise auth, so no operation ever
    /// reaches an engine.
    struct NoEngine;
    impl EngineExecutor for NoEngine {
        fn execute(&self, _op: Operation) -> Result<OpOutcome, OpsError> {
            Err(OpsError::Unsupported {
                what: "mcp_auth_test",
            })
        }
    }

    /// The auth wiring `run()` hands to the server: a verifier that re-reads
    /// `tokens.json` on every check, and the bearer presented to it.
    fn mcp_server(state_root: &std::path::Path, token: &str) -> McpServer {
        let verifier: Arc<dyn TokenVerifier> =
            Arc::new(StoreVerifier::new(state_root.to_path_buf()));
        McpServer::new(
            Arc::new(NoEngine),
            Arc::new(EngineDecides),
            verifier,
            Some(Arc::from(token)),
        )
    }

    /// STAGE3 H10: a tool call re-checks the token, so a token revoked
    /// through a second handle on the same file — what `detent token revoke`
    /// does from another process — is refused on the very next call, with no
    /// restart and no re-read of the environment.
    #[test]
    fn a_revoked_token_is_refused_on_the_next_call() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (secret, view) = store.issue("mcp", Scope::Write, None)?;
        let server = mcp_server(root.path(), secret.expose());

        assert!(
            server
                .check_auth(Some(secret.expose()), &Operation::ListModules)
                .is_ok(),
            "the fresh token should authenticate"
        );

        TokenStore::load(root.path())?.revoke(&view.id)?;

        assert!(
            server
                .check_auth(Some(secret.expose()), &Operation::ListModules)
                .is_err(),
            "a revoked token was still accepted on the next call"
        );
        Ok(())
    }

    /// STAGE3 H10: expiry is checked at use, not once at startup.
    #[test]
    fn an_expired_token_is_refused_on_the_next_call() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (secret, _view) =
            store.issue("stale", Scope::Write, Some(unix_now().saturating_sub(1)))?;
        let server = mcp_server(root.path(), secret.expose());

        assert!(
            server
                .check_auth(Some(secret.expose()), &Operation::ListModules)
                .is_err(),
            "an expired token was accepted"
        );
        Ok(())
    }

    /// STAGE3 H10: the audit label is the token's public id — never a slice
    /// of the secret, which would leak it to the audit log and panic on a
    /// non-ASCII boundary.
    #[test]
    fn the_identity_label_is_the_token_id() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (secret, view) = store.issue("mcp", Scope::Write, None)?;
        let server = mcp_server(root.path(), secret.expose());

        let who = server.check_auth(Some(secret.expose()), &Operation::ListModules)?;
        assert_eq!(who.subject, format!("token:{}", view.id));
        Ok(())
    }

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

    fn token_identity() -> Identity {
        Identity::new("token:t1", IdentityKind::Token)
    }

    fn apply(text: &str) -> Operation {
        Operation::Apply {
            id: crate::tests_support::MODULE.to_owned(),
            model: serde_json::json!({ "text": text }),
            expected_hash: None,
            service_action: None,
            confirm: None,
        }
    }

    /// A tool call runs through the CLI's own session: a mutation really
    /// writes, the audit log names the token identity rather than the local
    /// user, and an operations error comes back as that error.
    #[test]
    fn the_executor_runs_tools_through_the_session_as_the_token()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bound first so the rest of the harness (its temp dir) outlives
        // the session moved out of it.
        let harness = crate::tests_support::Harness::start(b"v1\n", false)?;
        let crate::tests_support::Harness {
            session, target, ..
        } = harness;
        let executor = SessionExecutor::new(
            session,
            false,
            token_identity(),
            detent_web::authz::Scopes::of(Scope::Write),
        );

        let applied = executor.execute(apply("v2\n"))?;
        assert!(matches!(applied, OpOutcome::Applied(_)), "{applied:?}");
        assert_eq!(std::fs::read(&target)?, b"v2\n");

        let audit = executor.execute(Operation::AuditQuery(detent_ops::AuditQuery {
            module: None,
            who: None,
            limit: None,
        }))?;
        let records = crate::tests_support::records_of(audit).ok_or("audit answers records")?;
        assert!(
            records
                .iter()
                .any(|record| record.who == "token:t1" && record.op == detent_ops::OpKind::Apply),
            "{records:?}"
        );

        let missing = executor.execute(Operation::GetModule {
            id: "no-such-module".to_owned(),
        });
        assert!(
            matches!(missing, Err(OpsError::UnknownModule { ref id }) if id == "no-such-module"),
            "{missing:?}"
        );
        Ok(())
    }

    /// Under `--dryrun` a mutating tool is refused outright — MCP has no
    /// plan preview to show instead — while a read still answers, and the
    /// target is left untouched.
    #[test]
    fn a_dry_run_executor_refuses_mutations_and_still_answers_reads()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bound first so the rest of the harness (its temp dir) outlives
        // the session moved out of it.
        let harness = crate::tests_support::Harness::start(b"v1\n", true)?;
        let crate::tests_support::Harness {
            session, target, ..
        } = harness;
        let executor = SessionExecutor::new(
            session,
            true,
            token_identity(),
            detent_web::authz::Scopes::of(Scope::Write),
        );

        let refused = executor.execute(apply("v2\n"));
        assert!(
            matches!(
                refused,
                Err(OpsError::Unsupported {
                    what: "dryrun_mutation"
                })
            ),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&target)?, b"v1\n");

        let listed = executor.execute(Operation::ListModules)?;
        assert!(
            matches!(listed, OpOutcome::Modules(ref modules) if modules.len() == 1),
            "{listed:?}"
        );
        Ok(())
    }

    /// A read-scoped token may read. The engine refuses every mutation,
    /// writes nothing, and audits the refusal under the token (STAGE3 M4).
    #[test]
    fn a_read_scope_permits_reads_and_the_engine_denies_and_audits_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let harness = crate::tests_support::Harness::start(b"v1\n", false)?;
        let crate::tests_support::Harness {
            session, target, ..
        } = harness;
        let executor = SessionExecutor::new(
            session,
            false,
            token_identity(),
            detent_web::authz::Scopes::of(Scope::Read),
        );

        let listed = executor.execute(Operation::ListModules)?;
        assert!(matches!(listed, OpOutcome::Modules(_)), "{listed:?}");

        let refused = executor.execute(apply("v2\n"));
        assert!(matches!(refused, Err(OpsError::Denied(_))), "{refused:?}");
        assert_eq!(std::fs::read(&target)?, b"v1\n");

        let audit = executor.execute(Operation::AuditQuery(detent_ops::AuditQuery::default()))?;
        let records = crate::tests_support::records_of(audit).ok_or("audit answers records")?;
        assert!(
            records.iter().any(|record| record.who == "token:t1"
                && record.op == detent_ops::OpKind::Apply
                && record.result == detent_ops::AuditResult::Denied
                && record.error_id.as_deref() == Some("web-denied-scope")),
            "{records:?}"
        );
        Ok(())
    }

    /// The tool-level policy defers to the engine.
    #[test]
    fn the_tool_policy_leaves_the_scope_check_to_the_engine() {
        use detent_mcp::Authz as _;
        assert!(
            EngineDecides
                .permit(&token_identity(), &apply("x\n"))
                .is_ok()
        );
    }

    /// The HTTP gate admits only the startup token, and only while the
    /// store still holds it: another live token from the same store (which
    /// may carry other scopes), an empty bearer, and the startup token after
    /// revocation are all refused.
    #[test]
    fn the_bearer_gate_admits_only_the_live_startup_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (startup, view) = store.issue("mcp", Scope::Read, None)?;
        let (other, _) = store.issue("rest", Scope::Write, None)?;
        let gate = BearerGate::new(
            startup.expose(),
            Arc::new(StoreVerifier::new(root.path().to_path_buf())),
        );

        assert!(gate.admits(startup.expose()));
        assert!(!gate.admits(other.expose()));
        assert!(!gate.admits(""));
        assert!(!gate.admits("not-a-token"));

        TokenStore::load(root.path())?.revoke(&view.id)?;
        assert!(!gate.admits(startup.expose()));
        Ok(())
    }

    /// The status line of one `POST /mcp` initialize to `addr`.
    async fn post_initialize(
        addr: std::net::SocketAddr,
        bearer: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.0"}
            }
        })
        .to_string();
        let auth = bearer.map_or_else(String::new, |token| {
            format!("Authorization: Bearer {token}\r\n")
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\n{auth}Content-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await?;
        let mut line = String::new();
        tokio::io::BufReader::new(stream)
            .read_line(&mut line)
            .await?;
        Ok(line.trim_end().to_owned())
    }

    /// The HTTP transport in-process: a request without the startup bearer,
    /// or with a different one, is 401 before MCP runs; the startup token
    /// reaches the rmcp service and is answered.
    #[tokio::test]
    async fn serve_http_answers_401_until_the_startup_bearer_is_presented()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let (secret, _) = TokenStore::load(root.path())?.issue("mcp", Scope::Write, None)?;
        let store = Arc::new(StoreVerifier::new(root.path().to_path_buf()));
        let gate = Arc::new(BearerGate::new(secret.expose(), store));
        let server = mcp_server(root.path(), secret.expose());
        // A port that was free a moment ago; `serve_http` binds it itself.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;

        let client = async {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            while tokio::net::TcpStream::connect(addr).await.is_err() {
                if tokio::time::Instant::now() > deadline {
                    return Err::<_, Box<dyn std::error::Error>>("never listened".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok((
                post_initialize(addr, None).await?,
                post_initialize(addr, Some("wrong")).await?,
                post_initialize(addr, Some(secret.expose())).await?,
            ))
        };
        let (missing, wrong, right) = tokio::select! {
            exit = serve_http(server, gate, addr) => {
                return Err(format!("the server stopped on its own: {exit:?}").into());
            }
            statuses = client => statuses?,
        };
        assert_eq!(missing, "HTTP/1.1 401 Unauthorized");
        assert_eq!(wrong, "HTTP/1.1 401 Unauthorized");
        assert_eq!(right, "HTTP/1.1 200 OK");
        Ok(())
    }

    /// An address another socket already holds is an operational failure,
    /// reported as `Exit::Failed` rather than a panic.
    #[tokio::test]
    async fn serve_http_fails_when_the_address_is_taken() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let blocker = std::net::TcpListener::bind("127.0.0.1:0")?;
        let store = Arc::new(StoreVerifier::new(root.path().to_path_buf()));
        let gate = Arc::new(BearerGate::new("token", store));
        let exit = serve_http(
            mcp_server(root.path(), "token"),
            gate,
            blocker.local_addr()?,
        )
        .await;
        assert_eq!(exit, Exit::Failed);
        Ok(())
    }

    /// The transport names `--dryrun` reports match the `--transport`
    /// values that select them.
    #[test]
    fn transport_names_match_the_cli_values() {
        use crate::cli::McpTransport;
        assert_eq!(super::transport_name(McpTransport::Stdio), "stdio");
        assert_eq!(super::transport_name(McpTransport::Http), "http");
    }
}
