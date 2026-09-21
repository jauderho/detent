//! Mechanical `rmcp` server mapping every `Operation` to a tool.
//!
//! One tool per `Operation` variant, named in `snake_case` to match the JSON
//! tag of the REST body (`list_modules`, `get_module`, `validate`, …). Input
//! schemas reuse the wire shapes `detent-web` accepts; the body of each
//! handler turns its input into an `Operation` and lets an [`EngineExecutor`]
//! run it, so the wire surface and the dispatch surface are the same code
//! path the CLI and the web layer take.
//!
//! The server is **transport-agnostic**: it does not own stdin/stdout or an
//! HTTP listener, so callers can run it under either of rmcp's transports
//! and so a unit test can list tools and execute `list_modules` against a
//! fake engine without touching any I/O at all.

use std::sync::Arc;

use detent_ops::{
    OpOutcome, OpsEngine, OpsError, ServiceCommand, audit::AuditQuery, identity::Identity,
    op::Operation,
};
use detent_platform::fs::Sha256Digest;
use detent_platform::privsep::proto::{BackupId, CommitId};
use rmcp::{
    handler::server::{
        ServerHandler,
        router::tool::{SyncTool, ToolBase, ToolRouter},
        tool::ToolCallContext,
    },
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        ErrorData, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    service::{RequestContext, RoleServer},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq as _;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No credential was presented.
    Missing,
    /// The credential was presented but did not authenticate.
    Invalid,
    /// The authenticated identity is not authorized for this operation.
    Denied,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("missing bearer token"),
            Self::Invalid => f.write_str("invalid bearer token"),
            Self::Denied => f.write_str("operation refused by policy"),
        }
    }
}

/// The outcome of an authentication check.
///
/// `Denied` becomes an MCP `-32603` (internal error) so the wire does not
/// let a caller probe for "which token was once valid?" — the same posture
/// the REST API takes (`docs/API.md`, "Auth").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The caller is known.
    Authenticated(Identity),
    /// The caller is not known, for any reason.
    Denied(AuthError),
}

/// Decides whether a presented bearer token names a known caller.
///
/// The default verifier returns `Denied(Missing)` for every call, so a server
/// constructed without one fails closed. The web layer's
/// `TokenStore::authenticate` (sha256-of-token, constant-time scan) is the
/// canonical implementation; this trait only describes the contract so the
/// MCP server does not have to depend on the web crate.
pub trait TokenVerifier: Send + Sync {
    /// Check one bearer token, returning the caller or the reason it is refused.
    fn authenticate(&self, token: &str) -> AuthOutcome;
}

/// A verifier that admits exactly the SHA-256 hex digests in `digests`.
///
/// Intended for tests and for callers that have already resolved a token to
/// its digest. Real deployments use the web layer's token store.
pub struct ConstantTimeTokenVerifier {
    digests: Vec<[u8; 32]>,
}

impl ConstantTimeTokenVerifier {
    /// Build from the SHA-256 of every acceptable token.
    #[must_use]
    pub fn from_digests<I: IntoIterator<Item = String>>(digests: I) -> Self {
        let mut out = Vec::new();
        for d in digests {
            if d.len() == 64
                && let Some(bytes) = hex_to_32(&d)
            {
                out.push(bytes);
            }
        }
        Self { digests: out }
    }

    /// Build from a single token, hashing it.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        let bytes = *Sha256Digest::of(token.as_bytes()).as_bytes();
        Self {
            digests: vec![bytes],
        }
    }
}

impl TokenVerifier for ConstantTimeTokenVerifier {
    fn authenticate(&self, token: &str) -> AuthOutcome {
        let presented = Sha256Digest::of(token.as_bytes());
        for d in &self.digests {
            if bool::from(presented.as_bytes().ct_eq(d)) {
                return AuthOutcome::Authenticated(Identity::new(
                    format!("mcp-token:{}", &token[..8.min(token.len())]),
                    detent_ops::identity::IdentityKind::Token,
                ));
            }
        }
        AuthOutcome::Denied(AuthError::Invalid)
    }
}

fn hex_to_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Authz hook
// ---------------------------------------------------------------------------

/// Decides whether an authenticated identity may run one operation.
///
/// The web layer's `ScopedAuthz` is the canonical implementation; here it is
/// a trait so an MCP-only deployment can plug in a single binary policy.
pub trait Authz: Send + Sync {
    /// Check whether `who` may run `op`.
    ///
    /// # Errors
    ///
    /// Returns `Err(AuthError::Denied)` when the identity may not run this operation.
    fn permit(&self, who: &Identity, op: &Operation) -> Result<(), AuthError>;
}

/// Permit everything — the same default the CLI takes (PLAN §2.5).
///
/// Kept crate-visible for tests; production binaries wire a real policy.
#[cfg_attr(not(test), expect(dead_code))]
pub struct AllowAllAuthz;

impl Authz for AllowAllAuthz {
    fn permit(&self, _who: &Identity, _op: &Operation) -> Result<(), AuthError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Runs one [`Operation`] and returns its outcome, or refuses it.
///
/// The trait object form means the real [`OpsEngine`] can sit behind a lock
/// in one binary and a fixture executor can sit behind it in tests, without
/// this crate having to pick a single shape.
pub trait EngineExecutor: Send + Sync {
    /// Run `op` to completion.
    ///
    /// # Errors
    ///
    /// Returns `Err(OpsError)` when the operation is refused or fails.
    fn execute(&self, op: Operation) -> Result<OpOutcome, OpsError>;
}

/// Wraps a real [`OpsEngine`] behind a mutex so the handlers can take the
/// engine mutably without an actor loop.
pub struct LockedEngine {
    engine: std::sync::Mutex<OpsEngine>,
}

impl LockedEngine {
    /// Wrap `engine`; the executor hands the same identity to every tool call.
    #[must_use]
    pub const fn new(engine: OpsEngine) -> Self {
        Self {
            engine: std::sync::Mutex::new(engine),
        }
    }
}

impl EngineExecutor for LockedEngine {
    fn execute(&self, op: Operation) -> Result<OpOutcome, OpsError> {
        let mut guard = self.engine.lock().map_err(|_| OpsError::Unsupported {
            what: "engine_locked",
        })?;
        let who = Identity::new("mcp", detent_ops::identity::IdentityKind::Token);
        guard.execute(op, &who)
    }
}

/// A fake executor that records every operation it is asked to run.
///
/// Used by the test path: the router is asserted to hold one tool per
/// [`Operation`] variant, and tools execute against this to prove the router
/// wires them through to the executor.
#[derive(Default)]
pub struct RecordingExecutor {
    recorded: std::sync::Mutex<Vec<Operation>>,
}

impl RecordingExecutor {
    /// Build an empty recorder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recorded: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Inspect what was recorded.
    #[must_use]
    pub fn recorded(&self) -> Vec<Operation> {
        self.recorded.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl EngineExecutor for RecordingExecutor {
    fn execute(&self, op: Operation) -> Result<OpOutcome, OpsError> {
        let mut guard = self.recorded.lock().map_err(|_| OpsError::Unsupported {
            what: "executor_locked",
        })?;
        guard.push(op.clone());
        Ok(match op {
            Operation::HostProfile => OpOutcome::Host(Box::new(detent_ops::report::HostReport {
                profile: detent_core::descriptor::HostProfile::default(),
                distro_id: Some("linux".to_owned()),
                distro_version_id: None,
                network_backend: "networkd",
                resolver_backend: "systemd-resolved",
                notes: Vec::new(),
            })),
            _ => OpOutcome::Modules(Vec::new()),
        })
    }
}

// ---------------------------------------------------------------------------
// Tool parameter structs
// ---------------------------------------------------------------------------
//
// One input struct per Operation variant, mirroring the JSON shapes the REST
// API accepts (`crates/detent-web/src/api/*.rs`). The fields, names and
// serde rules are identical so the JSON Schema the MCP client sees is the
// same JSON Schema the REST client sees. The only intentional deviation is
// the `expected_hash` shape: the REST body is a 64-hex string (validated
// server-side), and so is this one — see `ApplyRequest::expected_hash`.

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetModuleParams {
    /// Module id, e.g. `hosts`.
    pub id: String,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelParams {
    /// Module id, e.g. `hosts`.
    pub id: String,
    /// The candidate model, as the module's JSON schema describes it.
    pub model: Value,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    /// Module id.
    pub id: String,
    /// The candidate model.
    pub model: Value,
    /// Digest the caller last read, as 64 lowercase hex characters. A
    /// mismatch is refused rather than silently overwriting somebody else's
    /// edit.
    #[serde(default)]
    pub expected_hash: Option<String>,
    /// What to do to the module's service afterwards.
    #[serde(default)]
    pub service_action: Option<ServiceActionParam>,
    /// Commit-confirm window, in seconds. Omitted uses the module's default.
    #[serde(default)]
    pub confirm_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitParams {
    /// The id an `apply` returned.
    pub commit_id: u32,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreParams {
    /// Module id.
    pub id: String,
    /// Index into the listing `list_backups` returned.
    pub backup_id: u32,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdParams {
    /// Module id.
    pub id: String,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceActionParams {
    /// Module id.
    pub id: String,
    /// What to do.
    pub action: ServiceActionParam,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceActionParam {
    #[default]
    Restart,
    Reload,
    Start,
    Stop,
}

impl From<ServiceActionParam> for ServiceCommand {
    fn from(p: ServiceActionParam) -> Self {
        match p {
            ServiceActionParam::Restart => Self::Restart,
            ServiceActionParam::Reload => Self::Reload,
            ServiceActionParam::Start => Self::Start,
            ServiceActionParam::Stop => Self::Stop,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryParams {
    /// Only records about this module.
    #[serde(default)]
    pub module: Option<String>,
    /// Only records from this subject.
    #[serde(default)]
    pub who: Option<String>,
    /// At most this many records, newest first.
    #[serde(default)]
    pub limit: Option<usize>,
}

impl From<AuditQueryParams> for AuditQuery {
    fn from(p: AuditQueryParams) -> Self {
        Self {
            module: p.module,
            who: p.who,
            limit: p.limit,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateApplyParams {
    /// The update version to install, e.g. `v1.2.3`.
    pub version: String,
}

/// Empty parameter set: an MCP tool that takes no input gets
/// `{"type": "object", "properties": {}}` from schemars.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The MCP server. Holds the tool router, an executor, and an authenticator.
#[derive(Clone)]
pub struct McpServer {
    tool_router: ToolRouter<Self>,
    executor: Arc<dyn EngineExecutor>,
    authz: Arc<dyn Authz>,
    tokens: Arc<dyn TokenVerifier>,
}

impl McpServer {
    /// Build a server. Both `authz` and `tokens` may be permissive defaults
    /// while a real verifier is wired in.
    pub fn new(
        executor: Arc<dyn EngineExecutor>,
        authz: Arc<dyn Authz>,
        tokens: Arc<dyn TokenVerifier>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            executor,
            authz,
            tokens,
        }
    }

    /// Authn + authz in one place, called by every tool's `invoke`.
    ///
    /// Streamable HTTP callers must wire the bearer token into the
    /// `DETENT_MCP_TOKEN` env var before each request, or wrap
    /// `StreamableHttpService` in middleware that pre-resolves the identity
    /// and stashes it where `check_auth` can find it. The simplest deploy is
    /// stdio: the operator sets `DETENT_MCP_TOKEN` and the server picks it
    /// up.
    fn check_auth(&self, op: &Operation) -> Result<Identity, ErrorData> {
        let token = std::env::var("DETENT_MCP_TOKEN").ok();
        let who = match token {
            Some(ref t) => self.tokens.authenticate(t),
            None => AuthOutcome::Denied(AuthError::Missing),
        };
        let who = match who {
            AuthOutcome::Authenticated(who) => who,
            AuthOutcome::Denied(e) => {
                return Err(ErrorData::new(ErrorCode(-32003), e.to_string(), None));
            }
        };
        if self.authz.permit(&who, op).is_err() {
            return Err(ErrorData::new(
                ErrorCode(-32004),
                "operation refused by policy",
                None,
            ));
        }
        Ok(who)
    }

    fn tool_router() -> ToolRouter<Self> {
        ToolRouter::new()
            .with_sync_tool::<tools::ListModules>()
            .with_sync_tool::<tools::GetModule>()
            .with_sync_tool::<tools::Validate>()
            .with_sync_tool::<tools::Plan>()
            .with_sync_tool::<tools::Apply>()
            .with_sync_tool::<tools::ConfirmCommit>()
            .with_sync_tool::<tools::RollbackCommit>()
            .with_sync_tool::<tools::ListBackups>()
            .with_sync_tool::<tools::Restore>()
            .with_sync_tool::<tools::ServiceStatus>()
            .with_sync_tool::<tools::ServiceAction>()
            .with_sync_tool::<tools::HostProfile>()
            .with_sync_tool::<tools::AuditQueryTool>()
            .with_sync_tool::<tools::UpdateStatus>()
            .with_sync_tool::<tools::CertStatus>()
            .with_sync_tool::<tools::CertRenew>()
            .with_sync_tool::<tools::UpdateApply>()
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("detent MCP server: same Operations as the REST API, token-auth.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + '_ {
        let tools = self.tool_router.list_all();
        async move { Ok(ListToolsResult::with_all_items(tools)) }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + '_ {
        let ctx = ToolCallContext::new(self, request, context);
        async move { self.tool_router.call(ctx).await }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }
}

// The blanket `impl<H: ServerHandler> Service<RoleServer> for H` from rmcp
// provides `serve`, `call_tool`, etc. for any `ServerHandler`, so no manual
// `Service` impl is needed here.

fn op_err(e: &OpsError) -> ErrorData {
    ErrorData::new(ErrorCode::INTERNAL_ERROR, e.to_string(), None)
}

fn json_err(e: &serde_json::Error) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!("serialize: {e}"))])
}

fn bad_request(e: &AuthError) -> ErrorData {
    ErrorData::new(ErrorCode::INVALID_PARAMS, e.to_string(), None)
}

fn parse_hash(hex: &str) -> Result<Sha256Digest, AuthError> {
    use std::str::FromStr as _;
    Sha256Digest::from_str(hex).map_err(|_| AuthError::Invalid)
}

mod tools {
    use super::{
        ApplyParams, AuditQueryParams, BackupId, CallToolResult, CommitId, CommitParams,
        EmptyParams, ErrorData, GetModuleParams, McpServer, ModelParams, ModuleIdParams, Operation,
        RestoreParams, ServiceActionParams, ServiceCommand, SyncTool, ToolBase, UpdateApplyParams,
        bad_request, json_text, op_err, parse_hash,
    };
    use std::borrow::Cow;

    // ---- list_modules -----------------------------------------------------
    pub struct ListModules;
    impl ToolBase for ListModules {
        type Parameter = EmptyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "list_modules".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("List every module compiled into this build.".into())
        }
    }
    impl SyncTool<McpServer> for ListModules {
        fn invoke(server: &McpServer, _p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            server.check_auth(&Operation::ListModules)?;
            let outcome = server
                .executor
                .execute(Operation::ListModules)
                .map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- get_module -------------------------------------------------------
    pub struct GetModule;
    impl ToolBase for GetModule {
        type Parameter = GetModuleParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "get_module".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Read one module's descriptor, schema, current model and diagnostics.".into())
        }
    }
    impl SyncTool<McpServer> for GetModule {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::GetModule { id: p.id };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- validate ---------------------------------------------------------
    pub struct Validate;
    impl ToolBase for Validate {
        type Parameter = ModelParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "validate".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Validate a candidate model without touching anything.".into())
        }
    }
    impl SyncTool<McpServer> for Validate {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::Validate {
                id: p.id,
                model: p.model,
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- plan -------------------------------------------------------------
    pub struct Plan;
    impl ToolBase for Plan {
        type Parameter = ModelParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "plan".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some(
                "Render a candidate, diff against the file on disk, and run upstream validators. Writes nothing."
                    .into(),
            )
        }
    }
    impl SyncTool<McpServer> for Plan {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::Plan {
                id: p.id,
                model: p.model,
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- apply ------------------------------------------------------------
    pub struct Apply;
    impl ToolBase for Apply {
        type Parameter = ApplyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "apply".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some(
                "Write a candidate model, optionally act on the module's service, and optionally arm commit-confirm."
                    .into(),
            )
        }
    }
    impl SyncTool<McpServer> for Apply {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let expected_hash = p
                .expected_hash
                .as_deref()
                .map(parse_hash)
                .transpose()
                .map_err(|e| bad_request(&e))?;
            let confirm = p.confirm_secs.map(std::time::Duration::from_secs);
            let op = Operation::Apply {
                id: p.id,
                model: p.model,
                expected_hash,
                service_action: p.service_action.map(ServiceCommand::from),
                confirm,
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- confirm_commit ---------------------------------------------------
    pub struct ConfirmCommit;
    impl ToolBase for ConfirmCommit {
        type Parameter = CommitParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "confirm_commit".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Confirm a pending commit before its deadline.".into())
        }
    }
    impl SyncTool<McpServer> for ConfirmCommit {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::ConfirmCommit {
                commit_id: CommitId(p.commit_id),
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- rollback_commit --------------------------------------------------
    pub struct RollbackCommit;
    impl ToolBase for RollbackCommit {
        type Parameter = CommitParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "rollback_commit".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Roll a pending commit back immediately.".into())
        }
    }
    impl SyncTool<McpServer> for RollbackCommit {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::RollbackCommit {
                commit_id: CommitId(p.commit_id),
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- list_backups -----------------------------------------------------
    pub struct ListBackups;
    impl ToolBase for ListBackups {
        type Parameter = ModuleIdParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "list_backups".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("The backups retained for a module's targets, newest first.".into())
        }
    }
    impl SyncTool<McpServer> for ListBackups {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::ListBackups { id: p.id };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- restore ----------------------------------------------------------
    pub struct Restore;
    impl ToolBase for Restore {
        type Parameter = RestoreParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "restore".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Put one of those backups back.".into())
        }
    }
    impl SyncTool<McpServer> for Restore {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::Restore {
                id: p.id,
                backup_id: BackupId(p.backup_id),
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- service_status ---------------------------------------------------
    pub struct ServiceStatus;
    impl ToolBase for ServiceStatus {
        type Parameter = ModuleIdParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "service_status".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("The run state of the module's service.".into())
        }
    }
    impl SyncTool<McpServer> for ServiceStatus {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::ServiceStatus { id: p.id };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- service_action ---------------------------------------------------
    pub struct ServiceAction;
    impl ToolBase for ServiceAction {
        type Parameter = ServiceActionParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "service_action".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Start, stop, restart or reload the module's service.".into())
        }
    }
    impl SyncTool<McpServer> for ServiceAction {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::ServiceAction {
                id: p.id,
                action: p.action.into(),
            };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- host_profile -----------------------------------------------------
    pub struct HostProfile;
    impl ToolBase for HostProfile {
        type Parameter = EmptyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "host_profile".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("What was detected about this host.".into())
        }
    }
    impl SyncTool<McpServer> for HostProfile {
        fn invoke(server: &McpServer, _p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::HostProfile;
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- audit_query ------------------------------------------------------
    pub struct AuditQueryTool;
    impl ToolBase for AuditQueryTool {
        type Parameter = AuditQueryParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "audit_query".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Read back the audit log.".into())
        }
    }
    impl SyncTool<McpServer> for AuditQueryTool {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::AuditQuery(p.into());
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- update_status ----------------------------------------------------
    pub struct UpdateStatus;
    impl ToolBase for UpdateStatus {
        type Parameter = EmptyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "update_status".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Read whether a qualifying update exists for this build.".into())
        }
    }
    impl SyncTool<McpServer> for UpdateStatus {
        fn invoke(server: &McpServer, _p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::UpdateStatus;
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- cert_status ------------------------------------------------------
    pub struct CertStatus;
    impl ToolBase for CertStatus {
        type Parameter = EmptyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "cert_status".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Read the serving certificate's fingerprint and remaining lifetime.".into())
        }
    }
    impl SyncTool<McpServer> for CertStatus {
        fn invoke(server: &McpServer, _p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::CertStatus;
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- cert_renew -------------------------------------------------------
    pub struct CertRenew;
    impl ToolBase for CertRenew {
        type Parameter = EmptyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "cert_renew".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Check whether the serving certificate should renew, and renew it.".into())
        }
    }
    impl SyncTool<McpServer> for CertRenew {
        fn invoke(server: &McpServer, _p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::CertRenew;
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }

    // ---- update_apply -----------------------------------------------------
    pub struct UpdateApply;
    impl ToolBase for UpdateApply {
        type Parameter = UpdateApplyParams;
        type Output = CallToolResult;
        type Error = ErrorData;

        fn name() -> Cow<'static, str> {
            "update_apply".into()
        }
        fn description() -> Option<Cow<'static, str>> {
            Some("Install a verified update.".into())
        }
    }
    impl SyncTool<McpServer> for UpdateApply {
        fn invoke(server: &McpServer, p: Self::Parameter) -> Result<Self::Output, Self::Error> {
            let op = Operation::UpdateApply { version: p.version };
            server.check_auth(&op)?;
            let outcome = server.executor.execute(op).map_err(|e| op_err(&e))?;
            Ok(json_text(&outcome))
        }
    }
}

fn json_text<T: Serialize>(v: &T) -> CallToolResult {
    match serde_json::to_string(v) {
        Ok(s) => CallToolResult::success(vec![ContentBlock::text(s)]),
        Err(e) => json_err(&e),
    }
}

// ---------------------------------------------------------------------------
// Transport helper
// ---------------------------------------------------------------------------

/// A transport binding for [`McpServer::serve`].
pub use rmcp::transport::Transport;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server() -> (McpServer, Arc<RecordingExecutor>) {
        let executor = Arc::new(RecordingExecutor::new());
        let authz = Arc::new(AllowAllAuthz);
        let tokens = Arc::new(ConstantTimeTokenVerifier::from_token("test-token"));
        let server = McpServer::new(executor.clone(), authz, tokens);
        (server, executor)
    }

    #[test]
    fn every_operation_has_a_tool() {
        let (server, _) = server();
        let tools: Vec<Tool> = server.tool_router.list_all();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.contains(&"list_modules"));
        assert!(names.contains(&"get_module"));
        assert!(names.contains(&"validate"));
        assert!(names.contains(&"plan"));
        assert!(names.contains(&"apply"));
        assert!(names.contains(&"confirm_commit"));
        assert!(names.contains(&"rollback_commit"));
        assert!(names.contains(&"list_backups"));
        assert!(names.contains(&"restore"));
        assert!(names.contains(&"service_status"));
        assert!(names.contains(&"service_action"));
        assert!(names.contains(&"host_profile"));
        assert!(names.contains(&"audit_query"));
        assert!(names.contains(&"update_status"));
        assert!(names.contains(&"cert_status"));
        assert!(names.contains(&"cert_renew"));
        assert!(names.contains(&"update_apply"));
        assert_eq!(tools.len(), 17);
    }

    #[test]
    fn list_modules_executes_via_executor() -> Result<(), Box<dyn std::error::Error>> {
        let (server, executor) = server();
        let outcome = server.executor.execute(Operation::ListModules)?;
        let OpOutcome::Modules(modules) = outcome else {
            return Err("unexpected outcome variant".into());
        };
        assert!(modules.is_empty());
        assert_eq!(executor.recorded().len(), 1);
        Ok(())
    }

    #[test]
    fn get_module_records_an_operation() -> Result<(), Box<dyn std::error::Error>> {
        let (server, executor) = server();
        server
            .executor
            .execute(Operation::GetModule { id: "hosts".into() })?;
        assert_eq!(executor.recorded().len(), 1);
        Ok(())
    }

    #[test]
    fn host_profile_returns_host() -> Result<(), Box<dyn std::error::Error>> {
        let (server, _executor) = server();
        let outcome = server.executor.execute(Operation::HostProfile)?;
        assert!(matches!(outcome, OpOutcome::Host(_)));
        Ok(())
    }

    #[test]
    fn token_verifier_rejects_unknown_and_admits_known() {
        let v = ConstantTimeTokenVerifier::from_token("secret");
        assert!(matches!(
            v.authenticate("secret"),
            AuthOutcome::Authenticated(_)
        ));
        assert_eq!(
            v.authenticate("nope"),
            AuthOutcome::Denied(AuthError::Invalid)
        );
    }

    #[test]
    fn tool_params_round_trip_via_json() -> Result<(), Box<dyn std::error::Error>> {
        let raw = json!({
            "id": "hosts",
            "model": {"entries": []},
            "expected_hash": "0".repeat(64),
            "service_action": "reload",
            "confirm_secs": 90_u64,
        });
        let parsed: ApplyParams = serde_json::from_value(raw)?;
        assert_eq!(parsed.id, "hosts");
        assert!(parsed.expected_hash.is_some());
        assert_eq!(parsed.confirm_secs, Some(90));
        Ok(())
    }
}
