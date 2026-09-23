//! End-to-end tests of `crate::router` for every `/api/v1` endpoint.
//!
//! Each test drives the *assembled* stack — `crate::router` wrapped in
//! [`crate::server::harden`], exactly what [`crate::server::Server::bind`]
//! serves — with `tower::ServiceExt::oneshot`, never a bare handler function.
//!
//! # Why every module-scoped endpoint answers 404, not 200, for "success"
//!
//! The engine behind these tests is real (a genuine [`OpsEngine`] over a real
//! privsep monitor thread, exactly like [`crate::engine`]'s own tests) but
//! registers **no modules**, for the same reason [`crate::engine`]'s fixture
//! does not: every compiled-in module (`hosts`, …) targets a real, absolute,
//! `'static` system path (`/etc/hosts`) that a test must not write to, and
//! `ModuleDescriptor::targets` cannot be pointed at a temp directory at
//! runtime. So for `GetModule`/`Validate`/`Plan`/`Apply`/`ListBackups`/
//! `Restore`/`ServiceStatus`/`ServiceAction`, "authenticated and correctly
//! scoped" is demonstrated by reaching the engine and getting its
//! deterministic `ops-unknown-module` 404 — proof that auth, CSRF, scope and
//! routing all did their job — rather than a 200 a real module would need to
//! produce. `ListModules`, `HostProfile`, `AuditQuery` and `openapi.json`
//! need no module, so those get genuine 200 assertions. `ConfirmCommit` and
//! `RollbackCommit` get the same treatment with a commit id that was never
//! armed, which the monitor also reports as an unknown id (409).

use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use detent_core::descriptor::{HostProfile, InitSystem, ModuleDescriptor, Os, Upstream};
use detent_core::diag::{Diagnostics, MessageId};
use detent_ops::report::{ApplyReport, ModuleView, PlanReport};
use detent_ops::{AllowAll, NullAudit, OpOutcome, OpsEngine};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::{Detected, HostFacts};
use detent_platform::privsep::allowlist::{Allowlist, Config as AllowlistConfig};
use detent_platform::privsep::monitor::{Hooks, Monitor};
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::Client;
use detent_platform::service;
use tempfile::TempDir;
use tower::ServiceExt as _;

use crate::authz::Scope;
use crate::engine::{EngineHandle, EngineThread, spawn as spawn_engine};
use crate::server::harden;
use crate::state::{AppState, TestState, test_state};

type R = Result<(), Box<dyn std::error::Error>>;

/// A [`TestState`] whose engine is real rather than
/// [`crate::engine::EngineHandle::detached`], plus what keeps the privsep
/// monitor alive.
struct Live {
    state: TestState,
    monitor: Option<thread::JoinHandle<()>>,
    engine: Option<EngineThread>,
    _dir: TempDir,
}

impl Live {
    /// A live stack with no modules registered — see the module doc for why.
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut fixture = test_state()?;
        let dir = TempDir::new()?;
        let allow_config = AllowlistConfig::with_state_root(dir.path().join("state"));
        let allow = Allowlist::from_modules(&[], &allow_config)?;
        let (monitor_end, worker_end) = Channel::pair()?;
        let monitor = thread::spawn(move || {
            let mut channel = monitor_end;
            let _ = Monitor::new(allow, Hooks::default()).serve(&mut channel);
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        let host = Detected {
            profile: HostProfile {
                os: Os::Linux,
                init: InitSystem::Systemd,
                hostname: "detent-test".to_owned(),
                service_versions: BTreeMap::new(),
                ram_mib: 1024,
            },
            facts: HostFacts::default(),
        };
        let ops_engine = OpsEngine::new(
            Vec::new(),
            client,
            host,
            Box::new(NullAudit),
            Box::new(AllowAll),
            service::for_host(InitSystem::Systemd),
        );
        let (handle, engine) = spawn_engine(ops_engine);
        fixture.state.engine = handle;
        Ok(Self {
            state: fixture,
            monitor: Some(monitor),
            engine: Some(engine),
            _dir: dir,
        })
    }

    /// The state to build requests against.
    fn state(&self) -> &AppState {
        &self.state.state
    }

    /// Stop the engine thread and wait for the monitor. Best-effort: a test
    /// failure should not be masked by a shutdown failure.
    fn shutdown(mut self) {
        // `EngineThread::join` waits until every `EngineHandle` is dropped —
        // including the one living inside `self.state`'s `AppState` — so
        // that has to go first, or the join below waits forever.
        drop(self.state);
        if let Some(engine) = self.engine.take() {
            let _ = engine.join();
        }
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
    }
}

/// The assembled stack a real deployment serves, minus TLS and the listener.
fn app(state: &AppState) -> axum::Router {
    harden(crate::router(state.clone()), Duration::from_secs(30))
}

/// A bearer-token `Authorization` header value.
fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// `GET path` with an optional bearer token.
async fn get(
    state: &AppState,
    path: &str,
    token: Option<&str>,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, bearer(token));
    }
    Ok(app(state).oneshot(builder.body(Body::empty())?).await?)
}

/// `POST path` with a JSON body and an optional bearer token. A bearer
/// credential is exempt from the CSRF checks (PLAN §2.7), so these requests
/// need no `Sec-Fetch-Site`/`Origin`/`X-Detent-CSRF` triple.
async fn post(
    state: &AppState,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, bearer(token));
    }
    Ok(app(state)
        .oneshot(builder.body(Body::from(body.to_owned()))?)
        .await?)
}

/// The JSON body of a response.
async fn json(
    response: axum::response::Response,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// `code`/`message_id` of an error response.
async fn error_body(
    response: axum::response::Response,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let body = json(response).await?;
    Ok((
        body.pointer("/code")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        body.pointer("/message_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/v1/modules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_modules() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/modules", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let ok = get(live.state(), "/api/v1/modules", Some(&read)).await?;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(json(ok).await?, serde_json::json!([]));

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/modules/{id}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_module() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/modules/hosts", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    for path in ["/api/v1/modules/hosts", "/api/v1/modules/..%2f..%2fetc"] {
        let response = get(live.state(), path, Some(&read)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let (code, id) = error_body(response).await?;
        assert_eq!(code, "not_found");
        assert_eq!(id, "ops-unknown-module");
    }

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/modules/{id}/validate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_module() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = post(live.state(), "/api/v1/modules/hosts/validate", None, "{}").await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let unknown = post(
        live.state(),
        "/api/v1/modules/hosts/validate",
        Some(&read),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    for bad in ["not json", r#"{"model":{},"extra":1}"#, "{}"] {
        let response = post(
            live.state(),
            "/api/v1/modules/hosts/validate",
            Some(&read),
            bad,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
        assert!(!response.status().is_server_error());
    }

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/modules/{id}/plan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plan_module() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = post(live.state(), "/api/v1/modules/hosts/plan", None, "{}").await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let unknown = post(
        live.state(),
        "/api/v1/modules/hosts/plan",
        Some(&read),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/modules/{id}/apply
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_module() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    let unauthenticated = post(live.state(), "/api/v1/modules/hosts/apply", None, "{}").await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(
        live.state(),
        "/api/v1/modules/hosts/apply",
        Some(&read),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_body(wrong_scope).await?.1, "web-denied-scope");

    let unknown = post(
        live.state(),
        "/api/v1/modules/hosts/apply",
        Some(&write),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let bad_hash = post(
        live.state(),
        "/api/v1/modules/hosts/apply",
        Some(&write),
        r#"{"model":{},"expected_hash":"not-hex"}"#,
    )
    .await?;
    assert_eq!(bad_hash.status(), StatusCode::BAD_REQUEST);

    let unknown_field = post(
        live.state(),
        "/api/v1/modules/hosts/apply",
        Some(&write),
        r#"{"model":{},"nope":1}"#,
    )
    .await?;
    assert_eq!(unknown_field.status(), StatusCode::BAD_REQUEST);
    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// Module handler tails (PLAN §6.2: no LCOV_EXCL; tails get tests, not
// exclusions). The `Live` engine registers no modules, so its module-scoped
// answers are always 404 — that covers the unknown-id arms below. The
// `render_*` success tails need an engine that answers success, which is
// what `EngineHandle::stubbed` is for.
// ---------------------------------------------------------------------------

/// A malformed id answers 404 on every module POST route, not just GET.
#[tokio::test]
async fn malformed_module_id_is_404_on_every_post_route() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    // `apply` takes a `WriteCaller`: a read token is refused (403) before
    // the id is ever looked at, so it drives the write token.
    for (path, token) in [
        ("/api/v1/modules/..%2f..%2fetc/validate", &read),
        ("/api/v1/modules/..%2f..%2fetc/plan", &read),
        ("/api/v1/modules/..%2f..%2fetc/apply", &write),
    ] {
        let response = post(live.state(), path, Some(token), r#"{"model":{}}"#).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let (code, id) = error_body(response).await?;
        assert_eq!(code, "not_found");
        assert_eq!(id, "ops-unknown-module");
    }

    live.shutdown();
    Ok(())
}

/// A state whose engine answers every operation with `outcome`.
fn stub_state(outcome: OpOutcome) -> Result<TestState, Box<dyn std::error::Error>> {
    let mut fixture = test_state()?;
    fixture.state.engine = EngineHandle::stubbed(outcome);
    Ok(fixture)
}

/// A minimal descriptor for stubbed success outcomes; never a real module.
static STUB_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "stub",
    display_name_id: MessageId::new("web-request-malformed"),
    targets: &[],
    upstream: Upstream {
        project: "stub",
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

#[tokio::test]
async fn get_module_renders_the_engine_answer() -> R {
    let view = ModuleView {
        descriptor: &STUB_DESCRIPTOR,
        schema: serde_json::json!({}),
        model: None,
        current_hash: None,
        diagnostics: Diagnostics::default(),
    };
    let fixture = stub_state(OpOutcome::Module(Box::new(view)))?;
    let (read, _write) = tokens(&fixture.state)?;

    let response = get(&fixture.state, "/api/v1/modules/stub", Some(&read)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn validate_module_renders_the_engine_answer() -> R {
    let fixture = stub_state(OpOutcome::Validated(Diagnostics::default()))?;
    let (read, _write) = tokens(&fixture.state)?;

    let response = post(
        &fixture.state,
        "/api/v1/modules/stub/validate",
        Some(&read),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn plan_module_renders_the_engine_answer() -> R {
    let report = PlanReport {
        module: "stub".to_owned(),
        path: "/tmp/stub".to_owned(),
        diff: Vec::new(),
        rendered: String::new(),
        unified_diff: String::new(),
        affected_services: Vec::new(),
        checks: Vec::new(),
        diagnostics: Diagnostics::default(),
        current_hash: Sha256Digest::of(b"x"),
        would_change: false,
    };
    let fixture = stub_state(OpOutcome::Planned(Box::new(report)))?;
    let (read, _write) = tokens(&fixture.state)?;

    let response = post(
        &fixture.state,
        "/api/v1/modules/stub/plan",
        Some(&read),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn apply_module_renders_the_engine_answer() -> R {
    let report = ApplyReport {
        module: "stub".to_owned(),
        path: "/tmp/stub".to_owned(),
        prev_hash: None,
        new_hash: Sha256Digest::of(b"x"),
        created: true,
        backed_up: false,
        service: None,
        commit: None,
    };
    let fixture = stub_state(OpOutcome::Applied(Box::new(report)))?;
    let (_read, write) = tokens(&fixture.state)?;

    let response = post(
        &fixture.state,
        "/api/v1/modules/stub/apply",
        Some(&write),
        r#"{"model":{}}"#,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/commits/{id}/confirm and .../rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn confirm_commit() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    let unauthenticated = post(live.state(), "/api/v1/commits/1/confirm", None, "").await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(live.state(), "/api/v1/commits/1/confirm", Some(&read), "").await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    // Never armed: the monitor reports it as an unknown id, a state conflict.
    let unarmed = post(live.state(), "/api/v1/commits/1/confirm", Some(&write), "").await?;
    assert_eq!(unarmed.status(), StatusCode::CONFLICT);

    let malformed_id = post(
        live.state(),
        "/api/v1/commits/not-a-number/confirm",
        Some(&write),
        "",
    )
    .await?;
    assert_eq!(malformed_id.status(), StatusCode::BAD_REQUEST);

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn rollback_commit() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    let unauthenticated = post(live.state(), "/api/v1/commits/1/rollback", None, "").await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(live.state(), "/api/v1/commits/1/rollback", Some(&read), "").await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let unarmed = post(live.state(), "/api/v1/commits/1/rollback", Some(&write), "").await?;
    assert_eq!(unarmed.status(), StatusCode::CONFLICT);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/modules/{id}/backups and POST .../restore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_backups() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/modules/hosts/backups", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let unknown = get(live.state(), "/api/v1/modules/hosts/backups", Some(&read)).await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn restore_backup() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    let unauthenticated = post(
        live.state(),
        "/api/v1/modules/hosts/backups/0/restore",
        None,
        "",
    )
    .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(
        live.state(),
        "/api/v1/modules/hosts/backups/0/restore",
        Some(&read),
        "",
    )
    .await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let unknown = post(
        live.state(),
        "/api/v1/modules/hosts/backups/0/restore",
        Some(&write),
        "",
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let malformed_id = post(
        live.state(),
        "/api/v1/modules/hosts/backups/not-a-number/restore",
        Some(&write),
        "",
    )
    .await?;
    assert_eq!(malformed_id.status(), StatusCode::BAD_REQUEST);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET/POST /api/v1/services/{id}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_status() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/services/hosts", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let unknown = get(live.state(), "/api/v1/services/hosts", Some(&read)).await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn service_action() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;

    let unauthenticated = post(
        live.state(),
        "/api/v1/services/hosts",
        None,
        r#"{"action":"restart"}"#,
    )
    .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(
        live.state(),
        "/api/v1/services/hosts",
        Some(&read),
        r#"{"action":"restart"}"#,
    )
    .await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let unknown = post(
        live.state(),
        "/api/v1/services/hosts",
        Some(&write),
        r#"{"action":"restart"}"#,
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let bad_action = post(
        live.state(),
        "/api/v1/services/hosts",
        Some(&write),
        r#"{"action":"nope"}"#,
    )
    .await?;
    assert_eq!(bad_action.status(), StatusCode::BAD_REQUEST);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/system/profile
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_profile() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/system/profile", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let ok = get(live.state(), "/api/v1/system/profile", Some(&read)).await?;
    assert_eq!(ok.status(), StatusCode::OK);
    let body = json(ok).await?;
    assert_eq!(
        body.pointer("/profile/hostname").and_then(|v| v.as_str()),
        Some("detent-test")
    );

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_query() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/audit", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let ok = get(live.state(), "/api/v1/audit?limit=10", Some(&read)).await?;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(json(ok).await?, serde_json::json!([]));

    let unknown_param = get(live.state(), "/api/v1/audit?nope=1", Some(&read)).await?;
    assert_eq!(unknown_param.status(), StatusCode::BAD_REQUEST);

    let oversized_limit = get(live.state(), "/api/v1/audit?limit=100000000", Some(&read)).await?;
    assert_eq!(oversized_limit.status(), StatusCode::BAD_REQUEST);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/openapi.json and GET /healthz
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_document_needs_a_credential() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/openapi.json", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = get(live.state(), "/api/v1/openapi.json", Some(&read)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    assert!(body.get("openapi").is_some());
    assert!(
        body.pointer("/paths/~1api~1v1~1modules").is_some(),
        "the modules path is missing"
    );

    // The handler serves an `include_str!` constant rather than building the
    // document, so this is the assertion that the bytes on the wire are the
    // document this build describes — not merely well-formed JSON that
    // happens to have the right shape.
    let generated: serde_json::Value = {
        use utoipa::OpenApi as _;
        serde_json::to_value(super::openapi::ApiDoc::openapi())?
    };
    assert_eq!(
        body, generated,
        "the served document is not the one this build generates"
    );

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/system/update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_update_needs_a_credential_and_refuses_nothing_else() -> R {
    let live = Live::new()?;

    // The authenticated 200 path fetches the live release feed
    // (detent_update::update::check), which a test must not do; the report
    // itself is driven with mock transports in `api::system`'s own tests,
    // the same split `cert_report` uses. Here: the route is wired and
    // gated, and a read-scoped credential is *accepted* (scope `read` is
    // what `authorize` checks, before the network step) — the failure of
    // the offline fetch would answer 503, never a panic, which the
    // table-driven sweep below additionally exercises without one.
    let unauthenticated = get(live.state(), "/api/v1/system/update", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/system/update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_apply_needs_write_and_reports_the_stub() -> R {
    let live = Live::new()?;
    let (read, write) = tokens(live.state())?;
    let body = r#"{"version":"v9.9.9"}"#;

    let unauthenticated = post(live.state(), "/api/v1/system/update", None, body).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = post(live.state(), "/api/v1/system/update", Some(&read), body).await?;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_body(wrong_scope).await?.1, "web-denied-scope");

    // Without a staged binary the engine answers `UpdateApply` as
    // `Unsupported`: 500 with the `ops-unsupported` id and a reason, never
    // a silent no-op.
    let stub = post(live.state(), "/api/v1/system/update", Some(&write), body).await?;
    assert_eq!(stub.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_body(stub).await?.1, "ops-unsupported");

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn cert_status_describes_the_certificate_the_listener_serves() -> R {
    let live = Live::new()?;
    let (read, _write) = tokens(live.state())?;

    let unauthenticated = get(live.state(), "/api/v1/system/cert", None).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = get(live.state(), "/api/v1/system/cert", Some(&read)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;

    // The answer must describe the certificate the store actually holds, not
    // a re-derived one: compare against the live resolver.
    let served = live.state().cert_store.current();
    let der = served.cert.first().map(|c| c.to_vec()).unwrap_or_default();
    assert_eq!(
        body.get("fingerprint").and_then(serde_json::Value::as_str),
        Some(crate::tls::fingerprint(&der).as_str())
    );

    // A bootstrap certificate is 90 days long and backdated one hour, so it
    // expires in the future and has spent almost none of its life.
    let not_after = body
        .get("not_after_unix")
        .and_then(serde_json::Value::as_i64)
        .ok_or("not_after_unix must parse from a bootstrap certificate")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(not_after > now, "{not_after} should be in the future");
    let used = body
        .get("lifetime_used_percent")
        .and_then(serde_json::Value::as_u64)
        .ok_or("lifetime_used_percent must be known for a parseable certificate")?;
    assert!(
        used <= 1,
        "a fresh certificate has spent ~0% of its life, got {used}"
    );
    assert_eq!(
        body.get("renewal_due").and_then(serde_json::Value::as_bool),
        Some(false),
        "a fresh certificate is nowhere near the two-thirds renewal threshold"
    );

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn cert_status_reports_unknown_rather_than_failing_on_unparseable_der() -> R {
    // `validity_unix` is deliberately total: a certificate whose DER it cannot
    // walk is reported as "unknown", never as a 500. The store cannot hold
    // garbage, so the report function is driven directly.
    let live = Live::new()?;
    let report = super::system::cert_report(live.state());
    assert!(report.not_after_unix.is_some());

    let blank = crate::tls::fingerprint(&[]);
    assert_ne!(report.fingerprint, blank, "the real certificate was hashed");
    assert_eq!(crate::tls::validity_unix(b"not a certificate"), None);

    live.shutdown();
    Ok(())
}

/// Every route under `/api/v1` other than `/auth/*` refuses a request that
/// carries no credential.
///
/// The per-endpoint tests above each assert this for the one path they drive,
/// but they can only cover a route somebody remembered to write a test for.
/// This one is driven off [`crate::api::table`] — the same table the routers
/// are built from — so a new endpoint whose handler forgets to take a `Caller`
/// fails here instead of shipping open. `/api/v1/openapi.json` was exactly
/// that: it described the whole surface and needed nothing to read it.
///
/// `/healthz` is deliberately excluded: it is not in this table, and a
/// liveness probe has no credential to present.
#[tokio::test]
async fn no_api_route_is_reachable_without_a_credential() -> R {
    let live = Live::new()?;

    for route in crate::api::table() {
        // A path parameter's value is irrelevant — authentication is refused
        // before the engine ever sees the id.
        let path = route
            .path
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') {
                    "x"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");

        assert!(
            matches!(route.method, Method::GET | Method::POST),
            "{} {path}: this sweep can only drive GET and POST",
            route.method
        );
        let response = if route.method == Method::GET {
            get(live.state(), &path, None).await?
        } else {
            post(live.state(), &path, None, "{}").await?
        };
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{} {path} answered without a credential",
            route.method
        );
    }

    live.shutdown();
    Ok(())
}

#[tokio::test]
async fn healthz_is_reachable_through_the_assembled_router() -> R {
    let live = Live::new()?;
    let response = get(live.state(), "/healthz", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    live.shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

/// A read-only and a read-write API token for `state`.
fn tokens(state: &AppState) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (read, _view) = state.auth.tokens.issue("read-caller", Scope::Read, None)?;
    let (write, _view) = state
        .auth
        .tokens
        .issue("write-caller", Scope::Write, None)?;
    Ok((read.expose().to_owned(), write.expose().to_owned()))
}

// ---------------------------------------------------------------------------
// Contract fuzz (PLAN Phase 4 task 4): arbitrary/malformed bodies against
// every endpoint that takes one must never answer 5xx.
// ---------------------------------------------------------------------------

mod contract_fuzz {
    use super::{Live, app, tokens};
    use axum::body::Body;
    use axum::http::{Method, Request, header};
    use proptest::prelude::*;
    use proptest::sample::select;
    use proptest::test_runner::{TestCaseError, TestRunner};
    use tower::ServiceExt as _;

    /// Every route this crate registers with a JSON body, and the scope a
    /// caller needs to reach the handler at all. `ConfirmCommit`,
    /// `RollbackCommit` and `Restore` take no body — the id in the path is
    /// the whole request — so they are not here.
    const BODIED_ROUTES: &[(&str, &str)] = &[
        ("/api/v1/modules/hosts/validate", "read"),
        ("/api/v1/modules/hosts/plan", "read"),
        ("/api/v1/modules/hosts/apply", "write"),
        ("/api/v1/services/hosts", "write"),
        ("/api/v1/system/update", "write"),
    ];

    /// A mix of pure noise (exercises `JsonRejection`'s syntax-error path),
    /// scalars and arrays where an object is expected, and objects shaped
    /// close to a real body but carrying a field none of them declare
    /// (exercises `deny_unknown_fields`).
    fn arbitrary_body() -> impl Strategy<Value = String> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..512)
                .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            any::<String>().prop_map(|extra| {
                serde_json::json!({ "model": {}, "extra_field": extra }).to_string()
            }),
            any::<i64>().prop_map(|n| n.to_string()),
            any::<bool>().prop_map(|b| b.to_string()),
            Just(String::new()),
            Just("null".to_owned()),
            Just("[]".to_owned()),
            Just("{".to_owned()),
            Just(r#"{"model": null}"#.to_owned()),
            Just(r#"{"model": "not an object"}"#.to_owned()),
            Just(r#"{"action": "not-a-real-action"}"#.to_owned()),
            Just(r#"{"model": {}, "expected_hash": "not-hex"}"#.to_owned()),
        ]
    }

    #[test]
    fn no_bodied_endpoint_ever_answers_5xx() -> Result<(), Box<dyn std::error::Error>> {
        let live = Live::new()?;
        let (read, write) = tokens(live.state())?;
        let runtime = tokio::runtime::Runtime::new()?;

        let strategy = (select(BODIED_ROUTES), arbitrary_body());
        // This runner is built by hand rather than through the `proptest!`
        // macro (which wants its own `#[test]` fn) so the live fixture above
        // can be built once and shared across every case. There is no source
        // file for the macro to persist regressions against, so persistence
        // is off rather than warning about it on every run.
        let mut runner = TestRunner::new(proptest::test_runner::Config {
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        });
        let outcome = runner.run(&strategy, |((path, scope), body)| {
            let token = if scope == "write" { &write } else { &read };
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.clone()))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let response = runtime
                .block_on(app(live.state()).oneshot(request))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert!(
                !response.status().is_server_error(),
                "{path} answered {} to {body:?}",
                response.status()
            );
            Ok(())
        });

        live.shutdown();
        outcome.map_err(|error| format!("{error}").into())
    }

    /// A body nested far past anything a real model reaches must answer 4xx
    /// rather than exhausting the stack while `serde_json` parses it.
    ///
    /// `MAX_JSON_DEPTH` guards an *already-parsed* `Value`, so on its own it
    /// says nothing about the parse itself. What makes the parse safe is that
    /// `serde_json` enforces its own 128-deep recursion limit unless
    /// `Deserializer::disable_recursion_limit` is called, and nothing in this
    /// workspace calls it. That is a property of a dependency's default rather
    /// than of code in this repo, so it is asserted here instead of assumed:
    /// if a future `serde_json` changes the default, or somebody enables the
    /// `unbounded_depth` feature, this test fails instead of the server
    /// crashing.
    #[test]
    fn a_pathologically_nested_body_is_refused_without_crashing()
    -> Result<(), Box<dyn std::error::Error>> {
        let live = Live::new()?;
        let (read, _write) = tokens(live.state())?;
        let runtime = tokio::runtime::Runtime::new()?;

        // Small on the wire — 20 KiB, far under the 256 KiB body limit — and
        // 10 000 levels deep. Depth, not size, is the attack.
        let depth = 10_000;
        let body = format!("{{\"model\":{}{}}}", "[".repeat(depth), "]".repeat(depth));

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/modules/hosts/validate")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {read}"))
            .body(Body::from(body))?;
        let response = runtime.block_on(app(live.state()).oneshot(request))?;

        let status = response.status();
        live.shutdown();
        assert!(
            status.is_client_error(),
            "a {depth}-deep body answered {status}"
        );
        Ok(())
    }
}
