//! Route tests for [`super`]: a stepped-up session lists, mints and revokes
//! API tokens.

use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use tower::ServiceExt as _;

use super::{IssuedToken, TOKEN_REVOKE_PATH, TOKENS_PATH};
use crate::auth::audit::AuthEvent;
use crate::auth::extract::unix_now;
use crate::auth::routes::{LOGIN_PATH, routes};
use crate::auth::session::{COOKIE_NAME, STEP_UP_TTL};
use crate::auth::token::{MAX_LABEL_LEN, MAX_TOKENS, TokenStore, TokenView};
use crate::authz::{Scope, Scopes};
use crate::csrf::{CSRF_HEADER, SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
use crate::server::harden;
use crate::state::{AppState, TestState, test_state};

type R = Result<(), Box<dyn std::error::Error>>;
type E = Box<dyn std::error::Error>;

const PASSWORD: &str = "hunter2";
const ORIGIN: &str = "https://box.example:3333";

fn app(state: &AppState) -> Router {
    harden(
        routes()
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_guard,
            ))
            .with_state(state.clone()),
        Duration::from_secs(30),
    )
}

/// Alice; Carol must change her password.
fn fixture() -> Result<TestState, E> {
    let fixture = test_state()?;
    for (name, flagged) in [("alice", false), ("carol", true)] {
        fixture
            .state
            .auth
            .users
            .create(&fixture.state.auth.hasher, name, PASSWORD, flagged)?;
    }
    Ok(fixture)
}

/// A state over `fixture`'s stores, but with `auth.totp_required` set.
fn required_state(fixture: &TestState) -> Result<AppState, E> {
    let mut config = (*fixture.state.config).clone();
    config.auth.totp_required = true;
    Ok(AppState::new(
        crate::engine::EngineHandle::detached(),
        crate::state::AuthState::open_with_audit(
            fixture.state_root(),
            &config.auth,
            4096,
            Box::new(crate::state::SharedCapture(std::sync::Arc::clone(
                &fixture.audit,
            ))),
        )?,
        config.clone(),
        crate::csrf::Origin::for_config(&config),
        std::sync::Arc::clone(&fixture.state.cert_store),
        fixture.state_root().to_path_buf(),
    ))
}

/// A signed-in browser: the cookie id and the CSRF token.
struct Browser {
    id: String,
    csrf: String,
}

async fn json(response: axum::response::Response) -> Result<serde_json::Value, E> {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn sign_in(state: &AppState, name: &str) -> Result<Browser, E> {
    let body = serde_json::json!({"username": name, "password": PASSWORD});
    let response = app(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let id = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("no Set-Cookie")?
        .to_str()?
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .ok_or("no cookie value")?
        .1
        .to_owned();
    let csrf = json(response)
        .await?
        .pointer("/csrf_token")
        .and_then(|v| v.as_str())
        .ok_or("no csrf token")?
        .to_owned();
    Ok(Browser { id, csrf })
}

/// A session made directly in the store, as a sign-in with or without a
/// code would make it.
fn session(state: &AppState, scopes: Scopes, totp_satisfied: bool) -> Result<Browser, E> {
    let (id, session) =
        state
            .auth
            .sessions
            .create("alice", scopes, totp_satisfied, Instant::now())?;
    Ok(Browser {
        id: id.expose().to_owned(),
        csrf: session.csrf_token.expose().to_owned(),
    })
}

/// Step `browser` up, now or (with `ago`) that long ago.
fn step_up(state: &AppState, browser: &Browser, ago: Duration) -> Result<(), E> {
    let at = Instant::now().checked_sub(ago).ok_or("clock too young")?;
    assert!(state.auth.sessions.step_up(&browser.id, at));
    Ok(())
}

/// A request from `browser` with `body`, with the CSRF token when `csrf` is
/// set.
fn from(
    browser: &Browser,
    method: Method,
    uri: &str,
    body: &str,
    csrf: bool,
) -> Result<Request<Body>, E> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("{COOKIE_NAME}={}", browser.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(SEC_FETCH_SITE, SAME_ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .header(header::HOST, "box.example:3333");
    if csrf {
        builder = builder.header(CSRF_HEADER, &browser.csrf);
    }
    Ok(builder.body(Body::from(body.to_owned()))?)
}

fn revoke_uri(id: &str) -> String {
    TOKEN_REVOKE_PATH.replace("{id}", id)
}

/// `POST /api/v1/auth/tokens` from `browser` with `body`.
async fn mint(
    state: &AppState,
    browser: &Browser,
    body: &serde_json::Value,
) -> Result<axum::response::Response, E> {
    Ok(app(state)
        .oneshot(from(
            browser,
            Method::POST,
            TOKENS_PATH,
            &body.to_string(),
            true,
        )?)
        .await?)
}

/// `POST /api/v1/auth/tokens/{id}/revoke` from `browser`.
async fn revoke(
    state: &AppState,
    browser: &Browser,
    id: &str,
) -> Result<axum::response::Response, E> {
    Ok(app(state)
        .oneshot(from(browser, Method::POST, &revoke_uri(id), "", true)?)
        .await?)
}

/// The list `browser` sees.
async fn list(state: &AppState, browser: &Browser) -> Result<serde_json::Value, E> {
    let response = app(state)
        .oneshot(from(browser, Method::GET, TOKENS_PATH, "", false)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json(response).await
}

async fn message_id(response: axum::response::Response) -> Result<String, E> {
    Ok(json(response)
        .await?
        .pointer("/message_id")
        .and_then(|v| v.as_str())
        .ok_or("no message id")?
        .to_owned())
}

fn token_events(fixture: &TestState) -> Vec<AuthEvent> {
    fixture
        .audit
        .events()
        .into_iter()
        .filter(|event| matches!(event, AuthEvent::TokenIssued | AuthEvent::TokenRevoked))
        .collect()
}

fn write_token() -> serde_json::Value {
    serde_json::json!({"label": "ci", "scope": "write"})
}

#[tokio::test]
async fn a_stepped_up_session_mints_a_token_that_is_shown_once_and_works_at_once() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;

    let before = unix_now();
    let response = mint(
        state,
        &alice,
        &serde_json::json!({"label": "backup job", "scope": "read", "expires_in_secs": 3600}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await?;
    let mut keys: Vec<&str> = body
        .as_object()
        .ok_or("not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["created", "expires_at", "id", "label", "scopes", "token"]
    );
    assert_eq!(
        body.pointer("/label"),
        Some(&serde_json::json!("backup job"))
    );
    assert_eq!(body.pointer("/scopes"), Some(&serde_json::json!(["read"])));
    let expires_at = body
        .pointer("/expires_at")
        .and_then(serde_json::Value::as_i64)
        .ok_or("no expiry")?;
    assert!(
        (before.saturating_add(3600)..=unix_now().saturating_add(3600)).contains(&expires_at),
        "{expires_at}"
    );
    let token = body
        .pointer("/token")
        .and_then(|v| v.as_str())
        .ok_or("no token")?
        .to_owned();
    let id = body
        .pointer("/id")
        .and_then(|v| v.as_str())
        .ok_or("no id")?
        .to_owned();

    // It authenticates at once through the store that serves requests, and
    // the command line, which loads the file afresh, sees it too.
    let identity = state.auth.tokens.authenticate(&token, unix_now())?;
    assert_eq!(identity.id, id);
    assert_eq!(identity.scopes, Scopes::read_only());
    let cli = TokenStore::load(fixture.state_root())?;
    assert_eq!(cli.authenticate(&token, unix_now())?.id, id);

    // The list names it and never carries the value.
    let listed = list(state, &alice).await?;
    let text = listed.to_string();
    assert!(text.contains(&id), "{text}");
    assert!(!text.contains(&token), "{text}");
    for entry in listed.as_array().ok_or("not an array")? {
        assert!(entry.pointer("/token").is_none(), "{entry}");
        assert!(entry.pointer("/digest").is_none(), "{entry}");
    }

    // Audited by id, with alice as the actor and the address; no value.
    let record = fixture
        .audit
        .records()
        .into_iter()
        .find(|r| r.event == AuthEvent::TokenIssued)
        .ok_or("no token_issued record")?;
    assert_eq!(record.subject, format!("token:{id}"));
    assert_eq!(record.kind, IdentityKind::Session);
    assert_eq!(record.actor.as_deref(), Some("alice"));
    assert_eq!(record.result, AuditResult::Ok);
    assert!(record.client_ip.is_some());
    Ok(())
}

#[tokio::test]
async fn the_value_is_in_no_debug_output_and_no_audit_record() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    let body = json(mint(state, &alice, &write_token()).await?).await?;
    let token = body
        .pointer("/token")
        .and_then(|v| v.as_str())
        .ok_or("no token")?
        .to_owned();
    let id = body
        .pointer("/id")
        .and_then(|v| v.as_str())
        .ok_or("no id")?
        .to_owned();
    let view: TokenView = state
        .auth
        .tokens
        .list()
        .into_iter()
        .find(|view| view.id == id)
        .ok_or("not listed")?;

    let issued = IssuedToken {
        token: token.clone(),
        view,
    };
    let rendered = format!("{issued:?} {:?}", state.auth.tokens);
    assert!(rendered.contains(&id), "{rendered}");
    assert!(!rendered.contains(&token), "{rendered}");

    // The tracing line of each record is built from these same fields.
    let records = serde_json::to_string(&fixture.audit.records())?;
    assert!(records.contains(&id), "{records}");
    assert!(!records.contains(&token), "{records}");
    let file = std::fs::read_to_string(state.auth.tokens.path())?;
    assert!(!file.contains(&token));
    Ok(())
}

#[tokio::test]
async fn the_list_shows_tokens_the_command_line_made_and_a_get_mints_nothing() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    assert_eq!(list(state, &alice).await?, serde_json::json!([]));

    // The command line is another process with its own store over the file.
    let cli = TokenStore::load(fixture.state_root())?;
    let (secret, view) = cli.issue("laptop", Scope::Write, Some(4_000_000_000))?;

    let listed = list(state, &alice).await?;
    let entries = listed.as_array().ok_or("not an array")?;
    assert_eq!(entries.len(), 1);
    let entry = entries.first().ok_or("empty")?;
    let mut keys: Vec<&str> = entry
        .as_object()
        .ok_or("not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["created", "expires_at", "id", "label", "scopes"]);
    assert_eq!(entry.pointer("/id"), Some(&serde_json::json!(view.id)));
    assert_eq!(
        entry.pointer("/scopes"),
        Some(&serde_json::json!(["read", "write"]))
    );
    assert_eq!(
        entry.pointer("/expires_at"),
        Some(&serde_json::json!(4_000_000_000_i64))
    );
    assert!(!listed.to_string().contains(secret.expose()));
    assert_eq!(state.auth.tokens.list().len(), 1);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn a_token_the_command_line_made_meanwhile_survives_a_console_mint() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    // The served store has read the (empty) file; the CLI writes after that.
    assert_eq!(state.auth.tokens.list(), [] as [TokenView; 0]);
    let cli = TokenStore::load(fixture.state_root())?;
    let (cli_secret, cli_view) = cli.issue("laptop", Scope::Read, None)?;

    assert_eq!(
        mint(state, &alice, &write_token()).await?.status(),
        StatusCode::CREATED
    );
    let on_disk = TokenStore::load(fixture.state_root())?;
    let labels: Vec<String> = on_disk.list().into_iter().map(|v| v.label).collect();
    assert_eq!(labels, vec!["laptop".to_owned(), "ci".to_owned()]);
    assert_eq!(
        state
            .auth
            .tokens
            .authenticate(cli_secret.expose(), unix_now())?
            .id,
        cli_view.id
    );
    Ok(())
}

#[tokio::test]
async fn minting_and_revoking_need_a_step_up_younger_than_five_minutes() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let (_secret, view) = state.auth.tokens.issue("laptop", Scope::Read, None)?;

    for stepped in [None, Some(STEP_UP_TTL)] {
        if let Some(ago) = stepped {
            step_up(state, &alice, ago)?;
        }
        let minted = mint(state, &alice, &write_token()).await?;
        assert_eq!(minted.status(), StatusCode::FORBIDDEN, "{stepped:?}");
        assert_eq!(message_id(minted).await?, "web-auth-step-up-required");
        let revoked = revoke(state, &alice, &view.id).await?;
        assert_eq!(revoked.status(), StatusCode::FORBIDDEN, "{stepped:?}");
        assert_eq!(message_id(revoked).await?, "web-auth-step-up-required");
    }
    assert_eq!(state.auth.tokens.list().len(), 1);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);

    // One second inside the window is enough.
    step_up(
        state,
        &alice,
        STEP_UP_TTL
            .checked_sub(Duration::from_secs(1))
            .ok_or("ttl")?,
    )?;
    assert_eq!(
        revoke(state, &alice, &view.id).await?.status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}

#[tokio::test]
async fn a_session_without_a_second_factor_cannot_mint_where_one_is_required() -> R {
    let fixture = fixture()?;
    let state = required_state(&fixture)?;

    let unsatisfied = session(&state, Scopes::read_write(), false)?;
    step_up(&state, &unsatisfied, Duration::ZERO)?;
    let refused = mint(&state, &unsatisfied, &write_token()).await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(message_id(refused).await?, "web-auth-token-totp-required");
    assert_eq!(state.auth.tokens.list(), [] as [TokenView; 0]);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);

    // Asked before the step-up, so the dialog is not shown for nothing.
    let fresh = session(&state, Scopes::read_write(), false)?;
    let refused = mint(&state, &fresh, &write_token()).await?;
    assert_eq!(message_id(refused).await?, "web-auth-token-totp-required");

    let satisfied = session(&state, Scopes::read_write(), true)?;
    step_up(&state, &satisfied, Duration::ZERO)?;
    assert_eq!(
        mint(&state, &satisfied, &write_token()).await?.status(),
        StatusCode::CREATED
    );

    // Without the setting, the same session as the first one may mint.
    let plain = session(&fixture.state, Scopes::read_write(), false)?;
    step_up(&fixture.state, &plain, Duration::ZERO)?;
    assert_eq!(
        mint(&fixture.state, &plain, &write_token()).await?.status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[tokio::test]
async fn a_read_only_session_cannot_mint_any_token_or_revoke_one() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let reader = session(state, Scopes::read_only(), true)?;
    step_up(state, &reader, Duration::ZERO)?;
    let (_secret, view) = state.auth.tokens.issue("laptop", Scope::Read, None)?;

    for scope in ["write", "read"] {
        let refused = mint(
            state,
            &reader,
            &serde_json::json!({"label": "x", "scope": scope}),
        )
        .await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{scope}");
        assert_eq!(message_id(refused).await?, "web-denied-scope");
    }
    let refused = revoke(state, &reader, &view.id).await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.auth.tokens.list().len(), 1);
    // It may still read the list.
    assert_eq!(
        list(state, &reader).await?.as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn an_unusable_label_or_expiry_or_body_is_refused_and_nothing_is_issued() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;

    let too_long = "x".repeat(MAX_LABEL_LEN.saturating_add(1));
    for label in [
        "",
        "line\nbreak",
        "tab\there",
        "bidi\u{202e}mark",
        &too_long,
    ] {
        let refused = mint(
            state,
            &alice,
            &serde_json::json!({"label": label, "scope": "read"}),
        )
        .await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{label:?}");
        assert_eq!(message_id(refused).await?, "web-auth-token-label-invalid");
    }
    // Zero, past `i64::MAX` seconds, and a sum past `i64::MAX`.
    for secs in [0, u64::MAX, i64::MAX.unsigned_abs()] {
        let refused = mint(
            state,
            &alice,
            &serde_json::json!({"label": "ci", "scope": "read", "expires_in_secs": secs}),
        )
        .await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{secs}");
        assert_eq!(message_id(refused).await?, "web-auth-token-expiry-invalid");
    }
    for body in [
        "not json",
        r#"{"label":"ci"}"#,
        r#"{"scope":"read"}"#,
        r#"{"label":"ci","scope":"admin"}"#,
        r#"{"label":"ci","scope":"read","expires_in_secs":-5}"#,
        r#"{"label":"ci","scope":"read","expires_in_secs":1.5}"#,
        r#"{"label":"ci","scope":"read","extra":1}"#,
    ] {
        let refused = app(state)
            .oneshot(from(&alice, Method::POST, TOKENS_PATH, body, true)?)
            .await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            message_id(refused).await?,
            "web-request-malformed",
            "{body}"
        );
    }
    assert_eq!(state.auth.tokens.list(), [] as [TokenView; 0]);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);

    // The longest label and a one-second expiry are fine.
    let longest = "x".repeat(MAX_LABEL_LEN);
    let minted = mint(
        state,
        &alice,
        &serde_json::json!({"label": longest, "scope": "read", "expires_in_secs": 1}),
    )
    .await?;
    assert_eq!(minted.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn a_full_store_answers_409() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    for index in 0..MAX_TOKENS {
        let (_secret, _view) =
            state
                .auth
                .tokens
                .issue(&format!("token-{index}"), Scope::Read, None)?;
    }
    let refused = mint(state, &alice, &write_token()).await?;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(message_id(refused).await?, "web-auth-token-limit");
    assert_eq!(state.auth.tokens.list().len(), MAX_TOKENS);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn a_revoked_token_stops_working_at_once_and_the_revocation_is_audited() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    let (secret, view) = state.auth.tokens.issue("laptop", Scope::Write, None)?;
    let (kept, _kept_view) = state.auth.tokens.issue("ci", Scope::Read, None)?;

    let response = revoke(state, &alice, &view.id).await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        state
            .auth
            .tokens
            .authenticate(secret.expose(), unix_now())
            .is_err()
    );
    assert!(
        TokenStore::load(fixture.state_root())?
            .authenticate(secret.expose(), unix_now())
            .is_err()
    );
    assert!(
        state
            .auth
            .tokens
            .authenticate(kept.expose(), unix_now())
            .is_ok()
    );

    let record = fixture
        .audit
        .records()
        .into_iter()
        .find(|r| r.event == AuthEvent::TokenRevoked)
        .ok_or("no token_revoked record")?;
    assert_eq!(record.subject, format!("token:{}", view.id));
    assert_eq!(record.kind, IdentityKind::Session);
    assert_eq!(record.actor.as_deref(), Some("alice"));
    assert!(record.client_ip.is_some());
    Ok(())
}

#[tokio::test]
async fn revoking_an_unknown_id_is_404_and_writes_nothing() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    let (_secret, view) = state.auth.tokens.issue("laptop", Scope::Read, None)?;
    // A token the command line revoked after the console read the file.
    TokenStore::load(fixture.state_root())?.revoke(&view.id)?;

    for id in [view.id.as_str(), "0123456789abcdef", "x"] {
        let response = revoke(state, &alice, id).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{id}");
        assert_eq!(
            json(response).await?,
            serde_json::json!({"code": "not_found", "message_id": "web-auth-token-unknown"})
        );
    }
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn the_token_writes_need_the_csrf_token() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    step_up(state, &alice, Duration::ZERO)?;
    let (_secret, view) = state.auth.tokens.issue("laptop", Scope::Read, None)?;

    for (uri, body) in [
        (TOKENS_PATH.to_owned(), write_token().to_string()),
        (revoke_uri(&view.id), String::new()),
    ] {
        let response = app(state)
            .oneshot(from(&alice, Method::POST, &uri, &body, false)?)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(message_id(response).await?, "web-auth-csrf-rejected");
    }
    assert_eq!(state.auth.tokens.list().len(), 1);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_or_no_credential_cannot_list_mint_or_revoke_tokens() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (token, view) = state.auth.tokens.issue("ci", Scope::Write, None)?;

    for (method, uri, body) in [
        (Method::GET, TOKENS_PATH.to_owned(), String::new()),
        (
            Method::POST,
            TOKENS_PATH.to_owned(),
            write_token().to_string(),
        ),
        (Method::POST, revoke_uri(&view.id), String::new()),
    ] {
        for bearer in [Some(token.expose()), None] {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(&uri)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(token) = bearer {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = app(state)
                .oneshot(request.body(Body::from(body.clone()))?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
            assert_eq!(message_id(response).await?, "web-auth-unauthenticated");
        }
    }
    assert_eq!(state.auth.tokens.list().len(), 1);
    assert_eq!(token_events(&fixture), [] as [AuthEvent; 0]);
    Ok(())
}

#[tokio::test]
async fn a_session_that_owes_a_password_change_cannot_reach_the_token_routes() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let carol = sign_in(state, "carol").await?;
    step_up(state, &carol, Duration::ZERO)?;
    let (_secret, view) = state.auth.tokens.issue("ci", Scope::Read, None)?;

    for (method, uri, body) in [
        (Method::GET, TOKENS_PATH.to_owned(), String::new()),
        (
            Method::POST,
            TOKENS_PATH.to_owned(),
            write_token().to_string(),
        ),
        (Method::POST, revoke_uri(&view.id), String::new()),
    ] {
        let response = app(state)
            .oneshot(from(
                &carol,
                method.clone(),
                &uri,
                &body,
                method == Method::POST,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            message_id(response).await?,
            "web-auth-password-change-required"
        );
    }
    assert_eq!(state.auth.tokens.list().len(), 1);
    Ok(())
}

#[test]
fn an_expiry_is_now_plus_the_seconds_or_refused() {
    assert_eq!(super::expiry(1_000, 60).ok(), Some(1_060));
    assert_eq!(super::expiry(0, 1).ok(), Some(1));
    assert_eq!(
        super::expiry(0, i64::MAX.unsigned_abs()).ok(),
        Some(i64::MAX)
    );
    for (now, secs) in [
        (1_000, 0),
        (1, i64::MAX.unsigned_abs()),
        (0, i64::MAX.unsigned_abs().saturating_add(1)),
        (0, u64::MAX),
    ] {
        assert!(super::expiry(now, secs).is_err(), "{now} {secs}");
    }
}
