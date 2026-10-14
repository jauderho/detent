//! Route tests for [`super`]: the notices a user gets after signing in.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use tower::ServiceExt as _;

use super::{MAX_CHANGES, NOTICES_PATH};
use crate::auth::audit::{AuthEvent, AuthRecord};
use crate::auth::routes::{LOGIN_PATH, routes};
use crate::auth::session::COOKIE_NAME;
use crate::authz::Scope;
use crate::csrf::{SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
use crate::server::harden;
use crate::state::{AppState, TestState, test_state};

type R = Result<(), Box<dyn std::error::Error>>;
type E = Box<dyn std::error::Error>;

const PASSWORD: &str = "hunter2";
const ORIGIN: &str = "https://box.example:3333";
const CLI: IdentityKind = IdentityKind::LocalUser;
const SESSION: IdentityKind = IdentityKind::Session;

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

fn fixture() -> Result<TestState, E> {
    let fixture = test_state()?;
    for name in ["alice", "bob"] {
        fixture
            .state
            .auth
            .users
            .create(&fixture.state.auth.hasher, name, PASSWORD, false)?;
    }
    Ok(fixture)
}

/// Put one record in the log, as if an earlier request had written it.
fn seed(
    fixture: &TestState,
    event: AuthEvent,
    subject: &str,
    kind: IdentityKind,
    ip: Option<&str>,
) {
    let mut record = AuthRecord::new(event, subject, AuditResult::Ok).with_kind(kind);
    if let Some(ip) = ip {
        record = record.with_client_ip(ip);
    }
    fixture.state.auth.audit.record(&record);
}

async fn sign_in(state: &AppState, name: &str) -> Result<String, E> {
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
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("no Set-Cookie")?
        .to_str()?;
    Ok(cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .ok_or("no cookie value")?
        .1
        .to_owned())
}

async fn notices_for(state: &AppState, id: &str) -> Result<serde_json::Value, E> {
    let response = app(state)
        .oneshot(
            Request::builder()
                .uri(NOTICES_PATH)
                .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                .header(SEC_FETCH_SITE, SAME_ORIGIN)
                .header(header::HOST, "box.example:3333")
                .header(header::ORIGIN, ORIGIN)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn kinds(body: &serde_json::Value) -> Vec<&str> {
    body.pointer("/changes")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|c| c.pointer("/change").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

fn failed(body: &serde_json::Value) -> Option<u64> {
    body.pointer("/failed_sign_ins")
        .and_then(serde_json::Value::as_u64)
}

#[tokio::test]
async fn a_user_sees_only_changes_since_the_previous_sign_in() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    // Before the previous sign-in: not shown.
    seed(&fixture, AuthEvent::PasswordChanged, "alice", CLI, None);
    seed(
        &fixture,
        AuthEvent::LoginSucceeded,
        "alice",
        SESSION,
        Some("198.51.100.1"),
    );
    // After it: shown.
    seed(&fixture, AuthEvent::PasswordChanged, "alice", CLI, None);
    seed(
        &fixture,
        AuthEvent::TotpEnabled,
        "alice",
        SESSION,
        Some("198.51.100.9"),
    );
    seed(&fixture, AuthEvent::TotpDisabled, "alice", CLI, None);
    seed(&fixture, AuthEvent::TokenIssued, "token:t1", CLI, None);
    seed(&fixture, AuthEvent::TokenRevoked, "token:t1", CLI, None);
    let id = sign_in(state, "alice").await?;

    let body = notices_for(state, &id).await?;
    assert_eq!(
        kinds(&body),
        vec![
            "token_revoked",
            "token_issued",
            "totp_disabled",
            "totp_enabled",
            "password_changed"
        ],
        "{body}"
    );
    assert!(
        body.pointer("/since")
            .is_some_and(serde_json::Value::is_string)
    );
    assert_eq!(
        body.pointer("/changes/3/source").and_then(|v| v.as_str()),
        Some("session")
    );
    assert_eq!(
        body.pointer("/changes/4/source").and_then(|v| v.as_str()),
        Some("cli")
    );
    assert_eq!(
        body.pointer("/changes/3/client_ip")
            .and_then(|v| v.as_str()),
        Some("198.51.100.9")
    );
    assert!(
        body.pointer("/changes/4/client_ip")
            .is_some_and(serde_json::Value::is_null)
    );
    Ok(())
}

#[tokio::test]
async fn another_users_changes_and_failures_are_not_shown() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    seed(&fixture, AuthEvent::LoginSucceeded, "alice", SESSION, None);
    seed(&fixture, AuthEvent::PasswordChanged, "bob", CLI, None);
    seed(&fixture, AuthEvent::TotpEnabled, "bob", SESSION, None);
    seed(&fixture, AuthEvent::LoginFailed, "bob", SESSION, None);
    // A different user's sign-in does not move alice's window.
    seed(&fixture, AuthEvent::LoginSucceeded, "bob", SESSION, None);
    let id = sign_in(state, "alice").await?;

    let body = notices_for(state, &id).await?;
    assert!(kinds(&body).is_empty(), "{body}");
    assert_eq!(failed(&body), Some(0));
    Ok(())
}

#[tokio::test]
async fn refused_sign_ins_for_the_user_are_counted() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    seed(&fixture, AuthEvent::LoginFailed, "alice", SESSION, None);
    seed(&fixture, AuthEvent::LoginSucceeded, "alice", SESSION, None);
    seed(&fixture, AuthEvent::LoginFailed, "alice", SESSION, None);
    seed(&fixture, AuthEvent::LoginFailed, "alice", SESSION, None);
    seed(&fixture, AuthEvent::LoginFailed, "bob", SESSION, None);
    let id = sign_in(state, "alice").await?;

    assert_eq!(failed(&notices_for(state, &id).await?), Some(2));
    Ok(())
}

#[tokio::test]
async fn the_list_is_capped_and_keeps_the_newest() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    seed(&fixture, AuthEvent::LoginSucceeded, "alice", SESSION, None);
    seed(&fixture, AuthEvent::TotpDisabled, "alice", CLI, None);
    for _ in 0..MAX_CHANGES {
        seed(&fixture, AuthEvent::PasswordChanged, "alice", CLI, None);
    }
    let id = sign_in(state, "alice").await?;

    let body = notices_for(state, &id).await?;
    assert_eq!(kinds(&body).len(), MAX_CHANGES, "{body}");
    assert!(!kinds(&body).contains(&"totp_disabled"), "{body}");
    Ok(())
}

#[tokio::test]
async fn a_first_sign_in_and_a_quiet_one_answer_empty() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    seed(&fixture, AuthEvent::PasswordChanged, "alice", CLI, None);
    let first = sign_in(state, "alice").await?;
    let body = notices_for(state, &first).await?;
    assert!(kinds(&body).is_empty(), "{body}");
    assert!(
        body.pointer("/since")
            .is_some_and(serde_json::Value::is_null)
    );

    let second = sign_in(state, "alice").await?;
    let body = notices_for(state, &second).await?;
    assert!(kinds(&body).is_empty(), "{body}");
    assert!(
        body.pointer("/since")
            .is_some_and(serde_json::Value::is_string)
    );
    assert_eq!(failed(&body), Some(0));
    Ok(())
}

#[tokio::test]
async fn a_failed_change_is_not_a_notice() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    seed(&fixture, AuthEvent::LoginSucceeded, "alice", SESSION, None);
    for event in [AuthEvent::PasswordChangeFailed, AuthEvent::PasswordChanged] {
        state
            .auth
            .audit
            .record(&AuthRecord::new(event, "alice", AuditResult::Error));
    }
    let id = sign_in(state, "alice").await?;
    assert_eq!(kinds(&notices_for(state, &id).await?), [] as [&str; 0]);
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_and_no_credential_are_refused() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (token, _view) = state.auth.tokens.issue("robot", Scope::Read, None)?;
    for authorization in [Some(format!("Bearer {}", token.expose())), None] {
        let mut builder = Request::builder().uri(NOTICES_PATH);
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let response = app(state).oneshot(builder.body(Body::empty())?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

#[tokio::test]
async fn a_session_that_owes_a_password_change_is_refused() -> R {
    let fixture = test_state()?;
    let state = &fixture.state;
    state
        .auth
        .users
        .create(&state.auth.hasher, "alice", PASSWORD, true)?;
    let id = sign_in(state, "alice").await?;
    let response = app(state)
        .oneshot(
            Request::builder()
                .uri(NOTICES_PATH)
                .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}
