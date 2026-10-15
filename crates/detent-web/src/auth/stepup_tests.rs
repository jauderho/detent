//! Route tests for [`super`]: a session steps up with its password, and its
//! second factor when the account has one.

use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt as _;

use super::{ReauthRequest, STEP_UP_SECS};
use crate::auth::audit::AuthEvent;
use crate::auth::routes::{LOGIN_PATH, PASSWORD_PATH, REAUTH_PATH, SESSION_PATH, routes};
use crate::auth::session::COOKIE_NAME;
use crate::auth::totp::{STEP_SECS, TotpSecret};
use crate::authz::Scope;
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

/// A signed-in browser: the cookie id and the CSRF token.
struct Browser {
    id: String,
    csrf: String,
}

async fn json(response: axum::response::Response) -> Result<serde_json::Value, E> {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// The cookie id a response sets.
fn cookie_of(response: &axum::response::Response) -> Result<String, E> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("no Set-Cookie")?
        .to_str()?
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .ok_or("no cookie value")?
        .1
        .to_owned())
}

async fn sign_in(state: &AppState, body: serde_json::Value) -> Result<Browser, E> {
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
    let id = cookie_of(&response)?;
    let csrf = json(response)
        .await?
        .pointer("/csrf_token")
        .and_then(|v| v.as_str())
        .ok_or("no csrf token")?
        .to_owned();
    Ok(Browser { id, csrf })
}

async fn sign_in_as(state: &AppState, name: &str) -> Result<Browser, E> {
    sign_in(
        state,
        serde_json::json!({"username": name, "password": PASSWORD}),
    )
    .await
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

/// `POST /api/v1/auth/reauth` from `browser` with `body`.
async fn reauth(
    state: &AppState,
    browser: &Browser,
    body: &serde_json::Value,
) -> Result<axum::response::Response, E> {
    Ok(app(state)
        .oneshot(from(
            browser,
            Method::POST,
            REAUTH_PATH,
            &body.to_string(),
            true,
        )?)
        .await?)
}

fn with_password(password: &str) -> serde_json::Value {
    serde_json::json!({ "password": password })
}

/// What `GET /api/v1/auth/session` says about the step-up of `browser`.
async fn step_up_left(state: &AppState, browser: &Browser) -> Result<serde_json::Value, E> {
    let response = app(state)
        .oneshot(from(browser, Method::GET, SESSION_PATH, "", false)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(json(response)
        .await?
        .pointer("/step_up_expires_in_secs")
        .cloned()
        .ok_or("no step_up_expires_in_secs")?)
}

async fn message_id(response: axum::response::Response) -> Result<String, E> {
    Ok(json(response)
        .await?
        .pointer("/message_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned())
}

fn count(fixture: &TestState, event: AuthEvent) -> usize {
    fixture
        .audit
        .events()
        .iter()
        .filter(|e| **e == event)
        .count()
}

fn stepped_up(state: &AppState, browser: &Browser) -> bool {
    let now = Instant::now();
    state
        .auth
        .sessions
        .lookup(&browser.id, now)
        .and_then(|session| session.step_up_left(now))
        .is_some()
}

#[tokio::test]
async fn the_right_password_steps_up_for_five_minutes_and_is_audited() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in_as(state, "alice").await?;
    // A fresh sign-in is not a step-up.
    assert_eq!(step_up_left(state, &alice).await?, serde_json::Value::Null);

    let response = reauth(state, &alice, &with_password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json(response).await?,
        serde_json::json!({ "step_up_expires_in_secs": STEP_UP_SECS })
    );
    assert_eq!(STEP_UP_SECS, 300);
    assert!(stepped_up(state, &alice));
    let left = step_up_left(state, &alice)
        .await?
        .as_u64()
        .ok_or("not a number")?;
    assert!((STEP_UP_SECS - 2..=STEP_UP_SECS).contains(&left), "{left}");

    let record = fixture
        .audit
        .records()
        .into_iter()
        .find(|r| r.event == AuthEvent::StepUpSucceeded)
        .ok_or("no step_up_succeeded record")?;
    assert_eq!(record.subject, "alice");
    assert_eq!(record.kind, detent_ops::identity::IdentityKind::Session);
    assert_eq!(record.detail, None);
    Ok(())
}

#[tokio::test]
async fn a_wrong_password_is_refused_audited_and_counts_toward_the_lockout() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in_as(state, "alice").await?;

    // `auth.max_failures` is 5: the fifth wrong password locks the user and
    // the address, exactly as five wrong sign-ins do.
    for _ in 0_u32..5 {
        let response = reauth(state, &alice, &with_password("wrong")).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(message_id(response).await?, "web-auth-invalid-credentials");
    }
    assert!(!stepped_up(state, &alice));
    assert_eq!(count(&fixture, AuthEvent::StepUpFailed), 5);
    assert_eq!(count(&fixture, AuthEvent::LockedOut), 2);
    let record = fixture
        .audit
        .records()
        .into_iter()
        .find(|r| r.event == AuthEvent::StepUpFailed)
        .ok_or("no step_up_failed record")?;
    assert_eq!(record.subject, "alice");
    assert_eq!(
        record.detail.as_deref(),
        Some("web-auth-invalid-credentials")
    );

    // Now the right password is refused too, with the login's 429.
    let locked = reauth(state, &alice, &with_password(PASSWORD)).await?;
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(locked.headers().get(header::RETRY_AFTER).is_some());
    assert_eq!(message_id(locked).await?, "web-auth-rate-limited");
    assert!(!stepped_up(state, &alice));
    // The refusal for the lockout is not written again (M10).
    assert_eq!(count(&fixture, AuthEvent::StepUpFailed), 5);

    // And the lockout is the login's own: signing in is refused as well.
    let login = app(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"username": "alice", "password": PASSWORD}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(login.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn an_account_with_totp_must_send_a_fresh_code_and_a_replay_is_refused() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let secret = TotpSecret::generate()?;
    let counter = u64::try_from(crate::auth::extract::unix_now()).unwrap_or_default() / STEP_SECS;
    // The sign-in spends the code of the step before; the step-up then has
    // the current one.
    let earlier = secret.code_at(counter.saturating_sub(1));
    let code = secret.code_at(counter);
    state.auth.users.set_totp("alice", Some(&secret))?;
    let alice = sign_in(
        state,
        serde_json::json!({"username": "alice", "password": PASSWORD, "totp_code": earlier.expose()}),
    )
    .await?;

    // No code, and a wrong one: refused like a wrong password.
    for body in [
        with_password(PASSWORD),
        serde_json::json!({"password": PASSWORD, "totp_code": "000000"}),
    ] {
        let response = reauth(state, &alice, &body).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(message_id(response).await?, "web-auth-invalid-credentials");
    }
    // The code the sign-in already spent is a replay.
    let replay = reauth(
        state,
        &alice,
        &serde_json::json!({"password": PASSWORD, "totp_code": earlier.expose()}),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(!stepped_up(state, &alice));

    let response = reauth(
        state,
        &alice,
        &serde_json::json!({"password": PASSWORD, "totp_code": code.expose()}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(stepped_up(state, &alice));

    // The same code again is refused: the replay guard is the login's.
    let again = reauth(
        state,
        &alice,
        &serde_json::json!({"password": PASSWORD, "totp_code": code.expose()}),
    )
    .await?;
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(count(&fixture, AuthEvent::TotpReplayed), 2);
    assert_eq!(count(&fixture, AuthEvent::StepUpFailed), 2);
    assert_eq!(count(&fixture, AuthEvent::StepUpSucceeded), 1);
    Ok(())
}

#[tokio::test]
async fn the_reauth_route_needs_the_csrf_token() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in_as(state, "alice").await?;
    let response = app(state)
        .oneshot(from(
            &alice,
            Method::POST,
            REAUTH_PATH,
            &with_password(PASSWORD).to_string(),
            false,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(message_id(response).await?, "web-auth-csrf-rejected");
    assert!(!stepped_up(state, &alice));
    assert_eq!(count(&fixture, AuthEvent::StepUpSucceeded), 0);
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_or_no_credential_cannot_step_up() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (token, _view) = state.auth.tokens.issue("ci", Scope::Write, None)?;
    for bearer in [Some(token.expose()), None] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(REAUTH_PATH)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app(state)
            .oneshot(request.body(Body::from(with_password(PASSWORD).to_string()))?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(message_id(response).await?, "web-auth-unauthenticated");
    }
    assert_eq!(count(&fixture, AuthEvent::StepUpSucceeded), 0);
    assert_eq!(count(&fixture, AuthEvent::StepUpFailed), 0);
    Ok(())
}

#[tokio::test]
async fn a_session_that_owes_a_password_change_cannot_step_up() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let carol = sign_in_as(state, "carol").await?;
    let response = reauth(state, &carol, &with_password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        message_id(response).await?,
        "web-auth-password-change-required"
    );
    assert!(!stepped_up(state, &carol));
    Ok(())
}

#[tokio::test]
async fn a_malformed_or_oversized_body_is_refused_without_a_step_up() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in_as(state, "alice").await?;
    for body in ["{", r#"{"password":"hunter2","nope":1}"#, "[]"] {
        let response = app(state)
            .oneshot(from(&alice, Method::POST, REAUTH_PATH, body, true)?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(message_id(response).await?, "web-request-malformed");
    }
    // Over the length bounds: refused as a wrong password, with no hashing.
    let long_password = "x".repeat(crate::auth::routes::MAX_PASSWORD_LEN + 1);
    let long_code = "1".repeat(crate::auth::routes::MAX_TOTP_CODE_LEN + 1);
    for body in [
        with_password(&long_password),
        serde_json::json!({"password": PASSWORD, "totp_code": long_code}),
    ] {
        let response = reauth(state, &alice, &body).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(!stepped_up(state, &alice));
    assert_eq!(count(&fixture, AuthEvent::StepUpFailed), 2);
    Ok(())
}

#[tokio::test]
async fn a_password_change_ends_the_step_up() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in_as(state, "alice").await?;
    let response = reauth(state, &alice, &with_password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(stepped_up(state, &alice));

    let change = serde_json::json!({
        "current_password": PASSWORD,
        "new_password": "a much longer password",
    });
    let response = app(state)
        .oneshot(from(
            &alice,
            Method::POST,
            PASSWORD_PATH,
            &change.to_string(),
            true,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let id = cookie_of(&response)?;
    let view = json(response).await?;
    assert_eq!(
        view.pointer("/step_up_expires_in_secs"),
        Some(&serde_json::Value::Null)
    );
    let fresh = Browser {
        id,
        csrf: view
            .pointer("/csrf_token")
            .and_then(|v| v.as_str())
            .ok_or("no csrf token")?
            .to_owned(),
    };
    assert!(!stepped_up(state, &fresh));
    assert_eq!(step_up_left(state, &fresh).await?, serde_json::Value::Null);
    Ok(())
}

#[test]
fn the_request_never_renders_its_password_or_code() -> R {
    let request: ReauthRequest =
        serde_json::from_str(r#"{"password":"hunter2-secret","totp_code":"123456"}"#)?;
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("hunter2-secret"), "{rendered}");
    assert!(!rendered.contains("123456"), "{rendered}");
    assert!(rendered.contains("ReauthRequest"), "{rendered}");
    Ok(())
}
