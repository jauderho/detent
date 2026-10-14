//! Route tests for [`super`]: TOTP enrolment and disable from the console.

use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use tower::ServiceExt as _;

use crate::auth::audit::AuthEvent;
use crate::auth::routes::{
    LOGIN_PATH, SESSION_PATH, TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH, TOTP_ENROL_PATH, TOTP_PATH,
    routes,
};
use crate::auth::session::{COOKIE_NAME, PENDING_TOTP_TTL};
use crate::auth::totp::{STEP_SECS, TotpSecret};
use crate::authz::Scope;
use crate::csrf::{CSRF_HEADER, SAME_ORIGIN, SEC_FETCH_SITE, csrf_guard};
use crate::server::harden;
use crate::state::{AppState, TestState, test_state};

type R = Result<(), Box<dyn std::error::Error>>;
type E = Box<dyn std::error::Error>;
type Answer = axum::response::Response;

const ORIGIN: &str = "https://box.example:3333";
const PASSWORD: &str = "hunter2";

/// The auth routes behind the CSRF guard and the §2.7 middleware.
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
    fixture
        .state
        .auth
        .users
        .create(&fixture.state.auth.hasher, "alice", PASSWORD, false)?;
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

/// The current TOTP step.
fn step() -> u64 {
    u64::try_from(crate::auth::extract::unix_now()).unwrap_or_default() / STEP_SECS
}

/// A six-digit code the key does not accept now: none of the three in the
/// window.
fn wrong_code(secret: &TotpSecret) -> String {
    let window: Vec<String> = (step().saturating_sub(1)..=step().saturating_add(1))
        .map(|counter| secret.code_at(counter).expose().to_owned())
        .collect();
    (0_u32..10)
        .map(|n| format!("{n:06}"))
        .find(|code| !window.contains(code))
        .unwrap_or_default()
}

async fn json(response: Answer) -> Result<serde_json::Value, E> {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn message_id(response: Answer) -> Result<Option<String>, E> {
    Ok(json(response)
        .await?
        .pointer("/message_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned))
}

fn cookie_id(response: &Answer) -> Result<String, E> {
    let value = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("no Set-Cookie")?
        .to_str()?;
    Ok(value
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .ok_or("no cookie value")?
        .1
        .to_owned())
}

/// A signed-in browser: the cookie id and the CSRF token.
struct Browser {
    id: String,
    csrf: String,
}

/// The browser a 200 that set a new session leaves behind, and its body.
async fn browser_from(response: Answer) -> Result<(Browser, serde_json::Value), E> {
    let id = cookie_id(&response)?;
    let view = json(response).await?;
    let csrf = view
        .pointer("/csrf_token")
        .and_then(|v| v.as_str())
        .ok_or("no csrf token")?
        .to_owned();
    Ok((Browser { id, csrf }, view))
}

fn login_request(code: Option<&str>) -> Result<Request<Body>, E> {
    let body = match code {
        Some(code) => {
            serde_json::json!({"username": "alice", "password": PASSWORD, "totp_code": code})
        }
        None => serde_json::json!({"username": "alice", "password": PASSWORD}),
    };
    Ok(Request::builder()
        .method(Method::POST)
        .uri(LOGIN_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))?)
}

async fn sign_in(state: &AppState, code: Option<&str>) -> Result<Browser, E> {
    let response = app(state).oneshot(login_request(code)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(browser_from(response).await?.0)
}

/// A request carrying the cookie, and the CSRF proof when `csrf` is set.
fn from_browser(
    method: Method,
    uri: &str,
    id: &str,
    csrf: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<Request<Body>, E> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("{COOKIE_NAME}={id}"))
        .header(SEC_FETCH_SITE, SAME_ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .header(header::HOST, "box.example:3333");
    if let Some(csrf) = csrf {
        builder = builder.header(CSRF_HEADER, csrf);
    }
    Ok(match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))?,
        None => builder.body(Body::empty())?,
    })
}

async fn post(
    state: &AppState,
    browser: &Browser,
    uri: &str,
    body: serde_json::Value,
) -> Result<Answer, E> {
    Ok(app(state)
        .oneshot(from_browser(
            Method::POST,
            uri,
            &browser.id,
            Some(&browser.csrf),
            Some(body),
        )?)
        .await?)
}

async fn get(state: &AppState, browser: &Browser, uri: &str) -> Result<Answer, E> {
    Ok(app(state)
        .oneshot(from_browser(Method::GET, uri, &browser.id, None, None)?)
        .await?)
}

fn enrolled(state: &AppState) -> bool {
    state
        .auth
        .users
        .list()
        .iter()
        .any(|user| user.name == "alice" && user.totp_enrolled)
}

fn password(current: &str) -> serde_json::Value {
    serde_json::json!({"current_password": current})
}

fn code(code: &str) -> serde_json::Value {
    serde_json::json!({"code": code})
}

fn disable_body(current: &str, code: &str) -> serde_json::Value {
    serde_json::json!({"current_password": current, "code": code})
}

/// Start an enrolment and answer the key it returned.
async fn start(state: &AppState, browser: &Browser) -> Result<TotpSecret, E> {
    let response = post(state, browser, TOTP_ENROL_PATH, password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    let secret = body
        .pointer("/secret")
        .and_then(|v| v.as_str())
        .ok_or("no secret")?;
    Ok(TotpSecret::from_base32(secret)?)
}

/// The `(event, result, kind)` of every captured record.
fn audit(fixture: &TestState) -> Vec<(AuthEvent, AuditResult, IdentityKind)> {
    fixture
        .audit
        .records()
        .into_iter()
        .map(|record| (record.event, record.result, record.kind))
        .collect()
}

/// Alice with a key stored the way the CLI stores one, signed in with it.
async fn enrolled_alice(fixture: &TestState) -> Result<(TotpSecret, Browser), E> {
    let secret = TotpSecret::generate()?;
    fixture.state.auth.users.set_totp("alice", Some(&secret))?;
    let browser = sign_in(&fixture.state, Some(secret.code_at(step()).expose())).await?;
    Ok((secret, browser))
}

// -- enrolment ---------------------------------------------------------------

#[tokio::test]
async fn enrolment_stores_the_key_only_after_a_valid_code() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;

    let status = get(state, &browser, TOTP_PATH).await?;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        json(status).await?,
        serde_json::json!({"enrolled": false, "required": false})
    );

    let response = post(state, &browser, TOTP_ENROL_PATH, password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str())
            .transpose()?,
        Some("no-store")
    );
    let body = json(response).await?;
    let uri = body
        .pointer("/uri")
        .and_then(|v| v.as_str())
        .ok_or("no uri")?;
    let secret_text = body
        .pointer("/secret")
        .and_then(|v| v.as_str())
        .ok_or("no secret")?;
    assert!(uri.starts_with("otpauth://totp/detent:alice?"), "{uri}");
    assert!(uri.contains(&format!("secret={secret_text}")), "{uri}");
    assert_eq!(
        body.pointer("/expires_in_secs")
            .and_then(serde_json::Value::as_u64),
        Some(PENDING_TOTP_TTL.as_secs())
    );
    // A pending key is not an enrolled one.
    assert!(!enrolled(state));

    let secret = TotpSecret::from_base32(secret_text)?;
    let confirming = secret.code_at(step());
    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(confirming.expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let (fresh, view) = browser_from(response).await?;
    assert_ne!(fresh.id, browser.id);
    assert_eq!(
        view.pointer("/totp_satisfied")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(enrolled(state));

    // Every older session of the account is ended; the new one works.
    let old = get(state, &browser, SESSION_PATH).await?;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let status = get(state, &fresh, TOTP_PATH).await?;
    assert_eq!(
        json(status).await?,
        serde_json::json!({"enrolled": true, "required": false})
    );

    // The confirming code is used up: it cannot sign in.
    let replay = app(state)
        .oneshot(login_request(Some(confirming.expose()))?)
        .await?;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let records = audit(&fixture);
    assert!(
        records.contains(&(
            AuthEvent::TotpEnabled,
            AuditResult::Ok,
            IdentityKind::Session
        )),
        "{records:?}"
    );
    // The key is never written to the audit log.
    assert!(
        fixture
            .audit
            .records()
            .iter()
            .all(|record| !format!("{record:?}").contains(secret_text))
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_code_stores_nothing_and_the_key_stays_pending() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let secret = start(state, &browser).await?;

    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(&wrong_code(&secret)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-invalid-credentials")
    );
    assert!(!enrolled(state));
    let records = audit(&fixture);
    assert!(
        records.contains(&(
            AuthEvent::TotpEnabled,
            AuditResult::Error,
            IdentityKind::Session
        )),
        "{records:?}"
    );

    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(secret.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(enrolled(state));
    Ok(())
}

#[tokio::test]
async fn enrolment_needs_the_current_password() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let response = post(state, &browser, TOTP_ENROL_PATH, password("wrong")).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-invalid-credentials")
    );
    // Nothing is pending, so a code confirms nothing.
    let response = post(state, &browser, TOTP_CONFIRM_PATH, code("123456")).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-no-pending")
    );
    Ok(())
}

#[tokio::test]
async fn an_account_with_a_key_cannot_enrol_another() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (_secret, browser) = enrolled_alice(&fixture).await?;
    let response = post(state, &browser, TOTP_ENROL_PATH, password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-enrolled")
    );
    Ok(())
}

/// A key enrolled on the command line between start and confirm wins: the
/// console's pending key is not stored over it.
#[tokio::test]
async fn a_confirm_after_another_enrolment_is_refused() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let pending = start(state, &browser).await?;
    let other = TotpSecret::generate()?;
    state.auth.users.set_totp("alice", Some(&other))?;
    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(pending.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-enrolled")
    );
    Ok(())
}

#[tokio::test]
async fn an_expired_pending_key_cannot_be_confirmed() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let secret = TotpSecret::generate()?;
    let started = Instant::now()
        .checked_sub(PENDING_TOTP_TTL + Duration::from_secs(1))
        .ok_or("clock too young")?;
    assert!(
        state
            .auth
            .sessions
            .set_pending_totp(&browser.id, secret.clone(), started)
    );
    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(secret.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-no-pending")
    );
    assert!(!enrolled(state));
    Ok(())
}

/// The pending key belongs to the session that started it.
#[tokio::test]
async fn another_session_cannot_confirm_the_pending_key() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let first = sign_in(state, None).await?;
    let second = sign_in(state, None).await?;
    let secret = start(state, &first).await?;
    let response = post(
        state,
        &second,
        TOTP_CONFIRM_PATH,
        code(secret.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!enrolled(state));
    Ok(())
}

// -- disable -----------------------------------------------------------------

#[tokio::test]
async fn disabling_needs_the_password_and_a_fresh_code() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (secret, browser) = enrolled_alice(&fixture).await?;
    let next = secret.code_at(step().saturating_add(1));

    let response = post(
        state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body("wrong", next.expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(enrolled(state));

    let response = post(
        state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body(PASSWORD, &wrong_code(&secret)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(enrolled(state));

    // The code that signed in is used up, so it cannot turn the key off.
    let response = post(
        state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body(PASSWORD, secret.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(enrolled(state));

    let response = post(
        state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body(PASSWORD, next.expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let (fresh, view) = browser_from(response).await?;
    assert_eq!(
        view.pointer("/totp_satisfied")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(!enrolled(state));
    let old = get(state, &browser, SESSION_PATH).await?;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let status = get(state, &fresh, TOTP_PATH).await?;
    assert_eq!(
        json(status).await?,
        serde_json::json!({"enrolled": false, "required": false})
    );
    // A sign-in needs no code again.
    sign_in(state, None).await?;

    let records = audit(&fixture);
    let refused = (
        AuthEvent::TotpDisabled,
        AuditResult::Error,
        IdentityKind::Session,
    );
    assert_eq!(
        records.iter().filter(|record| **record == refused).count(),
        3,
        "{records:?}"
    );
    assert!(
        records.contains(&(
            AuthEvent::TotpDisabled,
            AuditResult::Ok,
            IdentityKind::Session
        )),
        "{records:?}"
    );
    Ok(())
}

#[tokio::test]
async fn disabling_without_a_key_is_a_conflict() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let response = post(
        state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body(PASSWORD, "123456"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-not-enrolled")
    );
    Ok(())
}

/// Under `auth.totp_required` the console cannot turn the key off: the
/// account could not sign in again. The command line still can.
#[tokio::test]
async fn a_host_that_requires_totp_refuses_to_disable_it() -> R {
    let fixture = fixture()?;
    let state = required_state(&fixture)?;
    let secret = TotpSecret::generate()?;
    state.auth.users.set_totp("alice", Some(&secret))?;
    let browser = sign_in(&state, Some(secret.code_at(step()).expose())).await?;

    let status = get(&state, &browser, TOTP_PATH).await?;
    assert_eq!(
        json(status).await?,
        serde_json::json!({"enrolled": true, "required": true})
    );
    let response = post(
        &state,
        &browser,
        TOTP_DISABLE_PATH,
        disable_body(PASSWORD, secret.code_at(step().saturating_add(1)).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-totp-required")
    );
    assert!(enrolled(&state));
    Ok(())
}

// -- the guards --------------------------------------------------------------

#[tokio::test]
async fn the_totp_routes_need_the_csrf_token() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    for (uri, body) in [
        (TOTP_ENROL_PATH, password(PASSWORD)),
        (TOTP_CONFIRM_PATH, code("123456")),
        (TOTP_DISABLE_PATH, disable_body(PASSWORD, "123456")),
    ] {
        let response = app(state)
            .oneshot(from_browser(
                Method::POST,
                uri,
                &browser.id,
                None,
                Some(body),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            message_id(response).await?.as_deref(),
            Some("web-auth-csrf-rejected"),
            "{uri}"
        );
    }
    assert!(
        state
            .auth
            .sessions
            .pending_totp(&browser.id, Instant::now())
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_cannot_reach_the_totp_routes() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let (token, _view) = state.auth.tokens.issue("robot", Scope::Write, None)?;
    for (method, uri, body) in [
        (Method::GET, TOTP_PATH, None),
        (Method::POST, TOTP_ENROL_PATH, Some(password(PASSWORD))),
        (Method::POST, TOTP_CONFIRM_PATH, Some(code("123456"))),
        (
            Method::POST,
            TOTP_DISABLE_PATH,
            Some(disable_body(PASSWORD, "123456")),
        ),
    ] {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {}", token.expose()));
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
            None => builder.body(Body::empty())?,
        };
        let response = app(state).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn a_session_that_owes_a_password_change_cannot_enrol() -> R {
    let fixture = test_state()?;
    let state = &fixture.state;
    state
        .auth
        .users
        .create(&state.auth.hasher, "alice", PASSWORD, true)?;
    let browser = sign_in(state, None).await?;
    let response = post(state, &browser, TOTP_ENROL_PATH, password(PASSWORD)).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        message_id(response).await?.as_deref(),
        Some("web-auth-password-change-required")
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_body_is_a_bad_request() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    for uri in [TOTP_ENROL_PATH, TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH] {
        let response = post(state, &browser, uri, serde_json::json!({"extra": 1})).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(
            message_id(response).await?.as_deref(),
            Some("web-request-malformed")
        );
    }
    Ok(())
}

/// Wrong codes count against the same limiter a wrong login does.
#[tokio::test]
async fn repeated_wrong_codes_are_rate_limited() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let browser = sign_in(state, None).await?;
    let secret = start(state, &browser).await?;
    let wrong = wrong_code(&secret);
    // `auth.max_failures` is 5.
    for _ in 0_u32..5 {
        let response = post(state, &browser, TOTP_CONFIRM_PATH, code(&wrong)).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = post(
        state,
        &browser,
        TOTP_CONFIRM_PATH,
        code(secret.code_at(step()).expose()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(!enrolled(state));
    assert!(
        audit(&fixture)
            .iter()
            .any(|record| record.0 == AuthEvent::LockedOut)
    );
    Ok(())
}

#[test]
fn the_bodies_never_render_a_credential() {
    let enrol = super::TotpEnrolRequest {
        current_password: "hunter2".to_owned(),
    };
    let confirm = super::TotpConfirmRequest {
        code: "123456".to_owned(),
    };
    let disable = super::TotpDisableRequest {
        current_password: "hunter2".to_owned(),
        code: "123456".to_owned(),
    };
    let enrolment = super::TotpEnrolment {
        uri: "otpauth://totp/detent:alice?secret=SECRETKEY".to_owned(),
        secret: "SECRETKEY".to_owned(),
        expires_in_secs: 600,
    };
    for rendered in [
        format!("{enrol:?}"),
        format!("{confirm:?}"),
        format!("{disable:?}"),
        format!("{enrolment:?}"),
    ] {
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("123456"), "{rendered}");
        assert!(!rendered.contains("SECRETKEY"), "{rendered}");
    }
}
