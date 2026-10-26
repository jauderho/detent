//! Route tests for [`super`]: a user lists and ends its own sessions.

use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt as _;

use super::{SESSION_REVOKE_PATH, SESSIONS_PATH, SESSIONS_REVOKE_OTHERS_PATH};
use crate::auth::audit::AuthEvent;
use crate::auth::routes::{LOGIN_PATH, SESSION_PATH, routes};
use crate::auth::session::COOKIE_NAME;
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

/// Alice and Bob; Carol must change her password.
fn fixture() -> Result<TestState, E> {
    let fixture = test_state()?;
    for (name, flagged) in [("alice", false), ("bob", false), ("carol", true)] {
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

/// A request from `browser`, with the CSRF token when `csrf` is set.
fn from(browser: &Browser, method: Method, uri: &str, csrf: bool) -> Result<Request<Body>, E> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("{COOKIE_NAME}={}", browser.id))
        .header(SEC_FETCH_SITE, SAME_ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .header(header::HOST, "box.example:3333");
    if csrf {
        builder = builder.header(CSRF_HEADER, &browser.csrf);
    }
    Ok(builder.body(Body::empty())?)
}

fn revoke_uri(handle: &str) -> String {
    SESSION_REVOKE_PATH.replace("{handle}", handle)
}

async fn json(response: axum::response::Response) -> Result<serde_json::Value, E> {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// The session list `browser` sees.
async fn list(state: &AppState, browser: &Browser) -> Result<Vec<serde_json::Value>, E> {
    let response = app(state)
        .oneshot(from(browser, Method::GET, SESSIONS_PATH, false)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(json(response)
        .await?
        .as_array()
        .ok_or("the list is not an array")?
        .clone())
}

/// The handle of the entry of `listed` that is (or is not) the current one.
fn handle_of(listed: &[serde_json::Value], current: bool) -> Result<String, E> {
    Ok(listed
        .iter()
        .find(|entry| {
            entry
                .pointer("/current")
                .and_then(serde_json::Value::as_bool)
                == Some(current)
        })
        .and_then(|entry| entry.pointer("/handle"))
        .and_then(|v| v.as_str())
        .ok_or("no such entry")?
        .to_owned())
}

fn live(state: &AppState, browser: &Browser) -> bool {
    state
        .auth
        .sessions
        .lookup(&browser.id, Instant::now())
        .is_some()
}

fn revoked(fixture: &TestState) -> usize {
    fixture
        .audit
        .events()
        .iter()
        .filter(|event| **event == AuthEvent::SessionRevoked)
        .count()
}

#[tokio::test]
async fn the_list_holds_only_the_callers_sessions_and_no_secret() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let first = sign_in(state, "alice").await?;
    let second = sign_in(state, "alice").await?;
    let bob = sign_in(state, "bob").await?;

    let listed = list(state, &first).await?;
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert_eq!(
        listed
            .iter()
            .filter(|e| e.pointer("/current").and_then(serde_json::Value::as_bool) == Some(true))
            .count(),
        1
    );
    for entry in &listed {
        let mut keys: Vec<&str> = entry
            .as_object()
            .ok_or("an entry is not an object")?
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "created_unix_s",
                "current",
                "expires_in_secs",
                "handle",
                "last_seen_unix_s",
                "totp_satisfied",
            ]
        );
    }
    let text = serde_json::to_string(&listed)?;
    for secret in [&first.id, &first.csrf, &second.id, &second.csrf, &bob.id] {
        assert!(!text.contains(secret.as_str()), "{text}");
    }
    let bob_handle = handle_of(&list(state, &bob).await?, true)?;
    assert!(!text.contains(&bob_handle), "{text}");
    Ok(())
}

#[tokio::test]
async fn ending_another_session_by_its_handle_ends_it_and_is_audited() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let mine = sign_in(state, "alice").await?;
    let other = sign_in(state, "alice").await?;
    let handle = handle_of(&list(state, &mine).await?, false)?;

    let response = app(state)
        .oneshot(from(&mine, Method::POST, &revoke_uri(&handle), true)?)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert!(!live(state, &other));
    assert!(live(state, &mine));
    assert_eq!(revoked(&fixture), 1);
    let record = fixture
        .audit
        .records()
        .into_iter()
        .find(|r| r.event == AuthEvent::SessionRevoked)
        .ok_or("no record")?;
    assert_eq!(record.subject, "alice");

    // The same handle again names nothing.
    let again = app(state)
        .oneshot(from(&mine, Method::POST, &revoke_uri(&handle), true)?)
        .await?;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn an_unknown_handle_and_another_users_handle_get_the_same_404() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let bob = sign_in(state, "bob").await?;
    let bob_handle = handle_of(&list(state, &bob).await?, true)?;

    let mut answers = Vec::new();
    for handle in [bob_handle.as_str(), "0123456789abcdef0123456789abcdef", "x"] {
        let response = app(state)
            .oneshot(from(&alice, Method::POST, &revoke_uri(handle), true)?)
            .await?;
        answers.push((response.status(), json(response).await?));
    }
    for answer in &answers {
        assert_eq!(answer.0, StatusCode::NOT_FOUND);
        assert_eq!(
            answer.1,
            serde_json::json!({"code": "not_found", "message_id": "web-auth-session-unknown"})
        );
    }
    assert!(live(state, &bob));
    assert!(live(state, &alice));
    // A miss writes nothing, so probing cannot grow the log.
    assert_eq!(revoked(&fixture), 0);
    Ok(())
}

#[tokio::test]
async fn ending_the_current_session_signs_out_and_clears_the_cookie() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let mine = sign_in(state, "alice").await?;
    let handle = handle_of(&list(state, &mine).await?, true)?;

    let response = app(state)
        .oneshot(from(&mine, Method::POST, &revoke_uri(&handle), true)?)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("no Set-Cookie")?
        .to_str()?;
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    assert!(!cookie.contains(&mine.id), "{cookie}");
    assert!(!live(state, &mine));
    assert_eq!(revoked(&fixture), 1);
    Ok(())
}

#[tokio::test]
async fn ending_the_other_sessions_keeps_the_current_one_and_counts() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let mine = sign_in(state, "alice").await?;
    let others = [
        sign_in(state, "alice").await?,
        sign_in(state, "alice").await?,
    ];
    let bob = sign_in(state, "bob").await?;

    let response = app(state)
        .oneshot(from(
            &mine,
            Method::POST,
            SESSIONS_REVOKE_OTHERS_PATH,
            true,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(json(response).await?, serde_json::json!({"ended": 2}));
    assert!(live(state, &mine));
    assert!(live(state, &bob));
    for other in &others {
        assert!(!live(state, other));
    }
    assert_eq!(revoked(&fixture), 2);
    assert_eq!(list(state, &mine).await?.len(), 1);

    // Nothing left to end: zero, and no record.
    let response = app(state)
        .oneshot(from(
            &mine,
            Method::POST,
            SESSIONS_REVOKE_OTHERS_PATH,
            true,
        )?)
        .await?;
    assert_eq!(json(response).await?, serde_json::json!({"ended": 0}));
    assert_eq!(revoked(&fixture), 2);
    Ok(())
}

#[tokio::test]
async fn the_revoke_routes_need_the_csrf_token() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let mine = sign_in(state, "alice").await?;
    let other = sign_in(state, "alice").await?;
    let handle = handle_of(&list(state, &mine).await?, false)?;

    for uri in [revoke_uri(&handle), SESSIONS_REVOKE_OTHERS_PATH.to_owned()] {
        let response = app(state)
            .oneshot(from(&mine, Method::POST, &uri, false)?)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            json(response)
                .await?
                .pointer("/message_id")
                .and_then(|v| v.as_str()),
            Some("web-auth-csrf-rejected")
        );
    }
    assert!(live(state, &other));
    assert_eq!(revoked(&fixture), 0);
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_or_no_credential_cannot_reach_the_session_routes() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let handle = handle_of(&list(state, &alice).await?, true)?;
    let (token, _view) = state.auth.tokens.issue("ci", Scope::Write, None)?;

    for (method, uri) in [
        (Method::GET, SESSIONS_PATH.to_owned()),
        (Method::POST, revoke_uri(&handle)),
        (Method::POST, SESSIONS_REVOKE_OTHERS_PATH.to_owned()),
    ] {
        for bearer in [Some(token.expose()), None] {
            let mut request = Request::builder().method(method.clone()).uri(&uri);
            if let Some(token) = bearer {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = app(state).oneshot(request.body(Body::empty())?).await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
            assert_eq!(
                json(response)
                    .await?
                    .pointer("/message_id")
                    .and_then(|v| v.as_str()),
                Some("web-auth-unauthenticated")
            );
        }
    }
    assert!(live(state, &alice));
    assert_eq!(revoked(&fixture), 0);
    Ok(())
}

#[tokio::test]
async fn a_session_that_owes_a_password_change_cannot_list_or_end_sessions() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let carol = sign_in(state, "carol").await?;
    for (method, uri) in [
        (Method::GET, SESSIONS_PATH),
        (Method::POST, SESSIONS_REVOKE_OTHERS_PATH),
    ] {
        let response = app(state)
            .oneshot(from(&carol, method.clone(), uri, method == Method::POST)?)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            json(response)
                .await?
                .pointer("/message_id")
                .and_then(|v| v.as_str()),
            Some("web-auth-password-change-required")
        );
    }
    assert!(live(state, &carol));
    Ok(())
}

// -- a change another process makes to the user file -------------------------

/// The status and message id of a plain authenticated GET of `uri`.
async fn get(state: &AppState, browser: &Browser, uri: &str) -> Result<(StatusCode, String), E> {
    let response = app(state)
        .oneshot(from(browser, Method::GET, uri, false)?)
        .await?;
    let status = response.status();
    let id = json(response)
        .await?
        .pointer("/message_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    Ok((status, id))
}

/// Whether `browser` is refused as unauthenticated on a route that takes a
/// pending caller (`/auth/session`) and on one that takes a full caller
/// (`/auth/sessions`).
async fn refused(state: &AppState, browser: &Browser) -> Result<bool, E> {
    for uri in [SESSION_PATH, SESSIONS_PATH] {
        let (status, id) = get(state, browser, uri).await?;
        if status != StatusCode::UNAUTHORIZED || id != "web-auth-unauthenticated" {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `browser` still reaches both routes.
async fn admitted(state: &AppState, browser: &Browser) -> Result<bool, E> {
    for uri in [SESSION_PATH, SESSIONS_PATH] {
        if get(state, browser, uri).await?.0 != StatusCode::OK {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A second store over the same file, as `detent user` opens it.
fn cli(fixture: &TestState) -> Result<crate::auth::users::UserStore, E> {
    Ok(crate::auth::users::UserStore::load(fixture.state_root())?)
}

/// `detent user rm` in another process ends the user's sessions on the
/// server's next request, with no explicit refresh; other users keep theirs.
#[tokio::test]
async fn a_user_removed_by_another_process_is_signed_out_at_once() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let bob = sign_in(state, "bob").await?;
    assert!(admitted(state, &alice).await?);

    cli(&fixture)?.remove("alice")?;

    assert!(refused(state, &alice).await?);
    assert!(!live(state, &alice));
    assert!(admitted(state, &bob).await?);
    Ok(())
}

/// `detent user passwd` in another process ends the user's sessions on the
/// server's next request; other users keep theirs.
#[tokio::test]
async fn a_password_reset_by_another_process_signs_the_user_out_at_once() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let bob = sign_in(state, "bob").await?;
    assert!(admitted(state, &alice).await?);

    cli(&fixture)?.set_password(&state.auth.hasher, "alice", &PASSWORD.repeat(2))?;

    assert!(refused(state, &alice).await?);
    assert!(admitted(state, &bob).await?);
    Ok(())
}

/// A session for `alice` made directly in the table, as a login with a TOTP
/// code would make it.
fn session_for_alice(state: &AppState) -> Result<Browser, E> {
    let (id, _session) = state.auth.sessions.create(
        "alice",
        crate::authz::Scopes::read_write(),
        true,
        Instant::now(),
    )?;
    Ok(Browser {
        id: id.expose().to_owned(),
        csrf: String::new(),
    })
}

/// Enrolling, replacing or clearing a TOTP secret in another process ends
/// the user's sessions; a new replay counter alone does not.
#[tokio::test]
async fn a_totp_change_by_another_process_signs_the_user_out_at_once() -> R {
    use crate::auth::totp::TotpSecret;

    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    let bob = sign_in(state, "bob").await?;
    let store = cli(&fixture)?;

    store.note_totp_counter("alice", 7)?;
    assert!(admitted(state, &alice).await?, "a counter is no credential");

    store.set_totp("alice", Some(&TotpSecret::generate()?))?;
    assert!(refused(state, &alice).await?, "enrolled");

    let replaced = session_for_alice(state)?;
    assert!(admitted(state, &replaced).await?);
    store.set_totp("alice", Some(&TotpSecret::generate()?))?;
    assert!(refused(state, &replaced).await?, "replaced");

    let cleared = session_for_alice(state)?;
    assert!(admitted(state, &cleared).await?);
    store.set_totp("alice", None)?;
    assert!(refused(state, &cleared).await?, "cleared");

    assert!(admitted(state, &bob).await?);
    Ok(())
}

/// A user file the server cannot read refuses every session request, rather
/// than trusting the copy in memory.
#[tokio::test]
async fn an_unreadable_user_file_refuses_the_session() -> R {
    let fixture = fixture()?;
    let state = &fixture.state;
    let alice = sign_in(state, "alice").await?;
    assert!(admitted(state, &alice).await?);

    let path = state.auth.users.path().to_path_buf();
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;

    for uri in [SESSION_PATH, SESSIONS_PATH] {
        assert_eq!(
            get(state, &alice, uri).await?,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "web-auth-store-unreadable".to_owned()
            ),
            "{uri}"
        );
    }
    Ok(())
}
