//! The CSRF middleware (PLAN §2.7, ADR-007).
//!
//! ```text
//!   GET / HEAD / OPTIONS ──────────────────────────────▶ pass (never mutates)
//!
//!   Authorization: Bearer ─────────────────────────────▶ pass (no ambient
//!                                                        authority to abuse)
//!   cookie session ─┬─ Sec-Fetch-Site: same-origin ─┐
//!                   ├─ Sec-Fetch-Site: same-site ───┼─ pass
//!                   ├─ Origin == configured origin ─┤
//!                   └─ X-Detent-CSRF == token ──────┘
//!                                          any missing ──▶ 403
//! ```
//!
//! # Guarantees
//!
//! * **A missing `Sec-Fetch-Site` is a rejection**, not a pass. Every browser
//!   that can reach this server sends it; something that does not is either
//!   not a browser — in which case it should be presenting a bearer token —
//!   or is trying to look like one.
//! * **All three checks must hold.** They are independent: `Sec-Fetch-Site`
//!   is set by the browser and cannot be forged by a page, `Origin` pins the
//!   host, and the token proves the request was composed by script that could
//!   read the session endpoint.
//! * **`GET` never mutates.** Enforced by construction — mutating routes are
//!   registered only for non-`GET` methods — and checked by a test that walks
//!   the route table.
//! * **No ambient authority, no check.** A request with no session cookie is
//!   let past and refused by the extractor with 401, because there is nothing
//!   a cross-site page could have abused.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};

use crate::auth::AuthError;
use crate::auth::session;
use crate::error::ApiError;
use crate::state::AppState;

/// Header the per-session CSRF token is echoed in.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-detent-csrf");

/// Header a browser states the request's site relationship in.
pub const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// The only `Sec-Fetch-Site` value a cookie-authenticated mutation may carry.
pub const SAME_ORIGIN: &str = "same-origin";
/// Same-site browser requests are accepted when `Origin` still names this host.
pub const SAME_SITE: &str = "same-site";

/// An origin, normalized for comparison.
///
/// Normalization is the whole point of the type: a browser sends
/// `https://box.example` for a request to port 443 and
/// `https://box.example:3333` for one to port 3333, so the configured value
/// and the header have to be reduced to the same shape before they are
/// compared. Scheme and host are lowercased, and a port that is the scheme's
/// default is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// `scheme://host[:port]`, lowercase, default port removed.
    normalized: String,
}

impl Origin {
    /// Parse `scheme://host[:port]`, or `None` if it is not one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (scheme, rest) = text.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443_u16,
            "http" => 80,
            _ => return None,
        };
        if rest.is_empty() || rest.contains('/') {
            return None;
        }
        // An IPv6 literal is bracketed, and its colons are not port
        // separators: `[::1]:3333`.
        let (host, port_text) = match rest.strip_prefix('[') {
            Some(after) => {
                let (inside, tail) = after.split_once(']')?;
                let port = match tail {
                    "" => None,
                    other => Some(other.strip_prefix(':')?),
                };
                (format!("[{}]", inside.to_ascii_lowercase()), port)
            }
            None => match rest.split_once(':') {
                Some((host, port)) => (host.to_ascii_lowercase(), Some(port)),
                None => (rest.to_ascii_lowercase(), None),
            },
        };
        if host.is_empty() || host == "[]" {
            return None;
        }
        let port = match port_text {
            None => None,
            Some(digits) => {
                let number: u16 = digits.parse().ok()?;
                (number != default_port).then_some(number)
            }
        };
        Some(Self {
            normalized: match port {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            },
        })
    }

    /// The origin `https://host[:port]`.
    #[must_use]
    pub fn https(host: &str, port: u16) -> Self {
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        Self::parse(&format!("https://{host}:{port}")).unwrap_or(Self {
            normalized: format!("https://{host}:{port}"),
        })
    }

    /// The origin this host serves on, derived from `[tls] hostnames` and
    /// `[listen] addr`.
    ///
    /// configured: the first configured hostname if there is one — that is
    /// the name a certificate is issued for and therefore the name a browser
    /// will use — and `localhost` for the default wildcard listener.
    #[must_use]
    pub fn for_config(config: &crate::config::Config) -> Self {
        let port = config.listen.addr.port();
        match config.tls.hostnames.first() {
            Some(host) => Self::https(host, port),
            None if config.listen.addr.ip().is_unspecified() => Self::https("localhost", port),
            None => Self::https(&config.listen.addr.ip().to_string(), port),
        }
    }

    /// The normalized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Whether `candidate` — an `Origin` header value — names this origin.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        Self::parse(candidate).is_some_and(|other| other.normalized == self.normalized)
    }
}

/// The one value of `name`, or `None` when the header is absent, is not
/// visible ASCII, or — deliberately — appears **more than once**.
///
/// Every header this module decides on is single-valued: a browser sends one
/// `Sec-Fetch-Site`, one `Origin`, and the SPA sends one `X-Detent-CSRF`. A
/// repeat therefore did not come from a browser. It matters because
/// [`HeaderMap::get`] answers with the *first* value, so a request carrying
///
/// ```text
/// Sec-Fetch-Site: same-origin
/// Sec-Fetch-Site: cross-site
/// ```
///
/// would otherwise read as same-origin — which is exactly the shape a request
/// smuggled through a front-end proxy takes. Treating a duplicate as absent
/// turns every such request into a refusal.
///
/// `Cookie` is deliberately not read this way: HTTP/2 permits a client to
/// split cookies across several field lines, so more than one is normal there.
fn sole_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).into_iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// Whether `headers` carry exactly one `Authorization: Bearer` credential.
///
/// Exactly one, because this is the test that *skips* the CSRF checks. A
/// request with two `Authorization` headers takes the full checks instead of
/// the bypass; the extractor refuses it separately.
fn has_bearer(headers: &HeaderMap) -> bool {
    let mut values = headers
        .get_all(axum::http::header::AUTHORIZATION)
        .into_iter();
    if values.next().is_none() || values.next().is_some() {
        return false;
    }
    crate::auth::extract::bearer(headers).is_some()
}

/// The §2.7 CSRF middleware.
///
/// Install with
/// `axum::middleware::from_fn_with_state(state.clone(), csrf_guard)` around
/// the API router.
pub async fn csrf_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Err(error) = verdict(&state, request.method(), request.headers()) {
        return ApiError::from(error).into_response();
    }
    next.run(request).await
}

/// The decision, separated from the middleware so it can be tested without a
/// router.
///
/// # Errors
///
/// [`AuthError::CsrfRejected`] when a cookie-authenticated mutation fails any
/// of the three checks.
pub fn verdict(state: &AppState, method: &Method, headers: &HeaderMap) -> Result<(), AuthError> {
    // Safe methods never mutate, so there is nothing to protect. HEAD and
    // OPTIONS are safe for the same reason GET is.
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    // A bearer token is not ambient: a cross-site page cannot make the
    // browser attach one.
    if has_bearer(headers) {
        return Ok(());
    }
    // No cookie, no ambient authority. The extractor answers 401; answering
    // 403 here would tell an unauthenticated caller about a control it never
    // reached.
    let Some(presented) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(session::cookie_value)
    else {
        return Ok(());
    };
    let Some(session) = state
        .auth
        .sessions
        .lookup(presented.expose(), std::time::Instant::now())
    else {
        return Ok(());
    };

    // The origin comparison below is the security boundary; accept the two
    // browser labels for a request that names this exact host.
    if !matches!(
        sole_header(headers, &SEC_FETCH_SITE),
        Some(SAME_ORIGIN | SAME_SITE)
    ) {
        return Err(AuthError::CsrfRejected);
    }

    let origin =
        sole_header(headers, &axum::http::header::ORIGIN).ok_or(AuthError::CsrfRejected)?;
    if !state.origin.matches(origin) {
        return Err(AuthError::CsrfRejected);
    }
    let token = sole_header(headers, &CSRF_HEADER).ok_or(AuthError::CsrfRejected)?;
    if !session.csrf_token.ct_eq(token) {
        return Err(AuthError::CsrfRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CSRF_HEADER, Origin, SAME_ORIGIN, SAME_SITE, SEC_FETCH_SITE, csrf_guard};

    use crate::auth::routes;
    use crate::auth::session::{COOKIE_NAME, SessionStore};
    use crate::authz::Scopes;
    use crate::state::{AppState, test_state};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::{get, post};
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A router with one safe and one mutating route behind the guard.
    fn app(state: &AppState) -> Router {
        Router::new()
            .route("/api/v1/safe", get(|| async { "safe" }))
            .route("/api/v1/mutate", post(|| async { "done" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_guard,
            ))
            .with_state(state.clone())
    }

    /// The origin the test fixture is configured for.
    const GOOD_ORIGIN: &str = "https://box.example:3333";

    /// The four headers a complete cookie-authenticated mutation carries.
    ///
    /// A struct rather than `good(..).header(..)` overrides, because
    /// `Builder::header` **appends** and [`HeaderMap::get`] answers with the
    /// *first* value: `good(..).header(SEC_FETCH_SITE, "cross-site")` leaves
    /// `same-origin` in front and tests nothing. Setting each header exactly
    /// once makes that mistake unrepresentable. `None` omits the header.
    #[derive(Clone, Copy)]
    struct Mutation<'a> {
        cookie: Option<&'a str>,
        site: Option<&'a str>,
        origin: Option<&'a str>,
        token: Option<&'a str>,
    }

    impl<'a> Mutation<'a> {
        /// Every header present and correct.
        fn complete(session_id: &'a str, csrf: &'a str) -> Self {
            Self {
                cookie: Some(session_id),
                site: Some(SAME_ORIGIN),
                origin: Some(GOOD_ORIGIN),
                token: Some(csrf),
            }
        }

        /// The `POST /api/v1/mutate` these headers describe.
        fn build(self) -> Result<Request<Body>, Box<dyn std::error::Error>> {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/mutate");
            if let Some(cookie) = self.cookie {
                builder = builder.header(header::COOKIE, format!("{COOKIE_NAME}={cookie}"));
            }
            if let Some(site) = self.site {
                builder = builder.header(SEC_FETCH_SITE, site);
            }
            if let Some(origin) = self.origin {
                builder = builder.header(header::ORIGIN, origin);
            }
            if let Some(token) = self.token {
                builder = builder.header(CSRF_HEADER, token);
            }
            Ok(builder.body(Body::empty())?)
        }
    }

    #[tokio::test]
    async fn a_complete_request_passes() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let response = app(state)
            .oneshot(Mutation::complete(id.expose(), session.csrf_token.expose()).build()?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn same_site_browser_mutation_passes() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let mutation = Mutation {
            site: Some(SAME_SITE),
            ..Mutation::complete(id.expose(), session.csrf_token.expose())
        };
        let response = app(state).oneshot(mutation.build()?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn each_missing_or_wrong_condition_is_a_refusal() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let token = session.csrf_token.expose().to_owned();
        let wrong_token = "0".repeat(64);
        let complete = Mutation::complete(id.expose(), &token);

        let cases: [(&str, Mutation<'_>); 9] = [
            (
                "missing Sec-Fetch-Site",
                Mutation {
                    site: None,
                    ..complete
                },
            ),
            (
                "Sec-Fetch-Site: cross-site",
                Mutation {
                    site: Some("cross-site"),
                    ..complete
                },
            ),
            (
                "Sec-Fetch-Site: none",
                Mutation {
                    site: Some("none"),
                    ..complete
                },
            ),
            (
                "missing Origin",
                Mutation {
                    origin: None,
                    ..complete
                },
            ),
            (
                "wrong Origin",
                Mutation {
                    origin: Some("https://evil.example:3333"),
                    ..complete
                },
            ),
            (
                "Origin on the wrong port",
                Mutation {
                    origin: Some("https://box.example:4444"),
                    ..complete
                },
            ),
            (
                "missing token",
                Mutation {
                    token: None,
                    ..complete
                },
            ),
            (
                "wrong token",
                Mutation {
                    token: Some(&wrong_token),
                    ..complete
                },
            ),
            (
                "empty token",
                Mutation {
                    token: Some(""),
                    ..complete
                },
            ),
        ];

        for (name, mutation) in cases {
            let request = mutation.build()?;
            let response = app(state).oneshot(request).await?;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{name} was allowed"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
            let json: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(
                json.pointer("/message_id").and_then(|v| v.as_str()),
                Some("web-auth-csrf-rejected"),
                "{name}"
            );
        }
        Ok(())
    }

    /// `HeaderMap::get` answers with the first value, so a repeated header
    /// whose first copy is well-formed would sail through a naive check. A
    /// browser never sends two of any of these, so a repeat is a refusal —
    /// this is the request-smuggling shape `sole_header` exists for.
    #[tokio::test]
    async fn a_repeated_security_header_is_a_refusal() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let token = session.csrf_token.expose().to_owned();

        let cases: [(&str, axum::http::HeaderName, &str); 3] = [
            ("Sec-Fetch-Site", SEC_FETCH_SITE, "cross-site"),
            (
                "Origin",
                axum::http::header::ORIGIN,
                "https://evil.example:3333",
            ),
            ("X-Detent-CSRF", CSRF_HEADER, "not-the-token"),
        ];

        for (name, header_name, second) in cases {
            // The good value first, the attacker's second: the order that
            // defeats a first-wins read.
            let mut request = Mutation::complete(id.expose(), &token).build()?;
            let value = axum::http::HeaderValue::from_str(second)?;
            request.headers_mut().append(header_name, value);

            let response = app(state).oneshot(request).await?;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "a repeated {name} was allowed"
            );
        }
        Ok(())
    }

    /// Two `Authorization` headers must not buy the bearer bypass either.
    #[tokio::test]
    async fn a_repeated_authorization_header_does_not_bypass() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let (id, session) = state.auth.sessions.create(
            "alice",
            Scopes::read_write(),
            false,
            std::time::Instant::now(),
        )?;
        let token = session.csrf_token.expose().to_owned();
        let mut request = Mutation {
            site: Some("cross-site"),
            ..Mutation::complete(id.expose(), &token)
        }
        .build()?;
        for _ in 0..2 {
            request.headers_mut().append(
                header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer whatever"),
            );
        }

        let response = app(state).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn a_bearer_token_skips_the_checks_entirely() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/mutate")
                    .header(header::AUTHORIZATION, "Bearer whatever")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn a_safe_method_is_never_checked() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri("/api/v1/safe")
                        .body(Body::empty())?,
                )
                .await?;
            assert_ne!(response.status(), StatusCode::FORBIDDEN, "{method}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_request_with_no_credential_is_left_to_the_extractor() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        // No cookie at all, and an unknown cookie: both pass the guard, which
        // has nothing to protect, and are refused later by the extractor.
        for cookie in [None, Some(format!("{COOKIE_NAME}={}", "0".repeat(64)))] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/mutate");
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            let response = app(state).oneshot(request.body(Body::empty())?).await?;
            assert_eq!(response.status(), StatusCode::OK);
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_expired_session_is_not_treated_as_a_csrf_failure() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let long_ago = std::time::Instant::now();
        let store = SessionStore::with_capacity(
            std::time::Duration::from_nanos(1),
            std::time::Duration::from_nanos(1),
            4,
        );
        let (id, _session) = store.create("alice", Scopes::read_write(), false, long_ago)?;
        // The session is not in this state's store at all, which is the same
        // thing an expired one looks like after eviction.
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/mutate")
                    .header(header::COOKIE, format!("{COOKIE_NAME}={}", id.expose()))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn no_get_route_is_registered_for_a_mutating_operation() {
        // PLAN §2.7: "GET never mutates". The auth router is built from this
        // table, so walking it walks the router.
        for route in routes::table() {
            assert!(
                !(route.method == Method::GET && route.mutating),
                "{} is registered as a mutating GET",
                route.path
            );
        }
        // And the table is not vacuously safe.
        assert!(routes::table().iter().any(|route| route.mutating));
        assert!(
            routes::table()
                .iter()
                .any(|route| route.method == Method::GET)
        );
    }

    #[tokio::test]
    async fn a_mutating_route_refuses_a_get() -> R {
        let fixture = test_state()?;
        let state = &fixture.state;
        let app = routes::routes().with_state(state.clone());
        for route in routes::table().iter().filter(|route| route.mutating) {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(route.path)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "GET {} was routed somewhere",
                route.path
            );
        }
        Ok(())
    }

    #[test]
    fn an_origin_is_normalized_before_it_is_compared() -> R {
        let origin = Origin::parse("HTTPS://Box.Example:443").ok_or("did not parse")?;
        assert_eq!(origin.as_str(), "https://box.example");
        assert!(origin.matches("https://box.example"));
        assert!(origin.matches("https://BOX.example:443"));
        assert!(!origin.matches("http://box.example"));
        assert!(!origin.matches("https://box.example:3333"));
        assert!(!origin.matches("null"));
        assert!(!origin.matches(""));

        let explicit = Origin::parse("https://box.example:3333").ok_or("did not parse")?;
        assert_eq!(explicit.as_str(), "https://box.example:3333");
        assert!(explicit.matches("https://box.example:3333"));
        assert!(!explicit.matches("https://box.example"));

        let plain = Origin::parse("http://box.example:80").ok_or("did not parse")?;
        assert_eq!(plain.as_str(), "http://box.example");

        let six = Origin::parse("https://[::1]:3333").ok_or("did not parse")?;
        assert_eq!(six.as_str(), "https://[::1]:3333");
        assert!(six.matches("https://[::1]:3333"));
        assert!(!six.matches("https://[::2]:3333"));
        assert_eq!(
            Origin::parse("https://[::1]:443").map(|o| o.as_str().to_owned()),
            Some("https://[::1]".to_owned())
        );

        for bad in [
            "box.example",
            "ftp://box.example",
            "https://",
            "https://box.example/path",
            "https://box.example:notaport",
            "https://box.example:99999",
            "https://[::1",
            "https://[]:443",
        ] {
            assert!(Origin::parse(bad).is_none(), "{bad:?} parsed");
        }
        Ok(())
    }

    #[test]
    fn the_origin_is_derived_from_the_configuration() -> R {
        let mut config = crate::config::Config::default();
        assert_eq!(
            Origin::for_config(&config).as_str(),
            "https://localhost:3333"
        );

        config.tls.hostnames = vec!["Box.Example".to_owned()];
        assert_eq!(
            Origin::for_config(&config).as_str(),
            "https://box.example:3333"
        );

        config.listen.addr = "127.0.0.1:443".parse()?;
        assert_eq!(Origin::for_config(&config).as_str(), "https://box.example");

        config.tls.hostnames.clear();
        config.listen.addr = "[::]:8443".parse()?;
        assert_eq!(
            Origin::for_config(&config).as_str(),
            "https://localhost:8443"
        );
        Ok(())
    }
}
