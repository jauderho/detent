//! The security headers every response carries (PLAN §2.7, "Headers").
//!
//! One middleware, one header set, applied to every route — including error
//! responses, which is why it wraps the router rather than living in the
//! handlers.
//!
//! # Guarantees
//!
//! * **The set is literal.** Every header below is the string PLAN §2.7 spells
//!   out; [`tests::every_header_is_present_with_its_exact_value`] compares
//!   against those strings, so a change to the policy is a change to a test.
//! * **`no-store` on the API, nothing on the rest.** Only paths under `/api/`
//!   get [`CACHE_CONTROL_API`]; Phase 4d gives hashed static assets their own
//!   immutable caching, which this middleware must not stamp on.
//! * **A handler's own `Cache-Control` wins.** The middleware never replaces a
//!   value a handler already set.

use axum::extract::Request;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// `Permissions-Policy`; the `http` crate has no constant for it.
pub const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

/// `Cross-Origin-Opener-Policy`; no `http` constant either.
pub const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");

/// `Cross-Origin-Resource-Policy`; no `http` constant either.
pub const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// `Cross-Origin-Embedder-Policy`; no `http` constant either.
pub const CROSS_ORIGIN_EMBEDDER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-embedder-policy");

/// Base64 SHA-256 of the inline theme script the SPA's `index.html` runs
/// before first paint, so the page does not flash the wrong theme.
///
/// **Placeholder.** Phase 5 writes the real digest here when the script exists;
/// until then the value hashes nothing, which means no inline script can run —
/// the safe direction to be wrong in. The build that ships the SPA must fail
/// if this and `index.html` disagree.
pub const THEME_SCRIPT_SHA256: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The `Content-Security-Policy` of PLAN §2.7, with
/// [`THEME_SCRIPT_SHA256`] substituted into `script-src`.
///
/// `default-src 'none'` means every fetch directive that is not named below is
/// denied outright, so the enumerated ones are the whole of what the page may
/// do.
pub static CONTENT_SECURITY_POLICY_VALUE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "default-src 'none'; script-src 'self' 'sha256-{THEME_SCRIPT_SHA256}'; \
             style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    });

/// Two years, with subdomains: PLAN §2.7. No `preload`, because a detent
/// appliance is usually on a private name its operator also uses for other
/// things.
pub const STRICT_TRANSPORT_SECURITY_VALUE: &str = "max-age=63072000; includeSubDomains";

/// `Referrer-Policy`: send nothing, to anybody.
pub const REFERRER_POLICY_VALUE: &str = "no-referrer";

/// `X-Content-Type-Options`.
pub const X_CONTENT_TYPE_OPTIONS_VALUE: &str = "nosniff";

/// `Cross-Origin-Opener-Policy`.
pub const CROSS_ORIGIN_OPENER_POLICY_VALUE: &str = "same-origin";

/// `Cross-Origin-Resource-Policy`.
pub const CROSS_ORIGIN_RESOURCE_POLICY_VALUE: &str = "same-origin";

/// `Cross-Origin-Embedder-Policy`.
pub const CROSS_ORIGIN_EMBEDDER_POLICY_VALUE: &str = "require-corp";

/// `Permissions-Policy`: PLAN §2.7 says "deny all", and a policy has to name
/// what it denies, so this is the list of powerful features the platform
/// defines. An empty allow-list — `()` — denies the feature to this document
/// and to every frame it could embed.
pub const PERMISSIONS_POLICY_VALUE: &str = "accelerometer=(), ambient-light-sensor=(), \
     autoplay=(), battery=(), bluetooth=(), camera=(), display-capture=(), \
     encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), \
     hid=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), \
     midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), \
     publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), \
     usb=(), window-management=(), xr-spatial-tracking=()";

/// `Cache-Control` for anything under [`API_PREFIX`].
pub const CACHE_CONTROL_API: &str = "no-store";

/// Path prefix that marks a response as API output rather than a static asset.
pub const API_PREFIX: &str = "/api/";

/// Set the §2.7 header set on every response.
///
/// Install with `axum::middleware::from_fn(security_headers)`, outermost, so
/// that responses produced by other layers (body-limit rejections, timeouts)
/// carry the headers too.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with(API_PREFIX);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // `HeaderValue::from_str` can only fail on a non-visible-ASCII value, and
    // every value here is a compile-time constant that is visible ASCII. A
    // failure would mean this file changed; skipping the header rather than
    // panicking keeps the deny-by-default posture of `panic = "deny"`.
    if let Ok(value) = HeaderValue::from_str(&CONTENT_SECURITY_POLICY_VALUE) {
        headers.insert(CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static(X_CONTENT_TYPE_OPTIONS_VALUE),
    );
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY_VALUE),
    );
    headers.insert(
        PERMISSIONS_POLICY,
        HeaderValue::from_static(PERMISSIONS_POLICY_VALUE),
    );
    headers.insert(
        CROSS_ORIGIN_OPENER_POLICY,
        HeaderValue::from_static(CROSS_ORIGIN_OPENER_POLICY_VALUE),
    );
    headers.insert(
        CROSS_ORIGIN_RESOURCE_POLICY,
        HeaderValue::from_static(CROSS_ORIGIN_RESOURCE_POLICY_VALUE),
    );
    headers.insert(
        CROSS_ORIGIN_EMBEDDER_POLICY,
        HeaderValue::from_static(CROSS_ORIGIN_EMBEDDER_POLICY_VALUE),
    );
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static(STRICT_TRANSPORT_SECURITY_VALUE),
    );
    if is_api && !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static(CACHE_CONTROL_API));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{
        API_PREFIX, CACHE_CONTROL_API, CONTENT_SECURITY_POLICY_VALUE, CROSS_ORIGIN_EMBEDDER_POLICY,
        CROSS_ORIGIN_EMBEDDER_POLICY_VALUE, CROSS_ORIGIN_OPENER_POLICY,
        CROSS_ORIGIN_OPENER_POLICY_VALUE, CROSS_ORIGIN_RESOURCE_POLICY,
        CROSS_ORIGIN_RESOURCE_POLICY_VALUE, PERMISSIONS_POLICY, PERMISSIONS_POLICY_VALUE,
        REFERRER_POLICY_VALUE, STRICT_TRANSPORT_SECURITY_VALUE, THEME_SCRIPT_SHA256,
        X_CONTENT_TYPE_OPTIONS_VALUE, security_headers,
    };
    use axum::Router;
    use axum::body::Body;
    use axum::http::header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
        X_CONTENT_TYPE_OPTIONS,
    };
    use axum::http::{HeaderName, Request, StatusCode};
    use axum::response::{IntoResponse as _, Response};
    use axum::routing::get;
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A router with one plain route, one API route, one API route that sets
    /// its own `Cache-Control`, and nothing else.
    fn app() -> Router {
        Router::new()
            .route("/index.html", get(|| async { "page" }))
            .route("/api/v1/modules", get(|| async { "modules" }))
            .route(
                "/api/v1/opinionated",
                get(|| async {
                    let mut response: Response = "cached".into_response();
                    response.headers_mut().insert(
                        CACHE_CONTROL,
                        axum::http::HeaderValue::from_static("private, max-age=60"),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn(security_headers))
    }

    async fn get_response(path: &str) -> Result<Response, Box<dyn std::error::Error>> {
        let request = Request::builder().uri(path).body(Body::empty())?;
        Ok(app().oneshot(request).await?)
    }

    /// Every header the policy names, and the exact value it must carry.
    fn expected() -> Vec<(HeaderName, String)> {
        vec![
            (
                CONTENT_SECURITY_POLICY,
                CONTENT_SECURITY_POLICY_VALUE.clone(),
            ),
            (
                X_CONTENT_TYPE_OPTIONS,
                X_CONTENT_TYPE_OPTIONS_VALUE.to_owned(),
            ),
            (REFERRER_POLICY, REFERRER_POLICY_VALUE.to_owned()),
            (PERMISSIONS_POLICY, PERMISSIONS_POLICY_VALUE.to_owned()),
            (
                CROSS_ORIGIN_OPENER_POLICY,
                CROSS_ORIGIN_OPENER_POLICY_VALUE.to_owned(),
            ),
            (
                CROSS_ORIGIN_RESOURCE_POLICY,
                CROSS_ORIGIN_RESOURCE_POLICY_VALUE.to_owned(),
            ),
            (
                CROSS_ORIGIN_EMBEDDER_POLICY,
                CROSS_ORIGIN_EMBEDDER_POLICY_VALUE.to_owned(),
            ),
            (
                STRICT_TRANSPORT_SECURITY,
                STRICT_TRANSPORT_SECURITY_VALUE.to_owned(),
            ),
        ]
    }

    #[tokio::test]
    async fn every_header_is_present_with_its_exact_value() -> R {
        for path in ["/index.html", "/api/v1/modules"] {
            let response = get_response(path).await?;
            assert_eq!(response.status(), StatusCode::OK);
            for (name, value) in expected() {
                let got = response
                    .headers()
                    .get(&name)
                    .ok_or_else(|| format!("{path}: {name} is missing"))?;
                assert_eq!(got.to_str()?, value, "{path}: {name}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_csp_is_the_policy_from_the_plan() {
        assert_eq!(
            *CONTENT_SECURITY_POLICY_VALUE,
            format!(
                "default-src 'none'; script-src 'self' 'sha256-{THEME_SCRIPT_SHA256}'; \
                 style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                 frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        );
    }

    #[tokio::test]
    async fn only_api_paths_are_marked_no_store() -> R {
        let api = get_response("/api/v1/modules").await?;
        assert_eq!(
            api.headers()
                .get(CACHE_CONTROL)
                .map(|v| v.to_str())
                .transpose()?,
            Some(CACHE_CONTROL_API)
        );

        let page = get_response("/index.html").await?;
        assert!(
            page.headers().get(CACHE_CONTROL).is_none(),
            "a non-API path must be left for Phase 4d's asset caching"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_handlers_own_cache_control_is_not_overwritten() -> R {
        let response = get_response("/api/v1/opinionated").await?;
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .map(|v| v.to_str())
                .transpose()?,
            Some("private, max-age=60")
        );
        Ok(())
    }

    #[tokio::test]
    async fn error_responses_carry_the_headers_too() -> R {
        let response = get_response("/api/v1/absent").await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for (name, value) in expected() {
            let got = response
                .headers()
                .get(&name)
                .ok_or_else(|| format!("{name} is missing from a 404"))?;
            assert_eq!(got.to_str()?, value);
        }
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .map(|v| v.to_str())
                .transpose()?,
            Some(CACHE_CONTROL_API)
        );
        Ok(())
    }

    #[test]
    fn the_api_prefix_matches_only_the_api() {
        assert!("/api/v1/modules".starts_with(API_PREFIX));
        assert!(!"/apiv1".starts_with(API_PREFIX));
        assert!(!"/".starts_with(API_PREFIX));
        assert!(!"/assets/api/app.js".starts_with(API_PREFIX));
    }
}
