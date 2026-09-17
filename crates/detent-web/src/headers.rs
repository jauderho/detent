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
//!   get [`CACHE_CONTROL_API`]; [`crate::spa`] gives hashed static assets their
//!   own immutable caching, which this middleware must not stamp on.
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

/// Base64 SHA-256 of `web/src/theme-init.js`, the inline theme script the
/// SPA's `index.html` runs before first paint, so the page does not flash
/// the wrong theme.
///
/// Two tests hold this together, because two things can drift.
/// [`tests::theme_script_sha256_matches_the_file_it_hashes`] recomputes the
/// constant from the file, and
/// [`tests::the_inline_script_in_index_html_is_the_file_byte_for_byte`]
/// checks what `web/index.html` actually inlines — which is what a browser
/// hashes, indentation and all. The second one matters more than it looks:
/// the inline copy started out as the same script re-indented to sit inside
/// `<head>`, which hashes differently and would have been refused by the CSP.
/// Phase 5, which owns the build, should inject the file rather than let a
/// copy of it be edited.
pub const THEME_SCRIPT_SHA256: &str = "n8ZCMTrvqTZT1jopUGZ8VOuIQ0IrMQBU0Xxdc4h9zjE=";

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

    /// Base64 (standard alphabet, padded) of `bytes`.
    ///
    /// A local encoder rather than a dependency: this is needed in exactly
    /// one place, this test, and never at run time — production code only
    /// ever reads the constant [`THEME_SCRIPT_SHA256`] already carries.
    fn base64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = u32::from(*chunk.first().unwrap_or(&0));
            let b1 = chunk.get(1).copied();
            let b2 = chunk.get(2).copied();
            let n = (b0 << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
            let sextets = [
                (n >> 18) & 0x3f,
                (n >> 12) & 0x3f,
                (n >> 6) & 0x3f,
                n & 0x3f,
            ];
            for (position, sextet) in sextets.iter().enumerate() {
                let present = match position {
                    2 => b1.is_some(),
                    3 => b2.is_some(),
                    _ => true,
                };
                if present {
                    if let Some(&digit) = ALPHABET.get(*sextet as usize) {
                        out.push(digit as char);
                    }
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// [`THEME_SCRIPT_SHA256`] must always be the digest of the file it
    /// claims to hash — this test is the enforcement the constant's own doc
    /// comment promises, and it names the value to fix it to when the file
    /// changes and this does not.
    #[test]
    fn theme_script_sha256_matches_the_file_it_hashes() -> Result<(), Box<dyn std::error::Error>> {
        use sha2::Digest as _;

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/src/theme-init.js");
        let bytes = std::fs::read(path)?;
        let digest = sha2::Sha256::digest(&bytes);
        let expected = base64_encode(&digest);
        assert_eq!(
            THEME_SCRIPT_SHA256, expected,
            "THEME_SCRIPT_SHA256 is stale for `{path}`; update the constant in headers.rs to `{expected}`"
        );
        Ok(())
    }

    /// Hashing the *file* is only half the invariant. What the browser
    /// actually hashes is the text between `<script>` and `</script>` in
    /// `index.html`, indentation and all — so a copy of the script that is
    /// merely equivalent, rather than byte-identical, is refused by the CSP
    /// and the page paints the wrong theme before correcting itself.
    ///
    /// The two were exactly that far apart when this test was written: the
    /// inline copy was the same code re-indented to sit inside `<head>`.
    #[test]
    fn the_inline_script_in_index_html_is_the_file_byte_for_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::Digest as _;

        let html =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/index.html"))?;
        let open = "<script>";
        let start = html
            .find(open)
            .ok_or("web/index.html has no inline <script>")?
            .saturating_add(open.len());
        let rest = html
            .get(start..)
            .ok_or("inline script start is out of range")?;
        let end = rest
            .find("</script>")
            .ok_or("web/index.html's inline <script> is unterminated")?;
        let inline = rest.get(..end).ok_or("inline script end is out of range")?;

        let digest = sha2::Sha256::digest(inline.as_bytes());
        let actual = base64_encode(&digest);
        assert_eq!(
            actual, THEME_SCRIPT_SHA256,
            "the inline theme script in web/index.html hashes to `{actual}`, not the \
             `{THEME_SCRIPT_SHA256}` the CSP pins. Its text must be web/src/theme-init.js \
             byte for byte — indentation included, because that is what the browser hashes."
        );
        Ok(())
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
