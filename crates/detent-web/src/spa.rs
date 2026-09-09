//! The embedded single-page app: everything under `/` that is not
//! `/healthz` or `/api/**` (PLAN §2.6, §4.2, Phase 4 "static SPA serving").
//!
//! ```text
//!   GET /anything ──▶ starts with "/api/"? ──yes──▶ 404
//!            │no
//!            ▼
//!   asset at that path? ──yes──▶ negotiate encoding ──▶ 200 or 304, cached
//!            │no
//!            ▼
//!   last path segment has a "."? ──yes──▶ 404 (a missing asset)
//!            │no
//!            ▼
//!   serve `index.html` ──▶ 200 (client-side routing takes it from there)
//! ```
//!
//! # Where the bytes come from
//!
//! [`AssetSource`] is the whole seam between this module's request-handling
//! logic and the bytes it serves. With the `ui` feature off — the default,
//! today — [`routes`] serves from an always-empty source, so every request
//! here answers 404; the router still assembles, and every other behaviour
//! in this module (negotiation, caching, the SPA fallback, conditional
//! requests) is exercised by the tests below against a fixture source,
//! independent of the feature.
//!
//! **What Phase 5 does to switch it on:** build `web/dist` (`bun run build`
//! in `web/`, producing hashed assets with pre-compressed `.br`/`.gz`
//! siblings next to each one — see [`is_hashed_asset`] for the exact naming
//! this module expects), then build `detent-web` with `--features ui`. That
//! compiles in [`EmbeddedAssets`], backed by `rust-embed` over `web/dist/`,
//! and [`routes`] picks it in place of the empty source. Nothing else in
//! this file changes.
//!
//! # Guarantees
//!
//! * **No filesystem lookup, ever, at request time.** [`AssetSource::get`]
//!   takes a logical path and returns bytes already resident in the binary
//!   (or, in tests, a fixture map); no path is ever joined to a base
//!   directory, so there is no path-traversal surface to have a bug in.
//! * **Never compressed at request time.** A `.br` or `.gz` sibling is
//!   served as-is when the client's `Accept-Encoding` accepts it and the
//!   sibling exists in [`AssetSource`]; nothing here ever invokes a
//!   compressor. See [`pick_variant`].
//! * **A hashed asset is cached forever; everything else is revalidated.**
//!   See [`is_hashed_asset`] for the exact pattern this recognises and where
//!   it comes from.
//! * **A missing asset is a 404, never `index.html`.** Only a path whose
//!   final segment carries no `.` falls back to the app shell — see
//!   [`looks_like_asset`]. Handing a client-side route to `index.html` makes
//!   the SPA's own router take over; handing a mistyped or deleted asset
//!   path to it would turn a deploy mistake into a confusing parse error
//!   instead of a 404.
//! * **`/api/**` never reaches the SPA fallback**, even for a path this
//!   build's API does not register: [`fallback`] refuses it before
//!   consulting [`AssetSource`] at all, so an API 404 is never HTML.
//! * **Range requests are not implemented.** Every response carries the
//!   whole asset; a `Range` header is ignored rather than half-honoured. A
//!   partial implementation — accepting the header but always answering 200
//!   instead of ever answering 206 — would be worse than not accepting it.

use std::borrow::Cow;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use sha2::{Digest as _, Sha256};

use crate::auth::routes::Route;
use crate::auth::secret::hex;
use crate::headers::API_PREFIX;

/// The asset served for `/` and for any unmatched client-side route.
const INDEX_HTML: &str = "index.html";

/// Length, in characters, of the hash Rollup (via Vite) appends to a built
/// asset's name. This is Rollup's own default for
/// `output.assetFileNames`/`chunkFileNames`/`entryFileNames` — eight
/// characters from its hash alphabet (letters, digits, `_`, `-`) — and
/// `web/vite.config.ts` does not override it, so this is a fact about the
/// toolchain this crate builds against, not a convention invented here.
const HASH_LEN: usize = 8;

/// `Cache-Control` for an [`is_hashed_asset`] match: the name changes when
/// the content does, so the old name can be cached until the browser evicts
/// it — nothing will ever ask for it under a different meaning.
const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for `index.html` and anything else unhashed: safe to
/// keep, but a client must revalidate before trusting a stored copy, so a
/// deploy cannot strand a browser on a shell that references chunks that no
/// longer exist.
const CACHE_CONTROL_REVALIDATE: &str = "no-cache";

// ---------------------------------------------------------------------------
// Where the bytes come from
// ---------------------------------------------------------------------------

/// A source of embedded-SPA bytes, keyed by a logical path with no leading
/// slash (`"index.html"`, `"assets/app-XXXXXXXX.js"`).
///
/// A pre-compressed `.br`/`.gz` sibling is looked up as an ordinary entry
/// under its own name (`"assets/app-XXXXXXXX.js.br"`) — there is no
/// separate compression-aware method, which is what keeps [`pick_variant`]
/// simple.
trait AssetSource: Send + Sync + 'static {
    /// The bytes at `path`, if this source has any.
    fn get(&self, path: &str) -> Option<Cow<'static, [u8]>>;
}

/// The source used when the `ui` feature is off: nothing is embedded, so
/// every lookup misses and every request this module handles answers 404.
#[cfg(not(feature = "ui"))]
struct EmptyAssets;

#[cfg(not(feature = "ui"))]
impl AssetSource for EmptyAssets {
    fn get(&self, _path: &str) -> Option<Cow<'static, [u8]>> {
        None
    }
}

/// `web/dist`, embedded at compile time. Only compiled in with the `ui`
/// feature; see the module docs for what Phase 5 does to turn it on.
#[cfg(feature = "ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist/"]
// `web/dist` is a build output, so it is not in git; `.gitkeep` is, purely so
// the directory exists for this macro on a fresh checkout — see the module
// docs. It is not an asset and must never be served.
#[exclude = ".gitkeep"]
struct Embedded;

/// [`AssetSource`] over [`Embedded`].
#[cfg(feature = "ui")]
struct EmbeddedAssets;

#[cfg(feature = "ui")]
impl AssetSource for EmbeddedAssets {
    fn get(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        <Embedded as rust_embed::RustEmbed>::get(path).map(|file| file.data)
    }
}

/// The source [`routes`] serves from: [`EmbeddedAssets`] with the `ui`
/// feature on, [`EmptyAssets`] without it.
#[cfg(feature = "ui")]
fn default_source() -> Arc<dyn AssetSource> {
    Arc::new(EmbeddedAssets)
}

/// The source [`routes`] serves from: [`EmbeddedAssets`] with the `ui`
/// feature on, [`EmptyAssets`] without it.
#[cfg(not(feature = "ui"))]
fn default_source() -> Arc<dyn AssetSource> {
    Arc::new(EmptyAssets)
}

// ---------------------------------------------------------------------------
// The route table
// ---------------------------------------------------------------------------

/// This module's one entry, in the [`Route`] shape [`crate::api`] and
/// [`crate::auth::routes`] use: a catch-all `GET` fallback, never mutating.
/// Unlike theirs, it names no one literal path — there is no request that
/// walking this table alone could replay — but it is listed here so a
/// reader enumerating every module's table does not find this surface
/// silently missing.
#[must_use]
pub fn table() -> &'static [Route] {
    static TABLE: [Route; 1] = [Route {
        method: Method::GET,
        path: "*",
        mutating: false,
    }];
    &TABLE
}

/// The SPA's whole surface: a single fallback behind [`default_source`].
///
/// Deliberately not given [`crate::state::AppState`] — the SPA needs no
/// session, no CSRF token, nothing this crate's other routes carry. Merge
/// this after `/healthz` and `/api/**` in [`crate::router`]: an exact route
/// registered by either of those always wins over this fallback regardless
/// of merge order, but merging it last keeps the router assembled in the
/// order a request meets it.
pub fn routes() -> Router {
    routes_with(default_source())
}

/// [`routes`], parameterised over the asset source — the seam the tests
/// below use to exercise this module's whole behaviour against a fixture,
/// independent of the `ui` feature.
fn routes_with(source: Arc<dyn AssetSource>) -> Router {
    Router::new().fallback(fallback).with_state(source)
}

// ---------------------------------------------------------------------------
// The fallback
// ---------------------------------------------------------------------------

/// Handle any request `/healthz` and `/api/**` did not claim.
async fn fallback(
    State(source): State<Arc<dyn AssetSource>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let path = uri.path();
    if path.starts_with(API_PREFIX) {
        // An API path this build does not register is a plain 404, never
        // the app shell — see the module guarantees.
        return StatusCode::NOT_FOUND.into_response();
    }
    let logical = logical_path(path);
    if let Some(response) = asset_response(source.as_ref(), &logical, &headers) {
        return response;
    }
    if looks_like_asset(&logical) {
        return StatusCode::NOT_FOUND.into_response();
    }
    asset_response(source.as_ref(), INDEX_HTML, &headers)
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

/// The request path, as a key into [`AssetSource`]: the leading slash
/// dropped, `/` itself mapped to [`INDEX_HTML`].
fn logical_path(request_path: &str) -> String {
    let trimmed = request_path.trim_start_matches('/');
    if trimmed.is_empty() {
        INDEX_HTML.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Whether `logical_path`'s final segment carries a `.` — the signal this
/// module uses to tell a missing *asset* (404) from an unmatched *client
/// route* (served `index.html`). None of `web/dist`'s own directory
/// segments carry a `.`, so this is unambiguous for every asset this crate
/// ships.
fn looks_like_asset(logical_path: &str) -> bool {
    logical_path
        .rsplit('/')
        .next()
        .is_some_and(|segment| segment.contains('.'))
}

// ---------------------------------------------------------------------------
// Serving one asset
// ---------------------------------------------------------------------------

/// `Some` response for `path`, negotiated and cache-headered; `None` when
/// [`AssetSource`] has nothing at `path` under any encoding.
fn asset_response(source: &dyn AssetSource, path: &str, headers: &HeaderMap) -> Option<Response> {
    let accept_encoding = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok());
    let (bytes, encoding) = pick_variant(source, path, accept_encoding)?;
    let etag = etag_for(&bytes);
    let cache_control = if is_hashed_asset(path) {
        CACHE_CONTROL_IMMUTABLE
    } else {
        CACHE_CONTROL_REVALIDATE
    };
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| if_none_match_hits(value, &etag));

    let mut response = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = Response::new(Body::from(bytes));
        let response_headers = response.headers_mut();
        response_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(path)),
        );
        if let Some(token) = encoding.header_value() {
            response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(token));
        }
        response
    };

    // Common to both 200 and 304: the response varies by Accept-Encoding
    // either way, and RFC 7232 has a validator answer carry the same
    // Cache-Control and ETag a full response would.
    let response_headers = response.headers_mut();
    response_headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    // `HeaderValue::from_str` can only fail on a value that is not visible
    // ASCII; `etag_for` only ever produces hex digits and quotes. Skipping
    // rather than panicking matches `crate::headers::security_headers`.
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response_headers.insert(header::ETAG, value);
    }
    Some(response)
}

/// Which pre-compressed sibling (if any) satisfies both `accept_encoding`
/// and [`AssetSource`], preferring `br`, then `gzip`, then the identity
/// file — PLAN §2.6's ordering.
fn pick_variant(
    source: &dyn AssetSource,
    path: &str,
    accept_encoding: Option<&str>,
) -> Option<(Cow<'static, [u8]>, Encoding)> {
    if accepts(accept_encoding, "br")
        && let Some(bytes) = source.get(&format!("{path}.br"))
    {
        return Some((bytes, Encoding::Br));
    }
    if accepts(accept_encoding, "gzip")
        && let Some(bytes) = source.get(&format!("{path}.gz"))
    {
        return Some((bytes, Encoding::Gzip));
    }
    source.get(path).map(|bytes| (bytes, Encoding::Identity))
}

/// The three encodings this module ever serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// A pre-compressed `.br` sibling.
    Br,
    /// A pre-compressed `.gz` sibling.
    Gzip,
    /// The asset as built, uncompressed.
    Identity,
}

impl Encoding {
    /// The `Content-Encoding` value to send, or `None` for identity — an
    /// explicit `Content-Encoding: identity` is legal but pointless, and
    /// omitting it is what every real server does.
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Br => Some("br"),
            Self::Gzip => Some("gzip"),
            Self::Identity => None,
        }
    }
}

/// Whether the raw `Accept-Encoding` header value `accept_encoding` names
/// `token` with a nonzero quality value. `None` (no header at all) accepts
/// nothing this function is ever asked about — a request with no header
/// only ever reaches the identity branch in [`pick_variant`], which does
/// not call this at all.
fn accepts(accept_encoding: Option<&str>, token: &str) -> bool {
    let Some(header_value) = accept_encoding else {
        return false;
    };
    header_value.split(',').any(|item| {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        if !name.eq_ignore_ascii_case(token) {
            return false;
        }
        let quality = parts
            .find_map(|part| part.trim().strip_prefix("q="))
            .and_then(|value| value.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        quality > 0.0
    })
}

// ---------------------------------------------------------------------------
// Cache validation
// ---------------------------------------------------------------------------

/// The strong `ETag` for `bytes`: its SHA-256, hex-encoded and quoted.
fn etag_for(bytes: &[u8]) -> String {
    format!("\"{}\"", hex(&Sha256::digest(bytes)))
}

/// Whether `if_none_match` (the raw `If-None-Match` header value, which may
/// be a comma-separated list) already names `etag`: a bare `*`, or the exact
/// tag with an optional weak (`W/`) prefix tolerated on the presented side.
fn if_none_match_hits(if_none_match: &str, etag: &str) -> bool {
    if_none_match.split(',').any(|candidate| {
        let candidate = candidate.trim().trim_start_matches("W/");
        candidate == "*" || candidate == etag
    })
}

// ---------------------------------------------------------------------------
// Asset kind
// ---------------------------------------------------------------------------

/// Whether `path`'s final segment matches Rollup's default hashed-asset
/// name: `<name>-<hash><ext>`, where `<hash>` is exactly [`HASH_LEN`]
/// characters of Rollup's hash alphabet (letters, digits, `_`, `-`). See
/// [`HASH_LEN`] for where that fact comes from.
fn is_hashed_asset(path: &str) -> bool {
    // `str::rsplit` always yields at least one item, even for `""`, so the
    // fallback is never actually taken; `unwrap_or` expresses that without a
    // branch `path` could never reach.
    let filename = path.rsplit('/').next().unwrap_or(path);
    let stem = filename
        .rsplit_once('.')
        .map_or(filename, |(stem, _extension)| stem);
    // At least one name character, the separating `-`, and HASH_LEN hash
    // characters.
    if stem.len() < HASH_LEN.saturating_add(2) {
        return false;
    }
    let hash_start = stem.len().saturating_sub(HASH_LEN);
    let separator_start = hash_start.saturating_sub(1);
    if stem.get(separator_start..hash_start) != Some("-") {
        return false;
    }
    stem.get(hash_start..).is_some_and(|hash| {
        hash.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// `Content-Type` for `path`, by its extension. A small fixed table rather
/// than a `mime_guess` dependency: `web/dist`'s asset set is one this crate
/// controls, not arbitrary user input.
fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff2" => "font/woff2",
        "json" | "map" => "application/json",
        "ico" => "image/x-icon",
        "webmanifest" => "application/manifest+json",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssetSource, CACHE_CONTROL_IMMUTABLE, CACHE_CONTROL_REVALIDATE, accepts, content_type,
        etag_for, if_none_match_hits, is_hashed_asset, logical_path, looks_like_asset, routes,
        routes_with, table,
    };
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::response::Response;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A fixture source, holding exactly the entries a test lists.
    struct FixtureAssets(HashMap<&'static str, &'static [u8]>);

    impl FixtureAssets {
        fn new(entries: &[(&'static str, &'static [u8])]) -> Self {
            Self(entries.iter().copied().collect())
        }
    }

    impl AssetSource for FixtureAssets {
        fn get(&self, path: &str) -> Option<Cow<'static, [u8]>> {
            self.0.get(path).map(|bytes| Cow::Borrowed(*bytes))
        }
    }

    /// A router over a representative fixture: one hashed JS asset with both
    /// pre-compressed siblings, one with only a `.gz` sibling, and one
    /// example of every content type this module knows.
    fn app() -> Router {
        routes_with(Arc::new(FixtureAssets::new(&[
            ("index.html", b"<html>index</html>"),
            ("robots.txt", b"User-agent: *"),
            ("favicon.ico", b"ICO"),
            ("data.json", b"{}"),
            ("manifest.webmanifest", b"{}"),
            ("assets/logo.svg", b"<svg></svg>"),
            ("assets/app-AbCdEfGh.js", b"console.log(1)"),
            ("assets/app-AbCdEfGh.js.br", b"BR-BYTES"),
            ("assets/app-AbCdEfGh.js.gz", b"GZ-BYTES"),
            ("assets/app-AbCdEfGh.css", b"body{}"),
            ("assets/app-AbCdEfGh.js.map", b"{\"version\":3}"),
            ("assets/photo-AbCdEfGh.png", b"PNGDATA"),
            ("assets/font-AbCdEfGh.woff2", b"WOFF2DATA"),
            ("legacy/only-gz-AbCdEfGh.js", b"legacy"),
            ("legacy/only-gz-AbCdEfGh.js.gz", b"legacy-gz"),
        ])))
    }

    async fn body_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await?
            .to_vec())
    }

    fn get(path: &str) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        Ok(Request::builder().uri(path).body(Body::empty())?)
    }

    // -- content negotiation --------------------------------------------------

    #[tokio::test]
    async fn content_negotiation_prefers_br_then_gzip_then_identity() -> R {
        let cases: [(&str, &[u8], Option<&str>); 3] = [
            ("br, gzip", b"BR-BYTES", Some("br")),
            ("gzip", b"GZ-BYTES", Some("gzip")),
            ("deflate", b"console.log(1)", None),
        ];
        for (accept, expected_body, expected_encoding) in cases {
            let response = app()
                .oneshot(
                    Request::builder()
                        .uri("/assets/app-AbCdEfGh.js")
                        .header(header::ACCEPT_ENCODING, accept)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "{accept}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .map(|v| v.to_str())
                    .transpose()?,
                expected_encoding,
                "{accept}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::VARY)
                    .map(|v| v.to_str())
                    .transpose()?,
                Some("Accept-Encoding"),
                "{accept}"
            );
            assert_eq!(body_bytes(response).await?, expected_body, "{accept}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn no_accept_encoding_header_serves_identity() -> R {
        let response = app().oneshot(get("/assets/app-AbCdEfGh.js")?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(body_bytes(response).await?, b"console.log(1)");
        Ok(())
    }

    #[tokio::test]
    async fn gzip_is_served_when_br_is_accepted_but_has_no_sibling() -> R {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/legacy/only-gz-AbCdEfGh.js")
                    .header(header::ACCEPT_ENCODING, "br, gzip")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_ENCODING)
                .map(|v| v.to_str())
                .transpose()?,
            Some("gzip")
        );
        assert_eq!(body_bytes(response).await?, b"legacy-gz");
        Ok(())
    }

    // -- cache headers ---------------------------------------------------------

    #[tokio::test]
    async fn hashed_assets_are_immutable_and_everything_else_revalidates() -> R {
        for (path, expected) in [
            ("/assets/app-AbCdEfGh.js", CACHE_CONTROL_IMMUTABLE),
            ("/assets/app-AbCdEfGh.css", CACHE_CONTROL_IMMUTABLE),
            ("/index.html", CACHE_CONTROL_REVALIDATE),
            ("/robots.txt", CACHE_CONTROL_REVALIDATE),
            ("/assets/logo.svg", CACHE_CONTROL_REVALIDATE),
        ] {
            let response = app().oneshot(get(path)?).await?;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .map(|v| v.to_str())
                    .transpose()?,
                Some(expected),
                "{path}"
            );
        }
        Ok(())
    }

    // -- content type ------------------------------------------------------

    #[tokio::test]
    async fn content_type_matches_the_extension() -> R {
        for (path, expected) in [
            ("/index.html", "text/html; charset=utf-8"),
            ("/assets/app-AbCdEfGh.js", "text/javascript; charset=utf-8"),
            ("/assets/app-AbCdEfGh.css", "text/css; charset=utf-8"),
            ("/assets/logo.svg", "image/svg+xml"),
            ("/assets/photo-AbCdEfGh.png", "image/png"),
            ("/assets/font-AbCdEfGh.woff2", "font/woff2"),
            ("/data.json", "application/json"),
            ("/favicon.ico", "image/x-icon"),
            ("/assets/app-AbCdEfGh.js.map", "application/json"),
            ("/manifest.webmanifest", "application/manifest+json"),
            ("/robots.txt", "text/plain; charset=utf-8"),
        ] {
            let response = app().oneshot(get(path)?).await?;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .map(|v| v.to_str())
                    .transpose()?,
                Some(expected),
                "{path}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_unknown_extension_falls_back_to_octet_stream() {
        assert_eq!(content_type("weird.xyz"), "application/octet-stream");
        assert_eq!(
            content_type("no-extension-at-all"),
            "application/octet-stream"
        );
    }

    // -- conditional requests -----------------------------------------------

    #[tokio::test]
    async fn a_repeated_request_with_the_etag_is_answered_304() -> R {
        let first = app().oneshot(get("/index.html")?).await?;
        assert_eq!(first.status(), StatusCode::OK);
        let etag = first
            .headers()
            .get(header::ETAG)
            .ok_or("no etag")?
            .to_str()?
            .to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");

        let second = app()
            .oneshot(
                Request::builder()
                    .uri("/index.html")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            second
                .headers()
                .get(header::ETAG)
                .map(|v| v.to_str())
                .transpose()?,
            Some(etag.as_str())
        );
        assert!(body_bytes(second).await?.is_empty());
        Ok(())
    }

    #[test]
    fn etag_for_differs_by_content_and_is_quoted() {
        let a = etag_for(b"a");
        let b = etag_for(b"b");
        assert_ne!(a, b);
        assert!(a.starts_with('"') && a.ends_with('"'), "{a}");
        assert_eq!(a, etag_for(b"a"), "not deterministic");
    }

    #[test]
    fn if_none_match_hits_matches_exact_wildcard_and_weak() {
        let etag = "\"abc\"";
        assert!(if_none_match_hits(etag, etag));
        assert!(if_none_match_hits("*", etag));
        assert!(if_none_match_hits("W/\"abc\"", etag));
        assert!(if_none_match_hits("\"nope\", \"abc\"", etag));
        assert!(!if_none_match_hits("\"other\"", etag));
    }

    // -- spa fallback vs missing asset ---------------------------------------

    #[tokio::test]
    async fn the_root_and_an_unmatched_route_both_get_index_html() -> R {
        for path in ["/", "/dashboard/settings"] {
            let response = app().oneshot(get(path)?).await?;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(body_bytes(response).await?, b"<html>index</html>", "{path}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_asset_with_an_extension_is_404_not_the_app_shell() -> R {
        let response = app().oneshot(get("/assets/does-not-exist.js")?).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body_bytes(response).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn an_api_shaped_path_is_refused_not_handed_the_app_shell() -> R {
        let response = app().oneshot(get("/api/v1/nope")?).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body_bytes(response).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_source_with_nothing_in_it_answers_404_for_every_request() -> R {
        // Exactly the shape `default_source` builds when the `ui` feature is
        // off, expressed as a fixture so the test does not depend on which
        // feature set this crate was built with.
        let empty = routes_with(Arc::new(FixtureAssets::new(&[])));
        for path in ["/", "/index.html", "/dashboard", "/assets/app.js"] {
            let response = empty.clone().oneshot(get(path)?).await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    /// `routes()` builds and answers regardless of the `ui` feature. An
    /// asset-shaped path that no real build would ever emit is a 404 either
    /// way — with the feature off there is nothing to find at all; with it
    /// on, `web/dist` still would not contain this exact name.
    #[tokio::test]
    async fn routes_assembles_and_answers_regardless_of_the_ui_feature() -> R {
        let response = routes()
            .oneshot(get("/definitely-not-a-real-asset-name.js")?)
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    // -- pure helpers ---------------------------------------------------------

    #[test]
    fn is_hashed_asset_matches_rollups_default_pattern() {
        for good in [
            "index-DrXhvoLE.js",
            "assets/index-CtbvlS6z.css",
            "archivo-latin-ext-standard-normal-7khWdh9v.woff2",
            "ibm-plex-mono-cyrillic-300-normal-Ba-HN6uq.woff2",
            "ibm-plex-mono-vietnamese-300-normal-V-xxqcpd.woff2",
        ] {
            assert!(is_hashed_asset(good), "{good}");
        }
        for bad in [
            "index.html",
            "robots.txt",
            "favicon.ico",
            "manifest.webmanifest",
            "assets/logo.svg",
            "app-AbCdEfG.js",       // 7-char hash: one short
            "toolong-AbCdEfGhI.js", // 9-char hash: one long
        ] {
            assert!(!is_hashed_asset(bad), "{bad}");
        }
    }

    #[test]
    fn looks_like_asset_is_true_only_for_a_dotted_final_segment() {
        assert!(looks_like_asset("assets/app.js"));
        assert!(looks_like_asset("favicon.ico"));
        assert!(!looks_like_asset("dashboard"));
        assert!(!looks_like_asset("dashboard/settings"));
        assert!(!looks_like_asset(""));
    }

    #[test]
    fn logical_path_maps_root_to_index_html() {
        assert_eq!(logical_path("/"), "index.html");
        assert_eq!(logical_path(""), "index.html");
        assert_eq!(logical_path("/assets/app.js"), "assets/app.js");
    }

    #[test]
    fn accepts_honours_quality_values_and_is_case_insensitive() {
        assert!(accepts(Some("br"), "br"));
        assert!(accepts(Some("BR"), "br"));
        assert!(accepts(Some("gzip;q=1.0, br;q=0.5"), "br"));
        assert!(!accepts(Some("br;q=0"), "br"));
        assert!(!accepts(None, "br"));
        assert!(!accepts(Some("gzip"), "br"));
    }

    // -- the route table -------------------------------------------------------

    #[test]
    fn the_table_is_one_non_mutating_get_entry() {
        assert_eq!(table().len(), 1);
        assert!(
            table()
                .iter()
                .all(|route| route.method == Method::GET && !route.mutating)
        );
    }
}
