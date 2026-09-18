//! Fetching release metadata and release artifacts over the workspace TLS
//! stack (PLAN §2.9 step 1).
//!
//! The HTTP stack is exactly one client: hyper + hyper-rustls, TLS 1.3 only,
//! roots pinned to `webpki-roots` at build time (no system store, ADR-009).
//! Everything tests can reach is behind [`Transport`]; the real client is
//! exercised offline against a loopback TLS server in the tests.

use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::policy::Candidate;

/// Cap on the releases JSON (PLAN §2.9 step 1).
pub const MAX_RELEASES_BYTES: u64 = 1 << 20;

/// Cap on the binary download (PLAN §2.9 step 3).
pub const MAX_BINARY_BYTES: u64 = 64 << 20;

/// Timeout for one HTTP GET.
const GET_TIMEOUT: Duration = Duration::from_secs(30);

/// `GET https://api.github.com/repos/jauderho/detent/releases`.
pub const RELEASES_URL: &str = "https://api.github.com/repos/jauderho/detent/releases";

/// A fetch failure. Infra-unavailable is a hard error, never a downgrade
/// path (refuse-closed, ADR-014).
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The response exceeded the caller's byte cap.
    #[error("response exceeded the {cap}-byte cap")]
    TooLarge {
        /// The cap that was exceeded.
        cap: u64,
    },
    /// The server answered with a non-2xx status.
    #[error("GET {url} answered HTTP {status}")]
    BadStatus {
        /// The request URL.
        url: String,
        /// The HTTP status code.
        status: u16,
    },
    /// The client could not reach the server at all.
    #[error("GET {url} failed: {reason}")]
    Unreachable {
        /// The request URL.
        url: String,
        /// A coarse reason (no secrets, no response bodies).
        reason: String,
    },
    /// The releases JSON was not the expected shape.
    #[error("releases JSON is malformed: {0}")]
    BadJson(String),
    /// The SHA256SUMS file did not name the requested asset.
    #[error("SHA256SUMS does not name {0}")]
    MissingSum(String),
}

/// One HTTP GET, at the boundary every test mocks.
pub trait Transport: Send + Sync {
    /// GETs `url` and streams at most `cap` bytes into `sink`, returning the
    /// byte count. Any status other than 2xx is an error.
    ///
    /// # Errors
    ///
    /// [`FetchError`] for status, transport, and cap failures.
    fn get(&self, url: &str, cap: u64, sink: &mut dyn std::io::Write) -> Result<u64, FetchError>;
}

/// The GitHub releases API response, narrowed to the fields we consume.
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    /// RFC 3339; `null` until GitHub publishes the release.
    published_at: Option<String>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    /// The browser download URL.
    browser_download_url: String,
}

/// The release an update run acts on, with the asset URLs resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The policy candidate (tag, publish time, body).
    pub candidate: Candidate,
    /// `detent-<target-triple>` download URL.
    pub binary_url: String,
    /// The Sigstore bundle URL (`*.sigstore.json`).
    pub bundle_url: String,
    /// The SHA256SUMS URL.
    pub sums_url: String,
}

/// Fetches the release list and turns it into policy candidates, dropping
/// drafts and prereleases (PLAN §2.9 step 2).
///
/// # Errors
///
/// [`FetchError`] for transport and JSON failures.
pub fn list_releases(
    transport: &dyn Transport,
    target_triple: &str,
) -> Result<Vec<Release>, FetchError> {
    let mut bytes = Vec::new();
    transport.get(RELEASES_URL, MAX_RELEASES_BYTES, &mut bytes)?;
    let releases: Vec<GithubRelease> =
        serde_json::from_slice(&bytes).map_err(|err| FetchError::BadJson(err.to_string()))?;
    Ok(releases
        .into_iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let binary = release
                .assets
                .iter()
                .find(|asset| asset.name == format!("detent-{target_triple}"))?;
            let sums = release
                .assets
                .iter()
                .find(|asset| asset.name == "SHA256SUMS")?;
            let bundle_name = format!("detent-{target_triple}.sigstore.json");
            let bundle = release
                .assets
                .iter()
                .find(|asset| asset.name == bundle_name)?;
            let published = release
                .published_at
                .as_deref()
                .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok());
            Some(Release {
                candidate: Candidate {
                    tag: release.tag_name,
                    published,
                    body: release.body,
                },
                binary_url: binary.browser_download_url.clone(),
                bundle_url: bundle.browser_download_url.clone(),
                sums_url: sums.browser_download_url.clone(),
            })
        })
        .collect())
}

/// The hex digest `SHA256SUMS` names for `asset_name`.
///
/// The sums file is one `<hex>  <name>` pair per line (two spaces, the
/// `sha256sum` text format).
///
/// # Errors
///
/// [`FetchError::MissingSum`] when the asset is not named.
pub fn digest_from_sums(sums: &str, asset_name: &str) -> Result<[u8; 32], FetchError> {
    for line in sums.lines() {
        let Some((hex, name)) = line.split_once("  ") else {
            continue;
        };
        let name = name.trim();
        if name != asset_name {
            continue;
        }
        let hex = hex.trim();
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(FetchError::MissingSum(asset_name.to_owned()));
        }
        let mut out = [0_u8; 32];
        for (slot, pair) in out.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            let text = std::str::from_utf8(pair)
                .map_err(|_| FetchError::MissingSum(asset_name.to_owned()))?;
            *slot = u8::from_str_radix(text, 16)
                .map_err(|_| FetchError::MissingSum(asset_name.to_owned()))?;
        }
        return Ok(out);
    }
    Err(FetchError::MissingSum(asset_name.to_owned()))
}

/// The SHA-256 of `bytes`, for the SUMS cross-check (PLAN §2.9 step 4).
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The asset name this build downloads, `detent-<target-triple>`.
#[must_use]
pub fn asset_name() -> String {
    format!("detent-{}", target_triple())
}

/// The target triple this binary was built for.
///
/// Cross-builds (`cargo zigbuild` in the release workflow) set `TARGET`; a
/// plain host build composes the triple from `std`'s constants.
#[must_use]
pub fn target_triple() -> String {
    if let Some(triple) = option_env!("TARGET") {
        return triple.to_owned();
    }
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "macos" => format!("{arch}-apple-darwin"),
        os => {
            let env = if cfg!(target_env = "musl") {
                "musl"
            } else {
                "gnu"
            };
            format!("{arch}-unknown-{os}-{env}")
        }
    }
}

/// The real client: hyper-rustls, TLS 1.3, webpki-roots, one thread.
#[derive(Debug)]
pub struct RealTransport {
    runtime: tokio::runtime::Runtime,
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<hyper::body::Bytes>,
    >,
}

impl RealTransport {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`FetchError::Unreachable`] when the runtime or TLS configuration
    /// cannot be built (refuse-closed: no client, no update).
    pub fn new() -> Result<Self, FetchError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| FetchError::Unreachable {
                url: String::new(),
                reason: format!("runtime: {err}"),
            })?;
        let mut roots = rustls::RootCertStore::empty();
        roots.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| FetchError::Unreachable {
                url: String::new(),
                reason: format!("tls config: {err}"),
            })?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https);
        Ok(Self { runtime, client })
    }
}

impl Transport for RealTransport {
    fn get(&self, url: &str, cap: u64, sink: &mut dyn std::io::Write) -> Result<u64, FetchError> {
        use http_body_util::BodyExt as _;
        self.runtime.block_on(async {
            let request = hyper::Request::builder()
                .method(hyper::Method::GET)
                .uri(url)
                .header(hyper::header::ACCEPT, "application/vnd.github+json")
                .header(hyper::header::USER_AGENT, "detent-update")
                .body(http_body_util::Full::new(hyper::body::Bytes::new()))
                .map_err(|err| FetchError::Unreachable {
                    url: url.to_owned(),
                    reason: format!("request: {err}"),
                })?;
            let response = tokio::time::timeout(GET_TIMEOUT, self.client.request(request))
                .await
                .map_err(|_| FetchError::Unreachable {
                    url: url.to_owned(),
                    reason: "timed out".to_owned(),
                })?
                .map_err(|err| FetchError::Unreachable {
                    url: url.to_owned(),
                    reason: err.to_string(),
                })?;
            if !response.status().is_success() {
                return Err(FetchError::BadStatus {
                    url: url.to_owned(),
                    status: response.status().as_u16(),
                });
            }
            let mut body = response.into_body();
            let mut total: u64 = 0;
            loop {
                let frame = match tokio::time::timeout(GET_TIMEOUT, body.frame()).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => {
                        return Err(FetchError::Unreachable {
                            url: url.to_owned(),
                            reason: "timed out".to_owned(),
                        });
                    }
                };
                let data = frame
                    .map_err(|err| FetchError::Unreachable {
                        url: url.to_owned(),
                        reason: err.to_string(),
                    })?
                    .into_data()
                    .map_err(|_| FetchError::Unreachable {
                        url: url.to_owned(),
                        reason: "stream returned a metadata frame".to_owned(),
                    })?;
                total = total.saturating_add(data.len() as u64);
                if total > cap {
                    return Err(FetchError::TooLarge { cap });
                }
                sink.write_all(&data)
                    .map_err(|err| FetchError::Unreachable {
                        url: url.to_owned(),
                        reason: err.to_string(),
                    })?;
            }
            Ok(total)
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    struct Canned {
        bytes: Vec<u8>,
    }

    impl Transport for Canned {
        fn get(
            &self,
            _url: &str,
            _cap: u64,
            sink: &mut dyn std::io::Write,
        ) -> Result<u64, FetchError> {
            sink.write_all(&self.bytes)
                .map_err(|err| FetchError::BadJson(err.to_string()))?;
            Ok(self.bytes.len() as u64)
        }
    }

    fn releases_doc(triple: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            {
                "tag_name": "v9.9.9",
                "draft": true,
                "prerelease": false,
                "published_at": "2020-01-01T00:00:00Z",
                "body": "",
                "assets": [],
            },
            {
                "tag_name": "v9.9.8",
                "draft": false,
                "prerelease": true,
                "published_at": "2020-01-01T00:00:00Z",
                "body": "",
                "assets": [],
            },
            {
                "tag_name": "v0.0.2",
                "draft": false,
                "prerelease": false,
                "published_at": "2020-01-01T00:00:00Z",
                "body": "notes",
                "assets": [
                    {"name": format!("detent-{triple}"), "browser_download_url": "https://example.invalid/b"},
                    {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/s"},
                    {"name": format!("detent-{triple}.sigstore.json"), "browser_download_url": "https://example.invalid/j"},
                ],
            },
            {
                "tag_name": "v0.0.3",
                "draft": false,
                "prerelease": false,
                "published_at": "2020-01-01T00:00:00Z",
                "body": "",
                "assets": [],
            },
        ]))
        .expect("canned releases")
    }

    #[test]
    fn list_releases_keeps_only_complete_stable_releases() {
        let triple = target_triple();
        let feed = Canned {
            bytes: releases_doc(&triple),
        };
        let releases = list_releases(&feed, &triple).expect("canned feed parses");
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].candidate.tag, "v0.0.2");
        assert_eq!(releases[0].binary_url, "https://example.invalid/b");
        assert_eq!(releases[0].sums_url, "https://example.invalid/s");
        assert_eq!(releases[0].bundle_url, "https://example.invalid/j");
    }

    #[test]
    fn list_releases_rejects_malformed_json() {
        let feed = Canned {
            bytes: b"not json".to_vec(),
        };
        assert!(matches!(
            list_releases(&feed, "x"),
            Err(FetchError::BadJson(_))
        ));
    }

    #[test]
    fn digest_from_sums_parses_sha256sum_lines() {
        let expected = sha256_of(b"binary");
        let hex: String = expected
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .concat();
        let sums = format!("{hex}  detent-x\ndead  other\n");
        assert_eq!(
            digest_from_sums(&sums, "detent-x").expect("named"),
            expected
        );
        assert!(matches!(
            digest_from_sums(&sums, "missing"),
            Err(FetchError::MissingSum(_))
        ));
        assert!(matches!(
            digest_from_sums("zz  detent-x\n", "detent-x"),
            Err(FetchError::MissingSum(_))
        ));
    }

    #[test]
    fn asset_name_tracks_target_triple() {
        assert_eq!(asset_name(), format!("detent-{}", target_triple()));
        assert!(!target_triple().is_empty());
    }
}
