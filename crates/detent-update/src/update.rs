//! The update flow (PLAN §2.9): check, and the fetch-verify-selftest run
//! that ends at the (still unwired) binary swap.
//!
//! The flow is refuse-closed end to end: any fetch, policy, or verification
//! error aborts with the current binary untouched. The final step — the
//! privileged swap via the monitor's `ReplaceBinary` — is answered
//! `Unsupported` by this build's monitor, so [`prepare`] stops after a fully
//! verified and self-tested candidate and the caller reports that the swap
//! itself is not implemented yet (steps 5b–5c of §2.9: atomic rename keeping
//! `detent.prev`, restart, `GET /healthz` within 30 s or roll back).

use std::path::PathBuf;

use semver::Version;

use crate::fetch::{self, Transport};
use crate::policy::{self, Policy};
use crate::verify::{self, VerificationError};

/// The result of `detent update --check`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckReport {
    /// Whether a qualifying release exists.
    pub update_available: bool,
    /// The running version, for the report's JSON.
    pub current: String,
    /// The qualifying tag, when one exists.
    pub tag: Option<String>,
    /// When GitHub published it, RFC 3339.
    pub published: Option<String>,
    /// Whether it bypassed the age gate via `detent-security: true`.
    pub security: bool,
}

/// A failure of the whole update flow.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Reaching or reading GitHub failed.
    #[error(transparent)]
    Fetch(#[from] fetch::FetchError),
    /// The release policy refused.
    #[error(transparent)]
    Policy(#[from] policy::PolicyError),
    /// The bundle did not verify (refuse-closed).
    #[error(transparent)]
    Verification(#[from] VerificationError),
    /// The SHA256SUMS digest disagrees with the downloaded bytes.
    #[error("downloaded {asset} does not match SHA256SUMS")]
    SumMismatch {
        /// The asset name checked.
        asset: String,
    },
    /// The bundle failed step-1 parsing (ADR-014's `BundleMalformed`).
    #[error(transparent)]
    Bundle(#[from] crate::bundle::BundleError),
    /// The trust root is unusable (placeholder, or expired at integratedTime).
    #[error("embedded trust root is unusable")]
    TrustRoot,
    /// The release names no matching assets.
    #[error("release {0} does not name the assets this build needs")]
    NoAssets(String),
    /// Nothing qualified, and nothing was installed.
    #[error("no update to install")]
    NoUpdate,
}

/// What `detent update` achieved before the (unwired) privileged swap.
#[derive(Debug)]
pub struct Candidate {
    /// The release tag that was verified.
    pub tag: String,
    /// The verified binary's SHA-256.
    pub digest: [u8; 32],
    /// The directory holding the downloaded binary, bundle and SUMS; removed
    /// when dropped. Sits in the binary's own directory, so a later atomic
    /// rename stays on one filesystem.
    pub staging: tempfile::TempDir,
    /// The staged binary file inside [`Candidate::staging`].
    pub binary_path: PathBuf,
}

/// What `detent --self-test --json` prints (PLAN §2.9 step 5): the version
/// and the compiled feature set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeatureSet {
    /// The binary's own version.
    pub version: String,
    /// Feature identifiers: module ids, plus the major features (`web`,
    /// `acme`, `update`, `mcp`, `crypto-aws-lc`, `crypto-ring`, the init
    /// systems).
    pub features: Vec<String>,
}

/// Whether the new binary's feature set covers the running one (step 5's
/// "checks feature set ⊇ current"). Feature *names* only: the version
/// comparison is the policy's job, done before the download.
#[must_use]
pub fn covers(current: &FeatureSet, new: &FeatureSet) -> bool {
    current
        .features
        .iter()
        .all(|feature| new.features.contains(feature))
}

/// `detent update --check --json` (PLAN §2.9 step 6).
///
/// # Errors
///
/// [`UpdateError`] for fetch and policy failures; a policy refusal means "no
/// update available", not a crash, and is folded into the report.
pub fn check(
    transport: &dyn Transport,
    current: &Version,
    policy: &Policy,
    now: time::OffsetDateTime,
) -> Result<CheckReport, UpdateError> {
    let releases = fetch::list_releases(transport, &fetch::target_triple())?;
    let candidates: Vec<policy::Candidate> = releases
        .iter()
        .map(|release| release.candidate.clone())
        .collect();
    Ok(match policy::select(&candidates, current, now, policy) {
        Ok(chosen) => {
            let security = chosen.body.contains(policy::SECURITY_MARKER);
            CheckReport {
                update_available: true,
                current: current.to_string(),
                tag: Some(chosen.tag),
                published: chosen.published.map(|published| {
                    published
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| published.to_string())
                }),
                security,
            }
        }
        Err(policy::PolicyError::NoUpdate) => CheckReport {
            update_available: false,
            current: current.to_string(),
            tag: None,
            published: None,
            security: false,
        },
        Err(policy::PolicyError::DowngradeRefused {
            candidate,
            current: _,
        }) => CheckReport {
            update_available: false,
            current: current.to_string(),
            tag: Some(candidate),
            published: None,
            security: false,
        },
        Err(policy::PolicyError::TooYoung { tag, .. } | policy::PolicyError::BadTag(tag)) => {
            CheckReport {
                update_available: false,
                current: current.to_string(),
                tag: Some(tag),
                published: None,
                security: false,
            }
        }
    })
}

/// Downloads and fully verifies the release a policy run selected
/// (PLAN §2.9 steps 2–5a): binary + bundle + SHA256SUMS, SUMS cross-check,
/// Sigstore verification, all into a staging directory next to the running
/// binary.
///
/// The caller runs `detent --self-test --json` on
/// [`Candidate::binary_path`] and compares feature sets; the privileged swap
/// (`ReplaceBinary`) is not implemented yet (see the module header).
///
/// # Errors
///
/// [`UpdateError`] for every refusal; nothing is installed on any error.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    transport: &dyn Transport,
    current: &Version,
    policy: &Policy,
    now: time::OffsetDateTime,
    trust: &crate::trust::TrustRoot,
    staging_parent: &std::path::Path,
) -> Result<Candidate, UpdateError> {
    let releases = fetch::list_releases(transport, &fetch::target_triple())?;
    let candidates: Vec<policy::Candidate> = releases
        .iter()
        .map(|release| release.candidate.clone())
        .collect();
    let chosen =
        policy::select(&candidates, current, now, policy).map_err(|_| UpdateError::NoUpdate)?;
    let release = releases
        .iter()
        .find(|release| release.candidate.tag == chosen.tag)
        .ok_or_else(|| UpdateError::NoAssets(chosen.tag.clone()))?;

    let asset = fetch::asset_name();
    let staging =
        tempfile::TempDir::with_prefix_in("detent-update-", staging_parent).map_err(|err| {
            fetch::FetchError::Unreachable {
                url: String::new(),
                reason: format!("staging dir: {err}"),
            }
        })?;

    // SHA256SUMS first: it is what the binary bytes are checked against.
    let mut sums_bytes = Vec::new();
    transport.get(
        &release.sums_url,
        fetch::MAX_RELEASES_BYTES,
        &mut sums_bytes,
    )?;
    let sums_text =
        std::str::from_utf8(&sums_bytes).map_err(|_| UpdateError::NoAssets(chosen.tag.clone()))?;
    let expected = fetch::digest_from_sums(sums_text, &asset)?;

    let mut binary_bytes = Vec::new();
    transport.get(
        &release.binary_url,
        fetch::MAX_BINARY_BYTES,
        &mut binary_bytes,
    )?;
    let digest = fetch::sha256_of(&binary_bytes);
    if digest != expected {
        return Err(UpdateError::SumMismatch { asset });
    }

    let mut bundle_bytes = Vec::new();
    transport.get(
        &release.bundle_url,
        crate::bundle::MAX_BUNDLE_BYTES as u64,
        &mut bundle_bytes,
    )?;
    let decoded = crate::bundle::parse(&bundle_bytes)?;
    verify::verify(&decoded, &digest, &chosen.tag, trust)?;

    let binary_path = staging.path().join(&asset);
    std::fs::write(&binary_path, &binary_bytes).map_err(|err| fetch::FetchError::Unreachable {
        url: release.binary_url.clone(),
        reason: format!("staging: {err}"),
    })?;

    Ok(Candidate {
        tag: chosen.tag,
        digest,
        staging,
        binary_path,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Canned {
        bytes: Vec<u8>,
    }

    impl crate::fetch::Transport for Canned {
        fn get(
            &self,
            _url: &str,
            _cap: u64,
            sink: &mut dyn std::io::Write,
        ) -> Result<u64, crate::fetch::FetchError> {
            sink.write_all(&self.bytes)
                .map_err(|err| crate::fetch::FetchError::BadJson(err.to_string()))?;
            Ok(self.bytes.len() as u64)
        }
    }

    fn feed(tag: &str, body: &str) -> Canned {
        let triple = crate::fetch::target_triple();
        let doc = serde_json::json!([{
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "published_at": "2020-01-01T00:00:00Z",
            "body": body,
            "assets": [
                {"name": format!("detent-{triple}"), "browser_download_url": "https://example.invalid/b"},
                {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/s"},
                {"name": format!("detent-{triple}.sigstore.json"), "browser_download_url": "https://example.invalid/j"},
            ],
        }]);
        Canned {
            bytes: serde_json::to_vec(&doc).expect("canned feed"),
        }
    }

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_786_780_800).expect("fixed timestamp")
    }

    #[test]
    fn covers_requires_every_current_feature() {
        let current = FeatureSet {
            version: "0.0.1".to_owned(),
            features: vec!["hosts".to_owned(), "web".to_owned()],
        };
        let superset = FeatureSet {
            version: "0.0.2".to_owned(),
            features: vec!["hosts".to_owned(), "web".to_owned(), "acme".to_owned()],
        };
        let subset = FeatureSet {
            version: "0.0.2".to_owned(),
            features: vec!["hosts".to_owned()],
        };
        assert!(covers(&current, &superset));
        assert!(!covers(&current, &subset));
    }

    #[test]
    fn check_maps_policy_outcomes_to_reports() {
        let current = semver::Version::new(0, 0, 1);
        let policy = Policy::default();
        let report = check(&feed("v0.0.2", ""), &current, &policy, now()).expect("newer");
        assert!(report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.0.2"));
        assert!(!report.security);
        let report = check(
            &feed("v0.0.2", "detent-security: true"),
            &current,
            &policy,
            now(),
        )
        .expect("security");
        assert!(report.update_available);
        assert!(report.security);
        let report =
            check(&feed("v0.0.0", ""), &current, &policy, now()).expect("downgrade refused");
        assert!(!report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.0.0"));
        let report = check(
            &feed("v0.0.2", ""),
            &current,
            &Policy {
                min_age_days: 10_000,
                ..policy
            },
            now(),
        )
        .expect("too young");
        assert!(!report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.0.2"));
    }

    #[test]
    fn check_propagates_transport_failures() {
        struct Failing;
        impl crate::fetch::Transport for Failing {
            fn get(
                &self,
                url: &str,
                _cap: u64,
                _sink: &mut dyn std::io::Write,
            ) -> Result<u64, crate::fetch::FetchError> {
                Err(crate::fetch::FetchError::Unreachable {
                    url: url.to_owned(),
                    reason: "offline".to_owned(),
                })
            }
        }
        let current = semver::Version::new(0, 0, 1);
        assert!(matches!(
            check(&Failing, &current, &Policy::default(), now()),
            Err(UpdateError::Fetch(_))
        ));
    }
}
