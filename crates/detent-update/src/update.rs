//! The update flow (PLAN §2.9): check, and the fetch-verify-selftest run
//! that ends at the binary swap.
//!
//! The flow is refuse-closed end to end: any fetch, policy, or verification
//! error aborts with the current binary untouched. After [`prepare`]
//! verifies the candidate, [`confirm_features`] executes its `--self-test`
//! probe and checks the feature set — and only a candidate that passes both
//! reaches [`crate::install::swap`], the atomic rename that keeps
//! `detent.prev`. Step 5's tail — restart, `GET /healthz` within 30 s,
//! roll back on failure — is wired in the CLI via `restart_and_check`
//! and [`crate::install::Installed::rollback`].

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
    /// The staged binary's `--self-test` probe did not run cleanly: it
    /// could not be executed, exited non-zero, or printed no [`FeatureSet`].
    #[error("staged binary failed its self-test: {0}")]
    SelfTest(String),
    /// The staged binary would drop a feature the running build has
    /// (PLAN §2.9 step 5: feature set must be a superset).
    #[error("staged binary would drop features the running build has")]
    FeatureShrink,
    /// The install target is missing, or is not a regular file: the swap
    /// replaces a binary, it never creates one.
    #[error("install target {path} is not a regular file")]
    BadTarget {
        /// The target path, as it was given.
        path: String,
    },
    /// A step of the atomic swap failed; the target still holds the binary
    /// it held before (see [`crate::install::swap`]).
    #[error("binary swap failed at {step}: {reason}")]
    Install {
        /// The step that failed.
        step: &'static str,
        /// The OS reason (no file contents).
        reason: String,
    },
    /// The restarted service did not answer `/healthz` in time, so the swap
    /// must be rolled back (PLAN §2.9 step 5).
    #[error("the restarted service was not healthy within {waited_secs}s: {reason}")]
    Unhealthy {
        /// How long it was given.
        waited_secs: u64,
        /// The last failure seen while polling.
        reason: String,
    },
    /// Nothing qualified, and nothing was installed.
    #[error("no update to install")]
    NoUpdate,
}

/// A verified release, staged and ready for the swap.
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

/// Runs `binary --self-test --json` (step 5's probe) and parses the feature
/// set it reports.
///
/// This *executes* the downloaded binary, so it is only ever called on a
/// candidate [`prepare`] has already verified end-to-end.
///
/// # Errors
///
/// [`UpdateError::SelfTest`] when the binary cannot be executed, exits
/// non-zero, or prints anything but one [`FeatureSet`] JSON document.
pub fn self_test(binary: &std::path::Path) -> Result<FeatureSet, UpdateError> {
    // ponytail: no kill-timeout yet — a candidate whose self-test never
    // exits hangs the update; wait_timeout when that becomes a real report.
    let out = std::process::Command::new(binary)
        .arg("--self-test")
        .arg("--json")
        .output()
        .map_err(|err| UpdateError::SelfTest(err.to_string()))?;
    if !out.status.success() {
        return Err(UpdateError::SelfTest(out.status.to_string()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim()).map_err(|err| UpdateError::SelfTest(err.to_string()))
}

/// Confirms a verified candidate can stand in for the running build (step 5,
/// before the swap): it passes its own self-test, and its feature set covers
/// the running one.
///
/// # Errors
///
/// [`UpdateError::SelfTest`] for a failed probe, [`UpdateError::FeatureShrink`]
/// when the candidate would drop a feature.
pub fn confirm_features(
    binary: &std::path::Path,
    current: &FeatureSet,
) -> Result<FeatureSet, UpdateError> {
    let new = self_test(binary)?;
    if !covers(current, &new) {
        return Err(UpdateError::FeatureShrink);
    }
    Ok(new)
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
/// The caller then runs [`confirm_features`] on
/// [`Candidate::binary_path`] against the running feature set, and only then
/// [`crate::install::swap`].
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
    // `fs::write` creates 0644, and step 5 runs this file: `self_test` spawns
    // it, so without the execute bit the whole flow refuses with EACCES one
    // step before the swap. The staging dir is 0700, so 0755 here is not a
    // window — nobody else can traverse into it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755)).map_err(
            |err| fetch::FetchError::Unreachable {
                url: release.binary_url.clone(),
                reason: format!("staging: {err}"),
            },
        )?;
    }

    Ok(Candidate {
        tag: chosen.tag,
        digest,
        staging,
        binary_path,
    })
}

/// Check cache for §2.9 steps 5a and 6: a dated [`CheckReport`] written and
/// read from disk so stomping requests cannot make this host poll GitHub
/// on every call. The interval is enforced by refusing to rewrite a stamp
/// newer than 24 h unless the caller passes `force`; the request path only
/// fetches fresh when no stamp exists yet.
///
/// Storage: `<state_root>/update/check.json`, atomic write, `0644`-alike via
/// `write_atomic` (read-only state callers must be able to read it). Must
/// not touch the network.
mod cache {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use super::CheckReport;

    /// How long a stamp stays fresh: 24 h (PLAN §2.9 step 6).
    #[allow(clippy::duration_suboptimal_units)]
    pub const CHECK_INTERVAL: Duration = Duration::from_secs(86_400);

    /// Written beside the report so staleness is authoritative. `checked_at`
    /// is stored as a Unix timestamp so the workspace's `time` crate (without
    /// `serde`) can serialize it cheaply.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CachedReport {
        /// When the wrapped [`CheckReport`] was fetched.
        #[serde(with = "ts_seconds")]
        pub checked_at: time::OffsetDateTime,
        /// The report that was fetched.
        pub report: CheckReport,
    }

    mod ts_seconds {
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(value: &time::OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            s.serialize_i64(value.unix_timestamp())
        }

        pub fn deserialize<'de, D>(d: D) -> Result<time::OffsetDateTime, D::Error>
        where
            D: Deserializer<'de>,
        {
            let secs = i64::deserialize(d)?;
            time::OffsetDateTime::from_unix_timestamp(secs).map_err(serde::de::Error::custom)
        }
    }

    /// The on-disk stamp for the interval-guarded check (PLAN §2.9 steps 5a
    /// and 6): `<state_root>/update/check.json`.
    #[must_use]
    pub fn stamp_path(state_root: &Path) -> PathBuf {
        state_root.join("update/check.json")
    }

    /// Read `<stamp>` if it exists and parses, else `None`. A corrupt file
    /// is a miss, not an error — the next successful check overwrites it.
    #[must_use]
    pub fn read_cached(stamp: &Path) -> Option<CachedReport> {
        let raw = std::fs::read(stamp).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Whether `checked_at` is already fresh enough that the next check
    /// should stay quiet unless forced. A `checked_at` in the future (clock
    /// skew) is not fresh — treat it as stale so the next run corrects it.
    #[must_use]
    pub fn is_fresh(checked_at: time::OffsetDateTime, now: time::OffsetDateTime) -> bool {
        #[allow(clippy::arithmetic_side_effects)]
        {
            checked_at <= now && (now - checked_at) < CHECK_INTERVAL
        }
    }

    /// Atomic stamp write: `stamp` is `<state_root>/update/check.json`.
    ///
    /// Enforces the interval — returns `Ok(None)` when `stamp` is fresh and
    /// `force` is false. Otherwise writes and returns `Ok(Some(stamp))`.
    ///
    /// # Errors
    ///
    /// Whatever the filesystem reports when creating the parent directory or
    /// writing the file.
    pub fn write_cached(
        stamp: &Path,
        report: &CheckReport,
        now: time::OffsetDateTime,
        force: bool,
    ) -> Result<Option<CachedReport>, std::io::Error> {
        let cached = CachedReport {
            checked_at: now,
            report: report.clone(),
        };
        #[allow(clippy::collapsible_if)]
        if !force {
            if let Some(existing) = read_cached(stamp) {
                if is_fresh(existing.checked_at, now) {
                    return Ok(None);
                }
            }
        }
        if let Some(parent) = stamp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(&cached)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(stamp, &body)?;
        Ok(Some(cached))
    }

    fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(body)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}

pub use cache::{CHECK_INTERVAL, CachedReport, is_fresh, read_cached, stamp_path, write_cached};

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

    #[test]
    fn cached_report_round_trips_through_the_stamp() {
        let dir = tempfile::TempDir::new().expect("stamp dir");
        let stamp = stamp_path(dir.path());
        let report = check(
            &feed("v0.0.2", ""),
            &semver::Version::new(0, 0, 1),
            &Policy::default(),
            now(),
        )
        .expect("canned report");
        // ponytail: one focused test for round-trip, staleness, corrupt-miss, skew.
        let written = write_cached(&stamp, &report, now(), false)
            .expect("write")
            .expect("fresh write");
        assert_eq!(written.report, report);
        let back = read_cached(&stamp).expect("read");
        assert_eq!(back.report, report);
        assert!(is_fresh(back.checked_at, now()));
        // Stale: past the 24 h window.
        #[allow(clippy::arithmetic_side_effects)]
        let old = now() - std::time::Duration::from_secs(86_401);
        assert!(!is_fresh(old, now()));
        // Clock skew: checked_at in the future is stale, not fresh.
        #[allow(clippy::arithmetic_side_effects)]
        let future = now() + std::time::Duration::from_secs(60);
        assert!(!is_fresh(future, now()));
        // Corrupt file reads as a miss.
        std::fs::write(&stamp, b"not json").expect("corrupt stamp");
        assert!(read_cached(&stamp).is_none());
        // Fresh stamp refuses a rewrite unless forced.
        std::fs::remove_file(&stamp).expect("clear stamp");
        write_cached(&stamp, &report, now(), false).expect("first write");
        assert!(
            write_cached(&stamp, &report, now(), false)
                .expect("guarded")
                .is_none()
        );
        assert!(
            write_cached(&stamp, &report, now(), true)
                .expect("forced")
                .is_some()
        );
    }

    /// Writes an executable `#!/bin/sh` script the probe can run.
    #[cfg(unix)]
    fn probe_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("candidate.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write probe script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod probe script");
        path
    }

    #[cfg(unix)]
    fn stage() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("staging dir")
    }

    #[cfg(unix)]
    #[test]
    fn self_test_parses_the_probe_json() {
        let dir = stage();
        let binary = probe_script(
            dir.path(),
            "echo '{\"version\":\"0.0.2\",\"features\":[\"hosts\",\"update\"]}'",
        );
        let set = self_test(&binary).expect("self-test parses");
        assert_eq!(set.version, "0.0.2");
        assert_eq!(set.features, vec!["hosts".to_owned(), "update".to_owned()]);
    }

    #[cfg(unix)]
    #[test]
    fn self_test_refuses_a_failing_or_silent_probe() {
        let dir = stage();
        let exiting = probe_script(dir.path(), "exit 1");
        assert!(
            matches!(self_test(&exiting), Err(UpdateError::SelfTest(_))),
            "non-zero exit must refuse"
        );
        let silent = probe_script(dir.path(), "echo 'not json'");
        assert!(
            matches!(self_test(&silent), Err(UpdateError::SelfTest(_))),
            "unparsable output must refuse"
        );
        // Not executable: the spawn itself fails, still refuse-closed.
        let dead = dir.path().join("not-executable");
        std::fs::write(&dead, b"#!/bin/sh\n").expect("write dead probe");
        assert!(
            matches!(self_test(&dead), Err(UpdateError::SelfTest(_))),
            "a non-executable candidate must refuse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn confirm_features_gates_on_feature_coverage() {
        let dir = stage();
        let current = FeatureSet {
            version: "0.0.1".to_owned(),
            features: vec!["hosts".to_owned(), "web".to_owned()],
        };
        let superset = probe_script(
            dir.path(),
            "echo '{\"version\":\"0.0.2\",\"features\":[\"hosts\",\"web\",\"update\"]}'",
        );
        assert!(
            confirm_features(&superset, &current).is_ok(),
            "superset admits"
        );
        let shrink = probe_script(
            dir.path(),
            "echo '{\"version\":\"0.0.2\",\"features\":[\"hosts\"]}'",
        );
        assert!(
            matches!(
                confirm_features(&shrink, &current),
                Err(UpdateError::FeatureShrink)
            ),
            "a feature-shrinking candidate must refuse"
        );
    }
}
