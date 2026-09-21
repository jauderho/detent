//! The staged binary must be executable.
//!
//! PLAN §2.9 step 5 runs the candidate (`--self-test`) before swapping it in.
//! `prepare` writes it with `std::fs::write`, which creates `0644`, so without
//! an explicit chmod the real flow refuses with `EACCES` one step before the
//! swap — while every hermetic test still passes, because they inject the
//! probe through a seam and never exec what `prepare` actually wrote.
//!
//! This test drives the real `prepare` end to end against the ADR-014 fixture
//! bundle and asserts the mode, so the gap cannot reopen.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use detent_update::fetch::{FetchError, Transport};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Serves the one release the fixture bundle attests, so `prepare` runs its
/// whole verify path rather than a stub.
struct FixtureFeed {
    binary: Vec<u8>,
}

impl Transport for FixtureFeed {
    fn get(&self, url: &str, _cap: u64, sink: &mut dyn std::io::Write) -> Result<u64, FetchError> {
        let bad = |reason: String| FetchError::BadJson(reason);
        let asset = detent_update::fetch::asset_name();
        let bytes = if url == detent_update::fetch::RELEASES_URL {
            serde_json::to_vec(&serde_json::json!([{
                "tag_name": "v0.0.2",
                "draft": false,
                "prerelease": false,
                "published_at": "2020-01-01T00:00:00Z",
                "body": "",
                "assets": [
                    {"name": asset, "browser_download_url": "https://example.invalid/b"},
                    {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/s"},
                    {"name": format!("{asset}.sigstore.json"), "browser_download_url": "https://example.invalid/j"},
                ],
            }]))
            .map_err(|err| bad(err.to_string()))?
        } else if url.ends_with("/s") {
            let mut hex = String::with_capacity(64);
            for byte in detent_update::fetch::sha256_of(&self.binary) {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
            }
            format!("{hex}  {asset}\n").into_bytes()
        } else if url.ends_with("/b") {
            self.binary.clone()
        } else if url.ends_with("/j") {
            std::fs::read(fixtures().join("valid.json")).map_err(|err| bad(err.to_string()))?
        } else {
            return Err(bad(format!("unexpected url {url}")));
        };
        sink.write_all(&bytes).map_err(|err| bad(err.to_string()))?;
        Ok(bytes.len() as u64)
    }
}

#[test]
fn prepare_stages_an_executable_binary() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::fs::read_to_string(fixtures().join("fulcio-root.pem"))?;
    let rekor = std::fs::read_to_string(fixtures().join("rekor-pub.pem"))?;
    let trust = detent_update::trust::from_pems(&root, &rekor)?;
    let feed = FixtureFeed {
        binary: std::fs::read(fixtures().join("binary.bin"))?,
    };
    let staging_parent = tempfile::tempdir()?;

    let candidate = detent_update::update::prepare(
        &feed,
        &semver::Version::new(0, 0, 1),
        &detent_update::Policy::default(),
        time::OffsetDateTime::parse(
            "2026-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )?,
        &trust,
        staging_parent.path(),
        &[],
    )?;

    let mode = std::fs::metadata(&candidate.binary_path)?
        .permissions()
        .mode();
    assert_ne!(
        mode & 0o111,
        0,
        "the staged binary is not executable (mode {mode:o}); step 5 spawns it, \
         so `--self-test` would fail with EACCES before the swap is ever reached"
    );
    // Owner-only writable: the staging dir is the operator's, and a
    // group/world-writable binary about to be renamed over the live one would
    // be a swap window.
    assert_eq!(
        mode & 0o022,
        0,
        "the staged binary is writable by others (mode {mode:o})"
    );
    Ok(())
}
