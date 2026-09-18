//! Fixture verification: every ADR-014 test vector, exercised through the
//! real six-step verifier.
//!
//! The fixtures are synthetic-but-shaped bundles minted by
//! `gen-fixtures` (`cargo run -p detent-update --features fixture-gen --bin
//! gen-fixtures`). When the first real `v0.0.1-rc` release bundle is captured
//! (PLAN Phase 9 task 3), these files are replaced with the captured
//! bundles; this test then asserts against the real material without
//! changes - the expectations below encode the ADR-014 table, not the
//! synthetic keys.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use detent_update::trust::TrustRoot;
use detent_update::verify::{VerificationError, pinned_identity, verify};
use sha2::Digest as _;
use sha2::Sha256;

const FIXTURE_TAG: &str = "v0.0.2";

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn trust() -> TrustRoot {
    let root = std::fs::read_to_string(fixtures().join("fulcio-root.pem"))
        .expect("fulcio-root.pem fixture");
    let rekor =
        std::fs::read_to_string(fixtures().join("rekor-pub.pem")).expect("rekor-pub.pem fixture");
    detent_update::trust::from_pems(&root, &rekor).expect("fixture trust root")
}

/// Verifies `fixture` against `binary.bin`'s digest.
fn run(name: &str) -> Result<(), VerificationError> {
    let bytes = std::fs::read(fixtures().join(name)).expect("fixture");
    let decoded = detent_update::bundle::parse(&bytes)?;
    let digest: [u8; 32] =
        Sha256::digest(std::fs::read(fixtures().join("binary.bin")).expect("binary")).into();
    verify(&decoded, &digest, FIXTURE_TAG, &trust())
}

#[test]
fn valid_bundle_passes_all_six_steps() {
    run("valid.json").expect("valid fixture must verify");
}

#[test]
fn a_bundle_with_no_covering_root_is_unavailable_not_invalid() {
    // trust gap: every embedded root's window misses integratedTime (a
    // rotation gap), so verification stops before the chain is attempted.
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let decoded = detent_update::bundle::parse(&raw).unwrap();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    let covered = trust();
    let far_future = decoded.integrated_time + 4_000_000_000;
    let trust = TrustRoot {
        root_windows: vec![(far_future, far_future + 1); covered.root_windows.len()],
        ..covered
    };
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust),
        Err(VerificationError::TrustRootUnavailable)
    );
}

#[test]
fn an_empty_chain_is_invalid_not_unavailable() {
    // empty chain: roots cover the instant, but the bundle carries no
    // certificates at all.
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let mut decoded = detent_update::bundle::parse(&raw).unwrap();
    decoded.certs.clear();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust()),
        Err(VerificationError::CertChainInvalid)
    );
}

#[test]
fn wrong_identity_is_refused_at_step_3() {
    let error = run("wrong-identity.json").expect_err("wrong identity must be refused");
    assert!(
        matches!(error, VerificationError::IdentityMismatch),
        "{error:?}"
    );
}

#[test]
fn expired_leaf_is_refused_at_step_2() {
    let error = run("expired-leaf.json").expect_err("expired leaf must be refused");
    assert!(matches!(error, VerificationError::CertExpired), "{error:?}");
}

#[test]
fn corrupted_dsse_signature_is_refused_at_step_4() {
    let error = run("bad-signature.json").expect_err("corrupt DSSE sig must be refused");
    assert!(
        matches!(error, VerificationError::SignatureInvalid),
        "{error:?}"
    );
}

#[test]
fn corrupted_inclusion_path_is_refused_at_step_6() {
    let error = run("bad-set.json").expect_err("corrupt inclusion path must be refused");
    assert!(matches!(error, VerificationError::SetInvalid), "{error:?}");
}

#[test]
fn corrupted_checkpoint_signature_is_refused_at_step_6() {
    let error = run("bad-sct.json").expect_err("corrupt checkpoint sig must be refused");
    assert!(matches!(error, VerificationError::SetInvalid), "{error:?}");
}

#[test]
fn a_bundle_for_another_tag_is_refused() {
    // The pinned identity is per-tag: the same valid bundle pinned to a
    // different tag fails step 3.
    let bytes = std::fs::read(fixtures().join("valid.json")).expect("fixture");
    let decoded = detent_update::bundle::parse(&bytes).expect("valid");
    let digest: [u8; 32] =
        Sha256::digest(std::fs::read(fixtures().join("binary.bin")).expect("binary")).into();
    let error = verify(&decoded, &digest, "v0.0.9", &trust()).expect_err("other tag refused");
    assert!(
        matches!(error, VerificationError::IdentityMismatch),
        "{error:?}"
    );
}

#[test]
fn the_pinned_identity_matches_the_fixture_tag() {
    assert_eq!(
        pinned_identity(FIXTURE_TAG),
        "https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/v0.0.2"
    );
}
