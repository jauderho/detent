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

// This file mints and then deliberately mangles DER: raw indexing, two-byte
// length arithmetic, and `usize as u8` length bytes are the job, not an
// oversight. Every input is a fixture this crate generated, so an out-of-range
// index or a truncating cast means the fixture is malformed — and panicking
// there *is* the assertion. Guarding each site would convert a loud fixture
// bug into a confusing verification failure several steps later.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::path::Path;

use detent_update::trust::TrustRoot;
use detent_update::verify::{VerificationError, pinned_identity, verify};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
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

/// (header length, content length) of the DER element at `at`.
///
/// Indexes and adds without guards on purpose: the only input is a fixture
/// this test file minted itself, so an out-of-range index means the fixture
/// is malformed and the panic *is* the assertion. A `None` here would be
/// silently swallowed into a confusing verification failure three steps later.
fn der_element(bytes: &[u8], at: usize) -> (usize, usize) {
    let first = bytes[at + 1];
    if first & 0x80 == 0 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        let len = bytes[at + 2..at + 2 + count]
            .iter()
            .fold(0, |len, byte| (len << 8) | usize::from(*byte));
        (2 + count, len)
    }
}

/// Rewrites `leaf`'s Fulcio OIDC-issuer extension to a wrong issuer and
/// re-signs the TBS with the fixture root's fixed key (gen-fixtures'
/// `01 02 … 20`), so step 2 (chain) still passes and step 3 is what refuses.
/// The issuer URL is 43 bytes both before and after, so every DER length
/// except the BIT STRING and outer SEQUENCE stays untouched.
/// Indexes and adds unguarded for the same reason as [`der_element`]: the
/// leaf is a fixture minted by this crate, and a bad offset must fail loudly
/// here rather than produce a subtly wrong certificate.
fn leaf_with_wrong_oidc_issuer(leaf: &[u8]) -> Vec<u8> {
    // The extension content is the raw issuer URL, present verbatim in the
    // signed TBS; the SAN URI never contains "githubusercontent".
    const ISSUER_URL: &[u8] = b"https://token.actions.githubusercontent.com";
    const WRONG_URL: &[u8] = b"https://token.actions.gitlabusercontent.com";

    assert_eq!(leaf[0], 0x30, "outer SEQUENCE");
    assert_eq!(leaf[1], 0x82, "long-form outer length");
    let (tbs_header, tbs_len) = der_element(leaf, 4);
    let tbs = &leaf[4..4 + tbs_header + tbs_len];

    let at = tbs
        .windows(ISSUER_URL.len())
        .position(|window| window == ISSUER_URL)
        .expect("OIDC issuer extension in TBS");
    let mut tbs_patched = tbs.to_vec();
    tbs_patched[at..at + ISSUER_URL.len()].copy_from_slice(WRONG_URL);

    let root_key =
        SigningKey::from_slice(&std::array::from_fn::<u8, 32, _>(|i: usize| (i + 1) as u8))
            .expect("fixture root key");
    let sig_der = <SigningKey as Signer<p256::ecdsa::Signature>>::sign(&root_key, &tbs_patched)
        .to_der()
        .as_bytes()
        .to_vec();

    // Splice the new signature into the BIT STRING and fix the enclosing
    // lengths. TBS and sig-alg spans are byte-identical in length.
    let tbs_end = 4 + tbs_header + tbs_len;
    let (sigalg_header, sigalg_len) = der_element(leaf, tbs_end);
    let bitstring_at = tbs_end + sigalg_header + sigalg_len;
    assert_eq!(leaf[bitstring_at], 0x03, "signature BIT STRING");
    let mut out = Vec::with_capacity(bitstring_at + 3 + sig_der.len());
    out.extend_from_slice(&leaf[..4]);
    out.extend_from_slice(&tbs_patched);
    out.extend_from_slice(&leaf[tbs_end..bitstring_at]);
    out.push(0x03);
    out.push(u8::try_from(1 + sig_der.len()).expect("short-form BIT STRING length"));
    out.push(0x00); // unused bits
    out.extend_from_slice(&sig_der);
    let outer_len = out.len() - 4;
    out[2] = (outer_len >> 8) as u8;
    out[3] = outer_len as u8;
    out
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
    let error = run("bad-inclusion-path.json").expect_err("corrupt inclusion path must be refused");
    assert!(matches!(error, VerificationError::SetInvalid), "{error:?}");
}

#[test]
fn a_bad_set_is_refused() {
    // The Rekor SET is a well-formed ECDSA signature over the right payload,
    // but by a key other than the embedded Rekor key. The inclusion proof,
    // checkpoint and body are valid, so only the SET check can refuse it.
    assert_eq!(run("bad-set.json"), Err(VerificationError::SetInvalid));
}

#[test]
fn corrupted_checkpoint_signature_is_refused_at_step_6() {
    let error = run("bad-checkpoint-sig.json").expect_err("corrupt checkpoint sig must be refused");
    assert!(matches!(error, VerificationError::SetInvalid), "{error:?}");
}

#[test]
fn a_body_with_another_signature_is_refused_at_step_6() {
    // The tlog body carries a signature other than the envelope's; the
    // inclusion proof and checkpoint are valid over that body, so only the
    // body-agreement check can refuse it.
    assert_eq!(run("bad-body-sig.json"), Err(VerificationError::SetInvalid));
}

#[test]
fn a_body_naming_another_key_is_refused_at_step_6() {
    // As above, but the body names a public key other than the leaf's.
    assert_eq!(run("bad-body-key.json"), Err(VerificationError::SetInvalid));
}

#[test]
fn a_wrong_subject_digest_is_refused() {
    // A consistent, validly signed bundle whose statement attests another
    // file: step 5 refuses it against binary.bin's digest.
    assert_eq!(
        run("wrong-digest.json"),
        Err(VerificationError::DigestMismatch)
    );
}

#[test]
fn a_forged_integrated_time_is_refused() {
    // integratedTime moved by one minute, still inside the leaf's validity
    // window, so step 2 passes. The Merkle leaf covers the body only, so the
    // inclusion proof and checkpoint still verify; only the Rekor SET
    // (inclusionPromise) signs integratedTime, and the SET check refuses.
    let raw = std::fs::read(fixtures().join("valid.json")).expect("fixture");
    let mut bundle: serde_json::Value = serde_json::from_slice(&raw).expect("fixture json");
    let time = bundle
        .pointer_mut("/verificationMaterial/tlogEntries/0/integratedTime")
        .expect("integratedTime");
    *time = serde_json::json!(time.as_i64().expect("integer") + 60);
    let decoded = detent_update::bundle::parse(&serde_json::to_vec(&bundle).expect("json"))
        .expect("forged bundle still parses");
    let digest: [u8; 32] =
        Sha256::digest(std::fs::read(fixtures().join("binary.bin")).expect("binary")).into();
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust()),
        Err(VerificationError::SetInvalid)
    );
}

#[test]
fn a_subject_digest_that_misses_the_file_is_refused_at_step_5() {
    // No subject carries the downloaded file's digest. The DSSE payload is
    // untouched (step 4 still passes); only the parsed statement is mutated.
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let mut decoded = detent_update::bundle::parse(&raw).unwrap();
    decoded.statement.subject[0].digest.sha256 = "00".repeat(32);
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust()),
        Err(VerificationError::DigestMismatch)
    );
}

#[test]
fn an_empty_inclusion_path_is_refused_at_step_6() {
    // A tlog entry stripped of its inclusion-proof hashes: the Merkle
    // recompute has no path to walk. Distinct from bad-inclusion-path.json,
    // where the path is present but one hash is corrupted.
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let mut decoded = detent_update::bundle::parse(&raw).unwrap();
    decoded.path_hashes.clear();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust()),
        Err(VerificationError::SetInvalid)
    );
}

#[test]
fn a_trust_root_with_no_roots_at_all_is_unavailable() {
    // Placeholder trust files: no embedded roots at all, so verification
    // stops before the chain is attempted (same refusal as the rotation gap
    // covered by a_bundle_with_no_covering_root_is_unavailable_not_invalid).
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let decoded = detent_update::bundle::parse(&raw).unwrap();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    let trust = TrustRoot {
        fulcio_roots: Vec::new(),
        root_windows: Vec::new(),
        ..trust()
    };
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust),
        Err(VerificationError::TrustRootUnavailable)
    );
}

#[test]
fn a_leaf_with_a_wrong_oidc_issuer_is_refused_at_step_3() {
    // The Fulcio OIDC-issuer extension names a different issuer. Plain byte
    // patching would break the TBS signature and fail at step 2, so the TBS
    // is re-signed with the fixture root's fixed key (see
    // leaf_with_wrong_oidc_issuer); step 3 (issuer, after identity) refuses.
    let dir = fixtures();
    let raw = std::fs::read(dir.join("valid.json")).unwrap();
    let mut decoded = detent_update::bundle::parse(&raw).unwrap();
    decoded.certs[0] = leaf_with_wrong_oidc_issuer(&decoded.certs[0]);
    let digest: [u8; 32] = Sha256::digest(std::fs::read(dir.join("binary.bin")).unwrap()).into();
    assert_eq!(
        verify(&decoded, &digest, FIXTURE_TAG, &trust()),
        Err(VerificationError::IssuerMismatch)
    );
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
