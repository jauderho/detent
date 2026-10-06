//! Real release bundles, verified with the embedded public-good trust root.
//!
//! * `v0.0.1-rc.2` (R1, STAGE3 H17 steps 1 and 8): the Rekor v1
//!   `actions/attest` bundle. One attestation names every binary.
//! * `v0.1.1`: the first production Rekor v2 bundle (cosign, `log2025-1`,
//!   RFC 3161 timestamp from `timestamp.sigstore.dev`), one per binary.
//!
//! Each test uses the `x86_64` musl binary's digest from that release's
//! `SHA256SUMS`.

use detent_update::verify::{VerificationError, verify};

const TAG: &str = "v0.0.1-rc.2";

/// `detent-x86_64-unknown-linux-musl` in the `v0.0.1-rc.2` `SHA256SUMS`.
const BINARY_SHA256: &str = "4a11d1a5b56c1592712e771dd5e49d71c5fca90d77341b0114711fd2e9005f3b";

const V2_TAG: &str = "v0.1.1";

/// `detent-x86_64-unknown-linux-musl` in the `v0.1.1` `SHA256SUMS`.
const V2_BINARY_SHA256: &str = "e9de9f265aac0e1fc69042054112cfe170555f635165e630df67c0f328b32ae9";

type R = Result<(), Box<dyn std::error::Error>>;

fn digest() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    hex_digest(BINARY_SHA256)
}

fn hex_digest(hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for pair in hex.as_bytes().chunks(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes.as_slice().try_into()?)
}

fn check(tag: &str, file_digest: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    check_fixture("real-v0.0.1-rc.2.sigstore.json", tag, file_digest)
}

fn check_fixture(
    fixture: &str,
    tag: &str,
    file_digest: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
    )?;
    let decoded = detent_update::bundle::parse(&bytes)?;
    let trust = detent_update::trust::embedded()?;
    Ok(verify(&decoded, file_digest, tag, &trust)?)
}

#[test]
fn real_attest_bundle_verifies() -> R {
    check(TAG, &digest()?)
}

#[test]
fn real_attest_bundle_is_refused_for_another_tag() -> R {
    let error = check("v0.1.0", &digest()?)
        .err()
        .ok_or("another tag verified")?;
    assert!(
        matches!(
            error.downcast_ref::<VerificationError>(),
            Some(VerificationError::IdentityMismatch)
        ),
        "{error}"
    );
    Ok(())
}

#[test]
fn real_attest_bundle_is_refused_for_another_binary() -> R {
    let mut other = digest()?;
    let first = other.first_mut().ok_or("empty digest")?;
    *first ^= 1;
    let error = check(TAG, &other).err().ok_or("another binary verified")?;
    assert!(
        matches!(
            error.downcast_ref::<VerificationError>(),
            Some(VerificationError::DigestMismatch)
        ),
        "{error}"
    );
    Ok(())
}

/// The error `check_fixture` gave, as a [`VerificationError`].
fn refusal(
    result: Result<(), Box<dyn std::error::Error>>,
) -> Result<VerificationError, Box<dyn std::error::Error>> {
    let error = result.err().ok_or("the bundle verified")?;
    match error.downcast::<VerificationError>() {
        Ok(error) => Ok(*error),
        Err(other) => Err(other),
    }
}

#[test]
fn real_rekor_v2_bundle_verifies() -> R {
    let bundle = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/real-v0.1.1.sigstore.json"),
    )?;
    assert!(detent_update::bundle::parse(&bundle)?.is_rekor_v2());
    check_fixture(
        "real-v0.1.1.sigstore.json",
        V2_TAG,
        &hex_digest(V2_BINARY_SHA256)?,
    )
}

#[test]
fn real_rekor_v2_bundle_is_refused_for_another_tag() -> R {
    let error = refusal(check_fixture(
        "real-v0.1.1.sigstore.json",
        "v0.1.0",
        &hex_digest(V2_BINARY_SHA256)?,
    ))?;
    assert_eq!(error, VerificationError::IdentityMismatch);
    Ok(())
}

#[test]
fn real_rekor_v2_bundle_is_refused_for_another_binary() -> R {
    let mut other = hex_digest(V2_BINARY_SHA256)?;
    let first = other.first_mut().ok_or("empty digest")?;
    *first ^= 1;
    let error = refusal(check_fixture("real-v0.1.1.sigstore.json", V2_TAG, &other))?;
    assert_eq!(error, VerificationError::DigestMismatch);
    Ok(())
}
