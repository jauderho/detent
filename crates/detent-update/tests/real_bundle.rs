//! The first real release bundle (R1, STAGE3 H17 steps 1 and 8): the
//! `actions/attest` bundle that `release.yml` published for `v0.0.1-rc.2`,
//! verified with the embedded public-good trust root. One attestation names
//! every binary, so the same bundle covers each target; the test uses the
//! `x86_64` musl binary's digest from that release's `SHA256SUMS`.

use detent_update::verify::{VerificationError, verify};

const TAG: &str = "v0.0.1-rc.2";

/// `detent-x86_64-unknown-linux-musl` in the `v0.0.1-rc.2` `SHA256SUMS`.
const BINARY_SHA256: &str = "4a11d1a5b56c1592712e771dd5e49d71c5fca90d77341b0114711fd2e9005f3b";

type R = Result<(), Box<dyn std::error::Error>>;

fn digest() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for pair in BINARY_SHA256.as_bytes().chunks(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes.as_slice().try_into()?)
}

fn check(tag: &str, file_digest: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/real-v0.0.1-rc.2.sigstore.json"),
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
