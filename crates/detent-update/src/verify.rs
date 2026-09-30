//! The six ordered verification steps of ADR-014, and the error taxonomy.
//!
//! The verifier performs zero I/O and never touches the system CA store: a
//! bundle either verifies fully offline against [`crate::trust`] or the update
//! is refused. Refuse-closed: every [`VerificationError`] aborts the update;
//! there is no weaker retry.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest as _, Sha256};
use webpki::EndEntityCert;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer as _, GeneralName};

use crate::bundle::{self, Decoded};
use crate::trust::TrustRoot;

/// The GitHub Actions OIDC issuer every leaf must carry (ADR-005).
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// OID of the deprecated Fulcio OIDC-issuer certificate extension, dotted.
const ISSUER_OID: &str = "1.3.6.1.4.1.57264.1.1";
/// OID of the current DER-encoded Fulcio issuer extension.
const ISSUER_V2_OID: &str = "1.3.6.1.4.1.57264.1.8";
/// OID of the current Fulcio build-signer URI extension.
const BUILD_SIGNER_URI_OID: &str = "1.3.6.1.4.1.57264.1.9";
/// RFC 6962 certificate-transparency signed-certificate-timestamp list.
const SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// The pinned build identity for `tag` (ADR-005): the release workflow, at
/// the exact tag being installed.
#[must_use]
pub fn pinned_identity(tag: &str) -> String {
    format!("https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/{tag}")
}

/// Why verification refused. Refuse-closed: every variant aborts the update.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum VerificationError {
    /// Step 1: unparsable, oversized, or missing required material.
    #[error("bundle is malformed: {0}")]
    BundleMalformed(#[from] bundle::BundleError),
    /// Step 2: trust material could not be loaded or is unavailable.
    #[error("embedded trust material is unavailable")]
    TrustRootUnavailable,
    /// Step 2: the chain does not verify to an embedded Fulcio root.
    #[error("certificate chain does not verify to the embedded Fulcio roots")]
    CertChainInvalid,
    /// Step 2: the leaf is invalid at `integratedTime`.
    #[error("leaf certificate is not valid at the bundle's integratedTime")]
    CertExpired,
    /// Step 3: the leaf's URI SAN is not the pinned workflow identity.
    #[error("certificate identity does not match the pinned workflow")]
    IdentityMismatch,
    /// Step 3: the OIDC issuer extension is missing or wrong.
    #[error("certificate issuer extension does not name the GitHub Actions OIDC issuer")]
    IssuerMismatch,
    /// Step 4: the DSSE signature does not verify against the leaf key.
    #[error("DSSE signature does not verify")]
    SignatureInvalid,
    /// Step 5: no unambiguous subject matches the file digest.
    #[error("statement subject digest does not match the downloaded file (or is ambiguous)")]
    DigestMismatch,
    /// Step 6: the Rekor inclusion proof, checkpoint, or tlog body fails.
    #[error("Rekor inclusion proof or checkpoint does not verify")]
    SetInvalid,
    /// The signing certificate has no parseable embedded SCT list.
    #[error("signing certificate has no valid embedded SCT list")]
    SctInvalid,
    /// Step 6: the Rekor entry kind is not `hashedrekord` or `dsse`.
    #[error("Rekor entry kind is not supported by the verifier")]
    UnsupportedEntryKind,
}

/// Verifies a parsed bundle end-to-end (ADR-014 steps 2–6; step 1 is
/// [`bundle::parse`]).
///
/// `file_digest` is the SHA-256 of the downloaded binary; `tag` is the exact
/// release tag being installed.
///
/// # Errors
///
/// The first failing step's [`VerificationError`]; no partial state.
#[allow(clippy::too_many_lines)]
pub fn verify(
    decoded: &Decoded,
    file_digest: &[u8; 32],
    tag: &str,
    trust: &TrustRoot,
) -> Result<(), VerificationError> {
    // Step 2: certificate chain to the embedded Fulcio roots, at
    // integratedTime, using only roots whose own window covers that instant.
    let usable_roots: Vec<CertificateDer<'_>> = trust
        .fulcio_roots
        .iter()
        .zip(&trust.root_windows)
        .filter(|(_, window)| crate::trust::window_covers(**window, decoded.integrated_time))
        .map(|(root, _)| CertificateDer::from(root.as_ref()))
        .collect();
    if usable_roots.is_empty() {
        return Err(VerificationError::TrustRootUnavailable);
    }
    let anchors: Vec<rustls_pki_types::TrustAnchor<'_>> = usable_roots
        .iter()
        .map(|root| webpki::anchor_from_trusted_cert(root))
        .collect::<Result<_, _>>()
        .map_err(|_| VerificationError::CertChainInvalid)?;

    let Some((leaf_raw, intermediate_raws)) = decoded.certs.split_first() else {
        return Err(VerificationError::CertChainInvalid);
    };
    let leaf_der = CertificateDer::from(leaf_raw.as_slice());
    let intermediates: Vec<CertificateDer<'_>> = intermediate_raws
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let leaf =
        EndEntityCert::try_from(&leaf_der).map_err(|_| VerificationError::CertChainInvalid)?;
    let integrated = UnixTime::since_unix_epoch(Duration::from_secs(
        decoded.integrated_time.max(0).cast_unsigned(),
    ));
    leaf.verify_for_usage(
        &[webpki::aws_lc_rs::ECDSA_P256_SHA256],
        &anchors,
        &intermediates,
        integrated,
        &PermissiveEku,
        None,
        None,
    )
    .map_err(|error| match error {
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            VerificationError::CertExpired
        }
        _ => VerificationError::CertChainInvalid,
    })?;

    // Step 3: identity pinning, on the parsed leaf. New Fulcio certificates
    // carry the workflow URI in the build-signer extension; older fixtures
    // carry it as a URI SAN, so accept either while pinning the exact tag.
    let (_, parsed_leaf) =
        X509Certificate::from_der(leaf_raw).map_err(|_| VerificationError::CertChainInvalid)?;
    let san = parsed_leaf
        .subject_alternative_name()
        .map_err(|_| VerificationError::CertChainInvalid)?;
    let pinned = pinned_identity(tag);
    let san_matches = san.is_some_and(|extension| {
        extension
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::URI(uri) if *uri == pinned))
    });
    let extension_uri = |oid: &str| {
        parsed_leaf.extensions().iter().any(|extension| {
            extension.oid.to_id_string() == oid && extension.value == pinned.as_bytes()
        })
    };
    if !san_matches && !extension_uri(BUILD_SIGNER_URI_OID) {
        return Err(VerificationError::IdentityMismatch);
    }
    let modern_issuer = parsed_leaf.extensions().iter().any(|extension| {
        let Some(value) = extension.value.strip_prefix(&[0x0c]) else {
            return false;
        };
        let Some(length) = value.first().copied() else {
            return false;
        };
        let value = value.get(1..).unwrap_or_default();
        usize::from(length) == value.len()
            && value == ISSUER.as_bytes()
            && extension.oid.to_id_string() == ISSUER_V2_OID
    });
    let legacy_issuer = parsed_leaf.extensions().iter().any(|extension| {
        extension.oid.to_id_string() == ISSUER_OID && extension.value == ISSUER.as_bytes()
    });
    if !modern_issuer && !legacy_issuer {
        return Err(VerificationError::IssuerMismatch);
    }
    if modern_issuer && !has_embedded_sct(&parsed_leaf) {
        return Err(VerificationError::SctInvalid);
    }

    // Step 4: DSSE signature, ECDSA P-256 over the PAE, with the leaf's key.
    let leaf_key =
        VerifyingKey::from_sec1_bytes(parsed_leaf.public_key().subject_public_key.data.as_ref())
            .map_err(|_| VerificationError::CertChainInvalid)?;
    let pae = dsse_pae(decoded.dsse_payload_type.as_bytes(), &decoded.dsse_payload);
    let signature = Signature::from_der(&decoded.dsse_signature)
        .map_err(|_| VerificationError::SignatureInvalid)?;
    leaf_key
        .verify(&pae, &signature)
        .map_err(|_| VerificationError::SignatureInvalid)?;

    // Step 5: exactly one subject carries the downloaded file's digest.
    let file_hex = hex_lower(file_digest);
    let matching = decoded
        .statement
        .subject
        .iter()
        .filter(|subject| subject.digest.sha256 == file_hex)
        .count();
    if matching != 1 {
        return Err(VerificationError::DigestMismatch);
    }

    // Step 6: Rekor inclusion — Merkle recompute, checkpoint signature
    // against the embedded log key, tree sizes, and body agreement; then
    // the SET, which binds integratedTime.
    verify_inclusion(
        decoded,
        trust,
        parsed_leaf.public_key().subject_public_key.data.as_ref(),
    )?;
    verify_set(decoded, &trust.rekor_key)?;
    Ok(())
}

/// The DSSE PAE (DSSE v1 spec): `DSSEv1 <len(type)> <type> <len(payload)> <payload>`.
#[must_use]
pub fn dsse_pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    #[allow(clippy::arithmetic_side_effects)] // capacity bound only; i8 counts, never overflows
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Accepts any EKU set; see the call site in [`verify`] for why.
struct PermissiveEku;

impl webpki::ExtendedKeyUsageValidator for PermissiveEku {
    fn validate(&self, _iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Step 6, split out: inclusion proof and checkpoint.
fn verify_inclusion(
    decoded: &Decoded,
    trust: &TrustRoot,

    leaf_point: &[u8],
) -> Result<(), VerificationError> {
    // The Merkle leaf covers the canonicalized body only. integratedTime,
    // logIndex and logID are bound by the SET (`verify_set`), not here.
    let leaf_hash = rekor_leaf_hash(&decoded.body);

    let path: Vec<[u8; 32]> = decoded
        .path_hashes
        .iter()
        .map(|hash| {
            <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| VerificationError::SetInvalid)
        })
        .collect::<Result<_, _>>()?;
    if decoded.proof_log_index < 0 || decoded.tree_size == 0 {
        return Err(VerificationError::SetInvalid);
    }
    let root = root_from_path(
        decoded.proof_log_index.cast_unsigned(),
        decoded.tree_size,
        leaf_hash,
        &path,
    )?;

    verify_checkpoint(
        &decoded.checkpoint,
        decoded.tree_size,
        &root,
        &trust.rekor_key,
    )?;

    // The hashedrekord body must embed the same signature bytes and the same
    // signing key the envelope carries (ADR-014 step 6).
    verify_body_agreement(decoded, leaf_point)?;
    Ok(())
}

/// The DER prefix of a `SubjectPublicKeyInfo` for an uncompressed P-256 point:
/// SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING } up to the
/// point itself.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The em dash and space that start a signed-note signature line.
const NOTE_SIGNATURE_PREFIX: &str = "\u{2014} ";

/// The key hint of a Rekor checkpoint signature: the first four bytes of
/// SHA-256 over the log key's SPKI DER. Rekor computes it this way and does
/// not add the key name or a signature-type byte that the generic
/// `golang.org/x/mod/sumdb/note` hint has: `getPublicKeyHash` and
/// `SignedNote.Sign` in Rekor `pkg/util/signed_note.go`. It is also the
/// first four bytes of the Rekor `logID`, and the unit test
/// `a_real_staging_checkpoint_verifies` checks it against a real checkpoint.
fn checkpoint_key_hint(key: &VerifyingKey) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(P256_SPKI_PREFIX);
    hasher.update(key.to_encoded_point(false).as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, ..] = digest;
    [a, b, c, d]
}

/// Verifies a Rekor checkpoint: a signed note (`golang.org/x/mod/sumdb/note`)
/// in the transparency-dev checkpoint format,
///
/// ```text
/// <origin>\n<tree size>\n<base64(root hash)>\n[<other lines>\n]\n
/// \u{2014} <key name> <base64(key hint[4] || DER signature)>\n
/// ```
///
/// The size must equal `tree_size` (the size the inclusion proof was
/// computed against) and the root must equal `root` (the root that proof
/// gives). At least one signature line must carry the hint of `key`, and
/// every line that does must verify over the whole body including its final
/// newline. Lines with another hint are other signers (witnesses) and are
/// not checked. Any other shape is refused.
///
/// Format: Rekor `pkg/util/checkpoint.go` (`UnmarshalCheckpoint`) and
/// `pkg/util/signed_note.go` (`UnmarshalText`, `Verify`).
fn verify_checkpoint(
    checkpoint: &str,
    tree_size: u64,
    root: &[u8; 32],
    key: &VerifyingKey,
) -> Result<(), VerificationError> {
    let (body, signature_lines) = checkpoint
        .split_once("\n\n")
        .ok_or(VerificationError::SetInvalid)?;
    if !signature_lines.ends_with('\n') {
        return Err(VerificationError::SetInvalid);
    }
    let mut lines = body.split('\n');
    let (Some(origin), Some(size), Some(root_line)) = (lines.next(), lines.next(), lines.next())
    else {
        return Err(VerificationError::SetInvalid);
    };
    if origin.is_empty()
        || size.is_empty()
        || !size.bytes().all(|byte| byte.is_ascii_digit())
        || size.parse::<u64>() != Ok(tree_size)
    {
        return Err(VerificationError::SetInvalid);
    }
    let checkpoint_root = BASE64
        .decode(root_line.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?;
    if checkpoint_root.as_slice() != root.as_slice() {
        return Err(VerificationError::SetInvalid);
    }

    // The signatures cover the body lines including the final newline, which
    // the blank-line split removed.
    let mut signed_body = body.to_owned();
    signed_body.push('\n');
    let hint = checkpoint_key_hint(key);
    let mut verified = false;
    for line in signature_lines.split_terminator('\n') {
        let mut fields = line
            .strip_prefix(NOTE_SIGNATURE_PREFIX)
            .ok_or(VerificationError::SetInvalid)?
            .split(' ');
        let (Some(name), Some(encoded), None) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(VerificationError::SetInvalid);
        };
        let raw = BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| VerificationError::SetInvalid)?;
        let Some((line_hint, signature_der)) = raw.split_first_chunk::<4>() else {
            return Err(VerificationError::SetInvalid);
        };
        if name.is_empty() || signature_der.is_empty() {
            return Err(VerificationError::SetInvalid);
        }
        if *line_hint != hint {
            continue;
        }
        let signature =
            Signature::from_der(signature_der).map_err(|_| VerificationError::SetInvalid)?;
        key.verify(signed_body.as_bytes(), &signature)
            .map_err(|_| VerificationError::SetInvalid)?;
        verified = true;
    }
    if verified {
        Ok(())
    } else {
        Err(VerificationError::SetInvalid)
    }
}

/// The Rekor Merkle leaf of an entry: `SHA-256(0x00 || canonicalizedBody)`
/// (RFC 6962 §2.1 leaf hash; Rekor stores the body bytes as the leaf).
#[must_use]
pub fn rekor_leaf_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(body);
    hasher.finalize().into()
}

/// The bytes a Rekor signed entry timestamp (SET) signs: the RFC 8785
/// canonical JSON of `{"body","integratedTime","logID","logIndex"}`. `body`
/// is the base64 `canonicalizedBody`, `logID` the lowercase hex of the log's
/// key id. The keys are written in RFC 8785 order (`logID` sorts before
/// `logIndex`), base64 and hex need no JSON escaping, and the integers are
/// plain decimals.
///
/// This is what Rekor signs and what sigstore-go checks: `RekorPayload`
/// marshalled and then `jsoncanonicalizer.Transform`ed, in sigstore-go
/// `pkg/tlog/entry.go` (`VerifySET`) and Rekor `pkg/verify/verify.go`
/// (`VerifySignedEntryTimestamp`). The unit test
/// `a_real_public_good_set_verifies` checks it against a production entry.
#[must_use]
pub fn rekor_set_payload(
    body: &[u8],
    integrated_time: i64,
    log_id: &[u8],
    log_index: i64,
) -> String {
    format!(
        r#"{{"body":"{}","integratedTime":{integrated_time},"logID":"{}","logIndex":{log_index}}}"#,
        base64_of(body),
        hex_lower(log_id),
    )
}

/// Step 6, SET: the Rekor signed entry timestamp is an ECDSA P-256 (SHA-256)
/// signature by the embedded Rekor key over [`rekor_set_payload`]. It is the
/// only signature over `integratedTime`, the instant step 2 checks the leaf
/// at.
fn verify_set(decoded: &Decoded, rekor_key: &VerifyingKey) -> Result<(), VerificationError> {
    let payload = rekor_set_payload(
        &decoded.body,
        decoded.integrated_time,
        &decoded.log_key_id,
        decoded.log_index,
    );
    let signature = Signature::from_der(&decoded.signed_entry_timestamp)
        .map_err(|_| VerificationError::SetInvalid)?;
    rekor_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| VerificationError::SetInvalid)
}

/// Returns true only for a non-empty SCT list parsed by x509-parser.
///
/// The DER OCTET STRING tag alone is not evidence of an SCT: malformed or
/// empty extension contents must not let a modern Fulcio certificate through.
fn has_embedded_sct(cert: &X509Certificate<'_>) -> bool {
    cert.extensions().iter().any(|extension| {
        extension.oid.to_id_string() == SCT_LIST_OID
            && matches!(
                extension.parsed_extension(),
                ParsedExtension::SCT(scts) if !scts.is_empty()
            )
    })
}

/// Verify the Rekor body binds the DSSE signature to this bundle. The
/// synthetic fixture uses `hashedrekord`; production attestations use Rekor's
/// `dsse` entry, whose canonical body carries the same signature and payload
/// hash under `spec`.
fn verify_body_agreement(decoded: &Decoded, leaf_point: &[u8]) -> Result<(), VerificationError> {
    let body: serde_json::Value =
        serde_json::from_slice(&decoded.body).map_err(|_| VerificationError::SetInvalid)?;
    match decoded.kind.as_str() {
        "dsse" => verify_dsse_body(decoded, &body),
        "hashedrekord" => verify_hashedrekord_body(decoded, &body, leaf_point),
        _ => Err(VerificationError::UnsupportedEntryKind),
    }
}

/// The `dsse` entry body: signature and payload hash under `spec`.
fn verify_dsse_body(decoded: &Decoded, body: &serde_json::Value) -> Result<(), VerificationError> {
    let signature = body
        .pointer("/spec/signatures/0/signature")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerificationError::SetInvalid)?;
    if BASE64
        .decode(signature.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?
        != decoded.dsse_signature
    {
        return Err(VerificationError::SetInvalid);
    }
    let payload_hash = body
        .pointer("/spec/payloadHash/value")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerificationError::SetInvalid)?;
    let want = Sha256::digest(&decoded.dsse_payload);
    if payload_hash != hex_lower(&want) {
        return Err(VerificationError::SetInvalid);
    }
    Ok(())
}

/// The `hashedrekord` entry body: signature content and leaf public key.
fn verify_hashedrekord_body(
    decoded: &Decoded,
    body: &serde_json::Value,
    leaf_point: &[u8],
) -> Result<(), VerificationError> {
    let content = body
        .pointer("/spec/signature/content")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerificationError::SetInvalid)?;
    let public_key = body
        .pointer("/spec/signature/publicKey")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerificationError::SetInvalid)?;
    if BASE64
        .decode(content.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?
        != decoded.dsse_signature
    {
        return Err(VerificationError::SetInvalid);
    }
    let pem = BASE64
        .decode(public_key.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?;
    let key_der =
        crate::trust::pem_body(&pem, "PUBLIC KEY").ok_or(VerificationError::SetInvalid)?;
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&key_der)
        .map_err(|_| VerificationError::SetInvalid)?;
    if spki.subject_public_key.data.as_ref() != leaf_point {
        return Err(VerificationError::SetInvalid);
    }
    Ok(())
}

/// Recomputes the Merkle tree hash from an inclusion path (RFC 9162
/// §2.1.3.2).
fn root_from_path(
    index: u64,
    size: u64,
    leaf: [u8; 32],
    path: &[[u8; 32]],
) -> Result<[u8; 32], VerificationError> {
    if size == 0 || index >= size {
        return Err(VerificationError::SetInvalid);
    }
    if size == 1 {
        return if path.is_empty() {
            Ok(leaf)
        } else {
            Err(VerificationError::SetInvalid)
        };
    }
    let Some((head, rest)) = path.split_last() else {
        return Err(VerificationError::SetInvalid);
    };
    let k = size.next_power_of_two() >> 1;
    let merged = |mut left: [u8; 32], right: [u8; 32]| {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        left = hasher.finalize().into();
        left
    };
    if index < k {
        let sub = root_from_path(index, k, leaf, rest)?;
        Ok(merged(sub, *head))
    } else {
        #[allow(clippy::arithmetic_side_effects)] // k <= index, k <= size by the branch above
        let sub = root_from_path(index - k, size - k, leaf, rest)?;
        Ok(merged(*head, sub))
    }
}

/// Lowercase hex encoding (the in-toto digest spelling).
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('?'));
    }
    out
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// A production Rekor entry and the public-good Rekor key, copied from
    /// sigstore-go `examples/bundle-provenance.json` and
    /// `examples/trusted-root-public-good.json`. Returns the SET-relevant
    /// fields as a [`Decoded`] and the key.
    fn public_good_set() -> (Decoded, VerifyingKey) {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rekor-public-good-set.json"))
                .expect("vector json");
        let text = |pointer: &str| raw.pointer(pointer).and_then(serde_json::Value::as_str);
        let b64 = |pointer: &str| BASE64.decode(text(pointer).expect(pointer)).expect(pointer);
        let int = |pointer: &str| text(pointer).expect(pointer).parse::<i64>().expect(pointer);
        let spki = b64("/rekorPublicKey");
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki).expect("spki");
        let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.data.as_ref())
            .expect("P-256 key");
        let decoded = Decoded {
            integrated_time: int("/entry/integratedTime"),
            certs: Vec::new(),
            statement: bundle::Statement {
                statement_type: bundle::STATEMENT_TYPE.to_owned(),
                subject: Vec::new(),
            },
            dsse_payload: Vec::new(),
            dsse_payload_type: bundle::DSSE_PAYLOAD_TYPE.to_owned(),
            dsse_signature: Vec::new(),
            log_index: int("/entry/logIndex"),
            log_key_id: b64("/entry/logId/keyId"),
            kind: "intoto".to_owned(),
            kind_version: "0.0.2".to_owned(),
            body: b64("/entry/canonicalizedBody"),
            tree_size: 0,
            proof_log_index: 0,
            path_hashes: Vec::new(),
            checkpoint: String::new(),
            signed_entry_timestamp: b64("/entry/inclusionPromise/signedEntryTimestamp"),
        };
        (decoded, key)
    }

    /// A `Decoded` whose body agrees with its DSSE signature and payload, in
    /// the given entry kind. Only `body_agreement_*` tests use it.
    fn agreeing_entry(kind: &str) -> Decoded {
        let payload = br#"{"_type":"https://in-toto.io/Statement/v1"}"#.to_vec();
        let dsse_signature = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        Decoded {
            integrated_time: 1,
            certs: Vec::new(),
            statement: bundle::Statement {
                statement_type: bundle::STATEMENT_TYPE.to_owned(),
                subject: Vec::new(),
            },
            dsse_payload: payload,
            dsse_payload_type: bundle::DSSE_PAYLOAD_TYPE.to_owned(),
            dsse_signature,
            log_index: 0,
            log_key_id: Vec::new(),
            kind: kind.to_owned(),
            kind_version: "0.0.1".to_owned(),
            body: Vec::new(),
            tree_size: 0,
            proof_log_index: 0,
            path_hashes: Vec::new(),
            checkpoint: String::new(),
            signed_entry_timestamp: Vec::new(),
        }
    }

    fn dsse_body(decoded: &Decoded, kind: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": kind,
            "spec": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hex_lower(&Sha256::digest(&decoded.dsse_payload))
                },
                "signatures": [{ "signature": BASE64.encode(&decoded.dsse_signature) }]
            }
        })
    }

    #[test]
    fn body_agreement_accepts_a_dsse_entry() {
        let mut decoded = agreeing_entry("dsse");
        decoded.body = dsse_body(&decoded, "dsse").to_string().into_bytes();
        assert_eq!(verify_body_agreement(&decoded, &[]), Ok(()));
    }

    #[test]
    fn body_agreement_refuses_entry_kinds_it_has_no_schema_for() {
        // `intoto` stores its signature under spec.content.envelope, not
        // spec.signatures, so a dsse-shaped body must not pass as `intoto`.
        for kind in ["intoto", "rekord", "helm", ""] {
            let mut decoded = agreeing_entry(kind);
            decoded.body = dsse_body(&decoded, kind).to_string().into_bytes();
            assert_eq!(
                verify_body_agreement(&decoded, &[]),
                Err(VerificationError::UnsupportedEntryKind),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_real_public_good_set_verifies() {
        // Proves rekor_set_payload is the canonical form Rekor signs.
        let (decoded, key) = public_good_set();
        assert_eq!(verify_set(&decoded, &key), Ok(()));
    }

    #[test]
    fn a_real_set_does_not_cover_a_changed_field() {
        type Change = fn(&mut Decoded);
        let changes: [(&str, Change); 4] = [
            ("integratedTime", |d| d.integrated_time += 1),
            ("logIndex", |d| d.log_index += 1),
            ("logID", |d| d.log_key_id[0] ^= 1),
            ("body", |d| d.body[0] ^= 1),
        ];
        for (field, change) in changes {
            let (mut decoded, key) = public_good_set();
            change(&mut decoded);
            assert_eq!(
                verify_set(&decoded, &key),
                Err(VerificationError::SetInvalid),
                "{field}"
            );
        }
    }

    #[test]
    fn an_sct_octet_string_must_parse_as_a_nonempty_list() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let mut params = CertificateParams::default();
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
            // A DER OCTET STRING containing an empty list: the old
            // first-byte check accepted this, but x509-parser rejects it.
            vec![0x04, 0x00],
        )];
        let key = KeyPair::generate().expect("fixture key");
        let cert = params.self_signed(&key).expect("fixture cert");
        let (_, parsed) = X509Certificate::from_der(cert.der()).expect("parse fixture cert");
        assert!(!has_embedded_sct(&parsed));
    }

    #[test]
    fn a_nonempty_sct_list_is_recognized() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let mut entry = vec![0]; // SCT version v1
        entry.extend_from_slice(&[0; 32]); // log ID
        entry.extend_from_slice(&[0; 8]); // timestamp
        entry.extend_from_slice(&[0, 0]); // extensions length
        entry.extend_from_slice(&[4, 3, 0, 0]); // hash, signature, signature length

        let mut value = vec![0x04, 0x33, 0x00, 0x31, 0x00, 0x2f];
        value.extend_from_slice(&entry);
        let mut params = CertificateParams::default();
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
            value,
        )];
        let key = KeyPair::generate().expect("fixture key");
        let cert = params.self_signed(&key).expect("fixture cert");
        let (_, parsed) = X509Certificate::from_der(cert.der()).expect("parse fixture cert");
        assert!(has_embedded_sct(&parsed));
    }

    #[test]
    fn the_leaf_hash_is_the_rfc6962_hash_of_the_body() {
        // Pinned hex computed outside this crate:
        // python3 -c 'import hashlib; print(hashlib.sha256(b"\x00" + b"{\"kind\":\"hashedrekord\"}").hexdigest())'
        assert_eq!(
            hex_lower(&rekor_leaf_hash(br#"{"kind":"hashedrekord"}"#)),
            "caf6b539d9cbed2236739ae10e4008b6fce2f4fe0fc3d828088cc3c5249efb8a"
        );
    }

    #[test]
    fn a_real_rekor_proof_reaches_its_root_from_the_body_leaf() {
        // A Rekor staging entry and its inclusion proof, copied from
        // sigstore-python `test/assets/bundle_v3.txt.sigstore`: the leaf
        // hash of the body plus the proof path must give Rekor's root hash.
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rekor-staging-proof.json"))
                .expect("vector json");
        let text = |pointer: &str| {
            raw.pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .expect(pointer)
        };
        let body = BASE64
            .decode(text("/entry/canonicalizedBody"))
            .expect("body");
        let leaf = rekor_leaf_hash(&body);
        assert_eq!(hex_lower(&leaf), text("/leafHash"));
        let path: Vec<[u8; 32]> = raw
            .pointer("/entry/inclusionProof/hashes")
            .and_then(serde_json::Value::as_array)
            .expect("hashes")
            .iter()
            .map(|hash| {
                BASE64
                    .decode(hash.as_str().expect("hash"))
                    .expect("hash")
                    .try_into()
                    .expect("32 bytes")
            })
            .collect();
        let root = root_from_path(
            text("/entry/inclusionProof/logIndex")
                .parse()
                .expect("index"),
            text("/entry/inclusionProof/treeSize")
                .parse()
                .expect("size"),
            leaf,
            &path,
        )
        .expect("proof");
        assert_eq!(BASE64.encode(root), text("/entry/inclusionProof/rootHash"));
    }

    /// The SPKI DER of a P-256 key, built here on its own so the tests do not
    /// lean on the production hint code: the fixed header, then the
    /// uncompressed point.
    fn test_spki(key: &VerifyingKey) -> Vec<u8> {
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(key.to_encoded_point(false).as_bytes());
        spki
    }

    /// The four key-hint bytes of the signed-note signature line for `key`.
    fn test_hint(key: &VerifyingKey) -> [u8; 4] {
        let digest: [u8; 32] = Sha256::digest(test_spki(key)).into();
        let [a, b, c, d, ..] = digest;
        [a, b, c, d]
    }

    /// One signed-note signature line: `\u{2014} <name> <b64(hint || DER)>\n`.
    fn note_signature_line(name: &str, hint: [u8; 4], signature: &Signature) -> String {
        let mut raw = hint.to_vec();
        raw.extend_from_slice(signature.to_der().as_bytes());
        format!("\u{2014} {name} {}\n", BASE64.encode(raw))
    }

    /// A hand-built single-leaf log: its body, the trust root holding the
    /// log key, the log key, and the root hash of the one-leaf tree.
    fn single_leaf_log() -> (Decoded, TrustRoot, p256::ecdsa::SigningKey, [u8; 32]) {
        use p256::ecdsa::SigningKey;

        let rekor = SigningKey::from_slice(&[0x41; 32]).expect("fixed scalar");
        let trust = TrustRoot {
            fulcio_roots: Vec::new(),
            rekor_key: *rekor.verifying_key(),
            root_windows: Vec::new(),
        };
        let payload = br#"{"_type":"https://in-toto.io/Statement/v1"}"#.to_vec();
        let dsse_signature = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": { "algorithm": "sha256", "value": hex_lower(&Sha256::digest(&payload)) },
                "signatures": [{ "signature": BASE64.encode(&dsse_signature) }]
            }
        })
        .to_string()
        .into_bytes();
        let root = rekor_leaf_hash(&body);
        let decoded = Decoded {
            integrated_time: 1,
            certs: Vec::new(),
            statement: bundle::Statement {
                statement_type: bundle::STATEMENT_TYPE.to_owned(),
                subject: Vec::new(),
            },
            dsse_payload: payload,
            dsse_payload_type: bundle::DSSE_PAYLOAD_TYPE.to_owned(),
            dsse_signature,
            log_index: 0,
            log_key_id: Vec::new(),
            kind: "dsse".to_owned(),
            kind_version: "0.0.1".to_owned(),
            body,
            tree_size: 1,
            proof_log_index: 0,
            path_hashes: Vec::new(),
            checkpoint: String::new(),
            signed_entry_timestamp: Vec::new(),
        };
        (decoded, trust, rekor, root)
    }

    /// A checkpoint note as Rekor writes it: origin, size, root, then any
    /// other lines, each ending in a newline.
    fn note(size: &str, root: &[u8], extra: &[&str]) -> String {
        let mut note = format!("test-log - 7\n{size}\n{}\n", BASE64.encode(root));
        for line in extra {
            note.push_str(line);
            note.push('\n');
        }
        note
    }

    /// `note` signed by `rekor` with the right key hint, as a full envelope.
    fn signed(rekor: &p256::ecdsa::SigningKey, note: &str) -> String {
        use p256::ecdsa::signature::Signer as _;

        let signature: Signature = rekor.sign(note.as_bytes());
        let line = note_signature_line("test-log", test_hint(rekor.verifying_key()), &signature);
        format!("{note}\n{line}")
    }

    fn inclusion_with(checkpoint: String) -> Result<(), VerificationError> {
        let (mut decoded, trust, _, _) = single_leaf_log();
        decoded.checkpoint = checkpoint;
        verify_inclusion(&decoded, &trust, &[])
    }

    /// The checkpoint commits to the Merkle root and covers the whole body.
    /// The entry fields outside the body are varied: none may move the leaf.
    #[test]
    fn the_leaf_hash_covers_the_body_only() {
        let (mut decoded, trust, rekor, root) = single_leaf_log();
        decoded.checkpoint = signed(&rekor, &note("1", &root, &[]));
        for (integrated_time, log_index, log_key_id, kind_version) in [
            (1_786_780_800, 0, vec![1_u8, 2, 3], "0.0.1"),
            (1, 99, vec![9_u8; 32], "0.0.2"),
        ] {
            decoded.integrated_time = integrated_time;
            decoded.log_index = log_index;
            decoded.log_key_id = log_key_id;
            decoded.kind_version = kind_version.to_owned();
            assert_eq!(verify_inclusion(&decoded, &trust, &[]), Ok(()));
        }
    }

    #[test]
    fn a_checkpoint_with_other_content_lines_verifies() {
        let (_, _, rekor, root) = single_leaf_log();
        let checkpoint = signed(&rekor, &note("1", &root, &["extra one", "extra two"]));
        assert_eq!(inclusion_with(checkpoint), Ok(()));
    }

    #[test]
    fn a_checkpoint_of_another_size_is_refused() {
        // Signed by the log key, so only the size check can refuse it. The
        // proof was computed against tree size 1; the checkpoint must say 1.
        let (_, _, rekor, root) = single_leaf_log();
        for size in ["0", "2", "18446744073709551615", "+1", "01x", ""] {
            let checkpoint = signed(&rekor, &note(size, &root, &[]));
            assert_eq!(
                inclusion_with(checkpoint),
                Err(VerificationError::SetInvalid),
                "size {size:?}"
            );
        }
    }

    #[test]
    fn a_checkpoint_of_another_root_is_refused() {
        // Both are signed by the log key: the sha256(root) the old code
        // expected, and an unrelated root. Only the computed root passes.
        let (_, _, rekor, root) = single_leaf_log();
        let hashed: [u8; 32] = Sha256::digest(root).into();
        for other in [&hashed[..], &[0_u8; 32][..], &root[..16]] {
            let checkpoint = signed(&rekor, &note("1", other, &[]));
            assert_eq!(
                inclusion_with(checkpoint),
                Err(VerificationError::SetInvalid)
            );
        }
    }

    #[test]
    fn a_checkpoint_with_a_wrong_signature_is_refused() {
        use p256::ecdsa::signature::Signer as _;

        let (_, _, rekor, root) = single_leaf_log();
        let good = note("1", &root, &[]);
        let hint = test_hint(rekor.verifying_key());
        // A valid signature over other text, and over the body without its
        // final newline.
        for signed_text in [note("1", &root, &["other"]), good.trim_end().to_owned()] {
            let signature: Signature = rekor.sign(signed_text.as_bytes());
            let line = note_signature_line("test-log", hint, &signature);
            assert_eq!(
                inclusion_with(format!("{good}\n{line}")),
                Err(VerificationError::SetInvalid)
            );
        }
        // The signature bytes are not DER.
        let line = format!(
            "\u{2014} test-log {}\n",
            BASE64.encode([hint.as_slice(), &[1; 8]].concat())
        );
        assert_eq!(
            inclusion_with(format!("{good}\n{line}")),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_checkpoint_with_a_wrong_key_hint_is_refused() {
        use p256::ecdsa::signature::Signer as _;

        let (_, _, rekor, root) = single_leaf_log();
        let good = note("1", &root, &[]);
        let signature: Signature = rekor.sign(good.as_bytes());
        let mut hint = test_hint(rekor.verifying_key());
        hint[0] ^= 1;
        let line = note_signature_line("test-log", hint, &signature);
        assert_eq!(
            inclusion_with(format!("{good}\n{line}")),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_checkpoint_without_a_signature_line_is_refused() {
        let (_, _, _, root) = single_leaf_log();
        let good = note("1", &root, &[]);
        for checkpoint in [
            format!("{good}\n"),
            good.clone(),
            format!("{good}\nnot a signature line\n"),
        ] {
            assert_eq!(
                inclusion_with(checkpoint),
                Err(VerificationError::SetInvalid)
            );
        }
    }

    #[test]
    fn a_checkpoint_needs_a_matching_line_but_ignores_other_keys() {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer as _;

        let (_, _, rekor, root) = single_leaf_log();
        let good = note("1", &root, &[]);
        let witness = SigningKey::from_slice(&[0x42; 32]).expect("fixed scalar");
        let witness_sig: Signature = witness.sign(good.as_bytes());
        let witness_line =
            note_signature_line("witness", test_hint(witness.verifying_key()), &witness_sig);
        let rekor_sig: Signature = rekor.sign(good.as_bytes());
        let rekor_line =
            note_signature_line("test-log", test_hint(rekor.verifying_key()), &rekor_sig);
        // A witness line beside the log's line is fine, before or after it.
        for lines in [
            format!("{witness_line}{rekor_line}"),
            format!("{rekor_line}{witness_line}"),
        ] {
            assert_eq!(inclusion_with(format!("{good}\n{lines}")), Ok(()));
        }
        // A witness line alone names no trusted key.
        assert_eq!(
            inclusion_with(format!("{good}\n{witness_line}")),
            Err(VerificationError::SetInvalid)
        );
    }

    /// A Rekor staging entry, its inclusion proof and its signed checkpoint,
    /// copied from sigstore-python `test/assets/bundle_v3.txt.sigstore` (pins
    /// in `rekor-staging-proof.json`), with the staging log key from
    /// sigstore's staging trusted root.
    fn staging_log() -> (Decoded, TrustRoot) {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rekor-staging-proof.json"))
                .expect("vector json");
        let text = |pointer: &str| {
            raw.pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .expect(pointer)
        };
        let b64 = |pointer: &str| BASE64.decode(text(pointer)).expect(pointer);
        let spki_der = b64("/rekorPublicKey");
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki_der).expect("spki");
        let trust = TrustRoot {
            fulcio_roots: Vec::new(),
            rekor_key: VerifyingKey::from_sec1_bytes(spki.subject_public_key.data.as_ref())
                .expect("P-256 key"),
            root_windows: Vec::new(),
        };
        let decoded = Decoded {
            integrated_time: 1_712_085_549,
            certs: Vec::new(),
            statement: bundle::Statement {
                statement_type: bundle::STATEMENT_TYPE.to_owned(),
                subject: Vec::new(),
            },
            dsse_payload: Vec::new(),
            dsse_payload_type: bundle::DSSE_PAYLOAD_TYPE.to_owned(),
            dsse_signature: Vec::new(),
            log_index: 25_915_956,
            log_key_id: Vec::new(),
            kind: "hashedrekord".to_owned(),
            kind_version: "0.0.1".to_owned(),
            body: b64("/entry/canonicalizedBody"),
            tree_size: text("/entry/inclusionProof/treeSize")
                .parse()
                .expect("size"),
            proof_log_index: text("/entry/inclusionProof/logIndex")
                .parse()
                .expect("index"),
            path_hashes: raw
                .pointer("/entry/inclusionProof/hashes")
                .and_then(serde_json::Value::as_array)
                .expect("hashes")
                .iter()
                .map(|hash| BASE64.decode(hash.as_str().expect("hash")).expect("hash"))
                .collect(),
            checkpoint: text("/entry/inclusionProof/checkpoint/envelope").to_owned(),
            signed_entry_timestamp: Vec::new(),
        };
        (decoded, trust)
    }

    /// The staging log's checkpoint check on its own: the root comes from the
    /// real body and proof, then the real checkpoint is verified against it.
    /// (The real `hashedrekord` body embeds the Fulcio certificate, not a bare
    /// key, so `verify_inclusion`'s body check is not the subject here.)
    fn staging_checkpoint(decoded: &Decoded, trust: &TrustRoot) -> Result<(), VerificationError> {
        let path: Vec<[u8; 32]> = decoded
            .path_hashes
            .iter()
            .map(|hash| <[u8; 32]>::try_from(hash.as_slice()).expect("32 bytes"))
            .collect();
        let root = root_from_path(
            decoded.proof_log_index.cast_unsigned(),
            decoded.tree_size,
            rekor_leaf_hash(&decoded.body),
            &path,
        )?;
        verify_checkpoint(
            &decoded.checkpoint,
            decoded.tree_size,
            &root,
            &trust.rekor_key,
        )
    }

    #[test]
    fn a_real_staging_checkpoint_verifies() {
        let (decoded, trust) = staging_log();
        assert_eq!(staging_checkpoint(&decoded, &trust), Ok(()));
    }

    #[test]
    fn a_real_staging_checkpoint_is_bound_to_its_size_root_and_key() {
        // Each change breaks a different rule; none can be re-signed, so
        // every one must be refused.
        type Change = fn(&mut Decoded);
        let changes: [(&str, Change); 4] = [
            ("size", |d| d.tree_size += 1),
            ("root", |d| d.path_hashes[0][0] ^= 1),
            ("text", |d| {
                d.checkpoint = d.checkpoint.replace("25901138", "25901139");
            }),
            ("hint", |d| {
                d.checkpoint = d.checkpoint.replace("0y8wozBF", "0y8xozBF");
            }),
        ];
        for (name, change) in changes {
            let (mut decoded, trust) = staging_log();
            change(&mut decoded);
            assert_eq!(
                staging_checkpoint(&decoded, &trust),
                Err(VerificationError::SetInvalid),
                "{name}"
            );
        }
        // Another key: the hint no longer names it.
        let (decoded, _) = staging_log();
        let (_, other_trust, _, _) = single_leaf_log();
        assert_eq!(
            staging_checkpoint(&decoded, &other_trust),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn pae_matches_dsse_spec_vectors() {
        // The spec's own worked example.
        let pae = dsse_pae(b"https://example.com/Report", b"body");
        assert_eq!(pae, b"DSSEv1 26 https://example.com/Report 4 body");
    }

    #[test]
    fn pinned_identity_is_the_release_workflow_at_the_tag() {
        assert_eq!(
            pinned_identity("v0.0.2"),
            "https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/v0.0.2"
        );
    }

    #[test]
    fn root_from_path_single_leaf() {
        let leaf = [7_u8; 32];
        assert_eq!(root_from_path(0, 1, leaf, &[]), Ok(leaf));
    }

    #[test]
    fn root_from_path_singleton_rejects_extra_nodes() {
        assert_eq!(
            root_from_path(0, 1, [0_u8; 32], &[[1_u8; 32]]),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn root_from_path_two_leaves() {
        let leaf = [1_u8; 32];
        let sibling = [2_u8; 32];
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(leaf);
        hasher.update(sibling);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(root_from_path(0, 2, leaf, &[sibling]), Ok(expected));
        assert_eq!(root_from_path(1, 2, sibling, &[leaf]), Ok(expected));
    }

    #[test]
    fn root_from_path_refuses_an_index_outside_the_tree() {
        assert_eq!(
            root_from_path(4, 4, [0_u8; 32], &[[1_u8; 32], [2_u8; 32]]),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn root_from_path_refuses_short_path() {
        assert_eq!(
            root_from_path(0, 4, [0_u8; 32], &[]),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn root_from_path_right_branch() {
        // Four leaves, path for index 3: [h(0,1), h(2,3)] with leaf 3's
        // sibling path.
        let l0 = [0_u8; 32];
        let l1 = [1_u8; 32];
        let l2 = [2_u8; 32];
        let l3 = [3_u8; 32];
        let merge = |left: [u8; 32], right: [u8; 32]| {
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(left);
            hasher.update(right);
            hasher.finalize().into()
        };
        let n01: [u8; 32] = merge(l0, l1);
        let n23: [u8; 32] = merge(l2, l3);
        let expected: [u8; 32] = merge(n01, n23);
        assert_eq!(root_from_path(3, 4, l3, &[l2, n01]), Ok(expected));
    }
}
