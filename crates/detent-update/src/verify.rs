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
    // against the embedded log key, tree sizes, and body agreement.
    verify_inclusion(
        decoded,
        trust,
        parsed_leaf.public_key().subject_public_key.data.as_ref(),
    )?;
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
    // The leaf hash covers the canonicalized tlog entry: its fields, JSON,
    // keys sorted (serde_json's default map), the sigstore canonical form.
    // ponytail: assumes sigstore's canonical-JSON field order (sorted keys);
    // the Phase 9 real-bundle capture is what proves it against production.
    let entry = serde_json::json!({
        "canonicalizedBody": base64_of(&decoded.body),
        "integratedTime": decoded.integrated_time,
        "kindVersion": { "kind": decoded.kind, "version": decoded.kind_version },
        "logId": { "keyId": base64_of(&decoded.log_key_id) },
        "logIndex": decoded.log_index,
    });
    let entry_bytes = serde_json::to_vec(&entry).map_err(|_| VerificationError::SetInvalid)?;
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00]);
    leaf_hasher.update(&entry_bytes);
    let leaf_hash: [u8; 32] = leaf_hasher.finalize().into();

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

    // Checkpoint: `<origin> <treeSize>\n<base64(sha256(root))>\n\n<signature>`.
    let (body, signature_block) = decoded
        .checkpoint
        .split_once("\n\n")
        .ok_or(VerificationError::SetInvalid)?;
    let mut lines = body.lines();
    let header = lines.next().ok_or(VerificationError::SetInvalid)?;
    let mut header_parts = header.split_whitespace();
    let origin = header_parts.next().ok_or(VerificationError::SetInvalid)?;
    let checkpoint_size: u64 = header_parts
        .next()
        .and_then(|size| size.parse().ok())
        .ok_or(VerificationError::SetInvalid)?;
    if header_parts.next().is_some() || origin.is_empty() {
        return Err(VerificationError::SetInvalid);
    }
    if checkpoint_size < decoded.tree_size {
        return Err(VerificationError::SetInvalid);
    }
    // Checkpoint stores base64(sha256(root)) - the RFC 6962 signed-note root
    // hash - not the root itself.
    let checkpoint_root_line = lines.next().ok_or(VerificationError::SetInvalid)?;
    let checkpoint_root = BASE64
        .decode(checkpoint_root_line.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?;
    let want = Sha256::digest(root);
    if checkpoint_root.as_slice() != &want[..] {
        return Err(VerificationError::SetInvalid);
    }

    // The signature covers the checkpoint body including its trailing newline.
    let signature_line = signature_block
        .lines()
        .next()
        .ok_or(VerificationError::SetInvalid)?;
    let signature_text = signature_line
        .rsplit(' ')
        .next()
        .ok_or(VerificationError::SetInvalid)?;
    let signature_der = BASE64
        .decode(signature_text.as_bytes())
        .map_err(|_| VerificationError::SetInvalid)?;
    let signature =
        Signature::from_der(&signature_der).map_err(|_| VerificationError::SetInvalid)?;
    // The signature covers the body lines including the trailing newline
    // (RFC 6962 signed notes); `body` lost it to the blank-line split.
    let mut signed_body = body.to_owned();
    signed_body.push('\n');
    trust
        .rekor_key
        .verify(signed_body.as_bytes(), &signature)
        .map_err(|_| VerificationError::SetInvalid)?;

    // The hashedrekord body must embed the same signature bytes and the same
    // signing key the envelope carries (ADR-014 step 6).
    verify_body_agreement(decoded, leaf_point)?;
    Ok(())
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
    if matches!(decoded.kind.as_str(), "dsse" | "intoto") {
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
        return Ok(());
    }
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
