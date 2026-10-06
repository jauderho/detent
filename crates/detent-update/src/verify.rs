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
use x509_parser::extensions::{CtVersion, ParsedExtension};
use x509_parser::prelude::{FromDer as _, GeneralName};

use crate::bundle::{self, Decoded};
use crate::trust::{CtLogKey, NoteLogKey, TrustRoot};

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
    /// Step 3: the signing certificate has no embedded SCT that an
    /// embedded CT log key signed.
    #[error("signing certificate has no valid embedded SCT list")]
    SctInvalid,
    /// An RFC 3161 timestamp does not verify against the embedded timestamp
    /// authority (the signing time of a Rekor v2 entry).
    #[error("RFC 3161 timestamp does not verify against the embedded timestamp authority")]
    TimestampInvalid,
    /// Step 6: the Rekor entry kind is not `hashedrekord` or `dsse`.
    #[error("Rekor entry kind is not supported by the verifier")]
    UnsupportedEntryKind,
}

/// Verifies a parsed bundle end-to-end (ADR-014 steps 2–6; step 1 is
/// [`bundle::parse`]).
///
/// `file_digest` is the SHA-256 of the downloaded binary; `tag` is the exact
/// release tag being installed. The identity is pinned to
/// [`pinned_identity`]`(tag)`.
///
/// # Errors
///
/// The first failing step's [`VerificationError`]; no partial state.
pub fn verify(
    decoded: &Decoded,
    file_digest: &[u8; 32],
    tag: &str,
    trust: &TrustRoot,
) -> Result<(), VerificationError> {
    verify_for_identity(decoded, file_digest, &pinned_identity(tag), trust)
}

/// [`verify`] with the pinned workflow identity given directly. Only
/// [`verify`] and tests call it: tests use it to verify real third-party
/// bundles, whose identity is not ours, through every step.
#[allow(clippy::too_many_lines)]
fn verify_for_identity(
    decoded: &Decoded,
    file_digest: &[u8; 32],
    pinned: &str,
    trust: &TrustRoot,
) -> Result<(), VerificationError> {
    // The signing times. Rekor v1: the integratedTime the SET binds (checked
    // in step 6). Rekor v2 has no signed integrated time. Every RFC 3161
    // timestamp the bundle carries must verify and adds its genTime; a Rekor
    // v2 entry needs at least one (sigstore-go `VerifyObserverTimestamps`).
    let times = signing_times(decoded, trust)?;

    // Step 2: certificate chain to the embedded Fulcio roots, at every
    // signing time.
    for &time in &times {
        verify_chain_at(decoded, trust, time)?;
    }
    let Some((leaf_raw, intermediate_raws)) = decoded.certs.split_first() else {
        return Err(VerificationError::CertChainInvalid);
    };

    // Step 3: identity pinning, on the parsed leaf. Fulcio certificates
    // carry the workflow URI as a URI SAN and in the build-signer extension
    // (a DER UTF8String); accept either while pinning the exact tag.
    let (_, parsed_leaf) =
        X509Certificate::from_der(leaf_raw).map_err(|_| VerificationError::CertChainInvalid)?;
    let san = parsed_leaf
        .subject_alternative_name()
        .map_err(|_| VerificationError::CertChainInvalid)?;
    let san_matches = san.is_some_and(|extension| {
        extension
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::URI(uri) if *uri == pinned))
    });
    if !san_matches && !build_signer_is(&parsed_leaf, pinned) {
        return Err(VerificationError::IdentityMismatch);
    }
    let modern_issuer = parsed_leaf.extensions().iter().any(|extension| {
        extension.oid.to_id_string() == ISSUER_V2_OID
            && der_utf8_string(extension.value) == Some(ISSUER.as_bytes())
    });
    let legacy_issuer = parsed_leaf.extensions().iter().any(|extension| {
        extension.oid.to_id_string() == ISSUER_OID && extension.value == ISSUER.as_bytes()
    });
    if !modern_issuer && !legacy_issuer {
        return Err(VerificationError::IssuerMismatch);
    }
    // Every leaf, with either issuer extension, needs a verified SCT.
    let candidates: Vec<CertificateDer<'_>> = trust
        .fulcio_roots
        .iter()
        .map(|root| CertificateDer::from(root.as_ref()))
        .chain(
            intermediate_raws
                .iter()
                .map(|der| CertificateDer::from(der.as_slice())),
        )
        .collect();
    let issuer_spki =
        sct_issuer_spki(&parsed_leaf, &candidates).ok_or(VerificationError::SctInvalid)?;
    verify_embedded_scts(&parsed_leaf, &issuer_spki, &trust.ct_logs)?;

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

    // Step 6, Rekor v2: the entry body rebuilt from this bundle, its
    // inclusion proof, and the Ed25519 checkpoint of the embedded log.
    if decoded.is_rekor_v2() {
        return verify_rekor_v2_entry(decoded, trust, &times, leaf_raw, &parsed_leaf);
    }

    // Step 6, Rekor v1: inclusion — Merkle recompute, checkpoint signature
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

/// Step 2 at one signing time: the leaf chains to an embedded Fulcio root
/// whose own window covers `time`, and is valid at `time`.
fn verify_chain_at(
    decoded: &Decoded,
    trust: &TrustRoot,
    time: i64,
) -> Result<(), VerificationError> {
    let usable_roots: Vec<CertificateDer<'_>> = trust
        .fulcio_roots
        .iter()
        .zip(&trust.root_windows)
        .filter(|(_, window)| crate::trust::window_covers(**window, time))
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
    let at = UnixTime::since_unix_epoch(Duration::from_secs(time.max(0).cast_unsigned()));
    leaf.verify_for_usage(
        &[
            webpki::aws_lc_rs::ECDSA_P256_SHA256,
            webpki::aws_lc_rs::ECDSA_P384_SHA384,
        ],
        &anchors,
        &intermediates,
        at,
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
    Ok(())
}

/// The signing times of a bundle: see the call in [`verify_for_identity`].
fn signing_times(decoded: &Decoded, trust: &TrustRoot) -> Result<Vec<i64>, VerificationError> {
    let mut times = Vec::with_capacity(decoded.rfc3161_timestamps.len().saturating_add(1));
    if !decoded.is_rekor_v2() {
        times.push(decoded.integrated_time);
    }
    for token in &decoded.rfc3161_timestamps {
        let time = trust
            .tsas
            .iter()
            .find_map(|tsa| crate::tsa::verify_timestamp(token, &decoded.dsse_signature, tsa).ok())
            .ok_or(VerificationError::TimestampInvalid)?;
        times.push(time);
    }
    if times.is_empty() {
        return Err(VerificationError::TimestampInvalid);
    }
    Ok(times)
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
    let root = inclusion_root(decoded)?;

    verify_checkpoint(
        &decoded.checkpoint,
        decoded.tree_size,
        &root,
        CheckpointKey::Rekor(&trust.rekor_key),
    )?;

    // The hashedrekord body must embed the same signature bytes and the same
    // signing key the envelope carries (ADR-014 step 6).
    verify_body_agreement(decoded, leaf_point)?;
    Ok(())
}

/// The root hash the inclusion proof gives for the entry's body: the RFC 6962
/// leaf hash of `canonicalizedBody`, walked up the path.
fn inclusion_root(decoded: &Decoded) -> Result<[u8; 32], VerificationError> {
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
    root_from_path(
        decoded.proof_log_index.cast_unsigned(),
        decoded.tree_size,
        leaf_hash,
        &path,
    )
}

/// Step 6 for a Rekor v2 entry (`hashedrekord` 0.0.2). The log key is the
/// embedded one whose log id is the entry's `logId`, and its window must
/// cover every signing time. The body must be exactly
/// [`rekor_v2_body`] for this bundle; its RFC 6962 leaf must reach the root
/// the checkpoint signs ([`verify_v2_checkpoint`]). Because the body is
/// rebuilt from the bundle's own signature, leaf and PAE digest, it binds
/// them to the log entry (sigstore-go `reconstructV2EntryHash`).
fn verify_rekor_v2_entry(
    decoded: &Decoded,
    trust: &TrustRoot,
    times: &[i64],
    leaf_der: &[u8],
    leaf: &X509Certificate<'_>,
) -> Result<(), VerificationError> {
    let key = trust
        .rekor_v2_keys
        .iter()
        .find(|key| key.log_id.as_slice() == decoded.log_key_id.as_slice())
        .ok_or(VerificationError::SetInvalid)?;
    if !times
        .iter()
        .all(|time| crate::trust::window_covers(key.window, *time))
    {
        return Err(VerificationError::SetInvalid);
    }
    if rekor_v2_body(decoded, leaf_der, leaf)?.as_bytes() != decoded.body.as_slice() {
        return Err(VerificationError::SetInvalid);
    }
    let root = inclusion_root(decoded)?;
    verify_v2_checkpoint(&decoded.checkpoint, decoded.tree_size, &root, key)
}

/// The canonical (RFC 8785) Rekor v2 `hashedrekord` 0.0.2 body for this
/// bundle: the digest is SHA-256 of the DSSE PAE, the signature the DSSE
/// signature, the verifier the leaf certificate. The keys are written in
/// RFC 8785 order and base64 needs no JSON escaping (rekor-tiles
/// `pkg/types/hashedrekord`, `ToEntryHash`). Only P-256 leaves
/// (`PKIX_ECDSA_P256_SHA_256`) are supported; others are
/// [`VerificationError::UnsupportedEntryKind`].
fn rekor_v2_body(
    decoded: &Decoded,
    leaf_der: &[u8],
    leaf: &X509Certificate<'_>,
) -> Result<String, VerificationError> {
    let spki = leaf.public_key().raw;
    if spki
        .strip_prefix(&P256_SPKI_PREFIX)
        .is_none_or(|point| point.len() != 65)
    {
        return Err(VerificationError::UnsupportedEntryKind);
    }
    let digest = Sha256::digest(dsse_pae(
        decoded.dsse_payload_type.as_bytes(),
        &decoded.dsse_payload,
    ));
    Ok(format!(
        concat!(
            r#"{{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{{"hashedRekordV002":{{"#,
            r#""data":{{"algorithm":"SHA2_256","digest":"{}"}},"#,
            r#""signature":{{"content":"{}","verifier":{{"keyDetails":"PKIX_ECDSA_P256_SHA_256","#,
            r#""x509Certificate":{{"rawBytes":"{}"}}}}}}}}}}}}"#,
        ),
        base64_of(&digest),
        base64_of(&decoded.dsse_signature),
        base64_of(leaf_der),
    ))
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

/// Verifies a Rekor v2 checkpoint, a signed note signed by the Ed25519 log
/// key `key`. As [`verify_checkpoint`], and also: the origin (first line)
/// must be `key.origin`; the log's signature line must carry the key name
/// `key.origin` and the key hash `key.log_id[..4]` (rekor-tiles
/// `pkg/note/note.go`, `genConformantKeyHash`); its signature is the raw
/// 64-byte Ed25519 signature over the body. Lines with another name or key
/// hash (witness cosignatures) are not checked.
///
/// Not yet called by [`verify`]; the Rekor v2 entry path will use it.
///
/// # Errors
///
/// [`VerificationError::SetInvalid`] when the checkpoint has another size,
/// root or origin, has no valid signature by the log, or is malformed.
pub fn verify_v2_checkpoint(
    checkpoint: &str,
    tree_size: u64,
    root: &[u8; 32],
    key: &NoteLogKey,
) -> Result<(), VerificationError> {
    verify_checkpoint(checkpoint, tree_size, root, CheckpointKey::Note(key))
}

/// The log key a checkpoint must be signed by.
#[derive(Clone, Copy)]
enum CheckpointKey<'a> {
    /// Rekor v1: ECDSA P-256, DER signatures, any key name.
    Rekor(&'a VerifyingKey),
    /// Rekor v2: Ed25519 signed note under the key's origin.
    Note(&'a NoteLogKey),
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
/// not checked. Any other shape is refused. For a [`CheckpointKey::Note`]
/// key see [`verify_v2_checkpoint`].
///
/// Format: Rekor `pkg/util/checkpoint.go` (`UnmarshalCheckpoint`) and
/// `pkg/util/signed_note.go` (`UnmarshalText`, `Verify`).
fn verify_checkpoint(
    checkpoint: &str,
    tree_size: u64,
    root: &[u8; 32],
    key: CheckpointKey<'_>,
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
        || matches!(key, CheckpointKey::Note(note) if origin != note.origin)
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
    let hint = match key {
        CheckpointKey::Rekor(rekor) => checkpoint_key_hint(rekor),
        CheckpointKey::Note(note) => {
            let [a, b, c, d, ..] = note.log_id;
            [a, b, c, d]
        }
    };
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
        match key {
            CheckpointKey::Rekor(rekor) => {
                let signature = Signature::from_der(signature_der)
                    .map_err(|_| VerificationError::SetInvalid)?;
                rekor
                    .verify(signed_body.as_bytes(), &signature)
                    .map_err(|_| VerificationError::SetInvalid)?;
            }
            CheckpointKey::Note(note) => {
                // A signed note names its signer: a line with the log's
                // key hash under another name is another signer's.
                if name != note.origin {
                    continue;
                }
                webpki::aws_lc_rs::ED25519
                    .verify_signature(&note.key, signed_body.as_bytes(), signature_der)
                    .map_err(|_| VerificationError::SetInvalid)?;
            }
        }
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

/// The SPKI DER of the certificate in `candidates` that issued `leaf`: its
/// subject is the leaf's issuer and its key verifies the leaf's signature.
fn sct_issuer_spki(
    leaf: &X509Certificate<'_>,
    candidates: &[CertificateDer<'_>],
) -> Option<Vec<u8>> {
    candidates.iter().find_map(|der| {
        let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
        let key = cert.public_key().subject_public_key.data.as_ref();
        let signs_leaf = [
            webpki::aws_lc_rs::ECDSA_P256_SHA256,
            webpki::aws_lc_rs::ECDSA_P384_SHA384,
        ]
        .iter()
        .any(|algorithm| {
            algorithm
                .verify_signature(
                    key,
                    leaf.tbs_certificate.as_ref(),
                    leaf.signature_value.data.as_ref(),
                )
                .is_ok()
        });
        (cert.subject() == leaf.issuer() && signs_leaf).then(|| cert.public_key().raw.to_vec())
    })
}

/// Requires one SCT embedded in `leaf` that a CT log in `ct_logs` signed
/// over the leaf's precertificate (RFC 6962 §3.2, `precert_entry`).
///
/// The signed data is
///
/// ```text
/// sct_version(1) = 0 ‖ signature_type(1) = 0 ‖ timestamp(8) ‖
/// entry_type(2) = 1 ‖ issuer_key_hash(32) ‖ tbs_length(3) ‖ tbs ‖
/// extensions_length(2) ‖ extensions
/// ```
///
/// `issuer_key_hash` is SHA-256 of `issuer_spki`, the SPKI DER of the CA
/// that issued the leaf; `tbs` is the leaf's `TBSCertificate` with the SCT
/// list extension removed ([`precert_tbs`]). The signature must be ECDSA
/// (3) with SHA-256 (4). SCTs from logs not in `ct_logs`, or of another
/// version or algorithm, do not count. The unit test
/// `a_real_embedded_sct_verifies` checks this against a real Fulcio leaf.
fn verify_embedded_scts(
    leaf: &X509Certificate<'_>,
    issuer_spki: &[u8],
    ct_logs: &[CtLogKey],
) -> Result<(), VerificationError> {
    let scts = leaf
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SCT(scts) if extension.oid.to_id_string() == SCT_LIST_OID => {
                Some(scts)
            }
            _ => None,
        })
        .ok_or(VerificationError::SctInvalid)?;
    let tbs = precert_tbs(leaf.tbs_certificate.as_ref()).ok_or(VerificationError::SctInvalid)?;
    let [0, tbs_len @ ..] = u32::try_from(tbs.len())
        .map_err(|_| VerificationError::SctInvalid)?
        .to_be_bytes()
    else {
        return Err(VerificationError::SctInvalid);
    };
    let issuer_key_hash = Sha256::digest(issuer_spki);

    let verified = scts.iter().any(|sct| {
        let Some(log) = ct_logs.iter().find(|log| log.log_id == *sct.id.key_id) else {
            return false;
        };
        let Ok(extensions_len) = u16::try_from(sct.extensions.0.len()) else {
            return false;
        };
        if sct.version != CtVersion::V1
            || sct.signature.hash_alg_id != 4
            || sct.signature.sign_alg_id != 3
        {
            return false;
        }
        let Ok(signature) = Signature::from_der(sct.signature.data) else {
            return false;
        };
        let mut signed = Vec::with_capacity(tbs.len().saturating_add(128));
        signed.extend_from_slice(&[0, 0]);
        signed.extend_from_slice(&sct.timestamp.to_be_bytes());
        signed.extend_from_slice(&[0, 1]);
        signed.extend_from_slice(&issuer_key_hash);
        signed.extend_from_slice(&tbs_len);
        signed.extend_from_slice(&tbs);
        signed.extend_from_slice(&extensions_len.to_be_bytes());
        signed.extend_from_slice(sct.extensions.0);
        log.key.verify(&signed, &signature).is_ok()
    });
    if verified {
        Ok(())
    } else {
        Err(VerificationError::SctInvalid)
    }
}

/// The DER encoding of [`SCT_LIST_OID`], tag and length included.
const SCT_LIST_OID_DER: [u8; 12] = [
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
];

/// The precertificate `TBSCertificate` an SCT signs (RFC 6962 §3.2): the
/// leaf's DER `TBSCertificate` with exactly one SCT list extension removed
/// and every enclosing length re-encoded. `None` when the DER does not have
/// that shape.
fn precert_tbs(tbs: &[u8]) -> Option<Vec<u8>> {
    let (0x30, mut fields, []) = der_tlv(tbs)? else {
        return None;
    };
    let mut out_fields = Vec::with_capacity(tbs.len());
    let mut removed = 0_usize;
    while !fields.is_empty() {
        let (tag, content, rest) = der_tlv(fields)?;
        if tag == 0xa3 {
            let (0x30, mut extensions, []) = der_tlv(content)? else {
                return None;
            };
            let mut kept = Vec::with_capacity(extensions.len());
            while !extensions.is_empty() {
                let (0x30, extension, next) = der_tlv(extensions)? else {
                    return None;
                };
                let whole = extensions.get(..extensions.len().checked_sub(next.len())?)?;
                if extension.starts_with(&SCT_LIST_OID_DER) {
                    removed = removed.checked_add(1)?;
                } else {
                    kept.extend_from_slice(whole);
                }
                extensions = next;
            }
            let mut sequence = Vec::with_capacity(kept.len().saturating_add(4));
            der_push(&mut sequence, 0x30, &kept)?;
            der_push(&mut out_fields, 0xa3, &sequence)?;
        } else {
            out_fields.extend_from_slice(fields.get(..fields.len().checked_sub(rest.len())?)?);
        }
        fields = rest;
    }
    if removed != 1 {
        return None;
    }
    let mut out = Vec::with_capacity(out_fields.len().saturating_add(4));
    der_push(&mut out, 0x30, &out_fields)?;
    Some(out)
}

/// Whether the leaf's Fulcio build-signer URI extension
/// (1.3.6.1.4.1.57264.1.9) names `pinned`.
fn build_signer_is(leaf: &X509Certificate<'_>, pinned: &str) -> bool {
    leaf.extensions().iter().any(|extension| {
        extension.oid.to_id_string() == BUILD_SIGNER_URI_OID
            && der_utf8_string(extension.value) == Some(pinned.as_bytes())
    })
}

/// The content of a DER `UTF8String` (tag 12) that fills `value` exactly.
fn der_utf8_string(value: &[u8]) -> Option<&[u8]> {
    match der_tlv(value)? {
        (0x0c, content, []) => Some(content),
        _ => None,
    }
}

/// Splits one DER TLV with a single-byte tag off `input`: (tag, contents,
/// rest). Lengths of up to three bytes; indefinite lengths are refused.
pub(crate) fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, input) = input.split_first()?;
    let (&first, mut input) = input.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if !(1..=3).contains(&count) {
            return None;
        }
        let (bytes, rest) = input.split_at_checked(count)?;
        input = rest;
        bytes
            .iter()
            .fold(0_usize, |len, &byte| (len << 8) | usize::from(byte))
    };
    let (content, rest) = input.split_at_checked(len)?;
    Some((tag, content, rest))
}

/// Appends a DER TLV with a minimal-length encoding.
fn der_push(out: &mut Vec<u8>, tag: u8, content: &[u8]) -> Option<()> {
    out.push(tag);
    let len = content.len();
    if let Ok(short @ 0..0x80) = u8::try_from(len) {
        out.push(short);
    } else {
        let bytes = len.to_be_bytes();
        let significant: Vec<u8> = bytes
            .iter()
            .copied()
            .skip_while(|&byte| byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(significant.len()).ok()?);
        out.extend_from_slice(&significant);
    }
    out.extend_from_slice(content);
    Some(())
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
            rfc3161_timestamps: Vec::new(),
        };
        (decoded, key)
    }

    /// A real public-good Fulcio leaf (P-384/SHA-384 CA signature) must chain
    /// to the embedded roots. `verify` runs step 2 (chain) before step 3
    /// (identity); this leaf is for another repository, so reaching
    /// `IdentityMismatch` proves the chain check passed.
    #[test]
    fn real_fulcio_leaf_chains_to_the_embedded_roots() {
        let (mut decoded, _) = public_good_set();
        let body: serde_json::Value = serde_json::from_slice(&decoded.body).expect("body json");
        let pem = body
            .pointer("/spec/content/envelope/signatures/0/publicKey")
            .and_then(serde_json::Value::as_str)
            .expect("publicKey");
        let pem = BASE64.decode(pem).expect("pem base64");
        decoded.certs = vec![crate::trust::pem_body(&pem, "CERTIFICATE").expect("leaf cert")];
        let trust = crate::trust::embedded().expect("embedded trust");
        assert_eq!(
            verify(&decoded, &[0; 32], "v0.0.0", &trust),
            Err(VerificationError::IdentityMismatch)
        );
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
            rfc3161_timestamps: Vec::new(),
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
    fn the_embedded_rekor_key_verifies_a_real_public_good_set() {
        let (decoded, _) = public_good_set();
        let trust = crate::trust::embedded().expect("embedded trust root");
        assert_eq!(verify_set(&decoded, &trust.rekor_key), Ok(()));
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

    /// The leaf certificate of the real `v0.0.1-rc.2` release bundle. It
    /// carries one embedded SCT from the `ctfe.sigstore.dev/2022` log.
    fn real_leaf() -> Vec<u8> {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/real-v0.0.1-rc.2.sigstore.json"
        ))
        .expect("bundle json");
        let leaf = raw
            .pointer("/verificationMaterial/certificate/rawBytes")
            .and_then(serde_json::Value::as_str)
            .expect("leaf rawBytes");
        BASE64.decode(leaf).expect("leaf base64")
    }

    /// The leaf of the real `v0.1.1` release bundle (cosign, Rekor v2).
    fn real_v2_leaf() -> Vec<u8> {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/real-v0.1.1.sigstore.json"))
                .expect("bundle json");
        let leaf = raw
            .pointer("/verificationMaterial/certificate/rawBytes")
            .and_then(serde_json::Value::as_str)
            .expect("leaf rawBytes");
        BASE64.decode(leaf).expect("leaf base64")
    }

    /// The build-signer extension holds a DER `UTF8String`, not the bare URI
    /// (E9: the raw compare could never match).
    #[test]
    fn the_build_signer_extension_names_the_release_workflow() {
        for (leaf, tag) in [(real_leaf(), "v0.0.1-rc.2"), (real_v2_leaf(), "v0.1.1")] {
            let (_, parsed) = X509Certificate::from_der(&leaf).expect("leaf");
            assert!(build_signer_is(&parsed, &pinned_identity(tag)), "{tag}");
            assert!(
                !build_signer_is(&parsed, &pinned_identity("v0.1.0")),
                "{tag}"
            );
            let longer = format!("{}x", pinned_identity(tag));
            assert!(!build_signer_is(&parsed, &longer), "{tag}");
        }
    }

    /// The SPKI of the embedded Fulcio certificate that issued the real leaf.
    fn real_issuer_spki() -> Vec<u8> {
        let leaf = real_leaf();
        let (_, parsed) = X509Certificate::from_der(&leaf).expect("parse leaf");
        let trust = crate::trust::embedded().expect("embedded trust");
        sct_issuer_spki(&parsed, &trust.fulcio_roots).expect("issuer of the real leaf")
    }

    /// Runs the SCT check on `leaf` with the real issuer key and the
    /// embedded CT log keys.
    fn check_scts(leaf: &[u8], issuer_spki: &[u8]) -> Result<(), VerificationError> {
        let (_, parsed) = X509Certificate::from_der(leaf).expect("parse leaf");
        let trust = crate::trust::embedded().expect("embedded trust");
        verify_embedded_scts(&parsed, issuer_spki, &trust.ct_logs)
    }

    /// The offset of the real SCT's log id in the real leaf DER.
    fn real_log_id_offset(leaf: &[u8]) -> usize {
        let trust = crate::trust::embedded().expect("embedded trust");
        let log_id = trust.ct_logs[0].log_id;
        let offsets: Vec<usize> = leaf
            .windows(32)
            .enumerate()
            .filter(|(_, window)| *window == log_id)
            .map(|(offset, _)| offset)
            .collect();
        assert_eq!(offsets.len(), 1, "the log id occurs once in the leaf");
        offsets[0]
    }

    #[test]
    fn the_real_leaf_issuer_is_the_embedded_intermediate() {
        let trust = crate::trust::embedded().expect("embedded trust");
        let (_, intermediate) =
            X509Certificate::from_der(trust.fulcio_roots[0].as_ref()).expect("intermediate");
        assert_eq!(real_issuer_spki(), intermediate.public_key().raw);
    }

    #[test]
    fn a_real_embedded_sct_verifies() {
        assert_eq!(check_scts(&real_leaf(), &real_issuer_spki()), Ok(()));
    }

    #[test]
    fn a_real_sct_with_a_flipped_signature_bit_is_refused() {
        let mut leaf = real_leaf();
        let issuer = real_issuer_spki();
        // log id (32), timestamp (8), extensions (2-byte length), hash and
        // signature algorithm (1 each), signature (2-byte length).
        let extensions = real_log_id_offset(&leaf) + 40;
        let extensions_len =
            usize::from(u16::from_be_bytes([leaf[extensions], leaf[extensions + 1]]));
        let signature = extensions + 2 + extensions_len + 2;
        let signature_len = usize::from(u16::from_be_bytes([leaf[signature], leaf[signature + 1]]));
        let last = signature + 2 + signature_len - 1;
        leaf[last] ^= 0x01;
        assert_eq!(
            check_scts(&leaf, &issuer),
            Err(VerificationError::SctInvalid)
        );
    }

    #[test]
    fn a_real_sct_from_an_unknown_log_is_refused() {
        let mut leaf = real_leaf();
        let issuer = real_issuer_spki();
        let offset = real_log_id_offset(&leaf);
        leaf[offset] ^= 0x01;
        assert_eq!(
            check_scts(&leaf, &issuer),
            Err(VerificationError::SctInvalid)
        );
    }

    #[test]
    fn a_real_sct_does_not_cover_a_changed_tbs() {
        let mut leaf = real_leaf();
        let issuer = real_issuer_spki();
        // The leaf's subject key identifier, outside the SCT extension.
        let ski = [0x19, 0x50, 0xfb, 0xd6, 0x99, 0x8f, 0xde, 0x8c];
        let offset = leaf
            .windows(ski.len())
            .position(|window| window == ski)
            .expect("subject key identifier");
        leaf[offset] ^= 0x01;
        assert_eq!(
            check_scts(&leaf, &issuer),
            Err(VerificationError::SctInvalid)
        );
    }

    #[test]
    fn a_real_sct_is_bound_to_its_issuer_key() {
        let trust = crate::trust::embedded().expect("embedded trust");
        let (_, root) = X509Certificate::from_der(trust.fulcio_roots[1].as_ref()).expect("root");
        assert_eq!(
            check_scts(&real_leaf(), root.public_key().raw),
            Err(VerificationError::SctInvalid)
        );
    }

    #[test]
    fn the_precert_tbs_refuses_malformed_der() {
        let leaf = real_leaf();
        let (_, parsed) = X509Certificate::from_der(&leaf).expect("parse leaf");
        let tbs = parsed.tbs_certificate.as_ref();
        let precert = precert_tbs(tbs).expect("real precert tbs");
        // The SCT list extension and nothing else is gone.
        assert!(precert.len() < tbs.len());
        assert!(
            !precert
                .windows(SCT_LIST_OID_DER.len())
                .any(|w| w == SCT_LIST_OID_DER)
        );
        // A TBS without an SCT list, truncated DER, an indefinite length and
        // an over-long length are all refused.
        assert_eq!(precert_tbs(&precert), None);
        for cut in 0..tbs.len() {
            assert_eq!(precert_tbs(&tbs[..cut]), None);
        }
        assert_eq!(precert_tbs(&[0x30, 0x80, 0x00, 0x00]), None);
        assert_eq!(precert_tbs(&[0x30, 0x84, 0, 0, 0, 0]), None);
    }

    #[test]
    fn der_lengths_are_minimal() {
        for (len, header) in [
            (0x7f_usize, vec![0x30, 0x7f]),
            (0x80, vec![0x30, 0x81, 0x80]),
            (0x1234, vec![0x30, 0x82, 0x12, 0x34]),
        ] {
            let mut out = Vec::new();
            der_push(&mut out, 0x30, &vec![0; len]).expect("push");
            assert_eq!(&out[..header.len()], header.as_slice());
            assert_eq!(
                der_tlv(&out).map(|(tag, content, rest)| (tag, content.len(), rest.len())),
                Some((0x30, len, 0))
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
        assert_eq!(
            check_scts(cert.der(), &real_issuer_spki()),
            Err(VerificationError::SctInvalid)
        );
    }

    #[test]
    fn an_unsigned_sct_from_the_embedded_log_is_refused() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let trust = crate::trust::embedded().expect("embedded trust");
        let mut entry = vec![0]; // SCT version v1
        entry.extend_from_slice(&trust.ct_logs[0].log_id); // log ID
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
        assert_eq!(
            check_scts(cert.der(), &real_issuer_spki()),
            Err(VerificationError::SctInvalid)
        );
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
            ct_logs: Vec::new(),
            rekor_v2_keys: Vec::new(),
            tsas: Vec::new(),
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
            rfc3161_timestamps: Vec::new(),
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
            ct_logs: Vec::new(),
            rekor_v2_keys: Vec::new(),
            tsas: Vec::new(),
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
            rfc3161_timestamps: Vec::new(),
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
            CheckpointKey::Rekor(&trust.rekor_key),
        )
    }

    /// The checkpoint, tree size and root hash of the staging Rekor v2 entry
    /// in the sigstore-python asset, and the staging `log2025-alpha3` key
    /// from the staging trust root (tests/fixtures/staging-rekor-v2).
    fn staging_v2() -> (String, u64, [u8; 32], NoteLogKey) {
        const ORIGIN: &str = "log2025-alpha3.rekor.sigstage.dev";
        let bundle: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/a.dsse.staging-rekor-v2.txt.sigstore.json"
        ))
        .expect("bundle json");
        let proof = bundle
            .pointer("/verificationMaterial/tlogEntries/0/inclusionProof")
            .expect("inclusionProof");
        let checkpoint = proof["checkpoint"]["envelope"].as_str().expect("envelope");
        let tree_size = proof["treeSize"]
            .as_str()
            .expect("treeSize")
            .parse()
            .expect("decimal");
        let root: [u8; 32] = BASE64
            .decode(proof["rootHash"].as_str().expect("rootHash"))
            .expect("base64")
            .try_into()
            .expect("32 bytes");
        let trusted: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/trusted_root.json"
        ))
        .expect("trusted root json");
        let log = trusted["tlogs"]
            .as_array()
            .expect("tlogs")
            .iter()
            .find(|log| log["baseUrl"] == format!("https://{ORIGIN}"))
            .expect("staging v2 log");
        let spki = BASE64
            .decode(log["publicKey"]["rawBytes"].as_str().expect("rawBytes"))
            .expect("base64");
        let key = NoteLogKey::from_spki(ORIGIN, &spki, (0, i64::MAX)).expect("Ed25519 key");
        assert_eq!(
            BASE64.encode(key.log_id),
            log["logId"]["keyId"].as_str().expect("keyId"),
            "the log id is the signed-note key hash of origin and key"
        );
        (checkpoint.to_owned(), tree_size, root, key)
    }

    /// `checkpoint` with its signature lines replaced by `lines`.
    fn with_signature_lines(checkpoint: &str, lines: &[&str]) -> String {
        let (body, _) = checkpoint.split_once("\n\n").expect("note body");
        let mut out = format!("{body}\n\n");
        for line in lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The SAN of the staging Rekor v2 bundle's leaf.
    const STAGING_V2_IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";

    /// The SHA-256 the staging bundle's one subject (`a.txt`) attests.
    const STAGING_V2_SUBJECT: &str =
        "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf";

    /// The staging Rekor v2 bundle as JSON.
    fn staging_v2_bundle() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/a.dsse.staging-rekor-v2.txt.sigstore.json"
        ))
        .expect("bundle json")
    }

    /// A [`TrustRoot`] from the staging `trusted_root.json`: the staging
    /// Fulcio CA, Rekor v1 key, CT log keys, Rekor v2 (Ed25519) log keys
    /// and timestamp authority. The real embedded root has the public-good
    /// equivalents.
    fn staging_trust() -> TrustRoot {
        let trusted: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/trusted_root.json"
        ))
        .expect("trusted root json");
        let b64 = |value: &serde_json::Value| {
            BASE64
                .decode(value.as_str().expect("base64 string"))
                .expect("base64")
        };
        let p256 = |spki: &[u8]| {
            let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki).expect("spki");
            VerifyingKey::from_sec1_bytes(spki.subject_public_key.data.as_ref()).expect("P-256")
        };
        let mut fulcio_roots = Vec::new();
        let mut root_windows = Vec::new();
        for authority in trusted["certificateAuthorities"].as_array().expect("CAs") {
            for cert in authority["certChain"]["certificates"]
                .as_array()
                .expect("chain")
            {
                let der = b64(&cert["rawBytes"]);
                let (_, parsed) = X509Certificate::from_der(&der).expect("CA cert");
                root_windows.push((
                    parsed.validity().not_before.timestamp(),
                    parsed.validity().not_after.timestamp(),
                ));
                fulcio_roots.push(CertificateDer::from(der));
            }
        }
        let tlogs = trusted["tlogs"].as_array().expect("tlogs");
        let rekor_key = tlogs
            .iter()
            .find(|log| log["publicKey"]["keyDetails"] == "PKIX_ECDSA_P256_SHA_256")
            .map(|log| p256(&b64(&log["publicKey"]["rawBytes"])))
            .expect("Rekor v1 key");
        let rekor_v2_keys = tlogs
            .iter()
            .filter(|log| log["publicKey"]["keyDetails"] == "PKIX_ED25519")
            .map(|log| {
                let origin = log["baseUrl"]
                    .as_str()
                    .and_then(|url| url.strip_prefix("https://"))
                    .expect("https baseUrl");
                NoteLogKey::from_spki(origin, &b64(&log["publicKey"]["rawBytes"]), (0, i64::MAX))
                    .expect("Ed25519 key")
            })
            .collect();
        let ct_logs = trusted["ctlogs"]
            .as_array()
            .expect("ctlogs")
            .iter()
            .filter(|log| log["publicKey"]["keyDetails"] == "PKIX_ECDSA_P256_SHA_256")
            .map(|log| {
                let spki = b64(&log["publicKey"]["rawBytes"]);
                CtLogKey {
                    log_id: Sha256::digest(&spki).into(),
                    key: p256(&spki),
                }
            })
            .collect();
        let chain = &trusted["timestampAuthorities"][0]["certChain"]["certificates"];
        let tsas = vec![crate::trust::TsaChain {
            leaf: b64(&chain[0]["rawBytes"]).into(),
            root: b64(&chain[1]["rawBytes"]).into(),
            // validFor.start 2025-04-09T00:00:00Z.
            window: (1_744_156_800, i64::MAX),
        }];
        TrustRoot {
            fulcio_roots,
            rekor_key,
            root_windows,
            ct_logs,
            rekor_v2_keys,
            tsas,
        }
    }

    fn staging_subject() -> [u8; 32] {
        let mut digest = [0_u8; 32];
        for (byte, pair) in digest
            .iter_mut()
            .zip(STAGING_V2_SUBJECT.as_bytes().chunks(2))
        {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
        }
        digest
    }

    /// Verifies `bundle` (JSON) against the staging trust root, pinned to
    /// the staging bundle's own identity.
    fn verify_staging_v2(
        bundle: &serde_json::Value,
        trust: &TrustRoot,
    ) -> Result<(), VerificationError> {
        let decoded = bundle::parse(bundle.to_string().as_bytes())?;
        verify_for_identity(&decoded, &staging_subject(), STAGING_V2_IDENTITY, trust)
    }

    #[test]
    fn a_real_staging_rekor_v2_bundle_verifies() {
        assert_eq!(
            verify_staging_v2(&staging_v2_bundle(), &staging_trust()),
            Ok(())
        );
    }

    #[test]
    fn a_real_staging_rekor_v2_bundle_is_pinned_to_our_identity() {
        let decoded = bundle::parse(staging_v2_bundle().to_string().as_bytes()).expect("parse");
        assert_eq!(
            verify(&decoded, &staging_subject(), "v0.0.1", &staging_trust()),
            Err(VerificationError::IdentityMismatch)
        );
    }

    #[test]
    fn a_rekor_v2_bundle_without_a_timestamp_is_refused() {
        let mut bundle = staging_v2_bundle();
        bundle["verificationMaterial"]
            .as_object_mut()
            .expect("verificationMaterial")
            .remove("timestampVerificationData");
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::TimestampInvalid)
        );
    }

    #[test]
    fn every_rfc3161_timestamp_must_verify() {
        let mut bundle = staging_v2_bundle();
        let timestamps =
            &mut bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"];
        let good = timestamps[0].clone();
        let mut token = BASE64
            .decode(good["signedTimestamp"].as_str().expect("token"))
            .expect("base64");
        *token.last_mut().expect("bytes") ^= 0x01;
        let bad = serde_json::json!({ "signedTimestamp": BASE64.encode(token) });
        *timestamps = serde_json::json!([bad.clone()]);
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::TimestampInvalid)
        );
        bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"] =
            serde_json::json!([good, bad]);
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::TimestampInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_integrated_time_is_ignored() {
        // 1970: outside every certificate's validity. A Rekor v2 entry has no
        // signed integrated time, so the value must not be used.
        let mut bundle = staging_v2_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = serde_json::json!("1");
        assert_eq!(verify_staging_v2(&bundle, &staging_trust()), Ok(()));
    }

    #[test]
    fn a_changed_rekor_v2_body_is_refused() {
        let mut bundle = staging_v2_bundle();
        let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
        let body = BASE64
            .decode(entry["canonicalizedBody"].as_str().expect("body"))
            .expect("base64");
        let mut body = String::from_utf8(body).expect("utf-8");
        // A space before the closing brace: same JSON, not the canonical bytes.
        body.insert(body.len() - 1, ' ');
        entry["canonicalizedBody"] = serde_json::json!(BASE64.encode(body));
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_entry_needs_an_inclusion_proof() {
        let mut bundle = staging_v2_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .expect("entry")
            .remove("inclusionProof");
        assert!(matches!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::BundleMalformed(_))
        ));
    }

    #[test]
    fn a_rekor_v2_entry_from_an_unknown_log_is_refused() {
        // The production log2025-1 key: another log id.
        let trust = TrustRoot {
            rekor_v2_keys: crate::trust::embedded().expect("embedded").rekor_v2_keys,
            ..staging_trust()
        };
        assert_eq!(
            verify_staging_v2(&staging_v2_bundle(), &trust),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_log_key_must_cover_the_signing_time() {
        let mut trust = staging_trust();
        for key in &mut trust.rekor_v2_keys {
            key.window = (0, 1_700_000_000);
        }
        assert_eq!(
            verify_staging_v2(&staging_v2_bundle(), &trust),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_checkpoint_of_another_origin_is_refused() {
        let mut bundle = staging_v2_bundle();
        let envelope = &mut bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]
            ["envelope"];
        let text = envelope.as_str().expect("envelope").replacen(
            "log2025-alpha3.rekor.sigstage.dev\n",
            "log2025-alpha2.rekor.sigstage.dev\n",
            1,
        );
        *envelope = serde_json::json!(text);
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_inclusion_path_must_reach_the_checkpoint_root() {
        let mut bundle = staging_v2_bundle();
        let hash =
            &mut bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"][0];
        let mut raw = BASE64.decode(hash.as_str().expect("hash")).expect("base64");
        raw[0] ^= 0x01;
        *hash = serde_json::json!(BASE64.encode(raw));
        assert_eq!(
            verify_staging_v2(&bundle, &staging_trust()),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_rekor_v2_bundle_still_needs_the_file_digest_and_dsse_signature() {
        let decoded = bundle::parse(staging_v2_bundle().to_string().as_bytes()).expect("parse");
        let mut other = staging_subject();
        other[0] ^= 0x01;
        assert_eq!(
            verify_for_identity(&decoded, &other, STAGING_V2_IDENTITY, &staging_trust()),
            Err(VerificationError::DigestMismatch)
        );
        let mut decoded = decoded;
        decoded.dsse_payload_type = bundle::LEGACY_DSSE_PAYLOAD_TYPE.to_owned();
        assert_eq!(
            verify_for_identity(
                &decoded,
                &staging_subject(),
                STAGING_V2_IDENTITY,
                &staging_trust()
            ),
            Err(VerificationError::SignatureInvalid)
        );
    }

    #[test]
    fn a_real_staging_v2_checkpoint_verifies() {
        let (checkpoint, size, root, key) = staging_v2();
        assert_eq!(verify_v2_checkpoint(&checkpoint, size, &root, &key), Ok(()));
    }

    #[test]
    fn a_real_staging_v2_checkpoint_is_bound_to_its_size_and_root() {
        let (checkpoint, size, root, key) = staging_v2();
        assert_eq!(
            verify_v2_checkpoint(&checkpoint, size + 1, &root, &key),
            Err(VerificationError::SetInvalid)
        );
        let mut other = root;
        other[0] ^= 1;
        assert_eq!(
            verify_v2_checkpoint(&checkpoint, size, &other, &key),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_real_staging_v2_checkpoint_with_a_flipped_signature_bit_is_refused() {
        let (checkpoint, size, root, key) = staging_v2();
        let (_, signatures) = checkpoint.split_once("\n\n").expect("note body");
        let lines: Vec<&str> = signatures.lines().collect();
        let (name, encoded) = lines[0]
            .strip_prefix(NOTE_SIGNATURE_PREFIX)
            .and_then(|line| line.split_once(' '))
            .expect("log signature line");
        assert_eq!(name, key.origin);
        let mut raw = BASE64.decode(encoded).expect("base64");
        *raw.last_mut().expect("signature bytes") ^= 0x01;
        let flipped = format!("{NOTE_SIGNATURE_PREFIX}{name} {}", BASE64.encode(raw));
        let mut mangled = vec![flipped.as_str()];
        mangled.extend_from_slice(&lines[1..]);
        assert_eq!(
            verify_v2_checkpoint(
                &with_signature_lines(&checkpoint, &mangled),
                size,
                &root,
                &key
            ),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_witness_only_v2_checkpoint_is_refused() {
        // The real witness cosignatures stay; the log's own line is gone.
        let (checkpoint, size, root, key) = staging_v2();
        let (_, signatures) = checkpoint.split_once("\n\n").expect("note body");
        let witnesses: Vec<&str> = signatures
            .lines()
            .filter(|line| !line.starts_with(&format!("{NOTE_SIGNATURE_PREFIX}{} ", key.origin)))
            .collect();
        assert_eq!(witnesses.len(), 3, "the asset carries three witness lines");
        assert_eq!(
            verify_v2_checkpoint(
                &with_signature_lines(&checkpoint, &witnesses),
                size,
                &root,
                &key
            ),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_v2_checkpoint_without_any_signature_is_refused() {
        let (checkpoint, size, root, key) = staging_v2();
        assert_eq!(
            verify_v2_checkpoint(&with_signature_lines(&checkpoint, &[]), size, &root, &key),
            Err(VerificationError::SetInvalid)
        );
    }

    /// A test Ed25519 log for `origin`: its key, and a signer that makes
    /// a signature line named `name` over a note body.
    fn test_note_log(origin: &str) -> (NoteLogKey, impl Fn(&str, &str) -> String) {
        use rcgen::{KeyPair, PublicKeyData as _, SigningKey as _};
        let pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 key");
        let key = NoteLogKey::from_spki(origin, &pair.subject_public_key_info(), (0, i64::MAX))
            .expect("Ed25519 SPKI");
        let hint = key.log_id;
        let signer = move |name: &str, body: &str| {
            let mut raw = hint[..4].to_vec();
            raw.extend_from_slice(&pair.sign(body.as_bytes()).expect("sign"));
            format!("{NOTE_SIGNATURE_PREFIX}{name} {}", BASE64.encode(raw))
        };
        (key, signer)
    }

    #[test]
    fn a_v2_checkpoint_must_start_with_the_log_origin() {
        let (key, sign) = test_note_log("log.example");
        let root = [7_u8; 32];
        let note = |origin: &str| {
            let body = format!("{origin}\n5\n{}\n", BASE64.encode(root));
            format!("{body}\n{}\n", sign("log.example", &body))
        };
        // The control: the same signer and shape verifies under its origin.
        assert_eq!(
            verify_v2_checkpoint(&note("log.example"), 5, &root, &key),
            Ok(())
        );
        // Validly signed by the log key, but for another origin.
        assert_eq!(
            verify_v2_checkpoint(&note("other.example"), 5, &root, &key),
            Err(VerificationError::SetInvalid)
        );
    }

    #[test]
    fn a_v2_signature_line_must_carry_the_log_name() {
        // Right key hash and a valid signature, but another key name: the
        // line is not the log's, so no log signature is left.
        let (key, sign) = test_note_log("log.example");
        let root = [7_u8; 32];
        let body = format!("log.example\n5\n{}\n", BASE64.encode(root));
        let note = format!("{body}\n{}\n", sign("witness.example", &body));
        assert_eq!(
            verify_v2_checkpoint(&note, 5, &root, &key),
            Err(VerificationError::SetInvalid)
        );
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
