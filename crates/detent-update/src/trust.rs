//! The embedded trust root (ADR-014): Fulcio root CAs and the Rekor log key,
//! baked in at build time from [`crate::trust`]'s PEM files — never the system
//! store, never fetched at runtime.
//!
//! The embedded files are placeholders until the first tagged release (PLAN
//! Phase 9 task 3); a placeholder fails PEM parsing and every verification
//! refuses closed with [`VerificationError::TrustRootUnavailable`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::VerifyingKey;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

use crate::VerificationError;

/// The Fulcio root CA(s), concatenated PEM. Refreshed every release (see
/// `trust/README.md`).
pub const FULCIO_ROOTS_PEM: &str = include_str!("../trust/fulcio-root.pem");

/// The Rekor log public key, PEM PKIX SPKI, ECDSA P-256.
pub const REKOR_KEY_PEM: &str = include_str!("../trust/rekor-pub.pem");

/// One-line provenance of the embedded trust material: the Sigstore TUF
/// snapshot version the files were extracted from. Updated with every root
/// refresh (trust/README.md step 4).
pub const TRUST_MANIFEST: &str = "placeholder: not yet extracted from TUF (PLAN Phase 9 task 3)";

/// The parsed trust material the verifier consumes.
#[derive(Debug)]
pub struct TrustRoot {
    /// Fulcio root certificates, DER.
    pub fulcio_roots: Vec<rustls_pki_types::CertificateDer<'static>>,
    /// The Rekor log key, for checkpoint-signature verification.
    pub rekor_key: VerifyingKey,
    /// The root CAs' own validity windows, in Unix seconds — a root is only
    /// used when the window covers the bundle's `integratedTime`.
    pub root_windows: Vec<(i64, i64)>,
}

/// Parses the embedded PEM constants into a [`TrustRoot`].
///
/// # Errors
///
/// [`VerificationError::TrustRootUnavailable`] when the embedded material
/// does not parse — including while the placeholders are still in place.
pub fn embedded() -> Result<TrustRoot, VerificationError> {
    from_pems(FULCIO_ROOTS_PEM, REKOR_KEY_PEM)
}

/// Parses trust material from PEM text (the embedded files are the only
/// production source; tests load their own fixtures through this).
///
/// # Errors
///
/// [`VerificationError::TrustRootUnavailable`] when the PEM material does
/// not parse.
pub fn from_pems(fulcio_pem: &str, rekor_pem: &str) -> Result<TrustRoot, VerificationError> {
    let fulcio_roots = pems(fulcio_pem, "CERTIFICATE")?
        .into_iter()
        .map(rustls_pki_types::CertificateDer::from)
        .collect::<Vec<_>>();
    if fulcio_roots.is_empty() {
        return Err(VerificationError::TrustRootUnavailable);
    }
    let mut root_windows = Vec::with_capacity(fulcio_roots.len());
    for root in &fulcio_roots {
        let (_, cert) = X509Certificate::from_der(root.as_ref())
            .map_err(|_| VerificationError::TrustRootUnavailable)?;
        let validity = cert.validity();
        root_windows.push((
            validity.not_before.timestamp(),
            validity.not_after.timestamp(),
        ));
    }

    let rekor_spki = pems(rekor_pem, "PUBLIC KEY")?
        .into_iter()
        .next()
        .ok_or(VerificationError::TrustRootUnavailable)?;
    let rekor_key = spki_to_p256(&rekor_spki)?;

    Ok(TrustRoot {
        fulcio_roots,
        rekor_key,
        root_windows,
    })
}

/// Extracts every PEM block of `label` from a PEM text, decoded to DER.
fn pems(text: &str, label: &str) -> Result<Vec<Vec<u8>>, VerificationError> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.by_ref().find(|line| line.starts_with("-----BEGIN ")) {
        let begin_label = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
            .ok_or(VerificationError::TrustRootUnavailable)?;
        if begin_label != label {
            continue;
        }
        let mut body = String::new();
        for line in lines.by_ref() {
            if let Some(end) = line.strip_prefix("-----END ") {
                if end.trim_end_matches('-').trim() != label {
                    return Err(VerificationError::TrustRootUnavailable);
                }
                break;
            }
            body.push_str(line.trim());
        }
        let der = BASE64
            .decode(body.as_bytes())
            .map_err(|_| VerificationError::TrustRootUnavailable)?;
        out.push(der);
    }
    Ok(out)
}

/// Turns a PKIX SPKI DER into the P-256 key inside it.
fn spki_to_p256(spki_der: &[u8]) -> Result<VerifyingKey, VerificationError> {
    use x509_parser::x509::SubjectPublicKeyInfo;
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|_| VerificationError::TrustRootUnavailable)?;
    let point = spki.subject_public_key.data;
    VerifyingKey::from_sec1_bytes(point.as_ref())
        .map_err(|_| VerificationError::TrustRootUnavailable)
}

/// Unix seconds window check: is `instant` inside `[not_before, not_after]`?
#[must_use]
pub fn window_covers(window: (i64, i64), instant: i64) -> bool {
    window.0 <= instant && instant <= window.1
}

/// The DER body of the first PEM block labelled `label`, or `None`.
///
/// Test fixtures and hashedrekord bodies carry PEM-encoded public keys; the
/// embedded trust files go through [`embedded`], which refuses closed instead
/// of returning `None`.
#[must_use]
pub fn pem_body(text: &[u8], label: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(text).ok()?;
    pems(text, label).ok()?.into_iter().next()
}
