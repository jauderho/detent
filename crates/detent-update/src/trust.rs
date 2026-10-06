//! The embedded trust root (ADR-014): Fulcio root CAs, the Rekor v1 and v2
//! log keys, the certificate-transparency log key and the timestamp
//! authority chain, baked in at build time from [`crate::trust`]'s PEM files — never the system
//! store, never fetched at runtime.
//!
//! The files hold the Sigstore public-good material named in
//! [`TRUST_MANIFEST`]. Material that does not parse refuses closed with
//! [`VerificationError::TrustRootUnavailable`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest as _, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

use crate::VerificationError;

/// The Fulcio CA certificates (intermediate and root), concatenated PEM; each
/// is a trust anchor. Refreshed every release (see `trust/README.md`).
pub const FULCIO_ROOTS_PEM: &str = include_str!("../trust/fulcio-root.pem");

/// The Rekor log public key, PEM PKIX SPKI, ECDSA P-256.
pub const REKOR_KEY_PEM: &str = include_str!("../trust/rekor-pub.pem");

/// The Sigstore CT log public key (`ctfe.sigstore.dev/2022`), PEM PKIX SPKI,
/// ECDSA P-256. It signs the SCTs embedded in Fulcio leaves.
pub const CT_LOG_KEY_PEM: &str = include_str!("../trust/ctfe-pub.pem");

/// The Rekor v2 log public key (`log2025-1.rekor.sigstore.dev`), PEM PKIX
/// SPKI, Ed25519. It signs the log's checkpoints (signed notes).
pub const REKOR_V2_KEY_PEM: &str = include_str!("../trust/rekor-v2-pub.pem");

/// The checkpoint origin of the Rekor v2 log: the host of its `baseUrl` in
/// `trusted_root.json`.
pub const REKOR_V2_ORIGIN: &str = "log2025-1.rekor.sigstore.dev";

/// `validFor.start` of the Rekor v2 log key, 2025-09-23T00:00:00Z, in Unix
/// seconds. `trusted_root.json` gives no end.
pub const REKOR_V2_VALID_FROM: i64 = 1_758_585_600;

/// The timestamp authority (`timestamp.sigstore.dev`) chain, PEM: the TSA
/// leaf, then its self-signed root.
pub const TSA_CHAIN_PEM: &str = include_str!("../trust/tsa-chain.pem");

/// `validFor.start` of the timestamp authority, 2025-07-04T00:00:00Z, in Unix
/// seconds. `trusted_root.json` gives no end.
pub const TSA_VALID_FROM: i64 = 1_751_587_200;

/// One-line provenance of the embedded trust material: the Sigstore
/// `trusted_root.json` every embedded file and validity constant was
/// extracted from (Fulcio, Rekor v1 and v2, CT log, timestamp authority). Updated with every root
/// refresh (trust/README.md step 4).
pub const TRUST_MANIFEST: &str = "sigstore/root-signing 5888f358fc4ab58874447259edf83790261fc616 \
     targets/trusted_root.json sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

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
    /// The CT log keys an embedded SCT must be signed by.
    pub ct_logs: Vec<CtLogKey>,
    /// The Rekor v2 log keys, for signed-note checkpoints.
    pub rekor_v2_keys: Vec<NoteLogKey>,
    /// The RFC 3161 timestamp authorities.
    pub tsas: Vec<TsaChain>,
}

/// One Rekor v2 log key: an Ed25519 key that signs checkpoints as signed
/// notes under `origin`.
#[derive(Debug, Clone)]
pub struct NoteLogKey {
    /// The checkpoint origin: the first line of every checkpoint, and the key
    /// name on the log's signature line.
    pub origin: String,
    /// The raw 32-byte Ed25519 public key.
    pub key: [u8; 32],
    /// SHA-256 of `origin ‖ "\n" ‖ 0x01 ‖ key`: the `trusted_root.json`
    /// `logId`. Its first four bytes are the signed-note key hash.
    pub log_id: [u8; 32],
    /// The key's validity window, in Unix seconds.
    pub window: (i64, i64),
}

impl NoteLogKey {
    /// Builds a key from its PKIX SPKI DER, which must be Ed25519.
    ///
    /// The log id follows rekor-tiles `pkg/note/note.go`
    /// (`genConformantKeyHash` with signature type 0x01 for Ed25519).
    ///
    /// # Errors
    ///
    /// [`VerificationError::TrustRootUnavailable`] when the SPKI is not an
    /// Ed25519 key.
    pub fn from_spki(
        origin: &str,
        spki_der: &[u8],
        window: (i64, i64),
    ) -> Result<Self, VerificationError> {
        use x509_parser::x509::SubjectPublicKeyInfo;
        let (rest, spki) = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|_| VerificationError::TrustRootUnavailable)?;
        if !rest.is_empty() || spki.algorithm.algorithm.to_id_string() != ED25519_OID {
            return Err(VerificationError::TrustRootUnavailable);
        }
        let key: [u8; 32] = spki
            .subject_public_key
            .data
            .as_ref()
            .try_into()
            .map_err(|_| VerificationError::TrustRootUnavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(origin.as_bytes());
        hasher.update(b"\n");
        hasher.update([0x01]);
        hasher.update(key);
        Ok(Self {
            origin: origin.to_owned(),
            key,
            log_id: hasher.finalize().into(),
            window,
        })
    }
}

/// One RFC 3161 timestamp authority: the signing leaf and its root.
#[derive(Debug, Clone)]
pub struct TsaChain {
    /// The TSA signing certificate, DER.
    pub leaf: rustls_pki_types::CertificateDer<'static>,
    /// The root that issued `leaf`, DER.
    pub root: rustls_pki_types::CertificateDer<'static>,
    /// The authority's `validFor` window, in Unix seconds.
    pub window: (i64, i64),
}

/// The dotted OID of Ed25519 (RFC 8410).
const ED25519_OID: &str = "1.3.101.112";

/// One certificate-transparency log key.
#[derive(Debug, Clone)]
pub struct CtLogKey {
    /// The RFC 6962 log id: SHA-256 of the key's SPKI DER.
    pub log_id: [u8; 32],
    /// The log's ECDSA P-256 key.
    pub key: VerifyingKey,
}

/// Parses the embedded PEM constants into a [`TrustRoot`].
///
/// # Errors
///
/// [`VerificationError::TrustRootUnavailable`] when the embedded material
/// does not parse.
pub fn embedded() -> Result<TrustRoot, VerificationError> {
    from_pems(FULCIO_ROOTS_PEM, REKOR_KEY_PEM)
}

/// Parses trust material from PEM text, with the embedded
/// [`CT_LOG_KEY_PEM`] as the CT log keys (see [`from_pems_with_ct`]).
///
/// # Errors
///
/// [`VerificationError::TrustRootUnavailable`] when the PEM material does
/// not parse.
pub fn from_pems(fulcio_pem: &str, rekor_pem: &str) -> Result<TrustRoot, VerificationError> {
    from_pems_with_ct(fulcio_pem, rekor_pem, CT_LOG_KEY_PEM)
}

/// Parses trust material from PEM text: Fulcio certificates, the Rekor key
/// and the CT log keys (one or more `PUBLIC KEY` blocks). The embedded files
/// are the only production source; tests load their own fixtures through
/// this. The Rekor v2 key and the timestamp authority are always the
/// embedded ones.
///
/// # Errors
///
/// [`VerificationError::TrustRootUnavailable`] when the PEM material does
/// not parse or holds no CT log key.
pub fn from_pems_with_ct(
    fulcio_pem: &str,
    rekor_pem: &str,
    ct_pem: &str,
) -> Result<TrustRoot, VerificationError> {
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

    let ct_logs = pems(ct_pem, "PUBLIC KEY")?
        .iter()
        .map(|spki| {
            Ok(CtLogKey {
                log_id: Sha256::digest(spki).into(),
                key: spki_to_p256(spki)?,
            })
        })
        .collect::<Result<Vec<_>, VerificationError>>()?;
    if ct_logs.is_empty() {
        return Err(VerificationError::TrustRootUnavailable);
    }

    Ok(TrustRoot {
        fulcio_roots,
        rekor_key,
        root_windows,
        ct_logs,
        rekor_v2_keys: embedded_rekor_v2_keys()?,
        tsas: embedded_tsas()?,
    })
}

/// The embedded Rekor v2 log key.
fn embedded_rekor_v2_keys() -> Result<Vec<NoteLogKey>, VerificationError> {
    let [spki] = pems(REKOR_V2_KEY_PEM, "PUBLIC KEY")?
        .try_into()
        .map_err(|_| VerificationError::TrustRootUnavailable)?;
    Ok(vec![NoteLogKey::from_spki(
        REKOR_V2_ORIGIN,
        &spki,
        (REKOR_V2_VALID_FROM, i64::MAX),
    )?])
}

/// The embedded timestamp authority chain.
fn embedded_tsas() -> Result<Vec<TsaChain>, VerificationError> {
    let [leaf, root] = pems(TSA_CHAIN_PEM, "CERTIFICATE")?
        .try_into()
        .map_err(|_| VerificationError::TrustRootUnavailable)?;
    for der in [&leaf, &root] {
        X509Certificate::from_der(der).map_err(|_| VerificationError::TrustRootUnavailable)?;
    }
    Ok(vec![TsaChain {
        leaf: leaf.into(),
        root: root.into(),
        window: (TSA_VALID_FROM, i64::MAX),
    }])
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

#[cfg(test)]
mod tests {
    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The public-good Rekor log id (SHA-256 of the key's DER SPKI), from
    /// `tlogs[0].logId.keyId` of `trusted_root.json` in the `TRUST_MANIFEST`
    /// commit.
    const PUBLIC_GOOD_REKOR_LOG_ID: &str = "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=";

    /// The `ctfe.sigstore.dev/2022` log id, from `ctlogs[1].logId.keyId` of
    /// `trusted_root.json` in the `TRUST_MANIFEST` commit.
    const PUBLIC_GOOD_CT_LOG_ID: &str = "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4=";

    /// The `log2025-1.rekor.sigstore.dev` log id, from `tlogs[1].logId.keyId`
    /// of `trusted_root.json` in the `TRUST_MANIFEST` commit.
    const PUBLIC_GOOD_REKOR_V2_LOG_ID: &str = "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=";

    #[test]
    fn the_embedded_trust_root_parses() -> R {
        let trust = embedded()?;
        // SHA-256 of each certificate's DER, in file order: the
        // sigstore-intermediate, then the sigstore root
        // (`certificateAuthorities[1].certChain` of `trusted_root.json`).
        let digests: Vec<String> = trust
            .fulcio_roots
            .iter()
            .map(|der| format!("{:x}", Sha256::digest(der.as_ref())))
            .collect();
        assert_eq!(
            digests,
            [
                "15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47",
                "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1",
            ]
        );
        assert_eq!(trust.root_windows.len(), 2);
        Ok(())
    }

    #[test]
    fn the_embedded_fulcio_intermediate_chains_to_the_embedded_root() -> R {
        let trust = embedded()?;
        let mut certs = Vec::new();
        for der in &trust.fulcio_roots {
            let (_, cert) = X509Certificate::from_der(der.as_ref())?;
            certs.push(cert);
        }
        let root = certs
            .iter()
            .find(|cert| cert.subject() == cert.issuer())
            .ok_or("no self-signed root")?;
        let intermediate = certs
            .iter()
            .find(|cert| cert.subject() != cert.issuer())
            .ok_or("no intermediate")?;
        assert_eq!(intermediate.issuer(), root.subject());
        assert!(intermediate.is_ca() && root.is_ca());
        let root_key = root.public_key().subject_public_key.data.as_ref();
        for cert in [intermediate, root] {
            webpki::aws_lc_rs::ECDSA_P384_SHA384
                .verify_signature(
                    root_key,
                    cert.tbs_certificate.as_ref(),
                    cert.signature_value.data.as_ref(),
                )
                .map_err(|_| "signature does not verify under the root key")?;
        }
        Ok(())
    }

    #[test]
    fn the_embedded_rekor_key_is_the_public_good_log_key() -> R {
        let spki = pem_body(REKOR_KEY_PEM.as_bytes(), "PUBLIC KEY").ok_or("no PUBLIC KEY block")?;
        assert_eq!(
            BASE64.encode(Sha256::digest(&spki)),
            PUBLIC_GOOD_REKOR_LOG_ID
        );
        embedded()?;
        Ok(())
    }

    #[test]
    fn the_embedded_ct_key_is_the_2022_log_key() -> R {
        let spki =
            pem_body(CT_LOG_KEY_PEM.as_bytes(), "PUBLIC KEY").ok_or("no PUBLIC KEY block")?;
        assert_eq!(BASE64.encode(Sha256::digest(&spki)), PUBLIC_GOOD_CT_LOG_ID);
        let trust = embedded()?;
        let [log] = trust.ct_logs.as_slice() else {
            return Err("expected exactly one CT log key".into());
        };
        assert_eq!(BASE64.encode(log.log_id), PUBLIC_GOOD_CT_LOG_ID);
        Ok(())
    }

    #[test]
    fn the_embedded_rekor_v2_key_is_the_log2025_1_key() -> R {
        let trust = embedded()?;
        let [log] = trust.rekor_v2_keys.as_slice() else {
            return Err("expected exactly one Rekor v2 key".into());
        };
        assert_eq!(BASE64.encode(log.log_id), PUBLIC_GOOD_REKOR_V2_LOG_ID);
        assert_eq!(log.origin, "log2025-1.rekor.sigstore.dev");
        assert_eq!(log.window, (1_758_585_600, i64::MAX));
        Ok(())
    }

    #[test]
    fn a_rekor_v2_key_must_be_ed25519() -> R {
        let spki = pem_body(REKOR_KEY_PEM.as_bytes(), "PUBLIC KEY").ok_or("no PUBLIC KEY block")?;
        assert!(matches!(
            NoteLogKey::from_spki(REKOR_V2_ORIGIN, &spki, (0, i64::MAX)),
            Err(VerificationError::TrustRootUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn the_embedded_tsa_is_the_public_good_tsa_and_chains_to_its_root() -> R {
        let trust = embedded()?;
        let [tsa] = trust.tsas.as_slice() else {
            return Err("expected exactly one timestamp authority".into());
        };
        // SHA-256 of `timestampAuthorities[0].certChain` of
        // `trusted_root.json`: the leaf, then the root.
        assert_eq!(
            format!("{:x}", Sha256::digest(tsa.leaf.as_ref())),
            "85f927bc07ab62cac3b44356c10efc81b2c6883fda7ab9e6d870d9d13acd05b7"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(tsa.root.as_ref())),
            "2aca8fea5d3ce48b01cc77076293c280e6c23ffe44034757ee7833ca9f45d633"
        );
        assert_eq!(tsa.window, (1_751_587_200, i64::MAX));

        let (_, leaf) = X509Certificate::from_der(tsa.leaf.as_ref())?;
        let (_, root) = X509Certificate::from_der(tsa.root.as_ref())?;
        assert_eq!(leaf.issuer(), root.subject());
        assert_eq!(root.issuer(), root.subject());
        assert!(root.is_ca() && !leaf.is_ca());
        let root_key = root.public_key().subject_public_key.data.as_ref();
        for cert in [&leaf, &root] {
            webpki::aws_lc_rs::ECDSA_P384_SHA384
                .verify_signature(
                    root_key,
                    cert.tbs_certificate.as_ref(),
                    cert.signature_value.data.as_ref(),
                )
                .map_err(|_| "signature does not verify under the TSA root key")?;
        }
        Ok(())
    }
}
