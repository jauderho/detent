//! RFC 3161 timestamp verification (BUGFIX Track E 7, Rekor v2).
//!
//! A Rekor v2 entry carries no signed `integratedTime`; the signing time is
//! the `genTime` of an RFC 3161 timestamp over the DSSE signature, signed by
//! an embedded timestamp authority ([`crate::trust::TsaChain`]). This module
//! checks one such timestamp. It is not yet called by [`crate::verify`].
//!
//! The checks follow sigstore-go `pkg/root/timestamping_authority.go` and
//! sigstore timestamp-authority `pkg/verification/verify.go`
//! (`VerifyTimestampResponse`), which parses with digitorus `timestamp` and
//! `pkcs7`. The DER is walked by hand along fixed paths; anything else is
//! refused.

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_parser::asn1_rs::{ASN1TimeZone, GeneralizedTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer as _;

use crate::trust::TsaChain;
use crate::verify::{VerificationError, der_tlv};

/// The largest timestamp response accepted, in bytes. A Sigstore response
/// without embedded certificates is under 1 KiB.
pub const MAX_TIMESTAMP_BYTES: usize = 16 * 1024;

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]` constructed: explicit content, `certificates`, `signedAttrs`.
const CONTEXT_0: u8 = 0xa0;
/// `[1]` constructed: `crls`, `unsignedAttrs`.
const CONTEXT_1: u8 = 0xa1;
/// `[0]` primitive: a `SignerIdentifier` `subjectKeyIdentifier`.
const CONTEXT_0_PRIMITIVE: u8 = 0x80;

/// id-signedData, 1.2.840.113549.1.7.2.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// id-ct-TSTInfo, 1.2.840.113549.1.9.16.1.4.
const OID_TST_INFO: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// id-contentType, 1.2.840.113549.1.9.3.
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// id-messageDigest, 1.2.840.113549.1.9.4.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// id-aa-signingCertificate (`ESSCertID`, SHA-1), 1.2.840.113549.1.9.16.2.12.
const OID_SIGNING_CERTIFICATE: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c,
];
/// id-aa-signingCertificateV2 (`ESSCertIDv2`), 1.2.840.113549.1.9.16.2.47.
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
];
/// id-sha256, 2.16.840.1.101.3.4.2.1.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-sha384, 2.16.840.1.101.3.4.2.2.
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// id-sha512, 2.16.840.1.101.3.4.2.3.
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
/// ecdsa-with-SHA256, 1.2.840.10045.4.3.2.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// ecdsa-with-SHA384, 1.2.840.10045.4.3.3.
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// Verifies an RFC 3161 `TimeStampResp` (`signedTimestamp` of a Sigstore
/// bundle) over `signed_bytes` (the DSSE signature) against `tsa`, and
/// returns its `genTime` in Unix seconds (fractions are dropped).
///
/// Every one of these must hold:
///
/// * the response is at most [`MAX_TIMESTAMP_BYTES`] and its status is
///   `granted` (0). `grantedWithMods` (1) is refused, as sigstore-go does
///   (digitorus `timestamp.ParseResponse` refuses any status above 0);
/// * the token is CMS `SignedData` with `id-ct-TSTInfo` content and exactly
///   one `SignerInfo`. Certificates in the token are ignored: only
///   `tsa.leaf` is trusted;
/// * the `TSTInfo` message imprint uses SHA-256, -384 or -512 (SHA-1 and any
///   other algorithm are refused) and equals the hash of `signed_bytes`;
/// * the signer identifier names `tsa.leaf` (issuer and serial number, or
///   subject key identifier);
/// * the signed attributes hold exactly one content type (`id-ct-TSTInfo`)
///   and one message digest, equal to the `SignerInfo` digest of the
///   `TSTInfo`; an `ESSCertIDv2` must hash `tsa.leaf`; an `ESSCertID` (SHA-1
///   only) is refused, as SHA-1 is not available here;
/// * the ECDSA signature (with SHA-256 or SHA-384) over the signed attributes,
///   re-tagged as a DER `SET OF`, verifies with the `tsa.leaf` key;
/// * `tsa.leaf` has a critical extended key usage of `timeStamping` only;
/// * `genTime` is a DER `GeneralizedTime` in UTC (`Z`), inside `tsa.window`
///   and inside the validity of `tsa.leaf`. The leaf-to-root signature is
///   checked for the embedded chain by the `trust` tests.
///
/// # Errors
///
/// [`VerificationError::TimestampInvalid`] when any check fails or the DER
/// is malformed.
pub fn verify_timestamp(
    signed_timestamp: &[u8],
    signed_bytes: &[u8],
    tsa: &TsaChain,
) -> Result<i64, VerificationError> {
    if signed_timestamp.len() > MAX_TIMESTAMP_BYTES {
        return Err(VerificationError::TimestampInvalid);
    }
    check(signed_timestamp, signed_bytes, tsa).ok_or(VerificationError::TimestampInvalid)
}

/// A cursor over the DER elements of one constructed value.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    /// The next element: (tag, contents, whole encoding). High tag numbers
    /// are refused; none of the fixed paths has one.
    fn next(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let (tag, content, rest) = der_tlv(self.0)?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let whole = self.0.get(..self.0.len().checked_sub(rest.len())?)?;
        self.0 = rest;
        Some((tag, content, whole))
    }

    /// The contents of the next element, which must carry `tag`.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (found, content, _) = self.next()?;
        (found == tag).then_some(content)
    }

    /// Skips the next element when it carries `tag`.
    fn skip_optional(&mut self, tag: u8) -> Option<()> {
        if self.0.first() == Some(&tag) {
            self.next()?;
        }
        Some(())
    }

    /// Succeeds only when every element was read.
    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

/// The contents of `bytes`, which must be exactly one element with `tag`.
fn single(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    let mut der = Der(bytes);
    let content = der.expect(tag)?;
    der.end()?;
    Some(content)
}

/// A digest algorithm the verifier accepts.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Parses the contents of a digest `AlgorithmIdentifier`: SHA-256, -384 or
/// -512, with absent or NULL parameters. Anything else (SHA-1 included) is
/// `None`.
fn hash_algorithm(algorithm_identifier: &[u8]) -> Option<Hash> {
    let mut der = Der(algorithm_identifier);
    let hash = match der.expect(OID)? {
        OID_SHA256 => Hash::Sha256,
        OID_SHA384 => Hash::Sha384,
        OID_SHA512 => Hash::Sha512,
        _ => return None,
    };
    if !der.0.is_empty() && !der.expect(NULL)?.is_empty() {
        return None;
    }
    der.end()?;
    Some(hash)
}

fn check(signed_timestamp: &[u8], signed_bytes: &[u8], tsa: &TsaChain) -> Option<i64> {
    let (_, leaf) = X509Certificate::from_der(tsa.leaf.as_ref()).ok()?;

    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken }
    let mut response = Der(single(signed_timestamp, SEQUENCE)?);
    let mut status = Der(response.expect(SEQUENCE)?);
    if status.expect(INTEGER)? != [0] {
        return None;
    }
    let token = response.expect(SEQUENCE)?;
    response.end()?;

    // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
    let mut content_info = Der(token);
    if content_info.expect(OID)? != OID_SIGNED_DATA {
        return None;
    }
    let signed_data = single(content_info.expect(CONTEXT_0)?, SEQUENCE)?;
    content_info.end()?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms,
    //   encapContentInfo, [0] certificates OPTIONAL, [1] crls OPTIONAL,
    //   signerInfos }
    let mut signed_data = Der(signed_data);
    signed_data.expect(INTEGER)?;
    signed_data.expect(SET)?;
    let mut encapsulated = Der(signed_data.expect(SEQUENCE)?);
    if encapsulated.expect(OID)? != OID_TST_INFO {
        return None;
    }
    let tst_info = single(encapsulated.expect(CONTEXT_0)?, OCTET_STRING)?;
    encapsulated.end()?;
    signed_data.skip_optional(CONTEXT_0)?;
    signed_data.skip_optional(CONTEXT_1)?;
    let signer_info = single(signed_data.expect(SET)?, SEQUENCE)?;
    signed_data.end()?;

    let gen_time = check_tst_info(tst_info, signed_bytes)?;
    check_signer_info(signer_info, tst_info, &leaf, tsa)?;
    check_leaf_usage(&leaf)?;

    let validity = leaf.validity();
    (crate::trust::window_covers(tsa.window, gen_time)
        && crate::trust::window_covers(
            (
                validity.not_before.timestamp(),
                validity.not_after.timestamp(),
            ),
            gen_time,
        ))
    .then_some(gen_time)
}

/// `TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
/// genTime, … }`: the imprint must be the hash of `signed_bytes`. Returns
/// `genTime`.
fn check_tst_info(tst_info: &[u8], signed_bytes: &[u8]) -> Option<i64> {
    let mut tst_info = Der(single(tst_info, SEQUENCE)?);
    tst_info.expect(INTEGER)?;
    tst_info.expect(OID)?;
    let mut imprint = Der(tst_info.expect(SEQUENCE)?);
    let hash = hash_algorithm(imprint.expect(SEQUENCE)?)?;
    let hashed_message = imprint.expect(OCTET_STRING)?;
    imprint.end()?;
    if hash.digest(signed_bytes) != hashed_message {
        return None;
    }
    tst_info.expect(INTEGER)?;
    generalized_time(tst_info.expect(GENERALIZED_TIME)?)
}

/// A DER `GeneralizedTime` in UTC, `YYYYMMDDHHMMSS[.fff]Z`, in Unix seconds.
fn generalized_time(content: &[u8]) -> Option<i64> {
    // Seconds are required and the decimal mark, if any, is a period.
    if !matches!(content.get(14), Some(b'.' | b'Z')) || content.contains(&b',') {
        return None;
    }
    let time = GeneralizedTime::from_bytes(content).ok()?;
    if time.0.tz != ASN1TimeZone::Z {
        return None;
    }
    Some(time.utc_datetime().ok()?.unix_timestamp())
}

/// `SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, [0] signedAttrs,
/// signatureAlgorithm, signature, [1] unsignedAttrs OPTIONAL }`.
fn check_signer_info(
    signer_info: &[u8],
    tst_info: &[u8],
    leaf: &X509Certificate<'_>,
    tsa: &TsaChain,
) -> Option<()> {
    let mut signer_info = Der(signer_info);
    match signer_info.expect(INTEGER)? {
        [1] => {
            // issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber }
            let mut sid = Der(signer_info.expect(SEQUENCE)?);
            let (_, _, issuer) = sid.next()?;
            let serial = sid.expect(INTEGER)?;
            sid.end()?;
            if issuer != leaf.tbs_certificate.issuer.as_raw()
                || serial != leaf.tbs_certificate.raw_serial()
            {
                return None;
            }
        }
        [3] => {
            let key_id = signer_info.expect(CONTEXT_0_PRIMITIVE)?;
            let matches = leaf.extensions().iter().any(|extension| {
                matches!(
                    extension.parsed_extension(),
                    ParsedExtension::SubjectKeyIdentifier(id) if id.0 == key_id
                )
            });
            if !matches {
                return None;
            }
        }
        _ => return None,
    }
    let digest = hash_algorithm(signer_info.expect(SEQUENCE)?)?;
    let (attributes_tag, attributes, attributes_whole) = signer_info.next()?;
    if attributes_tag != CONTEXT_0 {
        return None;
    }
    let mut signature_algorithm = Der(signer_info.expect(SEQUENCE)?);
    let signature_algorithm_oid = signature_algorithm.expect(OID)?;
    signature_algorithm.end()?;
    let signature = signer_info.expect(OCTET_STRING)?;
    signer_info.skip_optional(CONTEXT_1)?;
    signer_info.end()?;

    check_signed_attributes(attributes, digest, tst_info, tsa)?;

    // The signature covers the signed attributes as a DER SET OF: the same
    // bytes with the [0] IMPLICIT tag replaced (RFC 5652 §5.4).
    let mut signed = attributes_whole.to_vec();
    *signed.first_mut()? = SET;
    let algorithms = match signature_algorithm_oid {
        OID_ECDSA_SHA256 => [
            webpki::aws_lc_rs::ECDSA_P256_SHA256,
            webpki::aws_lc_rs::ECDSA_P384_SHA256,
        ],
        OID_ECDSA_SHA384 => [
            webpki::aws_lc_rs::ECDSA_P256_SHA384,
            webpki::aws_lc_rs::ECDSA_P384_SHA384,
        ],
        _ => return None,
    };
    let key = leaf.public_key().subject_public_key.data.as_ref();
    algorithms
        .iter()
        .any(|algorithm| algorithm.verify_signature(key, &signed, signature).is_ok())
        .then_some(())
}

/// The signed attributes: exactly one content type and one message digest,
/// at most one `ESSCertIDv2`, no `ESSCertID`; other attributes are allowed.
fn check_signed_attributes(
    attributes: &[u8],
    digest: Hash,
    tst_info: &[u8],
    tsa: &TsaChain,
) -> Option<()> {
    let mut content_type = None;
    let mut message_digest = None;
    let mut signing_certificate = None;
    let mut attributes = Der(attributes);
    while !attributes.0.is_empty() {
        // Attribute ::= SEQUENCE { attrType, attrValues SET OF }
        let mut attribute = Der(attributes.expect(SEQUENCE)?);
        let kind = attribute.expect(OID)?;
        let values = attribute.expect(SET)?;
        attribute.end()?;
        let slot = match kind {
            OID_CONTENT_TYPE => &mut content_type,
            OID_MESSAGE_DIGEST => &mut message_digest,
            OID_SIGNING_CERTIFICATE_V2 => &mut signing_certificate,
            OID_SIGNING_CERTIFICATE => return None,
            _ => continue,
        };
        if slot.replace(values).is_some() {
            return None;
        }
    }
    if single(content_type?, OID)? != OID_TST_INFO {
        return None;
    }
    if single(message_digest?, OCTET_STRING)? != digest.digest(tst_info) {
        return None;
    }
    if let Some(values) = signing_certificate {
        check_ess_cert_id_v2(values, tsa)?;
    }
    Some(())
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, … }`;
/// the first `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256,
/// certHash, … }` identifies the signer and must hash `tsa.leaf`.
fn check_ess_cert_id_v2(values: &[u8], tsa: &TsaChain) -> Option<()> {
    let mut signing_certificate = Der(single(values, SEQUENCE)?);
    let mut certs = Der(signing_certificate.expect(SEQUENCE)?);
    let mut cert_id = Der(certs.expect(SEQUENCE)?);
    let hash = if cert_id.0.first() == Some(&SEQUENCE) {
        hash_algorithm(cert_id.expect(SEQUENCE)?)?
    } else {
        Hash::Sha256
    };
    let cert_hash = cert_id.expect(OCTET_STRING)?;
    (hash.digest(tsa.leaf.as_ref()) == cert_hash).then_some(())
}

/// The TSA leaf must have a critical extended key usage of `timeStamping`
/// and nothing else (RFC 3161 §2.3).
fn check_leaf_usage(leaf: &X509Certificate<'_>) -> Option<()> {
    let usage = leaf.extended_key_usage().ok()??;
    let eku = usage.value;
    (usage.critical
        && eku.time_stamping
        && !eku.any
        && !eku.server_auth
        && !eku.client_auth
        && !eku.code_signing
        && !eku.email_protection
        && !eku.ocsp_signing
        && eku.other.is_empty())
    .then_some(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::*;

    type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// `genTime` of the staging token: 2026-05-13T19:23:33Z.
    const STAGING_GEN_TIME: i64 = 1_778_700_213;

    fn staging_bundle() -> R<serde_json::Value> {
        Ok(serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/a.dsse.staging-rekor-v2.txt.sigstore.json"
        ))?)
    }

    fn b64_at(value: &serde_json::Value, pointer: &str) -> R<Vec<u8>> {
        let text = value
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or(format!("no string at {pointer}"))?;
        Ok(BASE64.decode(text)?)
    }

    /// The RFC 3161 response of the staging bundle.
    fn staging_token() -> R<Vec<u8>> {
        b64_at(
            &staging_bundle()?,
            "/verificationMaterial/timestampVerificationData/rfc3161Timestamps/0/signedTimestamp",
        )
    }

    /// The DSSE signature the staging token covers.
    fn staging_signature() -> R<Vec<u8>> {
        b64_at(&staging_bundle()?, "/dsseEnvelope/signatures/0/sig")
    }

    /// The staging timestamp authority (`timestamp.sigstage.dev`) from the
    /// staging trust root; `validFor` starts 2025-04-09.
    fn staging_tsa() -> R<TsaChain> {
        let trusted: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/staging-rekor-v2/trusted_root.json"
        ))?;
        let chain = "/timestampAuthorities/0/certChain/certificates";
        Ok(TsaChain {
            leaf: b64_at(&trusted, &format!("{chain}/0/rawBytes"))?.into(),
            root: b64_at(&trusted, &format!("{chain}/1/rawBytes"))?.into(),
            window: (1_744_156_800, i64::MAX),
        })
    }

    fn check_staging(token: &[u8]) -> R<Result<i64, VerificationError>> {
        Ok(verify_timestamp(
            token,
            &staging_signature()?,
            &staging_tsa()?,
        ))
    }

    /// The offset of `needle` in `haystack`; it must occur once.
    fn offset(haystack: &[u8], needle: &[u8]) -> R<usize> {
        let found: Vec<usize> = haystack
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .map(|(at, _)| at)
            .collect();
        match found.as_slice() {
            [at] => Ok(*at),
            _ => Err(format!("needle found {} times", found.len()).into()),
        }
    }

    /// Flips the low bit of `bytes[at]`.
    fn flip(bytes: &mut [u8], at: usize) -> R {
        *bytes.get_mut(at).ok_or("offset out of range")? ^= 0x01;
        Ok(())
    }

    const REFUSED: Result<i64, VerificationError> = Err(VerificationError::TimestampInvalid);

    #[test]
    fn a_real_staging_timestamp_verifies() -> R {
        assert_eq!(check_staging(&staging_token()?)?, Ok(STAGING_GEN_TIME));
        Ok(())
    }

    #[test]
    fn a_flipped_imprint_byte_is_refused() -> R {
        let mut token = staging_token()?;
        let at = offset(&token, &Sha256::digest(staging_signature()?))?;
        flip(&mut token, at)?;
        assert_eq!(check_staging(&token)?, REFUSED);
        Ok(())
    }

    #[test]
    fn a_timestamp_over_other_bytes_is_refused() -> R {
        let mut signature = staging_signature()?;
        flip(&mut signature, 0)?;
        assert_eq!(
            verify_timestamp(&staging_token()?, &signature, &staging_tsa()?),
            REFUSED
        );
        Ok(())
    }

    #[test]
    fn a_flipped_signature_bit_is_refused() -> R {
        // The CMS signature is the last element of the response.
        let mut token = staging_token()?;
        *token.last_mut().ok_or("empty token")? ^= 0x01;
        assert_eq!(check_staging(&token)?, REFUSED);
        Ok(())
    }

    #[test]
    fn a_changed_message_digest_attribute_is_refused() -> R {
        // The message-digest attribute is SHA-256 of the TSTInfo: the 0xa4
        // content bytes of the eContent OCTET STRING `04 81 a4`.
        let mut token = staging_token()?;
        let start = offset(&token, &[0x04, 0x81, 0xa4, 0x30, 0x81, 0xa1])?
            .checked_add(3)
            .ok_or("offset")?;
        let end = start.checked_add(0xa4).ok_or("offset")?;
        let tst_info_hash = Sha256::digest(token.get(start..end).ok_or("TSTInfo")?);
        let at = offset(&token, &tst_info_hash)?;
        flip(&mut token, at)?;
        assert_eq!(check_staging(&token)?, REFUSED);
        Ok(())
    }

    #[test]
    fn the_production_tsa_does_not_verify_a_staging_timestamp() -> R {
        let trust = crate::trust::embedded()?;
        let tsa = trust.tsas.first().ok_or("no embedded TSA")?;
        assert_eq!(
            verify_timestamp(&staging_token()?, &staging_signature()?, tsa),
            REFUSED
        );
        Ok(())
    }

    #[test]
    fn gen_time_must_be_inside_the_tsa_window() -> R {
        const BEFORE: i64 = STAGING_GEN_TIME - 1;
        const AFTER: i64 = STAGING_GEN_TIME + 1;
        let token = staging_token()?;
        let signature = staging_signature()?;
        let tsa = staging_tsa()?;
        let with_window = |window| {
            let tsa = TsaChain {
                window,
                ..tsa.clone()
            };
            verify_timestamp(&token, &signature, &tsa)
        };
        assert_eq!(
            with_window((STAGING_GEN_TIME, STAGING_GEN_TIME)),
            Ok(STAGING_GEN_TIME)
        );
        assert_eq!(with_window((AFTER, i64::MAX)), REFUSED);
        assert_eq!(with_window((0, BEFORE)), REFUSED);
        Ok(())
    }

    #[test]
    fn only_the_granted_status_is_accepted() -> R {
        // PKIStatusInfo ::= SEQUENCE { INTEGER status }, at offset 4.
        let token = staging_token()?;
        assert_eq!(token.get(4..9), Some(&[0x30, 0x03, 0x02, 0x01, 0x00][..]));
        for status in [1, 2, 5] {
            let mut token = token.clone();
            *token.get_mut(8).ok_or("status")? = status;
            assert_eq!(check_staging(&token)?, REFUSED, "status {status}");
        }
        Ok(())
    }

    #[test]
    fn every_truncation_is_refused() -> R {
        let token = staging_token()?;
        for cut in 0..token.len() {
            let short = token.get(..cut).ok_or("cut")?;
            assert_eq!(check_staging(short)?, REFUSED, "cut at {cut}");
        }
        Ok(())
    }

    #[test]
    fn an_oversized_response_is_refused() -> R {
        let mut token = staging_token()?;
        token.resize(MAX_TIMESTAMP_BYTES.saturating_add(1), 0);
        assert_eq!(check_staging(&token)?, REFUSED);
        Ok(())
    }

    #[test]
    fn only_sha2_digests_are_accepted() {
        // AlgorithmIdentifier contents for SHA-1 (1.3.14.3.2.26), with and
        // without NULL parameters, and the SHA-256 control.
        let sha1 = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
        assert_eq!(hash_algorithm(&sha1), None);
        assert_eq!(hash_algorithm(&[&sha1[..], &[0x05, 0x00]].concat()), None);
        let sha256 = [&[0x06, 0x09][..], OID_SHA256, &[0x05, 0x00]].concat();
        assert_eq!(hash_algorithm(&sha256), Some(Hash::Sha256));
        assert_eq!(hash_algorithm(&[&sha256[..], &[0x05, 0x00]].concat()), None);
    }

    #[test]
    fn a_real_token_with_a_sha1_imprint_algorithm_is_refused() -> R {
        // The imprint AlgorithmIdentifier is `30 0d 06 09 <sha256> 05 00`
        // before the 32-byte hash. SHA-1's OID is shorter, so it is written
        // as the 5-byte SHA-1 OID inside the 9-byte slot, padded with an
        // empty NULL and an empty OCTET STRING to keep every length.
        let mut token = staging_token()?;
        let imprint = [
            &[0x30, 0x0d, 0x06, 0x09][..],
            OID_SHA256,
            &[0x05, 0x00, 0x04, 0x20],
        ]
        .concat();
        let at = offset(&token, &imprint)?;
        let patched = [
            0x30, 0x0d, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x00, 0x05,
            0x00,
        ];
        let end = at.checked_add(patched.len()).ok_or("offset")?;
        token
            .get_mut(at..end)
            .ok_or("imprint")?
            .copy_from_slice(&patched);
        assert_eq!(check_staging(&token)?, REFUSED);
        Ok(())
    }

    #[test]
    fn generalized_time_must_be_utc_with_seconds() {
        assert_eq!(generalized_time(b"20260513192333Z"), Some(STAGING_GEN_TIME));
        assert_eq!(
            generalized_time(b"20260513192333.5Z"),
            Some(STAGING_GEN_TIME)
        );
        assert_eq!(generalized_time(b"202605131923Z"), None);
        assert_eq!(generalized_time(b"20260513192333"), None);
        assert_eq!(generalized_time(b"20260513192333+0100"), None);
        assert_eq!(generalized_time(b"20260513192333,5Z"), None);
        assert_eq!(generalized_time(b"20260231192333Z"), None);
    }

    #[test]
    fn only_a_timestamping_leaf_can_sign() -> R {
        let tsa = staging_tsa()?;
        let (_, leaf) = X509Certificate::from_der(tsa.leaf.as_ref())?;
        assert_eq!(check_leaf_usage(&leaf), Some(()));
        let (_, root) = X509Certificate::from_der(tsa.root.as_ref())?;
        assert_eq!(check_leaf_usage(&root), None, "no EKU");
        let trust = crate::trust::embedded()?;
        let fulcio = trust.fulcio_roots.first().ok_or("no Fulcio CA")?;
        let (_, fulcio) = X509Certificate::from_der(fulcio.as_ref())?;
        assert_eq!(check_leaf_usage(&fulcio), None);
        Ok(())
    }
}
