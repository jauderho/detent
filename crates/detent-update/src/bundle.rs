//! The Sigstore bundle (v0.3, ADR-014): JSON shape, size cap, and the
//! fully-decoded view the verifier consumes.
//!
//! Strictness follows ADR-014: every field the verifier consumes is required —
//! a missing `mediaType`, `verificationMaterial`, `tlogEntries`,
//! `inclusionProof`, or `dsseEnvelope` is a hard error — while unknown extra
//! fields are tolerated, because GitHub may extend the predicate at any time.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;

/// Largest accepted bundle, in bytes (ADR-014 step 1).
pub const MAX_BUNDLE_BYTES: usize = 1 << 20;

/// Longest inclusion path accepted. RFC 9162 trees of at most 2^64 leaves
/// never need more than 64 sibling hashes; a longer path is refused before
/// any of it is decoded.
pub const MAX_INCLUSION_PATH: usize = 64;

/// The only bundle media type this verifier consumes (ADR-014: pinned to
/// v0.3; unknown major bumps are refused).
pub const MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// The in-toto envelope payload type emitted by Sigstore attestations.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Older synthetic fixtures used the generic DSSE media type. Accept it only
/// for backwards compatibility with those fixtures; production bundles use
/// [`DSSE_PAYLOAD_TYPE`].
pub const LEGACY_DSSE_PAYLOAD_TYPE: &str = "application/vnd.dsse.envelope.v1+json";

/// The in-toto statement type the payload must declare.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// A bundle error. Folded into [`crate::VerificationError::BundleMalformed`]
/// at the verify boundary; kept separate so tests can name the reason.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum BundleError {
    /// The bundle exceeded [`MAX_BUNDLE_BYTES`].
    #[error("bundle exceeds the {MAX_BUNDLE_BYTES}-byte cap")]
    Oversized,
    /// The JSON was unparsable or a required field was missing.
    #[error("bundle is malformed: {0}")]
    Malformed(String),
    /// The media type was not [`MEDIA_TYPE`].
    #[error("unsupported bundle media type: {0}")]
    BadMediaType(String),
    /// A base64 field did not decode.
    #[error("bundle contains undecodable base64: {0}")]
    BadBase64(&'static str),
    /// The decoded payload was not a well-formed in-toto v1 statement.
    #[error("payload is not a valid in-toto v1 statement: {0}")]
    BadStatement(&'static str),
}

/// The bundle as JSON, all fields the verifier consumes required.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleJson {
    media_type: String,
    verification_material: VerificationMaterialJson,
    dsse_envelope: DsseEnvelopeJson,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterialJson {
    #[serde(default)]
    x509_certificate_chain: Option<X509ChainJson>,
    #[serde(default)]
    certificate: Option<CertificateJson>,
    #[serde(default)]
    tlog_entries: Vec<TlogEntryJson>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CertificateJson {
    Raw(String),
    Wrapped {
        #[serde(rename = "rawBytes")]
        raw_bytes: String,
    },
}

impl CertificateJson {
    fn bytes(&self) -> &str {
        match self {
            Self::Raw(raw) | Self::Wrapped { raw_bytes: raw } => raw,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X509ChainJson {
    /// Base64 DER, leaf first (ADR-014). Sigstore v0.3 permits either a raw
    /// string or an object with `rawBytes` in this list.
    certificates: Vec<CertificateJson>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogEntryJson {
    #[serde(deserialize_with = "de_i64")]
    log_index: i64,
    #[serde(deserialize_with = "de_i64")]
    integrated_time: i64,
    log_id: LogIdJson,
    kind_version: KindVersionJson,
    canonicalized_body: String,
    inclusion_promise: InclusionPromiseJson,
    inclusion_proof: InclusionProofJson,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionPromiseJson {
    /// Base64 DER ECDSA signature by the Rekor key (the SET).
    signed_entry_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogIdJson {
    key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KindVersionJson {
    kind: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionProofJson {
    #[serde(deserialize_with = "de_i64")]
    log_index: i64,
    #[serde(deserialize_with = "de_u64")]
    tree_size: u64,
    checkpoint: CheckpointJson,
    hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointJson {
    envelope: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseEnvelopeJson {
    payload_type: String,
    payload: String,
    signatures: Vec<SignatureJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureJson {
    sig: String,
}
fn de_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(i64),
        String(String),
    }
    match NumberOrString::deserialize(deserializer)? {
        NumberOrString::Number(value) => Ok(value),
        NumberOrString::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn de_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(u64),
        String(String),
    }
    match NumberOrString::deserialize(deserializer)? {
        NumberOrString::Number(value) => Ok(value),
        NumberOrString::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

/// The in-toto v1 statement carried in the DSSE payload.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    /// The in-toto statement type: [`STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// The attested artifacts; the verifier requires exactly one match.
    pub subject: Vec<Subject>,
}

/// One attested artifact.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    /// The artifact name, e.g. `detent-aarch64-unknown-linux-musl`.
    pub name: String,
    /// The artifact's digests.
    pub digest: SubjectDigest,
}

/// The digests of one subject; only `sha256` is consumed.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectDigest {
    /// The SHA-256 of the artifact, 64 lowercase hex characters.
    pub sha256: String,
}

/// A fully decoded bundle: everything the six verification steps need, no
/// base64 left in it.
#[derive(Debug)]
pub struct Decoded {
    /// `integratedTime` of the tlog entry, in Unix seconds; the chain is
    /// validated at this instant, not now (ADR-014 step 2).
    pub integrated_time: i64,
    /// DER certificates, leaf first; `certs[0]` is the leaf, the rest are
    /// intermediates in order.
    pub certs: Vec<Vec<u8>>,
    /// The decoded in-toto statement.
    pub statement: Statement,
    /// The raw DSSE payload bytes (the statement JSON).
    pub dsse_payload: Vec<u8>,
    /// The DSSE payload type.
    pub dsse_payload_type: String,
    /// The decoded DSSE signature (DER ECDSA).
    pub dsse_signature: Vec<u8>,
    /// `logIndex` of the tlog entry.
    pub log_index: i64,
    /// The tlog entry's `keyId`, decoded.
    pub log_key_id: Vec<u8>,
    /// The tlog entry kind, e.g. `hashedrekord`.
    pub kind: String,
    /// The tlog entry version, e.g. `0.0.1`.
    pub kind_version: String,
    /// The canonicalized (hashedrekord) body, decoded JSON.
    pub body: Vec<u8>,
    /// `treeSize` the proof was computed against.
    pub tree_size: u64,
    /// The proof's leaf index within the tree.
    pub proof_log_index: i64,
    /// Sibling hashes along the inclusion path, decoded, leaf-upwards.
    pub path_hashes: Vec<Vec<u8>>,
    /// The checkpoint envelope text (body and signature lines).
    pub checkpoint: String,
    /// The Rekor signed entry timestamp (`inclusionPromise`), decoded DER.
    /// It is the only signature that binds `integratedTime` to the entry.
    pub signed_entry_timestamp: Vec<u8>,
}

/// Parses and decodes a bundle, enforcing the 1 MiB cap and the strict field
/// set.
///
/// # Errors
///
/// [`BundleError`] naming the first thing wrong, in ADR-014 step order:
/// size, JSON shape, media type, base64, then statement.
pub fn parse(bytes: &[u8]) -> Result<Decoded, BundleError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::Oversized);
    }
    let json: BundleJson =
        serde_json::from_slice(bytes).map_err(|err| BundleError::Malformed(err.to_string()))?;
    if json.media_type != MEDIA_TYPE {
        return Err(BundleError::BadMediaType(json.media_type));
    }

    let cert_json = json
        .verification_material
        .x509_certificate_chain
        .as_ref()
        .map(|chain| chain.certificates.as_slice())
        .or_else(|| {
            json.verification_material
                .certificate
                .as_ref()
                .map(std::slice::from_ref)
        })
        .unwrap_or_default();
    if cert_json.is_empty() {
        return Err(BundleError::Malformed(
            "bundle carries no X.509 certificate".to_owned(),
        ));
    }
    let tlog = json
        .verification_material
        .tlog_entries
        .first()
        .ok_or_else(|| BundleError::Malformed("no tlog entries".to_owned()))?;

    let dsse_payload = decode(json.dsse_envelope.payload.as_bytes(), "dsse payload")?;
    if json.dsse_envelope.payload_type != DSSE_PAYLOAD_TYPE
        && json.dsse_envelope.payload_type != LEGACY_DSSE_PAYLOAD_TYPE
    {
        return Err(BundleError::Malformed(format!(
            "unexpected DSSE payload type: {}",
            json.dsse_envelope.payload_type
        )));
    }
    if json.dsse_envelope.signatures.len() != 1 {
        return Err(BundleError::Malformed(
            "Sigstore bundles must carry exactly one DSSE signature".to_owned(),
        ));
    }
    let first_signature = json
        .dsse_envelope
        .signatures
        .first()
        .ok_or_else(|| BundleError::Malformed("no DSSE signatures".to_owned()))?;
    let dsse_signature = decode(first_signature.sig.as_bytes(), "dsse signature")?;

    let statement: Statement = serde_json::from_slice(&dsse_payload)
        .map_err(|_| BundleError::BadStatement("unparsable"))?;
    if statement.statement_type != STATEMENT_TYPE {
        return Err(BundleError::BadStatement("wrong _type"));
    }
    if statement.subject.is_empty() {
        return Err(BundleError::BadStatement("no subjects"));
    }
    for subject in &statement.subject {
        if subject.digest.sha256.len() != 64
            || !subject
                .digest
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BundleError::BadStatement(
                "subject digest is not hex sha256",
            ));
        }
    }

    let mut certs = Vec::with_capacity(cert_json.len());
    for cert in cert_json {
        certs.push(decode(cert.bytes().as_bytes(), "certificate")?);
    }

    Ok(Decoded {
        integrated_time: tlog.integrated_time,
        certs,
        statement,
        dsse_payload,
        dsse_payload_type: json.dsse_envelope.payload_type,
        dsse_signature,
        log_index: tlog.log_index,
        log_key_id: decode(tlog.log_id.key_id.as_bytes(), "log key id")?,
        kind: tlog.kind_version.kind.clone(),
        kind_version: tlog.kind_version.version.clone(),
        body: decode(tlog.canonicalized_body.as_bytes(), "canonicalized body")?,
        tree_size: tlog.inclusion_proof.tree_size,
        proof_log_index: tlog.inclusion_proof.log_index,
        path_hashes: decode_path(&tlog.inclusion_proof.hashes)?,
        checkpoint: tlog.inclusion_proof.checkpoint.envelope.clone(),
        signed_entry_timestamp: decode(
            tlog.inclusion_promise.signed_entry_timestamp.as_bytes(),
            "signed entry timestamp",
        )?,
    })
}

/// Decode an inclusion path, refusing one longer than [`MAX_INCLUSION_PATH`]
/// before any hash is decoded.
fn decode_path(hashes: &[String]) -> Result<Vec<Vec<u8>>, BundleError> {
    if hashes.len() > MAX_INCLUSION_PATH {
        return Err(BundleError::Malformed(format!(
            "inclusion path is longer than {MAX_INCLUSION_PATH} hashes"
        )));
    }
    hashes
        .iter()
        .map(|hash| decode(hash.as_bytes(), "inclusion path hash"))
        .collect()
}

fn decode(raw: &[u8], field: &'static str) -> Result<Vec<u8>, BundleError> {
    BASE64
        .decode(raw)
        .map_err(|_| BundleError::BadBase64(field))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A parsable statement, base64-encoded, for [`minimal`].
    const STATEMENT_B64: &str = "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YxIiwic3ViamVjdCI6W3sibmFtZSI6ImRldGVudCIsImRpZ2VzdCI6eyJzaGEyNTYiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIn19XX0=";

    /// The smallest bundle-shaped JSON every mutation test starts from.
    fn minimal() -> serde_json::Value {
        serde_json::json!({
            "mediaType": MEDIA_TYPE,
            "verificationMaterial": {
                "x509CertificateChain": { "certificates": ["AAAA"] },
                "tlogEntries": [{
                    "logIndex": 0, "integratedTime": 1_758_000_000,
                    "logId": { "keyId": "AAAA" },
                    "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
                    "canonicalizedBody": "AAAA",
                    "inclusionPromise": { "signedEntryTimestamp": "AAAA" },
                    "inclusionProof": {
                        "logIndex": 0, "treeSize": 1,
                        "checkpoint": { "envelope": "name 1\nAAAA\n\nQUJD\n" },
                        "hashes": ["AAAA"]
                    }
                }]
            },
            "dsseEnvelope": {
                "payloadType": DSSE_PAYLOAD_TYPE,
                "payload": STATEMENT_B64,
                "signatures": [ { "keyid": "", "sig": "AAAA" } ]
            }
        })
    }

    /// A bundle JSON mutated by `change`, plus a generous budget for the
    /// unknown-field tolerance check.
    fn parse_json(value: &serde_json::Value) -> Result<Decoded, BundleError> {
        parse(value.to_string().as_bytes())
    }

    #[test]
    fn accepts_minimal_shape_and_tolerates_unknown_fields() {
        let mut value = minimal();
        value["extraTopLevel"] = serde_json::json!({"github": "may extend this"});
        value["dsseEnvelope"]["signatures"][0]["extra"] = serde_json::json!(1);
        let decoded = parse_json(&value).map_err(|err| err.to_string());
        let decoded = decoded.expect("minimal bundle parses");
        assert_eq!(decoded.integrated_time, 1_758_000_000);
        assert_eq!(decoded.kind, "hashedrekord");
        assert_eq!(decoded.certs.len(), 1);
    }

    #[test]
    fn accepts_sigstore_certificate_objects_and_in_toto_payload_type() {
        let mut value = minimal();
        value["verificationMaterial"]["x509CertificateChain"]["certificates"] =
            serde_json::json!([{ "rawBytes": "AAAA" }]);
        value["dsseEnvelope"]["payloadType"] = serde_json::json!(DSSE_PAYLOAD_TYPE);
        let decoded = parse_json(&value).expect("real Sigstore envelope shape parses");
        assert_eq!(decoded.certs, vec![vec![0, 0, 0]]);
        assert_eq!(decoded.dsse_payload_type, DSSE_PAYLOAD_TYPE);
    }

    #[test]
    fn refuses_an_inclusion_path_longer_than_the_cap() {
        let mut value = minimal();
        let path = |len: usize| serde_json::json!(vec!["AAAA"; len]);
        value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"] =
            path(MAX_INCLUSION_PATH);
        assert!(parse_json(&value).is_ok(), "a path at the cap parses");
        value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"] =
            path(MAX_INCLUSION_PATH.saturating_add(1));
        assert!(matches!(parse_json(&value), Err(BundleError::Malformed(_))));
    }

    #[test]
    fn a_bundle_without_a_set_is_refused() {
        // Real v0.3 bundles carry the Rekor SET; without it integratedTime is
        // unauthenticated, so the bundle is refused at parse time.
        for field in [
            "/verificationMaterial/tlogEntries/0/inclusionPromise",
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        ] {
            let mut value = minimal();
            remove_pointer(&mut value, field);
            assert!(
                matches!(parse_json(&value), Err(BundleError::Malformed(_))),
                "missing {field} must be refused"
            );
        }
    }

    #[test]
    fn refuses_oversized() {
        let filler = vec![b'a'; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(parse(&filler), Err(BundleError::Oversized)));
    }

    #[test]
    fn refuses_unparsable_json() {
        assert!(matches!(
            parse(b"{not json"),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn refuses_missing_required_fields() {
        for field in [
            "/mediaType",
            "/verificationMaterial/x509CertificateChain",
            "/verificationMaterial/tlogEntries",
            "/verificationMaterial/tlogEntries/0/inclusionProof",
            "/dsseEnvelope/payload",
            "/dsseEnvelope/signatures",
        ] {
            let mut value = minimal();
            remove_pointer(&mut value, field);
            assert!(
                parse_json(&value).is_err(),
                "missing {field} must be refused"
            );
        }
    }

    #[test]
    fn refuses_wrong_media_type() {
        let mut value = minimal();
        value["mediaType"] = serde_json::json!("application/vnd.dev.sigstore.bundle.v0.4+json");
        assert!(matches!(
            parse_json(&value),
            Err(BundleError::BadMediaType(_))
        ));
    }

    #[test]
    fn refuses_undecodable_base64() {
        for field in [
            "/dsseEnvelope/payload",
            "/dsseEnvelope/signatures/0/sig",
            "/verificationMaterial/x509CertificateChain/certificates/0",
            "/verificationMaterial/tlogEntries/0/logId/keyId",
            "/verificationMaterial/tlogEntries/0/canonicalizedBody",
            "/verificationMaterial/tlogEntries/0/inclusionProof/hashes/0",
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        ] {
            let mut value = minimal();
            let slot = pointer_mut(&mut value, field);
            *slot = serde_json::json!("not base64!");
            assert!(
                matches!(parse_json(&value), Err(BundleError::BadBase64(_))),
                "{field} must name its base64 failure"
            );
        }
    }

    #[test]
    fn refuses_bad_statement_shapes() {
        // Wrong _type.
        let payload = serde_json::json!({
            "_type": "https://example.com/other",
            "subject": [{ "name": "detent", "digest": { "sha256": &"0".repeat(64) } }]
        });
        let mut value = minimal();
        value["dsseEnvelope"]["payload"] = serde_json::json!(BASE64.encode(payload.to_string()));
        assert!(matches!(
            parse_json(&value),
            Err(BundleError::BadStatement("wrong _type"))
        ));

        // No subjects.
        let payload = serde_json::json!({
            "_type": STATEMENT_TYPE,
            "subject": []
        });
        let mut value = minimal();
        value["dsseEnvelope"]["payload"] = serde_json::json!(BASE64.encode(payload.to_string()));
        assert!(matches!(
            parse_json(&value),
            Err(BundleError::BadStatement("no subjects"))
        ));

        // Unparsable payload.
        let mut value = minimal();
        value["dsseEnvelope"]["payload"] = serde_json::json!(BASE64.encode(b"{"));
        assert!(matches!(
            parse_json(&value),
            Err(BundleError::BadStatement("unparsable"))
        ));

        // Subject digest not 64 hex.
        let payload = serde_json::json!({
            "_type": STATEMENT_TYPE,
            "subject": [{ "name": "detent", "digest": { "sha256": "zz" } }]
        });
        let mut value = minimal();
        value["dsseEnvelope"]["payload"] = serde_json::json!(BASE64.encode(payload.to_string()));
        assert!(matches!(
            parse_json(&value),
            Err(BundleError::BadStatement(
                "subject digest is not hex sha256"
            ))
        ));
    }

    #[test]
    fn refuses_bad_payload_type_and_empty_chain_and_no_signatures() {
        let mut value = minimal();
        value["dsseEnvelope"]["payloadType"] = serde_json::json!("application/other");
        assert!(matches!(parse_json(&value), Err(BundleError::Malformed(_))));

        let mut value = minimal();
        value["verificationMaterial"]["x509CertificateChain"]["certificates"] =
            serde_json::json!([]);
        assert!(matches!(parse_json(&value), Err(BundleError::Malformed(_))));

        let mut value = minimal();
        value["dsseEnvelope"]["signatures"] = serde_json::json!([]);
        assert!(matches!(parse_json(&value), Err(BundleError::Malformed(_))));

        let mut value = minimal();
        value["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        assert!(matches!(parse_json(&value), Err(BundleError::Malformed(_))));
    }

    // -- tiny JSON pointer helpers (test-only; serde_json has no remover) --

    fn remove_pointer(value: &mut serde_json::Value, pointer: &str) {
        let path: Vec<&str> = pointer.split('/').skip(1).collect();
        remove_path(value, &path);
    }

    fn remove_path(value: &mut serde_json::Value, path: &[&str]) {
        let Some((head, rest)) = path.split_first() else {
            return;
        };
        if rest.is_empty() {
            if let Some(map) = value.as_object_mut() {
                map.remove(*head);
            }
            return;
        }
        if let Ok(key) = head.parse::<usize>()
            && let Some(entry) = value.as_array_mut().and_then(|array| array.get_mut(key))
        {
            remove_path(entry, rest);
        } else if let Some(entry) = value.as_object_mut().and_then(|map| map.get_mut(*head)) {
            remove_path(entry, rest);
        }
    }

    /// `pointer_mut` never misses here: every pointer above is written
    /// against [`minimal`].
    #[allow(clippy::expect_used)]
    fn pointer_mut<'a>(
        value: &'a mut serde_json::Value,
        pointer: &str,
    ) -> &'a mut serde_json::Value {
        value
            .pointer_mut(pointer)
            .expect("every pointer in this test hits minimal()")
    }
}
