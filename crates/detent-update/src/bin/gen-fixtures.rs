//! Mints the synthetic-but-shaped Sigstore fixtures under `tests/fixtures/`
//! (PLAN Phase 9 task 3; run with `--features fixture-gen`).
//!
//! A fixed test CA plays the Fulcio root, a fixed P-256 key plays the Rekor
//! log, another plays the CT log that signs each leaf's embedded SCT, a fixed
//! Ed25519 key plays the Rekor v2 log and a fixed test CA plays the RFC 3161
//! timestamp authority; every signature is real ECDSA over the real PAE / checkpoint bytes,
//! so the six verification steps fail for their cryptographic reasons. When
//! the first real `v0.0.1-rc` bundle is captured, these are replaced (ADR-014
//! test-vector table).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::expect_used,
    clippy::format_collect,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::unwrap_used,
    clippy::useless_vec
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::pkcs8::EncodePrivateKey as _;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// The tag the fixtures attest. It stays above any real `CARGO_PKG_VERSION`
/// because the real monitor refuses a downgrade.
const TAG: &str = "v99.0.0";
/// The integratedTime baked into every fixture (2026-09-18, fixture mint day).
const INTEGRATED_TIME: i64 = 1_786_780_800;
/// The "binary" the valid bundle attests.
const BINARY: &[u8] = b"detent synthetic binary fixture";

fn key(hex: &str) -> SigningKey {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("fixed hex");
    }
    SigningKey::from_bytes(&p256::FieldBytes::from(bytes)).expect("fixed scalar")
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// P-256 SPKI DER for a verifying key.
fn spki_der(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_sec1_point(false);
    let mut der = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    der.extend_from_slice(point.as_bytes());
    der
}

/// P-256 SPKI PEM for a verifying key.
fn spki_pem(key: &SigningKey) -> String {
    pem("PUBLIC KEY", &spki_der(key))
}

fn pkcs8(key: &SigningKey) -> Vec<u8> {
    key.to_pkcs8_der().expect("fixed key").as_bytes().to_vec()
}

fn leaf_keypair(key: &SigningKey) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8(key).into(), &rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("fixed pkcs8")
}

struct Material {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key: SigningKey,
    rekor_key: SigningKey,
}

/// The fixed test CT log key; its public key is `tests/fixtures/ctfe-pub.pem`.
fn ct_key() -> SigningKey {
    key("8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0")
}

/// DER TLV with a minimal-length encoding.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("short length"));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&byte| byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length bytes"));
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// The SCT list extension content (an OCTET STRING around the TLS list) with
/// one RFC 6962 precert SCT by [`ct_key`] over `tbs`, the leaf TBS without
/// the SCT extension, issued by the CA whose SPKI DER is `issuer_spki`. The
/// form is the one `verify` checks.
fn sct_extension(issuer_spki: &[u8], tbs: &[u8]) -> Vec<u8> {
    let timestamp = (u64::try_from(INTEGRATED_TIME).expect("positive time") * 1000).to_be_bytes();
    let mut signed = vec![0, 0];
    signed.extend_from_slice(&timestamp);
    signed.extend_from_slice(&[0, 1]);
    signed.extend_from_slice(&Sha256::digest(issuer_spki));
    signed.extend_from_slice(&u32::try_from(tbs.len()).expect("tbs length").to_be_bytes()[1..]);
    signed.extend_from_slice(tbs);
    signed.extend_from_slice(&[0, 0]);
    let signature: p256::ecdsa::Signature = ct_key().sign(&signed);
    let signature = encode_sig(&signature);

    let mut sct = vec![0];
    sct.extend_from_slice(&Sha256::digest(spki_der(&ct_key())));
    sct.extend_from_slice(&timestamp);
    sct.extend_from_slice(&[0, 0, 4, 3]);
    sct.extend_from_slice(
        &u16::try_from(signature.len())
            .expect("sig length")
            .to_be_bytes(),
    );
    sct.extend_from_slice(&signature);
    let sct_len = u16::try_from(sct.len()).expect("sct length");
    let mut list = (sct_len + 2).to_be_bytes().to_vec();
    list.extend_from_slice(&sct_len.to_be_bytes());
    list.extend_from_slice(&sct);
    der(0x04, &list)
}

/// Mints the test CA and a leaf carrying `identity` in its URI SAN and,
/// when `with_sct`, an SCT by the test CT log.
fn mint(identity: &str, not_before: i64, not_after: i64, with_sct: bool) -> Material {
    let root_key = key("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    let root_keypair = leaf_keypair(&root_key);
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.not_before = OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
    root_params.not_after = OffsetDateTime::from_unix_timestamp(2_500_000_000).unwrap();
    root_params.distinguished_name = rcgen::DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "detent fixture root");
    let root = root_params.self_signed(&root_keypair).expect("fixed root");
    let issuer = Issuer::from_params(&root_params, &root_keypair);

    let leaf_key = key("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    let leaf_keypair = leaf_keypair(&leaf_key);
    let mut leaf_params = CertificateParams::default();
    leaf_params.not_before = OffsetDateTime::from_unix_timestamp(not_before).unwrap();
    leaf_params.not_after = OffsetDateTime::from_unix_timestamp(not_after).unwrap();
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "detent fixture leaf");
    leaf_params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(identity.to_owned()).expect("ascii identity"),
    )];
    // Fulcio's OIDC-issuer extension (ADR-014 step 3).
    leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
        b"https://token.actions.githubusercontent.com".to_vec(),
    )];
    let mut leaf = leaf_params.signed_by(&leaf_keypair, &issuer).expect("leaf");
    if with_sct {
        // The precertificate is this leaf without the SCT extension; the
        // serial is derived from the leaf key, so the second signing gives
        // the same TBS plus the extension.
        let (_, precert) = x509_parser::parse_x509_certificate(leaf.der()).expect("precert");
        let content = sct_extension(&spki_der(&root_key), precert.tbs_certificate.as_ref());
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
                content,
            ));
        leaf = leaf_params.signed_by(&leaf_keypair, &issuer).expect("leaf");
    }

    Material {
        root_der: root.der().to_vec(),
        leaf_der: leaf.der().to_vec(),
        leaf_key,
        rekor_key: key("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
    }
}

/// The in-toto statement subject for the fixture binary.
fn statement(digest_hex: &str) -> Value {
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{ "name": "detent", "digest": { "sha256": digest_hex } }],
        "predicateType": "https://slsa.dev/provenance/v1"
    })
}

/// Builds one bundle around `material`; `mutate` corrupts one field.
fn bundle_for(material: &Material, digest_hex: &str, mutate: &str) -> Value {
    let payload_json = statement(digest_hex).to_string();
    let payload_type = detent_update::bundle::DSSE_PAYLOAD_TYPE;
    let pae = detent_update::verify::dsse_pae(payload_type.as_bytes(), payload_json.as_bytes());
    let sig: p256::ecdsa::Signature = material.leaf_key.sign(&pae);

    let mut dsse_sig = encode_sig(&sig);
    if mutate == "bad-signature" {
        // Flip one byte of the DER signature.
        dsse_sig[10] ^= 0x01;
    }

    let body = tlog_body(material, &sig, digest_hex, mutate);

    // Inclusion proof over a two-leaf tree: this entry and a fixed neighbor.
    // Rekor's log id is the SHA-256 of its public key's SPKI DER.
    let log_key_digest = Sha256::digest(spki_der(&material.rekor_key));
    let log_key_id = BASE64.encode(&log_key_digest[..]);

    // The SET: the Rekor key's signature over the canonical entry payload.
    // bad-set is signed by another key over the same payload.
    let set_payload = detent_update::verify::rekor_set_payload(
        body.to_string().as_bytes(),
        INTEGRATED_TIME,
        &log_key_digest,
        0,
    );
    let set_signer = if mutate == "bad-set" {
        key("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80")
    } else {
        material.rekor_key.clone()
    };
    let set: p256::ecdsa::Signature = set_signer.sign(set_payload.as_bytes());
    // Rekor's Merkle leaf is the canonicalized body alone (RFC 6962).
    let entry_leaf = leaf_hash(body.to_string().as_bytes());
    let sibling = leaf_hash(b"ABC");
    let root = merged(entry_leaf, sibling);
    let mut path_hashes = vec![sibling.to_vec()];
    let proof_log_index = 0_i64;

    // The checkpoint, a signed note: origin, tree size and base64(root) on
    // separate lines, a blank line, then `\u{2014} <name> <b64(hint || DER)>`.
    // The Rekor key signs the body lines including the trailing newline; the
    // hint is the first four bytes of the SHA-256 of the key's SPKI DER.
    let checkpoint_body = format!("detent-fixture - 1\n2\n{}\n", BASE64.encode(root));
    let checkpoint_sig: p256::ecdsa::Signature =
        material.rekor_key.sign(checkpoint_body.as_bytes());
    let mut checkpoint_sig_raw = log_key_digest[..4].to_vec();
    checkpoint_sig_raw.extend_from_slice(&encode_sig(&checkpoint_sig));

    // Per-fixture mutations after the valid construction.
    match mutate {
        "bad-inclusion-path" => {
            // Corrupt one path hash: the recomputed root diverges from the
            // checkpoint, which itself still verifies - inclusion fails.
            path_hashes[0][0] ^= 0xff;
        }
        "bad-checkpoint-sig" => {
            // Flip one byte of the DER signature, after the key hint: the
            // hint still names the Rekor key, so the signature is what fails.
            checkpoint_sig_raw[10] ^= 0x01;
        }
        "wrong-identity" | "expired-leaf" | "valid" | "bad-signature" | "bad-body-sig"
        | "bad-body-key" | "bad-set" => {}
        other => panic!("unknown fixture {other}"),
    }

    json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [BASE64.encode(&material.leaf_der), BASE64.encode(&material.root_der)]
            },
            "tlogEntries": [{
                "logIndex": 0,
                "integratedTime": INTEGRATED_TIME,
                "logId": { "keyId": log_key_id },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
                "canonicalizedBody": BASE64.encode(body.to_string().as_bytes()),
                "inclusionPromise": { "signedEntryTimestamp": BASE64.encode(encode_sig(&set)) },
                "inclusionProof": {
                    "logIndex": proof_log_index,
                    "treeSize": 2_u64,
                    "checkpoint": { "envelope": format!("{checkpoint_body}\n\u{2014} detent-fixture {}\n", BASE64.encode(&checkpoint_sig_raw)) },
                    "hashes": path_hashes.iter().map(|h| BASE64.encode(h)).collect::<Vec<_>>(),
                }
            }]
        },
        "dsseEnvelope": {
            "payloadType": payload_type,
            "payload": BASE64.encode(payload_json.as_bytes()),
            "signatures": [{ "keyid": "", "sig": BASE64.encode(&dsse_sig) }]
        }
    })
}

/// The hashedrekord tlog body for `sig`, as `mutate` shapes it.
fn tlog_body(
    material: &Material,
    sig: &p256::ecdsa::Signature,
    digest_hex: &str,
    mutate: &str,
) -> Value {
    // The tlog body normally repeats the envelope's signature and the leaf
    // key. The bad-body-* fixtures swap one of them before the inclusion
    // proof and checkpoint are computed, so both stay valid over the altered
    // body and only step 6's body-agreement check can refuse it.
    let body_sig = if mutate == "bad-body-sig" {
        let other: p256::ecdsa::Signature = material.leaf_key.sign(b"another statement");
        encode_sig(&other)
    } else {
        encode_sig(sig)
    };
    let body_key = if mutate == "bad-body-key" {
        spki_pem(&key(
            "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
        ))
    } else {
        spki_pem(&material.leaf_key)
    };
    json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha256", "value": digest_hex } },
            "signature": {
                "content": BASE64.encode(body_sig),
                "publicKey": BASE64.encode(body_key.as_bytes()),
            }
        }
    })
}

fn encode_sig(sig: &p256::ecdsa::Signature) -> Vec<u8> {
    sig.to_der().as_bytes().to_vec()
}

/// RFC 6962 leaf hash: SHA256(0x00 || entry).
fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// RFC 6962 interior node: SHA256(0x01 || left || right).
fn merged(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The checkpoint origin of the fixture Rekor v2 log; tests pass it to
/// `trust::from_pems_with_v2`.
const V2_ORIGIN: &str = "log.fixture.detent.test";

/// The fixed test Rekor v2 log key: Ed25519, PKCS#8 v1 around a fixed seed.
fn v2_log_key() -> KeyPair {
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(&[0xa1; 32]);
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8.into(), &rcgen::PKCS_ED25519)
        .expect("fixed Ed25519 key")
}

/// The fixture Rekor v2 log id: SHA-256 of `origin ‖ "\n" ‖ 0x01 ‖ key`.
fn v2_log_id() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(V2_ORIGIN.as_bytes());
    hasher.update(b"\n\x01");
    hasher.update(rcgen::PublicKeyData::der_bytes(&v2_log_key()));
    hasher.finalize().into()
}

/// The fixture timestamp authority: a P-256 leaf with a critical
/// `timeStamping`-only extended key usage, issued by a P-256 root.
struct Tsa {
    leaf_der: Vec<u8>,
    root_der: Vec<u8>,
    leaf_key: SigningKey,
}

fn mint_tsa() -> Tsa {
    let root_key = key("b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0");
    let root_keypair = leaf_keypair(&root_key);
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.not_before = OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
    root_params.not_after = OffsetDateTime::from_unix_timestamp(2_500_000_000).unwrap();
    root_params.distinguished_name = rcgen::DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "detent fixture tsa root");
    let root = root_params.self_signed(&root_keypair).expect("tsa root");
    let issuer = Issuer::from_params(&root_params, &root_keypair);

    let leaf_key = key("c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0");
    let mut leaf_params = CertificateParams::default();
    leaf_params.not_before = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    leaf_params.not_after = OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap();
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "detent fixture tsa");
    // extKeyUsage, critical, SEQUENCE { id-kp-timeStamping } (RFC 3161 §2.3).
    let mut eku = CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        vec![
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
        ],
    );
    eku.set_criticality(true);
    leaf_params.custom_extensions = vec![eku];
    let leaf = leaf_params
        .signed_by(&leaf_keypair(&leaf_key), &issuer)
        .expect("tsa leaf");
    Tsa {
        leaf_der: leaf.der().to_vec(),
        root_der: root.der().to_vec(),
        leaf_key,
    }
}

/// A DER `GeneralizedTime` value, `YYYYMMDDHHMMSSZ`.
fn generalized_time(unix: i64) -> String {
    let at = OffsetDateTime::from_unix_timestamp(unix).expect("time");
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// One CMS `Attribute` with a single value.
fn attribute(oid: &[u8], value: &[u8]) -> Vec<u8> {
    der(0x30, &[der(0x06, oid), der(0x31, value)].concat())
}

/// An RFC 3161 `TimeStampResp` by `tsa` over `signed_bytes` at `gen_time`,
/// in the form `tsa::verify_timestamp` checks: one `SignerInfo` naming the
/// TSA leaf by issuer and serial, content-type, message-digest and
/// `ESSCertIDv2` signed attributes, ECDSA P-256 SHA-256. `corrupt` flips the
/// last byte of the CMS signature.
fn timestamp_token(tsa: &Tsa, signed_bytes: &[u8], gen_time: i64, corrupt: bool) -> Vec<u8> {
    const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const TST_INFO: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
    ];
    const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    const SIGNING_CERTIFICATE_V2: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
    ];
    const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    // 1.3.6.1.4.1.57264.2, the Sigstore TSA policy.
    const POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x02];

    let sha256 = der(0x30, &[der(0x06, SHA256), vec![0x05, 0x00]].concat());
    let tst_info = der(
        0x30,
        &[
            der(0x02, &[0x01]),
            der(0x06, POLICY),
            der(
                0x30,
                &[sha256.clone(), der(0x04, &Sha256::digest(signed_bytes))].concat(),
            ),
            der(0x02, &[0x01]),
            der(0x18, generalized_time(gen_time).as_bytes()),
        ]
        .concat(),
    );
    let ess_cert_id_v2 = der(
        0x30,
        &der(0x30, &der(0x30, &der(0x04, &Sha256::digest(&tsa.leaf_der)))),
    );
    let attributes = [
        attribute(CONTENT_TYPE, &der(0x06, TST_INFO)),
        attribute(MESSAGE_DIGEST, &der(0x04, &Sha256::digest(&tst_info))),
        attribute(SIGNING_CERTIFICATE_V2, &ess_cert_id_v2),
    ]
    .concat();
    let signature: p256::ecdsa::Signature = tsa.leaf_key.sign(&der(0x31, &attributes));
    let mut signature = encode_sig(&signature);
    if corrupt {
        *signature.last_mut().expect("signature") ^= 0x01;
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(&tsa.leaf_der).expect("tsa leaf");
    let signer_info = der(
        0x30,
        &[
            der(0x02, &[0x01]),
            der(
                0x30,
                &[
                    leaf.tbs_certificate.issuer.as_raw().to_vec(),
                    der(0x02, leaf.tbs_certificate.raw_serial()),
                ]
                .concat(),
            ),
            sha256.clone(),
            der(0xa0, &attributes),
            der(0x30, &der(0x06, ECDSA_SHA256)),
            der(0x04, &signature),
        ]
        .concat(),
    );
    let signed_data = der(
        0x30,
        &[
            der(0x02, &[0x03]),
            der(0x31, &sha256),
            der(
                0x30,
                &[der(0x06, TST_INFO), der(0xa0, &der(0x04, &tst_info))].concat(),
            ),
            der(0x31, &signer_info),
        ]
        .concat(),
    );
    let content_info = der(
        0x30,
        &[der(0x06, SIGNED_DATA), der(0xa0, &signed_data)].concat(),
    );
    der(
        0x30,
        &[der(0x30, &der(0x02, &[0x00])), content_info].concat(),
    )
}

/// `timestampVerificationData` with one token, or none.
fn timestamps(token: Option<Vec<u8>>) -> Value {
    json!({ "rfc3161Timestamps": token.map(|token| vec![json!({ "signedTimestamp": BASE64.encode(token) })]).unwrap_or_default() })
}

/// A Rekor v2 bundle around `material`: a `hashedrekord` 0.0.2 entry over the
/// DSSE PAE, an inclusion proof to a two-leaf root, an Ed25519 checkpoint by
/// [`v2_log_key`], and an RFC 3161 timestamp by `tsa` over the DSSE
/// signature. `mutate` is `v2-valid`, `v2-no-timestamp` or
/// `v2-bad-timestamp`.
fn bundle_v2(material: &Material, tsa: &Tsa, digest_hex: &str, mutate: &str) -> Value {
    let payload_json = statement(digest_hex).to_string();
    let payload_type = detent_update::bundle::DSSE_PAYLOAD_TYPE;
    let pae = detent_update::verify::dsse_pae(payload_type.as_bytes(), payload_json.as_bytes());
    let sig: p256::ecdsa::Signature = material.leaf_key.sign(&pae);
    let dsse_sig = encode_sig(&sig);

    // The canonical (RFC 8785) body `verify` rebuilds and compares.
    let body = format!(
        concat!(
            r#"{{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{{"hashedRekordV002":{{"#,
            r#""data":{{"algorithm":"SHA2_256","digest":"{}"}},"#,
            r#""signature":{{"content":"{}","verifier":{{"keyDetails":"PKIX_ECDSA_P256_SHA_256","#,
            r#""x509Certificate":{{"rawBytes":"{}"}}}}}}}}}}}}"#,
        ),
        BASE64.encode(Sha256::digest(&pae)),
        BASE64.encode(&dsse_sig),
        BASE64.encode(&material.leaf_der),
    );
    let sibling = leaf_hash(b"ABC");
    let root = merged(leaf_hash(body.as_bytes()), sibling);
    let log_id = v2_log_id();
    let checkpoint_body = format!("{V2_ORIGIN}\n2\n{}\n", BASE64.encode(root));
    let mut note_signature = log_id[..4].to_vec();
    note_signature.extend_from_slice(
        &rcgen::SigningKey::sign(&v2_log_key(), checkpoint_body.as_bytes()).expect("sign"),
    );
    let token = match mutate {
        "v2-valid" => Some(timestamp_token(tsa, &dsse_sig, INTEGRATED_TIME, false)),
        "v2-bad-timestamp" => Some(timestamp_token(tsa, &dsse_sig, INTEGRATED_TIME, true)),
        "v2-no-timestamp" => None,
        other => panic!("unknown v2 fixture {other}"),
    };

    json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": { "rawBytes": BASE64.encode(&material.leaf_der) },
            "tlogEntries": [{
                "logIndex": "0",
                "logId": { "keyId": BASE64.encode(log_id) },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
                "canonicalizedBody": BASE64.encode(body.as_bytes()),
                "inclusionProof": {
                    "logIndex": "0",
                    "treeSize": "2",
                    "checkpoint": { "envelope": format!("{checkpoint_body}\n\u{2014} {V2_ORIGIN} {}\n", BASE64.encode(&note_signature)) },
                    "hashes": [BASE64.encode(sibling)],
                }
            }],
            "timestampVerificationData": timestamps(token),
        },
        "dsseEnvelope": {
            "payloadType": payload_type,
            "payload": BASE64.encode(payload_json.as_bytes()),
            "signatures": [{ "keyid": "", "sig": BASE64.encode(&dsse_sig) }]
        }
    })
}

/// `bundle` (Rekor v1) with an RFC 3161 timestamp by `tsa` over its DSSE
/// signature.
fn with_timestamp(mut bundle: Value, tsa: &Tsa) -> Value {
    let dsse_sig = BASE64
        .decode(
            bundle["dsseEnvelope"]["signatures"][0]["sig"]
                .as_str()
                .expect("sig"),
        )
        .expect("base64");
    bundle["verificationMaterial"]["timestampVerificationData"] = timestamps(Some(
        timestamp_token(tsa, &dsse_sig, INTEGRATED_TIME, false),
    ));
    bundle
}

/// The Rekor v2 and RFC 3161 fixtures: the v2 bundles, `valid.json` with a
/// timestamp, the fixture v2 log key and the fixture TSA chain.
fn write_rekor_v2_fixtures(dir: &std::path::Path, valid: &Material, digest_hex: &str) {
    let tsa = mint_tsa();
    for name in ["v2-valid", "v2-no-timestamp", "v2-bad-timestamp"] {
        write(
            dir,
            &format!("{name}.json"),
            bundle_v2(valid, &tsa, digest_hex, name),
        );
    }
    write(
        dir,
        "valid-with-timestamp.json",
        with_timestamp(bundle_for(valid, digest_hex, "valid"), &tsa),
    );
    write(
        dir,
        "rekor-v2-pub.pem",
        serde_json::to_value(pem(
            "PUBLIC KEY",
            &rcgen::PublicKeyData::subject_public_key_info(&v2_log_key()),
        ))
        .expect("text"),
    );
    write(
        dir,
        "tsa-chain.pem",
        serde_json::to_value(format!(
            "{}{}",
            pem("CERTIFICATE", &tsa.leaf_der),
            pem("CERTIFICATE", &tsa.root_der)
        ))
        .expect("text"),
    );
}

fn main() {
    let dir = std::path::Path::new("tests/fixtures");
    std::fs::create_dir_all(dir).expect("fixture dir");

    let pinned = detent_update::verify::pinned_identity(TAG);
    let digest_hex = hex(&Sha256::digest(BINARY));

    // Valid leaf, valid at integratedTime.
    let valid = mint(&pinned, 1_700_000_000, 1_900_000_000, true);
    // Wrong-identity leaf: same validity, a different SAN.
    let wrong = mint(
        &format!("https://github.com/other/repo/.github/workflows/release.yml@refs/tags/{TAG}"),
        1_700_000_000,
        1_900_000_000,
        true,
    );
    // Expired leaf: not valid at integratedTime.
    let expired = mint(&pinned, 1_800_000_000, 1_900_000_000, true);
    // A leaf with no SCT: otherwise valid, refused for the missing SCT.
    let no_sct = mint(&pinned, 1_700_000_000, 1_900_000_000, false);

    write(dir, "valid.json", bundle_for(&valid, &digest_hex, "valid"));
    write(
        dir,
        "no-sct.json",
        bundle_for(&no_sct, &digest_hex, "valid"),
    );
    write(
        dir,
        "wrong-identity.json",
        bundle_for(&wrong, &digest_hex, "valid"),
    );
    write(
        dir,
        "expired-leaf.json",
        bundle_for(&expired, &digest_hex, "valid"),
    );
    write(
        dir,
        "bad-signature.json",
        bundle_for(&valid, &digest_hex, "bad-signature"),
    );
    write(
        dir,
        "bad-inclusion-path.json",
        bundle_for(&valid, &digest_hex, "bad-inclusion-path"),
    );
    write(
        dir,
        "bad-set.json",
        bundle_for(&valid, &digest_hex, "bad-set"),
    );
    write(
        dir,
        "bad-checkpoint-sig.json",
        bundle_for(&valid, &digest_hex, "bad-checkpoint-sig"),
    );
    write(
        dir,
        "bad-body-sig.json",
        bundle_for(&valid, &digest_hex, "bad-body-sig"),
    );
    write(
        dir,
        "bad-body-key.json",
        bundle_for(&valid, &digest_hex, "bad-body-key"),
    );
    // A consistent bundle whose statement attests some other file: every
    // step before 5 passes, and the subject misses binary.bin's digest.
    write(
        dir,
        "wrong-digest.json",
        bundle_for(&valid, &hex(&Sha256::digest(b"another binary")), "valid"),
    );
    let older = mint(
        &detent_update::verify::pinned_identity("v0.0.0"),
        1_700_000_000,
        1_900_000_000,
        true,
    );
    write(
        dir,
        "older-tag.json",
        bundle_for(&older, &digest_hex, "valid"),
    );
    write_rekor_v2_fixtures(dir, &valid, &digest_hex);
    std::fs::write(dir.join("binary.bin"), BINARY).expect("write binary");

    write(
        dir,
        "fulcio-root.pem",
        serde_json::to_value(pem("CERTIFICATE", &valid.root_der)).expect("text"),
    );
    write(
        dir,
        "rekor-pub.pem",
        serde_json::to_value(spki_pem(&valid.rekor_key)).expect("text"),
    );
    write(
        dir,
        "ctfe-pub.pem",
        serde_json::to_value(spki_pem(&ct_key())).expect("text"),
    );
    println!("fixtures written to {}", dir.display());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write(dir: &std::path::Path, name: &str, value: Value) {
    if name.ends_with(".json") {
        std::fs::write(
            dir.join(name),
            serde_json::to_vec_pretty(&value).expect("json"),
        )
        .expect("write fixture");
    } else {
        std::fs::write(dir.join(name), value.as_str().expect("pem text")).expect("write pem");
    }
}
