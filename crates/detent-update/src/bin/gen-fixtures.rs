//! Mints the synthetic-but-shaped Sigstore fixtures under `tests/fixtures/`
//! (PLAN Phase 9 task 3; run with `--features fixture-gen`).
//!
//! A fixed test CA plays the Fulcio root, a fixed P-256 key plays the Rekor
//! log; every signature is real ECDSA over the real PAE / checkpoint bytes,
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

/// The tag the fixtures attest.
const TAG: &str = "v0.0.2";
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
    let point = key.verifying_key().to_encoded_point(false);
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

/// Mints the test CA and a leaf carrying `identity` in its URI SAN.
fn mint(identity: &str, not_before: i64, not_after: i64) -> Material {
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
    let leaf = leaf_params.signed_by(&leaf_keypair, &issuer).expect("leaf");

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

    // The checkpoint: origin, tree size, base64(sha256(root)), signed by the
    // Rekor key over the body lines including the trailing newline.
    let checkpoint_body = format!(
        "detent-fixture 2\n{}\n",
        BASE64.encode(Sha256::digest(root))
    );
    let checkpoint_sig: p256::ecdsa::Signature =
        material.rekor_key.sign(checkpoint_body.as_bytes());
    let mut checkpoint_sig_text = BASE64.encode(encode_sig(&checkpoint_sig));

    // Per-fixture mutations after the valid construction.
    match mutate {
        "bad-inclusion-path" => {
            // Corrupt one path hash: the recomputed root diverges from the
            // checkpoint, which itself still verifies - inclusion fails.
            path_hashes[0][0] ^= 0xff;
        }
        "bad-checkpoint-sig" => {
            // Corrupt the checkpoint signature.
            checkpoint_sig_text = format!(
                "u{}",
                checkpoint_sig_text
                    .get(1..)
                    .map(str::to_owned)
                    .unwrap_or_default()
            );
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
                    "checkpoint": { "envelope": format!("{checkpoint_body}\n{checkpoint_sig_text}\n") },
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

fn main() {
    let dir = std::path::Path::new("tests/fixtures");
    std::fs::create_dir_all(dir).expect("fixture dir");

    let pinned = detent_update::verify::pinned_identity(TAG);
    let digest_hex = hex(&Sha256::digest(BINARY));

    // Valid leaf, valid at integratedTime.
    let valid = mint(&pinned, 1_700_000_000, 1_900_000_000);
    // Wrong-identity leaf: same validity, a different SAN.
    let wrong = mint(
        "https://github.com/other/repo/.github/workflows/release.yml@refs/tags/v0.0.2",
        1_700_000_000,
        1_900_000_000,
    );
    // Expired leaf: not valid at integratedTime.
    let expired = mint(&pinned, 1_800_000_000, 1_900_000_000);

    write(dir, "valid.json", bundle_for(&valid, &digest_hex, "valid"));
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
    );
    write(
        dir,
        "older-tag.json",
        bundle_for(&older, &digest_hex, "valid"),
    );
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
