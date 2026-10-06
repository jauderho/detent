# ADR-014: In-tree Sigstore bundle verifier
Status: Accepted (2026-09-18)
Deciders: project owner (per PLAN Phase 9 and spike 01)

## Context

ADR-005 requires keyless Sigstore verification of self-update binaries with a
pinned workflow identity. Spike 01 (`docs/spikes/01-sigstore-size.md`)
measured the `sigstore` 0.14 crate at **+1.95 MiB / +139 crates** on
aarch64-unknown-linux-musl, found that even its `rustls-tls` feature drags in
`reqwest` (banned by PLAN §4.2 and ADR-009), duplicates the RustCrypto stack
across 16 version pairs, and **panics at verifier construction** on static
musl systems with no CA bundle. The decision stands; the mechanism is the
PLAN §2.9 fallback: a minimal in-tree verifier. This ADR is its build spec.

The verifier is **fully offline**: bundles from `actions/attest` carry enough
material (certificate chain, Rekor inclusion proof) to verify with no network,
using the embedded trust root only.

## Decision

`detent-update` verifies Sigstore bundles in-tree with: `rustls`/`webpki`
certificate-chain verification (already in the dependency tree), the RustCrypto
0.11 stack already present (`p256` ecdsa, `sha2`), and the single shared
hyper-rustls client (no new HTTP code — the verifier itself performs zero I/O).
No `reqwest`, no `sigstore` crate, no system CA store.

### Bundle shape consumed

The v0.3 Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`)
emitted by GitHub `actions/attest`:

```json
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "x509CertificateChain": { "certificates": [ "<base64 DER, leaf first>" ] },
    "tlogEntries": [ {
      "logIndex": 123, "integratedTime": 1758000000,
      "logId": { "keyId": "<base64>" },
      "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
      "canonicalizedBody": "<base64 hashedrekord JSON>",
      "inclusionPromise": { "signedEntryTimestamp": "<base64 DER ECDSA by the Rekor key>" },
      "inclusionProof": {
        "logIndex": 123, "treeSize": 456,
        "checkpoint": { "envelope": "<Rekor checkpoint text>" },
        "hashes": [ "<base64 sibling hashes>" ]
      }
    } ]
  },
  "dsseEnvelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "<base64 in-toto statement>",
    "signatures": [ { "keyid": "", "sig": "<base64 ECDSA-P256 over PAE>" } ]
  }
}
```

The `payload` decodes to an in-toto v1 statement:
`{"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": …,
"digest": {"sha256": …}}], "predicateType": "https://slsa.dev/provenance/v1", …}`.
Parsing uses `deny_unknown_fields`-style strictness on the envelope fields the
verifier consumes; unknown extra fields are tolerated (GitHub may extend
predicates), but a missing `mediaType`, `verificationMaterial`, `tlogEntries`,
`inclusionProof`, `inclusionPromise`, or `dsseEnvelope` is a hard error. The
v0.3 single-certificate form `verificationMaterial.certificate` (`{"rawBytes":
…}`) is accepted in place of `x509CertificateChain`.

### Verification steps, in order

Any failing step aborts with the corresponding `VerificationError` (below).
No partial state, no retries with weaker checks.

1. **Decode bundle** — parse JSON, size-cap at 1 MiB (larger = refuse).
2. **Certificate chain** — build the chain from
   `verificationMaterial.x509CertificateChain`, verify signatures and validity
   windows to the **embedded Fulcio roots** (never the system store). Validity
   is checked at `integratedTime` of the tlog entry, not "now" — bundles stay
   verifiable after the leaf expires.
3. **Identity pinning** — leaf certificate:
   - URI SAN **must equal**
     `https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/<tag>`
     where `<tag>` is the exact tag being updated to (ADR-005).
   - OIDC issuer extension (OID `1.3.6.1.4.1.57264.1.1`) **must equal**
     `https://token.actions.githubusercontent.com`.
4. **DSSE signature** — verify `signatures[0].sig` as ECDSA P-256 over the
   DSSE PAE (`DSSEv1 <len payloadType> <payloadType> <len payload> <payload>`)
   using the leaf's public key. PAE is constructed in-tree per the DSSE spec.
5. **Subject digest** — the statement's `subject[]` must contain exactly one
   entry whose `digest.sha256` equals the SHA-256 of the downloaded file.
   Zero or multiple matching subjects = refuse (ambiguous).
6. **Rekor inclusion** — verify `inclusionProof`: recompute the Merkle
   root from `hashes` + the leaf hash `SHA-256(0x00 ‖ canonicalizedBody)`
   (RFC 6962; the leaf covers the body only), and parse the `checkpoint`
   envelope as a signed note (origin, size, base64 root, optional other
   lines, a blank line, then `— <name> <base64(key hint ‖ DER signature)>`
   lines). Its size must **equal** the proof's tree size and its root must
   equal the recomputed root. At least one signature line must carry the
   hint of the **embedded Rekor log public key** (the first four bytes of
   SHA-256 over its SPKI DER, as Rekor `pkg/util/signed_note.go` computes
   it), and that signature must verify over the body including its final
   newline; lines with another hint are ignored. The
   `canonicalizedBody` must agree with the envelope: for `hashedrekord`, the
   same signature bytes and a public key equal to the leaf certificate's key;
   for `dsse`/`intoto`, the same signature bytes and a payload hash equal to
   the SHA-256 of the envelope payload. Then verify the Rekor signed entry
   timestamp (`inclusionPromise.signedEntryTimestamp`): an ECDSA P-256
   SHA-256 signature by the embedded Rekor key over the RFC 8785 JSON
   `{"body":<base64 canonicalizedBody>,"integratedTime":…,"logID":<hex keyId>,"logIndex":…}`
   (as Rekor `VerifySignedEntryTimestamp` and sigstore-go `VerifySET`). The
   SET is the only signature over `integratedTime`, the instant step 2 uses.

   **Embedded SCTs** (every leaf, with the current issuer extension
   1.3.6.1.4.1.57264.1.8 or only the legacy 1.3.6.1.4.1.57264.1.1): at least
   one SCT in the leaf must name the log id
   of an embedded CT log key and carry a valid ECDSA P-256 SHA-256 signature
   over the RFC 6962 §3.2 `precert_entry` data: the SHA-256 of the issuing
   CA's SPKI (the embedded or bundled certificate whose key verifies the
   leaf) and the leaf `TBSCertificate` with the SCT list extension removed.
   Otherwise `SctInvalid`. The self-minted fixtures carry SCTs by a test CT
   key (`tests/fixtures/ctfe-pub.pem`, loaded with
   `trust::from_pems_with_ct`). Unknown entry kinds fall
   through to the `hashedrekord` body check (H17 step 6).

### Embedded trust root and refresh procedure

Trust material is embedded at build time (PLAN §2.9 step 4) in
`crates/detent-update/trust/`: the Fulcio intermediate and root certificates
(each an anchor; v0.3 bundles carry only the leaf), the Rekor log public
key and the `ctfe.sigstore.dev/2022` CT log public key, extracted from Sigstore's `trusted_root.json` (2026-10-03: root-signing
commit 5888f35, recorded in `trust::TRUST_MANIFEST`).

For Rekor v2 (BUGFIX Track E 7, not yet wired into `verify`) the same
`trusted_root.json` also gives the `log2025-1.rekor.sigstore.dev` Ed25519
key (origin and `validFor` start as constants) and the `timestamp.sigstore.dev`
TSA leaf and root. Those are proven against `trusted_root.json` only: log id
and certificate digests, and the TSA chain signatures (`trust.rs` tests). The
Ed25519 checkpoint check (`verify::verify_v2_checkpoint`) is proven against
real **staging** material only (`tests/fixtures/staging-rekor-v2/`, from
sigstore-python, Apache-2.0): no public-good Rekor v2 bundle exists yet.
The same holds for the RFC 3161 check (`tsa::verify_timestamp`): it is
proven on the staging token with the staging TSA chain. It accepts only
status `granted` (0), as sigstore-go does; a SHA-256/384/512 imprint over the
DSSE signature; one `SignerInfo` that names the TSA leaf and whose ECDSA
signature over the signed attributes verifies with the leaf key; a matching
message digest and `ESSCertIDv2` (an SHA-1 `ESSCertID` is refused); a leaf
with a critical `timeStamping`-only EKU; and a UTC `genTime` inside the TSA
window and the leaf validity. Certificates in the token are ignored.

Refresh procedure (per release, and out-of-band when Sigstore rotates roots):
1. Fetch the current Sigstore TUF snapshot with the TUF client and verify the
   metadata chain up to the pinned TUF root (the only pinned secret).
2. Extract the active Fulcio root CA(s), Rekor log key, CT log key, Rekor v2
   log key (with origin and `validFor`) and TSA chain (with `validFor`).
3. Write them to `crates/detent-update/trust/` as PEM files, and set
   `TRUST_MANIFEST` to the source commit and `trusted_root.json` SHA-256.
   Do not copy a retired CA: the verifier honours the certificate's own
   validity, not `trusted_root.json` `validFor`.
4. Commit in the release PR; the release binary then carries the refreshed
   root. Multiple roots with overlapping validity windows are accepted, so a
   device updating across a rotation never hits a gap. A device that cannot
   update past a root expiry must refuse closed (no trust root = no install),
   which is why refresh ships in **every** release.

### Test vectors

The bundle fixtures under `crates/detent-update/tests/fixtures/` are
self-minted by `gen-fixtures` (a test Fulcio root and a test Rekor key; real
ECDSA over the real PAE, checkpoint and SET bytes). A captured real
`actions/attest` release bundle (PLAN Phase 9 task 3, STAGE3 H17 step 8)
still needs a release tag. Two real Rekor vectors check the formats against
production: `rekor-public-good-set.json` (a public-good SET and the Rekor
key, from sigstore-go) and `rekor-staging-proof.json` (a body, leaf hash and
inclusion proof to Rekor's root hash, from sigstore-python). Required set —
every one must fail or pass for the stated reason, asserted by test:

| Fixture | Expected |
|---|---|
| `valid.json` | passes all six steps |
| `wrong-identity.json` | step 3 fails: SAN ≠ pinned workflow identity (different repo/workflow ref) |
| `no-sct.json` | step 3 fails: the leaf has no SCT (`SctInvalid`) |
| `wrong-digest.json` | step 5 fails: subject digest ≠ file SHA-256 |
| `expired-leaf.json` | step 2 fails: leaf validity window excludes `integratedTime` |
| `bad-checkpoint-sig.json` | step 6 fails: checkpoint signature does not verify against the embedded Rekor key |
| `bad-body-sig.json` | step 6 fails: tlog body carries a signature other than the envelope's |
| `bad-body-key.json` | step 6 fails: tlog body names a key other than the leaf's |
| `bad-inclusion-path.json` | step 6 fails: a corrupted path hash gives a root the checkpoint does not sign |
| `bad-set.json` | step 6 fails: the SET is signed by a key other than the embedded Rekor key |

### Error taxonomy

```rust
enum VerificationError {
    BundleMalformed,      // step 1: unparsable, oversized, missing material
    CertChainInvalid,     // step 2: chain does not verify to embedded Fulcio roots
    CertExpired,          // step 2: leaf invalid at integratedTime
    IdentityMismatch,     // step 3: SAN != pinned workflow identity
    IssuerMismatch,       // step 3: OIDC issuer extension != GitHub Actions issuer
    SignatureInvalid,     // step 4: DSSE signature does not verify
    DigestMismatch,       // step 5: subject digest != file digest (or ambiguous subject)
    SetInvalid,           // step 6: Rekor inclusion proof / checkpoint / body / SET fails
    SctInvalid,           // step 3: no embedded SCT verifies against an embedded CT log key
    TimestampInvalid,     // Rekor v2: the RFC 3161 timestamp does not verify (not wired yet)
    TrustRootUnavailable, // no embedded root valid at integratedTime (rotation gap)
}
```

**Refuse-closed:** every variant aborts the update. Unreachable Rekor or
Fulcio infrastructure is not a downgrade path — the verifier needs no network,
so "infrastructure unavailability" means the bundle itself lacks tlog
material or no embedded root is valid, and in both cases the update is
refused. **Never** install an unverified binary; the failed state is recorded
and the current binary keeps running.

## Consequences

Positive:
- Zero added HTTP stack, zero system-CA dependency, no panic path at
  construction (spike 01's three blockers), no duplicate RustCrypto versions.
- Fully offline verification suits headless SBC devices and air-gapped
  deployments.
- The pinned identity means only builds from `release.yml` at the exact tag
  can pass.

Negative:
- ~6 cryptographic checks to maintain in-tree; upstream Sigstore protocol
  changes (bundle versions, Fulcio extension OIDs) land as our patches, not
  a dependency bump.
- Test fixtures must be re-captured if the bundle format version changes;
  the mediaType is pinned to v0.3 and unknown major bumps are refused.

## Alternatives considered

- The `sigstore` crate — rejected: reqwest duplication, RustCrypto stack
  duplication, CA-store panic on musl (spike 01).
- SHA-256 sums alone — rejected: no provenance; ADR-005 requires both.
- Vendoring `sigstore` behind a feature — rejected: same transitive cost when
  enabled, second client stack permanently under review pressure.

## References

PLAN.md §2.9 (self-update, step 4 trust-root refresh), §4.2 (banned deps),
Phase 9 (task 3 fixtures); ADR-005 (identity pins, refuse-closed), ADR-009
(single HTTP stack), ADR-011 (cooldown); spike 01
(`docs/spikes/01-sigstore-size.md`); Sigstore bundle spec v0.3, DSSE PAE
spec, RFC 6962 Merkle trees; `docs/RELEASING.md` (release verification).
