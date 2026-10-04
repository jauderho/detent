# Trust root (ADR-014, PLAN §2.9 step 4)

`fulcio-root.pem` and `rekor-pub.pem` are embedded into the binary at compile
time (`include_str!` from `src/trust.rs`) and are the *only* trust anchors the
self-update verifier accepts: never the system store, never anything fetched
at runtime (refuse-closed, ADR-014).

The files hold the Sigstore public-good material from `trusted_root.json`;
`TRUST_MANIFEST` in `src/trust.rs` names the source commit and digest.
Material that does not parse fails every verification with
`VerificationError::TrustRootUnavailable` — no root, no install.

## File contract

| File | Contents | Format |
| --- | --- | --- |
| `fulcio-root.pem` | The active Fulcio CA chain: intermediate, then root | PEM (`CERTIFICATE`), one after another; every certificate is a trust anchor, used only while its own validity window covers `integratedTime`. The intermediate must be here: a v0.3 bundle carries only the leaf. Multiple CAs with overlapping windows are all honored, so a device updating across a rotation never hits a gap |
| `rekor-pub.pem` | The Rekor v1 log public key (`rekor.sigstore.dev`) | PEM (`PUBLIC KEY`, PKIX SPKI), ECDSA P-256 |

Text outside the PEM blocks is ignored.

## Refresh procedure (every release, and out-of-band on Sigstore rotation)

1. Fetch the current Sigstore TUF snapshot (use a TUF client or the `sigstore`
   CLI) and verify the metadata chain up to the pinned TUF root — the pinned
   TUF root is the only secret in this whole procedure.
2. From the `trusted_root.json` target, take the `certChain` of each
   `certificateAuthorities` entry for `https://fulcio.sigstore.dev` whose
   `validFor` is still open, and the `publicKey` of the
   `https://rekor.sigstore.dev` tlog. Each `rawBytes` is base64 DER.
3. Write the certificates as PEM, chain order, into `fulcio-root.pem`; write
   the Rekor key as PEM into `rekor-pub.pem`. Update the pinned digests and
   log id in the `src/trust.rs` tests.
4. Set `TRUST_MANIFEST` in `src/trust.rs` to the source commit and the
   SHA-256 of `trusted_root.json`, so the provenance of the embedded roots is
   greppable.
5. Commit in the release PR. The release binary then carries the refreshed
   root; refresh ships in **every** release so no device is stranded past a
   root expiry (ADR-014).

A device that cannot update past a root expiry refuses closed: no valid
embedded root at `integratedTime` is `TrustRootUnavailable`, never a downgrade
path.
