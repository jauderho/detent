# Trust root (ADR-014, PLAN §2.9 step 4)

`fulcio-root.pem` and `rekor-pub.pem` are embedded into the binary at compile
time (`include_str!` from `src/trust.rs`) and are the *only* trust anchors the
self-update verifier accepts: never the system store, never anything fetched
at runtime (refuse-closed, ADR-014).

**Both files are placeholders right now.** They deliberately do not parse as
PEM, so every verification on this build fails with
`VerificationError::TrustRootUnavailable` — no root, no install. The real
material is captured from a Sigstore TUF snapshot at the first tagged release
(PLAN Phase 9 task 3, together with the real-bundle fixture capture).

## File contract

| File | Contents | Format |
| --- | --- | --- |
| `fulcio-root.pem` | Every active Fulcio root CA, concatenated | PEM (`CERTIFICATE`), one after another; multiple roots with overlapping validity windows are all honored, so a device updating across a rotation never hits a gap |
| `rekor-pub.pem` | The Rekor log public key | PEM (`PUBLIC KEY`, PKIX SPKI), ECDSA P-256 |

## Refresh procedure (every release, and out-of-band on Sigstore rotation)

1. Fetch the current Sigstore TUF snapshot (use a TUF client or the `sigstore`
   CLI) and verify the metadata chain up to the pinned TUF root — the pinned
   TUF root is the only secret in this whole procedure.
2. Extract the active Fulcio root CA(s) (`fulcio_v1.crt.pem` in the targets)
   and the Rekor log public key (`rekor.pub`).
3. Concatenate the Fulcio roots into `fulcio-root.pem`; write the Rekor key to
   `rekor-pub.pem`.
4. Append the TUF snapshot version and date to the manifest line in
   `src/trust.rs` (`TRUST_MANIFEST`) so the provenance of the embedded roots is
   greppable.
5. Commit in the release PR. The release binary then carries the refreshed
   root; refresh ships in **every** release so no device is stranded past a
   root expiry (ADR-014).

A device that cannot update past a root expiry refuses closed: no valid
embedded root at `integratedTime` is `TrustRootUnavailable`, never a downgrade
path.
