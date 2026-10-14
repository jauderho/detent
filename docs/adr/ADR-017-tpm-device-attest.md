# ADR-017: TPM device attestation (device-attest-01) deferred past v1
Status: Deferred (2026-10-14)
Deciders: project owner (BUGFIX.md §4, Track G question, answered 2026-10-14)

## Context

PLAN.md Phase 6 plans a TPM 2.0 attestor for ACME `device-attest-01`
(feature `acme-attest`, `tss-esapi`, CI against step-ca and swtpm). BUGFIX.md
§4 asked whether to defer it past v1. The owner answered yes. This record keeps
the stage-1 findings, so a later attempt does not start from zero.

The findings were verified by an implementer on 2026-10-14 against step-ca and
crate metadata. No attestor code exists, and none is added.

## Findings

### 1. Key custody

step-ca's `tpm` attestation format reads `ver`, `x5c`, `alg`, `sig`,
`certInfo` and `pubArea`. It stores a fingerprint of the certified public key
(`pubArea`). At finalize it refuses a CSR whose key does not match. So the
private key of the issued certificate must be the TPM-certified key.

ADR-015 has the acme process send the chain and the private key to the worker
(`Install`), and `finalize` today makes a software key. To keep the key in the
TPM there are two options:

- A TPM signing service, used for each TLS handshake (a rustls custom signer).
  Each handshake pays a TPM operation.
- A duplicable key. This weakens the attestation. step-ca does not check
  `fixedTPM`.

### 2. Certificate type

A step-ca `device-attest-01` order identifies the device by
`permanent-identifier` (the serial), not by DNS names. The result is a
device-identity (client, mTLS) certificate, not an HTTPS serving certificate.
A provisioner template could add DNS SANs. This was not verified.

### 3. AK certificate

step-ca verifies `x5c[0]` (the AK certificate) against the provisioner's
`attestationRoots`. A real TPM ships an EK certificate but no AK certificate.
Production use needs one of:

- an AK enrolment flow (`MakeCredential`/`ActivateCredential` against an
  attestation CA);
- an operator-supplied AK certificate and a persistent AK handle.

### 4. Dependencies

- `tss-esapi` 7.7.0 (2026-04-24) passes the ADR-011 cooldown. It needs the C
  `tpm2-tss` libraries through pkg-config. A bundled build exists only in alpha
  versions, which are inside the cooldown.
- Static musl linking with zig is not feasible without a vendored C build. It
  also pulls OpenSSL `libcrypto` into a binary that uses aws-lc only (ADR-002).
  `tctildr` uses `dlopen`, which fails in a static musl binary.
- Pure-Rust option: `tpm2-protocol` 1.2.0 (2026-09-02, MIT OR Apache-2.0, no
  dependencies, about 8.4k lines, a few documented unsafe zero-copy casts).
  Versions 1.2.1 to 1.2.3 are inside the cooldown. Detent would write its own
  read and write on `/dev/tpmrm0`, with password-session authorization, behind a
  non-default feature. No size row is affected.

## Decision

**Defer the TPM attestor (ACME `device-attest-01`) past v1.**

1. v1 has no `Attestor` implementation, no TPM code, no `tss-esapi` or
   `tpm2-protocol` dependency, and no change to `Cargo.toml`, `deny.toml`, the
   unit file or the size baselines.
2. ACME in v1 uses `dns-01` only.

## If revisited

- The acme process holds a file descriptor to `/dev/tpmrm0`, opened by the
  privileged parent before the fork. No Landlock rule and no `tss` group are
  needed. The ACME seccomp table already allows read, write and close.
  `/dev/tpmrm0` needs no ioctl.
- The unit needs `PrivateDevices=no` and `DeviceAllow=/dev/tpmrm0 rw` for that
  build (PLAN.md already notes this).
- CI runs in a separate `tpm.yml`: swtpm, a test CA that signs the AK, and
  step-ca with `attestationFormats: [tpm]`. It runs on push to main and
  nightly only. It includes a negative test with a wrong AK chain.

## Decisions needed to revisit

1. Which certificate: a separate device-identity certificate, or the HTTPS
   serving certificate.
2. Key custody: TPM signing service for each handshake, or a duplicable key.
3. AK provisioning: enrolment flow, or an operator-supplied AK certificate.

## Consequences

Positive:
- No C dependency, no `dlopen`, no OpenSSL in the static musl build.
- ADR-015 stays unchanged.

Negative:
- A private CA cannot bind a certificate to a TPM in v1.
- PLAN.md Phase 6 task 4 is not done.

## Alternatives considered

- `tss-esapi` — rejected for now: C libraries, `dlopen`, OpenSSL (finding 4).
- `tpm2-protocol` with our own device I/O — feasible, deferred with the rest.
- Duplicable key — rejected: it weakens the attestation (finding 1).

## References

PLAN.md Q2, Phase 6, §2.8, appendix on `device-attest-01`; BUGFIX.md §4 and
Track G; ADR-002 (crypto provider), ADR-011 (cooldown), ADR-015 (acme process);
step-ca provisioner documentation; crates.io metadata for `tss-esapi` and
`tpm2-protocol` (read 2026-10-14).
