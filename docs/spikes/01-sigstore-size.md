# Spike 2 — `sigstore` crate size and dependency cost

**Date:** 2026-09-03 · Same host/toolchain/crate as spike 1 (`docs/spikes/00-cross-build.md`).
**Target measured:** `aarch64-unknown-linux-musl`, `crypto-aws-lc` (the provider that
succeeded in spike 1 and remains the ADR-002 default).

## Setup (exact commands)

Feature selection was taken from <https://docs.rs/crate/sigstore/latest/features>
(fetched 2026-09-03). `sigstore` 0.14.0 has 14 default features including
`native-tls` and `full`. The minimal set that gives bundle/keyless verification
without OpenSSL or native-tls is `verify` + `rustls-tls` (`verify` transitively
enables `cert`, `fulcio`, `rekor`).

```bash
cd spikes/xbuild
cargo add sigstore@0.14 --optional --no-default-features --features verify,rustls-tls
# feature added by hand:  update-sigstore = ["dep:sigstore"]
```

`src/main.rs` gained a `sigstore-probe` subcommand that links the real verification
path, not just a type name:

```rust
use sigstore::bundle::verify::{policy, Verifier, VerificationPolicy};
let id = policy::Identity::new(
    "https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/v0.0.1",
    "https://token.actions.githubusercontent.com");
let _p: &dyn VerificationPolicy = &id;
let root = sigstore::trust::ManualTrustRoot::default();
let v = sigstore::bundle::verify::blocking::Verifier::new(Default::default(), root);
// ... v.verify(reader, bundle, &id, /* offline */ true)
```

`Verifier::production()` is gated behind the extra `sigstore-trust-root` feature and
was **not** enabled: §2.9 embeds its own trust root, so `ManualTrustRoot` is the
representative shape.

Both binaries built into the same `CARGO_TARGET_DIR=spikes/td-sigstore`:

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl --features update-sigstore
cargo zigbuild --release --target aarch64-unknown-linux-musl        # baseline
wc -c <binary>
cargo tree -e normal --target aarch64-unknown-linux-musl --prefix none | sort -u | wc -l
cargo tree -e normal --target aarch64-unknown-linux-musl --features update-sigstore --prefix none | sort -u | wc -l
cargo tree -d -e normal --target aarch64-unknown-linux-musl --features update-sigstore
```

## Results

### Size

| Build | Bytes | MiB |
|---|---:|---:|
| baseline (no `update-sigstore`) | 2 900 840 | 2.77 |
| with `update-sigstore` | 4 941 488 | 4.71 |
| **delta** | **+2 040 648** | **+1.95** |

### Dependency count

`cargo tree -e normal --prefix none \| sort -u \| wc -l` (the command specified for
this spike; it counts unique `name vX.Y.Z (*)`-suffixed lines, so re-exported
subtrees inflate it slightly):

| | lines |
|---|---:|
| without | 159 |
| with | 352 |
| **delta** | **+193** |

Normalising away the `(*)` suffix and counting distinct packages:
**131 → 270, +139 crates.**

### Stack contamination

| Crate | Present with `update-sigstore`? |
|---|---|
| `reqwest` | **yes — v0.13.4** |
| `openssl` / `openssl-sys` | no |
| `native-tls` | no |
| `ring` | no |
| `aws-lc-sys` | yes (already present in baseline) |
| `tough` | no |

`rustls-tls` does keep OpenSSL out, but it does **not** keep `reqwest` out.
PLAN §4.2 lists `reqwest` under *Avoid* explicitly, and ADR-009 says "no `reqwest`
(single hyper-rustls client shared by ACME and update)". Enabling `sigstore`
violates both.

### Duplicates introduced (`cargo tree -d`)

Baseline has 3 duplicate pairs (`base64` 0.22/0.23, `syn` 2/3, plus `pem`'s base64).
With `update-sigstore` the duplicate set grows to 19 pairs, i.e. **16 new**:

```
base64 0.21.7 (new) / 0.22.1 / 0.23.1     block-buffer 0.10.4 / 0.12.1
cipher 0.4.4 / 0.5.2                      cpufeatures 0.2.17 / 0.3.1
crypto-common 0.1.7 / 0.2.2               digest 0.10.7 / 0.11.3
getrandom 0.2.17 / 0.4.3                  hmac 0.12.1 / 0.13.0
inout 0.1.4 / 0.2.2                       itertools 0.10.5 / 0.14.0
pbkdf2 0.12.2 / 0.13.0                    pem 3.0.6 / 4.0.0
salsa20 0.10.2 / 0.11.0                   scrypt 0.11.0 / 0.12.0
sha2 0.10.9 / 0.11.0                      thiserror 1.0.69 / 2.0.20
untrusted 0.7.1 / 0.9.0                   syn 2.0.119 / 3.0.4
```

The whole RustCrypto 0.10-era stack (`digest`/`sha2`/`hmac`/`block-buffer`/
`crypto-common`) gets pulled in **alongside** the 0.11-era stack the rest of the
tree already uses. That is a `deny.toml` `bans` problem as much as a size problem.

### Runtime blocker found

The `update-sigstore` binary **aborts on a static musl system with no CA bundle**:

```bash
docker run --rm -v /tmp/xbuild-sigstore:/x:ro debian:bookworm /x sigstore-probe
```
```
thread 'main' panicked at reqwest-0.13.4/src/async_impl/client.rs:2507:38:
Client::new(): reqwest::Error { kind: Builder,
  source: General("No CA certificates were loaded from the system") }
Aborted
```

Diagnosis confirmed by installing a CA bundle in the same image:

```bash
docker run --rm -v /tmp/xbuild-sigstore:/x:ro debian:bookworm \
  sh -c 'apt-get install -y -qq ca-certificates >/dev/null; /x sigstore-probe'
```
```
sigstore: blocking verifier constructed = true
sigstore: verify path linked; bundle-parse result = true
SIGSTORE PROBE OK
```

So `sigstore`'s `rustls-tls` feature wires `reqwest` to the **system** root store,
not to `webpki-roots`, and `reqwest::Client::new()` **panics** (not `Result`) when
the store is empty. Constructing the verifier is eager — this happens before any
`offline = true` verification is attempted. A minimal SBC image or a distroless
container with no `/etc/ssl/certs` therefore turns self-update into a process abort.
Note also that PLAN §2.9 and ADR-010 require `panic = "abort"` and forbid panics in
non-test code; this is a panic inside a dependency's constructor.

## Conclusion

`sigstore` 0.14 costs **+1.95 MiB (+2 040 648 B)** on aarch64-musl, i.e. **16.2 % of
the 12 MiB full-build budget in §4.1**, and takes the floor binary from 2.77 MiB to
4.71 MiB. On size alone that is affordable: 4.71 MiB leaves 7.3 MiB for every
module, the web bundle, i18n, tracing, zbus and utoipa. Size is **not** the reason
to reject it.

The reasons to reject it are the other three findings: it drags in `reqwest`
(explicitly banned by §4.2 and ADR-009), it duplicates the entire RustCrypto stack
across 16 version pairs, and it **panics at verifier construction** on exactly the
minimal static-musl SBC images detent targets.

**Recommendation: take the §2.9 fallback — the in-tree minimal verifier** (x509
chain to embedded Fulcio roots + Rekor SET verification + certificate SAN/issuer
pinning), driven by the single shared hyper-rustls client with `webpki-roots`. It
keeps keyless signing, keeps the ADR-009 single-HTTP-stack rule, avoids the CA-store
panic, and is very likely to land well under +1.95 MiB.

## Open questions for the orchestrator

1. Does this flip **ADR-005**, or only its implementation? The decision
   ("Sigstore bundle verification with pinned identity") survives; the
   *mechanism* changes from `sigstore` the crate to an in-tree verifier. It
   probably needs a sentence in ADR-005 rather than a superseding ADR.
2. If `sigstore` is kept anyway, `reqwest` must be granted an explicit exemption in
   §4.2, and `deny.toml`'s duplicate-version bans must whitelist 16 pairs. Both are
   real, permanent maintenance costs. Recommend not doing this.
3. The in-tree verifier needs a scoped design task of its own (Fulcio root
   embedding + refresh policy, Rekor SET/checkpoint verification, SCT verification —
   the last is the easiest to get wrong). It should not be folded into a Phase 9
   "self-update" ticket.
4. `sigstore` was measured only for aarch64-musl. If it is kept, armv7/riscv64
   need their own measurement — the RustCrypto duplication may cost more on 32-bit.
5. Not tested: whether a real GitHub artifact-attestation bundle actually verifies
   end to end. This spike only proved the code links, constructs, and runs.
