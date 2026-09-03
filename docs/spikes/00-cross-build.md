# Spike 1 — cross-build (`cargo zigbuild`) with aws-lc-rs vs ring

**Date:** 2026-09-03 · **Host:** macOS 15 (Darwin 25.6.0), Apple Silicon (aarch64-apple-darwin)
**Toolchain:** rustc 1.98.0 (88d9e12ae 2026-08-18), cargo 1.98.0
**Scratch crate:** `spikes/xbuild/` (own `Cargo.lock`, own workspace, excluded from the repo workspace)

## Setup (exact commands)

Tools were **not** pre-installed (`/tmp/detent-tools.log` contained only the rustup
1.98.0 sync and never reached `done`). Installed by this spike:

```bash
uv tool install cargo-zigbuild          # cargo-zigbuild 0.23.2, ziglang 0.16.0
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf riscv64gc-unknown-linux-musl x86_64-unknown-freebsd
```

`uv tool install cargo-zigbuild` does **not** put a `zig` binary on `PATH` — only
`cargo-zigbuild`. `cargo zigbuild` then fails with `Error: Failed to find zig`.
Workaround used (kept in-tree so the result is reproducible):

```bash
cat spikes/bin/zig
#!/bin/sh
exec "$HOME/.local/share/uv/tools/cargo-zigbuild/bin/python" -m ziglang "$@"
```

Crate created with `cargo add`; resolved versions (`spikes/xbuild/Cargo.toml`):

```
argon2 0.6.0 · axum 0.8.9 · clap 4.6.6 (derive) · hyper-rustls 0.27.9 (http2, webpki-roots,
no default features) · instant-acme 0.8.5 (hyper-rustls, no default features) · mimalloc 0.1.52
(secure) · postcard 1.1.3 (alloc) · rcgen 0.14.10 (crypto, pem, no default features) ·
rustls 0.23.43 (std only — tls12 OFF) · serde 1.0.229 · serde_json 1.0.151 ·
tokio 1.53.1 (rt,net,time,macros,sync,signal)
[target.'cfg(target_os = "linux")'.dependencies] caps 0.5.6 · landlock 0.4.7 · seccompiler 0.5.0
```

Features (mutually exclusive crypto providers):

```toml
default       = ["crypto-aws-lc"]
crypto-aws-lc = ["rustls/aws-lc-rs", "hyper-rustls/aws-lc-rs", "instant-acme/aws-lc-rs", "rcgen/aws_lc_rs"]
crypto-ring   = ["rustls/ring",      "hyper-rustls/ring",      "instant-acme/ring",      "rcgen/ring"]
```

> **Finding worth carrying into the real build:** `rcgen`'s default features pull
> `ring` unconditionally. Without `default-features = false` on `rcgen`, an
> `aws-lc-rs` build links **both** crypto stacks. Verified after the fix:
> `cargo tree -i ring` → *nothing to print* under `crypto-aws-lc`, and
> `cargo tree -i aws-lc-sys --features crypto-ring` → *did not match any packages*.

`spikes/xbuild/src/main.rs` builds a `rustls::ServerConfig` via
`builder_with_provider(...).with_protocol_versions(&[&rustls::version::TLS13])`,
serves axum `/healthz` on `127.0.0.1:0` over plain TCP and self-requests it,
runs argon2id (m=64 MiB, t=3, p=1), round-trips postcard/serde_json, links
`instant_acme::ChallengeType`, and prints the highest supported Landlock ABI.
`mimalloc::MiMalloc` (feature `secure`) is the `#[global_allocator]`.

Build profile copied verbatim from PLAN §4.1 plus `[profile.release.package."*"] opt-level = "z"`.

Matrix driver: `spikes/matrix.sh` (results appended to `spikes/matrix-results.txt`),
one `CARGO_TARGET_DIR` per provider (`spikes/td-aws-lc`, `spikes/td-ring`):

```bash
cargo zigbuild --release --target <T>                                  # aws-lc
cargo zigbuild --release --target <T> --no-default-features --features crypto-ring
```

Sizes are `wc -c` on the linker output; `strip = "symbols"` is in the profile, so
no separate `strip` step was run (`file` confirms `stripped` on every artifact).

## Results

### `crypto-aws-lc` (default, ADR-002)

| Target | Result | Wall s | Bytes | MiB | `file` |
|---|---|---:|---:|---:|---|
| aarch64-unknown-linux-musl | ok | 51 | 2 900 840 | 2.77 | ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped |
| x86_64-unknown-linux-musl | ok | 113 | 3 433 432 | 3.27 | ELF 64-bit LSB executable, x86-64, statically linked, stripped |
| armv7-unknown-linux-musleabihf | ok | 118 | 2 571 872 | 2.45 | ELF 32-bit LSB executable, ARM EABI5, statically linked, stripped |
| riscv64gc-unknown-linux-musl | ok | 98 | 2 801 976 | 2.67 | ELF 64-bit LSB pie executable, UCB RISC-V RVC double-float, static-pie, stripped |
| x86_64-unknown-freebsd | ok | 96 | 3 497 096 | 3.34 | ELF 64-bit LSB pie, x86-64, **dynamically linked**, interp `/libexec/ld-elf.so.1`, FreeBSD 14.0 (1400500), stripped |

### `crypto-ring`

| Target | Result | Wall s | Bytes | MiB | Δ vs aws-lc |
|---|---|---:|---:|---:|---:|
| aarch64-unknown-linux-musl | ok | 49 | 2 407 864 | 2.30 | −492 976 (−17.0 %) |
| x86_64-unknown-linux-musl | ok | 43 | 2 740 392 | 2.61 | −693 040 (−20.2 %) |
| armv7-unknown-linux-musleabihf | ok | 38 | 2 202 592 | 2.10 | −369 280 (−14.4 %) |
| riscv64gc-unknown-linux-musl | ok | 33 | 2 303 944 | 2.20 | −498 032 (−17.8 %) |
| x86_64-unknown-freebsd | ok | 49 | 2 830 536 | 2.70 | −666 560 (−19.1 %) |

**10 / 10 builds succeeded.** No `AWS_LC_SYS_CMAKE_BUILDER=0` and no `bindgen`
feature was needed — `aws-lc-sys 0.45.0` cross-built out of the box for all four
musl targets *and* for `x86_64-unknown-freebsd` under `cargo zigbuild`. Plain
`cargo build --target x86_64-unknown-freebsd` was therefore not needed as a
fallback and was not run.

Wall times are not comparable across rows: each provider used a fresh
`CARGO_TARGET_DIR`, so the first target of each provider paid for host build
scripts and proc-macros, and per-target dependency artifacts are never shared.

### Runtime check (aarch64-musl, aws-lc)

```bash
docker run --rm -v .../xbuild:/x:ro debian:bookworm /x probe
```
```
rustls: TLS1.3-only ServerConfig built; alpn slots=0
instant-acme: challenge type linked = Dns01
argon2id(m=64MiB,t=3,p=1): 128 ms; first byte 0x6a
postcard: 1 bytes; serde_json: {"v":1}
axum: 127.0.0.1:34549 -> HTTP/1.1 200 OK
landlock: highest supported ABI = 5
PROBE OK
```

argon2id at m=64 MiB/t=3/p=1 costs **128 ms** on this (fast, virtualised) aarch64
host. On a Raspberry Pi class SBC this will be several times slower — it needs a
real-hardware measurement before the parameters are frozen.

### Budgets (PLAN §4.1, aarch64-musl stripped)

| Budget row | Limit | This spike |
|---|---:|---|
| Full default features ≤ 12 MiB | 12 582 912 B | 2 900 840 B — but the spike contains **no** modules, no web assets, no i18n bundles, no CLI surface, no `zbus`/`tracing`/`schemars`/`utoipa`/`hickory`. Treat as a **floor**, not a baseline. |
| `module-resolver,web` ≤ 5 MiB | 5 242 880 B | not measurable yet |
| CLI, no web ≤ 3 MiB | 3 145 728 B | 2 900 840 B for TLS+HTTP+ACME+argon2+sandbox alone — **this row is already at risk**: the CLI-only build still contains `argon2`, `postcard`, `clap`, `serde`, the modules, and (if `update` is on) the whole TLS/HTTP client. |

## Conclusion

**ADR-002 holds: `aws-lc-rs` stays the default.** Its flip condition ("if aws-lc-rs
cannot cross-build for a tier-1 target") was not met — aws-lc-rs cross-built
cleanly, first try, for all four musl targets and for FreeBSD, and the resulting
aarch64-musl binary runs and completes a TLS-1.3-only rustls handshake config,
an axum request, and an argon2id hash inside a Debian container.

The measured cost of that decision is **+14 % to +20 % binary size versus `ring`**
(+493 KiB on aarch64-musl). `crypto-ring` compiles and runs identically and should
stay in CI as a maintained fallback, as PLAN §7 already requires.

## Open questions for the orchestrator

1. **The ≤ 3 MiB CLI budget looks unreachable.** A feature-empty binary with only
   TLS + HTTP + ACME + argon2 + mimalloc-secure is already 2.77 MiB on aarch64-musl.
   Either the CLI build must exclude the entire TLS/HTTP/ACME stack (i.e. `update`
   and `acme` off by default in the CLI profile) or §4.1's 3 MiB row needs raising.
   Recommend re-deriving all three budget rows from a real Phase 1 build.
2. **FreeBSD artifacts are dynamically linked** against `/libexec/ld-elf.so.1` and
   tagged for FreeBSD 14.0. That is expected, but it means the FreeBSD release is
   not the "single static binary" §1.1 promises, and the minimum supported FreeBSD
   version is pinned by whatever sysroot zig ships. Worth an explicit ADR line.
3. **`rcgen` default features must be disabled** in the real workspace or every
   aws-lc build silently links `ring` too. Add it to `deny.toml`'s duplicate-ban
   list so a future `cargo add` cannot regress it.
4. **aarch64-unknown-freebsd was not attempted** (rustup tier 3; PLAN §7 already
   flags it for ADR-013). This spike gives no evidence either way.
5. **argon2id m=64 MiB is 128 ms here.** Needs a Pi-class measurement before
   §2.10's auth parameters are fixed; 64 MiB is also a meaningful chunk of a
   256 MiB SBC's RAM against the ≤ 30 MiB idle-RSS budget.
