# Releasing detent

Repository protections and the cut-a-release procedure (PLAN Phase 9, M3).
These rulesets are enforced as GitHub rulesets on `jauderho/detent`; this
document is the authoritative record of what is configured and why.

## Repo rulesets

### `main` branch ruleset

| Setting | Value |
|---|---|
| Require pull request before merging | yes |
| Required approvals | ≥ 1 |
| Require status checks to pass | yes (the `ci.yml` gates) |
| Require signed commits | yes |
| Require linear history | yes (no merge commits on `main`) |
| Allow force pushes | **no** |
| Allow deletions | **no** |

### `v*` tag ruleset

- Match pattern: `v*` (e.g. `v0.1.0`).
- Protected: force-push **disabled**, tag deletion **disabled** — a published
  release tag is immutable once `release.yml` has run against it.
- Only maintainers may create `v*` tags.

### Workflow hardening

- Every GitHub Action in every workflow is pinned to a full 40-hex commit SHA
  with the version in a trailing comment, per the `ci.yml` convention:
  `uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`.
  Never pin by tag or branch; `fuzz.yml` once pinned a branch that was
  force-pushed daily.
- Every job runs `step-security/harden-runner` with `egress-policy: audit`
  (release jobs: block), matching `ci.yml`.

### Dependency cooldowns

Dependabot applies a **7-day cooldown** (`cooldown.default-days: 7`) to all
four ecosystems it manages — `github-actions`, `cargo`, `bun` (`web/`), and
`docker` — see `.github/dependabot.yml`. This implements ADR-011; security
advisories bypass the cooldown. Do not lower these values.

### Releases

- Repo setting **immutable releases** is ON (Settings → Releases): published
  release assets and metadata cannot be modified or deleted.

## Cutting a release

1. Confirm `main` is green (all `ci.yml` checks pass) and the changelog entry
   for the new version is merged.
2. Tag from `main` and push the tag (signed, per the ruleset):
   ```
   git tag -s v0.1.0 -m "detent v0.1.0"
   git push origin v0.1.0
   ```
3. `release.yml` triggers on the `v*` tag: `cargo auditable` with
   `--locked` for four targets (`x86_64`/`aarch64-unknown-linux-musl` via
   `cargo zigbuild` on Linux runners, `aarch64`/`x86_64-apple-darwin` via
   `cargo build` on a macOS runner, not signed or notarized) with
   `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` and
   `RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"`,
   `bun install --frozen-lockfile` for the SPA, merged CycloneDX SBOM
   (`cargo cyclonedx` + `cdxgen`), then publishes `detent-<target-triple>`,
   per-asset `detent-<target-triple>.sigstore.json` bundles, `SHA256SUMS`,
   and `SBOM.cyclonedx.json` via `gh release create --verify-tag`. Each
   `.sigstore.json` file is a **Rekor v2** bundle made by `cosign
   attest-blob` (cosign v3.1.3, signing config
   `.github/sigstore/signing-config-rekor-v2.json`): one in-toto v1
   statement per binary, with that binary as the only subject and the SLSA
   provenance predicate of the `actions/attest` run, logged to
   `log2025-1.rekor.sigstore.dev` with an RFC 3161 timestamp. The
   self-updater verifies it (ADR-014). A gate step stops the release unless
   every bundle is `hashedrekord` 0.0.2 with a timestamp and one subject and
   passes `cosign verify-blob-attestation` for this workflow and tag, and
   passes detent's own verifier: the gate runs `detent verify-bundle --tag
   <tag> --bundle <bundle> <binary>` from the x86_64 musl build, so a bundle
   a device would refuse is never published.
   `actions/attest` still runs: its Rekor v1 attestation goes to GitHub's
   attestation store, which `gh attestation verify` (step 5) and
   `rebuild-verify.yml` use. Devices on `v0.1.0` or older verify Rekor v1
   only: they refuse these bundles and need a manual reinstall. `SHA256SUMS`
   covers the binaries only. Each target is built twice, on two runners
   (the second build without the cargo cache); the `reproducible` job
   stops the release unless both builds have the same SHA-256.
4. Watch the run (`gh run watch`); it must finish green before the release is
   announced. Do not retry by re-tagging — the tag is protected; delete the
   draft release and push a new patch tag instead.
5. Verify from a clean checkout:
   ```
   gh attestation verify detent-x86_64-unknown-linux-musl -R jauderho/detent
   gh attestation verify detent-aarch64-unknown-linux-musl -R jauderho/detent
   gh attestation verify detent-aarch64-apple-darwin -R jauderho/detent
   gh attestation verify detent-x86_64-apple-darwin -R jauderho/detent
   gh release verify v0.1.0 -R jauderho/detent
   ```
   Each asset must verify with the workflow identity pinned to
   `release.yml` at this tag (ADR-005); `SHA256SUMS` must match every
   downloaded asset. `gh attestation verify` checks the `actions/attest`
   attestation in GitHub's store. To check the updater bundle itself:
   ```
   cosign verify-blob-attestation \
     --bundle detent-x86_64-unknown-linux-musl.sigstore.json \
     --certificate-identity https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/<tag> \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --type https://slsa.dev/provenance/v1 \
     detent-x86_64-unknown-linux-musl
   ```
6. `rebuild-verify.yml` runs weekly and on demand (`workflow_dispatch`): it
   rebuilds the latest tag from source with the same reproducible flags and
   compares hashes against the published assets, plus `gh attestation verify`
   per asset. A red rebuild-verify run on a published release is a
   supply-chain incident — investigate immediately; do not publish further
   releases until explained.

Verification failures are always release-blockers. There is no override path;
the updater refuses closed on any verification failure (ADR-005, ADR-014).
