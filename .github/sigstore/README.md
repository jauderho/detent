# Sigstore signing config for the updater bundles

`signing-config-rekor-v2.json` is the signing config that `release.yml` gives
to `cosign attest-blob --signing-config` when it makes the self-updater bundle
`detent-<triple>.sigstore.json` (ADR-014). With it, cosign logs to Rekor v2
only and takes an RFC 3161 timestamp.

| | |
| --- | --- |
| Source | `sigstore/root-signing` commit `5888f358fc4ab58874447259edf83790261fc616`, `targets/signing_config_rekor_v2.v0.2.json` |
| Source SHA-256 | `0f5f38554e29e770d4d5d6f0e1b51fcbf84f61dc6934530a09b7a901eaad5bee` |
| This file SHA-256 | `9c740e670d5e811201491d16033746978234c87d0de74f166ac99607fb117e75` |

The one edit: the `rekorTlogUrls` entry for `https://rekor.sigstore.dev`
(`majorApiVersion` 1) is removed, so `log2025-1.rekor.sigstore.dev`
(`majorApiVersion` 2) is the only transparency log. Made with
`jq '.rekorTlogUrls |= map(select(.majorApiVersion == 2))'`; every other
byte is as in the source.

Refresh it with the trust root (`crates/detent-update/trust/README.md`): take
the same file from the same root-signing commit, make the same edit, and
update both digests here.
