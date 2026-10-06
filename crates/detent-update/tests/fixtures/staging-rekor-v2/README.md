# Staging Rekor v2 material (real, third-party)

These files are copied unchanged from
[sigstore/sigstore-python](https://github.com/sigstore/sigstore-python) at
commit `dbe933f28eb6433d0271ab96e0f1349dc0912c8f`. Licence: Apache-2.0 (the
repository's `LICENSE`).

| File here | Source path in sigstore-python | SHA-256 |
| --- | --- | --- |
| `a.dsse.staging-rekor-v2.txt` | `test/assets/a.dsse.staging-rekor-v2.txt` | `e248a5db4933dba6578200238c91a57f5e65b925b73050ae786933468b7ac101` |
| `a.dsse.staging-rekor-v2.txt.sigstore.json` | `test/assets/a.dsse.staging-rekor-v2.txt.sigstore.json` | `56e79ba9f94a34aba285769574c456601f38beeaa48a3acb67f8d5db706f9420` |
| `trusted_root.json` | `sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json` | `81f5af777952d2c3955062ad56924c05ca916b5d49f3a0bce945faa475a8b1cc` |

The bundle is a DSSE envelope signed against **staging** Sigstore and logged
to the staging Rekor v2 log `log2025-alpha3.rekor.sigstage.dev` as a
`hashedrekord` 0.0.2 entry, with one RFC 3161 timestamp. `trusted_root.json`
is the staging trust root that holds that log's Ed25519 key.

This is the only real Rekor v2 material in the tree. No public-good Rekor v2
bundle is available yet; the production `log2025-1` key and the production
timestamp authority are checked against the pinned public-good
`trusted_root.json` only (`src/trust.rs` tests).
