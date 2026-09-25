# STAGE4 — Handoff to oh-my-pi (2026-09-25)

Written by the orchestrator (Claude) at the end of a cloud session, for
oh-my-pi. Read this file, then `docs/STAGE3.md` §00 (still binding), §11.8 and
§12. `docs/PROGRESS.md` has one entry per landed item.

## 1. State now

- `main` = `733d6e0`. Fast-forward of branch `claude/determined-noether-wo0uh8`.
- **CI is green on `main`** at `c50200e`, the previous tip (run 36129123886, all 11 jobs; Codespell, Lint, Scorecard green). The commits after it are one `Cargo.toml` profile change and docs. **Fuzz is green** (run 36124973393, 29 targets). Check CI on `733d6e0` first.
- STAGE3 D6 items are all landed: C1-e, H3, H10-MCP, H19, L-SUP13, M20, M16, L-MODB7, L-MODA12. The hashes are in STAGE3 §11.8.
- The D5 attribution table is in STAGE3 §11.8.
- Allow count: **114** (`git grep -c -E '#!?\[(allow|expect)\(' HEAD -- crates | awk -F: '{s+=$NF}END{print s}'`). It may only go down.
- Owner decisions taken this session are recorded in STAGE3 §12 with answers: CLI-SIZE (gate), SIZE-BASELINE (re-cut), NET-ORDER (validate).
- STAGE3 is **not** marked complete. Only the orchestrator audit does that.

## 2. Disk and build hygiene (new — use it)

- `make clean` removes incremental caches, coverage, release and cross builds, fuzz builds and artifacts, the generated fuzz corpus, test reports, and debug files older than 2 days. It keeps the warm debug build and `web/node_modules`. `make realclean` returns the tree to the as-cloned state; it keeps `.sops/`, `.mcp.json*` and your untracked files. Both take `DRYRUN=1 VERBOSE=1`. `make du` shows usage.
- `Cargo.toml` `[profile.dev.package."*"] debug = false`: dependencies build without debug info. A clean full test build is 5.0 GB (it was 19 GB+). Run `make realclean` once after you pull, so the old target/ goes.
- Run `make clean` after a coverage run, a fuzz run or a cross build.
- `cargo llvm-cov` needs `cargo llvm-cov clean --workspace` first, or stale binaries give wrong line numbers. Only the full CI-shaped run is valid for the per-path floors (commands in `.github/workflows/ci.yml`, Coverage job). Per-crate `--lcov` output also counts comment and blank lines as uncovered; do not trust it.

## 3. Traps found this session (do not repeat)

- **`git commit` takes the whole index.** In a shared tree, another agent's staged change can land in your commit (this happened in `216d326`). Before every commit, run `git diff --cached --stat`. Sub-agents must never stage.
- **Root-only test:** `webadmin::tests::setup_with_force_reports_a_write_failure_as_a_credential_failure` fails only as uid 0. It passes unprivileged and in CI. It is not a regression.
- **A test must not skip itself** when it is not root (D2). One such test was removed from a delivery this session.
- **CI job logs and artifacts** (blob storage) are blocked from the cloud container. To find a fuzz crash, run it locally: `cargo +nightly fuzz run --target=x86_64-unknown-linux-gnu <target> -- -max_total_time=60` (cargo-fuzz 0.13.2).
- **Branch CI:** `ci.yml`, `codespell.yml`, `linter.yml` and `fuzz.yml` run on a branch only through `workflow_dispatch`.
- **Codespell:** smb.conf words (e.g. `browseable`) go in `.codespellignore`.

## 4. Work queue, in order

### 4.1 STAGE3 §11.3 step 4 — verification pass (IN PROGRESS, results not yet recorded)

Five reviewers were started at `733d6e0`'s parent. **Group C is recorded in STAGE3 §11.9** (7 VERIFIED, 8 PARTIAL, 3 REOPEN: H9 and L-WEB16 are real defects; fix them first). The other groups may not have been recorded before this session ended. **Redo any group that has no table in STAGE3 §11.9.**

For each item: read its Fix/Test/Acceptance lines in STAGE3 §3–§6, then:
1. Confirm the fix is present at HEAD (file:line).
2. Run the pinning test.
3. **Prove non-vacuity**: in a throwaway worktree, remove the fix and see the test fail. Command: `git worktree add --detach <scratch> HEAD`, with `CARGO_TARGET_DIR=<repo>/target` so the target is shared.
4. Give a verdict: VERIFIED / VERIFIED-NO-NEG (with reason) / PARTIAL / REOPEN.
5. Record the results in a new STAGE3 §11.9 table, and fix REOPEN items one per commit.

| Group | Items |
|---|---|
| A platform | C1-a, C1-b, C1-c, C1-d, H1, H2, H4, H6 (strace part blocked, see 5), H12, H23, M1, M2, M11, L-PLAT6, L-PLAT7, L-PLAT8, L-BIN16 |
| B ops/modules | H5, H7, H13, H14, H15, H16, M3, M4, M5, M7, M8, M21, M22, M23, M24, M25, L-OPS11, L-OPS12, L-OPS14–L-OPS19, L-MODA8–L-MODA11, L-MODB8 |
| C web | H8, H9, H10 (web half), H21, H22, M6, M9, M10, L-WEB9–L-WEB17, L-FE3 |
| D update/ACME | H17 (list which Fix steps 1–8 exist), H18, M14, M15, M17, M18, M19, L-SUP10–L-SUP12, L-SUP14–L-SUP18, L-ORC2 |
| E CLI/MCP/FFI | H11, M12, M13, L-BIN11–L-BIN15, L-BIN17–L-BIN19, L-ORC1 |

Already verified with failing-first evidence this session (skip): C1-e, H3, H10-MCP, H19, L-SUP13, M16, M20, L-MODB7, L-MODA12, and the H20 pieces.

### 4.2 STAGE3 §12 follow-ups

1. **H17 core + SET gap (Opus tier).** These go in one change, because together they change the fixture format:
   - Merkle leaf = `SHA-256(0x00 || canonicalizedBody)` (RFC 6962), not the whole entry JSON.
   - Verify `inclusionPromise.signedEntryTimestamp` with the embedded Rekor key. It is an ECDSA signature over canonical JSON `{"body","integratedTime","logID","logIndex"}`.
   - `bundle.rs` must parse `inclusionPromise`. `gen-fixtures` must mint the SET.
   - Re-mint all fixtures (rcgen signs with random ECDSA, so the bytes change). Keep the detent-platform monitor tests green.
   - Test: a forged `integratedTime` inside the leaf validity window is refused **by the SET check**. Today only the entry-JSON leaf hash catches it (`a_forged_integrated_time_is_refused`).
   - Rename `bad-set.json` to what it does (it corrupts a path hash). Add a real `bad-set.json`.
   - H17 step 8 (a captured real bundle) still needs a release tag (owner).
2. **Aligned edits for chrony, dhcp, network** with `Document::edit_entries` (detent-core `doc.rs`), as M20 did for hosts/samba/nfs/mounts/resolver. Each module needs a test that a deletion does not rewrite later lines.
3. **Network validation gaps:**
   - `validate` must flag the renderer's interface-name charset (ASCII alphanumerics and `-_.`) and a leading `-`.
   - `is_valid_cidr` must refuse a `+24` prefix.
   - `render_netplan` must write routes and gateways for bridges and routes for VLANs, or keep refusing them explicitly.
   - The networkd sectioned path should restore the document on refusal, as the positional path now does.
4. **Dead code:** delete `UserStore::refresh_locked` (detent-web `auth/users.rs`) and its `#[allow(dead_code)]`. The allow count goes down.
5. **Not doable without the owner:** H6 real-validator strace (needs a010), D4 (owner hold: "do not remove packages on a010").

### 4.3 PLAN Phase 6 (ACME) — in-repo items

The gap analysis was done at `c50200e`. In short: the pieces exist, but nothing wires them into `serve`.
1. **Provider HTTPS transport** for Cloudflare, acme-dns and deSEC. Use the hyper-rustls client that `detent-acme` `order.rs` already builds. **The docs are wrong that a new dependency is needed**; fix `providers.rs:51-60` and `Cargo.toml:12-15`. Add TSIG for RFC 2136 with `hmac`/aws-lc (already in the workspace). Add provider selection in `[acme]`. Tests: recorded fixtures, and a **log-capture** test that no secret is logged.
2. **Renewal loop in `serve`**:
   - Read `[acme]`, order, `CertStore::install_acme` (hot reload), ARI window (`should_renew_ari`).
   - Remove the `cli-serve-acme-unsupported` refusal (`serve.rs:~309`).
   - Implement `Operation::CertRenew` (now `Unsupported`, `engine.rs:~329`).
   - Apply the `shortlived` profile by default on LE.
3. **`detent cert status|renew` CLI**, journal/CLI warnings at 50 %/25 % lifetime, and a renew button on `CertificatesPage.tsx`.
4. **Order-flow seam**, so fixtures can drive `order.rs` and raise the detent-acme floor from 87 toward 100.
5. **Pebble test with a short-lifetime profile that really renews** (`ci.yml` job `acme-pebble`).

Phase 6 items **blocked on the owner or external infrastructure**:
- `hickory-client` propagation checks (new dependency, ADR-011 7-day cooldown);
- the TPM attestor with the step-ca + swtpm CI job (`tss-esapi`, cooldown);
- Let's Encrypt staging run (`docs/spikes/acme-le.md`).

### 4.4 After Phase 6

Phases 7, 8, 9 and 12 are in the gap analysis. Summary:
- **P7:** mounts `daemon-reload` apply; detection of the installed version for `since`-gated options (chrony/samba).
- **P9:**
  - `release.yml`: macOS targets, a double-build SHA gate, the `actions/attest` DSSE bundle (H17 1–7), and egress `block`.
  - Embedded trust root from TUF (`trust.rs:27` placeholder).
  - The UI update apply control.
- **P12:** THREAT_MODEL.md, PENTEST_CHECKLIST.md, `[privilege] mode` plus the doctor check, mTLS, de/ja translations, the mutants and geiger jobs, and semver-checks for detent-core.
- **Needs the owner:** VM runs, release tags, and repo settings.

## 5. Rules that still bind

STAGE3 §00:
- One item per commit, in the §00.3 body format.
- Test first, and show it failing.
- All gates `--all-features`.
- No new suppressions.
- No weakened checks.
- a010 is the only Linux host, test-only, and no packages are removed there for now.
- Commits are signed (`git commit -S -s -F <file>`) and use ASD-STE100 messages.
- Jev only for classification and routing, never for readiness.
