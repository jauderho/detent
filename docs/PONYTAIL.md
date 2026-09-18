# Ponytail audit — 2026-09-17

Whole-repo scan for over-engineering. One line per finding. Biggest cut first.
Does not apply fixes. Work through later, delete as you go.

Already triaged, do NOT re-list: `useCallback` in `web/src/i18n/index.tsx` + `web/src/lib/theme.ts`, `pad2`/`formatUtc` in `StatusBar`, `gen-pseudo.ts` regex/select handling — marked lean/kept.

## Delete first (dead / shipped)

- `delete` docs/spikes/m1-e2e.md, 574-line shipped M1 Docker transcript. Nothing replaces it. [docs/spikes/m1-e2e.md:1] ~-560
- ~~`delete` scripts/checkWorkflows.sh, 358-line wrapper over `gh run list` + `gh workflow run`. 5-line gh alias. [scripts/checkWorkflows.sh:1] ~-350~~ — **done**. Unreferenced by any CI workflow, Makefile, justfile, or package.json (grepped `.github/workflows/`, repo root). `docs/PLAN.md:483,763` and `docs/PROGRESS.md:94` still mention it — those files are out of scope for this pass (see hard constraints); a follow-up needs to strip those stale mentions.
- `delete` web/src/components/ui/button.tsx, zero imports; app Button.tsx replaced it. Drop `class-variance-authority` dep with it. [web/src/components/ui/button.tsx:1] ~-62, -1 dep
- ~~`delete` scripts/useCommitHash.sh, dead one-shot SHA migration, hardcoded SHAs stale. Nothing. [scripts/useCommitHash.sh:1] ~-42~~ — **done**. Unreferenced by any CI workflow; the current `pins` job in ci.yml does its own inline SHA-pin regex check, not this script. `docs/PLAN.md:463` still mentions it — out of scope for this pass, same as above.
- `delete` 2 empty stub crates detent-mcp / detent-update, 1-line lib.rs each + feature gates in detent/Cargo.toml. Re-add when Phase 9/10 land. [crates/detent-mcp/src/lib.rs:1] ~-6 (detent-acme struck — landed e4fe5f3, 437 lines, reviewed below)
- `delete` ci.yml shell job, shellcheck/shfmt already covered by super-linter BASH_EXEC/BASH_SHFMT. Delete job. [.github/workflows/ci.yml] ~-30 — **kept, claim false**. `linter.yml`'s super-linter step does not set `VALIDATE_BASH_EXEC` or `VALIDATE_BASH_SHFMT` at all (verified: absent from the env block). Since it sets other `VALIDATE_*` flags explicitly, super-linter runs in opt-in mode and bash is not linted there. The ci.yml `shell` job is the only shellcheck/shfmt coverage in the repo; it stays.

## Shrink (same logic, fewer lines)

- `shrink` web/src/components/ui/tooltip.tsx, single-consumer wrapper (FieldFrame only). Radix primitives directly in FieldFrame. [web/src/components/ui/tooltip.tsx:1] ~-45
- ~~`shrink` ProcessError single-variant Spawn enum.~~ **DONE 2026-09-17**, partly. Collapsed to a plain struct (one construction site, the rest were signatures) and dropped `#[non_exhaustive]`. `thiserror` **kept**: AGENTS.md mandates it for library errors, and callers use `?` across the `Result<_, ProcessError>` boundary. -13 net, not -15.
- `shrink` KickerTag single-consumer one-liner. Inline the span in ModuleDetailPage. [web/src/components/KickerTag.tsx:1] ~-15
- ~~`shrink` Scopes wrapping write:bool.~~ **REJECTED 2026-09-17.** Not a newtype for its own sake: 85 references over 8 files, and it owns the read/write policy. `allows()` is called 10 times over 3 files (collapsing it scatters the policy into every call site) and `names()` 5 times over 3 files rendering `["read"]`/`["read","write"]` for the API and the token store, which a bare `bool` orphans. `allows(Scope::Read) == true` unconditionally is *why* a read-scoped operation cannot be denied — that rule needs one home, not ten.
- ~~`shrink` ValidationCtx single-field &HostProfile wrapper.~~ **REJECTED 2026-09-17.** It is a parameter of `ConfigModule::validate`, implemented by every module: 60 references over 13 files including 7 modules and `_template`. The wrapper exists so that adding a field does not re-touch all 13 — and locale *is* coming (AGENTS.md: "implement localization features from the start"). Removing it costs 13 files now and 13 again later, to save one indirection.
- ~~`shrink` SandboxError tuple struct wrapping String, #[non_exhaustive]...~~ **REJECTED 2026-09-17, claim is factually wrong.** `SandboxError` carries no `#[non_exhaustive]`; that attribute is on `SpawnError`, a different type 11 lines below (spawn.rs:116). `SandboxError` is already 3 lines, and the suggested type alias to `String` would drop the `Error` impl that `Result<(), SandboxError>` needs for `?`. Nothing to shrink.

## YAGNI / native (speculative surface, stdlib covers it)

- `native` web/src/lib/storage.ts, 38-line try/catch localStorage for 2 callers. Inline native calls. [web/src/lib/storage.ts:1] ~-38
- `yagni` linter.yml VALIDATE_PYTHON_RUFF / JAVASCRIPT_BIOME / CHECKOV / GITHUB_ACTIONS_ZIZMOR — dup ci web job or inapplicable (no Python, no IaC, pins job covers zizmor). [linter.yml:65-69] ~-4 — **partially done, verified per-flag**:
  - `VALIDATE_PYTHON_RUFF` — removed. Confirmed 0 `.py` files in the repo (`fd -e py .`).
  - `VALIDATE_JAVASCRIPT_BIOME` — removed. Confirmed duplicate: ci.yml's `web` job runs `bun run lint`, which is `biome ci .` per `web/package.json`.
  - `VALIDATE_CHECKOV` — **kept, claim false**. The repo has `docs/openapi.json`, which Checkov lints as an OpenAPI security target (not just Terraform/IaC). `docs/PROGRESS.md:406` records Checkov catching real "OpenAPI security requirements" findings in CI history. Not inapplicable.
  - `VALIDATE_GITHUB_ACTIONS_ZIZMOR` — **kept, claim false**. Grepped all of `.github/workflows/*.yml`: zizmor does not run anywhere else. The ci.yml `pins` job only regex-checks that `uses:` lines are pinned to a 40-hex SHA with a version comment — it does not run zizmor's semantic checks (`artipacked`, `excessive-permissions`, etc.), which `docs/PROGRESS.md:406` records this workflow actually catching. Not duplicated.
- `yagni` codespell.yml stale super-linter comment + fetch-depth:0; semgrep.yml fetch-depth:0 works shallow. [codespell.yml:42 semgrep.yml:44] ~-4 — **done**. Neither workflow diffs against a base ref or needs history: codespell-project/actions-codespell scans the checked-out tree; `semgrep scan --config auto` is a full scan. Removed the stale comment (copy-pasted from linter.yml's super-linter step, which does need full history) and both `fetch-depth: 0` lines.
- `yagni` NullAuthAudit public test-only export. #[cfg(test)] or inline into its one test. [crates/detent-web/src/auth/audit.rs:234] ~-10
- `yagni` SCOPE_READ + hasScope single-use includes. Inline into ScopeGate. [web/src/auth/scopes.ts:17] ~-10
- `yagni` WriteGate + useCanWrite test-only exports, prod uses useWriteGate only. Delete both. [web/src/auth/ScopeGate.tsx:40] ~-10
- `yagni` statusOf + hasCsrfToken test-only API surface, zero prod callers. Delete both. [web/src/api/query.ts:55 web/src/api/client.ts:261] ~-7
- `delete` NoSandbox empty SandboxHooks impl, defaults already Ok. Nothing. [crates/detent-platform/src/privsep/spawn.rs:107] ~-8

net: -1296 lines, -1 deps possible.

## 2026-09-17 — e4fe5f3 detent-acme seam (crates/detent-acme/src/lib.rs, 437 lines)

Lean by PLAN Phase 6 (§ DnsProvider trait + RFC2136/Cloudflare/acme-dns/deSEC; order flow vs Pebble next): DnsProvider, Challenge, wait_propagated kept — not YAGNI.

- `crates/detent-acme/src/lib.rs:L206: yagni: Display for HookProvider used only by its display test. Debug covers it.`
- `crates/detent-acme/src/lib.rs:L184: yagni: state_dir() accessor with zero prod callers. Drop; keep new() + trait methods.`
- `net: -5 lines possible.`
