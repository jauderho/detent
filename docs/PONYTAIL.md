# Ponytail audit — 2026-09-17

Whole-repo scan for over-engineering. One line per finding. Biggest cut first.
Does not apply fixes. Work through later, delete as you go.

Already triaged, do NOT re-list: `useCallback` in `web/src/i18n/index.tsx` + `web/src/lib/theme.ts`, `pad2`/`formatUtc` in `StatusBar`, `gen-pseudo.ts` regex/select handling — marked lean/kept.

## Delete first (dead / shipped)

- `delete` docs/spikes/m1-e2e.md, 574-line shipped M1 Docker transcript. Nothing replaces it. [docs/spikes/m1-e2e.md:1] ~-560
- `delete` scripts/checkWorkflows.sh, 358-line wrapper over `gh run list` + `gh workflow run`. 5-line gh alias. [scripts/checkWorkflows.sh:1] ~-350
- `delete` web/src/components/ui/button.tsx, zero imports; app Button.tsx replaced it. Drop `class-variance-authority` dep with it. [web/src/components/ui/button.tsx:1] ~-62, -1 dep
- `delete` scripts/useCommitHash.sh, dead one-shot SHA migration, hardcoded SHAs stale. Nothing. [scripts/useCommitHash.sh:1] ~-42
- `delete` 2 empty stub crates detent-mcp / detent-update, 1-line lib.rs each + feature gates in detent/Cargo.toml. Re-add when Phase 9/10 land. [crates/detent-mcp/src/lib.rs:1] ~-6 (detent-acme struck — landed e4fe5f3, 437 lines, reviewed below)
- `delete` ci.yml shell job, shellcheck/shfmt already covered by super-linter BASH_EXEC/BASH_SHFMT. Delete job. [.github/workflows/ci.yml] ~-30

## Shrink (same logic, fewer lines)

- `shrink` web/src/components/ui/tooltip.tsx, single-consumer wrapper (FieldFrame only). Radix primitives directly in FieldFrame. [web/src/components/ui/tooltip.tsx:1] ~-45
- `shrink` ProcessError single-variant Spawn enum. Plain struct, no thiserror. [crates/detent-platform/src/service/exec.rs:58] ~-15
- `shrink` KickerTag single-consumer one-liner. Inline the span in ModuleDetailPage. [web/src/components/KickerTag.tsx:1] ~-15
- `shrink` Scopes wrapping write:bool. Plain bool at call sites. [crates/detent-web/src/authz.rs:58] ~-20
- `shrink` ValidationCtx single-field &HostProfile wrapper. Pass &HostProfile directly. [crates/detent-core/src/descriptor.rs:302] ~-15
- `shrink` SandboxError tuple struct wrapping String, #[non_exhaustive] for variants that never arrived. Type alias until needed. [crates/detent-platform/src/privsep/spawn.rs:104] ~-5

## YAGNI / native (speculative surface, stdlib covers it)

- `native` web/src/lib/storage.ts, 38-line try/catch localStorage for 2 callers. Inline native calls. [web/src/lib/storage.ts:1] ~-38
- `yagni` linter.yml VALIDATE_PYTHON_RUFF / JAVASCRIPT_BIOME / CHECKOV / GITHUB_ACTIONS_ZIZMOR — dup ci web job or inapplicable (no Python, no IaC, pins job covers zizmor). [linter.yml:65-69] ~-4
- `yagni` codespell.yml stale super-linter comment + fetch-depth:0; semgrep.yml fetch-depth:0 works shallow. [codespell.yml:42 semgrep.yml:44] ~-4
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
