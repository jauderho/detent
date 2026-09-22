# STAGE2 — Jev / TypeSafe opportunities (post-initial-development)

Status: INVESTIGATION ONLY. No production code changed for this stage.
Do after initial development is complete. Re-validate pricing, limits,
and thresholds against live docs before building; cookbook numbers are
starting points, not universals.

## 1. What detent is (ground truth)

Single static Rust binary for lossless host-config management (hosts,
resolver, chrony, mounts, NFS, Samba, DHCP, network). Every front end
(CLI, TLS 1.3 web UI, MCP, FFI) builds `Operation`
(`crates/detent-ops/src/op.rs:93`, 17 variants) and hands it to
`OpsEngine::execute` (`crates/detent-ops/src/engine.rs`), with audit
(`crates/detent-ops/src/audit.rs`) and commit-confirm rollback
(`DEFAULT_CONFIRM` 90s, `op.rs:29`).

## 2. Current model spend: zero in-product (verified 2026-09-22)

- `Cargo.lock` grep `tch|ort|candle|tokenizers|llm|pyo3|ndarray`: no hits.
- Repo grep `llm|openai|anthropic|completions|/v1/chat|inference` over
  `crates/ web/src/`: only false positives (`embedded_slash`,
  `embedded_newline`, `prompt_tty`, provider API tokens). No inference
  crate, no model endpoint.
- All 11 `.github/workflows/*`: no LLM steps. Product egress is release
  feed + ACME + upstream feeds (plain HTTP, serde-parsed).
- Real spend today is dev-process: `docs/PLAN.md` Fable/Opus/Sonnet/Haiku
  delegation contract; Jev-routed slice decisions in `docs/PROGRESS.md`
  (`// (Jev-routed)` on `crates/detent/src/mcp.rs:128`
  `resolve_identity`).

Where reasoning ran for this investigation: default model did complex
reasoning (architecture mapping, brittle-point analysis, request-shape
design, economics, evaluation design). Jev (`jev-1.13.0`, live
`POST /v1/systemone`) did classification, filtering, routing, and simple
judgments: opportunity ranking, generation-risk/signal Nouls, impact
Scores, PlanReport risk probe + benign control. Each step is labeled
below as [default] or [Jev].

## 3. Live TypeSafe ground truth (vendor docs, re-check before build)

Source pages: `docs.typesafe.ai/models.md`, `api.md`, `concepts/state.md`,
`primitives.md`, `confidence.md`, `patterns/fan-out.md`,
`patterns/confidence-routing.md`, `cookbooks/parallel_questions.md`,
plus `llms.txt` index and skill `skill://typesafe-ai`.

- Pricing: **$42/Btok = $0.042/Mtok input, output free**, no per-call
  price. No dedicated pricing page; pricing lives on Models page.
- Limits: 250k tokens/s AND 1,200 req/min (≈20 QPS implied); 64k
  tokens/request (32k state + longest question); Choice ≤255 options;
  Score 2–10 levels; text-only state (string | JSON object | array).
  Errors include 401/422/429/529. Rate limits flagged by vendor as
  dynamically adjusting — re-check at build time.
- SDKs: official Python + JS/TS only. No official Rust SDK (both
  crates.io Rust clients self-describe unofficial). Rust path is plain
  HTTP `POST https://api.typesafe.ai/v1/systemone` with Bearer key;
  retry/backoff + `Retry-After` are ~30 lines to replicate.
- Batching (vendor cookbook, measured): 13 questions over 54k-char
  article in one call $0.000497/0.27s vs 13 calls $0.006090/2.71s →
  **12.2x cheaper, 10.0x faster, identical answers**. Sequential-call
  comparison; concurrent singles narrow latency but not token cost.
- Latency vendor-claim ~100ms typical, 70–500ms end-to-end [vendor].
  Our live probes (6 questions/state shapes): 0.24–0.42s (see §5).
- Patterns to reuse: speculative fan-out (one call, code consumes the
  applicable answers), confidence-gated routing (per-action thresholds),
  citation-check (string-match first, then Choice supports/contradicts/
  says_nothing, conf ≥0.8 auto), SDE cascade (cheap pass → Noul verifier
  battery → escalate flagged only), composite scoring (retune weights in
  code without new calls).

## 4. Ranked opportunities [Jev-ranked, default-designed]

Ranking probe [Jev]: state = project summary + 6 candidates, one
request, 1,126 in-tokens, `jev-1.13.0`. `best_first` Choice →
**apply_risk_gate 0.57 conf 0.49**; doctor_prioritize 0.23;
mcp_intent_route 0.14; audit_triage/diag_relevance/update_notes_risk
≤0.03. Impact Scores [Jev]: apply 2.22 (Large, conf 0.71), audit 1.77
(conf 0.72). Flag [Jev]: `needs_generation_apply` Noul 0.74 (apply gate
may need more than a snap judgment → keep advisory-only);
`needs_generation_mcp` 0.05 (closed-set fit);
`audit_has_signal` 0.53 (thin signal, borderline).

### 4.1 Apply blast-radius gate (best-first, advisory only)

Brittle today [default]: `DEFAULT_CONFIRM` 90s + `commit_confirm: bool`
(`op.rs:29`, `engine.rs:515-521`, `descriptor.rs:196-198`) — safety is
time-only, operator manually confirms or loses the change.
`CheckReport{passed: bool}` collapses validator stdout via substring
match (`detent-platform/src/service/checks.rs:96-101`).

State (exists, typed): `PlanReport{module,path,unified_diff,
diagnostics[{severity,id,field}],affected_services,
checks[{ran,passed,exit_code,detail}],current_hash,would_change}`
(`report.rs:77-99`) + `Apply{id,model,expected_hash,service_action,
confirm}` (`op.rs:118-132`).

Request shape (one fan-out call, three questions):
```json
{"blast_radius":{"type":"score","instructions":"How large is the blast radius if applied per `unified_diff`, `affected_services`, `service_action`?","criteria":["No service impact.","Low: reloadable, easy revert.","High: restart of time-critical service with failing check.","Severe: likely loss of sync/lockout."]},
 "route":{"type":"choice","instructions":"Given `checks`,`diagnostics`,`service_action`, how should apply proceed?","criteria":{"auto_apply":"Safe without friction.","require_confirm":"Apply but require explicit confirm in window.","block":"Do not apply; resolve failing check first."}},
 "check_supports_block":{"type":"noul","instructions":"Does the failing check in `checks` support blocking?","criteria":{"true":"Failing check is a blocker.","false":"Unrelated/not a blocker."}}}
```

Composition [default]: deterministic `validate` / `has_errors()` stays
authoritative; Jev only tunes friction (`route=block` → require
confirm, never silent auto-apply; low Choice confidence →
require_confirm). Threshold starting points (tune on own plans):
`block≥0.70/review≥0.35` per guardrails cookbook, blast-gate analogue
`blast_radius≥2.0`. Pin `jev-1.13.0`, not `jev-latest`, once tuned.

### 4.2 Doctor urgency rank

Brittle today: `Status{Ok,Warn,Fail}` + `mode_status` bit masks
(`crates/detent/src/doctor.rs:45,207`) — whole Warn band is display-only
manual review. State: `Report{host: HostReport, checks:
Vec<Check{name,status,detail}>, ok}` + raw mode bits + kernel file
contents + `privsep_verdict`. Shape: one Score (urgency 0–3) + one
Choice (act_now/review/ignore) per check in one fan-out call; sort by
Score in code.

### 4.3 MCP NL→Operation intent route

Closed-set fit [Jev Noul 0.05 = no generation needed]. State: operator
utterance + 17 `Operation` variants + module ids. Shape: one Choice (17
options, inside 255 cap) + per-branch speculative Nouls (needs
`service_action`? needs `confirm`?) in the same call; downstream
`deny_unknown_fields` + authz validate. Confidence <0.5 → ask-clarify
(intent-routing cookbook gate).

### Deprioritized

- Audit triage: signal Noul only 0.53 — `AuditRecord` is hashes+ids, no
  bodies by design (`audit.rs:57-76`). Revisit only if review load
  proves painful.
- Update-notes risk, diag-relevance: Jev p≈0.0–0.03 in ranking.
- Authz granularity and privsep path: deliberately NOT Jev fits — must
  stay deterministic (security boundary).

## 5. Economics (measured live probes [Jev])

- Risky chrony-NTS plan (failing `chronyd -Q`, restart): `blast_radius`
  **2.03 conf 0.97**, `route` **block 0.75 conf 0.62**,
  `check_supports_block` **0.85** — 803 in-tokens, 0.24s.
- Benign hosts-comment control: blast **0.0 conf 1.0**, `route`
  **auto_apply 0.85 conf 0.78**, support-block **0.04** — 682 tokens,
  0.26s. Clean separation in the needed direction.
- Cost math: ~800 in-tokens × $0.042/10^6 ≈ **$0.000034/call**; 10k
  applies/day ≈ $0.34/day. Latency ~0.25s is noise next to privsep
  write + service restart. Batch per-check questions (state paid once)
  if ever fan-out heavy.

## 6. Falsifying evaluation

Done [Jev]: risky-vs-benign separation passed (block vs auto_apply,
blast 2.03 vs 0.0). Kills the proposal: route confidence <0.6 on >30%
of a 20-plan corpus, Noul inversion on controls, or p95 latency >1s on
the apply path.

Next (build after initial dev): 20-plan corpus (10 benign, 10
failing-check/restarts) + threshold sweep on `route`/`blast_radius`.
Go-criteria: ≥90% risky→block/require_confirm with zero benign→block;
else drop to doctor-only or abandon. Keep credentials server-side;
never send config bodies beyond what PlanReport already exposes.

## 7. Build order (when Stage 2 starts)

1. Apply gate probe harness (throwaway first, then corpus + sweep).
2. Doctor rank (read-only, lowest risk).
3. MCP intent route (closed-set, validated downstream).
4. Revisit audit triage only with operator-pain evidence.
