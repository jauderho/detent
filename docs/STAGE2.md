# STAGE2 — Jev / TypeSafe opportunities (post-v1 experiment)

Status: **INVESTIGATION ONLY — DO NOT IMPLEMENT YET.** No production code
has changed for this stage.

Revised 2026-09-23 after the adversarial review in [`STAGE3.md`](STAGE3.md) §8.
The original 2026-09-22 investigation is commit `117e740`. This revision
corrects its premises, adds hard constraints, and drops one proposal.
**Do not revert this file to `117e740`.**

## 0. When to run this, and the gate

**Order: STAGE3 → rest of PLAN.md (through Phase 12 / M4 v1.0) → STAGE2.**

Nothing here is on the v1 critical path. Do not start until **all** of the
following hold:

1. Every STAGE3 item in batches 0–7 has landed, and CI (`ci.yml`,
   `fuzz.yml`) is green on `main`. Batches 8–10 are either landed or
   explicitly deferred by the owner.
2. The PLAN.md phases the owner wants in v1 are done (currently Phase 12 /
   M4). This includes `docs/THREAT_MODEL.md`, which must cover the egress
   this stage adds.
3. The owner has answered the **egress decision** (§5.1) with a yes. If the
   answer is no, this stage is closed and nothing ships.

If the owner prefers, §6 step 1 (the offline corpus harness) may run earlier,
because it touches no product code. It still needs STAGE3's H5 and H6 to
land first, since until then the apply path produces no check results for
it to measure.

## 1. What detent is (ground truth)

Single static Rust binary for lossless host-config management (hosts,
resolver, chrony, mounts, NFS, Samba, DHCP, network). Every front end
(CLI, TLS 1.3 web UI, MCP, FFI) builds an `Operation`
(`crates/detent-ops/src/op.rs`, 17 variants) and hands it to
`OpsEngine::execute` (`crates/detent-ops/src/engine.rs`). Execution goes through
audit (`audit.rs`) and commit-confirm rollback (`DEFAULT_CONFIRM` 90 s,
`op.rs`). The engine runs in the unprivileged worker, and root work goes
through the privsep monitor.

## 2. Current model spend: zero in-product

No inference crate, no model endpoint, no LLM step in CI (verified
2026-09-22). All spend today is dev-process: the PLAN.md delegation
contract, and Jev slice-routing noted in PROGRESS.md.

**Process rule (added from STAGE3):** Jev may order work, meaning it may
pick which slice comes next. It may **never** gate readiness: push,
merge, "done", or release. Those are deterministic gates (fmt, clippy
`--all-features`, tests, CI green). PROGRESS shows `push_ready` Nouls being
used while CI was red; that practice stops.

## 3. Live TypeSafe ground truth (re-check all of it at build time)

- API: `POST https://api.typesafe.ai/v1/systemone`, Bearer key. Choice,
  Noul and Score primitives. Pin `jev-1.13.0`, or whatever version is current
  when tuning starts; never `jev-latest` in product code.
- Pricing as of 2026-09-22: $0.042 per million input tokens, output free.
- Limits: 64k tokens per request (32k state), a ~20 QPS-equivalent rate limit,
  Choice ≤255 options, Score 2–10 levels. Rate limits adjust dynamically.
- Official SDKs are Python and JS only. From Rust use plain HTTP, reusing the
  **existing** hyper-rustls stack from `detent-update` (ADR-009). No new TLS
  dependency and no ADR-011 cooldown needed.
- Batching many questions over one state is about 12× cheaper and 10× faster
  than separate calls (vendor cookbook).
- **Cloudflare WAF (observed 2026-09-23):** requests whose text contained
  literal system paths (`/etc/...`) or privilege words were refused with
  HTTP 403 and an HTML body. Neutral wording passed. Real plan metadata
  contains exactly those words, which is one more reason for §5.2's
  structural-only state. The client must treat a 403 like any other failure
  (§5.3).
- Python `httpx` got 403 where `curl` succeeded (User-Agent filtering). Set an
  explicit User-Agent and test from the production client.

## 4. Opportunities (revised)

### 4.1 Apply blast-radius advisory — CONDITIONAL

**Corrected premises.** The 2026-09-22 text had three of them wrong:
- It said validator stdout "collapses via substring match". Only a test
  fixture uses `StdoutPattern`; every shipped module check is `ExitZero`
  (STAGE3 L-PLAT6).
- It assumed check results exist on the apply path. They do not: validators
  run only in `plan` (STAGE3 H5), and under a confined `serve` running one
  kills the monitor (STAGE3 H6). Until both are fixed, the "state" this
  advisory reads is empty.
- It called safety "time-only", as if that were the defect. A deterministic
  commit-confirm window is the right mechanism (ADR-012). The actual defect
  was that it was broken (STAGE3 H1–H4, H21, H22). A model must never
  compensate for a broken safety net.

**What remains valid, after STAGE3 lands:** an *advisory* that can make
apply harder, never easier. It may:
- require an explicit confirm on a module that does not need one;
- lengthen the confirm window;
- show a "high blast radius" banner.

Constraints are in §5. The question shape (a Score and a Choice in one
call) is unchanged, but it runs over §5.2's structural features, not
`unified_diff`:

```json
{"blast_radius":{"type":"score","instructions":"How large is the blast radius if this change is applied, given `module`, `service_action`, `affected_units`, `changed_lines`, and `checks`?","criteria":["No service impact.","Low: reloadable, easy revert.","High: restart of a time-critical service or a failing check.","Severe: likely loss of time sync, name resolution, or remote access."]},
 "friction":{"type":"choice","instructions":"Given `checks`, `diagnostic_ids`, and `service_action`, how much friction should apply add?","criteria":{"none":"No extra friction beyond the deterministic rules.","confirm":"Require an explicit confirm within the window.","hold":"Show a blocking warning; operator must re-submit to proceed."}}}
```

The options are named `none`/`confirm`/`hold`, not `auto_apply`/`block`. The
model cannot authorise anything; `none` means "the deterministic rules
alone".

### 4.2 Doctor urgency ranking — FIRST TRIAL (lowest risk)

The check is read-only and display-only, and no apply depends on it. Fields
sent: the check name, its `Status`, and a **fixed** detail id. Never send raw
mode bits with paths, or file contents. The answer is one Score (urgency
0–3) plus a Choice (`act_now`/`review`/`ignore`) per check, all in one call,
with the sorting done in code. The value is modest; run it first because
it is the cheapest way to prove the client, the failure handling and the
egress config end to end.

### 4.3 MCP natural-language → Operation routing — REJECTED

MCP clients are already LLMs that emit typed tool calls against 17
`deny_unknown_fields` schemas. A server-side NL router duplicates the
client's job and adds a prompt-injection surface: text inside a config file,
ticket or log could steer which operation runs. It offers no benefit over
the typed tools. Do not build it.

### Deprioritised (unchanged)

- **Audit triage:** records hold hashes and ids only, by design. The signal
  Noul was 0.53, which is too thin to act on.
- **Update-notes risk, diag relevance:** ranked p ≈ 0.0–0.03.
- **Authz, privsep, validation, and update verification:** never Jev. These
  are security boundaries and must stay deterministic.

## 5. Hard constraints (apply to anything built from this file)

### 5.1 Egress is an owner decision — `DECISION`

The web front end (the worker, confined but root-adjacent) would call a
third party. The feature is:
- **off by default**;
- enabled only by an explicit `[typesafe]` config section (`enabled`,
  `endpoint`, `model`, `timeout_ms`, and a key file path, 0600, never
  inline);
- documented in THREAT_MODEL.md and SECURITY_HARDENING.md.

The API key is a secret: redact it in `Debug` (the crate convention), keep
it out of logs and the audit trail, and never return it from an endpoint.
The call runs worker-side only, never in the monitor.

### 5.2 Structural state only — no file content

`PlanReport.rendered` is the whole candidate file, and `unified_diff`
carries full lines. Together they can include CIFS passwords, Kea DB
passwords, NM PSKs and TSIG keys (STAGE3 M6). The original "nothing beyond
what PlanReport exposes" rule therefore protects nothing.

The request state must be a dedicated typed struct with **no free-text
fields that could carry file content**:

```rust
struct ApplyFeatures {
    module: ModuleId,                         // registry id, closed set
    service_action: Option<ServiceCommand>,   // enum
    affected_units: Vec<&'static str>,        // from static UnitNames
    hunks: u32, lines_added: u32, lines_removed: u32,
    checks: Vec<CheckFeature>,                // { program_id, ran, passed, exit_code }
    diagnostic_ids: Vec<MessageId>,           // Fluent ids, not rendered text
    commit_confirm: bool,
}
```

Also add a unit test that serialises an `ApplyFeatures` built from a
`PlanReport` whose `rendered` contains `"hunter2"`, and asserts that the
string is absent.

### 5.3 Fail safe, and only ever add friction

- Any error, a timeout (≤ 1 s budget), 403, 429, 5xx or a parse failure
  means apply behaves **exactly as it would with the feature off**.
- The model's answer can only raise friction. It can never skip a
  descriptor's `commit_confirm`, never override a failing check (after
  STAGE3 H5, a failing check refuses the apply regardless), and never shorten
  a window.
- Low confidence (Choice confidence < 0.5) maps to `confirm`, never to
  `none`.
- Every advisory outcome is audit-visible: add a field for the friction
  level applied and whether the model or the fallback chose it. Record no
  model text.

### 5.4 Thresholds are per data set

The starting points below come from cookbooks and must be tuned on this
repo's corpus (§6):
- `hold` at ≥ 0.70 and `confirm` at ≥ 0.35 on the Choice probability;
- a blast-radius Score ≥ 2.0 counts as high.

## 6. Evaluation (falsifying) — must pass before any product code

Already done (2026-09-22, over diff-bearing state): a risky chrony plan
(failing check + restart) scored blast 2.03 with route `block` 0.75, versus
a benign hosts-comment plan at blast 0.0 with `auto_apply` 0.85. The
separation was clean, but **redo it with §5.2 structural state**, because
removing the diff text may remove the signal.

1. **Offline harness** (throwaway, under `/tmp`, not in the repo; PEP 723
   script or a `curl` driver):
   - Build a corpus of **30 plans**: 12 benign, 12 risky (failing check,
     restart of a network/resolver/chrony service, fstab without `nofail`),
     and 6 ambiguous.
   - Generate them with the real engine after STAGE3 H5 and H6, so the
     `checks` values are genuine.
2. **Sweep** thresholds on `friction` and `blast_radius`.
3. **Go criteria** (all required):
   - ≥ 90 % of risky plans land on `confirm` or `hold`;
   - **zero** benign plans land on `hold`;
   - p95 latency ≤ 1 s from a010 (the only Linux host allowed for implementing agents);
   - no WAF 403 on any corpus request;
   - Choice confidence < 0.6 on ≤ 30 % of the corpus.
4. **Kill conditions:** any criterion failing, or a Noul inversion on a
   control. If killed, record the result here and close §4.1. §4.2 may
   still ship on its own.

## 7. Build order (only after §0's gate)

1. The egress decision (§5.1). If no, stop.
2. The `[typesafe]` config plus a client in the worker: timeout, explicit
   User-Agent, fail-safe mapping, redacted key, and tests with a stub
   transport covering 200, 403, 429 and timeout.
3. §4.2, doctor ranking (read-only), shipped behind the flag.
4. The §6 evaluation for §4.1. Build §4.1 only if it passes, as an advisory
   within §5.3.
5. Re-run §6 whenever the pinned model version changes.
