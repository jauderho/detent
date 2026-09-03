# ADR-009: Runtime — tokio current-thread, axum 0.8, single hyper-rustls client
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` targets SBC/IoT/GPS-server devices with tight memory budgets (§1.1,
§4.1: ≤ 30 MiB idle RSS for the full default build). Both the web server and
the ACME/update clients need an HTTP stack, and pulling in two different HTTP
or TLS stacks would waste both binary size and RSS.

## Decision

Use the tokio **current-thread** runtime, axum **0.8**, and no `reqwest` — a
single hyper-rustls client, shared by ACME and update (§1.3, §2.1, §2.9).
`detent-platform::http::Client` is that one client, with timeouts, size caps,
and `webpki-roots` (§2.2). The dependency policy explicitly excludes
`reqwest`, `openssl`, and "anything pulling in a second TLS or HTTP stack"
(§4.2).

## Consequences

Positive:
- Memory footprint and dependency surface are both reduced: one HTTP client,
  one TLS stack, one runtime flavor, matching the size/RSS budgets in §4.1.
- A single shared HTTP client for ACME and update means one place to enforce
  timeouts, response size caps, and TLS configuration consistently.

Negative:
- Current-thread runtime means no automatic work-stealing across cores; any
  future workload that benefits from multi-threaded tokio would need an
  explicit ADR change.
- Building ACME and update on the same shared client means a bug or resource
  leak in the client affects both subsystems simultaneously.

## Alternatives considered

- `reqwest` for ACME/update, axum's own client for the web server — rejected:
  explicitly excluded ("Avoid: reqwest … a second TLS or HTTP stack", §4.2)
  in favor of "Memory footprint and dependency surface" (§1.3 Why).
- Multi-threaded tokio runtime — not chosen; §1.3 specifies current-thread
  without further justification in the text beyond the general footprint
  rationale.

## Resolution of the current-thread choice

Current-thread is chosen because the daemon serves one administrator, not a
fleet: request concurrency is in the single digits, and a multi-threaded
runtime adds one stack and scheduler state per core on boards that may have
512 MiB of RAM. CPU-heavy work (Argon2id, cert verification) runs on
`tokio::task::spawn_blocking` with `max_blocking_threads = 2`, so login
hashing never stalls the event loop. Revisit only if a measured workload shows
event-loop starvation.

## References

PLAN.md §1.3 (ADR-009 row), §2.1, §2.2, §2.9, §4.1, §4.2, §8.E (axum 0.8.9,
tokio 1.53.1 pinned versions).
