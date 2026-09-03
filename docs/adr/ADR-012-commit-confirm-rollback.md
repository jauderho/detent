# ADR-012: Commit-confirm auto-rollback
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

Devices in scope are often headless SBCs reached only over the network being
configured. A bad network, resolver, or mount change applied without a
safety net can permanently cut off the admin's only path back in (§1.1,
§2.5).

## Decision

For modules marked `commit_confirm = true` (network, resolver, mounts, §2.5,
§2.3 `ModuleDescriptor.commit_confirm`), `Apply` writes files, restarts
services, and starts a timer in the **monitor** (default 90 s). The UI/CLI
must call `ConfirmCommit`, which — arriving over the network — proves the
new configuration is still reachable. On timeout, or if the monitor restarts
and finds a `pending-commit` marker, it restores the backup and re-applies
the prior service action. Only one pending commit is allowed at a time
(§1.3, §2.5). The protocol carries this as `StartConfirmTimer` and
`ConfirmCommit` messages between worker and monitor (Appendix B).

## Consequences

Positive:
- Headless SBCs cannot be permanently bricked by a single bad interface or
  resolver change: the monitor, not the (possibly now-unreachable) worker,
  owns the rollback timer and survives a worker crash or the admin losing
  connectivity.
- The `pending-commit` marker surviving a monitor restart means even a full
  process crash during the confirm window still results in rollback rather
  than a stuck bad config (§2.5).

Negative:
- Every commit-confirm module needs backup/restore and service-action replay
  to be correct and race-free — a false "successful confirm" or a stuck
  marker is a correctness bug with real-world consequences.
- The single-pending-commit rule means concurrent commit-confirm operations
  on different modules must be serialized or explicitly queued, adding
  operational complexity to `OpsEngine`.

## Alternatives considered

- No automatic rollback, rely on the admin noticing and fixing a bad config
  manually — rejected: "Headless SBCs must not be bricked by a bad interface
  config" (§1.3 Why) is the stated reason for commit-confirm existing at all.

## References

PLAN.md §1.3 (ADR-012 row), §2.3 (`ModuleDescriptor.commit_confirm`), §2.5,
Appendix B (`StartConfirmTimer`, `ConfirmCommit` messages).
