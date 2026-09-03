# Architecture Decision Records

This directory holds the binding architectural decisions for `detent`, in
MADR-lite format. Each ADR is traceable to `docs/PLAN.md` — the Decision
section cites the plan section it comes from, and any point PLAN.md leaves
ambiguous is called out under "Open points" in that ADR rather than decided
here.

## Rule: changing a decision requires a superseding ADR

An ADR's status is `Accepted` and stays that way. To change a decision, do
not edit the old file's Decision section. Write a new ADR that sets the old
one's status to `Superseded by ADR-NNN` and explains why. This keeps the
history of *why* a decision changed, not just what it changed to.

## Template

```
# ADR-NNN: <title>
Status: Accepted (YYYY-MM-DD)
Deciders: project owner (approved PLAN.md YYYY-MM-DD)
## Context
## Decision
## Consequences (positive / negative)
## Alternatives considered (one line each, why rejected)
## References (PLAN.md section numbers; external sources from PLAN §8.E where relevant)
```

File naming: `ADR-NNN-<kebab-slug>.md`, zero-padded to three digits.

## Index

| Number | Title | Status |
|---|---|---|
| ADR-001 | Privilege separation, OpenSSH style | Accepted |
| ADR-002 | Crypto provider — aws-lc-rs with ring fallback | Accepted |
| ADR-003 | i18n format — Project Fluent | Accepted |
| ADR-004 | One crate per module | Accepted |
| ADR-005 | Update verification via Sigstore / GitHub attestations | Accepted |
| ADR-006 | Aesthetic reconciliation — shadcn/ui + catfu tokens | Accepted |
| ADR-007 | Sessions and CSRF | Accepted |
| ADR-008 | Lossless document model and the six invariants | Accepted |
| ADR-009 | Runtime — tokio current-thread, axum 0.8, single hyper-rustls client | Accepted |
| ADR-010 | Panic policy and lints | Accepted |
| ADR-011 | 7-day supply-chain cooldown | Accepted |
| ADR-012 | Commit-confirm auto-rollback | Accepted |
| ADR-013 | Platform and architecture tiers | Accepted |
