# ADR-008: Lossless document model and the six invariants
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` edits config files that admins hand-edit and comment. A model that
discards comments, whitespace, ordering, or unrecognized directives would
silently destroy user intent and make diff previews dishonest (§1.1, §2.3).

## Decision

Each module parses its file into a concrete-syntax tree (`LosslessDoc`)
preserving comments, whitespace, order, and unknown directives; edits are
minimal; `render(parse(s)) == s` is a hard invariant (§1.3, §2.3). Every
module is checked by a shared conformance macro
(`detent_core::module_conformance!`) that enforces six invariants (§2.3):

1. `render(parse(s)) == s` for every `s` (proptest + fuzz).
2. `apply(doc, to_model(doc))` changes nothing.
3. For any valid model `m`: `to_model(apply(parse(s), m)) == m` (edit
   fidelity).
4. Rendered output re-parses to the same `Doc` (idempotence).
5. Values containing `\n`, `\r`, `\0`, or format-specific delimiters are
   rejected or quoted per format; never emitted raw (directive injection).
6. `parse` completes in bounded time on 1 MiB adversarial input (fuzz
   timeout).

## Consequences

Positive:
- Users' hand edits and comments survive round-trips; diff previews shown to
  the admin before `Apply` are honest, not reconstructions (§1.3 Why, §2.5
  Plan operation).
- Invariant 5 makes directive injection structurally hard to introduce per
  module, rather than relying on ad hoc escaping in each renderer.
- A shared conformance macro means every module, including ones written
  later by less specialized delegated agents, is held to the same bar
  automatically.

Negative:
- CST implementations (line-oriented, INI, lossless YAML/JSONC for netplan
  and Kea) are inherently more complex than parsing straight into a typed
  model; this is called out as a fidelity risk for netplan specifically (§7
  risk register: "Netplan YAML lossless editing is hard").
- 100% line coverage and adversarial fuzzing are required per module (§6.2,
  §6.3), which is a heavier bar than typical parser testing.

## Alternatives considered

- Parse-to-typed-model-only, discarding comments/formatting on write —
  rejected: this is the behavior the lossless model exists specifically to
  avoid (§2.3 rationale, "Users' hand edits and comments survive").

## References

PLAN.md §1.3 (ADR-008 row), §2.3, §6.2, §6.3, §7 (risk register, netplan
YAML fidelity), Appendix A (module authoring checklist).
