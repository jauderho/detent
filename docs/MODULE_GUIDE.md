# Module guide

This is the authoritative walkthrough for adding a config module to
`detent`. A module is a crate under `crates/modules/<id>/` implementing the
`ConfigModule` trait: a lossless parser/renderer, a typed model, validation,
smart secure defaults, an external check, and a service binding. See
`docs/PLAN.md` §2.3 for the trait shape and invariants, and Appendix A for
the full authoring checklist this guide is written against.

TODO(Phase 1): written against the hosts module.
