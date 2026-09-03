//! OS layer: atomic file ops, backups, privsep monitor/worker, sandboxing,
//! service managers, host detection, shared HTTP client.
//!
//! `unsafe` is allowed in this crate only with a `// SAFETY:` comment
//! justifying the invariant being upheld.
#![deny(unsafe_code)]
