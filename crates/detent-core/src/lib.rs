//! Pure core of `detent`: the lossless document model, the module SDK, diagnostics,
//! and the conformance harness that every config module is held to.
//!
//! This crate performs **no I/O**, spawns no threads, uses no `async`, and contains
//! no `unsafe` code. Everything here is a total function over in-memory data, which
//! is what makes it safe to link into `libdetent` and to fuzz aggressively.
//!
//! # Layout
//!
//! * [`doc`] — the line-oriented lossless concrete syntax tree (`Span`, `Line`,
//!   [`Document`](doc::Document)) shared by the line-based config formats.
//! * [`diag`] — [`Severity`](diag::Severity), [`Diagnostic`](diag::Diagnostic) and
//!   [`Diagnostics`](diag::Diagnostics); message ids are Fluent ids, this crate does
//!   not localize.
//! * [`descriptor`] — static module metadata (targets, upstream tracking, service
//!   bindings, external checks) plus the `x-detent` JSON Schema UI hints.
//! * [`module`] — the [`ConfigModule`](module::ConfigModule) trait, its error types,
//!   and the object-safe [`DynModule`](module::DynModule) JSON adapter.
//! * [`align`] — the bounded Myers alignment shared by the plan diff and by
//!   [`Document::edit_entries`](doc::Document::edit_entries).
//! * [`conformance`] — the six invariant checks and the
//!   [`module_conformance!`](crate::module_conformance) macro that wires them into
//!   a module crate's test suite.
#![forbid(unsafe_code)]

pub mod align;
pub mod conformance;
pub mod descriptor;
pub mod diag;
pub mod doc;
pub mod module;
