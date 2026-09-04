//! Operation layer: typed Operations, authz hooks, audit log, commit-confirm
//! state machine (PLAN §2.5).
//!
//! Every mutation of a managed host flows through one enum, [`Operation`],
//! executed by [`OpsEngine`]. The CLI, the web API, an MCP server and an
//! FFI-driven host construct operations; **none of them touches a file or a
//! service manager directly**. That is what makes a second or third front end
//! cheap to add, and what makes the audit log a complete record rather than a
//! best-effort one.
//!
//! ```text
//!   CLI / web / MCP ──▶ Operation ──▶ OpsEngine ──▶ privsep Client ──▶ monitor
//!                                        │
//!                                        ├─▶ Authz      (refuse before acting)
//!                                        ├─▶ AuditSink  (one record per mutation)
//!                                        └─▶ DynModule  (parse / render / validate)
//! ```
//!
//! # Guarantees
//!
//! * **Authorization first.** [`Authz::permit`] runs before anything is read
//!   or written, and a refusal is audited.
//! * **One audit record per mutation**, success or failure, carrying hashes
//!   and ids only — never a configuration body (see [`audit`]).
//! * **Plan writes nothing.** [`Operation::Plan`] reads the target, renders the
//!   candidate, diffs, and runs the module's upstream validators against a
//!   temporary file the *monitor* owns.
//! * **Apply refuses invalid input.** Any `Severity::Error` diagnostic stops
//!   the operation before the file is opened, and a stale `expected_hash` is a
//!   typed conflict rather than a lost update.
//! * **Rollback belongs to the monitor.** The engine starts and confirms
//!   commit-confirm windows; the timer, the `pending-commit.json` marker and
//!   the restore itself live in `detent-platform` (ADR-012).

pub mod audit;
pub mod authz;
pub mod diff;
mod engine;
mod error;
pub mod identity;
pub mod op;
pub mod report;

pub use audit::{
    AuditQuery, AuditRecord, AuditResult, AuditSink, CaptureAudit, FileAudit, NullAudit,
};
pub use authz::{AllowAll, Authz, Denied};
pub use diff::{DiffLine, Hunk};
pub use engine::OpsEngine;
pub use error::OpsError;
pub use identity::{Identity, IdentityKind};
pub use op::{OpKind, Operation, ServiceCommand};
pub use report::{OpOutcome, PlanReport};
