//! Scopes, and the policy that maps an [`Operation`] onto one (PLAN §2.7).
//!
//! ```text
//!   session cookie ─┐                     ┌─ Scope::Read  ── every read-only op
//!                   ├─▶ Scopes ─▶ ScopedAuthz ─┤
//!   Bearer token ───┘        (per request)     └─ Scope::Write ── every mutating op
//! ```
//!
//! `detent-ops` fixes its [`Authz`] at engine construction time, but a web
//! caller's authority changes with every request: one request arrives with a
//! read-only token, the next with an administrator's session. So
//! [`ScopedAuthz`] is built **per request** from the scopes the extractor
//! resolved, and the API layer asks it before handing the operation to the
//! engine. It implements [`Authz`] rather than inventing a second trait, so
//! the day a per-connection engine exists it plugs straight in.
//!
//! # Guarantees
//!
//! * **Adding an [`Operation`] variant is a compile error here.**
//!   [`ScopedAuthz::required_scope`] matches every variant by name rather than
//!   delegating to [`Operation::is_mutating`], so a new operation cannot
//!   inherit "read" by omission.
//! * **`read` is implied by `write`.** A `write` caller can also read; there
//!   is no operation that writing permits and reading forbids.
//! * **A refusal says what was missing.** [`Denied::with_scope`] carries
//!   `write`, so the front end can tell the operator to use a token that has
//!   it instead of showing a bare "forbidden".

use detent_core::diag::MessageId;
use detent_ops::authz::{Authz, Denied};
use detent_ops::identity::Identity;
use detent_ops::op::Operation;
use serde::{Deserialize, Serialize};

/// Fluent id of a refusal caused by a missing scope.
pub const DENIED_SCOPE_ID: &str = "web-denied-scope";

/// One capability a caller may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read anything: descriptors, models, diffs, service status, the audit
    /// log. Writes nothing and starts no service action.
    Read,
    /// Change the host: apply, restore, confirm or roll back a commit, act on
    /// a service. Implies [`Scope::Read`].
    Write,
}

impl Scope {
    /// The wire name, as it appears in an API response and in `tokens.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// The set of scopes one caller holds.
///
/// Only two sets are reachable — read, and read+write — so this is a flag
/// rather than a collection. Rendering it as a list keeps the API shape
/// stable if v2 ever adds a third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scopes {
    /// Whether [`Scope::Write`] is held. [`Scope::Read`] always is.
    write: bool,
}

impl Scopes {
    /// Read-only authority.
    #[must_use]
    pub const fn read_only() -> Self {
        Self { write: false }
    }

    /// Full authority: read and write.
    #[must_use]
    pub const fn read_write() -> Self {
        Self { write: true }
    }

    /// The set a token with `scope` gets.
    #[must_use]
    pub const fn of(scope: Scope) -> Self {
        match scope {
            Scope::Read => Self::read_only(),
            Scope::Write => Self::read_write(),
        }
    }

    /// Whether `needed` is held.
    #[must_use]
    pub const fn allows(self, needed: Scope) -> bool {
        match needed {
            Scope::Read => true,
            Scope::Write => self.write,
        }
    }

    /// The scopes held, for an API response: `["read"]` or `["read", "write"]`.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        if self.write {
            vec![Scope::Read.as_str(), Scope::Write.as_str()]
        } else {
            vec![Scope::Read.as_str()]
        }
    }
}

/// The web layer's authorization policy: one caller's scopes, checked against
/// one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedAuthz {
    /// What the caller holds.
    scopes: Scopes,
}

impl ScopedAuthz {
    /// A policy for a caller holding `scopes`.
    #[must_use]
    pub const fn new(scopes: Scopes) -> Self {
        Self { scopes }
    }

    /// The scopes this policy was built with.
    #[must_use]
    pub const fn scopes(&self) -> Scopes {
        self.scopes
    }

    /// The scope `op` requires.
    ///
    /// Matched variant by variant on purpose: [`Operation::is_mutating`] is
    /// the *definition* used here, but delegating to it would let a new
    /// variant default to read-only, and the compiler would say nothing.
    #[must_use]
    pub fn required_scope(op: &Operation) -> Scope {
        match *op {
            Operation::Apply { .. }
            | Operation::ConfirmCommit { .. }
            | Operation::RollbackCommit { .. }
            | Operation::Restore { .. }
            | Operation::ServiceAction { .. }
            | Operation::CertRenew => Scope::Write,
            Operation::ListModules
            | Operation::GetModule { .. }
            | Operation::Validate { .. }
            | Operation::Plan { .. }
            | Operation::ListBackups { .. }
            | Operation::ServiceStatus { .. }
            | Operation::HostProfile
            | Operation::CertStatus
            | Operation::UpdateStatus
            | Operation::AuditQuery(_) => Scope::Read,
        }
    }
}

impl Authz for ScopedAuthz {
    fn permit(&self, _who: &Identity, op: &Operation) -> Result<(), Denied> {
        let needed = Self::required_scope(op);
        if self.scopes.allows(needed) {
            return Ok(());
        }
        Err(Denied::with_scope(
            MessageId::new(DENIED_SCOPE_ID),
            needed.as_str(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{DENIED_SCOPE_ID, Scope, ScopedAuthz, Scopes};
    use detent_ops::authz::Authz as _;
    use detent_ops::identity::Identity;
    use detent_ops::op::{Operation, ServiceCommand};
    use detent_platform::privsep::proto::{BackupId, CommitId};
    use serde_json::json;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../locales/en-US/core.ftl");

    /// Every variant of [`Operation`], so the exhaustive match is exercised
    /// end to end rather than only type-checked.
    fn every_operation() -> Vec<Operation> {
        vec![
            Operation::ListModules,
            Operation::GetModule {
                id: "hosts".to_owned(),
            },
            Operation::Validate {
                id: "hosts".to_owned(),
                model: json!({}),
            },
            Operation::Plan {
                id: "hosts".to_owned(),
                model: json!({}),
            },
            Operation::Apply {
                id: "hosts".to_owned(),
                model: json!({}),
                expected_hash: None,
                service_action: None,
                confirm: None,
            },
            Operation::ConfirmCommit {
                commit_id: CommitId(1),
            },
            Operation::RollbackCommit {
                commit_id: CommitId(1),
            },
            Operation::ListBackups {
                id: "hosts".to_owned(),
            },
            Operation::Restore {
                id: "hosts".to_owned(),
                backup_id: BackupId(0),
            },
            Operation::ServiceStatus {
                id: "hosts".to_owned(),
            },
            Operation::ServiceAction {
                id: "hosts".to_owned(),
                action: ServiceCommand::Restart,
            },
            Operation::HostProfile,
            Operation::AuditQuery(detent_ops::audit::AuditQuery::default()),
            Operation::CertRenew,
        ]
    }

    #[test]
    fn the_required_scope_is_write_exactly_for_mutating_operations() {
        for op in every_operation() {
            let needed = ScopedAuthz::required_scope(&op);
            assert_eq!(
                needed == Scope::Write,
                op.is_mutating(),
                "{op:?} maps to {needed:?}"
            );
        }
    }

    #[test]
    fn write_implies_read_and_read_does_not_imply_write() {
        let read = Scopes::read_only();
        let write = Scopes::read_write();
        assert!(read.allows(Scope::Read));
        assert!(!read.allows(Scope::Write));
        assert!(write.allows(Scope::Read));
        assert!(write.allows(Scope::Write));
        assert_eq!(Scopes::of(Scope::Read), read);
        assert_eq!(Scopes::of(Scope::Write), write);
        assert_eq!(read.names(), vec!["read"]);
        assert_eq!(write.names(), vec!["read", "write"]);
        assert_eq!(Scope::Read.as_str(), "read");
        assert_eq!(Scope::Write.as_str(), "write");
        assert_ne!(read, write);
        assert_eq!(format!("{read:?}"), "Scopes { write: false }");
    }

    #[test]
    fn a_read_only_caller_may_read_everything_and_write_nothing() {
        let policy = ScopedAuthz::new(Scopes::read_only());
        let who = Identity::new("token:ci", detent_ops::identity::IdentityKind::Token);
        for op in every_operation() {
            let verdict = policy.permit(&who, &op);
            assert_eq!(verdict.is_ok(), !op.is_mutating(), "{op:?}");
            if let Err(denied) = verdict {
                assert_eq!(denied.id.as_str(), DENIED_SCOPE_ID);
                assert_eq!(denied.required_scope.as_deref(), Some("write"));
            }
        }
        assert_eq!(policy.scopes(), Scopes::read_only());
        assert_eq!(policy, ScopedAuthz::new(Scopes::read_only()));
        assert!(format!("{policy:?}").contains("write: false"));
    }

    #[test]
    fn a_read_write_caller_may_do_everything() {
        let policy = ScopedAuthz::new(Scopes::read_write());
        let who = Identity::new("alice", detent_ops::identity::IdentityKind::Session);
        for op in every_operation() {
            assert!(policy.permit(&who, &op).is_ok(), "{op:?}");
        }
    }

    #[test]
    fn scopes_round_trip_through_json_by_name() -> R {
        assert_eq!(serde_json::to_value(Scope::Read)?, json!("read"));
        assert_eq!(serde_json::to_value(Scope::Write)?, json!("write"));
        assert_eq!(
            serde_json::from_value::<Scope>(json!("write"))?,
            Scope::Write
        );
        assert!(serde_json::from_value::<Scope>(json!("admin")).is_err());
        Ok(())
    }

    #[test]
    fn the_refusal_id_is_in_the_catalogue() {
        assert!(
            CATALOGUE.lines().any(|line| line
                .split('=')
                .next()
                .is_some_and(|k| k.trim() == DENIED_SCOPE_ID)),
            "`{DENIED_SCOPE_ID}` is missing from core.ftl"
        );
    }
}
