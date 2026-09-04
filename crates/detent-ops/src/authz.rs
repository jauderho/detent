//! The authorization hook.
//!
//! [`OpsEngine`](crate::OpsEngine) asks an [`Authz`] before it does anything,
//! and records every refusal in the audit log. v1 has no RBAC (PLAN §1.2), so
//! the only implementation here is [`AllowAll`], which is the correct policy
//! for the CLI: its authority is already the uid of the process running it, and
//! a second check inside the same process would be theatre. Phase 4 adds the
//! scoped-token policy the web layer needs; it plugs in here without touching
//! the engine.

use detent_core::diag::MessageId;

use crate::identity::Identity;
use crate::op::Operation;

/// Why an operation was refused.
///
/// Carries a Fluent id rather than a sentence, like everything else that can
/// reach a user (`detent-core`'s `diag` module explains the convention).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("operation refused: {}", .id.as_str())]
pub struct Denied {
    /// Fluent id of the refusal message.
    pub id: MessageId,
    /// Which scope or role would have permitted it, when the policy can say.
    pub required_scope: Option<String>,
}

impl Denied {
    /// A refusal with no scope hint.
    #[must_use]
    pub const fn new(id: MessageId) -> Self {
        Self {
            id,
            required_scope: None,
        }
    }

    /// A refusal naming the scope that would have allowed the operation.
    #[must_use]
    pub fn with_scope(id: MessageId, scope: impl Into<String>) -> Self {
        Self {
            id,
            required_scope: Some(scope.into()),
        }
    }
}

/// Decides whether `who` may run `op`.
pub trait Authz: Send + Sync {
    /// Permit or refuse one operation.
    ///
    /// # Errors
    ///
    /// [`Denied`] when the policy refuses. The engine turns that into an
    /// audit record and an error; nothing is read or written.
    fn permit(&self, who: &Identity, op: &Operation) -> Result<(), Denied>;
}

/// The CLI policy: everything is permitted.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Authz for AllowAll {
    fn permit(&self, _who: &Identity, _op: &Operation) -> Result<(), Denied> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowAll, Authz as _, Denied};
    use crate::identity::Identity;
    use crate::op::Operation;
    use detent_core::diag::MessageId;

    #[test]
    fn allow_all_permits_every_operation() {
        let who = Identity::local("root");
        assert!(AllowAll.permit(&who, &Operation::ListModules).is_ok());
        assert!(AllowAll.permit(&who, &Operation::HostProfile).is_ok());
        assert_eq!(format!("{AllowAll:?}"), "AllowAll");
    }

    #[test]
    fn denied_carries_a_message_id_and_an_optional_scope() {
        let bare = Denied::new(MessageId::new("ops-denied"));
        assert_eq!(bare.id.as_str(), "ops-denied");
        assert_eq!(bare.required_scope, None);
        assert_eq!(bare.to_string(), "operation refused: ops-denied");

        let scoped = Denied::with_scope(MessageId::new("ops-denied"), "write");
        assert_eq!(scoped.required_scope.as_deref(), Some("write"));
        assert_ne!(scoped, bare);
        assert_eq!(scoped.clone(), scoped);
        assert!(format!("{scoped:?}").contains("write"));
    }
}
