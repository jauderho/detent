//! Who is asking.
//!
//! The operations layer does not authenticate anybody: each front end proves
//! identity its own way (the CLI's authority is the uid running it, the web
//! layer's is a session cookie or a bearer token) and hands the result here as
//! an [`Identity`]. Everything downstream — [`Authz`](crate::authz::Authz) and
//! the audit log — sees only this value.

use serde::{Deserialize, Serialize};

/// How a caller was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum IdentityKind {
    /// A local user running the CLI. Its authority is the uid of the process.
    LocalUser,
    /// A browser session established by the web layer (Phase 4).
    Session,
    /// An API token presented as a bearer credential (Phase 4).
    Token,
}

/// The caller, as the front end resolved it.
///
/// `subject` is a display/audit handle — a user name, a session subject, a
/// token label — never a credential. Nothing in this crate treats it as a
/// secret, because it is written verbatim to the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Stable name of the caller, for the audit log.
    pub subject: String,
    /// How the caller was authenticated.
    pub kind: IdentityKind,
}

impl Identity {
    /// A local CLI caller.
    #[must_use]
    pub fn local(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            kind: IdentityKind::LocalUser,
        }
    }

    /// A caller of any kind.
    #[must_use]
    pub fn new(subject: impl Into<String>, kind: IdentityKind) -> Self {
        Self {
            subject: subject.into(),
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Identity, IdentityKind};

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn identities_round_trip_as_json() -> R {
        let who = Identity::local("root");
        assert_eq!(who.kind, IdentityKind::LocalUser);
        let json = serde_json::to_value(&who)?;
        assert_eq!(
            json.pointer("/kind").and_then(|v| v.as_str()),
            Some("local_user")
        );
        assert_eq!(serde_json::from_value::<Identity>(json)?, who);

        for kind in [IdentityKind::Session, IdentityKind::Token] {
            let who = Identity::new("alice", kind);
            let json = serde_json::to_value(&who)?;
            assert_eq!(serde_json::from_value::<Identity>(json)?, who);
            assert_eq!(who.clone(), who);
        }
        assert!(format!("{who:?}").contains("root"));
        Ok(())
    }
}
