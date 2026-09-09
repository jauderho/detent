//! The auth event log (PLAN §2.7, "Misc": *audit for every auth event*).
//!
//! ```text
//!   login / logout / lockout / token issue / token revoke
//!            │
//!            ├─▶ tracing::info!(… "detent audit")  ── journald, one stream
//!            └─▶ AuthAudit sink ─▶ <state_root>/audit/detent-auth.jsonl (0600)
//! ```
//!
//! # Why this is not `detent_ops::audit`
//!
//! It would be, if it could be. `detent_ops::AuditRecord` types its `op` field
//! as `OpKind`, a closed enum of *operations* — `apply`, `restore`,
//! `service_action` and so on. There is no `login` in it, and adding one means
//! changing `detent-ops`, which this change may not do. Writing an auth event
//! into the same file with an invented `op` value would make
//! `detent_ops::FileAudit::query` skip the line as unparseable, so `detent
//! audit` would silently drop exactly the records an operator most wants after
//! a break-in.
//!
//! So auth events go to a **sibling file in the same directory**, in the same
//! JSON-lines shape, with the same `0600` mode and the same append-only
//! discipline — and, crucially, to the same `tracing` event name (`detent
//! audit`) as [`detent_ops::OpsEngine`], so journald and syslog see one
//! stream. When `detent-ops` grows auth operation kinds, this module becomes a
//! thin adapter over `AuditSink` and the second file goes away.
//!
//! # Guarantees
//!
//! * **A record carries no credential.** Subject, event, result, source
//!   address and a Fluent id; never a password, a token, a session id or a
//!   TOTP secret. [`AuthRecord`] has no field that could hold one.
//! * **A sink failure never fails the request.** It is logged at `error` and
//!   the operation's own result stands, exactly as `OpsEngine::emit` does.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use detent_ops::audit::AuditResult;
use detent_ops::identity::IdentityKind;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Mode of the auth log: readable only by the account that owns the state
/// directory.
const AUDIT_FILE_MODE: u32 = 0o600;

/// Directory under the state root that holds the logs (PLAN §2.10).
pub const AUDIT_SUBDIR: &str = "audit";

/// File the auth events are appended to.
pub const AUTH_LOG_FILE: &str = "detent-auth.jsonl";

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEvent {
    /// Credentials were accepted and a session was established.
    LoginSucceeded,
    /// Credentials were refused.
    LoginFailed,
    /// A principal was locked out by the rate limiter.
    LockedOut,
    /// A session was explicitly ended.
    LoggedOut,
    /// An API token was minted.
    TokenIssued,
    /// An API token was revoked.
    TokenRevoked,
}

/// One line of the auth log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRecord {
    /// When, as RFC 3339 in UTC.
    pub ts: String,
    /// What happened.
    pub event: AuthEvent,
    /// Who it was about: a user name, a rate-limit principal, or a token id.
    /// Never a credential.
    pub subject: String,
    /// How the subject was (or would have been) authenticated.
    pub kind: IdentityKind,
    /// The address the request came from.
    pub client_ip: Option<String>,
    /// How it ended.
    pub result: AuditResult,
    /// Fluent id of the failure, when it failed.
    pub detail: Option<String>,
}

impl AuthRecord {
    /// A record stamped with the current UTC time.
    #[must_use]
    pub fn new(event: AuthEvent, subject: impl Into<String>, result: AuditResult) -> Self {
        Self {
            ts: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            event,
            subject: subject.into(),
            kind: IdentityKind::Session,
            client_ip: None,
            result,
            detail: None,
        }
    }

    /// Say how the subject authenticated.
    #[must_use]
    pub const fn with_kind(mut self, kind: IdentityKind) -> Self {
        self.kind = kind;
        self
    }

    /// Attach the source address.
    #[must_use]
    pub fn with_client_ip(mut self, ip: impl std::fmt::Display) -> Self {
        self.client_ip = Some(ip.to_string());
        self
    }

    /// Attach the Fluent id of the failure.
    #[must_use]
    pub fn with_detail(mut self, id: detent_core::diag::MessageId) -> Self {
        self.detail = Some(id.as_str().to_owned());
        self
    }
}

/// Where auth records go.
pub trait AuthAudit: Send + Sync + std::fmt::Debug {
    /// Append one record. A failure is this implementation's problem to log,
    /// not the caller's to handle: the login already happened.
    fn record(&self, record: &AuthRecord);

    /// Read records back, newest first. Used by tests and, in Phase 4c, by
    /// the audit endpoint.
    fn query(&self, limit: Option<usize>) -> Vec<AuthRecord>;
}

/// Write `record` to `tracing` and to `sink`.
///
/// The `tracing` event carries the same message as
/// [`detent_ops::OpsEngine`]'s, so journald sees one audit stream rather than
/// two.
pub fn emit(sink: &dyn AuthAudit, record: &AuthRecord) {
    tracing::info!(
        event = ?record.event,
        who = %record.subject,
        kind = ?record.kind,
        client_ip = ?record.client_ip,
        result = ?record.result,
        error_id = ?record.detail,
        "detent audit"
    );
    sink.record(record);
}

/// The real sink: one JSON object per line, appended, `0600`.
#[derive(Debug, Clone)]
pub struct FileAuthAudit {
    /// The file appended to.
    path: PathBuf,
}

impl FileAuthAudit {
    /// A sink writing to `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The conventional location under a state root, beside
    /// `detent-audit.jsonl`.
    #[must_use]
    pub fn under_state_root(state_root: &Path) -> Self {
        Self::new(state_root.join(AUDIT_SUBDIR).join(AUTH_LOG_FILE))
    }

    /// The file this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one line, or say why not.
    fn append(&self, record: &AuthRecord) -> Result<(), std::io::Error> {
        let mut line =
            serde_json::to_vec(record).map_err(|err| std::io::Error::other(err.to_string()))?;
        line.push(b'\n');
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(AUDIT_FILE_MODE)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.sync_data()
    }
}

impl AuthAudit for FileAuthAudit {
    fn record(&self, record: &AuthRecord) {
        if let Err(err) = self.append(record) {
            tracing::error!(error = %err, "the auth audit record could not be persisted");
        }
    }

    fn query(&self, limit: Option<usize>) -> Vec<AuthRecord> {
        let Ok(raw) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let mut records: Vec<AuthRecord> = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        records.reverse();
        if let Some(limit) = limit {
            records.truncate(limit);
        }
        records
    }
}

/// A sink that discards everything, for tests that are not about auditing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullAuthAudit;

impl AuthAudit for NullAuthAudit {
    fn record(&self, _record: &AuthRecord) {}

    fn query(&self, _limit: Option<usize>) -> Vec<AuthRecord> {
        Vec::new()
    }
}

/// An in-memory sink, so a test can assert on what a request audited.
#[derive(Debug, Default)]
pub struct CaptureAuthAudit {
    /// Everything recorded, oldest first.
    records: Mutex<Vec<AuthRecord>>,
}

impl CaptureAuthAudit {
    /// An empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything captured so far, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<AuthRecord> {
        self.records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }

    /// The events captured so far, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<AuthEvent> {
        self.records().iter().map(|record| record.event).collect()
    }
}

impl AuthAudit for CaptureAuthAudit {
    fn record(&self, record: &AuthRecord) {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
    }

    fn query(&self, limit: Option<usize>) -> Vec<AuthRecord> {
        let mut records = self.records();
        records.reverse();
        if let Some(limit) = limit {
            records.truncate(limit);
        }
        records
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_LOG_FILE, AuthAudit as _, AuthEvent, AuthRecord, CaptureAuthAudit, FileAuthAudit,
        NullAuthAudit, emit,
    };
    use detent_core::diag::MessageId;
    use detent_ops::audit::AuditResult;
    use detent_ops::identity::IdentityKind;
    use std::os::unix::fs::PermissionsExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_record_carries_the_event_and_nothing_secret() -> R {
        let record = AuthRecord::new(AuthEvent::LoginFailed, "alice", AuditResult::Error)
            .with_kind(IdentityKind::Session)
            .with_client_ip("198.51.100.7")
            .with_detail(MessageId::new("web-auth-invalid-credentials"));
        assert!(!record.ts.is_empty());
        assert_eq!(record.subject, "alice");
        assert_eq!(record.client_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            record.detail.as_deref(),
            Some("web-auth-invalid-credentials")
        );

        let json = serde_json::to_string(&record)?;
        assert!(json.contains("\"event\":\"login_failed\""), "{json}");
        assert_eq!(serde_json::from_str::<AuthRecord>(&json)?, record);
        Ok(())
    }

    #[test]
    fn the_file_sink_appends_json_lines_0600() -> R {
        let root = tempfile::tempdir()?;
        let sink = FileAuthAudit::under_state_root(root.path());
        assert!(sink.path().ends_with(AUTH_LOG_FILE));

        for event in [
            AuthEvent::LoginSucceeded,
            AuthEvent::LoggedOut,
            AuthEvent::TokenIssued,
            AuthEvent::TokenRevoked,
            AuthEvent::LockedOut,
        ] {
            emit(&sink, &AuthRecord::new(event, "alice", AuditResult::Ok));
        }

        let raw = std::fs::read_to_string(sink.path())?;
        assert_eq!(raw.lines().count(), 5);
        assert_eq!(
            std::fs::metadata(sink.path())?.permissions().mode() & 0o777,
            0o600
        );

        let back = sink.query(Some(2));
        assert_eq!(back.len(), 2);
        assert_eq!(
            back.first().map(|record| record.event),
            Some(AuthEvent::LockedOut),
            "the newest record should come first"
        );
        assert_eq!(sink.query(None).len(), 5);
        Ok(())
    }

    #[test]
    fn an_unwritable_sink_does_not_fail_the_caller() {
        // A path whose parent cannot be created: the record is dropped with a
        // log line, and `emit` still returns.
        let sink = FileAuthAudit::new("/proc/detent-auth-should-not-exist/log.jsonl");
        emit(
            &sink,
            &AuthRecord::new(AuthEvent::LoginFailed, "alice", AuditResult::Error),
        );
        assert!(sink.query(None).is_empty());
    }

    #[test]
    fn an_unparseable_line_is_skipped_rather_than_poisoning_the_read() -> R {
        let root = tempfile::tempdir()?;
        let sink = FileAuthAudit::under_state_root(root.path());
        sink.record(&AuthRecord::new(
            AuthEvent::LoginSucceeded,
            "alice",
            AuditResult::Ok,
        ));
        // A crash mid-append leaves a truncated final line.
        if let Some(parent) = sink.path().parent() {
            let mut existing = std::fs::read_to_string(sink.path())?;
            existing.push_str("{\"ts\":\"trunc\n\n");
            std::fs::write(parent.join(AUTH_LOG_FILE), existing)?;
        }
        assert_eq!(sink.query(None).len(), 1);
        Ok(())
    }

    #[test]
    fn the_capture_sink_keeps_what_it_was_given() {
        let sink = CaptureAuthAudit::new();
        emit(
            &sink,
            &AuthRecord::new(AuthEvent::LoginFailed, "alice", AuditResult::Error),
        );
        emit(
            &sink,
            &AuthRecord::new(AuthEvent::LoginSucceeded, "alice", AuditResult::Ok),
        );
        assert_eq!(
            sink.events(),
            vec![AuthEvent::LoginFailed, AuthEvent::LoginSucceeded]
        );
        assert_eq!(
            sink.query(Some(1)).first().map(|record| record.event),
            Some(AuthEvent::LoginSucceeded)
        );
        assert!(format!("{sink:?}").contains("CaptureAuthAudit"));
    }

    #[test]
    fn the_null_sink_keeps_nothing() {
        let sink = NullAuthAudit;
        emit(
            &sink,
            &AuthRecord::new(AuthEvent::LoginSucceeded, "alice", AuditResult::Ok),
        );
        assert!(sink.query(None).is_empty());
        assert_eq!(format!("{sink:?}"), "NullAuthAudit");
    }
}
