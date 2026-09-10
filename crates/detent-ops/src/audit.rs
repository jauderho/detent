//! The append-only audit log (PLAN §2.5).
//!
//! One JSON object per line under the state directory, plus a `tracing` event
//! so the same record reaches journald/syslog. Every mutating operation
//! produces exactly one record — success or failure — and so does every
//! refusal by [`Authz`](crate::authz::Authz).
//!
//! # What is deliberately absent
//!
//! A record carries **hashes and ids only**: never a configuration body, never
//! a model, never a rendered file, never a credential. That is not a
//! convention, it is the reason the fields are what they are — `prev_hash` and
//! `new_hash` are what let an operator correlate a change with a backup
//! without the log itself becoming a copy of `/etc`. `crates/detent-ops`'s
//! integration tests assert that a marker string planted inside an applied
//! configuration never appears in the log file.
//!
//! [`AuditSink`] is a trait so Phase 4 can add the web layer's `client_ip` and
//! `ua` fields (PLAN §2.5) by wrapping or replacing [`FileAudit`], without the
//! engine learning what an IP address is.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use detent_core::diag::MessageId;
use detent_platform::fs::atomic::Sha256Digest;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::identity::{Identity, IdentityKind};
use crate::op::OpKind;

/// Mode of the audit file: readable only by the account that owns the state
/// directory.
const AUDIT_FILE_MODE: u32 = 0o600;

/// How an operation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AuditResult {
    /// It succeeded.
    Ok,
    /// The authorization policy refused it; nothing was read or written.
    Denied,
    /// It was attempted and failed.
    Error,
}

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditRecord {
    /// When, as RFC 3339 in UTC.
    pub ts: String,
    /// The caller's subject.
    pub who: String,
    /// How the caller was authenticated.
    pub kind: IdentityKind,
    /// Which operation, without its payload.
    pub op: OpKind,
    /// The module the operation was about, when it was about one.
    pub module: Option<String>,
    /// Digest of the target before the operation, as 64 hex characters.
    pub prev_hash: Option<String>,
    /// Digest of the target afterwards.
    pub new_hash: Option<String>,
    /// How it ended.
    pub result: AuditResult,
    /// Fluent id of the failure, when it failed.
    pub error_id: Option<String>,
}

impl AuditRecord {
    /// A record stamped with the current UTC time.
    #[must_use]
    pub fn new(who: &Identity, op: OpKind, module: Option<String>, result: AuditResult) -> Self {
        Self {
            ts: now_rfc3339(),
            who: who.subject.clone(),
            kind: who.kind,
            op,
            module,
            prev_hash: None,
            new_hash: None,
            result,
            error_id: None,
        }
    }

    /// Attach the digests the operation observed.
    #[must_use]
    pub fn with_hashes(mut self, prev: Option<Sha256Digest>, new: Option<Sha256Digest>) -> Self {
        self.prev_hash = prev.map(|digest| digest.to_string());
        self.new_hash = new.map(|digest| digest.to_string());
        self
    }

    /// Attach the Fluent id of the failure.
    #[must_use]
    pub fn with_error(mut self, id: MessageId) -> Self {
        self.error_id = Some(id.as_str().to_owned());
        self
    }
}

/// The current UTC instant as RFC 3339, or the empty string if the clock
/// cannot be formatted (which `time` only reports for values outside the
/// representable range).
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Which records to read back.
///
/// All filters must match; `None` means "any". `limit` keeps the **newest**
/// matching records, because that is what an operator asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditQuery {
    /// Only records about this module.
    pub module: Option<String>,
    /// Only records from this subject.
    pub who: Option<String>,
    /// At most this many records, newest first.
    pub limit: Option<usize>,
}

impl AuditQuery {
    /// Whether `record` passes the filters. `limit` is applied by the sink.
    #[must_use]
    pub fn matches(&self, record: &AuditRecord) -> bool {
        let module_ok = match self.module {
            Some(ref want) => record.module.as_deref() == Some(want.as_str()),
            None => true,
        };
        let who_ok = match self.who {
            Some(ref want) => record.who == *want,
            None => true,
        };
        module_ok && who_ok
    }
}

/// The audit log could not be written or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The log file could not be opened, appended to, or read.
    #[error("audit log i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// A record could not be encoded as JSON. Only reachable if a future
    /// field is added that `serde_json` cannot represent.
    #[error("audit record could not be encoded: {0}")]
    Encode(String),
}

/// Where audit records go.
pub trait AuditSink: Send + Sync {
    /// Append one record.
    ///
    /// # Errors
    ///
    /// [`AuditError`] when the record cannot be persisted. The engine logs
    /// this and still reports the operation's own result: a write that
    /// already happened must not be reported as a failure.
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;

    /// Read records back, newest first.
    ///
    /// # Errors
    ///
    /// [`AuditError`] when the log cannot be read.
    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError>;
}

/// Keep the newest `limit` of `records`, which arrive oldest-first, and return
/// them newest-first.
fn newest_first(mut records: Vec<AuditRecord>, limit: Option<usize>) -> Vec<AuditRecord> {
    records.reverse();
    if let Some(limit) = limit {
        records.truncate(limit);
    }
    records
}

/// The real sink: one JSON object per line, appended, `0600`.
#[derive(Debug, Clone)]
pub struct FileAudit {
    path: PathBuf,
}

impl FileAudit {
    /// A sink writing to `path`. The parent directory is created on first
    /// write, not here, so constructing a sink never touches the filesystem.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The conventional location under a state root (PLAN §2.10).
    #[must_use]
    pub fn under_state_root(state_root: &Path) -> Self {
        Self::new(state_root.join("audit").join("detent-audit.jsonl"))
    }

    /// The file this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut line =
            serde_json::to_vec(record).map_err(|err| AuditError::Encode(err.to_string()))?;
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
        file.sync_data()?;
        Ok(())
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(AuditError::Io(err)),
        };
        let mut out = Vec::new();
        for line in raw.lines().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<AuditRecord>(line) {
                Ok(record) if query.matches(&record) => out.push(record),
                Ok(_) => {}
                // A truncated final line (a crash mid-append) must not make
                // the whole log unreadable.
                Err(err) => tracing::warn!(error = %err, "skipping unparseable audit line"),
            }
        }
        Ok(newest_first(out, query.limit))
    }
}

/// A sink that discards everything, for `--dryrun` and for tests that are not
/// about auditing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullAudit;

impl AuditSink for NullAudit {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Ok(())
    }

    fn query(&self, _query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        Ok(Vec::new())
    }
}

/// An in-memory sink that keeps what it was given, so a test can assert on
/// the records an operation produced without going near a filesystem.
#[derive(Debug, Default)]
pub struct CaptureAudit {
    records: Mutex<Vec<AuditRecord>>,
}

impl CaptureAudit {
    /// An empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything captured so far, oldest first.
    ///
    /// Returns an empty vector if the lock was poisoned, which can only happen
    /// if another thread panicked while holding it.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }
}

impl AuditSink for CaptureAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
        Ok(())
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        let matching = self
            .records()
            .into_iter()
            .filter(|record| query.matches(record))
            .collect();
        Ok(newest_first(matching, query.limit))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditError, AuditQuery, AuditRecord, AuditResult, AuditSink, CaptureAudit, FileAudit,
        NullAudit, now_rfc3339,
    };
    use crate::identity::{Identity, IdentityKind};
    use crate::op::OpKind;
    use detent_core::diag::MessageId;
    use detent_platform::fs::atomic::Sha256Digest;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn record(who: &str, module: Option<&str>, result: AuditResult) -> AuditRecord {
        AuditRecord::new(
            &Identity::local(who),
            OpKind::Apply,
            module.map(ToOwned::to_owned),
            result,
        )
    }

    #[test]
    fn a_record_carries_hashes_and_an_error_id_but_no_payload() -> R {
        let prev = Sha256Digest::of(b"before");
        let new = Sha256Digest::of(b"after");
        let entry = record("root", Some("hosts"), AuditResult::Error)
            .with_hashes(Some(prev), Some(new))
            .with_error(MessageId::new("ops-hash-conflict"));
        assert_eq!(entry.prev_hash.as_deref(), Some(prev.to_string().as_str()));
        assert_eq!(entry.new_hash.as_deref(), Some(new.to_string().as_str()));
        assert_eq!(entry.error_id.as_deref(), Some("ops-hash-conflict"));
        assert_eq!(entry.kind, IdentityKind::LocalUser);
        assert!(!entry.ts.is_empty());
        let json = serde_json::to_value(&entry)?;
        assert_eq!(serde_json::from_value::<AuditRecord>(json)?, entry);
        assert_eq!(entry.clone(), entry);
        assert!(format!("{entry:?}").contains("hosts"));

        let bare = record("root", None, AuditResult::Ok);
        assert_eq!(bare.prev_hash, None);
        assert_eq!(bare.new_hash, None);
        assert_eq!(bare.error_id, None);
        assert_eq!(bare.clone().with_hashes(None, None).prev_hash, None);
        Ok(())
    }

    #[test]
    fn the_timestamp_is_rfc3339_utc() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'), "{ts} is not UTC RFC 3339");
        assert!(ts.contains('T'));
    }

    #[test]
    fn results_and_queries_serialize() -> R {
        for result in [AuditResult::Ok, AuditResult::Denied, AuditResult::Error] {
            let json = serde_json::to_value(result)?;
            assert_eq!(serde_json::from_value::<AuditResult>(json)?, result);
        }
        let query = AuditQuery {
            module: Some("hosts".to_owned()),
            who: Some("root".to_owned()),
            limit: Some(2),
        };
        let json = serde_json::to_value(&query)?;
        assert_eq!(serde_json::from_value::<AuditQuery>(json)?, query);
        assert_eq!(AuditQuery::default(), serde_json::from_str("{}")?);
        assert!(serde_json::from_str::<AuditQuery>(r#"{"nope":1}"#).is_err());
        assert!(format!("{query:?}").contains("hosts"));
        Ok(())
    }

    #[test]
    fn queries_filter_on_module_and_subject() {
        let hosts = record("root", Some("hosts"), AuditResult::Ok);
        let chrony = record("alice", Some("chrony"), AuditResult::Ok);
        let global = record("root", None, AuditResult::Ok);

        let any = AuditQuery::default();
        assert!(any.matches(&hosts) && any.matches(&global));

        let by_module = AuditQuery {
            module: Some("hosts".to_owned()),
            ..AuditQuery::default()
        };
        assert!(by_module.matches(&hosts));
        assert!(!by_module.matches(&chrony));
        assert!(!by_module.matches(&global));

        let by_who = AuditQuery {
            who: Some("alice".to_owned()),
            ..AuditQuery::default()
        };
        assert!(by_who.matches(&chrony));
        assert!(!by_who.matches(&hosts));
    }

    #[test]
    fn the_file_sink_appends_one_line_per_record_and_reads_them_newest_first() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::under_state_root(dir.path());
        assert!(sink.path().ends_with("detent-audit.jsonl"));
        // Reading before anything was written is not an error.
        assert!(sink.query(&AuditQuery::default())?.is_empty());

        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("alice", Some("chrony"), AuditResult::Error))?;

        let raw = std::fs::read_to_string(sink.path())?;
        assert_eq!(raw.lines().count(), 2);

        let all = sink.query(&AuditQuery::default())?;
        assert_eq!(all.len(), 2);
        assert_eq!(all.first().map(|r| r.who.as_str()), Some("alice"));

        let limited = sink.query(&AuditQuery {
            limit: Some(1),
            ..AuditQuery::default()
        })?;
        assert_eq!(limited.len(), 1);

        let filtered = sink.query(&AuditQuery {
            module: Some("hosts".to_owned()),
            ..AuditQuery::default()
        })?;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered.first().map(|r| r.who.as_str()), Some("root"));
        assert!(format!("{sink:?}").contains("FileAudit"));
        Ok(())
    }

    #[test]
    fn the_file_sink_skips_blank_and_unparseable_lines() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        let mut raw = serde_json::to_string(&record("root", Some("hosts"), AuditResult::Ok))?;
        raw.push_str("\n\n{ truncated\n");
        std::fs::write(sink.path(), raw)?;
        assert_eq!(sink.query(&AuditQuery::default())?.len(), 1);
        Ok(())
    }

    #[test]
    fn the_file_sink_reports_io_failures() -> R {
        let dir = tempfile::TempDir::new()?;
        // A regular file where the log's parent directory must be: both
        // `create_dir_all` and any later read fail.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x")?;
        let sink = FileAudit::new(blocker.join("audit.jsonl"));
        assert!(matches!(
            sink.record(&record("root", None, AuditResult::Ok)),
            Err(AuditError::Io(_))
        ));
        assert!(matches!(
            sink.query(&AuditQuery::default()),
            Err(AuditError::Io(_))
        ));
        assert!(
            AuditError::Encode("bad".to_owned())
                .to_string()
                .contains("bad")
        );

        // The filesystem root is the one path with no parent at all, so this
        // is what exercises the "nothing to create" arm of `record`.
        let rootless = FileAudit::new(std::path::MAIN_SEPARATOR_STR);
        assert_eq!(rootless.path().parent(), None);
        assert!(matches!(
            rootless.record(&record("root", None, AuditResult::Ok)),
            Err(AuditError::Io(_))
        ));
        Ok(())
    }

    #[test]
    fn the_null_sink_keeps_nothing() -> R {
        let sink = NullAudit;
        sink.record(&record("root", None, AuditResult::Ok))?;
        assert!(sink.query(&AuditQuery::default())?.is_empty());
        assert_eq!(format!("{NullAudit:?}"), "NullAudit");
        Ok(())
    }

    #[test]
    fn the_capturing_sink_keeps_records_in_order() -> R {
        let sink = CaptureAudit::new();
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("alice", Some("chrony"), AuditResult::Ok))?;
        assert_eq!(sink.records().len(), 2);
        assert_eq!(sink.records().first().map(|r| r.who.as_str()), Some("root"));

        let newest = sink.query(&AuditQuery {
            limit: Some(1),
            ..AuditQuery::default()
        })?;
        assert_eq!(newest.first().map(|r| r.who.as_str()), Some("alice"));
        assert_eq!(
            sink.query(&AuditQuery {
                who: Some("root".to_owned()),
                ..AuditQuery::default()
            })?
            .len(),
            1
        );
        assert!(format!("{sink:?}").contains("CaptureAudit"));
        assert!(CaptureAudit::default().records().is_empty());
        Ok(())
    }
}
