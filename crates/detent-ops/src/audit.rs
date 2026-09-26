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

use std::collections::VecDeque;
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
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
/// Mode of the directory that holds the audit logs.
const AUDIT_DIR_MODE: u32 = 0o700;

/// Number of records returned when a query omits `limit`.
pub const DEFAULT_AUDIT_QUERY_LIMIT: usize = 100;
/// Largest number of records one query may return.
pub const MAX_AUDIT_QUERY_LIMIT: usize = 1000;

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
    /// Intent recorded before any side effect; a following Ok/Error completes it.
    ///
    /// Mutating operations first write this record; if it cannot be persisted
    /// the operation is refused without dispatch. The outcome record (Ok or
    /// Error) follows after dispatch. See `OpsEngine::execute`.
    Started,
}

/// Serializes appends across every [`FileAudit`] instance in this process.
static APPEND_LOCK: Mutex<()> = Mutex::new(());

/// The sequence and chain hash stored in every persisted audit record.
///
/// `prev_hash` and `new_hash` describe the configuration target. These fields
/// describe the audit log itself, so a changed or removed record can be
/// detected with [`FileAudit::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditChain {
    /// One-based position in the log.
    pub sequence: u64,
    /// Hash of the preceding record, absent only for the first record.
    pub prev: Option<String>,
    /// Hash of this record and its link to the preceding one.
    pub hash: String,
    /// SHA-256 of the unreadable lines between the preceding record and this
    /// one, each with its newline. Set only after a crash tore an append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torn: Option<String>,
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
    /// Digest of the target before the operation, using the public audit name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub before_hash: Option<String>,
    /// Digest of the target afterwards, using the public audit name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub after_hash: Option<String>,
    /// Commit-confirm id associated with this operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<u32>))]
    pub commit_id: Option<u32>,
    /// How it ended.
    pub result: AuditResult,
    /// Fluent id of the failure, when it failed.
    pub error_id: Option<String>,
    /// Position and hash link in the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<Object>))]
    pub chain: Option<AuditChain>,
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
            chain: None,
            module,
            prev_hash: None,
            new_hash: None,
            before_hash: None,
            after_hash: None,
            commit_id: None,
            result,
            error_id: None,
        }
    }

    /// Attach the digests the operation observed.
    #[must_use]
    pub fn with_hashes(mut self, prev: Option<Sha256Digest>, new: Option<Sha256Digest>) -> Self {
        self.prev_hash = prev.map(|digest| digest.to_string());
        self.new_hash = new.map(|digest| digest.to_string());
        self.before_hash = self.prev_hash.clone();
        self.after_hash = self.new_hash.clone();
        self
    }

    /// Attach the commit-confirm id associated with this operation.
    #[must_use]
    pub fn with_commit_id(mut self, commit_id: u32) -> Self {
        self.commit_id = Some(commit_id);
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
/// matching records, because that is what an operator asks for. It defaults to
/// [`DEFAULT_AUDIT_QUERY_LIMIT`] and is capped at [`MAX_AUDIT_QUERY_LIMIT`].
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

    /// Effective result cap after applying the default and maximum.
    #[must_use]
    pub fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_AUDIT_QUERY_LIMIT)
            .min(MAX_AUDIT_QUERY_LIMIT)
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
    /// The log's sequence or hash chain is invalid.
    #[error("audit chain is invalid: {0}")]
    Chain(String),
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

impl FileAudit {
    /// Verify the complete sequence and hash chain.
    ///
    /// This detects modified, removed, reordered, and inserted records. The
    /// caller must retain the returned count/hash as an external anchor to
    /// detect truncation of the final records. Unreadable lines after the last
    /// record (a torn append) are not part of the chain and are ignored here;
    /// the next append records their digest.
    ///
    /// # Errors
    ///
    /// [`AuditError`] when the log cannot be read or its chain is invalid.
    pub fn verify(&self) -> Result<AuditChain, AuditError> {
        let Some(raw) = self.read_log()? else {
            return Err(AuditError::Chain("log does not exist".to_owned()));
        };
        scan_records(&raw, |_| {})?
            .anchor
            .ok_or_else(|| AuditError::Chain("log is empty".to_owned()))
    }

    /// Read the whole log, or nothing when it does not exist yet.
    fn read_log(&self) -> Result<Option<Vec<u8>>, AuditError> {
        match std::fs::read(&self.path) {
            Ok(raw) => Ok(Some(raw)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AuditError::Io(err)),
        }
    }

    /// Create the log's directory `0700` and open the log for appending.
    ///
    /// When the log is new, the directories that now hold it are fsynced so
    /// the new entries survive a crash.
    fn open_for_append(&self, is_new: bool) -> Result<std::fs::File, AuditError> {
        let parent = self.path.parent();
        if let Some(parent) = parent {
            DirBuilder::new()
                .recursive(true)
                .mode(AUDIT_DIR_MODE)
                .create(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(AUDIT_FILE_MODE)
            .open(&self.path)?;
        if is_new && let Some(parent) = parent {
            sync_directory(parent)?;
            if let Some(grandparent) = parent.parent() {
                sync_directory(grandparent)?;
            }
        }
        Ok(file)
    }
}

/// Fsync a directory so the entries created in it are durable. An empty path
/// means the current directory.
fn sync_directory(dir: &Path) -> Result<(), AuditError> {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    std::fs::File::open(dir)?.sync_all().map_err(AuditError::Io)
}

impl AuditSink for FileAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let _guard = APPEND_LOCK
            .lock()
            .map_err(|_| AuditError::Chain("audit append lock was poisoned".to_owned()))?;
        let raw = self.read_log()?;
        let scan = match raw {
            Some(ref raw) => scan_records(raw, |_| {})?,
            None => Scan::default(),
        };
        let mut chain = make_chain(record, scan.anchor.as_ref())?;
        if !scan.gap.is_empty() {
            tracing::warn!(
                bytes = scan.gap.len(),
                "the audit log ends in a torn line; the next record notes its digest"
            );
            chain.torn = Some(Sha256Digest::of(&scan.gap).to_string());
        }
        let mut stored = record.clone();
        stored.chain = Some(chain);
        let mut line = Vec::new();
        // Close a torn final line, so the new record starts on its own line.
        if raw
            .as_ref()
            .and_then(|raw| raw.last())
            .is_some_and(|last| *last != b'\n')
        {
            line.push(b'\n');
        }
        serde_json::to_writer(&mut line, &stored)
            .map_err(|err| AuditError::Encode(err.to_string()))?;
        line.push(b'\n');
        let mut file = self.open_for_append(raw.is_none())?;
        file.write_all(&line)?;
        file.sync_data().map_err(AuditError::Io)
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        let Some(raw) = self.read_log()? else {
            return Ok(Vec::new());
        };
        let limit = query.effective_limit();
        let mut out = VecDeque::with_capacity(limit);
        let scan = scan_records(&raw, |record| {
            if limit == 0 || !query.matches(&record) {
                return;
            }
            if out.len() == limit {
                out.pop_front();
            }
            out.push_back(record);
        })?;
        if !scan.gap.is_empty() {
            // A torn final line (a crash mid-append) must not make the whole
            // log unreadable. It is not a record.
            tracing::warn!(bytes = scan.gap.len(), "skipping a torn audit line");
        }
        Ok(out.into_iter().rev().collect())
    }
}

/// Hash a record with its own hash cleared, then link it to `previous`.
fn make_chain(
    record: &AuditRecord,
    previous: Option<&AuditChain>,
) -> Result<AuditChain, AuditError> {
    let mut unsigned = record.clone();
    unsigned.chain = None;
    let bytes = serde_json::to_vec(&unsigned).map_err(|err| AuditError::Encode(err.to_string()))?;
    Ok(AuditChain {
        sequence: previous.map_or(1, |chain| chain.sequence.saturating_add(1)),
        prev: previous.map(|chain| chain.hash.clone()),
        hash: Sha256Digest::of(&bytes).to_string(),
        torn: None,
    })
}

/// What a verified pass over the log found.
#[derive(Debug, Default)]
struct Scan {
    /// The chain of the last record.
    anchor: Option<AuditChain>,
    /// Unreadable lines after the last record, each with its newline.
    gap: Vec<u8>,
}

/// Parse and verify a whole JSON-lines log, passing each record to `each`,
/// oldest first.
///
/// A line that is not a record is accepted only when the next record's
/// `torn` digest names it, or when no record follows it (a torn append that
/// the next append will note).
fn scan_records(raw: &[u8], mut each: impl FnMut(AuditRecord)) -> Result<Scan, AuditError> {
    let mut scan = Scan::default();
    let mut first_bad: Option<String> = None;
    for (index, line) in raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .enumerate()
    {
        let number = index.saturating_add(1);
        let record: AuditRecord = match serde_json::from_slice(line) {
            Ok(record) => record,
            Err(err) => {
                first_bad
                    .get_or_insert_with(|| format!("record {number} is not valid JSON: {err}"));
                scan.gap.extend_from_slice(line);
                scan.gap.push(b'\n');
                continue;
            }
        };
        let previous = scan.anchor.as_ref();
        let actual = record
            .chain
            .as_ref()
            .ok_or_else(|| AuditError::Chain(format!("record {number} has no chain metadata")))?;
        let expected_sequence = previous.map_or(1, |chain| chain.sequence.saturating_add(1));
        let expected_prev = previous.map(|chain| chain.hash.clone());
        if actual.sequence != expected_sequence || actual.prev != expected_prev {
            return Err(AuditError::Chain(format!(
                "record {number} is not linked to its predecessor"
            )));
        }
        let expected_torn = (!scan.gap.is_empty()).then(|| Sha256Digest::of(&scan.gap).to_string());
        if actual.torn != expected_torn {
            return Err(AuditError::Chain(
                match (actual.torn.is_none(), first_bad) {
                    (true, Some(bad)) => bad,
                    _ => format!("record {number} does not match the skipped lines before it"),
                },
            ));
        }
        let expected = make_chain(&record, previous)?;
        if actual.hash != expected.hash {
            return Err(AuditError::Chain(format!(
                "record {number} hash does not match its contents"
            )));
        }
        scan.anchor = Some(actual.clone());
        scan.gap.clear();
        first_bad = None;
        each(record);
    }
    Ok(scan)
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
        Ok(newest_first(matching, Some(query.effective_limit())))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditError, AuditQuery, AuditRecord, AuditResult, AuditSink, CaptureAudit, FileAudit,
        NullAudit, now_rfc3339,
    };
    use crate::identity::Identity;
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
            .with_commit_id(7)
            .with_error(MessageId::new("ops-hash-conflict"));
        assert_eq!(entry.prev_hash.as_deref(), Some(prev.to_string().as_str()));
        assert_eq!(entry.new_hash.as_deref(), Some(new.to_string().as_str()));
        assert_eq!(entry.before_hash, entry.prev_hash);
        assert_eq!(entry.after_hash, entry.new_hash);
        assert_eq!(entry.commit_id, Some(7));
        assert_eq!(entry.error_id.as_deref(), Some("ops-hash-conflict"));
        assert!(!entry.ts.is_empty());
        let json = serde_json::to_value(&entry)?;
        assert_eq!(serde_json::from_value::<AuditRecord>(json)?, entry);
        assert_eq!(entry.clone(), entry);
        assert!(format!("{entry:?}").contains("hosts"));

        let bare = record("root", None, AuditResult::Ok);
        assert_eq!(bare.prev_hash, None);
        assert_eq!(bare.new_hash, None);
        assert_eq!(bare.before_hash, None);
        assert_eq!(bare.after_hash, None);
        assert_eq!(bare.commit_id, None);
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
        assert!(matches!(sink.verify(), Err(AuditError::Chain(_))));

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
        let anchor = sink.verify()?;
        assert_eq!(anchor.sequence, 2);
        assert_eq!(anchor.hash.len(), 64);
        assert!(anchor.prev.is_some());
        assert!(all.iter().all(|record| record.chain.is_some()));
        Ok(())
    }

    #[test]
    fn verification_detects_tampering_and_truncation_against_an_anchor() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("alice", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("root", Some("chrony"), AuditResult::Ok))?;
        let anchor = sink.verify()?;

        let raw = std::fs::read_to_string(sink.path())?;
        let mut lines: Vec<String> = raw.lines().map(ToOwned::to_owned).collect();
        let second = lines.get_mut(1).ok_or("three audit records")?;
        *second = second.replace("alice", "mallory");
        std::fs::write(sink.path(), lines.join("\n") + "\n")?;
        assert!(matches!(sink.verify(), Err(AuditError::Chain(_))));

        let truncated = format!("{}\n", lines.first().ok_or("three audit records")?);
        std::fs::write(sink.path(), truncated)?;
        assert!(matches!(sink.verify(), Ok(terminal) if terminal != anchor));
        Ok(())
    }

    #[test]
    fn a_deleted_middle_record_breaks_the_chain() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("alice", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("root", Some("chrony"), AuditResult::Ok))?;

        let raw = std::fs::read_to_string(sink.path())?;
        let kept: Vec<&str> = raw
            .lines()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, line)| line)
            .collect();
        std::fs::write(sink.path(), kept.join("\n") + "\n")?;

        assert!(matches!(sink.verify(), Err(AuditError::Chain(_))));
        assert!(matches!(
            sink.query(&AuditQuery::default()),
            Err(AuditError::Chain(_))
        ));
        assert!(matches!(
            sink.record(&record("root", Some("hosts"), AuditResult::Ok)),
            Err(AuditError::Chain(_))
        ));
        Ok(())
    }

    #[test]
    fn a_torn_final_line_does_not_block_later_records() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        sink.record(&record("alice", Some("hosts"), AuditResult::Ok))?;

        // A crash in the middle of an append leaves a line with no newline.
        // The cut can fall inside a multi-byte character.
        let whole = serde_json::to_vec(&record("bøb", Some("hosts"), AuditResult::Ok))?;
        let cut = whole
            .iter()
            .position(|byte| *byte == 0xC3)
            .ok_or("the record holds a two-byte character")?;
        let torn = whole.get(..=cut).ok_or("cut inside the record")?;
        let mut file = std::fs::OpenOptions::new().append(true).open(sink.path())?;
        std::io::Write::write_all(&mut file, torn)?;
        drop(file);

        // The torn line is not a record: reads and verification still work.
        assert_eq!(sink.verify()?.sequence, 2);
        assert_eq!(sink.query(&AuditQuery::default())?.len(), 2);

        // The next append succeeds, links to the last whole record, and
        // records the digest of the torn bytes.
        sink.record(&record("root", Some("chrony"), AuditResult::Ok))?;
        let anchor = sink.verify()?;
        assert_eq!(anchor.sequence, 3);
        let mut expected = torn.to_vec();
        expected.push(b'\n');
        assert_eq!(
            anchor.torn.as_deref(),
            Some(Sha256Digest::of(&expected).to_string().as_str())
        );
        let all = sink.query(&AuditQuery::default())?;
        assert_eq!(all.len(), 3);
        assert_eq!(all.first().map(|r| r.who.as_str()), Some("root"));
        assert_eq!(
            all.first().and_then(|r| r.module.as_deref()),
            Some("chrony")
        );

        // Later records carry no note.
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        assert_eq!(sink.verify()?.torn, None);
        Ok(())
    }

    #[test]
    fn a_second_crash_before_the_note_is_still_recovered() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        // The first recovery wrote the newline and part of its record, then
        // the process stopped again.
        let mut raw = std::fs::read(sink.path())?;
        raw.extend_from_slice(b"{\"ts\":\"20\n{\"ts\":\"2026-");
        std::fs::write(sink.path(), &raw)?;

        sink.record(&record("root", Some("chrony"), AuditResult::Ok))?;
        let anchor = sink.verify()?;
        assert_eq!(anchor.sequence, 2);
        assert_eq!(
            anchor.torn.as_deref(),
            Some(
                Sha256Digest::of(b"{\"ts\":\"20\n{\"ts\":\"2026-\n")
                    .to_string()
                    .as_str()
            )
        );
        Ok(())
    }

    #[test]
    fn an_unnoted_bad_line_in_the_middle_breaks_the_chain() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        let first = std::fs::read_to_string(sink.path())?;
        sink.record(&record("alice", Some("hosts"), AuditResult::Ok))?;
        let raw = std::fs::read_to_string(sink.path())?;
        let second = raw.strip_prefix(&first).ok_or("appended after the first")?;
        std::fs::write(sink.path(), format!("{first}{{ junk\n{second}"))?;
        assert!(matches!(
            sink.verify(),
            Err(AuditError::Chain(msg)) if msg.contains("not valid JSON")
        ));

        // A note that names other bytes is refused as well.
        let mut forged: AuditRecord = serde_json::from_str(second.trim_end())?;
        if let Some(chain) = forged.chain.as_mut() {
            chain.torn = Some(Sha256Digest::of(b"other\n").to_string());
        }
        let forged = serde_json::to_string(&forged)?;
        std::fs::write(sink.path(), format!("{first}{{ junk\n{forged}\n"))?;
        assert!(matches!(
            sink.verify(),
            Err(AuditError::Chain(msg)) if msg.contains("skipped lines")
        ));
        Ok(())
    }

    #[test]
    fn the_audit_directory_is_private() -> R {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::under_state_root(&dir.path().join("state"));
        sink.record(&record("root", None, AuditResult::Ok))?;
        let parent = sink.path().parent().ok_or("the log has a parent")?;
        let mode = std::fs::metadata(parent)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "audit directory mode is {mode:o}");
        Ok(())
    }

    #[test]
    fn the_file_sink_skips_blank_and_unparseable_lines() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        let mut raw = std::fs::read_to_string(sink.path())?;
        raw.push_str("\n{ truncated\n");
        std::fs::write(sink.path(), raw)?;
        assert_eq!(sink.query(&AuditQuery::default())?.len(), 1);
        Ok(())
    }

    #[test]
    fn verify_reports_invalid_json_missing_chain_and_a_broken_link() -> R {
        let dir = tempfile::TempDir::new()?;

        // Invariant 1: a line that is not valid JSON at all, followed by a
        // record that does not note it.
        let not_json = FileAudit::new(dir.path().join("not-json.jsonl"));
        let mut first = record("root", Some("hosts"), AuditResult::Ok);
        first.chain = Some(super::make_chain(&first, None)?);
        std::fs::write(
            not_json.path(),
            format!("{{ this is not json\n{}\n", serde_json::to_string(&first)?),
        )?;
        assert!(
            matches!(not_json.verify(), Err(AuditError::Chain(msg)) if msg.contains("not valid JSON"))
        );

        // Invariant 2: valid JSON, but the record was never chained.
        let no_chain = FileAudit::new(dir.path().join("no-chain.jsonl"));
        let unchained = serde_json::to_string(&record("root", Some("hosts"), AuditResult::Ok))?;
        std::fs::write(no_chain.path(), format!("{unchained}\n"))?;
        assert!(
            matches!(no_chain.verify(), Err(AuditError::Chain(msg)) if msg.contains("no chain metadata"))
        );

        // Invariant 3: two records, each independently the "first" of its own
        // chain, so the second is never linked to the one before it.
        let broken_link = FileAudit::new(dir.path().join("broken-link.jsonl"));
        broken_link.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        let mut second = record("alice", Some("chrony"), AuditResult::Ok);
        second.chain = Some(super::make_chain(&second, None)?);
        let mut raw = std::fs::read_to_string(broken_link.path())?;
        raw.push_str(&serde_json::to_string(&second)?);
        raw.push('\n');
        std::fs::write(broken_link.path(), raw)?;
        assert!(matches!(
            broken_link.verify(),
            Err(AuditError::Chain(msg)) if msg.contains("not linked to its predecessor")
        ));
        Ok(())
    }

    #[test]
    fn verify_reports_a_non_notfound_io_error() -> R {
        let dir = tempfile::TempDir::new()?;
        // The path is a directory, not a file: reading it fails with an error
        // other than `NotFound`.
        let sink = FileAudit::new(dir.path());
        assert!(matches!(sink.verify(), Err(AuditError::Io(_))));
        Ok(())
    }

    #[test]
    fn record_treats_an_existing_empty_log_as_having_no_predecessor() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        std::fs::write(sink.path(), "   \n")?;
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        let anchor = sink.verify()?;
        assert_eq!(anchor.sequence, 1);
        assert_eq!(anchor.prev, None);
        Ok(())
    }

    #[test]
    fn record_skips_creating_a_parent_when_the_path_has_none() {
        // An empty path has no parent (unlike `/`, which fails to read as a
        // file): `record` must skip `create_dir_all` and go straight on to
        // fail at the open, not at the missing-parent check.
        let sink = FileAudit::new("");
        assert_eq!(sink.path().parent(), None);
        assert!(matches!(
            sink.record(&record("root", None, AuditResult::Ok)),
            Err(AuditError::Io(_))
        ));
    }

    #[test]
    fn query_with_a_zero_limit_returns_nothing() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        sink.record(&record("root", Some("hosts"), AuditResult::Ok))?;
        let out = sink.query(&AuditQuery {
            limit: Some(0),
            ..AuditQuery::default()
        })?;
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn audit_queries_default_to_one_hundred_and_cap_at_one_thousand() -> R {
        let dir = tempfile::TempDir::new()?;
        let sink = FileAudit::new(dir.path().join("audit.jsonl"));
        let mut raw = String::new();
        let mut previous = None;
        for _ in 0..1001 {
            let mut entry = record("root", Some("hosts"), AuditResult::Ok);
            let chain = super::make_chain(&entry, previous.as_ref())?;
            entry.chain = Some(chain.clone());
            previous = Some(chain);
            raw.push_str(&serde_json::to_string(&entry)?);
            raw.push('\n');
        }
        std::fs::write(sink.path(), raw)?;
        assert_eq!(sink.query(&AuditQuery::default())?.len(), 100);
        assert_eq!(
            sink.query(&AuditQuery {
                limit: Some(usize::MAX),
                ..AuditQuery::default()
            })?
            .len(),
            1000
        );
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
