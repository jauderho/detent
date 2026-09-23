//! API tokens: `<state_root>/state/tokens.json`, `0600` (PLAN §2.7).
//!
//! ```text
//!   issue ──▶ 32 random bytes ──┬─▶ shown to the operator once
//!                               └─▶ sha256 ──▶ tokens.json (never the token)
//!
//!   Authorization: Bearer <token> ──▶ sha256 ──▶ constant-time scan ──▶ Scopes
//! ```
//!
//! Tokens live in their own file rather than in `users.json`. They have a
//! different lifecycle (minted and revoked far more often than accounts), a
//! different shape, and — the deciding reason — listing tokens should not
//! require deserializing a file full of password hashes.
//!
//! # Guarantees
//!
//! * **The token is stored nowhere.** Only its SHA-256 is, so a stolen
//!   `tokens.json` authenticates nobody.
//! * **Lookup does not early-exit.** Every record is compared, with
//!   `subtle`, so the time taken says nothing about which token was presented
//!   or how many exist.
//! * **Expiry and revocation are checked at use.** The store re-reads the
//!   file when its `(dev, ino, len, mtime_ns)` fingerprint changes, so a
//!   token revoked in another process stops working without a restart.
//! * **Nothing here renders a token or a digest.**

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::authz::{Scope, Scopes};

use super::secret::{Secret, hex, random_bytes};
use super::{AuthError, STATE_SUBDIR, confine_state_dir, write_credential_file};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_ns: i128,
}
#[allow(clippy::arithmetic_side_effects)]
fn fingerprint_of(m: &std::fs::Metadata) -> Fingerprint {
    use std::os::unix::fs::MetadataExt as _;
    Fingerprint {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
    }
}
fn current_fingerprint(p: &std::path::Path) -> Result<Option<Fingerprint>, AuthError> {
    match std::fs::metadata(p) {
        Ok(m) => Ok(Some(fingerprint_of(&m))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AuthError::StoreRead {
            path: p.to_path_buf(),
            source,
        }),
    }
}
struct TokenInner {
    tokens: Vec<TokenRecord>,
    fp: Option<Fingerprint>,
}

/// Envelope version this build reads and writes.
pub const TOKENS_VERSION: u32 = 1;

/// File name under `<state_root>/state`.
pub const TOKENS_FILE: &str = "tokens.json";

/// Tokens one host may hold at once.
pub const MAX_TOKENS: usize = 64;

/// Longest human label accepted.
pub const MAX_LABEL_LEN: usize = 64;

/// Bytes of randomness in the public id of a token (not the token itself).
const ID_BYTES: usize = 8;

/// Whether `label` is something safe to store, render and audit: printable
/// ASCII, no control characters, 1 to [`MAX_LABEL_LEN`] of them.
#[must_use]
pub fn label_is_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// The current UTC instant as RFC 3339, or the empty string if it cannot be
/// formatted.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// One API token, as stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// Public identifier, 16 lowercase hex digits. Names the token for
    /// revocation and for the audit log without revealing it.
    pub id: String,
    /// What the operator called it.
    pub label: String,
    /// Lowercase hex SHA-256 of the token. The token itself is not stored.
    digest: String,
    /// What the token may do.
    pub scope: Scope,
    /// When it was issued, RFC 3339 UTC.
    pub created: String,
    /// Unix seconds after which it stops working, when it expires at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl fmt::Debug for TokenRecord {
    /// Everything except the digest, which is a verifier for a bearer secret
    /// and has no business in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRecord")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("scope", &self.scope)
            .field("created", &self.created)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a listing may show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenView {
    /// Public identifier.
    pub id: String,
    /// What the operator called it.
    pub label: String,
    /// Scope names, `["read"]` or `["read", "write"]`.
    pub scopes: Vec<&'static str>,
    /// When it was issued.
    pub created: String,
    /// Unix seconds after which it stops working.
    pub expires_at: Option<i64>,
}

/// A token that has just authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIdentity {
    /// Public identifier, which is what the audit log records.
    pub id: String,
    /// What the operator called it.
    pub label: String,
    /// What it may do.
    pub scopes: Scopes,
}

/// The versioned envelope on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    /// Format version; [`TOKENS_VERSION`] for this build.
    version: u32,
    /// The tokens themselves.
    tokens: Vec<TokenRecord>,
}

/// The API token store.
pub struct TokenStore {
    path: PathBuf,
    inner: Mutex<TokenInner>,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenStore")
            .field("path", &self.path)
            .field("tokens", &self.list().len())
            .finish()
    }
}

impl TokenStore {
    /// Load `<state_root>/state/tokens.json`, creating and confining the
    /// directory if it is absent. A missing file is an empty store.
    ///
    /// # Errors
    ///
    /// [`AuthError::StorePrepare`], [`AuthError::StoreRead`] and
    /// [`AuthError::StoreMalformed`], as [`super::users::UserStore::load`].
    pub fn load(state_root: &Path) -> Result<Self, AuthError> {
        let dir = state_root.join(STATE_SUBDIR);
        confine_state_dir(&dir)?;
        let path = dir.join(TOKENS_FILE);
        let (tokens, fp) = match std::fs::read(&path) {
            Ok(raw) => (Self::decode(&path, &raw)?, current_fingerprint(&path)?),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => (Vec::new(), None),
            Err(source) => {
                return Err(AuthError::StoreRead {
                    path: path.clone(),
                    source,
                });
            }
        };
        Ok(Self {
            path,
            inner: Mutex::new(TokenInner { tokens, fp }),
        })
    }

    /// Parse and validate the file's contents.
    fn decode(path: &Path, raw: &[u8]) -> Result<Vec<TokenRecord>, AuthError> {
        let malformed = |reason: String| AuthError::StoreMalformed {
            path: path.to_path_buf(),
            source: serde::de::Error::custom(reason),
        };
        let file: TokensFile =
            serde_json::from_slice(raw).map_err(|source| AuthError::StoreMalformed {
                path: path.to_path_buf(),
                source,
            })?;
        if file.version != TOKENS_VERSION {
            return Err(malformed(format!(
                "unsupported version {}; this build reads {TOKENS_VERSION}",
                file.version
            )));
        }
        for record in &file.tokens {
            if !label_is_valid(&record.label) {
                return Err(malformed(format!("`{}` has an unusable label", record.id)));
            }
        }
        Ok(file.tokens)
    }

    /// The file this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every token, without its digest.
    #[must_use]
    pub fn list(&self) -> Vec<TokenView> {
        self.records()
            .iter()
            .map(|record| TokenView {
                id: record.id.clone(),
                label: record.label.clone(),
                scopes: Scopes::of(record.scope).names(),
                created: record.created.clone(),
                expires_at: record.expires_at,
            })
            .collect()
    }

    /// Re-read the file if its `(dev, ino, len, mtime_ns)` differs (NotFound=empty).
    ///
    /// # Errors
    ///
    /// [`AuthError::StoreRead`] when the file cannot be read or is malformed.
    #[allow(clippy::missing_errors_doc)]
    pub fn refresh(&self) -> Result<(), AuthError> {
        let mut guard = self.inner.lock().map_err(|_| AuthError::StoreRead {
            path: self.path.clone(),
            source: std::io::Error::other("lock poisoned"),
        })?;
        Self::refresh_locked(&mut guard, &self.path)
    }
    fn refresh_locked(inner: &mut TokenInner, path: &std::path::Path) -> Result<(), AuthError> {
        let cur = current_fingerprint(path)?;
        if cur == inner.fp {
            return Ok(());
        }
        let tokens = match std::fs::read(path) {
            Ok(raw) => Self::decode(path, &raw)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(AuthError::StoreRead {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        inner.tokens = tokens;
        inner.fp = cur;
        Ok(())
    }
    /// Mint a token. The plaintext comes back **once**; only its digest is
    /// kept.
    ///
    /// # Errors
    ///
    /// [`AuthError::NameInvalid`] for an unusable label,
    /// [`AuthError::Entropy`] when the token cannot be generated,
    /// [`AuthError::TokenLimit`] when the store already holds
    /// [`MAX_TOKENS`], and the store variants when the file cannot be
    /// written.
    pub fn issue(
        &self,
        label: &str,
        scope: Scope,
        expires_at: Option<i64>,
    ) -> Result<(Secret, TokenView), AuthError> {
        if !label_is_valid(label) {
            return Err(AuthError::NameInvalid {
                name: label
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(MAX_LABEL_LEN)
                    .collect(),
            });
        }
        let token = Secret::random()?;
        let record = TokenRecord {
            id: hex(&random_bytes::<ID_BYTES>()?),
            label: label.to_owned(),
            digest: digest_of(token.expose()),
            scope,
            created: now_rfc3339(),
            expires_at,
        };
        let view = TokenView {
            id: record.id.clone(),
            label: record.label.clone(),
            scopes: Scopes::of(scope).names(),
            created: record.created.clone(),
            expires_at,
        };
        self.mutate(|tokens| {
            if tokens.len() >= MAX_TOKENS {
                return Err(AuthError::TokenLimit);
            }
            tokens.push(record.clone());
            Ok(())
        })?;
        Ok((token, view))
    }

    /// Resolve a presented bearer token.
    ///
    /// `now_unix` is compared against the record's expiry; the caller passes
    /// the clock so a test does not have to wait for one.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownToken`] when nothing matches, or when what matched
    /// has expired. One answer for both, so a caller cannot learn that a token
    /// *used* to be valid.
    pub fn authenticate(&self, presented: &str, now_unix: i64) -> Result<TokenIdentity, AuthError> {
        self.refresh()?;
        let wanted = digest_of(presented);
        let mut matched: Option<TokenRecord> = None;
        // Every record is examined: no early exit, so the work done does not
        // depend on where in the file the token sits.
        for record in self.records() {
            let same: bool = record.digest.as_bytes().ct_eq(wanted.as_bytes()).into();
            if same {
                matched = Some(record);
            }
        }
        let record = matched.ok_or(AuthError::UnknownToken)?;
        if record
            .expires_at
            .is_some_and(|deadline| now_unix >= deadline)
        {
            return Err(AuthError::UnknownToken);
        }
        Ok(TokenIdentity {
            id: record.id,
            label: record.label,
            scopes: Scopes::of(record.scope),
        })
    }

    /// Revoke a token by its public id.
    ///
    /// The record is removed rather than tombstoned: a revoked token can
    /// never come back, and a file of dead records is a file that grows.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownToken`] when no token has that id, or a store
    /// variant when the file cannot be written.
    pub fn revoke(&self, id: &str) -> Result<(), AuthError> {
        self.mutate(|tokens| {
            let before = tokens.len();
            tokens.retain(|record| record.id != id);
            if tokens.len() == before {
                return Err(AuthError::UnknownToken);
            }
            Ok(())
        })
    }

    /// A snapshot of the records; empty if the lock was poisoned, which
    /// refuses every token rather than accepting one.
    fn records(&self) -> Vec<TokenRecord> {
        self.inner
            .lock()
            .map(|g| g.tokens.clone())
            .unwrap_or_default()
    }

    /// Apply `change` and persist, leaving the in-memory copy untouched if the
    /// write fails.
    fn mutate<F>(&self, change: F) -> Result<(), AuthError>
    where
        F: FnOnce(&mut Vec<TokenRecord>) -> Result<(), AuthError>,
    {
        let mut guard = self.inner.lock().map_err(|_| AuthError::UnknownToken)?;
        Self::refresh_locked(&mut guard, &self.path)?;
        let mut candidate = guard.tokens.clone();
        change(&mut candidate)?;
        let file = TokensFile {
            version: TOKENS_VERSION,
            tokens: candidate.clone(),
        };
        let mut encoded =
            serde_json::to_vec(&file).map_err(|source| AuthError::StoreMalformed {
                path: self.path.clone(),
                source,
            })?;
        encoded.push(b'\n');
        write_credential_file(&self.path, &encoded)?;
        guard.tokens = candidate;
        guard.fp = current_fingerprint(&self.path)?;
        Ok(())
    }
}

/// Lowercase hex SHA-256 of a presented token.
fn digest_of(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{MAX_LABEL_LEN, MAX_TOKENS, TOKENS_FILE, TokenStore, label_is_valid};
    use crate::auth::AuthError;
    use crate::authz::{Scope, Scopes};
    use std::os::unix::fs::PermissionsExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_token_is_shown_once_and_stored_only_as_a_digest() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, view) = store.issue("laptop", Scope::Read, None)?;
        assert_eq!(token.expose().len(), 64);
        assert_eq!(view.label, "laptop");
        assert_eq!(view.scopes, vec!["read"]);
        assert_eq!(view.id.len(), 16);

        let raw = std::fs::read_to_string(store.path())?;
        assert!(!raw.contains(token.expose()), "the token itself was stored");
        assert!(raw.contains("\"digest\""), "{raw}");
        assert_eq!(
            std::fs::metadata(store.path())?.permissions().mode() & 0o777,
            0o600
        );

        // And it authenticates after a reload.
        let reloaded = TokenStore::load(root.path())?;
        let identity = reloaded.authenticate(token.expose(), 0)?;
        assert_eq!(identity.id, view.id);
        assert_eq!(identity.label, "laptop");
        assert_eq!(identity.scopes, Scopes::read_only());
        Ok(())
    }

    #[test]
    fn a_write_token_carries_both_scopes() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, view) = store.issue("ci", Scope::Write, None)?;
        assert_eq!(view.scopes, vec!["read", "write"]);
        assert_eq!(
            store.authenticate(token.expose(), 0)?.scopes,
            Scopes::read_write()
        );
        Ok(())
    }

    #[test]
    fn an_unknown_token_is_refused() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, _view) = store.issue("laptop", Scope::Read, None)?;
        for presented in ["", "short", &"0".repeat(64), &token.expose()[..63]] {
            match store.authenticate(presented, 0) {
                Err(err @ AuthError::UnknownToken) => {
                    assert_eq!(err.message_id().as_str(), "web-auth-token-unknown");
                }
                other => return Err(format!("{presented:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn an_expired_token_is_refused_exactly_like_an_unknown_one() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, view) = store.issue("temporary", Scope::Read, Some(1000))?;
        assert_eq!(view.expires_at, Some(1000));
        assert!(store.authenticate(token.expose(), 999).is_ok());
        match store.authenticate(token.expose(), 1000) {
            Err(AuthError::UnknownToken) => {}
            other => return Err(format!("an expired token gave {other:?}").into()),
        }
        match store.authenticate(token.expose(), 100_000) {
            Err(AuthError::UnknownToken) => {}
            other => return Err(format!("an expired token gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_revoked_token_stops_working_at_once() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (first, first_view) = store.issue("one", Scope::Read, None)?;
        let (second, _second_view) = store.issue("two", Scope::Write, None)?;
        store.revoke(&first_view.id)?;

        match store.authenticate(first.expose(), 0) {
            Err(AuthError::UnknownToken) => {}
            other => return Err(format!("a revoked token gave {other:?}").into()),
        }
        assert!(store.authenticate(second.expose(), 0).is_ok());
        assert_eq!(store.list().len(), 1);

        match store.revoke(&first_view.id) {
            Err(AuthError::UnknownToken) => {}
            other => return Err(format!("a second revocation gave {other:?}").into()),
        }
        // And the revocation survives a reload.
        let reloaded = TokenStore::load(root.path())?;
        assert!(reloaded.authenticate(first.expose(), 0).is_err());
        Ok(())
    }

    #[test]
    fn only_usable_labels_are_accepted() -> R {
        for good in ["a", "my laptop", "ci-2026", &"x".repeat(MAX_LABEL_LEN)] {
            assert!(label_is_valid(good), "{good:?} was refused");
        }
        for bad in [
            "",
            "line\nbreak",
            "tab\there",
            "bidi\u{202e}mark",
            "null\0byte",
            &"x".repeat(MAX_LABEL_LEN.saturating_add(1)),
        ] {
            assert!(!label_is_valid(bad), "{bad:?} was accepted");
        }

        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        match store.issue("bad\nlabel", Scope::Read, None) {
            Err(err @ AuthError::NameInvalid { .. }) => {
                assert!(!err.to_string().contains('\n'), "{err}");
            }
            other => return Err(format!("expected a label refusal, got {other:?}").into()),
        }
        assert!(store.list().is_empty());
        Ok(())
    }

    #[test]
    fn the_store_is_capped() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        for index in 0..MAX_TOKENS {
            let (_token, _view) = store.issue(&format!("token-{index}"), Scope::Read, None)?;
        }
        match store.issue("one too many", Scope::Read, None) {
            Err(err @ AuthError::TokenLimit) => {
                assert_eq!(err.message_id().as_str(), "web-auth-token-limit");
            }
            other => return Err(format!("expected the cap to bite, got {other:?}").into()),
        }
        assert_eq!(store.list().len(), MAX_TOKENS);
        Ok(())
    }

    #[test]
    fn a_malformed_file_is_refused_rather_than_ignored() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(TOKENS_FILE);
        for text in [
            "not json",
            "{}",
            "{\"version\":9,\"tokens\":[]}",
            "{\"version\":1,\"tokens\":[],\"extra\":1}",
            "{\"version\":1,\"tokens\":[{\"id\":\"a\",\"label\":\"x\"}]}",
            "{\"version\":1,\"tokens\":[{\"id\":\"a\",\"label\":\"bad\\nlabel\",\
             \"digest\":\"d\",\"scope\":\"read\",\"created\":\"\"}]}",
            "{\"version\":1,\"tokens\":[{\"id\":\"a\",\"label\":\"x\",\
             \"digest\":\"d\",\"scope\":\"admin\",\"created\":\"\"}]}",
        ] {
            std::fs::write(&path, text)?;
            match TokenStore::load(root.path()) {
                Err(err @ AuthError::StoreMalformed { .. }) => {
                    assert_eq!(err.message_id().as_str(), "web-auth-store-malformed");
                }
                other => return Err(format!("{text} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_an_empty_store() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        std::fs::create_dir_all(&dir)?;
        std::fs::create_dir_all(dir.join(TOKENS_FILE))?;
        match TokenStore::load(root.path()) {
            Err(AuthError::StoreRead { .. }) => {}
            other => return Err(format!("expected a read failure, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_failed_write_leaves_the_store_as_it_was() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, _view) = store.issue("first", Scope::Read, None)?;
        std::fs::remove_dir_all(root.path().join("state"))?;
        std::fs::write(root.path().join("state"), b"")?;
        match store.issue("second", Scope::Read, None) {
            Err(AuthError::StoreWrite { .. } | AuthError::StoreRead { .. }) => {}
            other => return Err(format!("expected a write failure, got {other:?}").into()),
        }
        assert_eq!(store.list().len(), 1);
        match store.authenticate(token.expose(), 0) {
            Err(AuthError::StoreRead { .. }) => {}
            other => {
                return Err(format!("expected StoreRead after corruption, got {other:?}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn token_revoked_through_another_store_stops_working() -> R {
        let root = tempfile::tempdir()?;
        let a = TokenStore::load(root.path())?;
        let (token, view) = a.issue("laptop", Scope::Read, None)?;
        assert!(a.authenticate(token.expose(), 0).is_ok());
        let b = TokenStore::load(root.path())?;
        b.revoke(&view.id)?;
        match a.authenticate(token.expose(), 0) {
            Err(AuthError::UnknownToken) => {}
            other => return Err(format!("revoked token still worked: {other:?}").into()),
        }
        assert!(a.list().iter().all(|v| v.id != view.id));
        Ok(())
    }

    #[test]
    fn nothing_here_prints_a_token_or_a_digest() -> R {
        let root = tempfile::tempdir()?;
        let store = TokenStore::load(root.path())?;
        let (token, view) = store.issue("laptop", Scope::Read, None)?;
        let raw = std::fs::read_to_string(store.path())?;
        let digest = raw
            .split("\"digest\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .ok_or("no digest in the file")?
            .to_owned();

        let rendered = format!("{store:?} {view:?} {token:?} {:?}", store.list());
        assert!(!rendered.contains(token.expose()), "{rendered}");
        assert!(!rendered.contains(&digest), "{rendered}");
        assert!(rendered.contains("laptop"), "{rendered}");

        let json = serde_json::to_string(&store.list())?;
        assert!(!json.contains(&digest), "{json}");
        assert!(!json.contains(token.expose()), "{json}");
        Ok(())
    }
}
