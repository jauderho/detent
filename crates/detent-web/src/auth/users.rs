//! The user store: `<state_root>/state/users.json`, `0600` (PLAN §2.10).
//!
//! ```text
//!   {"version":1,"users":[{"name":"alice","phc":"$argon2id$…", …}]}
//!            │                                   │
//!            │ deny_unknown_fields               │ never leaves this crate
//!            ▼                                   ▼
//!   UserStore::load ──▶ verify_password ──▶ VerifiedUser { totp, counter }
//!                             │
//!                             └─ unknown name ⇒ Hasher::verify_dummy ⇒ same cost
//! ```
//!
//! # Guarantees
//!
//! * **An unknown user costs what a known one costs.** The miss branch runs
//!   [`Hasher::verify_dummy`] before returning
//!   [`AuthError::InvalidCredentials`], which is the same error a wrong
//!   password produces.
//! * **The file is `0600` with no backups.** Rotated copies of a credential
//!   file are exactly what nobody wants on disk, so `keep_backups` is zero —
//!   the same choice `tls::write_key_file` makes for the private key. The
//!   containing directory is confined `0700` the way `confine_cert_dir` does.
//! * **A name is safe to audit.** Names are `[a-z0-9._-]{1,32}` starting with
//!   an alphanumeric, checked on creation *and* on load, so no control
//!   character or bidi mark can reach the audit log through one.
//! * **Nothing here renders a hash.** [`UserStore`]'s and [`UserRecord`]'s
//!   `Debug` print names and counts; [`UserStore::list`] returns names, never
//!   hashes.
//! * **A future migration is possible.** The envelope carries
//!   `version`, and a version this build does not know is a typed refusal
//!   rather than a wrong-shaped read.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::password::Hasher;
use super::totp::TotpSecret;
use super::{AuthError, STATE_SUBDIR, confine_state_dir, write_credential_file};

/// Envelope version this build reads and writes.
pub const USERS_VERSION: u32 = 1;

/// File name under `<state_root>/state`.
pub const USERS_FILE: &str = "users.json";

/// Longest user name accepted.
pub const MAX_NAME_LEN: usize = 32;

/// Whether `name` is `[a-z0-9._-]{1,32}` starting with an alphanumeric.
///
/// A name is not a path and is not a filename here, but it *is* written to the
/// audit log and rendered in a UI, so the allow-list keeps out control
/// characters, bidi overrides and anything that is not obviously one token.
#[must_use]
pub fn name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    if !name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
    {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Check a name, or say why not.
fn check_name(name: &str) -> Result<(), AuthError> {
    if name_is_valid(name) {
        return Ok(());
    }
    Err(AuthError::NameInvalid {
        // Only the printable, length-capped prefix, so an error string can
        // never carry a control character into a log line.
        name: name
            .chars()
            .filter(char::is_ascii)
            .filter(|c| !c.is_control())
            .take(MAX_NAME_LEN)
            .collect(),
    })
}

/// The current UTC instant as RFC 3339, or the empty string if it cannot be
/// formatted — the same fallback `detent_ops::audit` uses.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// One user, as stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserRecord {
    /// The login name.
    pub name: String,
    /// Argon2id PHC string. Never leaves this crate.
    phc: String,
    /// Base32 TOTP secret, when the user has enrolled one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_secret: Option<String>,
    /// Counter of the last accepted TOTP code, for the replay guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_last_counter: Option<u64>,
    /// Whether the operator must change this password at next login.
    #[serde(default)]
    pub must_change_password: bool,
    /// When the record was created, RFC 3339 UTC.
    pub created: String,
    /// When it was last changed.
    pub updated: String,
}

impl fmt::Debug for UserRecord {
    /// Name, flags and timestamps — never the hash, never the TOTP secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("name", &self.name)
            .field("totp_enrolled", &self.totp_secret.is_some())
            .field("must_change_password", &self.must_change_password)
            .field("created", &self.created)
            .field("updated", &self.updated)
            .finish_non_exhaustive()
    }
}

/// What `GET /users` and the CLI may see: no hash, no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserView {
    /// The login name.
    pub name: String,
    /// Whether a TOTP secret is enrolled.
    pub totp_enrolled: bool,
    /// Whether the password must be changed at next login.
    pub must_change_password: bool,
    /// When the record was created.
    pub created: String,
    /// When it was last changed.
    pub updated: String,
}

/// A caller whose password has just verified.
///
/// Carries what the login path needs next — the TOTP enrolment and its replay
/// counter — so the store is consulted once rather than three times.
#[derive(Debug)]
pub struct VerifiedUser {
    /// The login name, as stored.
    pub name: String,
    /// The enrolled TOTP secret, when there is one.
    pub totp: Option<TotpSecret>,
    /// Counter of the last accepted TOTP code.
    pub totp_last_counter: Option<u64>,
    /// Whether the password must be changed.
    pub must_change_password: bool,
}

/// The versioned envelope on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersFile {
    /// Format version; [`USERS_VERSION`] for this build.
    version: u32,
    /// The users themselves.
    users: Vec<UserRecord>,
}

/// The user store.
pub struct UserStore {
    /// `<state_root>/state/users.json`.
    path: PathBuf,
    /// The records, guarded so handlers can share one store.
    users: Mutex<Vec<UserRecord>>,
}

impl fmt::Debug for UserStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserStore")
            .field("path", &self.path)
            .field("users", &self.list().len())
            .finish()
    }
}

impl UserStore {
    /// Load `<state_root>/state/users.json`, creating and confining the
    /// directory if it is absent.
    ///
    /// A missing file is an empty store: a host that has never run `setup`
    /// still starts, and has no accounts.
    ///
    /// # Errors
    ///
    /// [`AuthError::StorePrepare`] when the directory cannot be confined,
    /// [`AuthError::StoreRead`] when the file exists but cannot be read,
    /// [`AuthError::StoreMalformed`] when it is not this build's format, and
    /// [`AuthError::NameInvalid`] when it holds a name this build refuses.
    pub fn load(state_root: &Path) -> Result<Self, AuthError> {
        let dir = state_root.join(STATE_SUBDIR);
        confine_state_dir(&dir)?;
        let path = dir.join(USERS_FILE);
        let users = match std::fs::read(&path) {
            Ok(raw) => Self::decode(&path, &raw)?,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(AuthError::StoreRead {
                    path: path.clone(),
                    source,
                });
            }
        };
        Ok(Self {
            path,
            users: Mutex::new(users),
        })
    }

    /// Parse and validate the file's contents.
    fn decode(path: &Path, raw: &[u8]) -> Result<Vec<UserRecord>, AuthError> {
        let file: UsersFile =
            serde_json::from_slice(raw).map_err(|source| AuthError::StoreMalformed {
                path: path.to_path_buf(),
                source,
            })?;
        if file.version != USERS_VERSION {
            return Err(AuthError::StoreMalformed {
                path: path.to_path_buf(),
                source: serde::de::Error::custom(format!(
                    "unsupported version {}; this build reads {USERS_VERSION}",
                    file.version
                )),
            });
        }
        let mut seen = BTreeSet::new();
        for record in &file.users {
            check_name(&record.name)?;
            if !seen.insert(record.name.as_str()) {
                return Err(AuthError::StoreMalformed {
                    path: path.to_path_buf(),
                    source: serde::de::Error::custom(format!(
                        "`{}` appears more than once",
                        record.name
                    )),
                });
            }
        }
        Ok(file.users)
    }

    /// The file this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every user, names and flags only — never a hash.
    #[must_use]
    pub fn list(&self) -> Vec<UserView> {
        self.records()
            .iter()
            .map(|record| UserView {
                name: record.name.clone(),
                totp_enrolled: record.totp_secret.is_some(),
                must_change_password: record.must_change_password,
                created: record.created.clone(),
                updated: record.updated.clone(),
            })
            .collect()
    }

    /// Whether any account exists. `setup` asks before offering to make one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records().is_empty()
    }

    /// Add a user.
    ///
    /// # Errors
    ///
    /// [`AuthError::NameInvalid`] for a name outside the allow-list,
    /// [`AuthError::UserExists`] when the name is taken,
    /// [`AuthError::Hash`] when the password cannot be hashed, and the store
    /// variants when the file cannot be written.
    pub fn create(
        &self,
        hasher: &Hasher,
        name: &str,
        password: &str,
        must_change_password: bool,
    ) -> Result<(), AuthError> {
        check_name(name)?;
        let phc = hasher.hash(password)?;
        let now = now_rfc3339();
        self.mutate(|users| {
            if users.iter().any(|record| record.name == name) {
                return Err(AuthError::UserExists);
            }
            users.push(UserRecord {
                name: name.to_owned(),
                phc,
                totp_secret: None,
                totp_last_counter: None,
                must_change_password,
                created: now.clone(),
                updated: now.clone(),
            });
            Ok(())
        })
    }

    /// Verify a password, at the same cost whether or not the user exists.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidCredentials`] for an unknown user and for a wrong
    /// password alike. There is no third answer on purpose.
    pub fn verify_password(
        &self,
        hasher: &Hasher,
        name: &str,
        password: &str,
    ) -> Result<VerifiedUser, AuthError> {
        let record = self
            .records()
            .iter()
            .find(|record| record.name == name)
            .cloned();
        let Some(record) = record else {
            // The dummy verification is the whole point of this branch.
            let _refused = hasher.verify_dummy(password);
            return Err(AuthError::InvalidCredentials);
        };
        if !hasher.verify(password, &record.phc) {
            return Err(AuthError::InvalidCredentials);
        }
        let totp = match record.totp_secret {
            Some(ref text) => Some(TotpSecret::from_base32(text)?),
            None => None,
        };
        Ok(VerifiedUser {
            name: record.name,
            totp,
            totp_last_counter: record.totp_last_counter,
            must_change_password: record.must_change_password,
        })
    }

    /// Replace a user's password, clearing the "must change" flag.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownUser`], [`AuthError::Hash`], or a store variant.
    pub fn set_password(
        &self,
        hasher: &Hasher,
        name: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        let phc = hasher.hash(password)?;
        self.update(name, |record| {
            record.phc.clone_from(&phc);
            record.must_change_password = false;
        })
    }

    /// Enrol or clear a TOTP secret. Clearing also clears the replay counter,
    /// because a new enrolment starts a new sequence.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownUser`], or a store variant.
    pub fn set_totp(&self, name: &str, secret: Option<&TotpSecret>) -> Result<(), AuthError> {
        let encoded = secret.map(|secret| secret.to_base32().expose().to_owned());
        self.update(name, |record| {
            record.totp_secret.clone_from(&encoded);
            record.totp_last_counter = None;
        })
    }

    /// Record the counter a TOTP code was accepted at, so it cannot be
    /// replayed.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownUser`], or a store variant.
    pub fn note_totp_counter(&self, name: &str, counter: u64) -> Result<(), AuthError> {
        self.update(name, |record| {
            record.totp_last_counter = Some(counter);
        })
    }

    /// Delete a user.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownUser`], or a store variant.
    pub fn remove(&self, name: &str) -> Result<(), AuthError> {
        self.mutate(|users| {
            let before = users.len();
            users.retain(|record| record.name != name);
            if users.len() == before {
                return Err(AuthError::UnknownUser);
            }
            Ok(())
        })
    }

    /// A snapshot of the records. An empty vector if the lock was poisoned,
    /// which can only happen if another thread panicked holding it — and a
    /// store that answers "no users" refuses every login, which is the safe
    /// direction.
    fn records(&self) -> Vec<UserRecord> {
        self.users
            .lock()
            .map(|users| users.clone())
            .unwrap_or_default()
    }

    /// Apply `change` to one named record, then persist.
    fn update<F>(&self, name: &str, change: F) -> Result<(), AuthError>
    where
        F: Fn(&mut UserRecord),
    {
        let now = now_rfc3339();
        self.mutate(|users| {
            let record = users
                .iter_mut()
                .find(|record| record.name == name)
                .ok_or(AuthError::UnknownUser)?;
            change(record);
            record.updated.clone_from(&now);
            Ok(())
        })
    }

    /// Apply `change` to the whole set and persist it, leaving the in-memory
    /// copy untouched if the write fails.
    fn mutate<F>(&self, change: F) -> Result<(), AuthError>
    where
        F: FnOnce(&mut Vec<UserRecord>) -> Result<(), AuthError>,
    {
        let mut guard = self.users.lock().map_err(|_poisoned| AuthError::Hash)?;
        let mut candidate = guard.clone();
        change(&mut candidate)?;
        let file = UsersFile {
            version: USERS_VERSION,
            users: candidate.clone(),
        };
        let mut encoded =
            serde_json::to_vec(&file).map_err(|source| AuthError::StoreMalformed {
                path: self.path.clone(),
                source,
            })?;
        encoded.push(b'\n');
        write_credential_file(&self.path, &encoded)?;
        *guard = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_NAME_LEN, USERS_FILE, USERS_VERSION, UserStore, name_is_valid};
    use crate::auth::AuthError;
    use crate::auth::password::Hasher;
    use crate::auth::totp::TotpSecret;
    use crate::config::Argon2Params;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn hasher() -> Result<Hasher, AuthError> {
        Hasher::new(
            Argon2Params {
                m_kib: Some(8),
                t: 1,
                p: 1,
            },
            4096,
        )
    }

    fn open(root: &Path) -> Result<UserStore, AuthError> {
        UserStore::load(root)
    }

    #[test]
    fn a_missing_file_is_an_empty_store_with_a_confined_directory() -> R {
        let root = tempfile::tempdir()?;
        let store = open(root.path())?;
        assert!(store.is_empty());
        assert_eq!(store.list(), Vec::new());
        assert_eq!(store.path(), root.path().join("state").join(USERS_FILE));
        assert_eq!(
            std::fs::metadata(root.path().join("state"))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(format!("{store:?}").contains(USERS_FILE));
        Ok(())
    }

    #[test]
    fn a_created_user_persists_across_a_reload() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", true)?;

        let raw = std::fs::read_to_string(store.path())?;
        assert!(
            raw.starts_with(&format!("{{\"version\":{USERS_VERSION}")),
            "{raw}"
        );
        assert_eq!(
            std::fs::metadata(store.path())?.permissions().mode() & 0o777,
            0o600
        );

        let reloaded = open(root.path())?;
        let listed = reloaded.list();
        assert_eq!(listed.len(), 1);
        let alice = listed.first().ok_or("no user")?;
        assert_eq!(alice.name, "alice");
        assert!(alice.must_change_password);
        assert!(!alice.totp_enrolled);
        assert!(!alice.created.is_empty());
        assert!(
            reloaded
                .verify_password(&hasher, "alice", "hunter2")
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn a_listing_never_carries_a_hash() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;
        let rendered = format!("{:?}{:?}", store.list(), store);
        assert!(!rendered.contains("argon2"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        let serialized = serde_json::to_string(&store.list())?;
        assert!(!serialized.contains("phc"), "{serialized}");
        Ok(())
    }

    #[test]
    fn a_duplicate_name_is_refused_and_the_first_user_survives() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "first", false)?;
        match store.create(&hasher, "alice", "second", false) {
            Err(AuthError::UserExists) => {}
            other => return Err(format!("expected a conflict, got {other:?}").into()),
        }
        assert!(store.verify_password(&hasher, "alice", "first").is_ok());
        assert_eq!(store.list().len(), 1);
        Ok(())
    }

    #[test]
    fn only_the_allow_listed_names_are_accepted() -> R {
        for good in ["a", "alice", "0", "a.b_c-d", &"a".repeat(MAX_NAME_LEN)] {
            assert!(name_is_valid(good), "{good:?} was refused");
        }
        for bad in [
            "",
            ".alice",
            "-alice",
            "_alice",
            "Alice",
            "ali ce",
            "ali\u{202e}ce",
            "ali\nce",
            "aliçe",
            "ali/ce",
            &"a".repeat(MAX_NAME_LEN.saturating_add(1)),
        ] {
            assert!(!name_is_valid(bad), "{bad:?} was accepted");
        }

        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        match store.create(&hasher, "Alice\u{202e}", "pw", false) {
            Err(err @ AuthError::NameInvalid { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-auth-user-name-invalid");
                // The rejected name is echoed without its bidi mark.
                assert!(!err.to_string().contains('\u{202e}'), "{err}");
            }
            other => return Err(format!("expected a name refusal, got {other:?}").into()),
        }
        assert!(store.is_empty());
        Ok(())
    }

    #[test]
    fn an_unknown_user_and_a_wrong_password_answer_the_same() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;
        for (name, password) in [("alice", "wrong"), ("mallory", "hunter2"), ("", "")] {
            match store.verify_password(&hasher, name, password) {
                Err(err @ AuthError::InvalidCredentials) => {
                    assert_eq!(err.message_id().as_str(), "web-auth-invalid-credentials");
                }
                other => {
                    return Err(format!("{name}/{password} gave {other:?}").into());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn a_password_can_be_replaced_and_clears_the_change_flag() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "old", true)?;
        store.set_password(&hasher, "alice", "new")?;
        assert!(store.verify_password(&hasher, "alice", "new").is_ok());
        assert!(store.verify_password(&hasher, "alice", "old").is_err());
        let listed = store.list();
        let alice = listed.first().ok_or("no user")?;
        assert!(!alice.must_change_password);
        assert!(alice.updated >= alice.created);

        match store.set_password(&hasher, "nobody", "x") {
            Err(AuthError::UnknownUser) => {}
            other => return Err(format!("expected an unknown user, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_totp_enrolment_round_trips_and_its_counter_is_kept() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;

        let secret = TotpSecret::generate()?;
        store.set_totp("alice", Some(&secret))?;
        store.note_totp_counter("alice", 42)?;

        let reloaded = open(root.path())?;
        let verified = reloaded.verify_password(&hasher, "alice", "hunter2")?;
        assert_eq!(verified.totp_last_counter, Some(42));
        let enrolled = verified.totp.as_ref().ok_or("no secret came back")?;
        assert_eq!(enrolled.to_base32().expose(), secret.to_base32().expose());
        assert!(reloaded.list().first().is_some_and(|u| u.totp_enrolled));
        assert!(!format!("{verified:?}").contains(secret.to_base32().expose()));

        // Clearing the enrolment clears the replay counter with it.
        reloaded.set_totp("alice", None)?;
        let cleared = reloaded.verify_password(&hasher, "alice", "hunter2")?;
        assert!(cleared.totp.is_none());
        assert_eq!(cleared.totp_last_counter, None);

        match reloaded.note_totp_counter("nobody", 1) {
            Err(AuthError::UnknownUser) => {}
            other => return Err(format!("expected an unknown user, got {other:?}").into()),
        }
        match reloaded.set_totp("nobody", None) {
            Err(AuthError::UnknownUser) => {}
            other => return Err(format!("expected an unknown user, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_stored_secret_that_is_not_base32_is_a_typed_failure() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;
        let raw = std::fs::read_to_string(store.path())?;
        let tampered = raw.replace(
            "\"must_change_password\"",
            "\"totp_secret\":\"not base32\",\"must_change_password\"",
        );
        std::fs::write(store.path(), tampered)?;

        let reloaded = open(root.path())?;
        match reloaded.verify_password(&hasher, "alice", "hunter2") {
            Err(AuthError::TotpSecretInvalid) => {}
            other => return Err(format!("expected a secret refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_user_can_be_removed() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;
        store.create(&hasher, "bob", "hunter2", false)?;
        store.remove("alice")?;
        assert_eq!(
            store.list().into_iter().map(|u| u.name).collect::<Vec<_>>(),
            vec!["bob".to_owned()]
        );
        match store.remove("alice") {
            Err(AuthError::UnknownUser) => {}
            other => return Err(format!("expected an unknown user, got {other:?}").into()),
        }
        assert!(
            open(root.path())?
                .verify_password(&hasher, "alice", "hunter2")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_malformed_file_is_refused_rather_than_ignored() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(USERS_FILE);
        for text in [
            "not json",
            "{}",
            "{\"version\":1}",
            // An unknown field is refused, not dropped.
            "{\"version\":1,\"users\":[],\"extra\":true}",
            "{\"version\":1,\"users\":[{\"name\":\"alice\"}]}",
            // A version this build does not know.
            "{\"version\":2,\"users\":[]}",
            // The same name twice.
            "{\"version\":1,\"users\":[\
             {\"name\":\"a\",\"phc\":\"x\",\"created\":\"\",\"updated\":\"\"},\
             {\"name\":\"a\",\"phc\":\"y\",\"created\":\"\",\"updated\":\"\"}]}",
        ] {
            std::fs::write(&path, text)?;
            match UserStore::load(root.path()) {
                Err(err @ AuthError::StoreMalformed { .. }) => {
                    assert_eq!(err.message_id().as_str(), "web-auth-store-malformed");
                }
                other => return Err(format!("{text} gave {other:?}").into()),
            }
        }

        // A name this build refuses is refused on load too, not only on
        // creation.
        std::fs::write(
            &path,
            "{\"version\":1,\"users\":[{\"name\":\"Alice\",\"phc\":\"x\",\
             \"created\":\"\",\"updated\":\"\"}]}",
        )?;
        match UserStore::load(root.path()) {
            Err(AuthError::NameInvalid { name }) => assert_eq!(name, "Alice"),
            other => return Err(format!("expected a name refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_an_empty_store() -> R {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("state");
        std::fs::create_dir_all(&dir)?;
        // A directory where the file should be: readable as a path, not as a
        // file.
        std::fs::create_dir_all(dir.join(USERS_FILE))?;
        match UserStore::load(root.path()) {
            Err(err @ AuthError::StoreRead { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-auth-store-unreadable");
            }
            other => return Err(format!("expected a read failure, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_failed_write_leaves_the_store_as_it_was() -> R {
        let root = tempfile::tempdir()?;
        let hasher = hasher()?;
        let store = open(root.path())?;
        store.create(&hasher, "alice", "hunter2", false)?;

        // Replace the state directory with a file: the next write cannot
        // succeed.
        std::fs::remove_dir_all(root.path().join("state"))?;
        std::fs::write(root.path().join("state"), b"")?;
        match store.create(&hasher, "bob", "hunter2", false) {
            Err(AuthError::StoreWrite { .. }) => {}
            other => return Err(format!("expected a write failure, got {other:?}").into()),
        }
        // The in-memory set is unchanged: `bob` was never added.
        assert_eq!(
            store.list().into_iter().map(|u| u.name).collect::<Vec<_>>(),
            vec!["alice".to_owned()]
        );
        Ok(())
    }
}
