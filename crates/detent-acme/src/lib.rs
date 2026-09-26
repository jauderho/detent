//! ACME: dns-01 providers, device-attest-01 attestors, renewal scheduler, cert store.
//!
//! The dns-01 seam ([`DnsProvider`]) publishes `_acme-challenge` TXT records;
//! the device-attest-01 seam ([`Attestor`]) builds the CBOR attestation
//! object; the caller — not the seam — drives retry timing in both cases.
//! Seam types are sync and std-only so providers and attestors test without
//! network or hardware; the order flow in [`order`] is async (it drives
//! `instant-acme`), and networked backends (RFC 2136/Cloudflare/acme-dns/deSEC,
//! TPM 2.0) implement the same traits later.
//!
//! ```text
//!   Challenge ──▶ DnsRecord ──▶ DnsProvider::present ──▶ (caller polls) ──▶ delete
//!                                     │
//!                                     └─ HookProvider: challenge file in a
//!                                        0600 state dir for an external
//!                                        responder (challtestsrv) to serve
//! ```

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::{fs, io};

pub mod attest;
#[cfg(any(feature = "dns-providers", feature = "fuzzing"))]
mod https;
pub mod order;
#[cfg(any(feature = "dns-providers", feature = "fuzzing"))]
pub mod providers;
pub mod schedule;
#[cfg(any(feature = "dns-providers", feature = "fuzzing"))]
mod tsig;

pub use attest::Attestor;
#[cfg(feature = "fuzzing")]
pub use order::fuzz_acme_json;
pub use order::{
    EabCredentials, account_and_order, ari_identifier, cleanup_challenges, finalize,
    present_attest_challenges, present_challenges, should_renew_ari, wait_ready,
};
#[cfg(feature = "fuzzing")]
pub use providers::fuzz_provider_response;
#[cfg(any(feature = "dns-providers", feature = "fuzzing"))]
pub use providers::{AcmeDnsProvider, CloudflareProvider, DeSecProvider, Rfc2136Provider};
pub use schedule::{Warning, percent_used, should_renew, should_renew_in_window, warning_for};

/// Mode of the challenge files and the state directory holding them:
/// readable only by the account that runs the worker.
const HOOK_MODE: u32 = 0o600;

/// Mode of the state directory when [`HookProvider`] creates it.
const HOOK_DIR_MODE: u32 = 0o700;

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Why an ACME operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcmeError {
    /// An underlying file operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A record's fully qualified domain name is not a valid DNS name.
    #[error("invalid dns-01 fqdn: {0:?}")]
    InvalidFqdn(String),
    /// A record's TXT value is not a printable ASCII token.
    #[error("invalid dns-01 txt value: {0:?}")]
    InvalidValue(String),
    /// An ACME protocol error from instant-acme (API problem, timeout, …).
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    /// The authorization offered no dns-01 challenge to answer.
    #[error("authorization has no dns-01 challenge")]
    NoDns01Challenge,
    /// The authorization offered no device-attest-01 challenge to answer.
    #[error("authorization has no device-attest-01 challenge")]
    NoDeviceAttestChallenge,
    /// ACME account credentials could not be serialized or parsed.
    #[error("account credentials error: {0}")]
    Credentials(String),
    /// The ACME order ended in a non-`valid` state.
    #[error("order did not reach valid state: {0:?}")]
    InvalidOrder(instant_acme::OrderStatus),
    /// A dns provider was constructed or used with an unusable configuration,
    /// or its backend returned an unusable response.
    #[error("dns provider error: {0}")]
    Config(String),
    /// A networked provider could not yet confirm that the challenge record
    /// is visible; the caller owns retry timing and polls again.
    #[error("dns-01 record not yet propagated: {0}")]
    NotPropagated(String),
}

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// One `_acme-challenge` TXT record: the name to publish it under and the
/// value to publish.
///
/// Construct through [`DnsRecord::new`], which validates both halves; the
/// fields stay private so a record always carries a usable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    fqdn: String,
    value: String,
}

impl DnsRecord {
    /// Builds and validates a record.
    ///
    /// # Errors
    ///
    /// [`AcmeError::InvalidFqdn`] when `fqdn` is not a valid DNS name,
    /// [`AcmeError::InvalidValue`] when `value` is empty or carries
    /// non-printable ASCII.
    pub fn new(fqdn: impl Into<String>, value: impl Into<String>) -> Result<Self, AcmeError> {
        let fqdn = fqdn.into();
        let value = value.into();
        validate_fqdn(&fqdn)?;
        validate_value(&value)?;
        Ok(Self { fqdn, value })
    }

    /// The full record name, e.g. `_acme-challenge.example.com`.
    #[must_use]
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// The TXT value, e.g. the base64url digest of the key authorization.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A dns-01 challenge for `domain`, carrying the precomputed digest that
/// goes into the TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The identifier being validated, e.g. `example.com`.
    pub domain: String,
    /// Base64url SHA-256 digest of the key authorization (RFC 8555 §8.4).
    pub digest: String,
}

impl Challenge {
    /// The TXT record this challenge must publish.
    ///
    /// # Errors
    ///
    /// As [`DnsRecord::new`].
    pub fn record(&self) -> Result<DnsRecord, AcmeError> {
        DnsRecord::new(
            format!("_acme-challenge.{}", self.domain),
            self.digest.clone(),
        )
    }
}

// ---------------------------------------------------------------------------
// The provider trait
// ---------------------------------------------------------------------------

/// Publishes and withdraws dns-01 challenge TXT records.
///
/// Sync on purpose: the ACME client owns the propagation loop and calls
/// [`DnsProvider::wait_propagated`] as its check hook, so a provider never
/// sleeps and the trait stays object-safe (`Box<dyn DnsProvider>`).
pub trait DnsProvider: Send + Sync {
    /// Makes `record` resolvable. Must be idempotent: a re-present of an
    /// already-published record is a refresh, not a failure.
    ///
    /// # Errors
    ///
    /// Implementation-specific; see the concrete provider.
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError>;

    /// Withdraws `record`. Must tolerate a record that is already gone.
    ///
    /// # Errors
    ///
    /// Implementation-specific; see the concrete provider.
    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError>;

    /// Checks whether `record` is visible where it must be, returning
    /// `Ok(())` when propagation is confirmed.
    ///
    /// The default assumes the provider is instantly authoritative (true for
    /// local hook-based responders); networked providers override it.
    ///
    /// # Errors
    ///
    /// Implementation-specific; see the concrete provider.
    fn wait_propagated(&self, _record: &DnsRecord) -> Result<(), AcmeError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HookProvider
// ---------------------------------------------------------------------------

/// A [`DnsProvider`] that hands each challenge to an external responder
/// through the filesystem.
///
/// [`DnsProvider::present`] writes the TXT value to `<state_dir>/<fqdn>.txt`
/// (file `0600`, directory `0700`); an external script — challtestsrv in
/// development, a real hook provider later — reads that directory to serve
/// the challenge. [`DnsProvider::delete`] removes the file. No process is
/// spawned: the hook contract is a directory, not an exec.
#[derive(Debug, Clone)]
pub struct HookProvider {
    state_dir: PathBuf,
}

impl HookProvider {
    /// Creates a provider serving challenges out of `state_dir`.
    ///
    /// The directory itself is created lazily by [`DnsProvider::present`].
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    /// Path of the challenge file for `record`.
    fn challenge_path(&self, record: &DnsRecord) -> PathBuf {
        // The fqdn is validated to `[A-Za-z0-9.-]`, so it is a safe single
        // path component and needs no mangling.
        self.state_dir.join(format!("{}.txt", record.fqdn()))
    }

    /// Confines `state_dir` to `0700`, whether this call created it or found
    /// it: a directory that inherited the umask would let any local account
    /// watch challenges change.
    fn confine_dir(&self) -> Result<(), AcmeError> {
        fs::create_dir_all(&self.state_dir)?;
        fs::set_permissions(&self.state_dir, fs::Permissions::from_mode(HOOK_DIR_MODE))?;
        Ok(())
    }
}

impl DnsProvider for HookProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        self.confine_dir()?;
        let path = self.challenge_path(record);
        // Atomic: challtestsrv may read the file at any moment, so it must
        // never observe a partial digest or a stale-umask mode. Write a
        // 0600 temp in the same directory, then rename over the target.
        let tmp = self
            .state_dir
            .join(format!("{}.{}.tmp", record.fqdn(), std::process::id()));
        let write_tmp = || -> Result<(), AcmeError> {
            // `create_new`, not `create`: `mode` applies only at creation, so
            // reopening a leftover temp file — a crash plus PID reuse — would
            // write the challenge through whatever mode that file already
            // carries. A stale one is removed first so a retry still works.
            if tmp.exists() {
                fs::remove_file(&tmp)?;
            }
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(HOOK_MODE)
                .open(&tmp)?;
            f.write_all(record.value().as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &path)?;
            sync_dir(&self.state_dir)
        };
        if let Err(e) = write_tmp() {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let path = self.challenge_path(record);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            // Already gone is the success `delete` promises.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Checks that `fqdn` is a plausible DNS name: printable, no path separators,
/// and label lengths within RFC 1035 limits.
fn validate_fqdn(fqdn: &str) -> Result<(), AcmeError> {
    let plausible = !fqdn.is_empty()
        && fqdn.len() <= 253
        && fqdn
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && fqdn
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-'));
    if plausible {
        Ok(())
    } else {
        Err(AcmeError::InvalidFqdn(fqdn.to_owned()))
    }
}

/// Makes a rename in `dir` durable. A failure is returned, not dropped: a
/// rename that is not on disk can vanish in a crash.
pub(crate) fn sync_dir(dir: &std::path::Path) -> Result<(), AcmeError> {
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Checks that `value` is a printable ASCII token (a base64url digest or a
/// hook payload), with no whitespace or control bytes that could corrupt the
/// challenge file format.
fn validate_value(value: &str) -> Result<(), AcmeError> {
    if !value.is_empty() && value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        Ok(())
    } else {
        Err(AcmeError::InvalidValue(value.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn record() -> Result<DnsRecord, AcmeError> {
        DnsRecord::new("_acme-challenge.example.com", "digest-value-42")
    }

    fn provider(dir: &TempDir) -> HookProvider {
        HookProvider::new(state_dir(dir))
    }

    /// The directory a [`provider`]-built `HookProvider` writes challenges
    /// under, computed independently of the type under test.
    fn state_dir(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("challenges")
    }

    fn rejects_value(value: &str) -> bool {
        matches!(
            DnsRecord::new("example.com", value),
            Err(AcmeError::InvalidValue(_))
        )
    }

    #[test]
    fn hook_provider_is_object_safe() -> R {
        let dir = TempDir::new()?;
        let boxed: Box<dyn DnsProvider> = Box::new(provider(&dir));
        boxed.present(&record()?)?;
        boxed.delete(&record()?)?;
        Ok(())
    }

    #[test]
    fn present_then_delete_roundtrip() -> R {
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        hook.present(&record()?)?;
        let path = hook.challenge_path(&record()?);
        assert_eq!(std::fs::read_to_string(&path)?, "digest-value-42");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        hook.delete(&record()?)?;
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn present_creates_a_0700_state_dir() -> R {
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        hook.present(&record()?)?;
        let mode = std::fs::metadata(state_dir(&dir))?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        Ok(())
    }

    #[test]
    fn present_overwrites_a_stale_value() -> R {
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        hook.present(&record()?)?;
        let rotated = DnsRecord::new(record()?.fqdn(), "rotated-digest")?;
        hook.present(&rotated)?;
        assert_eq!(
            std::fs::read_to_string(hook.challenge_path(&rotated))?,
            "rotated-digest"
        );
        Ok(())
    }

    #[test]
    fn a_stale_temp_file_does_not_leak_its_permissions() -> R {
        // A crash plus PID reuse can leave `<fqdn>.<pid>.tmp` behind. `mode`
        // is applied only when a file is *created*, so reopening that file
        // with `create(true)` would write the challenge digest through
        // whatever mode it already carries — 0666 here. `create_new` plus a
        // removal of the stale file keeps the write at 0600.
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        std::fs::create_dir_all(state_dir(&dir))?;
        let stale =
            state_dir(&dir).join(format!("{}.{}.tmp", record()?.fqdn(), std::process::id()));
        std::fs::write(&stale, "leftover")?;
        std::fs::set_permissions(&stale, fs::Permissions::from_mode(0o666))?;

        hook.present(&record()?)?;

        let path = hook.challenge_path(&record()?);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "the challenge must not inherit the stale file's mode"
        );
        assert_eq!(std::fs::read_to_string(&path)?, "digest-value-42");
        assert!(!stale.exists(), "the temp file is consumed by the rename");
        Ok(())
    }

    #[test]
    fn delete_of_a_missing_record_succeeds() -> R {
        let dir = TempDir::new()?;
        provider(&dir).delete(&record()?)?;
        Ok(())
    }

    #[test]
    fn delete_surfaces_a_non_not_found_error() -> R {
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        // A directory in the challenge file's place: remove_file fails with
        // something other than NotFound, and delete must not swallow it.
        std::fs::create_dir(state_dir(&dir))?;
        std::fs::create_dir(hook.challenge_path(&record()?))?;
        assert!(matches!(hook.delete(&record()?), Err(AcmeError::Io(_))));
        Ok(())
    }

    #[test]
    fn default_wait_propagated_is_immediate_ok() -> R {
        let dir = TempDir::new()?;
        let hook: Box<dyn DnsProvider> = Box::new(provider(&dir));
        hook.wait_propagated(&record()?)?;
        Ok(())
    }

    #[test]
    fn invalid_fqdn_is_rejected() {
        for bad in [
            "",
            "example.com/path",
            "..",
            "../escape.example.com",
            "-leading-hyphen.example.com",
            "double..dot.example.com",
            "white space.example.com",
        ] {
            assert!(
                matches!(DnsRecord::new(bad, "v"), Err(AcmeError::InvalidFqdn(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn invalid_value_is_rejected() {
        for bad in ["", "two tokens", "line\nbreak"] {
            assert!(rejects_value(bad), "{bad:?} should be rejected");
        }
        assert!(DnsRecord::new("example.com", "good-digest").is_ok());
        assert!(!rejects_value("good-digest"));
    }

    #[test]
    fn challenge_builds_the_acme_challenge_fqdn() -> R {
        let challenge = Challenge {
            domain: "example.com".to_owned(),
            digest: "digest-value-42".to_owned(),
        };
        let r = challenge.record()?;
        assert_eq!(r.fqdn(), "_acme-challenge.example.com");
        assert_eq!(r.value(), "digest-value-42");
        Ok(())
    }

    #[test]
    fn io_error_surfaces_from_an_unusable_state_dir() -> R {
        let dir = TempDir::new()?;
        // A regular file where the state directory should be: creating the
        // directory fails deterministically, even as root.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "not a directory")?;
        let hook = HookProvider::new(blocker.join("challenges"));
        assert!(matches!(hook.present(&record()?), Err(AcmeError::Io(_))));
        Ok(())
    }

    #[test]
    fn io_error_surfaces_from_an_unwritable_challenge_path() -> R {
        let dir = TempDir::new()?;
        let hook = provider(&dir);
        // A directory occupying the challenge file's name makes the write
        // fail with EISDIR, deterministically.
        std::fs::create_dir(state_dir(&dir))?;
        std::fs::create_dir(hook.challenge_path(&record()?))?;
        assert!(matches!(hook.present(&record()?), Err(AcmeError::Io(_))));
        Ok(())
    }

    #[test]
    fn sync_dir_reports_a_directory_it_cannot_open() {
        let missing = std::path::Path::new("/nonexistent-detent-acme-dir");
        assert!(matches!(sync_dir(missing), Err(AcmeError::Io(_))));
        assert!(sync_dir(&std::env::temp_dir()).is_ok());
    }
}
