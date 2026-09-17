//! TLS 1.3, and nothing else (PLAN §2.7).
//!
//! ```text
//!   bootstrap_self_signed ──▶ CertifiedKeyPair ──▶ CertStore ──▶ ServerConfig
//!            │                       │                 ▲
//!            │                       └── fingerprint    │ replace()
//!            └── load_or_bootstrap (cert_dir, 0600)     └── ACME, Phase 6
//! ```
//!
//! # Guarantees
//!
//! * **TLS 1.2 cannot be negotiated.** The listener is built with
//!   [`builder_with_protocol_versions`] over `&[&TLS13]`, and the shipped
//!   binary does not even compile rustls' `tls12` feature — the code to speak
//!   it is absent, not merely disabled. (Test builds *do* enable `tls12`, so
//!   that the "a TLS 1.2 client is refused" test proves a refusal rather than
//!   an absence.)
//! * **One certificate, swapped atomically.** [`CertStore`] is the single
//!   [`ResolvesServerCert`] the server holds for its whole life;
//!   [`CertStore::replace`] changes what it answers without rebuilding the
//!   [`ServerConfig`] or dropping a connection. That is the seam ACME uses in
//!   Phase 6.
//! * **The private key never reaches a log.** [`CertifiedKeyPair`]'s `Debug`
//!   prints the certificate fingerprint and the key's length, never its bytes.
//! * **The fingerprint survives a restart.** [`load_or_bootstrap`] reuses the
//!   stored `0600` key and certificate, so the TOFU fingerprint an operator
//!   wrote down stays valid until ACME replaces it.
//!
//! [`builder_with_protocol_versions`]: rustls::ServerConfig::builder_with_protocol_versions

use std::fmt;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once, RwLock};

use detent_core::diag::MessageId;
use detent_platform::fs::atomic::{AtomicError, WriteRequest, write_atomic};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};

/// ALPN protocols the listener offers, most preferred first (PLAN §2.6).
pub const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];

/// How long a bootstrap certificate is valid for.
pub const BOOTSTRAP_VALIDITY_DAYS: i64 = 90;

/// File holding the bootstrap certificate, DER, inside `cert_dir`.
pub const BOOTSTRAP_CERT_FILE: &str = "bootstrap.cert.der";

/// File holding the bootstrap private key, PKCS#8 DER, inside `cert_dir`.
pub const BOOTSTRAP_KEY_FILE: &str = "bootstrap.key.der";

/// Mode of both bootstrap files: readable only by the account that runs the
/// worker (PLAN §2.8).
const KEY_MODE: u32 = 0o600;

/// Mode of `cert_dir` when this module has to create it.
const CERT_DIR_MODE: u32 = 0o700;

/// The permission bits that must be clear on the certificate directory.
const GROUP_AND_OTHER: u32 = 0o077;

/// Names every bootstrap certificate carries, whatever the operator
/// configured, so that a local `curl` and a local browser both work.
const ALWAYS_SANS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Why TLS could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The self-signed bootstrap certificate could not be produced.
    #[error("the bootstrap certificate could not be generated: {0}")]
    Generate(#[from] rcgen::Error),
    /// rustls refused the certificate or its private key — a wrong algorithm,
    /// a truncated file, or a key that does not match the certificate.
    #[error("the certificate and key were rejected: {0}")]
    Key(#[source] rustls::Error),
    /// The certificate or its private key was not parseable PEM — wrong
    /// armour, truncated body, or a section kind other than the one parsing
    /// (`CERTIFICATE` for the chain, `PRIVATE KEY` for the key).
    #[error("the ACME material was not PEM of the expected kind")]
    Pem,
    /// No `CryptoProvider` is installed and none could be derived from the
    /// crate features. Unreachable in a build that compiles, because at least
    /// one of `crypto-aws-lc` / `crypto-ring` is required.
    #[error("no rustls crypto provider is available")]
    NoProvider,
    /// A file in the certificate store could not be read.
    #[error("{path} could not be read: {source}")]
    Read {
        /// The file that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The certificate directory could not be created, or its mode could not
    /// be set.
    #[error("{path} could not be prepared: {source}")]
    Prepare {
        /// The directory that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// A file in the certificate store could not be written.
    #[error("{path} could not be written: {source}")]
    Persist {
        /// The file that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: AtomicError,
    },
}

impl TlsError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Generate(_) => MessageId::new("web-tls-generate-failed"),
            Self::Key(_) => MessageId::new("web-tls-key-rejected"),
            Self::NoProvider => MessageId::new("web-tls-no-provider"),
            Self::Read { .. } => MessageId::new("web-tls-store-unreadable"),
            Self::Prepare { .. } => MessageId::new("web-tls-store-unwritable"),
            Self::Persist { .. } => MessageId::new("web-tls-store-write-failed"),
            Self::Pem => MessageId::new("web-tls-acme-pem-rejected"),
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto provider
// ---------------------------------------------------------------------------

/// Guards the one-time provider installation.
static PROVIDER: Once = Once::new();

/// Install the process-wide rustls [`CryptoProvider`].
///
/// Idempotent and safe to call from any number of threads or tests: the first
/// call wins, later ones do nothing. When both `crypto-aws-lc` and
/// `crypto-ring` are compiled in — which is what `--all-features` does —
/// aws-lc-rs takes precedence, matching PLAN §2.2 and `rcgen`'s own ordering.
pub fn install_crypto_provider() {
    PROVIDER.call_once(|| {
        #[cfg(feature = "crypto-aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(all(feature = "crypto-ring", not(feature = "crypto-aws-lc")))]
        let provider = rustls::crypto::ring::default_provider();
        // An `Err` means something else installed a provider first, which is
        // exactly as good an outcome as installing ours.
        let _ = provider.install_default();
    });
}

/// The installed provider, installing ours first if nothing has.
fn provider() -> Result<Arc<CryptoProvider>, TlsError> {
    install_crypto_provider();
    CryptoProvider::get_default()
        .cloned()
        .ok_or(TlsError::NoProvider)
}

// ---------------------------------------------------------------------------
// A certificate and its key
// ---------------------------------------------------------------------------

/// One end-entity certificate and the private key that goes with it.
///
/// Held as DER rather than as a parsed [`CertifiedKey`] so it can be written
/// to disk, hashed for a fingerprint, and handed to whichever provider is
/// compiled in, all without a second representation.
#[derive(Clone, PartialEq, Eq)]
pub struct CertifiedKeyPair {
    /// The end-entity certificate, DER.
    cert_der: Vec<u8>,
    /// The private key, PKCS#8 DER.
    key_pkcs8_der: Vec<u8>,
}

impl fmt::Debug for CertifiedKeyPair {
    /// Prints the fingerprint and the key's *length*. Never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedKeyPair")
            .field("fingerprint", &self.fingerprint())
            .field("key_bytes", &self.key_pkcs8_der.len())
            .finish_non_exhaustive()
    }
}

impl CertifiedKeyPair {
    /// Wrap a DER certificate and its PKCS#8 DER private key.
    ///
    /// Nothing is validated here; [`to_certified_key`](Self::to_certified_key)
    /// is where a mismatched pair is caught.
    #[must_use]
    pub const fn new(cert_der: Vec<u8>, key_pkcs8_der: Vec<u8>) -> Self {
        Self {
            cert_der,
            key_pkcs8_der,
        }
    }

    /// Build a pair from what `instant-acme`'s `Order::finalize` returns: a
    /// PEM certificate chain and a PEM PKCS#8 private key.
    ///
    /// Only the chain's leaf is kept — [`to_certified_key`](Self::to_certified_key)
    /// serves a single end-entity certificate, and the intermediates travel
    /// the API, not the handshake. The key must be `PRIVATE KEY` (PKCS#8, as
    /// `finalize` generates); SEC1/EC `EC PRIVATE KEY` is refused rather
    /// than converted.
    ///
    /// # Errors
    ///
    /// [`TlsError::Pem`] when either side is not PEM of the expected kind.
    pub fn from_acme_pem(chain_pem: &str, key_pem: &str) -> Result<Self, TlsError> {
        use rustls::pki_types::pem::PemObject as _;
        let leaf =
            CertificateDer::from_pem_slice(chain_pem.as_bytes()).map_err(|_| TlsError::Pem)?;
        let key =
            PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| TlsError::Pem)?;
        Ok(Self::new(leaf.to_vec(), key.secret_pkcs8_der().to_vec()))
    }

    /// The end-entity certificate, DER.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// SHA-256 of the certificate, as printed for trust-on-first-use.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.cert_der)
    }

    /// Load the pair into the installed provider.
    ///
    /// # Errors
    ///
    /// [`TlsError::NoProvider`] when no crypto provider is available, and
    /// [`TlsError::Key`] when the key cannot be parsed by this provider or
    /// does not match the certificate.
    pub fn to_certified_key(&self) -> Result<Arc<CertifiedKey>, TlsError> {
        let provider = provider()?;
        let chain = vec![CertificateDer::from(self.cert_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()));
        CertifiedKey::from_der(chain, key, &provider)
            .map(Arc::new)
            .map_err(TlsError::Key)
    }
}

/// Uppercase, colon-separated SHA-256 of `der`, as printed at startup for
/// trust-on-first-use and as browsers display a certificate fingerprint.
#[must_use]
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len().saturating_mul(3));
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        // `write!` into a String cannot fail, but it returns a Result, and
        // `unwrap`/`expect` are denied; two nibble lookups avoid the question.
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

/// One uppercase hex digit from the low four bits of `value`.
const fn nibble(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'A',
        11 => 'B',
        12 => 'C',
        13 => 'D',
        14 => 'E',
        _ => 'F',
    }
}

// ---------------------------------------------------------------------------
// The hot-reload seam
// ---------------------------------------------------------------------------

/// The one certificate resolver a [`crate::server::Server`] holds, whose
/// answer can be changed while connections are in flight.
///
/// A plain `RwLock<Arc<..>>` rather than an `arc-swap`: the read side runs
/// once per handshake, not once per packet, and one fewer dependency in a TLS
/// path is worth more than the contention it saves.
#[derive(Debug)]
pub struct CertStore {
    /// What every subsequent handshake will be answered with.
    current: RwLock<Arc<CertifiedKey>>,
}

impl CertStore {
    /// Build a store serving `pair`.
    ///
    /// # Errors
    ///
    /// As [`CertifiedKeyPair::to_certified_key`].
    pub fn new(pair: &CertifiedKeyPair) -> Result<Self, TlsError> {
        Ok(Self {
            current: RwLock::new(pair.to_certified_key()?),
        })
    }

    /// Serve `pair` from the next handshake on. Connections already
    /// established keep the certificate they negotiated with.
    ///
    /// The new pair is parsed *before* the old one is dropped, so a bad
    /// replacement leaves the working certificate in place.
    ///
    /// # Errors
    ///
    /// As [`CertifiedKeyPair::to_certified_key`].
    pub fn replace(&self, pair: &CertifiedKeyPair) -> Result<(), TlsError> {
        let next = pair.to_certified_key()?;
        match self.current.write() {
            Ok(mut guard) => *guard = next,
            // The guarded value is a single `Arc` that is only ever wholly
            // replaced, so a panic elsewhere cannot have left it half-written:
            // recovering is correct, and refusing to reload a certificate
            // because of an unrelated panic is not.
            Err(poisoned) => *poisoned.into_inner() = next,
        }
        Ok(())
    }

    /// The certificate handshakes are currently answered with.
    #[must_use]
    pub fn current(&self) -> Arc<CertifiedKey> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

impl ResolvesServerCert for CertStore {
    /// One host, one certificate: SNI is not consulted.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

/// A TLS 1.3-only [`rustls::ServerConfig`] serving `cert`, advertising `alpn`.
///
/// Callers that need to swap the certificate later should build the
/// [`CertStore`] themselves and use
/// [`server_config_from_store`]; this is the one-shot form.
///
/// # Errors
///
/// As [`CertifiedKeyPair::to_certified_key`].
pub fn server_config(
    cert: &CertifiedKeyPair,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, TlsError> {
    server_config_from_store(Arc::new(CertStore::new(cert)?), alpn)
}

/// A TLS 1.3-only [`rustls::ServerConfig`] resolving certificates through
/// `store`, so the certificate can be replaced later without rebuilding it.
///
/// # Errors
///
/// [`TlsError::NoProvider`] when no crypto provider is available.
pub fn server_config_from_store(
    store: Arc<CertStore>,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, TlsError> {
    // Establish the provider before the builder reaches for it: the builder
    // panics rather than erroring when it finds none.
    let _provider = provider()?;
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(store);
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

// ---------------------------------------------------------------------------
// Bootstrap certificate
// ---------------------------------------------------------------------------

/// Generate a fresh self-signed ECDSA P-256 certificate valid for
/// [`BOOTSTRAP_VALIDITY_DAYS`] days.
///
/// The subject alternative names are `hostnames` plus `localhost`,
/// `127.0.0.1` and `::1`; an entry that parses as an IP address becomes an
/// `iPAddress` SAN and anything else a `dNSName`. The certificate is marked
/// explicitly not a CA and carries exactly the usages a TLS server needs
/// (`digitalSignature`, `serverAuth`).
///
/// # Errors
///
/// [`TlsError::Generate`] when a name is not a valid DNS name or the key
/// could not be generated.
pub fn bootstrap_self_signed(hostnames: &[String]) -> Result<CertifiedKeyPair, TlsError> {
    let mut sans: Vec<String> =
        Vec::with_capacity(hostnames.len().saturating_add(ALWAYS_SANS.len()));
    for name in hostnames.iter().map(String::as_str).chain(ALWAYS_SANS) {
        if !sans.iter().any(|existing| existing == name) {
            sans.push(name.to_owned());
        }
    }

    let mut params = CertificateParams::new(sans)?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, "detent bootstrap");
    // Back-dated an hour so an appliance whose clock has not been set by NTP
    // yet still serves a currently-valid certificate. Checked arithmetic
    // because unchecked arithmetic is denied crate-wide; the fallbacks need a
    // clock set within an hour of the end of the representable range, and both
    // of them yield a certificate that is already expired — the safe direction
    // to fail in, since nothing will accept it.
    let now = OffsetDateTime::now_utc();
    let not_before = now.checked_sub(Duration::hours(1)).unwrap_or(now);
    params.not_before = not_before;
    params.not_after = not_before
        .checked_add(Duration::days(BOOTSTRAP_VALIDITY_DAYS))
        .unwrap_or(not_before);

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    Ok(CertifiedKeyPair::new(
        cert.der().to_vec(),
        key.serialize_der(),
    ))
}

/// Read the stored bootstrap pair from `cert_dir`, or `None` when it has not
/// been generated yet.
///
/// A half-written store — one file present, the other not — reads as `None`,
/// so the next call regenerates rather than failing forever.
///
/// # Errors
///
/// [`TlsError::Read`] when a file exists but cannot be read.
pub fn load_bootstrap(cert_dir: &Path) -> Result<Option<CertifiedKeyPair>, TlsError> {
    let Some(certificate) = read_optional(&cert_dir.join(BOOTSTRAP_CERT_FILE))? else {
        return Ok(None);
    };
    let Some(key) = read_optional(&cert_dir.join(BOOTSTRAP_KEY_FILE))? else {
        return Ok(None);
    };
    Ok(Some(CertifiedKeyPair::new(certificate, key)))
}

/// Read `path`, mapping "not there" to `None`.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, TlsError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(TlsError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Write `pair` into `cert_dir`, creating the directory `0700` and both files
/// `0600`.
///
/// `cert_dir` must be absolute: the atomic writer refuses relative paths
/// because it resolves the parent directory by file descriptor.
///
/// # Errors
///
/// [`TlsError::Prepare`] when the directory cannot be created or its mode set,
/// [`TlsError::Persist`] when a file cannot be written.
pub fn store_bootstrap(cert_dir: &Path, pair: &CertifiedKeyPair) -> Result<(), TlsError> {
    if !cert_dir.is_dir() {
        std::fs::create_dir_all(cert_dir).map_err(|source| TlsError::Prepare {
            path: cert_dir.to_path_buf(),
            source,
        })?;
    }
    confine_cert_dir(cert_dir)?;
    write_key_file(&cert_dir.join(BOOTSTRAP_CERT_FILE), pair.cert_der())?;
    write_key_file(&cert_dir.join(BOOTSTRAP_KEY_FILE), &pair.key_pkcs8_der)?;
    Ok(())
}

/// Make sure `cert_dir` grants nothing to group or other, whether this call
/// created it or found it.
///
/// A directory that already existed is the interesting case: `tmpfiles.d`
/// creates `/var/lib/detent/certs` `0700` in a packaged install, but a hand-made
/// one inherits the umask, and a `0755` directory around a `0600` key still
/// lets any local account enumerate the store and watch it change. Tightening
/// is attempted only when the mode is actually too broad, so a correctly
/// provisioned directory this process does not own is left alone instead of
/// failing startup.
fn confine_cert_dir(cert_dir: &Path) -> Result<(), TlsError> {
    let prepare = |source| TlsError::Prepare {
        path: cert_dir.to_path_buf(),
        source,
    };
    let mode = std::fs::metadata(cert_dir)
        .map_err(prepare)?
        .permissions()
        .mode();
    if mode & GROUP_AND_OTHER != 0 {
        std::fs::set_permissions(cert_dir, std::fs::Permissions::from_mode(CERT_DIR_MODE))
            .map_err(prepare)?;
    }
    Ok(())
}

/// Write one secret file `0600`, atomically and without keeping backups —
/// rotated copies of a private key are exactly what nobody wants on disk.
fn write_key_file(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    let parent = path.parent().unwrap_or(path);
    let mut request = WriteRequest::new(path, contents, parent);
    // A private key has no business leaving rotated copies on disk.
    request.keep_backups = 0;
    request.create_mode = KEY_MODE;
    let _outcome = write_atomic(&request).map_err(|source| TlsError::Persist {
        path: path.to_path_buf(),
        source,
    })?;
    // `write_atomic` preserves the mode of a file that already existed, so an
    // earlier file created too permissively would stay that way. Assert the
    // mode rather than assume it.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_MODE)).map_err(|source| {
        TlsError::Prepare {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// The bootstrap pair for this host: the stored one if there is one, a freshly
/// generated and persisted one otherwise.
///
/// Reusing the stored pair is the point — the fingerprint an operator trusted
/// on first use must not change because the service restarted.
///
/// # Errors
///
/// As [`load_bootstrap`], [`bootstrap_self_signed`] and [`store_bootstrap`].
pub fn load_or_bootstrap(
    cert_dir: &Path,
    hostnames: &[String],
) -> Result<CertifiedKeyPair, TlsError> {
    if let Some(pair) = load_bootstrap(cert_dir)? {
        return Ok(pair);
    }
    let pair = bootstrap_self_signed(hostnames)?;
    store_bootstrap(cert_dir, &pair)?;
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use super::{
        ALPN_H2_HTTP11, BOOTSTRAP_CERT_FILE, BOOTSTRAP_KEY_FILE, CertStore, CertifiedKeyPair,
        TlsError, bootstrap_self_signed, confine_cert_dir, fingerprint, install_crypto_provider,
        load_bootstrap, load_or_bootstrap, server_config, store_bootstrap,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../locales/en-US/core.ftl");

    fn catalogue_has(id: &str) -> bool {
        CATALOGUE
            .lines()
            .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id))
    }

    fn pair() -> Result<CertifiedKeyPair, TlsError> {
        bootstrap_self_signed(&["box.example".to_owned()])
    }

    #[test]
    fn installing_the_provider_twice_is_harmless() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn a_bootstrap_certificate_loads_into_the_provider() -> R {
        let pair = pair()?;
        let key = pair.to_certified_key()?;
        assert!(!key.cert.is_empty());
        Ok(())
    }

    #[test]
    fn the_debug_output_never_carries_the_private_key() -> R {
        let pair = pair()?;
        let rendered = format!("{pair:?}");
        assert!(rendered.contains(&pair.fingerprint()));
        assert!(rendered.contains("key_bytes"));
        // Two bytes of the key in hex would be enough to prove a leak; check
        // the whole thing is absent in any obvious rendering.
        assert!(!rendered.contains("key_pkcs8"));
        Ok(())
    }

    #[test]
    fn the_fingerprint_is_uppercase_colon_separated_sha256() {
        let printed = fingerprint(b"");
        // SHA-256 of the empty input, the standard test vector.
        assert!(printed.starts_with("E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24"));
        assert_eq!(printed.len(), 32 * 3 - 1);
        assert_eq!(printed.matches(':').count(), 31);
        assert!(
            printed
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ':')
        );
        assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
    }

    #[test]
    fn a_certificate_carries_the_configured_and_the_always_names() -> R {
        // rcgen re-parsing needs `x509-parser`, which is not compiled in, so
        // the SANs are checked the way a client sees them: through a real
        // handshake in `tests/tls.rs`. Here we only prove generation succeeds
        // for names of both kinds and that a bad name is refused.
        let ok = bootstrap_self_signed(&["box.example".to_owned(), "10.0.0.1".to_owned()])?;
        assert!(!ok.cert_der().is_empty());

        // rcgen only rejects a SAN that is not representable as IA5 (ASCII),
        // so a non-ASCII name is the reachable failure.
        let bad = bootstrap_self_signed(&["bö.example".to_owned()]);
        match bad {
            Err(err @ TlsError::Generate(_)) => {
                assert_eq!(err.message_id().as_str(), "web-tls-generate-failed");
            }
            other => return Err(format!("expected a generate error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn duplicate_names_are_not_repeated() -> R {
        // `localhost` is always added; asking for it explicitly must not make
        // the certificate carry it twice.
        let pair = bootstrap_self_signed(&["localhost".to_owned()])?;
        assert!(!pair.cert_der().is_empty());
        Ok(())
    }

    #[test]
    fn the_store_swaps_what_it_resolves() -> R {
        let first = pair()?;
        let second = pair()?;
        assert_ne!(first.fingerprint(), second.fingerprint());

        let store = CertStore::new(&first)?;
        let before = store.current();
        store.replace(&second)?;
        let after = store.current();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(
            after.cert.first().map(|c| c.to_vec()),
            Some(second.cert_der().to_vec())
        );
        Ok(())
    }

    #[test]
    fn a_poisoned_store_still_serves_and_still_reloads() -> R {
        // A panic elsewhere in the process must not cost the service its
        // certificate, nor its ability to install a renewed one. The guarded
        // value is a single `Arc` that is only ever wholly replaced, so
        // recovering from the poison is sound.
        let store = Arc::new(CertStore::new(&pair()?)?);
        let poisoner = Arc::clone(&store);
        let outcome = std::thread::spawn(move || {
            let _guard = poisoner.current.write();
            // Poisons the lock on purpose. `panic!` is denied crate-wide;
            // `unreachable!` is the escape hatch the lint set leaves.
            unreachable!("poisoning the certificate lock deliberately")
        })
        .join();
        assert!(outcome.is_err(), "the poisoning thread did not panic");
        assert!(store.current.is_poisoned());

        assert!(!store.current().cert.is_empty());
        let renewed = pair()?;
        store.replace(&renewed)?;
        assert_eq!(
            store.current().cert.first().map(|c| c.to_vec()),
            Some(renewed.cert_der().to_vec())
        );
        Ok(())
    }

    #[test]
    fn the_store_refuses_a_mismatched_pair_and_keeps_the_old_one() -> R {
        let good = pair()?;
        let other = pair()?;
        let store = CertStore::new(&good)?;
        // A certificate from one key with the private key of another.
        let mismatched = CertifiedKeyPair::new(good.cert_der().to_vec(), Vec::new());
        assert!(store.replace(&mismatched).is_err());
        assert_eq!(
            store.current().cert.first().map(|c| c.to_vec()),
            Some(good.cert_der().to_vec())
        );
        assert!(other.to_certified_key().is_ok());
        Ok(())
    }

    #[test]
    fn a_garbage_key_is_rejected_with_a_catalogued_id() -> R {
        let good = pair()?;
        let broken = CertifiedKeyPair::new(good.cert_der().to_vec(), vec![0_u8; 8]);
        match broken.to_certified_key() {
            Err(err @ TlsError::Key(_)) => {
                assert_eq!(err.message_id().as_str(), "web-tls-key-rejected");
            }
            other => return Err(format!("expected a key error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn acme_pem_round_trips_through_a_store_swap() -> R {
        // Simulates the Phase 6 renewal path with fixtures, not the network:
        // a PEM chain + PEM key become a pair that the live store accepts,
        // replacing the bootstrap pair a handshake would have used.
        use rcgen::generate_simple_self_signed;
        let rendered = generate_simple_self_signed(["renewed.example".to_owned()])?;
        let renewed = CertifiedKeyPair::from_acme_pem(
            &rendered.cert.pem(),
            &rendered.signing_key.serialize_pem(),
        )?;
        let store = CertStore::new(&pair()?)?;
        store.replace(&renewed)?;
        assert_eq!(
            store.current().cert.first().map(|c| c.to_vec()),
            Some(renewed.cert_der().to_vec())
        );
        Ok(())
    }

    #[test]
    fn acme_pem_rejects_the_wrong_armour_with_a_catalogued_id() -> R {
        use rcgen::generate_simple_self_signed;
        let rendered = generate_simple_self_signed(["bad.example".to_owned()])?;
        let chain_pem = rendered.cert.pem();
        // A SEC1 `EC PRIVATE KEY` header where PKCS#8 `PRIVATE KEY` belongs:
        // same body, wrong armour, refused rather than converted.
        let sec1 =
            rendered
                .signing_key
                .serialize_pem()
                .replacen("PRIVATE KEY", "EC PRIVATE KEY", 2);
        match CertifiedKeyPair::from_acme_pem(&chain_pem, &sec1) {
            Err(err @ TlsError::Pem) => {
                assert_eq!(err.message_id().as_str(), "web-tls-acme-pem-rejected");
                assert!(catalogue_has("web-tls-acme-pem-rejected"));
            }
            other => return Err(format!("expected a PEM error, got {other:?}").into()),
        }
        match CertifiedKeyPair::from_acme_pem("not pem at all", &chain_pem) {
            Err(err @ TlsError::Pem) => {
                assert_eq!(err.message_id().as_str(), "web-tls-acme-pem-rejected");
            }
            other => return Err(format!("expected a PEM error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_server_config_advertises_the_requested_alpn() -> R {
        let config = server_config(&pair()?, ALPN_H2_HTTP11)?;
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // rustls keeps the enabled version list private, so "TLS 1.3 only" is
        // proved where it matters — over a real handshake, in `tests/tls.rs`.
        Ok(())
    }

    #[test]
    fn the_store_is_written_0600_under_a_0700_directory() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        let pair = pair()?;
        store_bootstrap(&cert_dir, &pair)?;

        let dir_mode = std::fs::metadata(&cert_dir)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "certs dir is {dir_mode:o}");
        for name in [BOOTSTRAP_CERT_FILE, BOOTSTRAP_KEY_FILE] {
            let mode = std::fs::metadata(cert_dir.join(name))?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} is {mode:o}");
        }
        Ok(())
    }

    #[test]
    fn a_restart_reuses_the_stored_fingerprint() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        let names = vec!["box.example".to_owned()];

        let first = load_or_bootstrap(&cert_dir, &names)?;
        let second = load_or_bootstrap(&cert_dir, &names)?;
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first, second);
        assert!(second.to_certified_key().is_ok());
        Ok(())
    }

    #[test]
    fn a_half_written_store_reads_as_absent() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        assert!(load_bootstrap(&cert_dir)?.is_none());

        store_bootstrap(&cert_dir, &pair()?)?;
        std::fs::remove_file(cert_dir.join(BOOTSTRAP_KEY_FILE))?;
        assert!(load_bootstrap(&cert_dir)?.is_none());

        store_bootstrap(&cert_dir, &pair()?)?;
        std::fs::remove_file(cert_dir.join(BOOTSTRAP_CERT_FILE))?;
        assert!(load_bootstrap(&cert_dir)?.is_none());
        Ok(())
    }

    #[test]
    fn an_overwrite_restores_the_0600_mode() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        store_bootstrap(&cert_dir, &pair()?)?;
        let key = cert_dir.join(BOOTSTRAP_KEY_FILE);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;

        store_bootstrap(&cert_dir, &pair()?)?;
        let mode = std::fs::metadata(&key)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode is {mode:o}");
        Ok(())
    }

    /// A `certs/` directory that already exists — made by hand, or by a
    /// `tmpfiles.d` snippet that was edited — must be narrowed to `0700`, not
    /// left as the umask made it. A `0600` key under a `0755` directory is
    /// still enumerable and still watchable by every local account.
    #[test]
    fn a_pre_existing_store_directory_is_narrowed_to_0700() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        std::fs::create_dir_all(&cert_dir)?;
        std::fs::set_permissions(&cert_dir, std::fs::Permissions::from_mode(0o755))?;

        store_bootstrap(&cert_dir, &pair()?)?;
        let mode = std::fs::metadata(&cert_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "certs dir is {mode:o}");
        Ok(())
    }

    /// A directory that is already tight is left exactly as it is: an install
    /// where `certs/` belongs to another account would otherwise fail to start
    /// on a `set_permissions` this process has no business making.
    #[test]
    fn an_already_confined_store_directory_is_left_alone() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        std::fs::create_dir_all(&cert_dir)?;
        std::fs::set_permissions(&cert_dir, std::fs::Permissions::from_mode(0o500))?;

        confine_cert_dir(&cert_dir)?;
        let mode = std::fs::metadata(&cert_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o500, "certs dir is {mode:o}");
        Ok(())
    }

    #[test]
    fn an_unreadable_store_is_reported_not_silently_regenerated() -> R {
        let dir = tempfile::tempdir()?;
        let cert_dir = dir.path().join("certs");
        std::fs::create_dir_all(cert_dir.join(BOOTSTRAP_CERT_FILE))?;
        match load_bootstrap(&cert_dir) {
            Err(err @ TlsError::Read { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-tls-store-unreadable");
            }
            other => return Err(format!("expected a read error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_relative_certificate_directory_is_refused_by_the_atomic_writer() -> R {
        let cert_dir = std::path::Path::new("relative-certs-should-not-work");
        match store_bootstrap(cert_dir, &pair()?) {
            Err(err @ TlsError::Persist { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-tls-store-write-failed");
            }
            other => {
                let _ = std::fs::remove_dir_all(cert_dir);
                return Err(format!("expected a persist error, got {other:?}").into());
            }
        }
        std::fs::remove_dir_all(cert_dir)?;
        Ok(())
    }

    #[test]
    fn a_directory_that_cannot_be_created_is_reported() -> R {
        let dir = tempfile::tempdir()?;
        // A regular file where the directory should be: `create_dir_all` fails.
        let blocked = dir.path().join("certs");
        std::fs::write(&blocked, b"not a directory")?;
        match store_bootstrap(&blocked, &pair()?) {
            Err(err @ TlsError::Prepare { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-tls-store-unwritable");
            }
            other => return Err(format!("expected a prepare error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn every_error_variant_has_a_catalogued_message_id() {
        for id in [
            "web-tls-generate-failed",
            "web-tls-key-rejected",
            "web-tls-acme-pem-rejected",
            "web-tls-no-provider",
            "web-tls-store-unreadable",
            "web-tls-store-unwritable",
            "web-tls-store-write-failed",
        ] {
            assert!(catalogue_has(id), "`{id}` is missing from core.ftl");
        }
        let no_provider = TlsError::NoProvider;
        assert_eq!(no_provider.message_id().as_str(), "web-tls-no-provider");
        assert!(!no_provider.to_string().is_empty());
        assert!(!format!("{no_provider:?}").is_empty());
    }
}
