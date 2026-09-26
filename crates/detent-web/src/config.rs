//! `/etc/detent/detent.toml`, read into types (PLAN §2.10).
//!
//! Two rules shape everything here.
//!
//! * **A missing file is not a failure.** An appliance that has never been
//!   through `detent setup` must still start, and it must start on the secure
//!   settings rather than on nothing at all. So every table carries a
//!   [`Default`] that matches the documented default, the container types are
//!   `#[serde(default)]`, and [`Config::load`] answers
//!   [`Config::default()`](Config::default) when the path does not exist. A
//!   file that *does* exist but cannot be read or parsed is a hard error: that
//!   is an operator mistake, and silently running on defaults would hide it.
//! * **A typo is not a silent downgrade.** Every struct is
//!   `#[serde(deny_unknown_fields)]`, so `totp_requird = true` is refused
//!   instead of leaving TOTP off while the operator believes it is on.
//!
//! [`Config::validate`] then rejects the values the type system cannot: a
//! connection cap of zero, a timeout of zero, and Argon2 parameters below the
//! OWASP floor.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use detent_core::diag::MessageId;
use serde::Deserialize;

/// Port `detent` listens on when the operator has not said otherwise.
pub const DEFAULT_PORT: u16 = 3333;

/// Where the bootstrap and ACME certificates live (PLAN §2.8, §2.10).
pub const DEFAULT_CERT_DIR: &str = "/var/lib/detent/certs";

/// The lowest Argon2id memory cost this build accepts, in KiB.
///
/// OWASP's floor for the `m=19456, t=2, p=1` profile. A tiny board may go
/// this low; nothing may go lower, however small the board (PLAN §2.7).
pub const MIN_ARGON2_M_KIB: u32 = 19456;

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Why a configuration file could not be turned into a [`Config`].
///
/// Each variant carries a stable [`MessageId`] so a front end renders a
/// localized sentence rather than a Rust error string, exactly as
/// `detent_ops::OpsError` does. The `Display` text exists for logs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file exists but could not be read.
    #[error("{path} could not be read: {source}")]
    Read {
        /// The path that was tried.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The file is not valid TOML, or does not match the documented shape.
    #[error("{path} is not a valid detent configuration: {source}")]
    Parse {
        /// The path that was tried, or `<memory>` for [`Config::parse`].
        path: PathBuf,
        /// The parser's own report, with a span.
        source: toml::de::Error,
    },
    /// A field parsed but holds a value that cannot mean anything useful.
    #[error("{field} must be greater than zero")]
    ZeroValue {
        /// Dotted path of the offending field, e.g. `listen.max_connections`.
        field: &'static str,
    },
    /// `auth.argon2.m_kib` was set explicitly below [`MIN_ARGON2_M_KIB`].
    #[error("auth.argon2.m_kib is {m_kib}, below the minimum of {MIN_ARGON2_M_KIB}")]
    WeakArgon2 {
        /// What the file asked for.
        m_kib: u32,
    },
}

impl ConfigError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Read { .. } => MessageId::new("web-config-unreadable"),
            Self::Parse { .. } => MessageId::new("web-config-malformed"),
            Self::ZeroValue { .. } => MessageId::new("web-config-zero-value"),
            Self::WeakArgon2 { .. } => MessageId::new("web-config-weak-argon2"),
        }
    }
}

// ---------------------------------------------------------------------------
// [acme]
// ---------------------------------------------------------------------------

/// `[acme]` — how the renewal loop orders certificates (PLAN Phase 6).
///
/// All opt-in: an empty table means "self-signed only", and the loop only
/// runs when every field it needs is present. Paths are files the worker
/// owns (`0600` credentials, PEM CA root); `domains` are the dns-01 names a
/// renewal orders for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AcmeConfig {
    /// ACME directory URL, e.g. a Pebble or Let's Encrypt endpoint.
    /// `None` means the renewal loop stays idle.
    pub directory_url: Option<String>,
    /// `mailto:`/`tel:` URIs recorded on fresh account registration.
    pub contacts: Vec<String>,
    /// Domains a renewal orders for. Empty means no order is attempted.
    pub domains: Vec<String>,
    /// Where the cached account credentials live (`0600`).
    pub credentials_path: Option<PathBuf>,
    /// Optional PEM CA root for a private ACME server.
    pub ca_root: Option<PathBuf>,
    /// CA profile to request (e.g. `"shortlived"`); `None` where the server
    /// advertises no profiles extension (Pebble).
    pub profile: Option<String>,
    /// `[acme.provider]`: the dns-01 provider that publishes the challenge
    /// record. `None` means no provider is configured. Its one secret is in
    /// `secrets.toml` (`crate::secrets`), never in this table.
    pub provider: Option<DnsProviderConfig>,
}

/// `[acme.provider]`: which dns-01 provider to use, selected by `kind`.
///
/// Each variant holds only the non-secret settings. The secret (API token,
/// acme-dns password or TSIG key) is `[acme] dns_provider` in
/// `secrets.toml`. An unknown `kind` or an unknown field is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DnsProviderConfig {
    /// `kind = "cloudflare"`: the Cloudflare v4 API.
    Cloudflare {
        /// The zone id, 32 hex characters.
        zone_id: String,
    },
    /// `kind = "acme-dns"`: an acme-dns server.
    AcmeDns {
        /// The `https://` URL of the server.
        server: String,
        /// The subdomain the server gave at registration.
        username: String,
    },
    /// `kind = "desec"`: the deSEC.io API.
    Desec {
        /// The zone, e.g. `example.com`.
        domain: String,
    },
    /// `kind = "rfc2136"`: TSIG-signed dynamic updates to the primary server.
    Rfc2136 {
        /// The primary server, `host:port`.
        server: String,
        /// The zone that holds the SOA.
        zone: String,
        /// The TSIG key name.
        key_name: String,
        /// The TSIG algorithm, e.g. `hmac-sha256`.
        algorithm: String,
    },
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// The whole of `/etc/detent/detent.toml`.
///
/// Tables this build does not own yet (`[privilege]`, `[secrets]`) are
/// deliberately absent rather than accepted-and-ignored: with
/// `deny_unknown_fields` an operator who writes one gets told this build does
/// not read it, which is the truth. They arrive with the phases that use them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Socket, connection cap and timeouts.
    pub listen: ListenConfig,
    /// Where the certificate comes from and where it is kept.
    pub tls: TlsConfig,
    /// How certificate renewal orders certificates. Empty means self-signed.
    pub acme: AcmeConfig,
    /// Password hashing, session lifetimes, lockout.
    pub auth: AuthConfig,
    /// Self-update policy.
    pub update: UpdateConfig,
    /// Which of the compiled-in modules are offered.
    pub modules: ModulesConfig,
    /// Presentation defaults for the web UI.
    pub ui: UiConfig,
}

impl Config {
    /// Read and validate the file at `path`.
    ///
    /// A **missing file yields [`Config::default()`]** — a host that has never
    /// been configured still starts, on the documented defaults. Anything else
    /// that goes wrong is an error.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] when the file exists but cannot be read,
    /// [`ConfigError::Parse`] when it is not valid TOML or carries an unknown
    /// key, and the validation variants when a value is out of range.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        Self::from_str_at(&text, path)
    }

    /// Parse and validate configuration text that is already in memory.
    ///
    /// # Errors
    ///
    /// As [`Config::load`], minus [`ConfigError::Read`].
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        Self::from_str_at(s, Path::new("<memory>"))
    }

    /// The shared body of [`load`](Self::load) and [`parse`](Self::parse):
    /// `path` only names the source in the error.
    fn from_str_at(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Reject values that parse but cannot mean anything.
    ///
    /// Called by [`load`](Self::load) and [`parse`](Self::parse); public so a
    /// caller that assembles a `Config` by hand can hold itself to the same
    /// bar.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ZeroValue`] for a zero cap or timeout,
    /// [`ConfigError::WeakArgon2`] for an explicit memory cost below
    /// [`MIN_ARGON2_M_KIB`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.max_connections == 0 {
            return Err(ConfigError::ZeroValue {
                field: "listen.max_connections",
            });
        }
        if self.listen.request_timeout_secs == 0 {
            return Err(ConfigError::ZeroValue {
                field: "listen.request_timeout_secs",
            });
        }
        if self.auth.idle_timeout_secs == 0 {
            return Err(ConfigError::ZeroValue {
                field: "auth.idle_timeout_secs",
            });
        }
        if self.auth.absolute_timeout_secs == 0 {
            return Err(ConfigError::ZeroValue {
                field: "auth.absolute_timeout_secs",
            });
        }
        self.auth.argon2.validate()
    }
}

// ---------------------------------------------------------------------------
// [listen]
// ---------------------------------------------------------------------------

/// `[listen]` — the socket and the two limits that bound one connection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenConfig {
    /// Address and port to bind. Default `0.0.0.0:3333`.
    pub addr: SocketAddr,
    /// Hard cap on concurrent TLS connections. Default 64.
    pub max_connections: u32,
    /// Ceiling on one request, handshake excluded. Default 30 s.
    pub request_timeout_secs: u64,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT),
            max_connections: 64,
            request_timeout_secs: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// [tls]
// ---------------------------------------------------------------------------

/// Where the certificate the listener serves comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Bootstrap {
    /// Generate (and reuse) a self-signed certificate, printing its
    /// fingerprint for trust-on-first-use. The default, and what `setup`
    /// writes before ACME has ever succeeded.
    #[default]
    SelfSigned,
    /// Expect `detent-acme` to supply the certificate (Phase 6).
    Acme,
}

/// `[tls]` — certificate source, storage, and the names the bootstrap
/// certificate is valid for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Where the certificate comes from. Default [`Bootstrap::SelfSigned`].
    pub bootstrap: Bootstrap,
    /// Directory holding the key and certificate, `0700`, worker-owned.
    /// Default `/var/lib/detent/certs`.
    pub cert_dir: PathBuf,
    /// Extra subject alternative names for the bootstrap certificate.
    ///
    /// Empty by default: the caller adds the host's own name, which only it
    /// can resolve. `localhost`, `127.0.0.1` and `::1` are always included by
    /// [`bootstrap_self_signed`](crate::tls::bootstrap_self_signed) and need
    /// not be listed here.
    pub hostnames: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            bootstrap: Bootstrap::SelfSigned,
            cert_dir: PathBuf::from(DEFAULT_CERT_DIR),
            hostnames: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// [auth]
// ---------------------------------------------------------------------------

/// Argon2id cost parameters (PLAN §2.7).
///
/// `t` and `p` are fixed by the plan at 3 and 1; only memory scales with the
/// board, which is why `m_kib` is the only optional one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Argon2Params {
    /// Memory cost in KiB. `None` means "derive it from this host's RAM" —
    /// see [`Argon2Params::for_host`] and
    /// [`Argon2Params::resolved_m_kib`].
    pub m_kib: Option<u32>,
    /// Time cost (iterations). Default 3.
    pub t: u32,
    /// Parallelism. Default 1.
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: None,
            t: 3,
            p: 1,
        }
    }
}

/// The memory cost PLAN §2.7 prescribes for a host with `ram_mib` of RAM:
/// 64 MiB on anything with a gibibyte or more, 32 MiB on a half-gibibyte
/// board, and the OWASP floor below that.
const fn derived_m_kib(ram_mib: u64) -> u32 {
    if ram_mib >= 1024 {
        65536
    } else if ram_mib >= 512 {
        32768
    } else {
        MIN_ARGON2_M_KIB
    }
}

impl Argon2Params {
    /// The parameters PLAN §2.7 prescribes for a host with `ram_mib` of RAM.
    ///
    /// 64 MiB of hashing memory on anything with a gibibyte or more, 32 MiB on
    /// a half-gibibyte board, and the OWASP floor below that. `t` and `p` do
    /// not scale.
    #[must_use]
    pub const fn for_host(ram_mib: u64) -> Self {
        Self {
            m_kib: Some(derived_m_kib(ram_mib)),
            t: 3,
            p: 1,
        }
    }

    /// The memory cost to hash with: what the operator asked for, or what
    /// [`for_host`](Self::for_host) would pick for `ram_mib`.
    #[must_use]
    pub const fn resolved_m_kib(&self, ram_mib: u64) -> u32 {
        match self.m_kib {
            Some(m_kib) => m_kib,
            None => derived_m_kib(ram_mib),
        }
    }

    /// Reject costs that would make verification trivial or impossible.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ZeroValue`] for `t == 0` or `p == 0`,
    /// [`ConfigError::WeakArgon2`] when `m_kib` is set below
    /// [`MIN_ARGON2_M_KIB`]. An unset `m_kib` is always fine: it is derived
    /// from the host and never falls below the floor.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.t == 0 {
            return Err(ConfigError::ZeroValue {
                field: "auth.argon2.t",
            });
        }
        if self.p == 0 {
            return Err(ConfigError::ZeroValue {
                field: "auth.argon2.p",
            });
        }
        if let Some(m_kib) = self.m_kib
            && m_kib < MIN_ARGON2_M_KIB
        {
            return Err(ConfigError::WeakArgon2 { m_kib });
        }
        Ok(())
    }
}

/// `[auth]` — how a password becomes a session, and how long that lasts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// Password hashing cost.
    pub argon2: Argon2Params,
    /// Seconds of inactivity before a session is dropped. Default 900 (15 min).
    pub idle_timeout_secs: u64,
    /// Seconds a session may live regardless of activity. Default 28800 (8 h).
    pub absolute_timeout_secs: u64,
    /// Consecutive failures before lockout and backoff. Default 5.
    pub max_failures: u32,
    /// Require a TOTP second factor. Default false; the UI lands in Phase 5.
    pub totp_required: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            argon2: Argon2Params::default(),
            idle_timeout_secs: 900,
            absolute_timeout_secs: 28800,
            max_failures: 5,
            totp_required: false,
        }
    }
}

// ---------------------------------------------------------------------------
// [update], [modules], [ui]
// ---------------------------------------------------------------------------

/// `[update]` — self-update policy (PLAN §2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateConfig {
    /// A release must be at least this old before it is offered, unless it is
    /// flagged as a security release. Default 2 days.
    pub min_age_days: u16,
    /// Install automatically rather than only notifying. Default false.
    pub auto_install: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            min_age_days: 2,
            auto_install: false,
        }
    }
}

/// `[modules]` — which compiled-in modules this host offers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModulesConfig {
    /// Subset of the compiled-in modules to expose. `None` means every module
    /// this build contains; an empty list means none of them.
    pub enabled: Option<Vec<String>>,
}

/// `[ui]` — presentation defaults for the web UI.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    /// BCP-47 tag to prefer over the browser's `Accept-Language`. `None`
    /// negotiates against the request.
    pub default_locale: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AcmeConfig, Argon2Params, Bootstrap, Config, ConfigError, DEFAULT_CERT_DIR, DEFAULT_PORT,
        DnsProviderConfig, MIN_ARGON2_M_KIB,
    };
    use std::path::{Path, PathBuf};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The catalogue every localized build ships. Checked here rather than
    /// against a hand-kept list so a new variant without a message fails the
    /// build instead of rendering a bare `[web-...]` id at an operator.
    const CATALOGUE: &str = include_str!("../../../locales/en-US/core.ftl");

    fn catalogue_has(id: &str) -> bool {
        CATALOGUE
            .lines()
            .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id))
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let config = Config::default();
        assert_eq!(config.listen.addr.port(), DEFAULT_PORT);
        assert!(config.listen.addr.ip().is_unspecified());
        assert_eq!(config.listen.max_connections, 64);
        assert_eq!(config.listen.request_timeout_secs, 30);
        assert_eq!(config.tls.bootstrap, Bootstrap::SelfSigned);
        assert_eq!(config.tls.cert_dir, PathBuf::from(DEFAULT_CERT_DIR));
        assert!(config.tls.hostnames.is_empty());
        assert_eq!(config.acme, AcmeConfig::default());
        assert!(config.acme.directory_url.is_none());
        assert!(config.acme.contacts.is_empty());
        assert!(config.acme.domains.is_empty());
        assert!(config.acme.credentials_path.is_none());
        assert!(config.acme.ca_root.is_none());
        assert!(config.acme.profile.is_none());
        assert!(config.acme.provider.is_none());
        assert_eq!(config.auth.argon2, Argon2Params::default());
        assert_eq!(config.auth.argon2.m_kib, None);
        assert_eq!(config.auth.argon2.t, 3);
        assert_eq!(config.auth.argon2.p, 1);
        assert_eq!(config.auth.idle_timeout_secs, 900);
        assert_eq!(config.auth.absolute_timeout_secs, 28800);
        assert_eq!(config.auth.max_failures, 5);
        assert!(!config.auth.totp_required);
        assert_eq!(config.update.min_age_days, 2);
        assert!(!config.update.auto_install);
        assert_eq!(config.modules.enabled, None);
        assert_eq!(config.ui.default_locale, None);
    }

    #[test]
    fn an_empty_document_is_the_default_document() -> R {
        assert_eq!(Config::parse("")?, Config::default());
        Ok(())
    }

    #[test]
    fn a_missing_table_keeps_that_table_at_its_default() -> R {
        let config = Config::parse("[listen]\nmax_connections = 8\n")?;
        assert_eq!(config.listen.max_connections, 8);
        assert_eq!(config.listen.request_timeout_secs, 30);
        assert_eq!(config.auth, Config::default().auth);
        Ok(())
    }

    #[test]
    fn a_full_document_round_trips_into_types() -> R {
        let config = Config::parse(
            r#"
            [listen]
            addr = "127.0.0.1:8443"
            max_connections = 4
            request_timeout_secs = 5

            [tls]
            bootstrap = "acme"
            cert_dir = "/tmp/certs"
            hostnames = ["box.example"]

            [acme]
            directory_url = "https://ca.example/directory"
            contacts = ["mailto:ops@example"]
            domains = ["box.example"]
            credentials_path = "/tmp/acme.json"
            ca_root = "/tmp/ca.pem"
            profile = "shortlived"

            [auth]
            idle_timeout_secs = 60
            absolute_timeout_secs = 120
            max_failures = 2
            totp_required = true

            [auth.argon2]
            m_kib = 65536
            t = 4
            p = 2

            [update]
            min_age_days = 9
            auto_install = true

            [modules]
            enabled = ["hosts"]

            [ui]
            default_locale = "en-US"
            "#,
        )?;
        assert_eq!(config.listen.addr.to_string(), "127.0.0.1:8443");
        assert_eq!(config.listen.max_connections, 4);
        assert_eq!(config.listen.request_timeout_secs, 5);
        assert_eq!(config.tls.bootstrap, Bootstrap::Acme);
        assert_eq!(config.tls.cert_dir, PathBuf::from("/tmp/certs"));
        assert_eq!(config.tls.hostnames, vec!["box.example".to_owned()]);
        assert_eq!(
            config.acme.directory_url.as_deref(),
            Some("https://ca.example/directory")
        );
        assert_eq!(config.acme.contacts, vec!["mailto:ops@example".to_owned()]);
        assert_eq!(config.acme.domains, vec!["box.example".to_owned()]);
        assert_eq!(
            config.acme.credentials_path,
            Some(PathBuf::from("/tmp/acme.json"))
        );
        assert_eq!(config.acme.ca_root, Some(PathBuf::from("/tmp/ca.pem")));
        assert_eq!(config.acme.profile.as_deref(), Some("shortlived"));
        assert_eq!(config.auth.argon2.m_kib, Some(65536));
        assert_eq!(config.update.min_age_days, 9);
        assert!(config.update.auto_install);
        assert_eq!(config.modules.enabled, Some(vec!["hosts".to_owned()]));
        assert_eq!(config.ui.default_locale, Some("en-US".to_owned()));
        Ok(())
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        for text in [
            "totp_requird = true\n",
            "[listen]\nport = 3333\n",
            "[tls]\nboostrap = \"acme\"\n",
            "[acme]\ndirectory = \"https://ca.example\"\n",
            "[auth]\nargon = {}\n",
            "[auth.argon2]\nmemory = 1\n",
            "[update]\nmin_age = 1\n",
            "[modules]\nall = true\n",
            "[ui]\nlocale = \"en\"\n",
        ] {
            let err = Config::parse(text).err().map(|e| e.message_id());
            assert_eq!(
                err.map(|id| id.as_str().to_owned()),
                Some("web-config-malformed".to_owned()),
                "{text:?} was accepted"
            );
        }
    }

    #[test]
    fn an_acme_provider_table_selects_each_kind() -> R {
        let zone_id = "0123456789abcdef0123456789abcdef";
        let cases = [
            (
                format!("[acme.provider]\nkind = \"cloudflare\"\nzone_id = \"{zone_id}\"\n"),
                DnsProviderConfig::Cloudflare {
                    zone_id: zone_id.to_owned(),
                },
            ),
            (
                "[acme.provider]\nkind = \"acme-dns\"\nserver = \"https://auth.example\"\n\
                 username = \"sub-user\"\n"
                    .to_owned(),
                DnsProviderConfig::AcmeDns {
                    server: "https://auth.example".to_owned(),
                    username: "sub-user".to_owned(),
                },
            ),
            (
                "[acme.provider]\nkind = \"desec\"\ndomain = \"example.com\"\n".to_owned(),
                DnsProviderConfig::Desec {
                    domain: "example.com".to_owned(),
                },
            ),
            (
                "[acme.provider]\nkind = \"rfc2136\"\nserver = \"ns1.example.com:53\"\n\
                 zone = \"example.com\"\nkey_name = \"k.example.com\"\n\
                 algorithm = \"hmac-sha256\"\n"
                    .to_owned(),
                DnsProviderConfig::Rfc2136 {
                    server: "ns1.example.com:53".to_owned(),
                    zone: "example.com".to_owned(),
                    key_name: "k.example.com".to_owned(),
                    algorithm: "hmac-sha256".to_owned(),
                },
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(
                Config::parse(&text)?.acme.provider,
                Some(expected),
                "{text}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_bad_acme_provider_table_is_refused() {
        let zone_id = "0123456789abcdef0123456789abcdef";
        for text in [
            // An unknown kind, a kind in the wrong case, and no kind at all.
            "[acme.provider]\nkind = \"route53\"\n".to_owned(),
            format!("[acme.provider]\nkind = \"Cloudflare\"\nzone_id = \"{zone_id}\"\n"),
            format!("[acme.provider]\nzone_id = \"{zone_id}\"\n"),
            // No secret field exists here: the secret lives in secrets.toml.
            format!(
                "[acme.provider]\nkind = \"cloudflare\"\nzone_id = \"{zone_id}\"\n\
                 token = \"not-a-real-token\"\n"
            ),
            "[acme.provider]\nkind = \"acme-dns\"\nserver = \"https://auth.example\"\n\
             username = \"u\"\npassword = \"not-a-real-password\"\n"
                .to_owned(),
            "[acme.provider]\nkind = \"rfc2136\"\nserver = \"ns1.example.com:53\"\n\
             zone = \"example.com\"\nkey_name = \"k.example.com\"\n\
             algorithm = \"hmac-sha256\"\nkey_value = \"czNjcjN0LWtleQ==\"\n"
                .to_owned(),
            // A field that belongs to another kind.
            "[acme.provider]\nkind = \"desec\"\ndomain = \"example.com\"\n\
             zone_id = \"x\"\n"
                .to_owned(),
            // A required field left out.
            "[acme.provider]\nkind = \"cloudflare\"\n".to_owned(),
            "[acme.provider]\nkind = \"rfc2136\"\nserver = \"ns1.example.com:53\"\n\
             zone = \"example.com\"\nkey_name = \"k.example.com\"\n"
                .to_owned(),
        ] {
            let err = Config::parse(&text).err().map(|e| e.message_id());
            assert_eq!(
                err.map(|id| id.as_str().to_owned()),
                Some("web-config-malformed".to_owned()),
                "{text:?} was accepted"
            );
        }
    }

    #[test]
    fn a_bad_bootstrap_value_is_refused() {
        let err = Config::parse("[tls]\nbootstrap = \"self_signed\"\n");
        assert!(err.is_err());
    }

    #[test]
    fn zero_valued_limits_are_refused_field_by_field() -> R {
        let cases = [
            ("[listen]\nmax_connections = 0\n", "listen.max_connections"),
            (
                "[listen]\nrequest_timeout_secs = 0\n",
                "listen.request_timeout_secs",
            ),
            ("[auth]\nidle_timeout_secs = 0\n", "auth.idle_timeout_secs"),
            (
                "[auth]\nabsolute_timeout_secs = 0\n",
                "auth.absolute_timeout_secs",
            ),
            ("[auth.argon2]\nt = 0\n", "auth.argon2.t"),
            ("[auth.argon2]\np = 0\n", "auth.argon2.p"),
        ];
        for (text, field) in cases {
            match Config::parse(text) {
                Err(ConfigError::ZeroValue { field: got }) => assert_eq!(got, field),
                other => return Err(format!("{text:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn an_explicit_memory_cost_below_the_owasp_floor_is_refused() -> R {
        let text = format!(
            "[auth.argon2]\nm_kib = {}\n",
            MIN_ARGON2_M_KIB.saturating_sub(1)
        );
        match Config::parse(&text) {
            Err(ConfigError::WeakArgon2 { m_kib }) => {
                assert_eq!(m_kib, MIN_ARGON2_M_KIB.saturating_sub(1));
            }
            other => return Err(format!("{text:?} gave {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn the_owasp_floor_itself_is_accepted() -> R {
        let text = format!("[auth.argon2]\nm_kib = {MIN_ARGON2_M_KIB}\n");
        assert_eq!(
            Config::parse(&text)?.auth.argon2.m_kib,
            Some(MIN_ARGON2_M_KIB)
        );
        Ok(())
    }

    #[test]
    fn argon2_memory_follows_the_hosts_ram() {
        assert_eq!(Argon2Params::for_host(4096).m_kib, Some(65536));
        assert_eq!(Argon2Params::for_host(1024).m_kib, Some(65536));
        assert_eq!(Argon2Params::for_host(1023).m_kib, Some(32768));
        assert_eq!(Argon2Params::for_host(512).m_kib, Some(32768));
        assert_eq!(Argon2Params::for_host(511).m_kib, Some(MIN_ARGON2_M_KIB));
        assert_eq!(Argon2Params::for_host(0).m_kib, Some(MIN_ARGON2_M_KIB));
        for ram in [0_u64, 511, 512, 1024, 65536] {
            let params = Argon2Params::for_host(ram);
            assert_eq!(params.t, 3);
            assert_eq!(params.p, 1);
            assert!(params.validate().is_ok());
        }
    }

    #[test]
    fn an_unset_memory_cost_resolves_against_the_host() {
        let unset = Argon2Params::default();
        assert_eq!(unset.resolved_m_kib(4096), 65536);
        assert_eq!(unset.resolved_m_kib(256), MIN_ARGON2_M_KIB);
        let explicit = Argon2Params {
            m_kib: Some(20000),
            ..Argon2Params::default()
        };
        assert_eq!(explicit.resolved_m_kib(4096), 20000);
    }

    #[test]
    fn a_missing_file_is_the_default_configuration() -> R {
        let dir = tempfile::tempdir()?;
        let config = Config::load(&dir.path().join("absent.toml"))?;
        assert_eq!(config, Config::default());
        Ok(())
    }

    #[test]
    fn a_present_file_is_read_and_validated() -> R {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("detent.toml");
        std::fs::write(&path, "[listen]\nmax_connections = 3\n")?;
        assert_eq!(Config::load(&path)?.listen.max_connections, 3);

        std::fs::write(&path, "[listen]\nmax_connections = 0\n")?;
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::ZeroValue { .. })
        ));
        Ok(())
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_a_silent_default() -> R {
        // A directory is readable as a path but not as a file, which is the
        // portable way to reach a non-`NotFound` I/O failure.
        let dir = tempfile::tempdir()?;
        match Config::load(dir.path()) {
            Err(err @ ConfigError::Read { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-config-unreadable");
            }
            other => return Err(format!("expected a read error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn the_parse_error_names_the_file_it_came_from() -> R {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("detent.toml");
        std::fs::write(&path, "this is not toml\n")?;
        match Config::load(&path) {
            Err(err @ ConfigError::Parse { .. }) => {
                assert!(err.to_string().contains("detent.toml"), "{err}");
            }
            other => return Err(format!("expected a parse error, got {other:?}").into()),
        }
        assert!(
            Config::parse("nope")
                .err()
                .is_some_and(|e| e.to_string().contains("<memory>"))
        );
        Ok(())
    }

    #[test]
    fn every_error_variant_has_a_catalogued_message_id() {
        let cases: Vec<(ConfigError, &str)> = vec![
            (
                ConfigError::Read {
                    path: Path::new("/etc/detent/detent.toml").to_path_buf(),
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                },
                "web-config-unreadable",
            ),
            (
                ConfigError::ZeroValue {
                    field: "listen.max_connections",
                },
                "web-config-zero-value",
            ),
            (
                ConfigError::WeakArgon2 { m_kib: 8 },
                "web-config-weak-argon2",
            ),
        ];
        for (error, id) in cases {
            assert_eq!(error.message_id().as_str(), id);
            assert!(!error.to_string().is_empty(), "{error:?} renders empty");
            assert!(catalogue_has(id), "`{id}` is missing from core.ftl");
        }
        // `Parse` cannot be built by hand: `toml::de::Error` has no public
        // constructor, so it is reached through a real malformed document.
        let parse = Config::parse("=").err();
        assert_eq!(
            parse.map(|e| e.message_id().as_str().to_owned()),
            Some("web-config-malformed".to_owned())
        );
        assert!(catalogue_has("web-config-malformed"));
    }
}
