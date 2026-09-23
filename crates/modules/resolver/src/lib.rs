//! The `resolver` module: `/etc/resolv.conf`, systemd-resolved and unbound.
//!
//! One module, three backend formats (PLAN §7 resolver row):
//!
//! * `/etc/resolv.conf` — the glibc line format: `nameserver <ip>`, `search`,
//!   `domain` and `options`. On a host where systemd-resolved or `NetworkManager`
//!   manages the file, it is a symlink into the manager's runtime state; the
//!   `/etc/resolv.conf` target's detector then reports `false` so the
//!   operations layer picks the managing backend's target instead, and the
//!   platform layer's symlink refusal backs this up at write time.
//! * `/etc/systemd/resolved.conf` (+ `resolved.conf.d/` drop-ins) — INI-style
//!   `key=value` settings under `[Resolve]`.
//! * `/etc/unbound/unbound.conf` — the unbound clause format: `server:` and
//!   `forward-zone:` sections holding `key: value` items, attributes indented
//!   under their section.
//!
//! A line is [`LineKind::Directive`] when one of the three flavor parsers
//! accepts it; anything else — a resolv.conf directive this module does not
//! model, an unbound key outside its known set, a resolved.conf key outside
//! the modeled subset — stays [`LineKind::Unknown`] and is copied through an
//! edit untouched. Unbound quotes values
//! (`auto-trust-anchor-file: "/var/lib/unbound/root.key"`); quotes are
//! stripped in the model and a changed line is re-rendered unquoted, which
//! unbound parses the same way.
//!
//! # Formatting policy
//!
//! A line is left byte for byte alone whenever the entry parsed from it equals
//! the entry in the model, so hand indentation (unbound's tab-indented keys)
//! and odd spacing survive. Only lines that actually change are re-rendered,
//! canonically: `nameserver <ip>`, `[Resolve]`, `DNSSEC=yes`, `server:` and a
//! four-space-indented unbound attribute.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time. `detent-platform`
//! owns every file operation (PLAN §2.1).

use detent_core::descriptor::{
    FieldHints, HostProfile, ModuleDescriptor, Os, Owner, PathSpec, SecurityImpact, Target,
    TargetKind, UiGroup, Upstream, ValidationCtx, apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

// ------------------------------------------------------------------------- model

/// One DNS server in resolved.conf's `DNS=`/`FallbackDNS=` lists.
///
/// systemd's port syntax (`ip:port`, bracketed for IPv6) is deliberately not
/// modeled: a server token carrying a port stays [`LineKind::Unknown`] and is
/// preserved verbatim, because rendering it back would mean re-deriving
/// upstream's bracket rules.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    /// The server address.
    pub ip: IpAddr,
    /// The TLS authentication name after `#`, when the server carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One directive of `/etc/resolv.conf` this module models.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ResolvEntry {
    /// `nameserver <ip>`; one address per directive, in query order.
    Nameserver {
        /// The address of the upstream resolver.
        ip: IpAddr,
    },
    /// `search <domains…>`, the search list, in query order.
    Search {
        /// The search domains.
        domains: Vec<String>,
    },
    /// `domain <name>`, the legacy single-domain search list.
    Domain {
        /// The domain.
        domain: String,
    },
    /// `options <opt>…`, resolver behavior modifiers.
    Options {
        /// The option tokens, e.g. `ndots:2`, `edns0`.
        options: Vec<String>,
    },
}

/// One setting of `resolved.conf` under `[Resolve]` this module models.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ResolvedEntry {
    /// The `[Resolve]` section header.
    Resolve,
    /// `DNS=<servers…>`, the global DNS servers.
    Dns {
        /// The servers, optionally carrying `#auth-name` suffixes.
        servers: Vec<DnsServer>,
    },
    /// `FallbackDNS=<servers…>`, used when no configured server answers.
    FallbackDns {
        /// The servers, optionally carrying `#auth-name` suffixes.
        servers: Vec<DnsServer>,
    },
    /// `Domains=<domains…>`, search and routing domains (`~.`).
    Domains {
        /// The domains, in query order.
        domains: Vec<String>,
    },
    /// `DNSSEC=yes|no|allow-downgrade`.
    DnsSec {
        /// The DNSSEC mode.
        mode: ResolvedDnsSec,
    },
    /// `DNSOverTLS=yes|no|opportunistic`.
    DnsOverTls {
        /// The `DoT` mode.
        mode: ResolvedDnsOverTls,
    },
}

/// The `DNSSEC=` modes of systemd-resolved.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum ResolvedDnsSec {
    /// Validate strictly; a failed validation fails the query.
    Yes,
    /// Do not validate.
    No,
    /// Validate when upstream DNSSEC data is available, tolerate its absence.
    AllowDowngrade,
}

/// Parses `DNSSEC=` values.
impl std::str::FromStr for ResolvedDnsSec {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "yes" => Ok(Self::Yes),
            "no" => Ok(Self::No),
            "allow-downgrade" => Ok(Self::AllowDowngrade),
            _ => Err(()),
        }
    }
}

/// The value `DNSSEC=<mode>` renders as.
impl std::fmt::Display for ResolvedDnsSec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yes => f.write_str("yes"),
            Self::No => f.write_str("no"),
            Self::AllowDowngrade => f.write_str("allow-downgrade"),
        }
    }
}

/// The `DNSOverTLS=` modes of systemd-resolved.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "snake_case")]
pub enum ResolvedDnsOverTls {
    /// Require TLS; the query fails without it.
    Yes,
    /// Never use TLS.
    No,
    /// Use TLS when the server offers it, downgrade to plaintext otherwise.
    Opportunistic,
}

/// Parses `DNSOverTLS=` values.
impl std::str::FromStr for ResolvedDnsOverTls {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "yes" => Ok(Self::Yes),
            "no" => Ok(Self::No),
            "opportunistic" => Ok(Self::Opportunistic),
            _ => Err(()),
        }
    }
}

/// The value `DNSOverTLS=<mode>` renders as.
impl std::fmt::Display for ResolvedDnsOverTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yes => f.write_str("yes"),
            Self::No => f.write_str("no"),
            Self::Opportunistic => f.write_str("opportunistic"),
        }
    }
}

/// One item of `unbound.conf` this module models.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum UnboundEntry {
    /// The `server:` section header.
    Server,
    /// The `forward-zone:` section header.
    ForwardZone,
    /// A known `yes`/`no` hardening setting inside `server:`.
    Hardening {
        /// The directive name, e.g. `qname-minimisation`.
        key: String,
        /// Whether the directive is enabled.
        enabled: bool,
    },
    /// `name: <zone>` inside `forward-zone:`.
    ForwardName {
        /// The zone forwarded, `.` for the root.
        name: String,
    },
    /// `forward-addr: <ip>[@port][#auth-name]` inside `forward-zone:`.
    ForwardAddr {
        /// The upstream address, port and authentication name.
        addr: String,
    },
    /// `forward-tls-upstream: yes|no` inside `forward-zone:`.
    ForwardTls {
        /// Whether the zone forwards over `DoT`.
        enabled: bool,
    },
}

/// The typed model of the resolver module: the directives it owns, in file
/// order per flavor. Exactly one flavor is normally non-empty — the one the
/// document came from; a model carrying several flavors at once is legal and
/// applies each flavor to the lines parsed as it.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The `/etc/resolv.conf` directives, in file order.
    pub resolv: Vec<ResolvEntry>,
    /// The `resolved.conf` settings, in file order.
    pub resolved: Vec<ResolvedEntry>,
    /// The `unbound.conf` items, in file order.
    pub unbound: Vec<UnboundEntry>,
}

/// One directive of any flavor, as the parsers and `apply` see it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// A resolv.conf directive.
    Resolv(ResolvEntry),
    /// A resolved.conf setting.
    Resolved(ResolvedEntry),
    /// An unbound.conf item.
    Unbound(UnboundEntry),
}

// ---------------------------------------------------------------- fuzzing support

/// Brings the `Arbitrary` trait into scope for the helpers below.
#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

/// Builds an RFC 1035-valid domain: one or two small labels with an optional
/// trailing dot (the fuzz `edit` target never needs the full 253-byte range to
/// exercise `apply`'s matching and rendering logic).
#[cfg(feature = "fuzzing")]
fn arbitrary_domain(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let labels = u.int_in_range(1..=2usize)?;
    let mut name = String::new();
    for index in 0..labels {
        if index > 0 {
            name.push('.');
        }
        let len = u.int_in_range(1..=6usize)?;
        for _ in 0..len {
            let at = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
            name.push(char::from(ALPHABET.get(at).copied().unwrap_or(b'a')));
        }
    }
    if bool::arbitrary(u)? {
        name.push('.');
    }
    Ok(name)
}

/// A fuzz-friendly `Arbitrary` for [`ResolvEntry`]: derived generation would
/// produce domain and option tokens carrying arbitrary bytes, nearly all of
/// which `render_resolv` refuses (correctly — invariant 5). This constrains
/// the tokens to the shapes the file format really accepts.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for ResolvEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        const OPTIONS: &[&str] = &["edns0", "trust-ad", "ndots:2", "timeout:5", "attempts:2"];
        match u.int_in_range(0..=3usize)? {
            0 => Ok(Self::Nameserver {
                ip: IpAddr::arbitrary(u)?,
            }),
            1 => {
                let domains = u.int_in_range(1..=3usize)?;
                let mut list = Vec::with_capacity(domains);
                for _ in 0..domains {
                    list.push(arbitrary_domain(u)?);
                }
                Ok(Self::Search { domains: list })
            }
            2 => Ok(Self::Domain {
                domain: arbitrary_domain(u)?,
            }),
            _ => {
                let count = u.int_in_range(1..=3usize)?;
                let mut options = Vec::with_capacity(count);
                for _ in 0..count {
                    let at = u.int_in_range(0..=OPTIONS.len().saturating_sub(1))?;
                    options.push(OPTIONS.get(at).copied().unwrap_or("edns0").to_owned());
                }
                Ok(Self::Options { options })
            }
        }
    }
}

/// Builds 1–3 DNS server entries: plain addresses, or `DoT` servers carrying an
/// authentication name.
#[cfg(feature = "fuzzing")]
fn arbitrary_dns_servers(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<DnsServer>> {
    let count = u.int_in_range(1..=3usize)?;
    let mut servers = Vec::with_capacity(count);
    for _ in 0..count {
        let name = if bool::arbitrary(u)? {
            Some(arbitrary_domain(u)?)
        } else {
            None
        };
        servers.push(DnsServer {
            ip: IpAddr::arbitrary(u)?,
            name,
        });
    }
    Ok(servers)
}

/// A fuzz-friendly `Arbitrary` for [`ResolvedEntry`]: DNS server tokens are
/// constrained to `ip` and `ip#auth-name` shapes, the only ones the renderer
/// accepts.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for ResolvedEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=5usize)? {
            0 => Ok(Self::Resolve),
            1 => Ok(Self::Dns {
                servers: arbitrary_dns_servers(u)?,
            }),
            2 => Ok(Self::FallbackDns {
                servers: arbitrary_dns_servers(u)?,
            }),
            3 => {
                let domains = u.int_in_range(1..=3usize)?;
                let mut list = Vec::with_capacity(domains);
                for _ in 0..domains {
                    list.push(arbitrary_domain(u)?);
                }
                Ok(Self::Domains { domains: list })
            }
            4 => Ok(Self::DnsSec {
                mode: ResolvedDnsSec::arbitrary(u)?,
            }),
            _ => Ok(Self::DnsOverTls {
                mode: ResolvedDnsOverTls::arbitrary(u)?,
            }),
        }
    }
}

/// A fuzz-friendly `Arbitrary` for [`UnboundEntry`]: keys come from the known
/// set, addresses from a round-trippable `ip[@port][#auth-name]` shape.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for UnboundEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=5usize)? {
            0 => Ok(Self::Server),
            1 => Ok(Self::ForwardZone),
            2 => {
                let at = u.int_in_range(0..=KNOWN_HARDENING.len().saturating_sub(1))?;
                Ok(Self::Hardening {
                    key: KNOWN_HARDENING
                        .get(at)
                        .copied()
                        .unwrap_or("harden-glue")
                        .to_owned(),
                    enabled: bool::arbitrary(u)?,
                })
            }
            3 => Ok(Self::ForwardName {
                name: if bool::arbitrary(u)? {
                    ".".to_owned()
                } else {
                    arbitrary_domain(u)?
                },
            }),
            4 => Ok(Self::ForwardAddr {
                addr: arbitrary_forward_addr(u)?,
            }),
            _ => Ok(Self::ForwardTls {
                enabled: bool::arbitrary(u)?,
            }),
        }
    }
}

/// Builds an `ip`, `ip@port` or `ip@port#auth-name` address.
#[cfg(feature = "fuzzing")]
fn arbitrary_forward_addr(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    let mut addr = IpAddr::arbitrary(u)?.to_string();
    if bool::arbitrary(u)? {
        addr.push('@');
        addr.push_str(u.int_in_range(1..=65535u16)?.to_string().as_str());
    }
    if bool::arbitrary(u)? {
        addr.push('#');
        addr.push_str(arbitrary_domain(u)?.as_str());
    }
    Ok(addr)
}

// ------------------------------------------------------------ parsing / rendering

/// Parses one line as a resolv.conf directive, or `None` when it is not one.
///
/// `nameserver` takes exactly one address; `search` and `options` need at least
/// one token. glibc supports no inline comments, so `nameserver 1.2.3.4 # note`
/// is not a directive and stays [`LineKind::Unknown`].
fn parse_resolv(raw: &str) -> Option<ResolvEntry> {
    let mut tokens = raw.split_whitespace();
    match tokens.next()? {
        "nameserver" => {
            let ip = tokens.next()?.parse().ok()?;
            if tokens.next().is_some() {
                return None;
            }
            Some(ResolvEntry::Nameserver { ip })
        }
        "search" => {
            let domains: Vec<String> = tokens.map(str::to_owned).collect();
            if domains.is_empty() {
                return None;
            }
            Some(ResolvEntry::Search { domains })
        }
        "domain" => {
            let domain = tokens.next()?;
            if tokens.next().is_some() {
                return None;
            }
            Some(ResolvEntry::Domain {
                domain: domain.to_owned(),
            })
        }
        "options" => {
            let options: Vec<String> = tokens.map(str::to_owned).collect();
            if options.is_empty() {
                return None;
            }
            Some(ResolvEntry::Options { options })
        }
        _ => None,
    }
}

/// Parses one line as a resolved.conf setting, or `None` when it is not one.
///
/// Only the keys this module models are accepted, spelled as upstream spells
/// them; keys and values are trimmed around the `=` the way systemd tolerates.
/// Any other key, a bad value, or a server token carrying the port syntax
/// stays [`LineKind::Unknown`] and is preserved verbatim.
fn parse_resolved(raw: &str) -> Option<ResolvedEntry> {
    let trimmed = raw.trim();
    if trimmed == "[Resolve]" {
        return Some(ResolvedEntry::Resolve);
    }
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    match key {
        "DNS" => Some(ResolvedEntry::Dns {
            servers: parse_dns_servers(value)?,
        }),
        "FallbackDNS" => Some(ResolvedEntry::FallbackDns {
            servers: parse_dns_servers(value)?,
        }),
        "Domains" => {
            let domains: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
            if domains.is_empty() {
                return None;
            }
            Some(ResolvedEntry::Domains { domains })
        }
        "DNSSEC" => Some(ResolvedEntry::DnsSec {
            mode: value.parse().ok()?,
        }),
        "DNSOverTLS" => Some(ResolvedEntry::DnsOverTls {
            mode: value.parse().ok()?,
        }),
        _ => None,
    }
}

/// Parses a space-separated `DNS=` list into [`DnsServer`] entries.
///
/// A server token is `ip` or `ip#auth-name`; systemd's port syntax is not
/// modeled and leaves the directive [`LineKind::Unknown`]. An empty value is
/// the empty list (`DNS=`), not a refusal.
fn parse_dns_servers(value: &str) -> Option<Vec<DnsServer>> {
    let mut servers = Vec::new();
    for token in value.split_whitespace() {
        let (ip, name) = match token.split_once('#') {
            Some((ip, name)) if !name.is_empty() => (ip, Some(name.to_owned())),
            Some(_) => return None,
            None => (token, None),
        };
        servers.push(DnsServer {
            ip: ip.parse().ok()?,
            name,
        });
    }
    Some(servers)
}

/// Parses one line as an unbound.conf item, or `None` when it is not one.
///
/// Section headers are matched exactly (`server:`, `forward-zone:`); known
/// `key: value` items are accepted with any indentation, which unbound treats
/// as cosmetic. Anything else — an unmodeled key, a `yes`/`no` key with a
/// different value — stays [`LineKind::Unknown`].
fn parse_unbound(raw: &str) -> Option<UnboundEntry> {
    let trimmed = raw.trim();
    if trimmed == "server:" {
        return Some(UnboundEntry::Server);
    }
    if trimmed == "forward-zone:" {
        return Some(UnboundEntry::ForwardZone);
    }
    let (key, value) = trimmed.split_once(':')?;
    let key = key.trim();
    let value = value.trim();
    match key {
        "name" => Some(UnboundEntry::ForwardName {
            name: strip_quotes(value),
        }),
        "forward-addr" => Some(UnboundEntry::ForwardAddr {
            addr: strip_quotes(value),
        }),
        "forward-tls-upstream" => Some(UnboundEntry::ForwardTls {
            enabled: parse_yes_no(value)?,
        }),
        key if KNOWN_HARDENING.contains(&key) => Some(UnboundEntry::Hardening {
            key: key.to_owned(),
            enabled: parse_yes_no(value)?,
        }),
        _ => None,
    }
}

/// Drops surrounding double quotes from an unbound value, as upstream quotes it.
fn strip_quotes(value: &str) -> String {
    value.trim_matches(|c| c == '"' || c == ' ').to_owned()
}

/// Parses `yes`/`no`, refusing anything else.
fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Parses one line as any flavor's directive, or `None` when it is not one.
///
/// The classifier's contract (invariant 2) is that [`LineKind::Directive`]
/// means exactly this function succeeds; `to_model` and `apply` both walk
/// `Directive` lines through it.
fn parse_entry(raw: &str) -> Option<Entry> {
    if let Some(entry) = parse_resolv(raw) {
        return Some(Entry::Resolv(entry));
    }
    if let Some(entry) = parse_resolved(raw) {
        return Some(Entry::Resolved(entry));
    }
    parse_unbound(raw).map(Entry::Unbound)
}

/// Classifies a line for the lossless document model.
///
/// A pure function of the line text alone: `Document` re-runs it after every
/// edit, so a context-dependent classifier would make `apply` non-deterministic.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with(['#', ';']) {
        LineKind::Comment
    } else if parse_entry(raw).is_some() {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

/// Renders a resolv.conf entry, refusing anything that would not round-trip.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when a token carries `\n`, `\r` or NUL
/// (invariant 5), and [`EditError::Unsupported`] when the rendered line does
/// not parse back to the same entry — an empty `search`/`options` list, or a
/// token that is not already trimmed.
fn render_resolv(entry: &ResolvEntry) -> Result<String, EditError> {
    let raw = match entry {
        ResolvEntry::Nameserver { ip } => format!("nameserver {ip}"),
        ResolvEntry::Search { domains } => format!("search {}", domains.join(" ")),
        ResolvEntry::Domain { domain } => format!("domain {domain}"),
        ResolvEntry::Options { options } => format!("options {}", options.join(" ")),
    };
    finish_render(entry, &raw, parse_resolv)
}

/// Renders a resolved.conf setting, refusing anything that would not round-trip.
///
/// # Errors
///
/// As [`render_resolv`]: a token carrying `\n`, `\r` or NUL, or a rendered
/// line that does not parse back to the same setting.
fn render_resolved(entry: &ResolvedEntry) -> Result<String, EditError> {
    let raw = match entry {
        ResolvedEntry::Resolve => "[Resolve]".to_owned(),
        ResolvedEntry::Dns { servers } => format!("DNS={}", render_dns_servers(servers)),
        ResolvedEntry::FallbackDns { servers } => {
            format!("FallbackDNS={}", render_dns_servers(servers))
        }
        ResolvedEntry::Domains { domains } => format!("Domains={}", domains.join(" ")),
        ResolvedEntry::DnsSec { mode } => format!("DNSSEC={mode}"),
        ResolvedEntry::DnsOverTls { mode } => format!("DNSOverTLS={mode}"),
    };
    finish_render(entry, &raw, parse_resolved)
}

/// Renders one resolved.conf DNS server token: `ip` or `ip#auth-name`.
fn render_dns_servers(servers: &[DnsServer]) -> String {
    let mut tokens = Vec::with_capacity(servers.len());
    for server in servers {
        let mut token = server.ip.to_string();
        if let Some(name) = server.name.as_deref() {
            token.push('#');
            token.push_str(name);
        }
        tokens.push(token);
    }
    tokens.join(" ")
}

/// Renders an unbound.conf item, refusing anything that would not round-trip.
///
/// Attributes are re-rendered with unbound's conventional four-space indent;
/// a line the model already matches is never rendered at all, so the original
/// indentation survives.
///
/// # Errors
///
/// As [`render_resolv`].
fn render_unbound(entry: &UnboundEntry) -> Result<String, EditError> {
    match entry {
        UnboundEntry::ForwardName { name } => {
            if name.contains(' ') || name.contains('\t') || name.contains(':') || name.contains('#')
            {
                return Err(EditError::Unsupported {
                    message: format!("forward name would not round-trip: {name:?}"),
                });
            }
        }
        UnboundEntry::ForwardAddr { addr } => {
            if addr.contains(' ') || addr.contains('\t') {
                return Err(EditError::Unsupported {
                    message: format!("forward addr would not round-trip: {addr:?}"),
                });
            }
            // `:` and `#` appear in valid forward-addrs (`2001:db8::1`,
            // `9.9.9.9@853#dns.quad9.net`), so only reject them when the addr
            // is not valid — otherwise an injection like `1.1.1.1 server: ...`
            // or `1.1.1.1# bad` would not round-trip.
            // ponytail: allow `:`/`#` inside valid addrs (IPv6, Quad9 DoT) to keep defaults rendering.
            if (addr.contains(':') || addr.contains('#')) && !is_valid_forward_addr(addr) {
                return Err(EditError::Unsupported {
                    message: format!("forward addr would not round-trip: {addr:?}"),
                });
            }
        }
        _ => {}
    }
    let raw = match entry {
        UnboundEntry::Server => "server:".to_owned(),
        UnboundEntry::ForwardZone => "forward-zone:".to_owned(),
        UnboundEntry::Hardening { key, enabled } => {
            format!("    {key}: {}", yes_no(*enabled))
        }
        UnboundEntry::ForwardName { name } => format!("    name: {name}"),
        UnboundEntry::ForwardAddr { addr } => format!("    forward-addr: {addr}"),
        UnboundEntry::ForwardTls { enabled } => {
            format!("    forward-tls-upstream: {}", yes_no(*enabled))
        }
    };
    finish_render(entry, &raw, parse_unbound)
}

/// `yes`/`no` for an unbound boolean.
fn yes_no(enabled: bool) -> &'static str {
    if enabled { "yes" } else { "no" }
}

/// The two guards every `render_*` shares: invariant 5 (no `\n`, `\r` or NUL
/// is ever emitted) and the round-trip check (an edit that would re-parse to a
/// different entry would silently mean something else, so it is refused).
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] and [`EditError::Unsupported`].
fn finish_render<T: PartialEq>(
    entry: &T,
    raw: &str,
    reparse: fn(&str) -> Option<T>,
) -> Result<String, EditError> {
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue {
            value: raw.to_owned(),
        });
    }
    if reparse(raw).as_ref() != Some(entry) {
        return Err(EditError::Unsupported {
            message: format!("entry does not round-trip through the file format: {raw:?}"),
        });
    }
    Ok(raw.to_owned())
}

// -------------------------------------------------------------------- descriptor

/// `/etc/resolv.conf` is detent's target only when no resolver backend manages
/// it: systemd-resolved and `NetworkManager` both make it a symlink into their
/// runtime state, which the platform layer refuses to edit and which detent
/// expresses by steering at the backend's own target below.
fn resolv_backend_detect(profile: &HostProfile) -> bool {
    !resolved_backend_detect(profile) && !nm_backend_detect(profile)
}

/// `/etc/systemd/resolved.conf` is the right target when systemd-resolved is
/// detected on the host.
fn resolved_backend_detect(profile: &HostProfile) -> bool {
    profile.service_version(SERVICE_RESOLVED).is_some()
}

/// `NetworkManager` also owns `/etc/resolv.conf` when it runs the resolver.
fn nm_backend_detect(profile: &HostProfile) -> bool {
    profile.service_version(SERVICE_NM).is_some()
}

/// `/etc/unbound/unbound.conf` is the right target when unbound is detected.
fn unbound_backend_detect(profile: &HostProfile) -> bool {
    profile.service_version(SERVICE_UNBOUND).is_some()
}

/// The service version key systemd-resolved is probed under.
const SERVICE_RESOLVED: &str = "systemd-resolved";
/// The service version key `NetworkManager` is probed under.
const SERVICE_NM: &str = "NetworkManager";
/// The service version key unbound is probed under.
const SERVICE_UNBOUND: &str = "unbound";

static RESOLVER_TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/resolv.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: resolv_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/systemd/resolved.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: resolved_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/systemd/resolved.conf.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: resolved_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/unbound/unbound.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Named("unbound"),
        backend_detect: unbound_backend_detect,
    },
];

static RESOLVER_SERVICES: &[detent_core::descriptor::ServiceBinding] = &[
    detent_core::descriptor::ServiceBinding {
        units: detent_core::descriptor::UnitNames {
            systemd: &["systemd-resolved.service"],
            openrc: &["systemd-resolved"],
            bsdrc: &[],
        },
        actions: &[detent_core::descriptor::ServiceAction::Restart],
    },
    detent_core::descriptor::ServiceBinding {
        units: detent_core::descriptor::UnitNames {
            systemd: &["unbound.service"],
            openrc: &["unbound"],
            bsdrc: &["unbound"],
        },
        actions: &[
            detent_core::descriptor::ServiceAction::Reload,
            detent_core::descriptor::ServiceAction::Restart,
        ],
    },
];

/// `unbound-checkconf` validates an unbound.conf candidate. resolv.conf has no
/// upstream validator binary and resolved.conf is checked by systemd itself at
/// load time, so no check is declared for those candidates; the check runner
/// reports, rather than fails, a validator that cannot run.
static RESOLVER_CHECKS: &[detent_core::descriptor::ExternalCheck] =
    &[detent_core::descriptor::ExternalCheck {
        program: PathSpec::new("/usr/sbin/unbound-checkconf"),
        args: &[detent_core::descriptor::ArgTemplate::TempFile],
        expects: detent_core::descriptor::CheckExpectation::ExitZero,
    }];

/// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
/// reads the TOML; the UI reads the descriptor.
#[cfg(test)]
const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

static RESOLVER_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "resolver",
    display_name_id: MessageId::new("resolver-name"),
    targets: RESOLVER_TARGETS,
    upstream: Upstream {
        project: "systemd",
        repo_url: "https://github.com/systemd/systemd.git",
        tracked_version: "257.6",
        release_feed: Some("https://github.com/systemd/systemd/releases.atom"),
        docs: &[
            "https://man7.org/linux/man-pages/man5/resolv.conf.5.html",
            "https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html",
            "https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html",
        ],
    },
    services: RESOLVER_SERVICES,
    checks: RESOLVER_CHECKS,
    // Network-critical per ADR-012: a bad resolver config can lock the admin
    // out of name resolution entirely.
    commit_confirm: true,
    security_notes: &[MessageId::new("resolver-note-managed-symlink")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `resolv`.
static RESOLV_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("resolver-tip-resolv"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `resolved`.
static RESOLVED_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("resolver-tip-resolved"),
    recommendation: None,
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

/// UI hints for `unbound`.
static UNBOUND_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("resolver-tip-unbound"),
    recommendation: None,
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `ResolverModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema. The hints live on the three backend fields; the entry
/// kinds inside each vector are the schema's enums and carry no hints of
/// their own.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/resolv", &RESOLV_HINTS),
        ("/properties/resolved", &RESOLVED_HINTS),
        ("/properties/unbound", &UNBOUND_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: no nameserver is configured.
const NO_NAMESERVER: MessageId = MessageId::new("resolver-no-nameserver");
/// Fluent id: the same address appears as two nameservers.
const DUPLICATE_NAMESERVER: MessageId = MessageId::new("resolver-duplicate-nameserver");
/// Fluent id: more nameservers than glibc reads.
const TOO_MANY_NAMESERVERS: MessageId = MessageId::new("resolver-too-many-nameservers");
/// Fluent id: a search, routing or server domain is not a valid domain name.
const INVALID_DOMAIN: MessageId = MessageId::new("resolver-invalid-domain");
/// Fluent id: an option token is not in glibc's `name[:value]` shape.
const UNKNOWN_OPTION: MessageId = MessageId::new("resolver-unknown-option");
/// Fluent id: both `search` and `domain` are present.
const SEARCH_AND_DOMAIN: MessageId = MessageId::new("resolver-search-and-domain");
/// Fluent id: the model configures no backend at all.
const NO_CONFIG: MessageId = MessageId::new("resolver-no-config");
/// Fluent id: a host-aware warning about an undetected backend.
const BACKEND_MISSING: MessageId = MessageId::new("resolver-backend-missing");
/// Fluent id: recommendation to require strict DNSSEC validation.
const REC_DNSSEC: MessageId = MessageId::new("resolver-rec-dnssec");
/// Fluent id: recommendation to require `DoT` instead of opportunistic TLS.
const REC_DOT: MessageId = MessageId::new("resolver-rec-dot");
/// Fluent id: an unbound key outside the modeled set.
const UNKNOWN_HARDENING: MessageId = MessageId::new("resolver-unknown-hardening");
/// Fluent id: an unbound setting in the wrong section.
const UNBOUND_MISPLACED: MessageId = MessageId::new("resolver-unbound-misplaced");
/// Fluent id: a forward-addr outside the `ip[@port][#auth-name]` shape.
const INVALID_FORWARD_ADDR: MessageId = MessageId::new("resolver-invalid-forward-addr");
/// Fluent id: a forward-zone name that is neither `.` nor a domain.
const INVALID_FORWARD_NAME: MessageId = MessageId::new("resolver-invalid-forward-name");
/// Fluent id: `DoT` forwarding without an authentication name.
const FORWARD_TLS_NO_AUTH: MessageId = MessageId::new("resolver-forward-tls-no-auth");
/// Fluent id: a recommended hardening setting is explicitly disabled.
const REC_HARDENING: MessageId = MessageId::new("resolver-rec-hardening");
/// Fluent id: a `forward-zone:` without a `name:`.
const FORWARD_ZONE_UNNAMED: MessageId = MessageId::new("resolver-forward-zone-unnamed");

/// How many nameserver entries glibc reads (MAXNS).
const MAX_NAMESERVERS: usize = 3;
/// Longest domain name RFC 1035 allows.
const MAX_DOMAIN_LEN: usize = 253;
/// Longest single label RFC 1035 allows.
const MAX_LABEL_LEN: usize = 63;

/// The unbound `yes`/`no` keys this module models.
const KNOWN_HARDENING: &[&str] = &[
    "qname-minimisation",
    "qname-minimisation-strict",
    "aggressive-nsec",
    "harden-glue",
    "harden-dnssec-stripped",
    "harden-below-nxdomain",
    "harden-referral-path",
    "hide-identity",
    "hide-version",
];

/// The hardening keys `validate` recommends enabling (PLAN §7 resolver row).
const RECOMMENDED_HARDENING: &[&str] = &[
    "qname-minimisation",
    "aggressive-nsec",
    "harden-dnssec-stripped",
    "harden-below-nxdomain",
];

/// Whether `name` is a valid domain name.
///
/// Labels are 1–63 characters of ASCII letters, digits and `-`, and may not
/// start or end with `-`; the whole name is at most 253 characters. One
/// trailing dot is allowed (FQDN presentation form), as is the bare root `.`.
/// A leading `~` is allowed: that is systemd-resolved's routing-domain marker.
fn is_valid_domain(name: &str) -> bool {
    let name = name.strip_prefix('~').unwrap_or(name);
    if name == "." {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= MAX_DOMAIN_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Whether `option` is in the shape glibc's resolv.conf options parser accepts.
///
/// glibc splits each token at the first `:` into a name and an optional value;
/// both are alphanumeric runs that may also carry `-`, `_` and `.`. An
/// unrecognized name is *not* refused outright — glibc tolerates unknown
/// options — which is why a bad token raises a warning, never an error.
fn is_valid_option(option: &str) -> bool {
    !option.is_empty()
        && option.split(':').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        })
}

/// Whether `addr` matches unbound's `forward-addr` shape `ip[@port][#auth-name]`.
fn is_valid_forward_addr(addr: &str) -> bool {
    let (server, auth) = match addr.split_once('#') {
        Some((server, auth)) => (server, Some(auth)),
        None => (addr, None),
    };
    if let Some(auth) = auth
        && (auth.is_empty() || !is_valid_domain(auth))
    {
        return false;
    }
    match server.split_once('@') {
        Some((ip, port)) => {
            ip.parse::<IpAddr>().is_ok() && !port.is_empty() && port.parse::<u16>().is_ok()
        }
        None => server.parse::<IpAddr>().is_ok(),
    }
}

/// Whether `name` is a valid `forward-zone:` name: the root or a domain.
fn is_valid_forward_zone_name(name: &str) -> bool {
    name == "." || is_valid_domain(name)
}

/// Validates the resolv.conf flavor: nameservers, domains and options.
fn validate_resolv(entries: &[ResolvEntry], diagnostics: &mut Diagnostics) {
    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    let mut count = 0usize;
    let mut has_search = false;
    let mut has_domain = false;
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            ResolvEntry::Nameserver { ip } => {
                count = count.saturating_add(1);
                if !seen.insert(*ip) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Warning, DUPLICATE_NAMESERVER)
                            .with_field(FieldPath::new(format!("resolv/{index}/ip")))
                            .with_arg("ip", ip.to_string()),
                    );
                }
            }
            ResolvEntry::Search { domains } => {
                has_search = true;
                validate_domains(domains, &format!("resolv/{index}/domains"), diagnostics);
            }
            ResolvEntry::Domain { domain } => {
                has_domain = true;
                validate_domains(
                    std::slice::from_ref(domain),
                    &format!("resolv/{index}"),
                    diagnostics,
                );
            }
            ResolvEntry::Options { options } => {
                for (position, option) in options.iter().enumerate() {
                    if !is_valid_option(option) {
                        diagnostics.push(
                            Diagnostic::new(Severity::Warning, UNKNOWN_OPTION)
                                .with_field(FieldPath::new(format!(
                                    "resolv/{index}/options/{position}"
                                )))
                                .with_arg("option", option.clone()),
                        );
                    }
                }
            }
        }
    }
    if count == 0 && !entries.is_empty() {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, NO_NAMESERVER).with_field(FieldPath::new("resolv")),
        );
    }
    if count > MAX_NAMESERVERS {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, TOO_MANY_NAMESERVERS)
                .with_field(FieldPath::new("resolv"))
                .with_arg("count", count.to_string())
                .with_arg("max", MAX_NAMESERVERS.to_string()),
        );
    }
    if has_search && has_domain {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, SEARCH_AND_DOMAIN)
                .with_field(FieldPath::new("resolv")),
        );
    }
}

/// Validates a list of domains against [`is_valid_domain`], reporting each bad
/// entry under `prefix`.
fn validate_domains(domains: &[String], prefix: &str, diagnostics: &mut Diagnostics) {
    for (position, domain) in domains.iter().enumerate() {
        if !is_valid_domain(domain) {
            diagnostics.push(
                Diagnostic::new(Severity::Error, INVALID_DOMAIN)
                    .with_field(FieldPath::new(format!("{prefix}/{position}")))
                    .with_arg("domain", domain.clone()),
            );
        }
    }
}

/// Validates the resolved.conf settings.
fn validate_resolved(entries: &[ResolvedEntry], diagnostics: &mut Diagnostics) {
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            ResolvedEntry::Dns { servers } | ResolvedEntry::FallbackDns { servers } => {
                for (position, server) in servers.iter().enumerate() {
                    let field = FieldPath::new(format!("resolved/{index}/servers/{position}"));
                    if let Some(name) = server.name.as_deref()
                        && (name.is_empty() || !is_valid_domain(name))
                    {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, INVALID_DOMAIN)
                                .with_field(field)
                                .with_arg("domain", name.to_owned()),
                        );
                    }
                }
            }
            ResolvedEntry::Domains { domains } => {
                validate_domains(domains, &format!("resolved/{index}/domains"), diagnostics);
            }
            ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::AllowDowngrade,
            } => {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_DNSSEC)
                        .with_field(FieldPath::new(format!("resolved/{index}/mode"))),
                );
            }
            ResolvedEntry::DnsOverTls {
                mode: ResolvedDnsOverTls::Opportunistic,
            } => {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_DOT)
                        .with_field(FieldPath::new(format!("resolved/{index}/mode"))),
                );
            }
            _ => {}
        }
    }
}

/// Pushes one `resolver-forward-zone-unnamed` finding.
fn unnamed(diagnostics: &mut Diagnostics) {
    diagnostics.push(Diagnostic::new(Severity::Error, FORWARD_ZONE_UNNAMED));
}

/// Pushes one `resolver-unbound-misplaced` finding: `key` belongs in `section`.
fn misplaced(diagnostics: &mut Diagnostics, index: usize, field: &str, key: &str, section: &str) {
    diagnostics.push(
        Diagnostic::new(Severity::Warning, UNBOUND_MISPLACED)
            .with_field(FieldPath::new(format!("unbound/{index}/{field}")))
            .with_arg("key", key.to_owned())
            .with_arg("section", section.to_owned()),
    );
}

/// Validates the unbound.conf items, tracking which section each belongs to.
/// The sections an unbound.conf item can belong to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    /// The main `server:` section.
    Server,
    /// A `forward-zone:` section.
    ForwardZone,
}

/// Closes an open forward zone, flagging it when no zone name has arrived.
fn close_zone(section: Option<Section>, forward_named: bool, diagnostics: &mut Diagnostics) {
    if section == Some(Section::ForwardZone) && !forward_named {
        unnamed(diagnostics);
    }
}

fn validate_unbound(entries: &[UnboundEntry], diagnostics: &mut Diagnostics) {
    let mut section: Option<Section> = None;
    let mut forward_named = false;
    let mut forward_tls = false;
    let mut forward_auth = false;
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            UnboundEntry::Server => {
                close_zone(section, forward_named, diagnostics);
                section = Some(Section::Server);
            }
            UnboundEntry::ForwardZone => {
                close_zone(section, forward_named, diagnostics);
                section = Some(Section::ForwardZone);
                forward_named = false;
                forward_tls = false;
                forward_auth = false;
            }
            UnboundEntry::Hardening { key, enabled } => {
                if !KNOWN_HARDENING.contains(&key.as_str()) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, UNKNOWN_HARDENING)
                            .with_field(FieldPath::new(format!("unbound/{index}/key")))
                            .with_arg("key", key.clone()),
                    );
                }
                if section != Some(Section::Server) {
                    misplaced(diagnostics, index, "key", key, "server");
                }
                if !enabled && RECOMMENDED_HARDENING.contains(&key.as_str()) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Recommendation, REC_HARDENING)
                            .with_field(FieldPath::new(format!("unbound/{index}/enabled")))
                            .with_arg("key", key.clone()),
                    );
                }
            }
            UnboundEntry::ForwardName { name } => {
                if !is_valid_forward_zone_name(name) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_FORWARD_NAME)
                            .with_field(FieldPath::new(format!("unbound/{index}/name")))
                            .with_arg("name", name.clone()),
                    );
                }
                if section == Some(Section::ForwardZone) {
                    if is_valid_forward_zone_name(name) {
                        forward_named = true;
                    }
                } else {
                    misplaced(diagnostics, index, "name", "name", "forward-zone");
                }
            }
            UnboundEntry::ForwardAddr { addr } => {
                if !is_valid_forward_addr(addr) {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, INVALID_FORWARD_ADDR)
                            .with_field(FieldPath::new(format!("unbound/{index}/addr")))
                            .with_arg("addr", addr.clone()),
                    );
                }
                if section == Some(Section::ForwardZone) {
                    if addr.contains('#') {
                        forward_auth = true;
                    }
                } else {
                    misplaced(diagnostics, index, "addr", "forward-addr", "forward-zone");
                }
            }
            UnboundEntry::ForwardTls { enabled } => {
                if section == Some(Section::ForwardZone) {
                    if *enabled {
                        forward_tls = true;
                    }
                } else {
                    misplaced(
                        diagnostics,
                        index,
                        "enabled",
                        "forward-tls-upstream",
                        "forward-zone",
                    );
                }
            }
        }
    }
    close_zone(section, forward_named, diagnostics);
    if forward_tls && !forward_auth {
        diagnostics.push(Diagnostic::new(
            Severity::Recommendation,
            FORWARD_TLS_NO_AUTH,
        ));
    }
}

// ---------------------------------------------------------------------- defaults

/// `127.0.0.1`, the loopback resolver glibc already assumes when no nameserver
/// is configured; the default file states it explicitly.
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Builds one resolv.conf default: the loopback resolver (explicit is better
/// than implicit) plus EDNS and DNSSEC-aware AD handling.
fn resolv_defaults() -> Model {
    Model {
        resolv: vec![
            ResolvEntry::Nameserver { ip: LOOPBACK },
            ResolvEntry::Options {
                options: vec!["edns0".to_owned(), "trust-ad".to_owned()],
            },
        ],
        resolved: Vec::new(),
        unbound: Vec::new(),
    }
}

/// Builds one resolved.conf default: per-link DNS (no `DNS=`), validation in
/// the allow-downgrade middle ground and opportunistic `DoT`. `validate` offers
/// the upgrade to `DNSSEC=yes` / `DNSOverTLS=yes` as recommendations.
fn resolved_defaults() -> Model {
    Model {
        resolv: Vec::new(),
        resolved: vec![
            ResolvedEntry::Resolve,
            ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::AllowDowngrade,
            },
            ResolvedEntry::DnsOverTls {
                mode: ResolvedDnsOverTls::Opportunistic,
            },
        ],
        unbound: Vec::new(),
    }
}

/// Builds one unbound.conf default: the hardening set PLAN §7 names, plus a
/// root forward-zone over `DoT` to Quad9's validating resolvers.
fn unbound_defaults() -> Model {
    const HARDENED: &[&str] = &[
        "qname-minimisation",
        "harden-dnssec-stripped",
        "harden-below-nxdomain",
        "aggressive-nsec",
        "hide-identity",
        "hide-version",
    ];
    let mut unbound = vec![UnboundEntry::Server];
    for key in HARDENED {
        unbound.push(UnboundEntry::Hardening {
            key: (*key).to_owned(),
            enabled: true,
        });
    }
    unbound.push(UnboundEntry::ForwardZone);
    unbound.push(UnboundEntry::ForwardName {
        name: ".".to_owned(),
    });
    unbound.push(UnboundEntry::ForwardTls { enabled: true });
    unbound.push(UnboundEntry::ForwardAddr {
        addr: "9.9.9.9@853#dns.quad9.net".to_owned(),
    });
    unbound.push(UnboundEntry::ForwardAddr {
        addr: "149.112.112.112@853#dns.quad9.net".to_owned(),
    });
    Model {
        resolv: Vec::new(),
        resolved: Vec::new(),
        unbound,
    }
}

// ----------------------------------------------------------------------- module

/// The resolver config module: `/etc/resolv.conf`, systemd-resolved, unbound.
pub struct ResolverModule;

impl ConfigModule for ResolverModule {
    /// The stable id. It appears in URLs, the CLI, the audit log, the
    /// `module-resolver` feature name, the Fluent id prefix,
    /// `fixtures/resolver/` and the fuzz target names.
    const ID: &'static str = "resolver";
    /// `detent_core::doc::Document` is the shared line-oriented CST and fits
    /// all three resolver formats: directives, comments and blanks.
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &RESOLVER_DESCRIPTOR
    }

    /// Total for line-oriented formats: succeeds on any `&str`, including
    /// empty input, lone `\r` and embedded NUL.
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// Projects only what the model can express, dropping nothing else —
    /// `Unknown` and `Comment` lines stay in the `Doc` and are what makes
    /// `render` lossless.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        let mut model = Model::default();
        for entry in doc
            .lines_of_kind(LineKind::Directive)
            .filter_map(|line| parse_entry(line.raw()))
        {
            match entry {
                Entry::Resolv(entry) => model.resolv.push(entry),
                Entry::Resolved(entry) => model.resolved.push(entry),
                Entry::Unbound(entry) => model.unbound.push(entry),
            }
        }
        Ok(model)
    }

    /// The minimal-edit two-pass shape shared with `hosts`, extended to pair
    /// each flavor's model entries with the directive lines parsed as that
    /// flavor. Pass 1 is read-only, so a refused value leaves the file exactly
    /// as it was; a line whose parsed entry already equals the model's is never
    /// rendered, so hand indentation and spacing survive.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1, read-only: pair each flavor's model entries with the directive
        // lines parsed as that flavor, in order, and render the ones that differ.
        let mut planned: Vec<(usize, Planned)> = Vec::new();
        let mut resolv_cursor = 0usize;
        let mut resolved_cursor = 0usize;
        let mut unbound_cursor = 0usize;
        let mut leftover: Vec<String> = Vec::new();
        for (line_index, entry) in doc
            .lines()
            .iter()
            .enumerate()
            .filter(|(_, line)| line.kind() == LineKind::Directive)
            .filter_map(|(index, line)| parse_entry(line.raw()).map(|entry| (index, entry)))
        {
            let action = match &entry {
                Entry::Resolv(entry) => {
                    plan_slot(&model.resolv, &mut resolv_cursor, entry, render_resolv)?
                }
                Entry::Resolved(entry) => plan_slot(
                    &model.resolved,
                    &mut resolved_cursor,
                    entry,
                    render_resolved,
                )?,
                Entry::Unbound(entry) => {
                    plan_slot(&model.unbound, &mut unbound_cursor, entry, render_unbound)?
                }
            };
            planned.push((line_index, action));
        }
        for wanted in model.resolv.iter().skip(resolv_cursor) {
            leftover.push(render_resolv(wanted)?);
        }
        for wanted in model.resolved.iter().skip(resolved_cursor) {
            leftover.push(render_resolved(wanted)?);
        }
        for wanted in model.unbound.iter().skip(unbound_cursor) {
            leftover.push(render_unbound(wanted)?);
        }

        // Pass 2: rewrite and drop, highest line index first so removals do not
        // shift the indices still to be edited.
        let mut report = EditReport::default();
        for (line_index, action) in planned.into_iter().rev() {
            match action {
                Planned::Keep => {}
                Planned::Replace(raw) => {
                    doc.replace_raw(line_index, raw.as_str())?;
                    report.changed_lines = report.changed_lines.saturating_add(1);
                }
                Planned::Drop => {
                    doc.remove_line(line_index)?;
                    report.removed = report.removed.saturating_add(1);
                }
            }
        }

        // New lines go after the last remaining directive line, not at the end
        // of the file, so a trailing comment block stays trailing.
        let mut at = doc
            .lines()
            .iter()
            .rposition(|line| line.kind() == LineKind::Directive)
            .map_or_else(|| doc.len(), |index| index.saturating_add(1));
        for raw in leftover {
            doc.insert_line(at, raw.as_str())?;
            at = at.saturating_add(1);
            report.added = report.added.saturating_add(1);
        }
        Ok(report)
    }

    /// Findings carry Fluent ids, never rendered sentences (ADR-003), a field
    /// path so the UI can point at the control, and named arguments so
    /// translators can reorder them. `ctx` makes the backend findings
    /// host-aware: settings for a backend that is not detected on this host
    /// are flagged rather than applied silently.
    fn validate(model: &Self::Model, ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        validate_resolv(&model.resolv, &mut diagnostics);
        validate_resolved(&model.resolved, &mut diagnostics);
        validate_unbound(&model.unbound, &mut diagnostics);
        if model.resolv.is_empty() && model.resolved.is_empty() && model.unbound.is_empty() {
            diagnostics.push(
                Diagnostic::new(Severity::Warning, NO_NAMESERVER)
                    .with_field(FieldPath::new("resolv")),
            );
            diagnostics.push(
                Diagnostic::new(Severity::Warning, NO_CONFIG).with_field(FieldPath::new("resolv")),
            );
        }
        if !model.resolved.is_empty() && ctx.profile.service_version(SERVICE_RESOLVED).is_none() {
            diagnostics.push(
                Diagnostic::new(Severity::Warning, BACKEND_MISSING)
                    .with_field(FieldPath::new("resolved"))
                    .with_arg("service", SERVICE_RESOLVED),
            );
        }
        if !model.unbound.is_empty() && !unbound_backend_detect(ctx.profile) {
            diagnostics.push(
                Diagnostic::new(Severity::Warning, BACKEND_MISSING)
                    .with_field(FieldPath::new("unbound"))
                    .with_arg("service", SERVICE_UNBOUND),
            );
        }
        diagnostics
    }

    /// Smart, secure defaults for this host: the managing backend's config
    /// when one is detected, the static file otherwise. `Os` is matched
    /// exhaustively so a new platform tier is a compile error here.
    fn defaults(profile: &HostProfile) -> Self::Model {
        match profile.os {
            Os::Linux => {
                if resolved_backend_detect(profile) {
                    resolved_defaults()
                } else if unbound_backend_detect(profile) {
                    unbound_defaults()
                } else {
                    resolv_defaults()
                }
            }
            Os::MacOs | Os::Other => resolv_defaults(),
        }
    }

    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

/// One planned edit to a directive line.
#[derive(Debug, PartialEq, Eq)]
enum Planned {
    /// The line already parses to the model's entry: leave it byte-identical.
    Keep,
    /// Re-render the line canonically.
    Replace(String),
    /// The model has no entry for this line: remove it.
    Drop,
}

/// Decides the edit for one directive line against its flavor's next model
/// entry, advancing `cursor` past whichever entry was consumed.
///
/// # Errors
///
/// [`EditError`] from the flavor's renderer, before any document edit happens.
fn plan_slot<T: PartialEq>(
    slots: &[T],
    cursor: &mut usize,
    parsed: &T,
    render: fn(&T) -> Result<String, EditError>,
) -> Result<Planned, EditError> {
    let Some(wanted) = slots.get(*cursor) else {
        return Ok(Planned::Drop);
    };
    *cursor = cursor.saturating_add(1);
    if wanted == parsed {
        return Ok(Planned::Keep);
    }
    Ok(Planned::Replace(render(wanted)?))
}

#[cfg(test)]
mod tests {
    use super::{
        BACKEND_MISSING, DUPLICATE_NAMESERVER, DnsServer, FORWARD_TLS_NO_AUTH,
        FORWARD_ZONE_UNNAMED, INVALID_DOMAIN, INVALID_FORWARD_ADDR, INVALID_FORWARD_NAME,
        KNOWN_HARDENING, NO_CONFIG, NO_NAMESERVER, REC_DNSSEC, REC_DOT, REC_HARDENING,
        RECOMMENDED_HARDENING, RESOLVER_DESCRIPTOR, ResolvEntry, ResolvedDnsOverTls,
        ResolvedDnsSec, ResolverModule, SEARCH_AND_DOMAIN, SERVICE_NM, SERVICE_RESOLVED,
        SERVICE_UNBOUND, TOO_MANY_NAMESERVERS, UNBOUND_MISPLACED, UNKNOWN_HARDENING,
        UNKNOWN_OPTION, UPSTREAM_TOML, UnboundEntry, classify, is_valid_domain,
        is_valid_forward_addr, is_valid_option, parse_entry, parse_resolv, parse_resolved,
        parse_unbound, render_resolv, render_resolved, render_unbound, resolv_backend_detect,
        strip_quotes,
    };
    use super::{Entry, Model, Planned, ResolvedEntry, plan_slot};
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{Diagnostics, MessageId};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    /// Parses an address literal, or the unspecified address when a test's
    /// literal is malformed, so the assertion that uses it fails instead of
    /// panicking.
    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    /// An empty host profile: Linux, systemd, no service versions detected.
    fn profile() -> HostProfile {
        profile_versions(&[])
    }

    /// A host profile with service versions probed.
    fn profile_versions(versions: &[(&str, &str)]) -> HostProfile {
        let mut service_versions = BTreeMap::new();
        for (service, version) in versions {
            service_versions.insert((*service).to_owned(), (*version).to_owned());
        }
        HostProfile {
            os: Os::Linux,
            init: InitSystem::Systemd,
            hostname: "detent-test".to_owned(),
            service_versions,
            ram_mib: 1024,
        }
    }

    fn ctx(p: &HostProfile) -> ValidationCtx<'_> {
        ValidationCtx { profile: p }
    }

    fn m(
        resolv: Vec<ResolvEntry>,
        resolved: Vec<ResolvedEntry>,
        unbound: Vec<UnboundEntry>,
    ) -> Model {
        Model {
            resolv,
            resolved,
            unbound,
        }
    }

    fn name(ip: &str, name: Option<&str>) -> DnsServer {
        DnsServer {
            ip: ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            name: name.map(str::to_owned),
        }
    }

    /// Whether `diagnostics` carries a finding with `id`.
    fn has(diagnostics: &Diagnostics, id: MessageId) -> bool {
        diagnostics.iter().any(|d| d.id == id)
    }

    /// A model with one resolv.conf entry.
    fn one_resolv(resolv: ResolvEntry) -> Model {
        m(vec![resolv], Vec::new(), Vec::new())
    }

    // -------------------------------------------------------------- parse tests

    #[test]
    fn parse_resolv_reads_nameservers() {
        assert_eq!(
            parse_resolv("nameserver 192.0.2.1"),
            Some(ResolvEntry::Nameserver {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            })
        );
        assert_eq!(
            parse_resolv("  nameserver\t2001:db8::1  "),
            Some(ResolvEntry::Nameserver {
                ip: ip("2001:db8::1")
            })
        );
        assert_eq!(
            parse_resolv("nameserver 192.0.2.1 192.0.2.2"),
            None,
            "two addresses on one line is not glibc's format"
        );
        assert_eq!(parse_resolv("nameserver not-an-ip"), None);
        assert_eq!(
            parse_resolv("nameserver 192.0.2.1 # note"),
            None,
            "glibc supports no inline comments"
        );
    }

    #[test]
    fn parse_resolv_reads_search_domain_options() {
        assert_eq!(
            parse_resolv("search example.com corp.example.com"),
            Some(ResolvEntry::Search {
                domains: vec!["example.com".to_owned(), "corp.example.com".to_owned()]
            })
        );
        assert_eq!(
            parse_resolv("domain example.com"),
            Some(ResolvEntry::Domain {
                domain: "example.com".to_owned()
            })
        );
        assert_eq!(
            parse_resolv("options ndots:2 edns0"),
            Some(ResolvEntry::Options {
                options: vec!["ndots:2".to_owned(), "edns0".to_owned()]
            })
        );
        assert_eq!(parse_resolv("search"), None);
        assert_eq!(parse_resolv("options"), None);
        assert_eq!(parse_resolv("domain"), None);
        assert_eq!(
            parse_resolv("domain example.com extra"),
            None,
            "domain takes exactly one token"
        );
        assert_eq!(parse_resolv("sortlist 130.155.160.0/24"), None);
        assert_eq!(parse_resolv("lookup file bind"), None);
        assert_eq!(parse_resolv("nameserverx 192.0.2.1"), None);
    }

    #[test]
    fn parse_resolved_reads_the_modeled_subset() {
        assert_eq!(parse_resolved("[Resolve]"), Some(ResolvedEntry::Resolve));
        assert_eq!(
            parse_resolved(" DNSSEC = allow-downgrade "),
            Some(ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::AllowDowngrade
            }),
            "spacing around `=` is cosmetic"
        );
        assert_eq!(
            parse_resolved("DNSOverTLS=opportunistic"),
            Some(ResolvedEntry::DnsOverTls {
                mode: ResolvedDnsOverTls::Opportunistic
            })
        );
        assert_eq!(
            parse_resolved("Domains=example.com ~corp.example.com"),
            Some(ResolvedEntry::Domains {
                domains: vec!["example.com".to_owned(), "~corp.example.com".to_owned()]
            })
        );
        assert_eq!(
            parse_resolved("DNS=1.1.1.1 9.9.9.9#dns.quad9.net"),
            Some(ResolvedEntry::Dns {
                servers: vec![
                    name("1.1.1.1", None),
                    name("9.9.9.9", Some("dns.quad9.net"))
                ]
            })
        );
        assert_eq!(
            parse_resolved("DNS="),
            Some(ResolvedEntry::Dns {
                servers: Vec::new()
            }),
            "an empty value is the empty list, not a refusal"
        );
    }

    #[test]
    fn parse_resolved_rejects_bad_values_and_unmodeled_keys() {
        assert_eq!(parse_resolved("DNSSEC=strict"), None);
        assert_eq!(parse_resolved("DNSOverTLS=require"), None);
        assert_eq!(parse_resolved("DNS=192.0.2.1:53"), None, "no port syntax");
        assert_eq!(parse_resolved("DNS=192.0.2.1#"), None, "empty auth name");
        assert_eq!(parse_resolved("DNS=not-an-ip"), None);
        assert_eq!(parse_resolved("Cache=yes"), None, "unmodeled key");
        assert_eq!(parse_resolved("[Network]"), None);
        assert_eq!(parse_resolved("DNS"), None, "no value separator");
    }

    #[test]
    fn parse_unbound_reads_sections_and_known_keys() {
        assert_eq!(parse_unbound("server:"), Some(UnboundEntry::Server));
        assert_eq!(
            parse_unbound("forward-zone:"),
            Some(UnboundEntry::ForwardZone)
        );
        assert_eq!(
            parse_unbound("    qname-minimisation: yes"),
            Some(UnboundEntry::Hardening {
                key: "qname-minimisation".to_owned(),
                enabled: true
            }),
            "indentation is cosmetic"
        );
        assert_eq!(
            parse_unbound("harden-dnssec-stripped: no"),
            Some(UnboundEntry::Hardening {
                key: "harden-dnssec-stripped".to_owned(),
                enabled: false
            })
        );
        assert_eq!(
            parse_unbound("    name: \".\""),
            Some(UnboundEntry::ForwardName {
                name: ".".to_owned()
            }),
            "quotes are stripped in the model"
        );
        assert_eq!(
            parse_unbound("    name: example.com"),
            Some(UnboundEntry::ForwardName {
                name: "example.com".to_owned()
            })
        );
        assert_eq!(
            parse_unbound("    forward-addr: 9.9.9.9@853#dns.quad9.net"),
            Some(UnboundEntry::ForwardAddr {
                addr: "9.9.9.9@853#dns.quad9.net".to_owned()
            })
        );
        assert_eq!(
            parse_unbound("    forward-tls-upstream: yes"),
            Some(UnboundEntry::ForwardTls { enabled: true })
        );
        assert_eq!(
            parse_unbound("    forward-tls-upstream: no"),
            Some(UnboundEntry::ForwardTls { enabled: false })
        );
    }

    #[test]
    fn parse_unbound_rejects_unmodeled_and_malformed() {
        assert_eq!(parse_unbound("    rrset-cache-size: 100m"), None);
        assert_eq!(parse_unbound("    do-tcp: \"yes\""), None, "not yes/no");
        assert_eq!(
            parse_unbound("    auto-trust-anchor-file: \"/var/lib/key\""),
            None
        );
        assert_eq!(parse_unbound("stub-zone:"), None);
        assert_eq!(parse_unbound("no-colon-here"), None);
        assert_eq!(parse_unbound("    hide-identity:"), None, "empty value");
    }

    #[test]
    fn parse_entry_dispatches_across_flavors() {
        assert_eq!(
            parse_entry("nameserver 192.0.2.1"),
            Some(Entry::Resolv(ResolvEntry::Nameserver {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            }))
        );
        assert_eq!(
            parse_entry("[Resolve]"),
            Some(Entry::Resolved(ResolvedEntry::Resolve))
        );
        assert_eq!(
            parse_entry("server:"),
            Some(Entry::Unbound(UnboundEntry::Server))
        );
        assert_eq!(parse_entry("Cache=yes"), None);
    }

    #[test]
    fn classify_buckets_the_three_flavors() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("   \t "), LineKind::Blank);
        assert_eq!(classify("# comment"), LineKind::Comment);
        assert_eq!(classify("; resolv.conf comment"), LineKind::Comment);
        assert_eq!(classify("nameserver 192.0.2.1"), LineKind::Directive);
        assert_eq!(classify("[Resolve]"), LineKind::Directive);
        assert_eq!(classify("server:"), LineKind::Directive);
        assert_eq!(classify("    name: \".\""), LineKind::Directive);
        assert_eq!(classify("sortlist 130.155.0.0/24"), LineKind::Unknown);
        assert_eq!(classify("Cache=yes"), LineKind::Unknown);
        assert_eq!(classify("nameserver 999.1.2.3"), LineKind::Unknown);
    }

    // ------------------------------------------------------------ render tests

    #[test]
    fn render_resolv_is_canonical() -> Result<(), String> {
        assert_eq!(
            render_resolv(&ResolvEntry::Nameserver {
                ip: ip("192.0.2.53")
            })
            .map_err(|e| e.to_string())?,
            "nameserver 192.0.2.53"
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Search {
                domains: vec!["example.com".to_owned()]
            })
            .map_err(|e| e.to_string())?,
            "search example.com"
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Domain {
                domain: "example.com".to_owned()
            })
            .map_err(|e| e.to_string())?,
            "domain example.com"
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Options {
                options: vec!["ndots:2".to_owned()]
            })
            .map_err(|e| e.to_string())?,
            "options ndots:2"
        );

        Ok(())
    }

    #[test]
    fn render_resolved_is_canonical() -> Result<(), String> {
        assert_eq!(
            render_resolved(&ResolvedEntry::Resolve).map_err(|e| e.to_string())?,
            "[Resolve]"
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::Dns {
                servers: vec![name("9.9.9.9", Some("dns.quad9.net"))]
            })
            .map_err(|e| e.to_string())?,
            "DNS=9.9.9.9#dns.quad9.net"
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::AllowDowngrade
            })
            .map_err(|e| e.to_string())?,
            "DNSSEC=allow-downgrade"
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::DnsOverTls {
                mode: ResolvedDnsOverTls::Opportunistic
            })
            .map_err(|e| e.to_string())?,
            "DNSOverTLS=opportunistic"
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::Domains {
                domains: vec!["~.".to_owned()]
            })
            .map_err(|e| e.to_string())?,
            "Domains=~."
        );

        Ok(())
    }

    #[test]
    fn render_unbound_is_canonical() -> Result<(), String> {
        assert_eq!(
            render_unbound(&UnboundEntry::Server).map_err(|e| e.to_string())?,
            "server:"
        );
        assert_eq!(
            render_unbound(&UnboundEntry::ForwardZone).map_err(|e| e.to_string())?,
            "forward-zone:"
        );
        assert_eq!(
            render_unbound(&UnboundEntry::Hardening {
                key: "aggressive-nsec".to_owned(),
                enabled: true
            })
            .map_err(|e| e.to_string())?,
            "    aggressive-nsec: yes"
        );
        assert_eq!(
            render_unbound(&UnboundEntry::ForwardName {
                name: ".".to_owned()
            })
            .map_err(|e| e.to_string())?,
            "    name: ."
        );
        assert_eq!(
            render_unbound(&UnboundEntry::ForwardAddr {
                addr: "9.9.9.9@853#dns.quad9.net".to_owned()
            })
            .map_err(|e| e.to_string())?,
            "    forward-addr: 9.9.9.9@853#dns.quad9.net"
        );
        assert_eq!(
            render_unbound(&UnboundEntry::ForwardTls { enabled: true })
                .map_err(|e| e.to_string())?,
            "    forward-tls-upstream: yes"
        );

        Ok(())
    }

    #[test]
    fn render_refuses_injection() {
        assert_eq!(
            render_resolv(&ResolvEntry::Search {
                domains: vec!["a\nnameserver 10.0.0.1".to_owned()]
            }),
            Err(EditError::LineBreakInValue {
                value: "search a\nnameserver 10.0.0.1".to_owned()
            }),
            "newline in a token is rejected, never written"
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Search {
                domains: vec!["a\rb".to_owned()]
            }),
            Err(EditError::LineBreakInValue {
                value: "search a\rb".to_owned()
            })
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Domain {
                domain: "a\0b".to_owned()
            }),
            Err(EditError::LineBreakInValue {
                value: "domain a\0b".to_owned()
            })
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::Domains {
                domains: vec!["a\nb".to_owned()]
            }),
            Err(EditError::LineBreakInValue {
                value: "Domains=a\nb".to_owned()
            })
        );
        assert_eq!(
            render_unbound(&UnboundEntry::ForwardName {
                name: "a\nb".to_owned()
            }),
            Err(EditError::LineBreakInValue {
                value: "    name: a\nb".to_owned()
            })
        );
    }

    #[test]
    fn render_refuses_non_round_trippable_input() {
        assert_eq!(
            render_resolv(&ResolvEntry::Search {
                domains: Vec::new()
            }),
            Err(EditError::Unsupported {
                message: "entry does not round-trip through the file format: \"search \""
                    .to_owned()
            }),
            "an empty list would silently mean something else"
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Options {
                options: Vec::new()
            }),
            Err(EditError::Unsupported {
                message: "entry does not round-trip through the file format: \"options \""
                    .to_owned()
            })
        );
        assert_eq!(
            render_resolv(&ResolvEntry::Domain {
                domain: " a ".to_owned()
            }),
            Err(EditError::Unsupported {
                message: "entry does not round-trip through the file format: \"domain  a \""
                    .to_owned()
            }),
            "untrimmed tokens are refused, not silently normalized"
        );
        assert_eq!(
            render_resolved(&ResolvedEntry::Domains {
                domains: Vec::new()
            }),
            Err(EditError::Unsupported {
                message: "entry does not round-trip through the file format: \"Domains=\""
                    .to_owned()
            })
        );
        assert_eq!(
            render_unbound(&UnboundEntry::Hardening {
                key: "not-a-modeled-key".to_owned(),
                enabled: true
            }),
            Err(EditError::Unsupported {
                message: "entry does not round-trip through the file format: \"    not-a-modeled-key: yes\"".to_owned()
            })
        );
    }

    #[test]
    fn strip_quotes_trims_quotes_and_spaces() {
        assert_eq!(strip_quotes("\"value\""), "value");
        assert_eq!(strip_quotes("value"), "value");
        assert_eq!(strip_quotes("\" spaced \""), "spaced");
    }

    // ---------------------------------------------------------------- model

    #[test]
    fn to_model_walks_all_three_flavors() -> Result<(), String> {
        let src = concat!(
            "# /etc/resolv.conf\n",
            "nameserver 192.0.2.1\n",
            "search example.com\n",
            "[Resolve]\n",
            "DNSSEC=no\n",
            "server:\n",
            "    aggressive-nsec: yes\n",
            "# trailing comment\n"
        );
        let doc = ResolverModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(
            ResolverModule::to_model(&doc).map_err(|e| e.to_string())?,
            m(
                vec![
                    ResolvEntry::Nameserver {
                        ip: ip("192.0.2.1")
                    },
                    ResolvEntry::Search {
                        domains: vec!["example.com".to_owned()]
                    },
                ],
                vec![
                    ResolvedEntry::Resolve,
                    ResolvedEntry::DnsSec {
                        mode: ResolvedDnsSec::No
                    },
                ],
                vec![
                    UnboundEntry::Server,
                    UnboundEntry::Hardening {
                        key: "aggressive-nsec".to_owned(),
                        enabled: true
                    },
                ],
            ),
            "each directive lands in its flavor's vec"
        );

        Ok(())
    }

    // ------------------------------------------------------------ plan / apply

    #[test]
    fn plan_slot_walks_slots_in_order() -> Result<(), String> {
        let slots = vec![
            ResolvEntry::Nameserver {
                ip: ip("192.0.2.1"),
            },
            ResolvEntry::Domain {
                domain: "example.com".to_owned(),
            },
        ];
        let mut cursor = 0usize;
        let parsed = ResolvEntry::Nameserver {
            ip: ip("192.0.2.1"),
        };
        assert_eq!(
            plan_slot(&slots, &mut cursor, &parsed, render_resolv).map_err(|e| e.to_string())?,
            Planned::Keep,
            "equal entries are never re-rendered"
        );
        assert_eq!(cursor, 1);
        assert_eq!(
            plan_slot(&slots, &mut cursor, &parsed, render_resolv).map_err(|e| e.to_string())?,
            Planned::Replace("domain example.com".to_owned()),
            "the next slot in order pairs with the next directive line"
        );
        assert_eq!(cursor, 2);
        assert_eq!(
            plan_slot(&slots, &mut cursor, &parsed, render_resolv).map_err(|e| e.to_string())?,
            Planned::Drop,
            "exhausted model drops surplus lines"
        );

        Ok(())
    }

    #[test]
    fn plan_slot_refuses_before_touching_the_document() {
        let slots = vec![ResolvEntry::Search {
            domains: vec!["a\nb".to_owned()],
        }];
        let mut cursor = 0usize;
        let parsed = ResolvEntry::Domain {
            domain: "example.com".to_owned(),
        };
        assert_eq!(
            plan_slot(&slots, &mut cursor, &parsed, render_resolv),
            Err(EditError::LineBreakInValue {
                value: "search a\nb".to_owned()
            }),
            "pass 1 is read-only: a refused value leaves the file untouched"
        );
        assert_eq!(cursor, 1, "the slot is consumed by the refusal");
    }

    #[test]
    fn apply_is_a_noop_on_a_fresh_copy() -> Result<(), String> {
        let src = concat!(
            "# /etc/resolv.conf\n",
            "nameserver 192.0.2.1\n",
            "\n",
            "; a comment\n",
            "search example.com\n",
            "sortlist 130.155.160.0/24\n"
        );
        let mut doc = ResolverModule::parse(src).map_err(|e| e.to_string())?;
        let model = ResolverModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = ResolverModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default(), "nothing changes");
        assert_eq!(
            ResolverModule::render(&doc),
            src,
            "unknown lines and comments survive byte for byte"
        );

        Ok(())
    }

    #[test]
    fn apply_rewrites_changed_lines_only() -> Result<(), String> {
        let src = concat!(
            "# /etc/resolv.conf\n",
            "nameserver 192.0.2.1\n",
            "domain example.com\n"
        );
        let mut doc = ResolverModule::parse(src).map_err(|e| e.to_string())?;
        let wanted = m(
            vec![
                ResolvEntry::Nameserver {
                    ip: ip("192.0.2.53"),
                },
                ResolvEntry::Domain {
                    domain: "example.com".to_owned(),
                },
            ],
            Vec::new(),
            Vec::new(),
        );
        let report = ResolverModule::apply(&mut doc, &wanted).map_err(|e| e.to_string())?;
        assert_eq!(
            report.changed_lines, 1,
            "only the changed line is rewritten"
        );
        assert_eq!(
            ResolverModule::render(&doc),
            "# /etc/resolv.conf\nnameserver 192.0.2.53\ndomain example.com\n"
        );

        Ok(())
    }

    #[test]
    fn apply_removes_and_appends() -> Result<(), String> {
        let mut doc = ResolverModule::parse("nameserver 192.0.2.1\n").map_err(|e| e.to_string())?;
        let wanted = m(
            vec![
                ResolvEntry::Nameserver {
                    ip: ip("192.0.2.53"),
                },
                ResolvEntry::Options {
                    options: vec!["edns0".to_owned()],
                },
            ],
            Vec::new(),
            Vec::new(),
        );
        let report = ResolverModule::apply(&mut doc, &wanted).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 1);
        assert_eq!(
            ResolverModule::render(&doc),
            "nameserver 192.0.2.53\noptions edns0\n"
        );

        // And the inverse: a model with fewer entries drops the surplus line.
        let mut doc = ResolverModule::parse("nameserver 192.0.2.1\noptions edns0\n")
            .map_err(|e| e.to_string())?;
        let wanted = m(
            vec![ResolvEntry::Nameserver {
                ip: ip("192.0.2.1"),
            }],
            Vec::new(),
            Vec::new(),
        );
        let report = ResolverModule::apply(&mut doc, &wanted).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(ResolverModule::render(&doc), "nameserver 192.0.2.1\n");

        Ok(())
    }

    #[test]
    fn apply_on_an_empty_document_appends_everything() -> Result<(), String> {
        let mut doc = ResolverModule::parse("# empty\n").map_err(|e| e.to_string())?;
        let wanted = m(
            vec![ResolvEntry::Nameserver {
                ip: ip("192.0.2.1"),
            }],
            Vec::new(),
            Vec::new(),
        );
        let report = ResolverModule::apply(&mut doc, &wanted).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            ResolverModule::render(&doc),
            "# empty\nnameserver 192.0.2.1\n"
        );

        Ok(())
    }

    #[test]
    fn apply_edits_all_three_flavors_in_one_document() -> Result<(), String> {
        let src = concat!(
            "[Resolve]\n",
            "DNSSEC=no\n",
            "nameserver 192.0.2.1\n",
            "server:\n",
            "    aggressive-nsec: no\n"
        );
        let mut doc = ResolverModule::parse(src).map_err(|e| e.to_string())?;
        let wanted = m(
            vec![ResolvEntry::Nameserver {
                ip: ip("192.0.2.53"),
            }],
            vec![ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::Yes,
            }],
            vec![
                UnboundEntry::Server,
                UnboundEntry::Hardening {
                    key: "aggressive-nsec".to_owned(),
                    enabled: true,
                },
            ],
        );
        let report = ResolverModule::apply(&mut doc, &wanted).map_err(|e| e.to_string())?;
        assert_eq!(
            report.changed_lines, 3,
            "the section headers keep their place, the settings change"
        );
        let reparsed =
            ResolverModule::parse(&ResolverModule::render(&doc)).map_err(|e| e.to_string())?;
        assert_eq!(
            ResolverModule::to_model(&reparsed).map_err(|e| e.to_string())?,
            wanted,
            "invariant 3: the model survives the edit"
        );

        Ok(())
    }

    #[test]
    fn apply_refuses_injection_before_touching_the_document() -> Result<(), String> {
        let mut doc = ResolverModule::parse("nameserver 192.0.2.1\n").map_err(|e| e.to_string())?;
        let wanted = m(
            vec![ResolvEntry::Search {
                domains: vec!["a\nnameserver 10.0.0.1".to_owned()],
            }],
            Vec::new(),
            Vec::new(),
        );
        let result = ResolverModule::apply(&mut doc, &wanted);
        assert!(result.is_err(), "invariant 5: the value is refused");
        assert_eq!(
            ResolverModule::render(&doc),
            "nameserver 192.0.2.1\n",
            "a refused edit leaves the document exactly as it was"
        );

        Ok(())
    }

    // ------------------------------------------------------------- validation

    #[test]
    fn empty_model_gets_the_no_nameserver_warning() {
        let diagnostics = ResolverModule::validate(&Model::default(), &ctx(&profile()));
        assert!(has(&diagnostics, NO_NAMESERVER));
        assert!(has(&diagnostics, NO_CONFIG));
        assert!(!diagnostics.has_errors());
    }

    #[test]
    fn a_fresh_copy_validates_without_findings() -> Result<(), String> {
        let model = ResolverModule::to_model(
            &ResolverModule::parse("nameserver 192.0.2.1\nsearch example.com\noptions ndots:2\n")
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert_eq!(diagnostics, Diagnostics::new());

        Ok(())
    }

    #[test]
    fn duplicate_and_excess_nameservers_are_flagged() {
        let model = one_resolv(ResolvEntry::Nameserver {
            ip: ip("192.0.2.1"),
        });
        let mut with_dup = model.clone();
        with_dup.resolv.push(ResolvEntry::Nameserver {
            ip: ip("192.0.2.1"),
        });
        let diagnostics = ResolverModule::validate(&with_dup, &ctx(&profile()));
        assert!(has(&diagnostics, DUPLICATE_NAMESERVER));

        let mut four = model;
        for last in [2u8, 3, 4] {
            four.resolv.push(ResolvEntry::Nameserver {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            });
        }
        let diagnostics = ResolverModule::validate(&four, &ctx(&profile()));
        assert!(has(&diagnostics, TOO_MANY_NAMESERVERS));
    }

    #[test]
    fn bad_domains_and_options_are_flagged() {
        let model = one_resolv(ResolvEntry::Search {
            domains: vec!["-bad.label-".to_owned()],
        });
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert!(has(&diagnostics, INVALID_DOMAIN));

        let model = one_resolv(ResolvEntry::Options {
            options: vec!["bogus option".to_owned()],
        });
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert!(has(&diagnostics, UNKNOWN_OPTION));
        assert!(!diagnostics.has_errors(), "options are tolerated by glibc");
    }

    #[test]
    fn resolved_server_names_and_domains_are_checked() {
        let model = m(
            Vec::new(),
            vec![
                ResolvedEntry::Dns {
                    servers: vec![
                        DnsServer {
                            ip: ip("192.0.2.1"),
                            name: Some("bad..domain".to_owned()),
                        },
                        DnsServer {
                            ip: ip("9.9.9.9"),
                            name: Some(String::new()),
                        },
                    ],
                },
                ResolvedEntry::FallbackDns {
                    servers: vec![DnsServer {
                        ip: ip("8.8.8.8"),
                        name: Some("-bad-".to_owned()),
                    }],
                },
                ResolvedEntry::Domains {
                    domains: vec!["-bad".to_owned()],
                },
            ],
            Vec::new(),
        );
        let profile = profile_versions(&[(SERVICE_RESOLVED, "257")]);
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile));
        assert!(has(&diagnostics, INVALID_DOMAIN));
        assert!(diagnostics.has_errors());
    }

    #[test]
    fn search_and_domain_conflict_is_flagged() {
        let model = m(
            vec![
                ResolvEntry::Search {
                    domains: vec!["example.com".to_owned()],
                },
                ResolvEntry::Domain {
                    domain: "corp.example.com".to_owned(),
                },
            ],
            Vec::new(),
            Vec::new(),
        );
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert!(has(&diagnostics, SEARCH_AND_DOMAIN));
    }

    #[test]
    fn resolved_recommendations_fire() {
        let diagnostics = ResolverModule::validate(
            &m(
                Vec::new(),
                vec![
                    ResolvedEntry::Resolve,
                    ResolvedEntry::DnsSec {
                        mode: ResolvedDnsSec::AllowDowngrade,
                    },
                    ResolvedEntry::DnsOverTls {
                        mode: ResolvedDnsOverTls::Opportunistic,
                    },
                ],
                Vec::new(),
            ),
            &ctx(&profile_versions(&[(SERVICE_RESOLVED, "257")])),
        );
        assert!(has(&diagnostics, REC_DNSSEC));
        assert!(has(&diagnostics, REC_DOT));
        assert!(!has(&diagnostics, BACKEND_MISSING));
        assert!(!diagnostics.has_errors());
    }

    #[test]
    fn settings_for_an_undetected_backend_are_flagged() {
        let diagnostics = ResolverModule::validate(
            &m(Vec::new(), vec![ResolvedEntry::Resolve], Vec::new()),
            &ctx(&profile()),
        );
        assert!(has(&diagnostics, BACKEND_MISSING));
        assert_eq!(
            diagnostics
                .iter()
                .find(|d| d.id == BACKEND_MISSING)
                .and_then(|d| d.args.get("service"))
                .map(String::as_str),
            Some(SERVICE_RESOLVED)
        );

        let diagnostics = ResolverModule::validate(
            &m(Vec::new(), Vec::new(), vec![UnboundEntry::Server]),
            &ctx(&profile()),
        );
        assert!(has(&diagnostics, BACKEND_MISSING));
        assert_eq!(
            diagnostics
                .iter()
                .find(|d| d.id == BACKEND_MISSING)
                .and_then(|d| d.args.get("service"))
                .map(String::as_str),
            Some(SERVICE_UNBOUND)
        );
    }

    #[test]
    fn networkmanager_takes_resolv_conf_with_resolved() {
        let p = profile_versions(&[(SERVICE_NM, "1.48")]);
        assert!(!resolv_backend_detect(&p));
        let p = profile_versions(&[(SERVICE_RESOLVED, "257")]);
        assert!(!resolv_backend_detect(&p));
        assert!(resolv_backend_detect(&profile()));
    }

    #[test]
    fn unbound_hardening_findings_fire() {
        // A known key in server: is silent.
        let clean = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::Hardening {
                    key: "qname-minimisation".to_owned(),
                    enabled: true,
                },
            ],
        );
        let diagnostics = ResolverModule::validate(
            &clean,
            &ctx(&profile_versions(&[(SERVICE_UNBOUND, "1.20")])),
        );
        assert_eq!(diagnostics, Diagnostics::new());

        // An unknown key is an error.
        let unknown = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::Hardening {
                    key: "made-up-key".to_owned(),
                    enabled: true,
                },
            ],
        );
        let diagnostics = ResolverModule::validate(&unknown, &ctx(&profile()));
        assert!(has(&diagnostics, UNKNOWN_HARDENING));
        assert!(diagnostics.has_errors());

        // A server item outside server: is misplaced.
        let misplaced = m(
            Vec::new(),
            Vec::new(),
            vec![UnboundEntry::Hardening {
                key: "qname-minimisation".to_owned(),
                enabled: true,
            }],
        );
        let diagnostics = ResolverModule::validate(&misplaced, &ctx(&profile()));
        assert!(has(&diagnostics, UNBOUND_MISPLACED));

        // A recommended key explicitly disabled is a recommendation.
        let disabled = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::Hardening {
                    key: "aggressive-nsec".to_owned(),
                    enabled: false,
                },
            ],
        );
        let diagnostics = ResolverModule::validate(&disabled, &ctx(&profile()));
        assert!(has(&diagnostics, REC_HARDENING));
        assert!(
            !has(&diagnostics, UNKNOWN_HARDENING),
            "aggressive-nsec is a modeled key"
        );
    }

    #[test]
    fn unbound_forward_zones_are_checked() {
        // Named zone, TLS with auth: silent.
        let good = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::ForwardZone,
                UnboundEntry::ForwardName {
                    name: ".".to_owned(),
                },
                UnboundEntry::ForwardTls { enabled: true },
                UnboundEntry::ForwardAddr {
                    addr: "9.9.9.9@853#dns.quad9.net".to_owned(),
                },
            ],
        );
        let diagnostics =
            ResolverModule::validate(&good, &ctx(&profile_versions(&[(SERVICE_UNBOUND, "1.20")])));
        assert_eq!(diagnostics, Diagnostics::new());

        // An unnamed zone, terminated by another section.
        let unnamed = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::ForwardZone,
                UnboundEntry::ForwardAddr {
                    addr: "192.0.2.1".to_owned(),
                },
                UnboundEntry::Server,
            ],
        );
        let diagnostics = ResolverModule::validate(&unnamed, &ctx(&profile()));
        assert!(has(&diagnostics, FORWARD_ZONE_UNNAMED));
        assert!(diagnostics.has_errors());

        // A trailing unnamed zone.
        let trailing = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::Server,
                UnboundEntry::ForwardZone,
                UnboundEntry::ForwardName {
                    name: "example.com".to_owned(),
                },
                UnboundEntry::ForwardZone,
            ],
        );
        let diagnostics = ResolverModule::validate(&trailing, &ctx(&profile()));
        assert!(has(&diagnostics, FORWARD_ZONE_UNNAMED));

        // TLS without an auth name, plus a bad addr and a bad zone name.
        let no_auth = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::ForwardZone,
                UnboundEntry::ForwardName {
                    name: "-bad.zone-".to_owned(),
                },
                UnboundEntry::ForwardTls { enabled: true },
                UnboundEntry::ForwardAddr {
                    addr: "192.0.2.1:53".to_owned(),
                },
            ],
        );
        let diagnostics = ResolverModule::validate(&no_auth, &ctx(&profile()));
        assert!(has(&diagnostics, FORWARD_TLS_NO_AUTH));
        assert!(has(&diagnostics, INVALID_FORWARD_NAME));
        assert!(has(&diagnostics, INVALID_FORWARD_ADDR));
        assert!(
            diagnostics.has_errors(),
            "a bad name and a bad addr are errors"
        );
    }

    #[test]
    fn forward_items_outside_a_zone_are_misplaced() {
        let model = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::ForwardName {
                    name: ".".to_owned(),
                },
                UnboundEntry::ForwardAddr {
                    addr: "192.0.2.1".to_owned(),
                },
                UnboundEntry::ForwardTls { enabled: true },
            ],
        );
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.id == UNBOUND_MISPLACED)
                .count(),
            3,
            "each forward item outside a zone is misplaced"
        );
        // valid misplaced items are warnings, not errors
        assert!(
            !diagnostics.iter().any(|d| d.id == INVALID_FORWARD_NAME),
            "valid misplaced name is not an error"
        );
        assert!(
            !diagnostics.iter().any(|d| d.id == INVALID_FORWARD_ADDR),
            "valid misplaced addr is not an error"
        );
        // invalid misplaced values must still be errors
        let bad = m(
            Vec::new(),
            Vec::new(),
            vec![
                UnboundEntry::ForwardName {
                    name: "bad name with space".to_owned(),
                },
                UnboundEntry::ForwardAddr {
                    addr: "not-an-ip".to_owned(),
                },
            ],
        );
        let diag_bad = ResolverModule::validate(&bad, &ctx(&profile()));
        assert!(
            diag_bad.iter().any(|d| d.id == INVALID_FORWARD_NAME),
            "invalid forward name is an error even when misplaced"
        );
        assert!(
            diag_bad.iter().any(|d| d.id == INVALID_FORWARD_ADDR),
            "invalid forward addr is an error even when misplaced"
        );
        assert!(diag_bad.has_errors(), "invalid misplaced values are errors");
    }

    #[test]
    fn misplaced_forward_name_is_still_validated() {
        // invalid name outside any forward-zone must be Error + Warning
        let model = m(
            Vec::new(),
            Vec::new(),
            vec![UnboundEntry::ForwardName {
                name: "bad name with space".to_owned(),
            }],
        );
        let diagnostics = ResolverModule::validate(&model, &ctx(&profile()));
        assert!(
            diagnostics.iter().any(|d| d.id == INVALID_FORWARD_NAME),
            "invalid name outside zone is an error"
        );
        assert!(
            diagnostics.iter().any(|d| d.id == UNBOUND_MISPLACED),
            "misplaced name is a warning"
        );
        assert!(diagnostics.has_errors());
        // invalid addr outside zone likewise
        let model2 = m(
            Vec::new(),
            Vec::new(),
            vec![UnboundEntry::ForwardAddr {
                addr: "not-an-ip".to_owned(),
            }],
        );
        let diag2 = ResolverModule::validate(&model2, &ctx(&profile()));
        assert!(
            diag2.iter().any(|d| d.id == INVALID_FORWARD_ADDR),
            "invalid addr outside zone is an error"
        );
        assert!(
            diag2.iter().any(|d| d.id == UNBOUND_MISPLACED),
            "misplaced addr is a warning"
        );
        // render must reject injection chars
        assert!(matches!(
            render_unbound(&UnboundEntry::ForwardName {
                name: "a b".to_owned()
            }),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_unbound(&UnboundEntry::ForwardName {
                name: "a:b".to_owned()
            }),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_unbound(&UnboundEntry::ForwardName {
                name: "a#b".to_owned()
            }),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_unbound(&UnboundEntry::ForwardAddr {
                addr: "1.1.1.1 bad".to_owned()
            }),
            Err(EditError::Unsupported { .. })
        ));
        // valid DoT addr must still render
        assert!(
            render_unbound(&UnboundEntry::ForwardAddr {
                addr: "9.9.9.9@853#dns.quad9.net".to_owned()
            })
            .is_ok()
        );
        assert!(
            render_unbound(&UnboundEntry::ForwardAddr {
                addr: "2001:db8::1".to_owned()
            })
            .is_ok()
        );
    }

    // -------------------------------------------------------------- validators

    #[test]
    fn domain_validation_matches_rfc_1035() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("EXAMPLE.COM."));
        assert!(is_valid_domain("."));
        assert!(is_valid_domain("~corp.example.com"));
        assert!(!is_valid_domain("-bad-"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("a..b"));
        assert!(!is_valid_domain("a b.c"));
    }

    #[test]
    fn option_validation_tolerates_known_shapes() {
        assert!(is_valid_option("ndots:2"));
        assert!(is_valid_option("edns0"));
        assert!(is_valid_option("timeout:5"));
        assert!(!is_valid_option("bogus option"));
        assert!(!is_valid_option(""));
    }

    #[test]
    fn forward_addr_validation_accepts_the_upstream_shape() {
        assert!(is_valid_forward_addr("192.0.2.1"));
        assert!(is_valid_forward_addr("2001:db8::1"));
        assert!(is_valid_forward_addr("9.9.9.9@853#dns.quad9.net"));
        assert!(is_valid_forward_addr("2001:db8::1@853"));
        assert!(!is_valid_forward_addr("192.0.2.1:53"));
        assert!(!is_valid_forward_addr("not-an-ip"));
        assert!(!is_valid_forward_addr("192.0.2.1#"));
        assert!(!is_valid_forward_addr("192.0.2.1@"));
        assert!(!is_valid_forward_addr("192.0.2.1@not-a-port"));
        assert!(!is_valid_forward_addr("192.0.2.1#-bad.name-"));
    }

    #[test]
    fn every_hardening_key_is_known_and_some_recommended() {
        assert!(KNOWN_HARDENING.contains(&"qname-minimisation"));
        assert!(!KNOWN_HARDENING.contains(&"forward-addr"));
        for key in RECOMMENDED_HARDENING {
            assert!(
                KNOWN_HARDENING.contains(key),
                "{key} recommended but not modeled"
            );
        }
    }

    // --------------------------------------------------------------- defaults

    #[test]
    fn defaults_follow_the_detected_backend() {
        let defaults = ResolverModule::defaults(&profile());
        assert_eq!(defaults.resolv.len(), 2, "loopback + options");
        assert!(defaults.resolved.is_empty());
        assert!(defaults.unbound.is_empty());

        let defaults = ResolverModule::defaults(&profile_versions(&[(SERVICE_RESOLVED, "257")]));
        assert!(defaults.resolv.is_empty());
        assert_eq!(
            defaults.resolved.first(),
            Some(&ResolvedEntry::Resolve),
            "the section header leads the file"
        );

        let defaults = ResolverModule::defaults(&profile_versions(&[(SERVICE_UNBOUND, "1.20")]));
        assert!(defaults.unbound.len() >= 2);
        assert_eq!(defaults.unbound.first(), Some(&UnboundEntry::Server));
    }

    #[test]
    fn defaults_on_non_linux_tiers_are_the_static_file() {
        let mut mac = profile();
        mac.os = Os::MacOs;
        let defaults = ResolverModule::defaults(&mac);
        assert_eq!(defaults, ResolverModule::defaults(&profile()));
    }

    // ------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_targets_steering_and_checks() {
        let descriptor = ResolverModule::descriptor();
        assert_eq!(descriptor.id, "resolver");
        let paths: Vec<&str> = descriptor
            .targets
            .iter()
            .map(|target| target.path.as_str())
            .collect();
        assert!(paths.contains(&"/etc/resolv.conf"));
        assert!(paths.contains(&"/etc/systemd/resolved.conf"));
        assert!(paths.contains(&"/etc/systemd/resolved.conf.d"));
        assert!(paths.contains(&"/etc/unbound/unbound.conf"));
        assert!(descriptor.commit_confirm, "network-critical");
        assert_eq!(
            descriptor
                .checks
                .first()
                .map(|check| check.program.as_str()),
            Some("/usr/sbin/unbound-checkconf")
        );
        assert_eq!(
            descriptor.upstream.project, "systemd",
            "unbound's docs and tracker ride along under systemd's umbrella"
        );
    }

    #[test]
    fn schema_carries_the_three_hinted_fields() {
        let schema = ResolverModule::schema();
        for pointer in [
            "/properties/resolv",
            "/properties/resolved",
            "/properties/unbound",
        ] {
            let hints = schema
                .pointer(pointer)
                .and_then(|node| node.get("x-detent"));
            assert!(hints.is_some(), "{pointer} carries x-detent hints");
            let hints = hints.unwrap_or(&serde_json::Value::Null);
            assert!(hints.get("tooltip").is_some());
        }
        assert!(schema.get("$schema").is_some());
    }

    /// `upstream-watch` reads the TOML; the descriptor is what the UI shows.
    /// When the two disagree, `upstream.toml` wins and this test fails until
    /// the descriptor catches up.
    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = RESOLVER_DESCRIPTOR.upstream;
        for value in [
            upstream.project,
            upstream.repo_url,
            upstream.tracked_version,
        ] {
            assert!(
                UPSTREAM_TOML.contains(value),
                "upstream.toml does not mention `{value}`"
            );
        }
        for doc in upstream.docs {
            assert!(
                UPSTREAM_TOML.contains(doc),
                "upstream.toml is missing {doc}"
            );
        }
        // systemd publishes a release atom feed, so the descriptor carries
        // `Some` and upstream-watch compares the feed head against
        // `tracked_version` (a fake old version proves the issue path).
        assert_eq!(
            upstream.release_feed,
            Some("https://github.com/systemd/systemd/releases.atom")
        );
        assert!(UPSTREAM_TOML.contains("tracked_version = \"257.6\""));
        assert!(
            UPSTREAM_TOML
                .contains("dirs = [\"glibc-2.42\", \"resolved-257\", \"unbound-1.24\", \"edge\"]")
        );
    }

    /// `MessageId` is a compile-time constant, so this test fails at build
    /// time if an id is dropped from the file — no TOML parser needed.
    #[test]
    fn every_message_id_has_a_locale_entry() {
        let ftl = include_str!("../../../../locales/en-US/core.ftl");
        for id in [
            "resolver-name",
            "resolver-note-managed-symlink",
            "resolver-tip-resolv",
            "resolver-tip-resolved",
            "resolver-tip-unbound",
            "resolver-no-nameserver",
            "resolver-duplicate-nameserver",
            "resolver-too-many-nameservers",
            "resolver-invalid-domain",
            "resolver-unknown-option",
            "resolver-search-and-domain",
            "resolver-no-config",
            "resolver-backend-missing",
            "resolver-rec-dnssec",
            "resolver-rec-dot",
            "resolver-unknown-hardening",
            "resolver-unbound-misplaced",
            "resolver-invalid-forward-addr",
            "resolver-invalid-forward-name",
            "resolver-forward-tls-no-auth",
            "resolver-rec-hardening",
            "resolver-forward-zone-unnamed",
        ] {
            assert!(
                ftl.contains(&format!("{id} =")),
                "locale file is missing `{id}`"
            );
        }
    }

    #[test]
    fn serde_round_trips_the_model() -> Result<(), String> {
        let model = m(
            vec![ResolvEntry::Nameserver {
                ip: ip("192.0.2.1"),
            }],
            vec![ResolvedEntry::DnsSec {
                mode: ResolvedDnsSec::AllowDowngrade,
            }],
            vec![UnboundEntry::ForwardTls { enabled: true }],
        );
        let json = serde_json::to_value(&model).map_err(|e| e.to_string())?;
        assert_eq!(
            serde_json::from_value::<Model>(json).map_err(|e| e.to_string())?,
            model
        );
        assert!(
            serde_json::from_value::<Model>(serde_json::json!({ "resolv": [], "bogus": 1 }))
                .is_err(),
            "deny_unknown_fields guards the model"
        );

        Ok(())
    }

    // ------------------------------------------------------------ fuzz support

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_builds_a_model() {
        use arbitrary::{Arbitrary, Unstructured};
        let data: Vec<u8> = (0u8..64).collect();
        let mut u = Unstructured::new(&data);
        assert!(Model::arbitrary(&mut u).is_ok());
        assert!(ResolvEntry::arbitrary(&mut u).is_ok());
        assert!(ResolvedEntry::arbitrary(&mut u).is_ok());
        assert!(UnboundEntry::arbitrary(&mut u).is_ok());
        assert!(DnsServer::arbitrary(&mut u).is_ok());
        assert!(<Model as Arbitrary>::size_hint(0).1.is_none());
    }
    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_impls_cover_every_arm_and_apply_cleanly() -> Result<(), String> {
        use super::{arbitrary_dns_servers, arbitrary_domain, arbitrary_forward_addr};
        use arbitrary::{Arbitrary, Unstructured};

        // Constant first bytes drive every `int_in_range` arm of the three
        // manual `Arbitrary` impls (`% 4` for resolv, `% 6` for
        // resolved/unbound); `0x00`/`0xff` take both sides of every bool coin.
        let buffers: &[&[u8]] = &[
            &[0; 256],
            &[1; 256],
            &[2; 256],
            // First int reads `3` (`% 6 == 3` takes the `ForwardName` arm) and
            // the following bool reads `0`, taking the `arbitrary_domain`
            // side — every constant buffer above reads `"."` here instead.
            &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[4; 256],
            &[5; 256],
            &[0xff; 256],
        ];
        for data in buffers {
            let resolv =
                ResolvEntry::arbitrary(&mut Unstructured::new(data)).map_err(|e| e.to_string())?;
            let resolved = ResolvedEntry::arbitrary(&mut Unstructured::new(data))
                .map_err(|e| e.to_string())?;
            let unbound =
                UnboundEntry::arbitrary(&mut Unstructured::new(data)).map_err(|e| e.to_string())?;
            let domain =
                arbitrary_domain(&mut Unstructured::new(data)).map_err(|e| e.to_string())?;
            let servers =
                arbitrary_dns_servers(&mut Unstructured::new(data)).map_err(|e| e.to_string())?;
            let addr =
                arbitrary_forward_addr(&mut Unstructured::new(data)).map_err(|e| e.to_string())?;

            assert!(
                is_valid_domain(&domain),
                "generated invalid domain {domain:?}"
            );
            for server in &servers {
                if let Some(name) = server.name.as_ref() {
                    assert!(
                        is_valid_domain(name),
                        "generated invalid auth name {name:?}"
                    );
                }
            }
            assert!(
                is_valid_forward_addr(&addr),
                "generated invalid forward-addr {addr:?}"
            );
            let applied = Model {
                resolv: vec![resolv],
                resolved: vec![resolved],
                unbound: vec![unbound],
            };
            let mut doc = ResolverModule::parse("").map_err(|e| e.to_string())?;
            ResolverModule::apply(&mut doc, &applied).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
