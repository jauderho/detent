//! The `hosts` module: `/etc/hosts`, the reference implementation of
//! [`detent_core::module::ConfigModule`].
//!
//! `/etc/hosts` is a line-oriented file. Each line is blank, a `#` comment, or an
//! entry of the form `<ip> <canonical-name> [aliases…] [# comment]`. Anything that
//! does not parse as an entry — a bare address, an IPv6 address carrying a zone id
//! (`fe80::1%eth0`), a malformed address — is kept as
//! [`LineKind::Unknown`] and is never rewritten.
//!
//! # Formatting policy
//!
//! Hand-aligned columns are common in this file, so a line is left byte-for-byte
//! alone whenever the entry parsed from it equals the entry in the model. Only lines
//! that actually change are re-rendered, as `<ip>\t<names joined by spaces>` followed
//! by `\t# <comment>` when the entry carries one.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time.

use detent_core::descriptor::{
    FieldHints, HostProfile, ModuleDescriptor, Os, Owner, PathSpec, SecurityImpact, Target,
    TargetKind, UiGroup, Upstream, ValidationCtx, apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ------------------------------------------------------------------------- model

/// One `/etc/hosts` entry: an address and the names that resolve to it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The address the names map to.
    pub ip: IpAddr,
    /// The names, canonical name first, then aliases.
    pub hostnames: Vec<String>,
    /// The text of the inline `#` comment, without the `#` and trimmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The typed model of `/etc/hosts`: its entries, in file order.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The entries, in the order they appear in the file.
    pub entries: Vec<Entry>,
}

/// Builds an RFC 1123-valid hostname label: 1–10 lowercase letters or digits, never
/// starting or ending with `-` (the fuzz `edit` target never needs the full 63-byte
/// range to exercise `apply`'s matching and rendering logic).
#[cfg(feature = "fuzzing")]
fn arbitrary_label(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let len = u.int_in_range(1..=10usize)?;
    let mut label = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        label.push(char::from(byte));
    }
    Ok(label)
}

/// Builds an RFC 1123-valid hostname of one to three dot-separated labels.
#[cfg(feature = "fuzzing")]
fn arbitrary_hostname(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    let labels = u.int_in_range(1..=3usize)?;
    let mut parts = Vec::with_capacity(labels);
    for _ in 0..labels {
        parts.push(arbitrary_label(u)?);
    }
    Ok(parts.join("."))
}

/// Builds a comment with no line breaks or NUL, already trimmed.
#[cfg(feature = "fuzzing")]
fn arbitrary_comment(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789 -_.";
    let len = u.int_in_range(0..=20usize)?;
    let mut comment = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        comment.push(char::from(byte));
    }
    Ok(comment.trim().to_owned())
}

/// A fuzz-friendly `Arbitrary` for [`Entry`]: derived generation would produce
/// hostnames and comments carrying arbitrary bytes, most of which `apply` rejects
/// (correctly — invariant 5) before ever reaching the matching or rendering logic
/// the `fuzz_hosts_edit` target wants to exercise. This constrains names to RFC
/// 1123 shapes and comments to a safe alphabet instead.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for Entry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let ip = IpAddr::arbitrary(u)?;
        let count = u.int_in_range(1..=4usize)?;
        let mut hostnames = Vec::with_capacity(count);
        for _ in 0..count {
            hostnames.push(arbitrary_hostname(u)?);
        }
        let comment = if bool::arbitrary(u)? {
            Some(arbitrary_comment(u)?)
        } else {
            None
        };
        Ok(Self {
            ip,
            hostnames,
            comment,
        })
    }
}

// ------------------------------------------------------------ parsing / rendering

/// Splits a line into its field part and its inline comment, if any.
///
/// The comment text is trimmed, so `"1.2.3.4 a  #  note "` yields `Some("note")`.
fn split_comment(raw: &str) -> (&str, Option<&str>) {
    match raw.split_once('#') {
        Some((fields, comment)) => (fields, Some(comment.trim())),
        None => (raw, None),
    }
}

/// Parses one line as an entry, or `None` when it is not one.
///
/// A line is an entry when it starts with a parseable [`IpAddr`] followed by at least
/// one name. `std`'s address parser rejects zone ids, so `fe80::1%eth0` is not an
/// entry and stays [`LineKind::Unknown`].
fn parse_entry(raw: &str) -> Option<Entry> {
    let (fields, comment) = split_comment(raw);
    let (address, rest) = fields.trim_start().split_once(char::is_whitespace)?;
    let ip: IpAddr = address.parse().ok()?;
    let hostnames: Vec<String> = rest.split_whitespace().map(str::to_owned).collect();
    if hostnames.is_empty() {
        return None;
    }
    Some(Entry {
        ip,
        hostnames,
        comment: comment.map(str::to_owned),
    })
}

/// Classifies a line for the lossless document model.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with('#') {
        LineKind::Comment
    } else if parse_entry(raw).is_some() {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

/// Renders an entry as a line, refusing anything that would not survive a round trip.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when a name or comment carries `\n`, `\r` or NUL
/// (invariant 5), and [`EditError::Unsupported`] when the rendered line does not parse
/// back to the same entry — an empty name list, a name containing whitespace or `#`,
/// or a comment that is not already trimmed.
fn render_line(entry: &Entry) -> Result<String, EditError> {
    let mut raw = format!("{}\t{}", entry.ip, entry.hostnames.join(" "));
    if let Some(comment) = entry.comment.as_deref() {
        raw.push_str("\t#");
        if !comment.is_empty() {
            raw.push(' ');
            raw.push_str(comment);
        }
    }
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue { value: raw });
    }
    if parse_entry(&raw).as_ref() != Some(entry) {
        return Err(EditError::Unsupported {
            message: format!("entry does not round-trip through the file format: {raw:?}"),
        });
    }
    Ok(raw)
}

// -------------------------------------------------------------------- descriptor

/// `/etc/hosts` exists on every supported operating system.
fn hosts_backend_detect(_profile: &HostProfile) -> bool {
    true
}

static HOSTS_TARGETS: &[Target] = &[Target {
    path: PathSpec::new("/etc/hosts"),
    kind: TargetKind::File,
    mode: 0o644,
    owner: Owner::Root,
    backend_detect: hosts_backend_detect,
}];

static HOSTS_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "hosts",
    display_name_id: MessageId::new("hosts-name"),
    targets: HOSTS_TARGETS,
    upstream: Upstream {
        project: "glibc",
        repo_url: "https://sourceware.org/git/glibc.git",
        tracked_version: "2.42",
        release_feed: None,
        docs: &["https://man7.org/linux/man-pages/man5/hosts.5.html"],
    },
    services: &[],
    checks: &[],
    commit_confirm: false,
    security_notes: &[MessageId::new("hosts-note-spoofing")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `entries`.
static ENTRIES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("hosts-tip-entries"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].ip`.
static IP_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("hosts-tip-ip"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].hostnames`.
static HOSTNAMES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("hosts-tip-hostnames"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].comment`.
static COMMENT_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("hosts-tip-comment"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `HostsModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/entries", &ENTRIES_HINTS),
        ("/$defs/Entry/properties/ip", &IP_HINTS),
        ("/$defs/Entry/properties/hostnames", &HOSTNAMES_HINTS),
        ("/$defs/Entry/properties/comment", &COMMENT_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: a name is not a valid RFC 1123 hostname.
const INVALID_HOSTNAME: MessageId = MessageId::new("hosts-invalid-hostname");
/// Fluent id: two entries declare the same canonical name.
const DUPLICATE_CANONICAL: MessageId = MessageId::new("hosts-duplicate-canonical");
/// Fluent id: an entry has no names at all.
const NO_HOSTNAMES: MessageId = MessageId::new("hosts-no-hostnames");
/// Fluent id: a name is an address literal.
const HOSTNAME_IS_IP: MessageId = MessageId::new("hosts-hostname-is-ip");
/// Fluent id: a name carries an IPv6 zone id.
const ZONE_UNSUPPORTED: MessageId = MessageId::new("hosts-ipv6-zone-unsupported");
/// Fluent id: one name maps to several addresses of the same family.
const MULTIPLE_IPS: MessageId = MessageId::new("hosts-hostname-multiple-ips");
/// Fluent id: `localhost` does not point at a loopback address.
const LOCALHOST_NOT_LOOPBACK: MessageId = MessageId::new("hosts-localhost-not-loopback");
/// Fluent id: there is no `localhost` entry.
const MISSING_LOCALHOST: MessageId = MessageId::new("hosts-missing-localhost");
/// Fluent id: there is no IPv6 `localhost` entry.
const MISSING_IPV6_LOCALHOST: MessageId = MessageId::new("hosts-missing-ipv6-localhost");
/// Fluent id: the file has grown past the point where DNS is the better tool.
const TOO_MANY_ENTRIES: MessageId = MessageId::new("hosts-too-many-entries");

/// Above this many entries, `validate` recommends DNS instead.
const ENTRY_COUNT_ADVICE_THRESHOLD: usize = 500;
/// Longest hostname RFC 1123 allows.
const MAX_HOSTNAME_LEN: usize = 253;
/// Longest single label RFC 1123 allows.
const MAX_LABEL_LEN: usize = 63;

/// Whether `name` is a valid RFC 1123 hostname.
///
/// Labels are 1–63 characters of ASCII letters, digits and `-`, and may not start or
/// end with `-`. The whole name is at most 253 characters. A trailing dot is
/// **rejected**: `/etc/hosts` names are not DNS presentation names.
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_HOSTNAME_LEN || name.ends_with('.') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The part of `name` before an IPv6 zone id, when `name` looks like one.
fn zone_id_address(name: &str) -> Option<&str> {
    let (address, _zone) = name.split_once('%')?;
    address.parse::<IpAddr>().ok().map(|_| address)
}

/// Checks the names of one entry.
fn validate_hostnames(entry: &Entry, index: usize, diagnostics: &mut Diagnostics) {
    if entry.hostnames.is_empty() {
        diagnostics.push(
            Diagnostic::new(Severity::Error, NO_HOSTNAMES)
                .with_field(FieldPath::new(format!("entries/{index}/hostnames"))),
        );
    }
    for (position, name) in entry.hostnames.iter().enumerate() {
        let field = FieldPath::new(format!("entries/{index}/hostnames/{position}"));
        if let Some(address) = zone_id_address(name) {
            diagnostics.push(
                Diagnostic::new(Severity::Error, ZONE_UNSUPPORTED)
                    .with_field(field)
                    .with_arg("name", name.clone())
                    .with_arg("address", address.to_owned()),
            );
        } else if name.parse::<IpAddr>().is_ok() {
            diagnostics.push(
                Diagnostic::new(Severity::Error, HOSTNAME_IS_IP)
                    .with_field(field)
                    .with_arg("name", name.clone()),
            );
        } else if !is_valid_hostname(name) {
            diagnostics.push(
                Diagnostic::new(Severity::Error, INVALID_HOSTNAME)
                    .with_field(field)
                    .with_arg("name", name.clone()),
            );
        }
    }
}

/// Reports a canonical name that two entries both claim **within the same
/// address family**.
///
/// A standard dual-stack file has `127.0.0.1 localhost` and `::1 localhost` —
/// same canonical, different families — and must not error. Keying by
/// `(name, family)` fixes that for free and still errors true duplicates
/// (`192.0.2.1 dup` + `192.0.2.2 dup`).
fn validate_canonical_uniqueness(model: &Model, diagnostics: &mut Diagnostics) {
    let mut seen: std::collections::BTreeSet<(String, bool)> = std::collections::BTreeSet::new();
    for (index, entry) in model.entries.iter().enumerate() {
        let Some(canonical) = entry.hostnames.first() else {
            continue;
        };
        let key = (canonical.to_ascii_lowercase(), entry.ip.is_ipv6());
        if !seen.insert(key) {
            diagnostics.push(
                Diagnostic::new(Severity::Error, DUPLICATE_CANONICAL)
                    .with_field(FieldPath::new(format!("entries/{index}/hostnames/0")))
                    .with_arg("name", canonical.clone()),
            );
        }
    }
}

/// Reports names that resolve to more than one address of the same family, which
/// makes lookup order significant and surprising.
fn validate_address_families(model: &Model, diagnostics: &mut Diagnostics) {
    let mut by_name: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    for entry in &model.entries {
        for name in &entry.hostnames {
            by_name
                .entry(name.to_ascii_lowercase())
                .or_default()
                .insert(entry.ip);
        }
    }
    for (name, addresses) in by_name {
        let v4 = addresses.iter().filter(|ip| ip.is_ipv4()).count();
        let v6 = addresses.iter().filter(|ip| ip.is_ipv6()).count();
        if v4 > 1 || v6 > 1 {
            diagnostics.push(
                Diagnostic::new(Severity::Warning, MULTIPLE_IPS)
                    .with_field(FieldPath::new("entries"))
                    .with_arg("name", name),
            );
        }
    }
}

/// Checks the `localhost` entries every host is expected to have.
fn validate_localhost(model: &Model, diagnostics: &mut Diagnostics) {
    let mut present = false;
    let mut ipv6_present = false;
    for (index, entry) in model.entries.iter().enumerate() {
        let is_localhost = entry
            .hostnames
            .iter()
            .any(|name| name.eq_ignore_ascii_case("localhost"));
        let is_ipv6_alias = entry.hostnames.iter().any(|name| {
            name.eq_ignore_ascii_case("ip6-localhost") || name.eq_ignore_ascii_case("ip6-loopback")
        });
        if !is_localhost && !is_ipv6_alias {
            continue;
        }
        present |= is_localhost;
        if entry.ip.is_loopback() {
            ipv6_present |= entry.ip.is_ipv6() && (is_localhost || is_ipv6_alias);
        } else if is_localhost || is_ipv6_alias {
            diagnostics.push(
                Diagnostic::new(Severity::Error, LOCALHOST_NOT_LOOPBACK)
                    .with_field(FieldPath::new(format!("entries/{index}/ip")))
                    .with_arg("ip", entry.ip.to_string()),
            );
        }
    }
    if !present {
        diagnostics.push(Diagnostic::new(Severity::Error, MISSING_LOCALHOST));
    }
    if !ipv6_present {
        diagnostics.push(Diagnostic::new(
            Severity::Recommendation,
            MISSING_IPV6_LOCALHOST,
        ));
    }
}

// ---------------------------------------------------------------------- defaults

/// Builds one default entry.
fn entry(ip: IpAddr, hostnames: &[&str]) -> Entry {
    Entry {
        ip,
        hostnames: hostnames.iter().map(|name| (*name).to_owned()).collect(),
        comment: None,
    }
}

/// `ff02::1`, the all-nodes link-local multicast group.
const IP6_ALLNODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// `ff02::2`, the all-routers link-local multicast group.
const IP6_ALLROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// `127.0.1.1`, where Debian-style systems point the host's own name.
const DEBIAN_HOSTNAME_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 1, 1);

// ----------------------------------------------------------------------- module

/// The `/etc/hosts` config module.
pub struct HostsModule;

impl ConfigModule for HostsModule {
    const ID: &'static str = "hosts";
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &HOSTS_DESCRIPTOR
    }

    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        Ok(Model {
            entries: doc
                .lines_of_kind(LineKind::Directive)
                .filter_map(|line| parse_entry(line.raw()))
                .collect(),
        })
    }

    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1 (`plan_entries`) is read-only: it aligns the model with the
        // existing entry lines and renders only the ones that differ, so a
        // rejected value (invariant 5) leaves the document untouched and an
        // unchanged line keeps its hand-aligned columns. Pass 2 keeps unchanged
        // lines in place, rewrites changed ones in place, drops deleted ones
        // and puts new ones after the previous kept entry line.
        doc.edit_entries(&model.entries, parse_entry, render_line, |_| false)
    }

    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        for (index, entry) in model.entries.iter().enumerate() {
            validate_hostnames(entry, index, &mut diagnostics);
        }
        validate_canonical_uniqueness(model, &mut diagnostics);
        validate_address_families(model, &mut diagnostics);
        validate_localhost(model, &mut diagnostics);
        if model.entries.len() > ENTRY_COUNT_ADVICE_THRESHOLD {
            diagnostics.push(
                Diagnostic::new(Severity::Recommendation, TOO_MANY_ENTRIES)
                    .with_field(FieldPath::new("entries"))
                    .with_arg("count", model.entries.len().to_string()),
            );
        }
        diagnostics
    }

    fn defaults(profile: &HostProfile) -> Self::Model {
        let mut entries = vec![entry(IpAddr::V4(Ipv4Addr::LOCALHOST), &["localhost"])];
        match profile.os {
            Os::MacOs => {
                entries.push(entry(IpAddr::V4(Ipv4Addr::BROADCAST), &["broadcasthost"]));
                entries.push(entry(IpAddr::V6(Ipv6Addr::LOCALHOST), &["localhost"]));
            }
            Os::Linux => {
                if !profile.hostname.is_empty() {
                    entries.push(entry(
                        IpAddr::V4(DEBIAN_HOSTNAME_IP),
                        &[profile.hostname.as_str()],
                    ));
                }
                entries.push(entry(
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    &["localhost", "ip6-localhost", "ip6-loopback"],
                ));
                entries.push(entry(IpAddr::V6(IP6_ALLNODES), &["ip6-allnodes"]));
                entries.push(entry(IpAddr::V6(IP6_ALLROUTERS), &["ip6-allrouters"]));
            }
            Os::Other => entries.push(entry(IpAddr::V6(Ipv6Addr::LOCALHOST), &["localhost"])),
        }
        Model { entries }
    }

    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEBIAN_HOSTNAME_IP, DUPLICATE_CANONICAL, Entry, HOSTNAME_IS_IP, HOSTS_DESCRIPTOR,
        HostsModule, INVALID_HOSTNAME, LOCALHOST_NOT_LOOPBACK, MISSING_IPV6_LOCALHOST,
        MISSING_LOCALHOST, MULTIPLE_IPS, Model, NO_HOSTNAMES, TOO_MANY_ENTRIES, ZONE_UNSUPPORTED,
        is_valid_hostname, parse_entry, render_line, schema_with_hints, zone_id_address,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::module::{ConfigModule, EditError, EditReport};
    use std::net::{IpAddr, Ipv4Addr};

    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");
    /// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
    /// reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    /// Every `MessageId` string literal referenced in this crate must have a Fluent
    /// entry, or the UI would show a raw id.
    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "hosts-name",
            "hosts-note-spoofing",
            "hosts-tip-entries",
            "hosts-tip-ip",
            "hosts-tip-hostnames",
            "hosts-tip-comment",
            "hosts-invalid-hostname",
            "hosts-duplicate-canonical",
            "hosts-no-hostnames",
            "hosts-hostname-is-ip",
            "hosts-ipv6-zone-unsupported",
            "hosts-hostname-multiple-ips",
            "hosts-localhost-not-loopback",
            "hosts-missing-localhost",
            "hosts-missing-ipv6-localhost",
            "hosts-too-many-entries",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    /// `upstream.toml` is read by `upstream-watch`; the descriptor is read by
    /// the UI. They must not drift apart.
    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = HOSTS_DESCRIPTOR.upstream;
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
        // glibc publishes no release atom feed, so the descriptor carries
        // `None` and upstream-watch falls back to comparing tags in `repo_url`.
        assert_eq!(upstream.release_feed, None);
        assert!(UPSTREAM_TOML.contains("release_feed = \"\""));
    }

    fn entry(ip: &str, hostnames: &[&str], comment: Option<&str>) -> Entry {
        Entry {
            ip: ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            hostnames: hostnames.iter().map(|n| (*n).to_owned()).collect(),
            comment: comment.map(str::to_owned),
        }
    }

    fn profile(os: Os, hostname: &str) -> HostProfile {
        HostProfile {
            os,
            init: InitSystem::None,
            hostname: hostname.to_owned(),
            service_versions: std::collections::BTreeMap::new(),
            ram_mib: 0,
        }
    }

    fn has(model: &Model, id: MessageId, severity: Severity) -> bool {
        let host = profile(Os::Linux, "host");
        let ctx = ValidationCtx::new(&host);
        HostsModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    // --------------------------------------------------------- is_valid_hostname

    #[test]
    fn hostname_validation_accepts_rfc1123_shapes() {
        assert!(is_valid_hostname("a"));
        assert!(is_valid_hostname("a-b"));
        assert!(is_valid_hostname("a.b.c"));
        assert!(is_valid_hostname("host-01.example.com"));
        assert!(is_valid_hostname(&"a".repeat(63)));
        let max_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max_name.len(), 253);
        assert!(is_valid_hostname(&max_name));
    }

    #[test]
    fn hostname_validation_rejects_bad_shapes() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("a."));
        assert!(!is_valid_hostname("-a"));
        assert!(!is_valid_hostname("a-"));
        assert!(!is_valid_hostname("a..b"));
        assert!(!is_valid_hostname("a_b"));
        assert!(!is_valid_hostname("a b"));
        assert!(!is_valid_hostname(&"a".repeat(64)));
        let too_long = format!(
            "{}.{}.{}.{}.a",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(60)
        );
        assert!(!is_valid_hostname(&too_long));
    }

    // ------------------------------------------------------------ zone_id_address

    #[test]
    fn zone_id_address_extracts_only_real_addresses() {
        assert_eq!(zone_id_address("fe80::1%eth0"), Some("fe80::1"));
        assert_eq!(zone_id_address("not-an-address%eth0"), None);
        assert_eq!(zone_id_address("plain"), None);
    }

    // ------------------------------------------------------------------ validate

    #[test]
    fn validate_flags_empty_hostnames() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &[], None)],
        };
        assert!(has(&model, NO_HOSTNAMES, Severity::Error));
    }

    #[test]
    fn validate_flags_zone_id_hostname() {
        // Not reachable through parsing (zone ids never classify as directives), but
        // `validate` must still reject one arriving via the JSON API.
        let model = Model {
            entries: vec![entry("192.0.2.1", &["fe80::1%eth0"], None)],
        };
        assert!(has(&model, ZONE_UNSUPPORTED, Severity::Error));
    }

    #[test]
    fn validate_flags_ip_literal_hostname() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["192.0.2.2"], None)],
        };
        assert!(has(&model, HOSTNAME_IS_IP, Severity::Error));
    }

    #[test]
    fn validate_flags_invalid_hostname() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["-bad"], None)],
        };
        assert!(has(&model, INVALID_HOSTNAME, Severity::Error));
    }

    #[test]
    fn validate_accepts_a_clean_entry() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["good.example"], None)],
        };
        assert!(!has(&model, INVALID_HOSTNAME, Severity::Error));
        assert!(!has(&model, NO_HOSTNAMES, Severity::Error));
        assert!(!has(&model, HOSTNAME_IS_IP, Severity::Error));
        assert!(!has(&model, ZONE_UNSUPPORTED, Severity::Error));
    }

    #[test]
    fn validate_flags_duplicate_canonical_names_case_insensitively() {
        let model = Model {
            entries: vec![
                entry("192.0.2.1", &["Host.Example"], None),
                entry("192.0.2.2", &["host.example"], None),
            ],
        };
        assert!(has(&model, DUPLICATE_CANONICAL, Severity::Error));
    }

    #[test]
    fn validate_does_not_flag_unique_canonical_names() {
        let model = Model {
            entries: vec![
                entry("192.0.2.1", &["a.example"], None),
                entry("192.0.2.2", &["b.example"], None),
            ],
        };
        assert!(!has(&model, DUPLICATE_CANONICAL, Severity::Error));
    }

    #[test]
    fn validate_flags_a_name_bound_to_two_addresses_of_one_family() {
        let model = Model {
            entries: vec![
                entry("192.0.2.1", &["dup"], None),
                entry("192.0.2.2", &["dup"], None),
            ],
        };
        assert!(has(&model, MULTIPLE_IPS, Severity::Warning));
    }

    #[test]
    fn validate_allows_one_v4_and_one_v6_address_for_the_same_name() {
        let model = Model {
            entries: vec![
                entry("192.0.2.1", &["dual"], None),
                entry("::1", &["dual"], None),
            ],
        };
        assert!(!has(&model, MULTIPLE_IPS, Severity::Warning));
    }

    #[test]
    fn validate_flags_localhost_that_is_not_loopback() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["localhost"], None)],
        };
        assert!(has(&model, LOCALHOST_NOT_LOOPBACK, Severity::Error));
    }

    #[test]
    fn validate_flags_missing_localhost_and_missing_ipv6_localhost() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["other"], None)],
        };
        assert!(has(&model, MISSING_LOCALHOST, Severity::Error));
        assert!(has(
            &model,
            MISSING_IPV6_LOCALHOST,
            Severity::Recommendation
        ));
    }

    #[test]
    fn validate_is_satisfied_by_v4_and_v6_loopback_localhost() {
        let model = Model {
            entries: vec![
                entry("127.0.0.1", &["localhost"], None),
                entry("::1", &["localhost"], None),
            ],
        };
        assert!(!has(&model, MISSING_LOCALHOST, Severity::Error));
        assert!(!has(
            &model,
            MISSING_IPV6_LOCALHOST,
            Severity::Recommendation
        ));
        assert!(!has(&model, LOCALHOST_NOT_LOOPBACK, Severity::Error));
    }

    #[test]
    fn validate_accepts_dual_stack_localhost() {
        let model = Model {
            entries: vec![
                entry("127.0.0.1", &["localhost"], None),
                entry("::1", &["localhost"], None),
            ],
        };
        assert!(
            !has(&model, DUPLICATE_CANONICAL, Severity::Error),
            "127.0.0.1 localhost + ::1 localhost must not be a duplicate (per-family key)"
        );
    }

    #[test]
    fn validate_recognizes_ipv6_localhost_aliases() {
        let model = Model {
            entries: vec![
                entry("127.0.0.1", &["localhost"], None),
                entry("::1", &["ip6-localhost", "ip6-loopback"], None),
            ],
        };
        assert!(!has(
            &model,
            MISSING_IPV6_LOCALHOST,
            Severity::Recommendation
        ));
    }

    #[test]
    fn validate_flags_ipv6_localhost_aliases_that_are_not_loopback() {
        for alias in ["ip6-localhost", "ip6-loopback"] {
            let model = Model {
                entries: vec![
                    entry("127.0.0.1", &["localhost"], None),
                    entry("192.0.2.1", &[alias], None),
                ],
            };
            assert!(
                has(&model, LOCALHOST_NOT_LOOPBACK, Severity::Error),
                "{alias} mapped to a non-loopback address must be an Error"
            );
        }
    }

    #[test]
    fn validate_recommends_dns_past_five_hundred_entries() {
        let entries = (0..=500)
            .map(|i| {
                entry(
                    "192.0.2.1",
                    &[Box::leak(format!("h{i}").into_boxed_str())],
                    None,
                )
            })
            .collect();
        let model = Model { entries };
        assert!(has(&model, TOO_MANY_ENTRIES, Severity::Recommendation));
    }

    #[test]
    fn validate_does_not_recommend_dns_at_five_hundred_entries() {
        let entries = (0..500)
            .map(|i| {
                entry(
                    "192.0.2.1",
                    &[Box::leak(format!("h{i}").into_boxed_str())],
                    None,
                )
            })
            .collect();
        let model = Model { entries };
        assert!(!has(&model, TOO_MANY_ENTRIES, Severity::Recommendation));
    }

    // -------------------------------------------------------------------- defaults

    #[test]
    fn defaults_for_linux_include_the_hostname_and_ipv6_block() {
        let model = HostsModule::defaults(&profile(Os::Linux, "myhost"));
        assert_eq!(
            model,
            Model {
                entries: vec![
                    entry("127.0.0.1", &["localhost"], None),
                    entry("127.0.1.1", &["myhost"], None),
                    entry("::1", &["localhost", "ip6-localhost", "ip6-loopback"], None),
                    entry("ff02::1", &["ip6-allnodes"], None),
                    entry("ff02::2", &["ip6-allrouters"], None),
                ]
            }
        );
    }

    #[test]
    fn defaults_for_linux_without_a_hostname_skip_the_127_0_1_1_entry() {
        let model = HostsModule::defaults(&profile(Os::Linux, ""));
        assert!(
            !model
                .entries
                .iter()
                .any(|e| e.ip == IpAddr::V4(DEBIAN_HOSTNAME_IP))
        );
    }

    #[test]
    fn defaults_for_macos_include_broadcasthost() {
        let model = HostsModule::defaults(&profile(Os::MacOs, "mac"));
        assert_eq!(
            model,
            Model {
                entries: vec![
                    entry("127.0.0.1", &["localhost"], None),
                    entry("255.255.255.255", &["broadcasthost"], None),
                    entry("::1", &["localhost"], None),
                ]
            }
        );
    }

    #[test]
    fn defaults_for_other_os_are_minimal() {
        let model = HostsModule::defaults(&profile(Os::Other, "x"));
        assert_eq!(
            model,
            Model {
                entries: vec![
                    entry("127.0.0.1", &["localhost"], None),
                    entry("::1", &["localhost"], None),
                ]
            }
        );
    }

    // ------------------------------------------------------- derived trait impls

    /// Exercises the derived `Debug`, `Clone`, `PartialEq`, `Default`, `Serialize`
    /// and `Deserialize` impls of `Entry` and `Model`, which are otherwise never
    /// called by the module's own logic.
    #[test]
    fn model_and_entry_support_debug_clone_default_and_serde() {
        let model = Model {
            entries: vec![entry("192.0.2.1", &["a", "b"], Some("note"))],
        };
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("192.0.2.1"));
        assert_eq!(Model::default(), Model { entries: vec![] });

        let json = serde_json::to_value(&model).unwrap_or_default();
        let back: Model = serde_json::from_value(json).unwrap_or_default();
        assert_eq!(back, model);

        let bare = entry("192.0.2.2", &["c"], None);
        let bare_json = serde_json::to_value(&bare).unwrap_or_default();
        assert!(bare_json.get("comment").is_none());
        let bare_back: Entry = serde_json::from_value(bare_json).unwrap_or_else(|_| bare.clone());
        assert_eq!(bare_back, bare);
    }

    // --------------------------------------------------------------- parse_entry

    #[test]
    fn parse_entry_rejects_lines_without_a_name() {
        assert_eq!(parse_entry("192.0.2.1"), None);
        assert_eq!(parse_entry("192.0.2.1   "), None);
    }

    #[test]
    fn parse_entry_rejects_an_unparsable_address() {
        assert_eq!(parse_entry("not-an-ip host"), None);
    }

    #[test]
    fn parse_entry_keeps_an_inline_comment() {
        assert_eq!(
            parse_entry("192.0.2.1 host # note"),
            Some(entry("192.0.2.1", &["host"], Some("note")))
        );
    }

    // --------------------------------------------------------------- render_line

    #[test]
    fn render_line_rejects_a_line_break_in_a_comment() {
        let e = entry("192.0.2.1", &["host"], Some("a\nb"));
        assert_eq!(
            render_line(&e),
            Err(EditError::LineBreakInValue {
                value: "192.0.2.1\thost\t# a\nb".to_owned()
            })
        );
    }

    #[test]
    fn render_line_rejects_a_hostname_that_would_not_round_trip() {
        let e = entry("192.0.2.1", &["has space"], None);
        assert!(matches!(
            render_line(&e),
            Err(EditError::Unsupported { .. })
        ));
    }

    #[test]
    fn render_line_rejects_an_empty_hostname_list() {
        let e = Entry {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            hostnames: vec![],
            comment: None,
        };
        assert!(matches!(
            render_line(&e),
            Err(EditError::Unsupported { .. })
        ));
    }

    // -------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\n10.0.0.1    host   # note\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_entry() -> Result<(), String> {
        let src = "10.0.0.1\thost\t# note\n10.0.0.2\tother\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![
                entry("10.0.0.1", &["host"], Some("changed")),
                entry("10.0.0.2", &["other"], None),
            ],
        };
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(
            HostsModule::render(&doc),
            "10.0.0.1\thost\t# changed\n10.0.0.2\tother\n"
        );
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_entries() -> Result<(), String> {
        let src = "10.0.0.1\thost\n10.0.0.2\tother\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("10.0.0.1", &["host"], None)],
        };
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(HostsModule::render(&doc), "10.0.0.1\thost\n");
        Ok(())
    }

    #[test]
    fn apply_appends_new_entries_after_the_last_directive_line() -> Result<(), String> {
        let src = "10.0.0.1\thost\n# trailing comment\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.entries.push(entry("10.0.0.2", &["new"], None));
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            HostsModule::render(&doc),
            "10.0.0.1\thost\n10.0.0.2\tnew\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_directive_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("10.0.0.1", &["host"], None)],
        };
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            HostsModule::render(&doc),
            "# only a comment\n10.0.0.1\thost\n"
        );
        Ok(())
    }

    #[test]
    fn dropping_the_first_entry_rewrites_no_other_line() -> Result<(), String> {
        let src = "10.0.0.1\tfirst\n10.0.0.2    second   # aligned\n10.0.0.3    third\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.entries.remove(0);
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 0);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 1);
        assert_eq!(
            HostsModule::render(&doc),
            "10.0.0.2    second   # aligned\n10.0.0.3    third\n"
        );
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        let src = "10.0.0.1\thost\n";
        let mut doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("10.0.0.1", &["host"], Some("a\nb"))],
        };
        assert!(HostsModule::apply(&mut doc, &model).is_err());
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    // -------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_targets_detect_on_every_host() {
        let descriptor = HostsModule::descriptor();
        assert_eq!(descriptor.id, "hosts");
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux, "h")));
            assert!((target.backend_detect)(&profile(Os::MacOs, "h")));
            assert!((target.backend_detect)(&profile(Os::Other, "h")));
        }
    }

    // ---------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, HostsModule::schema());
        for pointer in [
            "/properties/entries",
            "/$defs/Entry/properties/ip",
            "/$defs/Entry/properties/hostnames",
            "/$defs/Entry/properties/comment",
        ] {
            assert!(
                schema
                    .pointer(pointer)
                    .and_then(|v| v.get("x-detent"))
                    .is_some(),
                "missing x-detent hint at {pointer}"
            );
        }
    }

    // ------------------------------------------------------------- adversarial

    #[test]
    fn ten_thousand_entries_round_trip_through_apply() -> Result<(), String> {
        use std::fmt::Write as _;
        let mut src = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(src, "192.0.2.1\thost{i}");
        }
        let mut doc = HostsModule::parse(&src).map_err(|e| e.to_string())?;
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.entries.len(), 10_000);
        let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn a_one_mebibyte_line_round_trips_as_unknown() -> Result<(), String> {
        let src = format!("{}\n", "x".repeat(1024 * 1024));
        let doc = HostsModule::parse(&src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert!(model.entries.is_empty());
        Ok(())
    }

    #[test]
    fn a_nul_byte_line_round_trips_as_unknown() -> Result<(), String> {
        let src = "\0\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert!(model.entries.is_empty());
        Ok(())
    }

    #[test]
    fn a_bare_hash_line_is_a_comment() -> Result<(), String> {
        let src = "#\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn leading_whitespace_before_a_hash_is_still_a_comment() -> Result<(), String> {
        let src = "   # indented\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert!(model.entries.is_empty());
        Ok(())
    }

    #[test]
    fn leading_whitespace_before_an_entry_still_parses() -> Result<(), String> {
        let src = "   192.0.2.1\thost\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        let model = HostsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.entries, vec![entry("192.0.2.1", &["host"], None)]);
        Ok(())
    }

    #[test]
    fn a_lone_carriage_return_line_round_trips_as_unknown() -> Result<(), String> {
        let src = "\r\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn crlf_hosts_fixture_round_trips_exactly() -> Result<(), String> {
        let src = "127.0.0.1\tlocalhost\r\n::1\tlocalhost\r\n";
        let doc = HostsModule::parse(src).map_err(|e| e.to_string())?;
        assert_eq!(HostsModule::render(&doc), src);
        Ok(())
    }

    // ----------------------------------------------------------------- fuzzing

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_entries_are_rfc1123_valid_and_apply_cleanly() -> Result<(), String> {
        use arbitrary::{Arbitrary, Unstructured};

        // Enough varied bytes to drive several label and comment lengths, a
        // multi-label hostname, and both branches of the `comment.is_some()` coin
        // flip, on both the IPv4 and IPv6 arms of `IpAddr::arbitrary`.
        let buffers: &[&[u8]] = &[
            &[0; 64],
            &[0xff; 64],
            &[
                1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 0, 1, 2, 3, 4, 5, 6,
                7, 8, 9, 10, 1, 1,
            ],
            &(0u8..80).collect::<Vec<u8>>(),
        ];
        for data in buffers {
            let mut u = Unstructured::new(data);
            let model = Model::arbitrary(&mut u).unwrap_or_default();
            for e in &model.entries {
                assert!(!e.hostnames.is_empty());
                for name in &e.hostnames {
                    assert!(is_valid_hostname(name), "generated invalid name {name:?}");
                }
            }
            let mut doc = HostsModule::parse("").map_err(|e| e.to_string())?;
            let report = HostsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report.added, model.entries.len());
        }
        Ok(())
    }
}
