//! The `dhcp` module: `dnsmasq.conf` and Kea DHCPv4/v6 configuration.
//!
//! One module, two backends (PLAN §8 dhcp row):
//!
//! * `dnsmasq.conf` — the dnsmasq line format: `key=value`, bare flags
//!   (`domain-needed`), `#` comment lines and blank lines. A line that is none
//!   of those is [`LineKind::Unknown`] and is copied through an edit untouched,
//!   External-file directives remain modeled only so validation can flag them;
//!   the renderer refuses to create or modify them.
//! * `/etc/kea/kea-dhcp4.conf` and `kea-dhcp6.conf` — Kea's JSON with
//!   comments. See [the JSONC CST](#the-jsonc-cst) below.
//!
//! # The JSONC CST
//!
//! Kea configuration is JSON with `//` and `/* */` comments. `serde_json`
//! cannot represent either, so this crate carries its own lossless JSONC
//! concrete syntax tree, [`Jsonc`] → [`Obj`]/[`Arr`]/[`Lit`]. The design rule
//! is: **every byte of the source lives in exactly one field of exactly one
//! node**, so [`LosslessDoc::render`] is a plain concatenation and
//! `render(parse(s)) == s` holds by construction rather than by bookkeeping.
//!
//! ```text
//! Obj   { open,   members: Vec<Member>,                       close }
//! Member{ key,    colon, value: Jsonc,  post, comma, tail }
//! Arr   { open,   items:  Vec<ArrItem>,                       close }
//! ArrItem{ value: Jsonc, post, comma, tail }
//! Lit   { Str { raw, value } | Raw(raw) }   // numbers, true/false/null
//! ```
//!
//! `open` is `{`/`[` plus the trivia (whitespace and comments) after it;
//! `close` is the trivia before `}`/`]` plus the bracket. Each member/item
//! owns the trivia chunks around it: `colon` is trivia + `:` + trivia, `post`
//! the trivia between the value and the comma, `comma` the comma itself, and
//! `tail` the trivia between the comma and the next member. Comments are just
//! trivia — they need no node of their own and survive untouched.
//!
//! The model sees only a fixed set of *managed* keys (top-level
//! `interfaces-config`, `valid-lifetime` and `subnet4`/`subnet6`; inside a
//! subnet `id`, `subnet`, `pools` and the `routers`/`domain-name-servers`
//! entries of `option-data`). Everything else — unknown top-level keys such as
//! `Logging`, unknown members of `interfaces-config` such as
//! `dhcp-socket-type`, unknown options inside `option-data`, unknown members
//! of a subnet — is preserved untouched, the JSON analog of an `Unknown` line.
//! Lists pair model entries with *modeled* document entries in order
//! (unmodeled entries are skipped, never paired), so an edit touches only the
//! entries that actually changed. One deliberate ceiling: when a managed
//! value *does* change, its replacement is written canonically (compact JSON),
//! so comments that decorate a changed value do not survive that one rewrite —
//! trivia around the change does.
//!
//! # Format dispatch
//!
//! [`DhcpDoc`] is an enum: input that sniffs as JSONC (optional trivia, then
//! `{`) *and* parses cleanly *and* carries a `Dhcp4` or `Dhcp6` key becomes a
//! Kea document; everything else — including malformed JSONC, which then
//! classifies as dnsmasq `Unknown` lines — becomes a dnsmasq
//! [`Document`]. `parse` is therefore total, and each document applies only
//! the model section that matches its format: applying dnsmasq settings to a
//! Kea file (or the wrong Kea flavor, or vice versa) is
//! [`EditError::Unsupported`], never a silent mismatch.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time. `detent-platform`
//! owns every file operation (PLAN §2.1).

use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, FieldHints, HostProfile, ModuleDescriptor, Os,
    Owner, PathSpec, SecurityImpact, ServiceAction, ServiceBinding, Target, TargetKind, UiGroup,
    UnitNames, Upstream, ValidationCtx, apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, LineKind};
use detent_core::module::{
    ConfigModule, EditError, EditReport, LosslessDoc, ModelError, ParseError,
};
use std::net::IpAddr;

// ------------------------------------------------------------------------- model

/// One dnsmasq setting: `key=value`, or a bare flag when `value` is `None`.
///
/// Rules that are not negotiable (PLAN §2.3, Appendix A):
///
/// * `#[serde(deny_unknown_fields)]` on **every** struct: the JSON that reaches
///   `apply` comes from the web API and the C ABI, so a typo in a field name
///   must be a loud [`ModelError::Shape`], never a silently dropped setting.
/// * Derive [`schemars::JsonSchema`]; the UI is generated from it.
/// * Model semantics, not syntax — no spans, no comments.
/// * Every field needs a doc comment: `missing_docs` is on and the text is
///   what the schema shows.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct DnsmasqSetting {
    /// The option name, one word, no whitespace, no `=`.
    pub key: String,
    /// The value after `=`; `None` for a bare flag such as `domain-needed`.
    pub value: Option<String>,
}

/// One Kea address pool: `{"pool": "192.168.1.100 - 192.168.1.200"}`.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct KeaPool {
    /// The pool range or prefix, exactly as Kea accepts it.
    pub pool: String,
}

/// One Kea subnet, shared by the `DHCPv4` and `DHCPv6` models.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct KeaSubnet {
    /// Kea's stable subnet identifier.
    pub id: u32,
    /// The subnet prefix, e.g. `192.168.1.0/24`.
    pub subnet: String,
    /// The dynamic address pools of the subnet.
    pub pools: Vec<KeaPool>,
    /// The `routers` option data, one entry per `option-data` item.
    pub routers: Vec<String>,
    /// The `domain-name-servers` option data, one entry per `option-data` item.
    #[serde(rename = "domain-name-servers")]
    pub domain_servers: Vec<String>,
}

/// One Kea server configuration (the contents of `Dhcp4` or `Dhcp6`).
///
/// Only the managed subset of Kea's options; everything else in the file is
/// preserved untouched by an edit.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct KeaConfig {
    /// Interfaces the server listens on (`interfaces-config.interfaces`).
    pub interfaces: Vec<String>,
    /// The default lease lifetime in seconds (`valid-lifetime`).
    #[serde(rename = "valid-lifetime")]
    pub valid_lifetime: Option<u32>,
    /// The configured subnets (`subnet4` or `subnet6`).
    pub subnets: Vec<KeaSubnet>,
}

/// The typed model of the whole module: dnsmasq settings plus both Kea
/// servers. A document only ever carries one backend's section; the other
/// sections stay at their default, and `apply` refuses a model whose
/// non-default sections do not match the document's format.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The `dnsmasq.conf` settings, in file order.
    pub dnsmasq: Vec<DnsmasqSetting>,
    /// The Kea `DHCPv4` server (`kea-dhcp4.conf`).
    pub kea_v4: KeaConfig,
    /// The Kea `DHCPv6` server (`kea-dhcp6.conf`).
    pub kea_v6: KeaConfig,
}

// --------------------------------------------------------------- dnsmasq format

/// External-file directives are modeled for diagnostics but never rendered.
const INCLUDE_KEYS: &[&str] = &["conf-file", "conf-dir", "include", "includedir", "script"];

/// Parses one dnsmasq line as a setting, or `None` when it is not one.
///
/// The whole grammar of the format, and a total function: blank lines and
/// `#` comments are rejected here so [`classify_dnsmasq`] can rely on it
/// alone. A key must be one whitespace-free word; anything else (multi-word
/// lines without `=`, an empty key before `=`) stays `Unknown`.
fn parse_dnsmasq(raw: &str) -> Option<DnsmasqSetting> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if let Some((key, value)) = trimmed.split_once('=') {
        let key = key.trim();
        if !is_valid_dnsmasq_key(key) {
            return None;
        }
        Some(DnsmasqSetting {
            key: key.to_owned(),
            value: Some(value.trim().to_owned()),
        })
    } else {
        if !is_valid_dnsmasq_key(trimmed) {
            return None;
        }
        Some(DnsmasqSetting {
            key: trimmed.to_owned(),
            value: None,
        })
    }
}

/// Classifies a dnsmasq line for the lossless document model.
///
/// A pure function of the line text alone: `Document` re-runs it after every
/// edit. `Directive` means exactly "the entry parser succeeds", or invariant 2
/// breaks.
fn classify_dnsmasq(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with('#') {
        LineKind::Comment
    } else if parse_dnsmasq(raw).is_some() {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

/// Renders a dnsmasq setting as a line, refusing anything that would not
/// round-trip.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when the key or value carries `\n`, `\r` or
/// NUL (invariant 5), and [`EditError::Unsupported`] when the rendered line
/// does not parse back to the same setting — a key containing whitespace,
/// `=`, or `#`, or a value with leading/trailing whitespace.
fn render_dnsmasq(setting: &DnsmasqSetting) -> Result<String, EditError> {
    if INCLUDE_KEYS.contains(&setting.key.to_ascii_lowercase().as_str()) {
        return Err(EditError::Unsupported {
            message: format!(
                "external-file directive cannot be rendered: {}",
                setting.key
            ),
        });
    }
    let raw = match &setting.value {
        Some(value) => format!("{}={}", setting.key, value),
        None => setting.key.clone(),
    };
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue { value: raw });
    }
    if parse_dnsmasq(&raw).as_ref() != Some(setting) {
        return Err(EditError::Unsupported {
            message: format!("setting does not round-trip through the file format: {raw:?}"),
        });
    }
    Ok(raw)
}

/// Applies dnsmasq settings to a dnsmasq [`Document`] with the minimal-edit
/// two-pass shape shared with `hosts` and `chrony`.
///
/// Pass 1 is read-only: every changed line is rendered *before* the document
/// is touched, so a rejected value leaves the file exactly as it was. Pass 2
/// rewrites, drops and appends; new lines go after the last existing setting
/// so a trailing comment block stays trailing.
///
/// # Errors
///
/// As [`render_dnsmasq`].
fn apply_dnsmasq(doc: &mut Document, settings: &[DnsmasqSetting]) -> Result<EditReport, EditError> {
    let mut planned: Vec<Option<String>> = Vec::with_capacity(settings.len());
    for line in doc
        .lines()
        .iter()
        .filter(|l| l.kind() == LineKind::Directive)
    {
        let Some(wanted) = settings.get(planned.len()) else {
            break;
        };
        let unchanged = parse_dnsmasq(line.raw()).as_ref() == Some(wanted);
        planned.push(if unchanged {
            None
        } else {
            Some(render_dnsmasq(wanted)?)
        });
    }
    for wanted in settings.iter().skip(planned.len()) {
        planned.push(Some(render_dnsmasq(wanted)?));
    }

    let mut report = EditReport::default();
    let mut index = 0usize;
    let mut matched = 0usize;
    let mut after_last_directive: Option<usize> = None;
    while index < doc.len() {
        if doc.lines().get(index).map(detent_core::doc::Line::kind) != Some(LineKind::Directive) {
            index = index.saturating_add(1);
            continue;
        }
        let Some(slot) = planned.get(matched) else {
            doc.remove_line(index)?;
            report.removed = report.removed.saturating_add(1);
            continue;
        };
        if let Some(raw) = slot.as_deref() {
            doc.replace_raw(index, raw)?;
            report.changed_lines = report.changed_lines.saturating_add(1);
        }
        matched = matched.saturating_add(1);
        index = index.saturating_add(1);
        after_last_directive = Some(index);
    }
    let mut at = after_last_directive.unwrap_or_else(|| doc.len());
    for raw in planned.iter().skip(matched).flatten() {
        doc.insert_line(at, raw)?;
        at = at.saturating_add(1);
        report.added = report.added.saturating_add(1);
    }
    Ok(report)
}

// ------------------------------------------------------------------ JSONC lexer

/// Maximum nesting depth accepted by the JSONC parser. Deeper input falls back
/// to the dnsmasq classifier (`Unknown` lines), which keeps `parse` total and
/// bounded: unbounded recursion on adversarial nesting would overflow the
/// stack inside a fuzz target.
const MAX_JSONC_DEPTH: usize = 128;

/// Whether `src` looks like a JSONC document: optional trivia, then `{`.
///
/// A pure function of the text; `parse` uses it as a cheap sniff before
/// committing to the JSONC grammar.
fn sniffs_jsonc(src: &str) -> bool {
    let bytes = src.as_bytes();
    let mut index = 0usize;
    loop {
        match bytes.get(index) {
            Some(b' ' | b'\t' | b'\r' | b'\n') => {
                index = index.saturating_add(1);
            }
            Some(b'/') => match (bytes.get(index.saturating_add(1)), bytes.get(index)) {
                (Some(b'*'), _) => {
                    index = index.saturating_add(2);
                    loop {
                        match (bytes.get(index), bytes.get(index.saturating_add(1))) {
                            (None, _) => return false,
                            (Some(b'*'), Some(b'/')) => {
                                index = index.saturating_add(2);
                                break;
                            }
                            _ => index = index.saturating_add(1),
                        }
                    }
                }
                // The tuple is (next, current) and `current` is always
                // `/` here, so this arm is the line-comment case (a lone
                // `/` at EOF consumes to the end either way).
                _ => {
                    while !matches!(bytes.get(index), None | Some(b'\n')) {
                        index = index.saturating_add(1);
                    }
                }
            },
            _ => break,
        }
    }
    bytes.get(index) == Some(&b'{')
}

/// Decodes a JSON string literal (including its quotes) to its value.
///
/// Returns `None` on anything the JSON grammar rejects — an unknown escape or
/// a lone surrogate — so the whole document falls back to the dnsmasq
/// classifier instead of a lossy guess.
fn decode_json_string(raw: &str) -> Option<String> {
    // `raw` must be a complete quoted token, quotes included.
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        return None;
    }
    let inner = raw.get(1..raw.len().saturating_sub(1))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let first = decode_hex4(&mut chars)?;
                let scalar = if (0xD800..=0xDBFF).contains(&first) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let second = decode_hex4(&mut chars)?;
                    if !(0xDC00..=0xDFFF).contains(&second) {
                        return None;
                    }
                    0x1_0000u32
                        .wrapping_add(first.wrapping_sub(0xD800).wrapping_shl(10))
                        .wrapping_add(second.wrapping_sub(0xDC00))
                } else {
                    first
                };
                out.push(char::try_from(scalar).ok()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Reads four hex digits as a scalar value.
fn decode_hex4(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..4 {
        value = value
            .checked_mul(16)?
            .checked_add(chars.next()?.to_digit(16)?)?;
    }
    Some(value)
}

/// Escapes `s` as the body of a JSON string literal (without the quotes).
fn json_escape(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

// ------------------------------------------------------------------ JSONC CST

/// A leaf JSONC value: a string literal (raw token plus decoded value) or a
/// number/keyword run kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lit {
    /// A quoted string: `raw` is the exact source token, `value` its decoded
    /// content.
    Str {
        /// The exact source token, quotes and escapes included.
        raw: String,
        /// The decoded string value.
        value: String,
    },
    /// A number, `true`, `false` or `null`, kept as written.
    Raw(String),
}

impl Lit {
    /// The decoded value of a string literal.
    fn as_str(&self) -> Option<&str> {
        match self {
            Lit::Str { value, .. } => Some(value),
            Lit::Raw(_) => None,
        }
    }

    /// The numeric value of a raw token that parses as `u32`.
    fn as_u32(&self) -> Option<u32> {
        match self {
            Lit::Raw(raw) => raw.parse().ok(),
            Lit::Str { .. } => None,
        }
    }
}

/// One `key: value` pair of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The key, as a string literal.
    pub key: Lit,
    /// Trivia between key and `:`, then the `:`, then trivia before the value.
    pub colon: String,
    /// The value.
    pub value: Jsonc,
    /// Trivia between the value and the comma; empty when there is no comma.
    pub post: String,
    /// The comma separating this member from the next; empty on the last one.
    pub comma: String,
    /// Trivia between the comma and the next member.
    pub tail: String,
}

impl Member {
    /// The decoded key name of a string-literal key.
    fn key_name(&self) -> Option<&str> {
        self.key.as_str()
    }
}

/// One element of an array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrItem {
    /// The element value.
    pub value: Jsonc,
    /// Trivia between the value and the comma; empty when there is no comma.
    pub post: String,
    /// The comma separating this item from the next; empty on the last one.
    pub comma: String,
    /// Trivia between the comma and the next item.
    pub tail: String,
}

/// A JSONC object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Obj {
    /// `{` plus the trivia after it.
    pub open: String,
    /// The members, in file order.
    pub members: Vec<Member>,
    /// The trivia before `}` plus the `}`.
    pub close: String,
}

impl Obj {
    /// The first member named `key`.
    fn member_by_key(&self, key: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.key_name() == Some(key))
    }

    /// The first member named `key`, mutably.
    fn member_mut_by_key(&mut self, key: &str) -> Option<&mut Member> {
        self.members.iter_mut().find(|m| m.key_name() == Some(key))
    }

    /// Replaces the value of the first member named `key`, or appends a
    /// canonical member when there is none.
    fn set_member(&mut self, key: &str, value: Jsonc, report: &mut EditReport) {
        if let Some(member) = self.member_mut_by_key(key) {
            member.value = value;
            report.changed_lines = report.changed_lines.saturating_add(1);
        } else {
            if let Some(last) = self.members.last_mut() {
                last.comma = ",".into();
            }
            self.members.push(Member {
                key: lit_str(key),
                colon: ":".to_owned(),
                value,
                post: String::new(),
                comma: String::new(),
                tail: String::new(),
            });
            report.added = report.added.saturating_add(1);
        }
    }

    /// Removes the first member named `key`, when present.
    fn remove_member(&mut self, key: &str, report: &mut EditReport) {
        if let Some(index) = self.members.iter().position(|m| m.key_name() == Some(key)) {
            self.members.remove(index);
            report.removed = report.removed.saturating_add(1);
        }
    }

    /// Reconstructs the exact source text of the object.
    fn render(&self) -> String {
        let mut out = String::with_capacity(64);
        out.push_str(&self.open);
        for member in &self.members {
            out.push_str(&member.key.render());
            out.push_str(&member.colon);
            out.push_str(&member.value.render());
            out.push_str(&member.post);
            out.push_str(&member.comma);
            out.push_str(&member.tail);
        }
        out.push_str(&self.close);
        out
    }
}

/// A JSONC array.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Arr {
    /// `[` plus the trivia after it.
    pub open: String,
    /// The items, in file order.
    pub items: Vec<ArrItem>,
    /// The trivia before `]` plus the `]`.
    pub close: String,
}

impl Arr {
    /// Reconstructs the exact source text of the array.
    fn render(&self) -> String {
        let mut out = String::with_capacity(64);
        out.push_str(&self.open);
        for item in &self.items {
            out.push_str(&item.value.render());
            out.push_str(&item.post);
            out.push_str(&item.comma);
            out.push_str(&item.tail);
        }
        out.push_str(&self.close);
        out
    }
}

/// A JSONC value: object, array or leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jsonc {
    /// An object.
    Obj(Obj),
    /// An array.
    Arr(Arr),
    /// A leaf token.
    Lit(Lit),
}

impl Jsonc {
    /// The object value, when this is one.
    fn as_obj(&self) -> Option<&Obj> {
        match self {
            Jsonc::Obj(obj) => Some(obj),
            _ => None,
        }
    }

    /// The object value, mutably, when this is one.
    fn as_obj_mut(&mut self) -> Option<&mut Obj> {
        match self {
            Jsonc::Obj(obj) => Some(obj),
            _ => None,
        }
    }

    /// The decoded value, when this is a string literal.
    fn as_str(&self) -> Option<&str> {
        match self {
            Jsonc::Lit(lit) => lit.as_str(),
            _ => None,
        }
    }

    /// The numeric value, when this is a raw token parsing as `u32`.
    fn as_u32(&self) -> Option<u32> {
        match self {
            Jsonc::Lit(lit) => lit.as_u32(),
            _ => None,
        }
    }

    /// Reconstructs the exact source text of the value.
    fn render(&self) -> String {
        match self {
            Jsonc::Obj(obj) => obj.render(),
            Jsonc::Arr(arr) => arr.render(),
            Jsonc::Lit(lit) => lit.render(),
        }
    }
}

impl Lit {
    /// Reconstructs the exact source text of the leaf.
    fn render(&self) -> String {
        match self {
            Lit::Str { raw, .. } | Lit::Raw(raw) => raw.clone(),
        }
    }
}

/// Builds a string literal from its decoded value.
fn lit_str(value: &str) -> Lit {
    Lit::Str {
        raw: format!("\"{}\"", json_escape(value)),
        value: value.to_owned(),
    }
}

/// Builds a canonical leaf value.
fn canon_lit(value: &str) -> Jsonc {
    Jsonc::Lit(lit_str(value))
}

/// Builds a canonical `u32` leaf.
fn canon_u32(value: u32) -> Jsonc {
    Jsonc::Lit(Lit::Raw(value.to_string()))
}

/// Builds a canonical array of string literals.
fn canon_strs(values: &[String]) -> Jsonc {
    Jsonc::Arr(Arr {
        open: "[".to_owned(),
        items: values
            .iter()
            .map(|v| ArrItem {
                value: canon_lit(v),
                post: String::new(),
                comma: ",".to_owned(),
                tail: String::new(),
            })
            .collect(),
        close: "]".to_owned(),
    })
}

/// Builds a canonical object from `(key, value)` pairs; the last member carries
/// no comma.
fn canon_obj(members: Vec<(&str, Jsonc)>) -> Jsonc {
    let count = members.len();
    Jsonc::Obj(Obj {
        open: "{".to_owned(),
        members: members
            .into_iter()
            .enumerate()
            .map(|(index, (key, value))| Member {
                key: lit_str(key),
                colon: ":".to_owned(),
                value,
                post: String::new(),
                comma: if index.saturating_add(1) < count {
                    ",".to_owned()
                } else {
                    String::new()
                },
                tail: String::new(),
            })
            .collect(),
        close: "}".to_owned(),
    })
}

/// Builds a canonical array from values; the last item carries no comma.
fn canon_arr(items: Vec<Jsonc>) -> Jsonc {
    let count = items.len();
    Jsonc::Arr(Arr {
        open: "[".to_owned(),
        items: items
            .into_iter()
            .enumerate()
            .map(|(index, value)| ArrItem {
                value,
                post: String::new(),
                comma: if index.saturating_add(1) < count {
                    ",".to_owned()
                } else {
                    String::new()
                },
                tail: String::new(),
            })
            .collect(),
        close: "]".to_owned(),
    })
}

// ------------------------------------------------------------------ JSONC parser

/// A recursive-descent JSONC parser over a `&str`.
///
/// Total and allocation-bounded: every failure is `Err(())` and every slice is
/// taken through `str::get`, so no input can panic, and the depth cap keeps
/// recursion bounded.
struct JsoncParser<'a> {
    src: &'a str,
    pos: usize,
}

impl JsoncParser<'_> {
    /// The byte at the cursor, if any.
    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    /// Consumes one byte when it matches.
    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos = self.pos.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Consumes a maximal run of whitespace and comments, returning it.
    fn trivia(&mut self) -> Result<String, ()> {
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.pos = self.pos.saturating_add(1);
                }
                Some(b'/')
                    if self.src.as_bytes().get(self.pos.saturating_add(1)) == Some(&b'*') =>
                {
                    self.pos = self.pos.saturating_add(2);
                    loop {
                        match (
                            self.peek(),
                            self.src.as_bytes().get(self.pos.saturating_add(1)),
                        ) {
                            (None, _) => return Err(()),
                            (Some(b'*'), Some(b'/')) => {
                                self.pos = self.pos.saturating_add(2);
                                break;
                            }
                            _ => self.pos = self.pos.saturating_add(1),
                        }
                    }
                }
                Some(b'/')
                    if self.src.as_bytes().get(self.pos.saturating_add(1)) == Some(&b'/') =>
                {
                    while !matches!(self.peek(), None | Some(b'\n')) {
                        self.pos = self.pos.saturating_add(1);
                    }
                }
                _ => break,
            }
        }
        self.src.get(start..self.pos).ok_or(()).map(str::to_owned)
    }

    /// Parses a quoted string literal at the cursor.
    fn parse_string_lit(&mut self) -> Result<Lit, ()> {
        let start = self.pos;
        if !self.eat(b'"') {
            return Err(());
        }
        loop {
            match self.peek() {
                None => return Err(()),
                Some(b'"') => {
                    self.pos = self.pos.saturating_add(1);
                    break;
                }
                Some(b'\\') => {
                    self.pos = self.pos.saturating_add(1);
                    self.peek().ok_or(())?;
                    self.pos = self.pos.saturating_add(1);
                }
                Some(c) if c < 0x20 => return Err(()),
                Some(_) => self.pos = self.pos.saturating_add(1),
            }
        }
        let raw = self.src.get(start..self.pos).ok_or(())?;
        let value = decode_json_string(raw).ok_or(())?;
        Ok(Lit::Str {
            raw: raw.to_owned(),
            value,
        })
    }

    /// Parses a bare token: number, `true`, `false` or `null`.
    fn parse_raw(&mut self) -> Result<Lit, ()> {
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            self.pos = self.pos.saturating_add(1);
        }
        let raw = self.src.get(start..self.pos).ok_or(())?;
        if raw.is_empty() {
            return Err(());
        }
        Ok(Lit::Raw(raw.to_owned()))
    }

    /// Parses one value at the cursor.
    fn parse_value(&mut self, depth: usize) -> Result<Jsonc, ()> {
        if depth > MAX_JSONC_DEPTH {
            return Err(());
        }
        self.trivia()?;
        match self.peek() {
            Some(b'{') => Ok(Jsonc::Obj(self.parse_obj(depth)?)),
            Some(b'[') => Ok(Jsonc::Arr(self.parse_arr(depth)?)),
            Some(b'"') => Ok(Jsonc::Lit(self.parse_string_lit()?)),
            _ => Ok(Jsonc::Lit(self.parse_raw()?)),
        }
    }

    /// Parses an object at the cursor.
    fn parse_obj(&mut self, depth: usize) -> Result<Obj, ()> {
        // `parse_value` bounds the depth; `parse_jsonc` calls this for the
        // root without peeking, so the opener is still verified.
        if !self.eat(b'{') {
            return Err(());
        }
        let mut open = String::from("{");
        open.push_str(&self.trivia()?);
        // An empty object closes here; after a member the loop only reaches a
        // key, because a trailing comma is not JSONC and falls through to the
        // `parse_string_lit` error.
        if self.eat(b'}') {
            return Ok(Obj {
                open,
                members: Vec::new(),
                close: "}".to_owned(),
            });
        }
        let mut members = Vec::new();
        let close;
        loop {
            let key = self.parse_string_lit()?;
            let pre = self.trivia()?;
            if !self.eat(b':') {
                return Err(());
            }
            let post = self.trivia()?;
            let value = self.parse_value(depth.saturating_add(1))?;
            let after = self.trivia()?;
            if self.eat(b',') {
                let tail = self.trivia()?;
                members.push(Member {
                    key,
                    colon: format!("{pre}:{post}"),
                    value,
                    post: after,
                    comma: ",".to_owned(),
                    tail,
                });
            } else {
                if !self.eat(b'}') {
                    return Err(());
                }
                members.push(Member {
                    key,
                    colon: format!("{pre}:{post}"),
                    value,
                    post: String::new(),
                    comma: String::new(),
                    tail: String::new(),
                });
                close = format!("{after}}}");
                break;
            }
        }
        Ok(Obj {
            open,
            members,
            close,
        })
    }

    /// Parses an array at the cursor.
    fn parse_arr(&mut self, depth: usize) -> Result<Arr, ()> {
        // `parse_value` bounds the depth and dispatches here only after
        // peeking `[`, so both guards live on the caller side and this
        // opener is unconditional.
        self.eat(b'[');
        let mut open = String::from("[");
        open.push_str(&self.trivia()?);
        let mut items = Vec::new();
        let close;
        loop {
            let lead = self.trivia()?;
            if self.eat(b']') {
                close = format!("{lead}]");
                break;
            }
            let value = self.parse_value(depth.saturating_add(1))?;
            let after = self.trivia()?;
            if self.eat(b',') {
                let tail = self.trivia()?;
                items.push(ArrItem {
                    value,
                    post: after,
                    comma: ",".to_owned(),
                    tail,
                });
            } else {
                if !self.eat(b']') {
                    return Err(());
                }
                items.push(ArrItem {
                    value,
                    post: String::new(),
                    comma: String::new(),
                    tail: String::new(),
                });
                close = format!("{after}]");
                break;
            }
        }
        Ok(Arr { open, items, close })
    }
}

/// Parses `src` as a JSONC document, returning the root object.
///
/// `Err` means "not JSONC after all" — malformed grammar, unterminated
/// comment, over-deep nesting — and `parse` then falls back to the dnsmasq
/// classifier, which is what keeps `parse` total.
fn parse_jsonc(src: &str) -> Result<JsoncRoot, ()> {
    let mut parser = JsoncParser { src, pos: 0 };
    let lead = parser.trivia()?;
    let root = parser.parse_obj(1)?;
    let trail = parser.trivia()?;
    if parser.pos != src.len() {
        // Trailing garbage after the root object: not JSONC after all.
        return Err(());
    }
    Ok(JsoncRoot { lead, root, trail })
}

/// The whole JSONC document: trivia before and after the root object, plus
/// the root object itself. Keeping the outside trivia is what makes
/// `// header` and a trailing newline survive `apply` byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsoncRoot {
    /// Trivia (whitespace and comments) before `{`.
    pub lead: String,
    /// The root object.
    pub root: Obj,
    /// Trivia after the root object's `}`, usually a final newline.
    pub trail: String,
}

impl JsoncRoot {
    /// Reconstructs the exact source text of the document.
    fn render(&self) -> String {
        let mut out = String::with_capacity(self.lead.len().saturating_add(64));
        out.push_str(&self.lead);
        out.push_str(&self.root.render());
        out.push_str(&self.trail);
        out
    }
}

// ------------------------------------------------------------------- Kea model

/// Which Kea daemon a JSONC document configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeaFlavor {
    /// `kea-dhcp4.conf` (`Dhcp4`, `subnet4`).
    V4,
    /// `kea-dhcp6.conf` (`Dhcp6`, `subnet6`).
    V6,
}

impl KeaFlavor {
    /// The top-level config element key: `Dhcp4` or `Dhcp6`.
    fn config_key(self) -> &'static str {
        match self {
            KeaFlavor::V4 => "Dhcp4",
            KeaFlavor::V6 => "Dhcp6",
        }
    }

    /// The subnet array key: `subnet4` or `subnet6`.
    fn subnets_key(self) -> &'static str {
        match self {
            KeaFlavor::V4 => "subnet4",
            KeaFlavor::V6 => "subnet6",
        }
    }
}

/// A Kea document: which flavor plus the lossless JSONC root.
#[derive(Debug, PartialEq)]
pub enum DhcpDoc {
    /// A `dnsmasq.conf` line-oriented document.
    Dnsmasq(Document),
    /// A Kea JSONC document.
    Kea {
        /// Which daemon the file configures.
        flavor: KeaFlavor,
        /// The lossless JSONC document: outside trivia plus root object.
        root: JsoncRoot,
    },
}

impl LosslessDoc for DhcpDoc {
    fn render(&self) -> String {
        match self {
            DhcpDoc::Dnsmasq(doc) => doc.render(),
            DhcpDoc::Kea { root, .. } => root.render(),
        }
    }
}

/// Projects the `interfaces` array of an `interfaces-config` object.
///
/// `Some(vec![])` covers both "member absent" and "array present but empty";
/// `None` marks a value the model cannot express (a non-object
/// `interfaces-config`, a non-array `interfaces`), which an edit leaves alone
/// unless it needs somewhere to write.
fn project_interfaces(inner: &Obj) -> Option<Vec<String>> {
    match inner.member_by_key("interfaces") {
        None => Some(Vec::new()),
        Some(member) => match &member.value {
            Jsonc::Arr(arr) => Some(
                arr.items
                    .iter()
                    .filter_map(|item| item.value.as_str().map(str::to_owned))
                    .collect(),
            ),
            _ => None,
        },
    }
}

/// Projects the whole `interfaces-config` member of a server config object.
fn project_interfaces_config(obj: &Obj) -> Option<Vec<String>> {
    match obj.member_by_key("interfaces-config") {
        None => Some(Vec::new()),
        Some(member) => match member.value.as_obj() {
            Some(inner) => project_interfaces(inner),
            None => None,
        },
    }
}

/// Projects `valid-lifetime`. The outer `Option` is "member present and
/// parseable", the inner "the value it holds" — the distinction an edit needs
/// (`None`/`Some(None)` = untouched vs removed).
#[allow(clippy::option_option)]
fn project_valid_lifetime(obj: &Obj) -> Option<Option<u32>> {
    match obj.member_by_key("valid-lifetime") {
        None => Some(None),
        Some(member) => member.value.as_u32().map(Some),
    }
}

/// Projects one pool object to its `pool` string.
fn project_pool(value: &Jsonc) -> Option<String> {
    value
        .as_obj()
        .and_then(|obj| obj.member_by_key("pool"))
        .and_then(|member| member.value.as_str())
        .map(str::to_owned)
}

/// Projects the `pools` member of a subnet object.
fn project_pools(obj: &Obj) -> Option<Vec<String>> {
    match obj.member_by_key("pools") {
        None => Some(Vec::new()),
        Some(member) => match &member.value {
            Jsonc::Arr(arr) => Some(
                arr.items
                    .iter()
                    .filter_map(|item| project_pool(&item.value))
                    .collect(),
            ),
            _ => None,
        },
    }
}

/// The two managed option-data lists of a subnet object: routers and
/// domain-name-servers. Each modeled entry contributes its `data` string
/// verbatim — Kea's comma-separated form is the admin's business, not the
/// model's, and keeping entries 1:1 with model strings is what makes an edit
/// byte-minimal.
fn project_option_data(obj: &Obj) -> (Vec<String>, Vec<String>) {
    let mut routers = Vec::new();
    let mut domain_servers = Vec::new();
    let Some(member) = obj.member_by_key("option-data") else {
        return (routers, domain_servers);
    };
    let Jsonc::Arr(arr) = &member.value else {
        return (routers, domain_servers);
    };
    for item in &arr.items {
        let Some(entry) = item.value.as_obj() else {
            continue;
        };
        let (Some(name), Some(data)) = (
            entry.member_by_key("name").and_then(|m| m.value.as_str()),
            entry.member_by_key("data").and_then(|m| m.value.as_str()),
        ) else {
            continue;
        };
        if name == "routers" {
            routers.push(data.to_owned());
        } else if name == "domain-name-servers" {
            domain_servers.push(data.to_owned());
        }
    }
    (routers, domain_servers)
}

/// Projects one subnet object. `None` marks a subnet the model cannot express
/// (missing `id`/`subnet`, a non-array `pools`), which an edit preserves as if
/// it were an `Unknown` line.
fn project_subnet(obj: &Obj) -> Option<KeaSubnet> {
    Some(KeaSubnet {
        id: obj.member_by_key("id")?.value.as_u32()?,
        subnet: obj.member_by_key("subnet")?.value.as_str()?.to_owned(),
        pools: project_pools(obj)?
            .into_iter()
            .map(|pool| KeaPool { pool })
            .collect(),
        routers: project_option_data(obj).0,
        domain_servers: project_option_data(obj).1,
    })
}

/// Projects the subnets array of a server config object.
fn project_subnets(obj: &Obj, subnets_key: &str) -> Option<Vec<KeaSubnet>> {
    match obj.member_by_key(subnets_key) {
        None => Some(Vec::new()),
        Some(member) => match &member.value {
            Jsonc::Arr(arr) => Some(
                arr.items
                    .iter()
                    .filter_map(|item| item.value.as_obj().and_then(project_subnet))
                    .collect(),
            ),
            _ => None,
        },
    }
}

/// Projects the whole managed subset of a server config object.
fn project_kea_config(obj: &Obj, flavor: KeaFlavor) -> KeaConfig {
    KeaConfig {
        interfaces: project_interfaces_config(obj).unwrap_or_default(),
        valid_lifetime: project_valid_lifetime(obj).unwrap_or(None),
        subnets: project_subnets(obj, flavor.subnets_key()).unwrap_or_default(),
    }
}

/// Builds a canonical `interfaces-config` object.
fn canon_interfaces_config(interfaces: &[String]) -> Jsonc {
    canon_obj(vec![("interfaces", canon_strs(interfaces))])
}

/// Builds a canonical option-data entry.
fn canon_option_entry(name: &str, data: &str) -> Jsonc {
    canon_obj(vec![("name", canon_lit(name)), ("data", canon_lit(data))])
}

/// Builds a canonical subnet object from the model.
fn canon_subnet(subnet: &KeaSubnet) -> Jsonc {
    let mut members = vec![
        ("id", canon_u32(subnet.id)),
        ("subnet", canon_lit(&subnet.subnet)),
    ];
    if !subnet.pools.is_empty() {
        let pools = subnet
            .pools
            .iter()
            .map(|p| canon_obj(vec![("pool", canon_lit(&p.pool))]))
            .collect();
        members.push(("pools", canon_arr(pools)));
    }
    let mut options = Vec::new();
    for router in &subnet.routers {
        options.push(canon_option_entry("routers", router));
    }
    for server in &subnet.domain_servers {
        options.push(canon_option_entry("domain-name-servers", server));
    }
    if !options.is_empty() {
        members.push(("option-data", canon_arr(options)));
    }
    canon_obj(members)
}

/// Builds a canonical subnets array from the model.
fn canon_subnets(subnets: &[KeaSubnet]) -> Jsonc {
    canon_arr(subnets.iter().map(canon_subnet).collect())
}

/// Builds a canonical pools array from the model.
fn canon_pools(pools: &[String]) -> Jsonc {
    canon_arr(
        pools
            .iter()
            .map(|pool| canon_obj(vec![("pool", canon_lit(pool))]))
            .collect(),
    )
}

/// Builds a canonical option-data array for the managed entries.
fn canon_option_data(routers: &[String], domain_servers: &[String]) -> Jsonc {
    let mut entries: Vec<Jsonc> = routers
        .iter()
        .map(|r| canon_option_entry("routers", r))
        .collect();
    entries.extend(
        domain_servers
            .iter()
            .map(|d| canon_option_entry("domain-name-servers", d)),
    );
    canon_arr(entries)
}

/// Appends canonical items to an array's item list, fixing the previous last
/// item's comma.
fn append_items(items: &mut Vec<ArrItem>, fresh: Vec<ArrItem>, report: &mut EditReport) {
    for item in fresh {
        if let Some(last) = items.last_mut() {
            last.comma = ",".into();
        }
        items.push(item);
        report.added = report.added.saturating_add(1);
    }
}

/// Pairs model items with the *modeled* items of an array in order and rewrites
/// only the ones that differ; unmodeled items are skipped and preserved, extra
/// modeled items are removed, extra model items are appended canonically.
fn sync_modeled_items<P, F, G>(
    items: &mut Vec<ArrItem>,
    wanted: &[P],
    project: F,
    render: G,
    report: &mut EditReport,
) where
    P: PartialEq,
    F: Fn(&Jsonc) -> Option<P>,
    G: Fn(&P) -> Jsonc,
{
    let mut matched = 0usize;
    let mut index = 0usize;
    while index < items.len() {
        let modeled = items.get(index).and_then(|item| project(&item.value));
        if modeled.is_some() && matched >= wanted.len() {
            items.remove(index);
            report.removed = report.removed.saturating_add(1);
            continue;
        }
        if modeled.is_none() {
            index = index.saturating_add(1);
            continue;
        }
        if let (Some(item), Some(wanted_item)) = (items.get_mut(index), wanted.get(matched))
            && project(&item.value).as_ref() != Some(wanted_item)
        {
            item.value = render(wanted_item);
            report.changed_lines = report.changed_lines.saturating_add(1);
        }
        matched = matched.saturating_add(1);
        index = index.saturating_add(1);
    }
    let fresh: Vec<ArrItem> = wanted
        .iter()
        .skip(matched)
        .map(|wanted_item| ArrItem {
            value: render(wanted_item),
            post: String::new(),
            comma: String::new(),
            tail: String::new(),
        })
        .collect();
    append_items(items, fresh, report);
}

/// Rewrites one modeled list member of `obj`: absent means "add canonically
/// only when the model needs somewhere to write"; an existing array is synced
/// entry-wise ([`sync_modeled_items`]); a non-array member is unmodeled and
/// replaced wholesale only when the model needs somewhere to write.
///
/// This backs the `interfaces` and `pools` lists; subnets get their own loop
/// because a changed subnet is merged member-wise rather than replaced whole.
fn sync_list_member<P, F, G, H>(
    obj: &mut Obj,
    key: &str,
    want: &[P],
    project: F,
    render_item: G,
    render_member: H,
    report: &mut EditReport,
) where
    P: PartialEq,
    F: Fn(&Jsonc) -> Option<P>,
    G: Fn(&P) -> Jsonc,
    H: Fn(&[P]) -> Jsonc,
{
    let Some(member) = obj.member_mut_by_key(key) else {
        if !want.is_empty() {
            obj.set_member(key, render_member(want), report);
        }
        return;
    };
    match &mut member.value {
        Jsonc::Arr(arr) => {
            sync_modeled_items(&mut arr.items, want, project, render_item, report);
        }
        // A non-array member is unmodeled garbage. For `pools` this edge is
        // unreachable: a non-array member made the subnet unmodeled in
        // `project_subnet`, so the subnet never reaches `merge_subnet`.
        _ if !want.is_empty() => {
            member.value = render_member(want);
            report.changed_lines = report.changed_lines.saturating_add(1);
        }
        _ => {}
    }
}

/// Rewrites the `interfaces-config` member of a server config object.
fn apply_interfaces_config(obj: &mut Obj, want: &[String], report: &mut EditReport) {
    let current = project_interfaces_config(obj);
    if current.as_deref() == Some(want) {
        return;
    }
    let Some(member) = obj.member_mut_by_key("interfaces-config") else {
        if !want.is_empty() {
            obj.set_member("interfaces-config", canon_interfaces_config(want), report);
        }
        return;
    };
    match &mut member.value {
        Jsonc::Obj(inner) => sync_list_member(
            inner,
            "interfaces",
            want,
            |value| value.as_str().map(str::to_owned),
            |s| canon_lit(s),
            canon_strs,
            report,
        ),
        _ if !want.is_empty() => {
            member.value = canon_interfaces_config(want);
            report.changed_lines = report.changed_lines.saturating_add(1);
        }
        _ => {}
    }
}

/// Rewrites the `valid-lifetime` member of a server config object.
fn apply_valid_lifetime(obj: &mut Obj, want: Option<u32>, report: &mut EditReport) {
    let current = project_valid_lifetime(obj);
    if current.as_ref() == Some(&want) {
        return;
    }
    match obj.member_mut_by_key("valid-lifetime") {
        None => {
            if let Some(lifetime) = want {
                obj.set_member("valid-lifetime", canon_u32(lifetime), report);
            }
        }
        Some(member) => match &member.value {
            Jsonc::Lit(Lit::Raw(raw)) if raw.parse::<u32>().is_ok() => {
                if want.is_none() {
                    obj.remove_member("valid-lifetime", report);
                } else if let Some(lifetime) = want {
                    member.value = canon_u32(lifetime);
                    report.changed_lines = report.changed_lines.saturating_add(1);
                }
            }
            // Unmodeled garbage: replace only when the model wants a value.
            _ => {
                if let Some(lifetime) = want {
                    member.value = canon_u32(lifetime);
                    report.changed_lines = report.changed_lines.saturating_add(1);
                }
            }
        },
    }
}

/// Merges one modeled subnet pair member-wise, so unknown members of the
/// subnet (`interface`, unknown `option-data`, …) survive an edit.
fn merge_subnet(obj: &mut Obj, want: &KeaSubnet, report: &mut EditReport) {
    if project_subnet(obj).as_ref() == Some(want) {
        return;
    }
    if obj.member_by_key("id").and_then(|m| m.value.as_u32()) != Some(want.id) {
        obj.set_member("id", canon_u32(want.id), report);
    }
    if obj.member_by_key("subnet").and_then(|m| m.value.as_str()) != Some(want.subnet.as_str()) {
        obj.set_member("subnet", canon_lit(&want.subnet), report);
    }
    let want_pools: Vec<String> = want.pools.iter().map(|p| p.pool.clone()).collect();
    // A non-array `pools` made the subnet unmodeled (see `project_subnet`),
    // so only an array reaches the sync and the wholesale-replacement edge
    // below cannot fire here.
    sync_list_member(
        obj,
        "pools",
        &want_pools,
        project_pool,
        |pool| canon_obj(vec![("pool", canon_lit(pool))]),
        canon_pools,
        report,
    );
    let current = project_option_data(obj);
    if current.0 == want.routers && current.1 == want.domain_servers {
        return;
    }
    match obj.member_mut_by_key("option-data") {
        None => {
            if !want.routers.is_empty() || !want.domain_servers.is_empty() {
                obj.set_member(
                    "option-data",
                    canon_option_data(&want.routers, &want.domain_servers),
                    report,
                );
            }
        }
        Some(member) => {
            // One sync pass per managed option name: a pass projects only
            // entries carrying its `name`, so `routers` entries pair with
            // `want.routers` in order, `domain-name-servers` with
            // `want.domain_servers`, and every other entry (Kea's other
            // options, garbage) is skipped and preserved.
            if let Jsonc::Arr(arr) = &mut member.value {
                sync_modeled_items(
                    &mut arr.items,
                    &want.routers,
                    |value| named_data(value, "routers"),
                    |data| canon_option_entry("routers", data),
                    report,
                );
                sync_modeled_items(
                    &mut arr.items,
                    &want.domain_servers,
                    |value| named_data(value, "domain-name-servers"),
                    |data| canon_option_entry("domain-name-servers", data),
                    report,
                );
            } else if !want.routers.is_empty() || !want.domain_servers.is_empty() {
                member.value = canon_option_data(&want.routers, &want.domain_servers);
                report.changed_lines = report.changed_lines.saturating_add(1);
            }
        }
    }
}

/// The `data` of an option-data entry whose `name` is exactly `wanted`, or
/// `None` for anything else (other options, malformed entries) so the sync
/// pass treats it as unmodeled and leaves it alone.
fn named_data(value: &Jsonc, wanted: &str) -> Option<String> {
    let entry = value.as_obj()?;
    if entry.member_by_key("name").and_then(|m| m.value.as_str()) != Some(wanted) {
        return None;
    }
    entry
        .member_by_key("data")
        .and_then(|m| m.value.as_str())
        .map(str::to_owned)
}

/// Pairs model subnets with the modeled subnet items of the `subnet4`/`subnet6`
/// array, in order, merging each pair member-wise.
fn sync_subnets(items: &mut Vec<ArrItem>, wanted: &[KeaSubnet], report: &mut EditReport) {
    let mut matched = 0usize;
    let mut index = 0usize;
    while index < items.len() {
        let modeled = items
            .get(index)
            .and_then(|item| item.value.as_obj())
            .and_then(project_subnet);
        if modeled.is_some() && matched >= wanted.len() {
            items.remove(index);
            report.removed = report.removed.saturating_add(1);
            continue;
        }
        if modeled.is_none() {
            index = index.saturating_add(1);
            continue;
        }
        if let (Some(item), Some(wanted_subnet)) = (items.get_mut(index), wanted.get(matched))
            && let Jsonc::Obj(obj) = &mut item.value
        {
            merge_subnet(obj, wanted_subnet, report);
        }
        matched = matched.saturating_add(1);
        index = index.saturating_add(1);
    }
    let fresh: Vec<ArrItem> = wanted
        .iter()
        .skip(matched)
        .map(|wanted_subnet| ArrItem {
            value: canon_subnet(wanted_subnet),
            post: String::new(),
            comma: String::new(),
            tail: String::new(),
        })
        .collect();
    append_items(items, fresh, report);
}

/// Rewrites the subnets array of a server config object.
fn apply_subnets(obj: &mut Obj, flavor: KeaFlavor, want: &[KeaSubnet], report: &mut EditReport) {
    let key = flavor.subnets_key();
    let current = project_subnets(obj, key);
    if current.as_deref() == Some(want) {
        return;
    }
    let Some(member) = obj.member_mut_by_key(key) else {
        if !want.is_empty() {
            obj.set_member(key, canon_subnets(want), report);
        }
        return;
    };
    match &mut member.value {
        Jsonc::Arr(arr) => sync_subnets(&mut arr.items, want, report),
        _ if !want.is_empty() => {
            member.value = canon_subnets(want);
            report.changed_lines = report.changed_lines.saturating_add(1);
        }
        _ => {}
    }
}

/// Applies one Kea server's model section to its config object, then
/// renormalizes the whole tree by re-parsing its own render, so the edited
/// document is always exactly `parse(render(doc))` (invariant 4 holds even
/// after edits redistribute trivia between a member's fields).
fn apply_kea_config(
    root: &mut Obj,
    flavor: KeaFlavor,
    config: &KeaConfig,
    report: &mut EditReport,
) -> Result<(), EditError> {
    let default = KeaConfig::default();
    let Some(member) = root.member_mut_by_key(flavor.config_key()) else {
        // Unreachable from `parse` (a Kea document always carries its flavor
        // key) but reachable from a hand-built doc: refuse non-default
        // content instead of silently dropping it.
        return if *config == default {
            Ok(())
        } else {
            Err(EditError::Unsupported {
                message: format!(
                    "the {} element of the Kea configuration file is missing",
                    flavor.config_key()
                ),
            })
        };
    };
    let Some(obj) = member.value.as_obj_mut() else {
        return if *config == default {
            Ok(())
        } else {
            Err(EditError::Unsupported {
                message: format!(
                    "the {} element of the Kea configuration file is not an object",
                    flavor.config_key()
                ),
            })
        };
    };
    apply_interfaces_config(obj, &config.interfaces, report);
    apply_valid_lifetime(obj, config.valid_lifetime, report);
    apply_subnets(obj, flavor, &config.subnets, report);
    let text = obj.render();
    let fresh = parse_jsonc(&text).map_err(|()| EditError::Unsupported {
        message: "the Kea configuration element failed to re-parse after an edit".to_owned(),
    })?;
    member.value = Jsonc::Obj(fresh.root);
    Ok(())
}

/// The Kea flavor of a root object: `Dhcp4` present means v4, `Dhcp6` v6,
/// anything else "not Kea after all".
fn kea_flavor(root: &Obj) -> Option<KeaFlavor> {
    if root.member_by_key("Dhcp4").is_some() {
        Some(KeaFlavor::V4)
    } else if root.member_by_key("Dhcp6").is_some() {
        Some(KeaFlavor::V6)
    } else {
        None
    }
}

/// Rejects model strings that would break out of their JSON string on a
/// literal-minded consumer: `\n`, `\r` or NUL never reach the file (invariant
/// 5).
fn check_kea_injection(config: &KeaConfig) -> Result<(), EditError> {
    let mut strings: Vec<&str> = config.interfaces.iter().map(String::as_str).collect();
    for subnet in &config.subnets {
        strings.push(&subnet.subnet);
        strings.extend(subnet.pools.iter().map(|p| p.pool.as_str()));
        strings.extend(subnet.routers.iter().map(String::as_str));
        strings.extend(subnet.domain_servers.iter().map(String::as_str));
    }
    for value in strings {
        if value.contains(['\n', '\r', '\0']) {
            return Err(EditError::LineBreakInValue {
                value: value.to_owned(),
            });
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- descriptor

/// Whether this backend is the right one for `profile`: every target of this
/// module lives under `/etc` on Linux only (ADR-013).
fn linux_only(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

/// The files this module owns. Paths are `&'static` templates and are **never**
/// user-supplied (PLAN §2.3).
static TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/dnsmasq.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: linux_only,
    },
    Target {
        path: PathSpec::new("/etc/dnsmasq.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: linux_only,
    },
    Target {
        path: PathSpec::new("/etc/kea/kea-dhcp4.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: linux_only,
    },
    Target {
        path: PathSpec::new("/etc/kea/kea-dhcp6.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: linux_only,
    },
];

/// The upstream validators run against candidate files before they are
/// installed: `dnsmasq --test` parses a configuration file without starting
/// the daemon, and `kea-dhcp4 -t` / `kea-dhcp6 -t` do the same for Kea.
static CHECKS: &[ExternalCheck] = &[
    ExternalCheck {
        program: PathSpec::new("/usr/sbin/dnsmasq"),
        args: &[
            ArgTemplate::Literal("--test"),
            ArgTemplate::Literal("-C"),
            ArgTemplate::TempFile,
        ],
        expects: CheckExpectation::ExitZero,
    },
    ExternalCheck {
        program: PathSpec::new("/usr/sbin/kea-dhcp4"),
        args: &[ArgTemplate::Literal("-t"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    },
    ExternalCheck {
        program: PathSpec::new("/usr/sbin/kea-dhcp6"),
        args: &[ArgTemplate::Literal("-t"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    },
];

/// The services a change to these files affects. A bad DHCP config cuts every
/// client off the network, so restart is the only sane action for Kea;
/// dnsmasq reloads on SIGHUP.
static SERVICES: &[ServiceBinding] = &[
    ServiceBinding {
        units: UnitNames {
            systemd: &["dnsmasq.service"],
            openrc: &["dnsmasq"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Reload, ServiceAction::Restart],
    },
    ServiceBinding {
        units: UnitNames {
            systemd: &["kea-dhcp4-server.service"],
            openrc: &["kea-dhcp4"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Restart],
    },
    ServiceBinding {
        units: UnitNames {
            systemd: &["kea-dhcp6-server.service"],
            openrc: &["kea-dhcp6"],
            bsdrc: &[],
        },
        actions: &[ServiceAction::Restart],
    },
];

/// Keep every value here in sync with `upstream.toml`; the unit test below
/// fails when they drift. `commit_confirm` is `true` because a bad DHCP or
/// network change cuts the admin off the host (ADR-012).
static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "dhcp",
    display_name_id: MessageId::new("dhcp-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "dnsmasq",
        repo_url: "https://thekelleys.org.uk/git/dnsmasq.git",
        tracked_version: "2.93",
        release_feed: None,
        docs: &[
            "https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html",
            "https://kea.readthedocs.io/en/kea-3.2.0/",
        ],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: true,
    security_notes: &[MessageId::new("dhcp-note-commit-confirm")],
};

// ------------------------------------------------------------------ schema hints

/// Builds one `x-detent` hint entry: every field of [`Model`] gets a tooltip
/// and a security weight, none a recommendation (module-level diagnostics
/// carry those instead).
fn hint(
    pointer: &'static str,
    tooltip: &'static str,
    group: UiGroup,
    impact: SecurityImpact,
) -> (&'static str, FieldHints) {
    (
        pointer,
        FieldHints {
            group,
            tooltip: MessageId::new(tooltip),
            recommendation: None,
            security_impact: impact,
            since: None,
            deprecated_in: None,
            requires_restart: false,
        },
    )
}

/// The `x-detent` hints for every field of [`Model`], keyed by JSON pointer.
fn field_hints() -> Vec<(&'static str, FieldHints)> {
    vec![
        hint(
            "/properties/dnsmasq",
            "dhcp-tip-dnsmasq",
            UiGroup::Basic,
            SecurityImpact::Low,
        ),
        hint(
            "/properties/kea_v4",
            "dhcp-tip-kea-v4",
            UiGroup::Basic,
            SecurityImpact::High,
        ),
        hint(
            "/properties/kea_v6",
            "dhcp-tip-kea-v6",
            UiGroup::Basic,
            SecurityImpact::High,
        ),
        hint(
            "/$defs/DnsmasqSetting/properties/key",
            "dhcp-tip-key",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/DnsmasqSetting/properties/value",
            "dhcp-tip-value",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaConfig/properties/interfaces",
            "dhcp-tip-interfaces",
            UiGroup::Basic,
            SecurityImpact::High,
        ),
        hint(
            "/$defs/KeaConfig/properties/valid-lifetime",
            "dhcp-tip-valid-lifetime",
            UiGroup::Basic,
            SecurityImpact::Low,
        ),
        hint(
            "/$defs/KeaConfig/properties/subnets",
            "dhcp-tip-subnets",
            UiGroup::Basic,
            SecurityImpact::Low,
        ),
        hint(
            "/$defs/KeaSubnet/properties/id",
            "dhcp-tip-id",
            UiGroup::Advanced,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaSubnet/properties/subnet",
            "dhcp-tip-subnet",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaSubnet/properties/pools",
            "dhcp-tip-pools",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaSubnet/properties/routers",
            "dhcp-tip-routers",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaSubnet/properties/domain-name-servers",
            "dhcp-tip-domain-servers",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
        hint(
            "/$defs/KeaPool/properties/pool",
            "dhcp-tip-pool",
            UiGroup::Basic,
            SecurityImpact::None,
        ),
    ]
}

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`], so both `DhcpModule::schema()` and,
/// through `Dyn`, `DynModule::schema_json` see the hinted schema. Every field
/// of the model carries a hint (Appendix A); `apply_hints` returning `false`
/// is a test failure, not a silent skip.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, field_hints) in field_hints() {
        let _applied: bool = apply_hints(&mut schema, pointer, &field_hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: a dnsmasq setting has an empty key.
const EMPTY_KEY: MessageId = MessageId::new("dhcp-empty-key");
/// Fluent id: a dnsmasq key is not shaped like an option name.
const INVALID_KEY: MessageId = MessageId::new("dhcp-invalid-key");
/// Fluent id: a dnsmasq directive loads external files or runs commands.
const EXTERNAL_DIRECTIVE: MessageId = MessageId::new("dhcp-external-directive");
/// Fluent id: a subnet prefix or `dhcp-range` value is not a valid CIDR.
const MALFORMED_CIDR: MessageId = MessageId::new("dhcp-malformed-cidr");
/// Fluent id: a pool value is neither a CIDR prefix nor an `ip - ip` range.
const MALFORMED_POOL: MessageId = MessageId::new("dhcp-malformed-pool");
/// Fluent id: `dhcp-authoritative` is set.
const AUTHORITATIVE: MessageId = MessageId::new("dhcp-authoritative-set");
/// Fluent id: a configured Kea server has no interfaces to listen on.
const KEA_INTERFACES_EMPTY: MessageId = MessageId::new("dhcp-kea-interfaces-empty");
/// Fluent id: rebind protection flags are missing.
const REC_REBIND: MessageId = MessageId::new("dhcp-rec-rebind");
/// Fluent id: a lease lifetime outside the recommended window.
const REC_LIFETIME: MessageId = MessageId::new("dhcp-rec-lifetime");

/// The recommended lease-lifetime window in seconds (5 minutes to 1 day).
const LIFETIME_WINDOW: std::ops::RangeInclusive<u32> = 300..=86400;

/// Parses `value` as a CIDR prefix: `ip/prefix` with a prefix that fits the
/// address family.
fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = value.trim().split_once('/')?;
    let ip: IpAddr = ip.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => None,
        IpAddr::V6(_) if prefix > 128 => None,
        _ => Some((ip, prefix)),
    }
}

/// Whether `value` is a valid Kea pool: a CIDR prefix or an `ip - ip` range.
fn is_valid_pool(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.contains('/') {
        return parse_cidr(trimmed).is_some();
    }
    match trimmed.split_once('-') {
        None => false,
        Some((low, high)) => {
            low.trim().parse::<IpAddr>().is_ok() && high.trim().parse::<IpAddr>().is_ok()
        }
    }
}

/// Whether `key` is shaped like a dnsmasq option name: one word of letters,
/// digits, `-`, `_` or `.` (the characters every real dnsmasq option uses).
/// Anything else — `{`, `#flag`, `a=b`, `two words` — is not a key the
/// renderer can emit, so both the parser and `validate` refuse it.
fn is_valid_dnsmasq_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Whether a bare flag with this exact name is present.
fn has_flag(model: &Model, key: &str) -> bool {
    model
        .dnsmasq
        .iter()
        .any(|s| s.key == key && s.value.is_none())
}

// ---------------------------------------------------------------------- defaults

/// Builds one `key=value` setting.
fn setting(key: &str, value: &str) -> DnsmasqSetting {
    DnsmasqSetting {
        key: key.to_owned(),
        value: Some(value.to_owned()),
    }
}

/// Builds one bare-flag setting.
fn flag(key: &str) -> DnsmasqSetting {
    DnsmasqSetting {
        key: key.to_owned(),
        value: None,
    }
}

/// The default dnsmasq settings: DNS hardening (`domain-needed`, `bogus-priv`,
/// `stop-dns-rebind`), a loopback-safe bind (`bind-interfaces` +
/// `interface=lo`, so the daemon serves nothing until the admin adds a real
/// interface), a lease file, and a private-subnet pool with a 12-hour lease —
/// the "sane lifetime" for the default backend. No `dhcp-authoritative`.
fn default_dnsmasq() -> Vec<DnsmasqSetting> {
    vec![
        flag("domain-needed"),
        flag("bogus-priv"),
        flag("stop-dns-rebind"),
        flag("bind-interfaces"),
        setting("interface", "lo"),
        setting("dhcp-leasefile", "/var/lib/dnsmasq/dnsmasq.leases"),
        setting("dhcp-range", "192.168.0.50,192.168.0.150,12h"),
    ]
}

// ----------------------------------------------------------------------- module

/// The DHCP config module: dnsmasq and Kea.
pub struct DhcpModule;

impl ConfigModule for DhcpModule {
    /// The stable id. It appears in URLs, the CLI, the audit log, the
    /// `module-dhcp` feature name, the Fluent id prefix, `fixtures/dhcp/` and
    /// the fuzz target names.
    const ID: &'static str = "dhcp";
    /// A custom CST: dnsmasq uses the shared line `Document`, Kea needs the
    /// JSONC tree defined in this crate (ADR-008 allows a module-specific CST
    /// for formats `Document` cannot carry).
    type Doc = DhcpDoc;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    /// Total: input that sniffs as JSONC, parses cleanly and carries `Dhcp4`/
    /// `Dhcp6` becomes a Kea document; everything else — including malformed
    /// JSONC — is classified line by line, where it survives as blank, comment
    /// or `Unknown` lines.
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        if sniffs_jsonc(src)
            && let Ok(document) = parse_jsonc(src)
            && let Some(flavor) = kea_flavor(&document.root)
        {
            return Ok(DhcpDoc::Kea {
                flavor,
                root: document,
            });
        }
        Ok(DhcpDoc::Dnsmasq(Document::parse(src, classify_dnsmasq)))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// Projects only what the model can express: the matching backend's
    /// section. The other sections stay at their default, which is exactly
    /// what makes `apply(doc, to_model(doc))` a no-op on every document.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        match doc {
            DhcpDoc::Dnsmasq(doc) => Ok(Model {
                dnsmasq: doc
                    .lines_of_kind(LineKind::Directive)
                    .filter_map(|line| parse_dnsmasq(line.raw()))
                    .collect(),
                kea_v4: KeaConfig::default(),
                kea_v6: KeaConfig::default(),
            }),
            DhcpDoc::Kea { flavor, root } => {
                let config = root
                    .root
                    .member_by_key(flavor.config_key())
                    .and_then(|member| member.value.as_obj())
                    .map(|obj| project_kea_config(obj, *flavor))
                    .unwrap_or_default();
                let (kea_v4, kea_v6) = match flavor {
                    KeaFlavor::V4 => (config, KeaConfig::default()),
                    KeaFlavor::V6 => (KeaConfig::default(), config),
                };
                Ok(Model {
                    dnsmasq: Vec::new(),
                    kea_v4,
                    kea_v6,
                })
            }
        }
    }

    /// Dispatches to the document's backend and applies only that backend's
    /// model section. A model carrying non-default content for another backend
    /// is refused — [`EditError::Unsupported`] — never silently ignored.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        match doc {
            DhcpDoc::Dnsmasq(doc) => {
                if model.kea_v4 != KeaConfig::default() || model.kea_v6 != KeaConfig::default() {
                    return Err(EditError::Unsupported {
                        message: "kea settings cannot be applied to a dnsmasq configuration file"
                            .to_owned(),
                    });
                }
                apply_dnsmasq(doc, &model.dnsmasq)
            }
            DhcpDoc::Kea { flavor, root } => {
                let other_default = match flavor {
                    KeaFlavor::V4 => &model.kea_v6,
                    KeaFlavor::V6 => &model.kea_v4,
                } == &KeaConfig::default();
                if !model.dnsmasq.is_empty() || !other_default {
                    return Err(EditError::Unsupported {
                        message: "dnsmasq settings cannot be applied to a Kea configuration file"
                            .to_owned(),
                    });
                }
                let config = match flavor {
                    KeaFlavor::V4 => &model.kea_v4,
                    KeaFlavor::V6 => &model.kea_v6,
                };
                check_kea_injection(config)?;
                let mut report = EditReport::default();
                apply_kea_config(&mut root.root, *flavor, config, &mut report)?;
                Ok(report)
            }
        }
    }

    /// A module needs at least one of each severity, and every finding carries
    /// a Fluent id — never a rendered sentence (ADR-003). Attach a
    /// [`FieldPath`] whenever the finding is about one field, and pass every
    /// value that appears in the message as a named argument, so translators
    /// can reorder them.
    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        for (index, item) in model.dnsmasq.iter().enumerate() {
            let path = format!("dnsmasq/{index}");
            if item.key.is_empty() {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, EMPTY_KEY)
                        .with_field(FieldPath::new(format!("{path}/key"))),
                );
            } else if !is_valid_dnsmasq_key(&item.key) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, INVALID_KEY)
                        .with_field(FieldPath::new(format!("{path}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
            if INCLUDE_KEYS.contains(&item.key.to_ascii_lowercase().as_str()) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, EXTERNAL_DIRECTIVE)
                        .with_field(FieldPath::new(format!("{path}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
            if item.key == "dhcp-range"
                && let Some(value) = &item.value
                && let Some(first) = value.split(',').next()
                && first.contains('/')
                && parse_cidr(first).is_none()
            {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, MALFORMED_CIDR)
                        .with_field(FieldPath::new(format!("{path}/value")))
                        .with_arg("value", first.to_owned()),
                );
            }
            if item.key == "dhcp-authoritative" {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, AUTHORITATIVE)
                        .with_field(FieldPath::new(format!("{path}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
        }
        if !has_flag(model, "domain-needed") || !has_flag(model, "bogus-priv") {
            diagnostics.push(
                Diagnostic::new(Severity::Recommendation, REC_REBIND)
                    .with_field(FieldPath::new("dnsmasq")),
            );
        }
        for (name, config, path) in [
            ("kea-dhcp4", &model.kea_v4, "kea_v4"),
            ("kea-dhcp6", &model.kea_v6, "kea_v6"),
        ] {
            // An untouched (fully default) server section is not in use; skip
            // its warnings so a dnsmasq-only model stays clean.
            if config == &KeaConfig::default() {
                continue;
            }
            if config.interfaces.is_empty() {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, KEA_INTERFACES_EMPTY)
                        .with_field(FieldPath::new(format!("{path}/interfaces")))
                        .with_arg("server", name.to_owned()),
                );
            }
            for (subnet_index, subnet) in config.subnets.iter().enumerate() {
                let subnet_path = format!("{path}/subnets/{subnet_index}");
                if parse_cidr(&subnet.subnet).is_none() {
                    diagnostics.push(
                        Diagnostic::new(Severity::Error, MALFORMED_CIDR)
                            .with_field(FieldPath::new(format!("{subnet_path}/subnet")))
                            .with_arg("value", subnet.subnet.clone()),
                    );
                }
                for (pool_index, pool) in subnet.pools.iter().enumerate() {
                    if !is_valid_pool(&pool.pool) {
                        diagnostics.push(
                            Diagnostic::new(Severity::Error, MALFORMED_POOL)
                                .with_field(FieldPath::new(format!(
                                    "{subnet_path}/pools/{pool_index}/pool"
                                )))
                                .with_arg("value", pool.pool.clone()),
                        );
                    }
                }
            }
            if let Some(lifetime) = config.valid_lifetime
                && !LIFETIME_WINDOW.contains(&lifetime)
            {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_LIFETIME)
                        .with_field(FieldPath::new(format!("{path}/valid-lifetime")))
                        .with_arg("server", name.to_owned())
                        .with_arg("lifetime", lifetime.to_string()),
                );
            }
        }
        diagnostics
    }

    /// Secure, host-appropriate defaults. The Kea sections stay at their
    /// default until the admin opts in — an untouched `kea-dhcp*.conf` is the
    /// safest state, and `apply` refuses cross-backend content, so defaults
    /// must be applicable to a fresh dnsmasq document. The match stays
    /// exhaustive over [`Os`] without a `_` arm so a new platform tier is a
    /// compile error here instead of a silently wrong file (ADR-013).
    fn defaults(profile: &HostProfile) -> Self::Model {
        match profile.os {
            Os::Linux | Os::MacOs | Os::Other => Model {
                dnsmasq: default_dnsmasq(),
                kea_v4: KeaConfig::default(),
                kea_v6: KeaConfig::default(),
            },
        }
    }

    /// The hinted schema; without the override the UI would get the bare
    /// `schemars` schema with no `x-detent` hints.
    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORITATIVE, DhcpDoc, DhcpModule, DnsmasqSetting, EMPTY_KEY, EXTERNAL_DIRECTIVE,
        INCLUDE_KEYS, INVALID_KEY, Jsonc, JsoncRoot, KEA_INTERFACES_EMPTY, KeaConfig, KeaFlavor,
        KeaPool, KeaSubnet, Lit, MALFORMED_CIDR, MALFORMED_POOL, Member, Model, Obj, REC_LIFETIME,
        REC_REBIND, classify_dnsmasq, decode_json_string, is_valid_dnsmasq_key, is_valid_pool,
        json_escape, parse_cidr, parse_dnsmasq, parse_jsonc, render_dnsmasq, schema_with_hints,
        sniffs_jsonc,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};
    use std::net::{IpAddr, Ipv4Addr};

    /// `locales/en-US/core.ftl` is the source of truth for every user-facing
    /// string (PLAN §4.3). This test is what keeps a raw id from reaching the
    /// UI: list every `MessageId` this crate constructs and add the matching
    /// lines to `core.ftl`. It fails until the orchestrator appends
    /// `locale-snippet.ftl`; that is expected mid-flight.
    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
    /// reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "dhcp-name",
            "dhcp-note-commit-confirm",
            "dhcp-tip-dnsmasq",
            "dhcp-tip-kea-v4",
            "dhcp-tip-kea-v6",
            "dhcp-tip-key",
            "dhcp-tip-value",
            "dhcp-tip-interfaces",
            "dhcp-tip-valid-lifetime",
            "dhcp-tip-subnets",
            "dhcp-tip-id",
            "dhcp-tip-subnet",
            "dhcp-tip-pools",
            "dhcp-tip-routers",
            "dhcp-tip-domain-servers",
            "dhcp-tip-pool",
            "dhcp-empty-key",
            "dhcp-invalid-key",
            "dhcp-malformed-cidr",
            "dhcp-malformed-pool",
            "dhcp-external-directive",
            "dhcp-authoritative-set",
            "dhcp-kea-interfaces-empty",
            "dhcp-rec-rebind",
            "dhcp-rec-lifetime",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = DhcpModule::descriptor().upstream;
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
        assert_eq!(upstream.release_feed, None);
        assert!(UPSTREAM_TOML.contains("release_feed = \"\""));
        assert!(UPSTREAM_TOML.contains("[fixtures]"));
        assert!(UPSTREAM_TOML.contains("dirs = [\"dnsmasq-2.93\", \"edge\"]"));
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
        DhcpModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    fn dnsmasq_setting(key: &str, value: Option<&str>) -> DnsmasqSetting {
        DnsmasqSetting {
            key: key.to_owned(),
            value: value.map(str::to_owned),
        }
    }

    fn dnsmasq_only(settings: Vec<DnsmasqSetting>) -> Model {
        Model {
            dnsmasq: settings,
            ..Model::default()
        }
    }

    fn kea4(interfaces: &[&str], lifetime: Option<u32>, subnets: Vec<KeaSubnet>) -> Model {
        Model {
            kea_v4: KeaConfig {
                interfaces: interfaces.iter().map(|s| (*s).to_owned()).collect(),
                valid_lifetime: lifetime,
                subnets,
            },
            ..Model::default()
        }
    }

    fn subnet(id: u32, prefix: &str, pools: &[&str]) -> KeaSubnet {
        KeaSubnet {
            id,
            subnet: prefix.to_owned(),
            pools: pools
                .iter()
                .map(|p| KeaPool {
                    pool: (*p).to_owned(),
                })
                .collect(),
            routers: Vec::new(),
            domain_servers: Vec::new(),
        }
    }

    // ---------------------------------------------------------------- sniff

    #[test]
    fn sniffs_jsonc_only_for_brace_documents() {
        assert!(sniffs_jsonc("{ \"Dhcp4\": {} }"));
        assert!(sniffs_jsonc("// lead\n{ \"Dhcp6\": {} }"));
        assert!(sniffs_jsonc("/* lead */ { \"Dhcp4\": {} }"));
        assert!(sniffs_jsonc("\r\n\t { \"Dhcp4\": {} }"));
        assert!(!sniffs_jsonc("interface=lo\n"));
        assert!(!sniffs_jsonc(""));
        assert!(!sniffs_jsonc("# comment\n"));
        assert!(!sniffs_jsonc("x{"));
        assert!(!sniffs_jsonc("/* unterminated {"));
        assert!(!sniffs_jsonc("[1, 2]"));
    }

    // ----------------------------------------------------------- dnsmasq parse

    #[test]
    fn parse_dnsmasq_reads_flags_and_pairs() {
        assert_eq!(
            parse_dnsmasq("  domain-needed  "),
            Some(dnsmasq_setting("domain-needed", None))
        );
        assert_eq!(
            parse_dnsmasq("interface\t=\teth0"),
            Some(dnsmasq_setting("interface", Some("eth0")))
        );
        assert_eq!(
            parse_dnsmasq("dhcp-range=192.168.0.50,192.168.0.150,12h"),
            Some(dnsmasq_setting(
                "dhcp-range",
                Some("192.168.0.50,192.168.0.150,12h")
            ))
        );
        assert_eq!(
            parse_dnsmasq("server=/example.com/9.9.9.9"),
            Some(dnsmasq_setting("server", Some("/example.com/9.9.9.9")))
        );
    }

    #[test]
    fn parse_dnsmasq_keeps_external_directives_for_validation() {
        for key in INCLUDE_KEYS {
            let line = format!("{key}=/tmp/untrusted");
            assert_eq!(
                parse_dnsmasq(&line),
                Some(dnsmasq_setting(key, Some("/tmp/untrusted")))
            );
        }
    }

    #[test]
    fn parse_dnsmasq_rejects_non_settings() {
        for line in [
            "",
            "   ",
            "# comment",
            "  # indented",
            "two words",
            "=missing-key",
        ] {
            assert_eq!(parse_dnsmasq(line), None, "expected {line:?} to be refused");
        }
    }

    #[test]
    fn classify_dnsmasq_assigns_the_four_buckets() {
        assert_eq!(classify_dnsmasq(""), LineKind::Blank);
        assert_eq!(classify_dnsmasq("\t"), LineKind::Blank);
        assert_eq!(classify_dnsmasq("# c"), LineKind::Comment);
        assert_eq!(classify_dnsmasq("interface=lo"), LineKind::Directive);
        assert_eq!(classify_dnsmasq("bind-interfaces"), LineKind::Directive);
        assert_eq!(classify_dnsmasq("garbage here"), LineKind::Unknown);
        assert_eq!(classify_dnsmasq("{"), LineKind::Unknown);
    }

    // ---------------------------------------------------------- dnsmasq render

    #[test]
    fn render_dnsmasq_emits_the_canonical_line() {
        assert_eq!(
            render_dnsmasq(&dnsmasq_setting("interface", Some("eth0"))),
            Ok("interface=eth0".to_owned())
        );
        assert_eq!(
            render_dnsmasq(&dnsmasq_setting("bind-interfaces", None)),
            Ok("bind-interfaces".to_owned())
        );
    }

    #[test]
    fn render_dnsmasq_rejects_a_line_break_in_a_value() {
        assert_eq!(
            render_dnsmasq(&dnsmasq_setting("interface", Some("a\nb"))),
            Err(EditError::LineBreakInValue {
                value: "interface=a\nb".to_owned()
            })
        );
        assert!(render_dnsmasq(&dnsmasq_setting("interface", Some("a\0b"))).is_err());
        assert!(render_dnsmasq(&dnsmasq_setting("inter\nface", Some("v"))).is_err());
    }

    #[test]
    fn render_dnsmasq_rejects_values_that_would_not_round_trip() {
        for bad in [
            dnsmasq_setting("", None),
            dnsmasq_setting("a b", None),
            dnsmasq_setting("a=b", None),
            dnsmasq_setting("#flag", None),
            dnsmasq_setting("interface", Some(" padded")),
            dnsmasq_setting("conf-file", Some("x")),
        ] {
            assert!(
                matches!(render_dnsmasq(&bad), Err(EditError::Unsupported { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    // ------------------------------------------------------------------ kea CST

    #[test]
    fn jsonc_parse_render_is_lossless_on_comment_styles() -> Result<(), String> {
        for src in [
            "{}",
            "{ }",
            "{\"a\":1}",
            "{ \"a\" : 1 , \"b\" : [ 1 , 2 ] }",
            "// lead\n{\n  // one\n  \"a\": 1, /* inline */ \"b\": 2\n} /* tail */\n",
            "{\"a\":\"esc\\\"\\u00e9\\n\"}",
            "{\"a\":true,\"b\":null,\"c\":-12.5e3}",
        ] {
            let root = parse_jsonc(src).map_err(|()| format!("refused {src:?}"))?;
            assert_eq!(root.render(), src, "lossless failed for {src:?}");
        }
        Ok(())
    }

    #[test]
    fn jsonc_parse_rejects_malformed_grammar() {
        for src in [
            "{",
            "{\"a\"}",
            "{\"a\":}",
            "{\"a\":1,}",
            "{\"a\":1 \"b\":2}",
            "[1,",
            "{\"a\":\"unterminated}",
            "{\"a\":tru",
            "/* unterminated",
            "{\u{1}}",
            "{\"a\":1",
        ] {
            assert!(parse_jsonc(src).is_err(), "expected {src:?} to be refused");
        }
    }

    #[test]
    fn jsonc_parse_rejects_over_deep_nesting() {
        let deep = "[".repeat(500);
        assert!(parse_jsonc(&deep).is_err());
        let ok = format!("{{\"a\":{}{}}}", "[".repeat(100), "]".repeat(100));
        assert!(parse_jsonc(&ok).is_ok());
    }

    #[test]
    fn jsonc_string_decode_follows_rfc8259() {
        assert_eq!(
            decode_json_string("\"a\\u00e9\\n\\t\\\"\\\\\\/\\b\\f\\r\""),
            Some("a\u{e9}\n\t\"\\/\u{8}\u{c}\r".to_owned())
        );
        assert_eq!(
            decode_json_string("\"\\ud83d\\ude00\""),
            Some("\u{1f600}".to_owned())
        );
        assert_eq!(decode_json_string("\"\\ud83d\""), None);
        assert_eq!(decode_json_string("\"\\u00\""), None);
        assert_eq!(decode_json_string("\"\\x\""), None);
        assert_eq!(decode_json_string("\"unterminated"), None);
    }

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn jsonc_read_write_keeps_unknown_keys() -> Result<(), String> {
        let src = "{\n  \"Dhcp4\": {\n    // kept\n    \"lease-database\": {\"type\": \"memfile\"},\n    \"interfaces-config\": {\"interfaces\": [\"eth0\"], \"dhcp-socket-type\": \"raw\"},\n    \"valid-lifetime\": 4000\n  },\n  \"Logging\": {\"loggers\": []}\n}\n";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = kea4(&["eth1"], Some(3600), Vec::new());
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 2);
        let rendered = DhcpModule::render(&doc);
        // Unknown keys and comments survive; only the two managed values moved.
        assert!(rendered.contains("\"lease-database\""));
        assert!(rendered.contains("\"dhcp-socket-type\": \"raw\""));
        assert!(rendered.contains("\"Logging\""));
        assert!(rendered.contains("// kept"));
        assert!(rendered.contains("\"eth1\""));
        assert!(rendered.contains("\"valid-lifetime\": 3600"));
        assert!(!rendered.contains("4000"));
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn kea_apply_is_a_noop_on_its_own_model() -> Result<(), String> {
        let src = "// c\n{ \"Dhcp4\": { \"valid-lifetime\": 4000,\n  \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\"} ] } }\n";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.kea_v4.valid_lifetime, Some(4000));
        assert_eq!(model.kea_v4.subnets.len(), 1);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(DhcpModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn kea_option_data_round_trips_per_entry() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"option-data\": [\n        {\"name\": \"routers\", \"data\": \"192.0.2.1\"},\n        {\"name\": \"domain-name-servers\", \"data\": \"192.0.2.53\"},\n        {\"name\": \"ntp-servers\", \"data\": \"192.0.2.9\"}\n      ]} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        let projected = model.kea_v4.subnets.first();
        assert_eq!(
            projected.map(|s| s.routers.as_slice()),
            Some(&["192.0.2.1".to_owned()][..])
        );
        assert_eq!(
            projected.map(|s| s.domain_servers.as_slice()),
            Some(&["192.0.2.53".to_owned()][..])
        );
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(DhcpModule::render(&doc), src);
        // Adding a second router touches only the option-data member.
        let mut model2 = model.clone();
        if let Some(first) = model2.kea_v4.subnets.first_mut() {
            first.routers.push("192.0.2.2".to_owned());
        }
        let report = DhcpModule::apply(&mut doc, &model2).map_err(|e| e.to_string())?;
        // Byte-minimal: the two existing managed entries match in place and
        // only the new router is appended; `ntp-servers` is untouched.
        assert_eq!(
            report,
            EditReport {
                added: 1,
                ..EditReport::default()
            }
        );
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("\"192.0.2.2\""));
        assert!(rendered.contains("\"ntp-servers\""));
        Ok(())
    }

    #[test]
    fn kea_unmodeled_array_entries_are_preserved() -> Result<(), String> {
        let src = "{ \"Dhcp6\": { \"subnet6\": [ {\"id\": 1, \"subnet\": \"2001:db8:1::/64\"}, 42, {\"subnet\": \"no-id\"} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.kea_v6.subnets.len(), 1);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        // Appending a subnet keeps the unmodeled 42 and the id-less object.
        model.kea_v6.subnets.push(subnet(2, "2001:db8:2::/64", &[]));
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("42"));
        assert!(rendered.contains("\"no-id\""));
        assert!(rendered.contains("\"2001:db8:2::/64\""));
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn kea_garbage_members_are_left_alone_until_written() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"valid-lifetime\": \"garbage\", \"interfaces-config\": \"junk\", \"subnet4\": \"junk\" } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model.kea_v4, KeaConfig::default());
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(DhcpModule::render(&doc), src);
        // Writing real values replaces the garbage wholesale; the empty
        // subnets list leaves the garbage `subnet4` alone.
        let model = kea4(&["eth0"], Some(3600), Vec::new());
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 2);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("\"eth0\""));
        assert!(rendered.contains("3600"));
        Ok(())
    }

    #[test]
    fn kea_missing_members_are_inserted() -> Result<(), String> {
        // No interfaces-config, no valid-lifetime, no subnet4: all three are
        // appended canonically inside the existing Dhcp4 object.
        let src = "{ \"Dhcp4\": {\n    // untouched comment\n    \"lease-database\": {\"type\": \"memfile\"}\n} }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = kea4(
            &["eth0"],
            Some(3600),
            vec![subnet(1, "192.0.2.0/24", &["192.0.2.1 - 192.0.2.50"])],
        );
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 3);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("\"interfaces-config\""));
        assert!(rendered.contains("\"valid-lifetime\":3600"));
        assert!(rendered.contains("\"subnet4\""));
        assert!(rendered.contains("// untouched comment"));
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn kea_partial_member_merges_preserve_unknown_keys() -> Result<(), String> {
        // interfaces-config exists without `interfaces`; `interfaces` is not an
        // array; the subnet carries unknown members and garbage option-data.
        let src = "{ \"Dhcp4\": {\n    \"interfaces-config\": {\"dhcp-socket-type\": \"raw\"},\n    \"subnet4\": [\n      {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"interface\": \"eth0\", \"valid-lifetime\": 60, \"option-data\": \"junk\"}\n    ]\n} }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = kea4(
            &["eth1"],
            None,
            vec![KeaSubnet {
                id: 1,
                subnet: "192.0.2.0/24".to_owned(),
                pools: vec![KeaPool {
                    pool: "192.0.2.1 - 192.0.2.9".to_owned(),
                }],
                routers: vec!["192.0.2.1".to_owned()],
                domain_servers: Vec::new(),
            }],
        );
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        // `interfaces` inside the existing interfaces-config, plus `pools`
        // inside the matched subnet; the garbage option-data is replaced.
        assert_eq!(report.added, 2);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("\"dhcp-socket-type\""));
        assert!(rendered.contains("\"interface\": \"eth0\""));
        assert!(rendered.contains("\"valid-lifetime\": 60"));
        assert!(rendered.contains("\"option-data\""));
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    #[test]
    fn kea_removed_model_entries_disappear() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"interfaces-config\": {\"interfaces\": [\"eth0\", \"eth1\"]}, \"valid-lifetime\": 3600, \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"pools\": [{\"pool\": \"192.0.2.1 - 192.0.2.50\"}]} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model::default();
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 4); // eth0, eth1, valid-lifetime, subnet entry
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("\"interfaces-config\""));
        assert!(!rendered.contains("eth0"));
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back, model);
        Ok(())
    }

    // ---------------------------------------------------------- apply refusal

    #[test]
    fn apply_refuses_cross_backend_content() -> Result<(), String> {
        let mut dnsmasq_doc = DhcpModule::parse("interface=lo\n").map_err(|e| e.to_string())?;
        let kea_model = kea4(&[], Some(3600), Vec::new());
        assert!(DhcpModule::apply(&mut dnsmasq_doc, &kea_model).is_err());
        let mut kea_doc = DhcpModule::parse("{ \"Dhcp4\": {} }").map_err(|e| e.to_string())?;
        let dnsmasq_model = dnsmasq_only(vec![dnsmasq_setting("interface", Some("lo"))]);
        assert!(DhcpModule::apply(&mut kea_doc, &dnsmasq_model).is_err());
        // A v4 document refuses v6 content and the other way round.
        let mut v6_model = Model::default();
        v6_model.kea_v6.valid_lifetime = Some(3600);
        assert!(DhcpModule::apply(&mut kea_doc, &v6_model).is_err());
        let mut v6_doc = DhcpModule::parse("{ \"Dhcp6\": {} }").map_err(|e| e.to_string())?;
        assert!(DhcpModule::apply(&mut v6_doc, &kea_model).is_err());
        Ok(())
    }

    #[test]
    fn kea_apply_rejects_injected_strings_and_leaves_the_doc_untouched() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"valid-lifetime\": 4000 } }";
        for bad in ["a\nb", "a\rb", "a\0b"] {
            let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
            let model = kea4(&[bad], None, Vec::new());
            assert!(DhcpModule::apply(&mut doc, &model).is_err());
            assert_eq!(DhcpModule::render(&doc), src);
        }
        Ok(())
    }

    #[test]
    fn defensive_paths_on_hand_built_documents() -> Result<(), String> {
        // A Kea doc whose claimed flavor key is missing, and one whose config
        // element is not an object: the default model applies as a no-op, a
        // non-default one is refused.
        let mut no_key = DhcpDoc::Kea {
            flavor: KeaFlavor::V4,
            root: JsoncRoot {
                lead: String::new(),
                root: Obj::default(),
                trail: String::new(),
            },
        };
        let model = DhcpModule::to_model(&no_key).map_err(|e| e.to_string())?;
        assert_eq!(model, Model::default());
        let report = DhcpModule::apply(&mut no_key, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert!(DhcpModule::apply(&mut no_key, &kea4(&[], Some(3600), Vec::new())).is_err());
        let mut lit_root = DhcpDoc::Kea {
            flavor: KeaFlavor::V4,
            root: JsoncRoot {
                lead: String::new(),
                root: Obj {
                    open: "{".to_owned(),
                    members: vec![Member {
                        key: Lit::Str {
                            raw: "\"Dhcp4\"".to_owned(),
                            value: "Dhcp4".to_owned(),
                        },
                        colon: ":".to_owned(),
                        value: Jsonc::Lit(Lit::Raw("42".to_owned())),
                        post: String::new(),
                        comma: String::new(),
                        tail: String::new(),
                    }],
                    close: "}".to_owned(),
                },
                trail: String::new(),
            },
        };
        let model = DhcpModule::to_model(&lit_root).map_err(|e| e.to_string())?;
        assert_eq!(model, Model::default());
        let report = DhcpModule::apply(&mut lit_root, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert!(DhcpModule::apply(&mut lit_root, &kea4(&[], Some(3600), Vec::new())).is_err());
        Ok(())
    }

    // --------------------------------------------------------------- validate

    #[test]
    fn validate_flags_empty_and_invalid_keys() {
        let model = dnsmasq_only(vec![dnsmasq_setting("", None)]);
        assert!(has(&model, EMPTY_KEY, Severity::Error));
        let model = dnsmasq_only(vec![dnsmasq_setting("a b=1", Some("v"))]);
        assert!(has(&model, INVALID_KEY, Severity::Error));
        let model = dnsmasq_only(vec![dnsmasq_setting("#a", Some("v"))]);
        assert!(has(&model, INVALID_KEY, Severity::Error));
    }

    #[test]
    fn validate_rejects_external_file_and_script_directives() {
        for key in INCLUDE_KEYS {
            let model = dnsmasq_only(vec![dnsmasq_setting(key, Some("/tmp/untrusted"))]);
            assert!(has(&model, EXTERNAL_DIRECTIVE, Severity::Error), "{key}");
        }
    }

    #[test]
    fn validate_flags_malformed_cidr_and_pools() {
        let mut model = Model::default();
        model
            .kea_v4
            .subnets
            .push(subnet(1, "192.0.2.0", &["not a pool"]));
        assert!(has(&model, MALFORMED_CIDR, Severity::Error));
        assert!(has(&model, MALFORMED_POOL, Severity::Error));
        let mut good = Model::default();
        good.kea_v4.subnets.push(subnet(
            1,
            "192.0.2.0/24",
            &["192.0.2.1 - 192.0.2.50", "2001:db8:1::/80"],
        ));
        assert!(!has(&good, MALFORMED_CIDR, Severity::Error));
        assert!(!has(&good, MALFORMED_POOL, Severity::Error));
        // A `dhcp-range` whose first comma token carries a malformed prefix.
        let model = dnsmasq_only(vec![dnsmasq_setting(
            "dhcp-range",
            Some("192.0.2.0/33,12h"),
        )]);
        assert!(has(&model, MALFORMED_CIDR, Severity::Error));
        let model = dnsmasq_only(vec![dnsmasq_setting(
            "dhcp-range",
            Some("192.0.2.0/24,12h"),
        )]);
        assert!(!has(&model, MALFORMED_CIDR, Severity::Error));
    }

    #[test]
    fn validate_warns_on_authoritative_and_empty_kea_interfaces() {
        let model = dnsmasq_only(vec![dnsmasq_setting("dhcp-authoritative", None)]);
        assert!(has(&model, AUTHORITATIVE, Severity::Warning));
        let mut model = Model::default();
        model.kea_v4.valid_lifetime = Some(3600);
        assert!(has(&model, KEA_INTERFACES_EMPTY, Severity::Warning));
        // An untouched (default) Kea section is not in use and stays quiet.
        let model = dnsmasq_only(vec![]);
        assert!(!has(&model, KEA_INTERFACES_EMPTY, Severity::Warning));
    }

    #[test]
    fn validate_recommends_rebind_protection_and_sane_lifetimes() {
        assert!(has(
            &dnsmasq_only(vec![]),
            REC_REBIND,
            Severity::Recommendation
        ));
        let hardened = dnsmasq_only(vec![
            dnsmasq_setting("domain-needed", None),
            dnsmasq_setting("bogus-priv", None),
        ]);
        assert!(!has(&hardened, REC_REBIND, Severity::Recommendation));
        let mut model = Model::default();
        model.kea_v4.valid_lifetime = Some(299);
        assert!(has(&model, REC_LIFETIME, Severity::Recommendation));
        model.kea_v4.valid_lifetime = Some(86401);
        assert!(has(&model, REC_LIFETIME, Severity::Recommendation));
        model.kea_v4.valid_lifetime = Some(3600);
        assert!(!has(&model, REC_LIFETIME, Severity::Recommendation));
    }

    #[test]
    fn cidr_and_pool_parsers_follow_the_documented_rules() -> Result<(), String> {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 0).into();
        let v6: IpAddr = "2001:db8::"
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        assert_eq!(parse_cidr("192.0.2.0/24"), Some((v4, 24)));
        assert_eq!(parse_cidr("  2001:db8::/64 "), Some((v6, 64)));
        assert_eq!(parse_cidr("192.0.2.0/33"), None);
        assert_eq!(parse_cidr("2001:db8::/129"), None);
        assert_eq!(parse_cidr("192.0.2.0"), None);
        assert_eq!(parse_cidr("nope/24"), None);
        assert!(is_valid_pool("192.0.2.1-192.0.2.9"));
        assert!(is_valid_pool(" 192.0.2.1 - 192.0.2.9 "));
        assert!(!is_valid_pool("192.0.2.1 - nope"));
        assert!(!is_valid_pool("just one ip"));
        Ok(())
    }

    #[test]
    fn is_valid_dnsmasq_key_follows_the_documented_rule() {
        assert!(is_valid_dnsmasq_key("interface"));
        assert!(!is_valid_dnsmasq_key(""));
        assert!(!is_valid_dnsmasq_key("a b"));
        assert!(!is_valid_dnsmasq_key("a=b"));
        assert!(!is_valid_dnsmasq_key("#a"));
    }

    // --------------------------------------------------------------- defaults

    #[test]
    fn defaults_branch_on_the_operating_system() {
        let linux = DhcpModule::defaults(&profile(Os::Linux, ""));
        for os in [Os::MacOs, Os::Other] {
            assert_eq!(DhcpModule::defaults(&profile(os, "")), linux);
        }
        assert!(!linux.dnsmasq.is_empty());
        assert_eq!(linux.kea_v4, KeaConfig::default());
        assert_eq!(linux.kea_v6, KeaConfig::default());
        assert!(!linux.dnsmasq.iter().any(|s| s.key == "dhcp-authoritative"));
    }

    #[test]
    fn defaults_are_valid_and_apply_to_an_empty_file() -> Result<(), String> {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            let host = profile(os, "node1");
            let ctx = ValidationCtx::new(&host);
            let model = DhcpModule::defaults(&host);
            assert!(!DhcpModule::validate(&model, &ctx).has_errors());
            let mut doc = DhcpModule::parse("").map_err(|e| e.to_string())?;
            let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report.added, model.dnsmasq.len());
            let rendered = DhcpModule::render(&doc);
            let back =
                DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            assert_eq!(back, model);
        }
        Ok(())
    }

    // ------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_and_backends() {
        let descriptor = DhcpModule::descriptor();
        assert_eq!(descriptor.id, DhcpModule::ID);
        assert_eq!(descriptor.targets.len(), 4);
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux, "h")));
            assert!(!(target.backend_detect)(&profile(Os::MacOs, "h")));
        }
        assert_eq!(descriptor.checks.len(), 3);
        assert_eq!(descriptor.services.len(), 3);
        assert!(descriptor.commit_confirm);
        assert_eq!(descriptor.security_notes.len(), 1);
    }

    // ----------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, DhcpModule::schema());
        for pointer in [
            "/properties/dnsmasq",
            "/properties/kea_v4",
            "/properties/kea_v6",
            "/$defs/DnsmasqSetting/properties/key",
            "/$defs/DnsmasqSetting/properties/value",
            "/$defs/KeaConfig/properties/interfaces",
            "/$defs/KeaConfig/properties/valid-lifetime",
            "/$defs/KeaConfig/properties/subnets",
            "/$defs/KeaSubnet/properties/id",
            "/$defs/KeaSubnet/properties/subnet",
            "/$defs/KeaSubnet/properties/pools",
            "/$defs/KeaSubnet/properties/routers",
            "/$defs/KeaSubnet/properties/domain-name-servers",
            "/$defs/KeaPool/properties/pool",
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

    // ---------------------------------------------------- derived trait impls

    /// Exercises the derived impls the module's own logic never calls.
    /// Coverage is 100 % lines for `crates/modules/` (PLAN §6.2), and a derive
    /// with no caller is the usual reason a module misses it.
    #[test]
    fn model_supports_debug_clone_default_and_serde() -> Result<(), String> {
        let mut model = Model::default();
        model.dnsmasq.push(dnsmasq_setting("interface", Some("lo")));
        model.kea_v4.subnets.push(KeaSubnet {
            id: 1,
            subnet: "192.0.2.0/24".to_owned(),
            pools: vec![KeaPool {
                pool: "192.0.2.1 - 192.0.2.9".to_owned(),
            }],
            routers: vec!["192.0.2.1".to_owned()],
            domain_servers: vec!["192.0.2.53".to_owned()],
        });
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("kea_v4"));
        assert_eq!(Model::default(), Model::default());
        let json = serde_json::to_value(&model).map_err(|e| e.to_string())?;
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(model));
        assert!(
            serde_json::from_str::<Model>(r#"{"dnsmasq":[],"kea_v4":{},"kea_v6":{},"x":1}"#)
                .is_err()
        );
        let full = r#"{"dnsmasq":[],"kea_v4":{"interfaces":[],"valid-lifetime":null,"subnets":[]},"kea_v6":{"interfaces":[],"valid-lifetime":null,"subnets":[]}}"#;
        assert!(serde_json::from_str::<Model>(full).is_ok());
        Ok(())
    }

    // ------------------------------------------------------------ adversarial

    /// Keep an adversarial block. These are the shapes that broke real
    /// parsers: no trailing newline, CRLF, NUL, over-deep JSONC nesting, one
    /// very long line, and a file large enough that a super-linear `apply`
    /// shows up as a timeout.
    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "key{i}=v");
        }
        let mut deep = String::from("{ \"Dhcp4\": { \"a\": ");
        deep.push_str(&"[".repeat(400));
        deep.push('1');
        deep.push_str(&"]".repeat(400));
        deep.push_str("} }");
        let mut big_jsonc = String::from("{ \"Dhcp6\": { \"valid-lifetime\": 3600");
        for i in 0..5_000u32 {
            let _ = write!(big_jsonc, ", \"key{i}\": {i}");
        }
        big_jsonc.push_str("} }");
        for src in [
            "interface=lo",
            "interface=lo\r\nbind-interfaces\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
            deep.as_str(),
            big_jsonc.as_str(),
        ] {
            let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(DhcpModule::render(&doc), src);
            let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(DhcpModule::render(&doc), src);
        }
        Ok(())
    }

    // ------------------------------------------------------- at least one edit

    #[test]
    fn an_edited_value_reaches_the_rendered_file() -> Result<(), String> {
        let src = "# comment\n\ninterface=lo\nbind-interfaces\n# trailing comment\n";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = dnsmasq_only(vec![
            dnsmasq_setting("interface", Some("eth0")),
            dnsmasq_setting("bind-interfaces", None),
        ]);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(
            DhcpModule::render(&doc),
            "# comment\n\ninterface=eth0\nbind-interfaces\n# trailing comment\n"
        );
        Ok(())
    }

    // ------------------------------------------------- coverage: edge paths

    #[test]
    fn non_kea_jsonc_falls_back_to_the_dnsmasq_classifier() -> Result<(), String> {
        let src = "{ \"Other\": {} }\n";
        let doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        assert!(matches!(doc, DhcpDoc::Dnsmasq(_)));
        assert_eq!(DhcpModule::render(&doc), src);
        let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(model, Model::default());
        Ok(())
    }

    #[test]
    fn jsonc_trailing_garbage_is_not_jsonc() {
        assert!(parse_jsonc("{} x").is_err());
        assert!(parse_jsonc("{} }").is_err());
    }

    #[test]
    fn sniffs_jsonc_rejects_a_slash_that_is_not_a_comment() {
        assert!(!sniffs_jsonc("/x {"));
        assert!(!sniffs_jsonc("2 { \"Dhcp4\": {} }"));
    }

    #[test]
    fn jsonc_malformed_edge_grammar() {
        // Backslash at EOF inside a string; `*` at EOF inside a block
        // comment; an object with a comma where a key belongs.
        for src in ["{\"a\":1\\", "/* x*", "{\"a\":1,\"}"] {
            assert!(parse_jsonc(src).is_err(), "expected {src:?} to be refused");
        }
    }

    #[test]
    fn decode_json_string_edge_cases() {
        // A bare token, an empty token, a bad low surrogate and an unknown
        // escape are all refused.
        assert_eq!(decode_json_string(""), None);
        assert_eq!(decode_json_string("42"), None);
        assert_eq!(decode_json_string("\"\\ud800\\ud800\""), None);
        assert_eq!(decode_json_string("\"\\ud800\\u0041\""), None);
        assert_eq!(decode_json_string("\"\\q\""), None);
        assert_eq!(json_escape("a\rb"), "a\\rb");
    }

    #[test]
    fn raw_literals_project_to_no_string() {
        let raw = Lit::Raw("4000".to_owned());
        assert_eq!(raw.as_str(), None);
        assert_eq!(raw.as_u32(), Some(4000));
    }

    #[test]
    fn cidr_parser_refuses_out_of_range_prefixes() {
        assert_eq!(parse_cidr("192.0.2.0/300"), None);
    }

    #[test]
    fn option_data_entries_without_data_or_other_names_are_skipped() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"option-data\": [\n        {\"name\": \"ntp-servers\"},\n        {\"name\": \"routers\"},\n        7\n      ]} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = DhcpModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            model.kea_v4.subnets.first().map(|s| s.routers.as_slice()),
            Some(&[][..])
        );
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        Ok(())
    }

    #[test]
    fn kea_full_subnet_edit_rewrites_every_managed_member() -> Result<(), String> {
        // A subnet carrying pools, routers and domain-name-servers exercises
        // every canonical builder and every merge branch at once.
        let src = "{ \"Dhcp4\": { \"keep\": true } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let want = vec![KeaSubnet {
            id: 2,
            subnet: "192.0.2.0/24".to_owned(),
            pools: vec![KeaPool {
                pool: "192.0.2.1 - 192.0.2.9".to_owned(),
            }],
            routers: vec!["192.0.2.1".to_owned()],
            domain_servers: vec!["192.0.2.53".to_owned()],
        }];
        let mut model = Model::default();
        model.kea_v4.subnets = want.clone();
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("192.0.2.9"), "{rendered}");
        assert!(rendered.contains("192.0.2.53"), "{rendered}");
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back.kea_v4.subnets, want);
        let _ = report;
        Ok(())
    }

    #[test]
    fn kea_subnet_and_pools_merge_branches() -> Result<(), String> {
        // Changing the id and subnet string, a pools array with modeled and
        // unmodeled entries, and a non-array pools member.
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"pools\": [{\"pool\": \"192.0.2.1 - 192.0.2.9\"}, {\"garbage\": 1}]}, {\"id\": 2, \"subnet\": \"192.0.2.8.0/24\", \"pools\": \"junk\"} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let want = vec![
            KeaSubnet {
                id: 7,
                subnet: "192.0.2.0/24".to_owned(),
                pools: vec![
                    KeaPool {
                        pool: "192.0.2.1 - 192.0.2.9".to_owned(),
                    },
                    KeaPool {
                        pool: "192.0.2.10 - 192.0.2.20".to_owned(),
                    },
                ],
                routers: Vec::new(),
                domain_servers: Vec::new(),
            },
            KeaSubnet {
                id: 2,
                subnet: "192.0.2.8.0/24".to_owned(),
                pools: Vec::new(),
                routers: Vec::new(),
                domain_servers: Vec::new(),
            },
        ];
        let mut model = Model::default();
        model.kea_v4.subnets = want.clone();
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let rendered = DhcpModule::render(&doc);
        // Subnet 1: id rewritten in place, pools kept + appended canonically;
        // the unmodeled garbage pool entry survives. Subnet 2 is unmodeled
        // (its `pools` is not an array), so the model's copy is appended.
        assert!(rendered.contains("192.0.2.10"), "{rendered}");
        assert!(rendered.contains("\"garbage\": 1"), "{rendered}");
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back.kea_v4.subnets, want);
        let _ = report;
        Ok(())
    }

    #[test]
    fn kea_option_data_is_set_and_replaced_from_the_model() -> Result<(), String> {
        // Absent option-data with routers wanted, then garbage option-data
        // with domain servers wanted.
        let mut doc = DhcpModule::parse(
            "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\"} ] } }",
        )
        .map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![KeaSubnet {
                    id: 1,
                    subnet: "192.0.2.0/24".to_owned(),
                    routers: vec!["192.0.2.1".to_owned()],
                    ..KeaSubnet::default()
                }],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("192.0.2.1"), "{rendered}");
        let _ = report;
        // Now the whole option-data member is garbage.
        let mut doc =
            DhcpModule::parse("{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"option-data\": \"junk\"} ] } }")
                .map_err(|e| e.to_string())?;
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("192.0.2.1"), "{rendered}");
        let _ = report;
        Ok(())
    }

    #[test]
    fn kea_subnet4_garbage_is_replaced_when_wanted() -> Result<(), String> {
        let mut doc = DhcpModule::parse("{ \"Dhcp4\": { \"subnet4\": \"junk\" } }")
            .map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![subnet(1, "192.0.2.0/24", &[])],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("192.0.2.0/24"), "{rendered}");
        Ok(())
    }

    #[test]
    fn kea_interfaces_member_garbage_is_replaced_when_wanted() -> Result<(), String> {
        let mut doc = DhcpModule::parse(
            "{ \"Dhcp4\": { \"interfaces-config\": { \"interfaces\": \"junk\" } } }",
        )
        .map_err(|e| e.to_string())?;
        let model = kea4(&["eth0"], None, Vec::new());
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("eth0"), "{rendered}");
        Ok(())
    }

    #[test]
    fn kea_set_member_into_an_empty_object() -> Result<(), String> {
        let mut doc = DhcpModule::parse("{ \"Dhcp4\": {} }").map_err(|e| e.to_string())?;
        let model = kea4(&["eth0"], Some(3600), vec![subnet(1, "192.0.2.0/24", &[])]);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 3);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("3600"), "{rendered}");
        Ok(())
    }

    #[test]
    fn apply_dnsmasq_removes_and_appends_directive_lines() -> Result<(), String> {
        let src = "# c\ninterface=lo\nbind-interfaces\n# tail\n";
        // Fewer settings: the surplus directive lines are dropped.
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = dnsmasq_only(vec![dnsmasq_setting("interface", Some("lo"))]);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(DhcpModule::render(&doc), "# c\ninterface=lo\n# tail\n");
        // More settings: the surplus ones are appended after the directives.
        let mut doc =
            DhcpModule::parse("# c\ninterface=lo\n# tail\n").map_err(|e| e.to_string())?;
        let model = dnsmasq_only(vec![
            dnsmasq_setting("interface", Some("lo")),
            dnsmasq_setting("bind-interfaces", None),
        ]);
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            DhcpModule::render(&doc),
            "# c\ninterface=lo\nbind-interfaces\n# tail\n"
        );
        let _ = report;
        Ok(())
    }

    #[test]
    fn jsonc_sniff_and_literal_roots_edge_paths() {
        // A leading comment (block and line) before the object brace.
        assert!(sniffs_jsonc("/* head */ {"));
        assert!(sniffs_jsonc("// head\n{"));
        // Literal roots at the Jsonc level: a string literal projects, raw
        // tokens and containers do not.
        assert_eq!(Jsonc::Lit(Lit::Raw("7".to_owned())).as_str(), None);
        assert_eq!(
            Jsonc::Lit(Lit::Str {
                raw: "\"s\"".to_owned(),
                value: "s".to_owned(),
            })
            .as_str(),
            Some("s")
        );
        assert_eq!(Jsonc::Obj(Obj::default()).as_str(), None);
        assert_eq!(Jsonc::Obj(Obj::default()).as_u32(), None);
    }

    #[test]
    fn jsonc_depth_limit_and_unterminated_arrays() {
        let deep = "[".repeat(200);
        assert!(parse_jsonc(&deep).is_err());
        assert!(parse_jsonc(&format!("{deep}]")).is_err());
        // Object nesting is depth-limited too: a fully closed 130-deep
        // document is refused, a 100-deep one parses.
        let closed = |levels: usize| {
            let mut s = "{\"a\":".repeat(levels);
            s.push('1');
            s.extend(std::iter::repeat_n('}', levels));
            s
        };
        assert!(parse_jsonc(&closed(200)).is_err());
        assert!(parse_jsonc(&closed(100)).is_ok());
        // Arrays nest and are depth-limited the same way.
        let mut deep_arr = String::from("{ \"a\": ");
        deep_arr.push_str(&"[".repeat(300));
        deep_arr.push_str(&"]".repeat(300));
        deep_arr.push_str(" }");
        assert!(parse_jsonc(&deep_arr).is_err());
        for src in ["[1", "[1,", "{\"a\": [1", "{ \"a\": 1"] {
            assert!(parse_jsonc(src).is_err(), "expected {src:?} to be refused");
        }
    }

    #[test]
    fn decode_high_surrogate_without_an_escape_pair_is_refused() {
        assert_eq!(decode_json_string("\"\\ud800x\""), None);
    }

    #[test]
    fn option_data_member_untouched_when_model_wants_no_options() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"option-data\": [{\"name\": \"ntp-servers\", \"data\": \"1.1.1.1\"}]} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![subnet(1, "192.0.2.0/24", &[])],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        Ok(())
    }

    #[test]
    fn subnet_string_change_is_rewritten_in_place() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\"} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![subnet(1, "192.0.2.0/25", &[])],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("/25"), "{rendered}");
        Ok(())
    }

    #[test]
    fn kea_edit_whose_render_no_longer_parses_is_refused() -> Result<(), String> {
        // `remove_member` fixes no commas: removing the *last* member of the
        // flavor object leaves the previous member's comma behind, the
        // rendered element no longer re-parses, and the whole edit is
        // refused instead of writing a broken file.
        let mut doc =
            DhcpModule::parse("{ \"Dhcp4\": { \"subnet4\": [], \"valid-lifetime\": 3600 } }")
                .map_err(|e| e.to_string())?;
        let model = kea4(&[], None, Vec::new());
        let err = DhcpModule::apply(&mut doc, &model)
            .err()
            .ok_or("expected the edit to be refused")?;
        assert!(
            matches!(err, EditError::Unsupported { .. }),
            "expected the re-parse failure to be refused, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn non_array_pools_are_replaced_when_wanted() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"pools\": \"junk\"} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![subnet(1, "192.0.2.0/24", &["192.0.2.1 - 192.0.2.9"])],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 0);
        let rendered = DhcpModule::render(&doc);
        // The unmodeled subnet is preserved; the model's copy is appended.
        assert!(rendered.contains("\"junk\""), "{rendered}");
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back.kea_v4.subnets, model.kea_v4.subnets);
        let _ = report;
        Ok(())
    }

    #[test]
    fn kea_domain_servers_sync_through_an_existing_option_data_array() -> Result<(), String> {
        // A subnet already carrying a modeled `routers` entry: the model
        // adds domain servers, so the second sync pass runs.
        let src = "{ \"Dhcp4\": { \"subnet4\": [ {\"id\": 1, \"subnet\": \"192.0.2.0/24\", \"option-data\": [{\"name\": \"routers\", \"data\": \"192.0.2.1\"}]} ] } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            kea_v4: KeaConfig {
                subnets: vec![KeaSubnet {
                    routers: vec!["192.0.2.1".to_owned()],
                    domain_servers: vec!["192.0.2.53".to_owned()],
                    ..subnet(1, "192.0.2.0/24", &[])
                }],
                ..KeaConfig::default()
            },
            ..Model::default()
        };
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 0);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("192.0.2.53"), "{rendered}");
        let back = DhcpModule::to_model(&DhcpModule::parse(&rendered).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert_eq!(back.kea_v4.subnets, model.kea_v4.subnets);
        let _ = report;
        Ok(())
    }

    #[test]
    fn interfaces_config_garbage_is_replaced_when_wanted() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"interfaces-config\": \"junk\" } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let model = kea4(&["eth0"], None, Vec::new());
        let report = DhcpModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        let rendered = DhcpModule::render(&doc);
        assert!(rendered.contains("eth0"), "{rendered}");
        Ok(())
    }

    #[test]
    fn garbage_interfaces_member_survives_when_nothing_is_wanted() -> Result<(), String> {
        let src = "{ \"Dhcp4\": { \"interfaces-config\": { \"interfaces\": \"junk\" } } }";
        let mut doc = DhcpModule::parse(src).map_err(|e| e.to_string())?;
        let report = DhcpModule::apply(&mut doc, &Model::default()).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        Ok(())
    }
    // --------------------------------------------------------------- fuzzing

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_builds_a_model() {
        use arbitrary::{Arbitrary, Unstructured};
        let data: Vec<u8> = (0u8..64).collect();
        let mut u = Unstructured::new(&data);
        assert!(Model::arbitrary(&mut u).is_ok());
        assert!(<Model as Arbitrary>::size_hint(0).1.is_none());
    }
}
