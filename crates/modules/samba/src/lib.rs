//! The `samba` module: `/etc/samba/smb.conf` and the `/etc/samba/smb.conf.d`
//! drop-in directory, the Samba server configuration (`testparm`).
//!
//! Every line of `smb.conf` is blank, a `#` or `;` comment, a `[section]`
//! header, or a directive `key = value` — the key may be multi-word, as in
//! `guest ok`, and whitespace around the tokens is insignificant. A `[section]`
//! header and a directive are both modeled as one [`Entry`]: the header carries
//! its name in `section` and leaves `key` and `value` empty, the directive
//! leaves `section` unset. `to_model` walks the file in order, so the UI sees
//! the headers inline exactly where they appear.
//!
//! What is deliberately *not* modeled, and therefore stays
//! [`LineKind::Unknown`]:
//!
//! * a `[`-opening line that does not close its `]` (`[bad`), or one whose
//!   section name is empty (`[]`);
//! * a directive with no key (`= value`);
//! * a bare word or a backslash-continued line — a value ending in `\\`
//!   folds the next line into it (smb.conf(5)), so a line ending in `\\`
//!   cannot stand on its own and is copied through byte for byte rather
//!   than guessed at;
//! * plain garbage.
//!
//! `%` macros (`%m`, `%S`, …) are Samba's runtime substitution, not file
//! syntax: they are kept verbatim in values and never expanded. A value this
//! module cannot re-render is refused by [`render_line`], and the `testparm`
//! check in the descriptor catches whatever a parsing-side refusal cannot.
//!
//! # Formatting policy
//!
//! Hand-tuned indentation is common in this file, so a line is left byte for
//! byte alone whenever the entry parsed from it equals the entry in the model.
//! Only lines that actually change are re-rendered, as `[section]` or
//! `key = value` with single spaces around `=`.
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
use detent_core::doc::{Document, Line, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};

// ------------------------------------------------------------------------- model

/// One entry of `smb.conf`: a `[section]` header or a `key = value` directive.
///
/// A header carries its name in `section` and leaves `key` and `value` empty; a
/// directive carries `key` and `value` and leaves `section` unset. The section
/// a directive belongs to is *not* recorded: the document keeps the headers
/// inline in order, so the section context is whatever header precedes the
/// directive, and duplicating it here would break invariant 2 the moment an
/// edit moves a line.
///
/// Rules that are not negotiable (PLAN §2.3, Appendix A):
///
/// * `#[serde(deny_unknown_fields)]` on **every** struct: the JSON that reaches
///   `apply` comes from the web API and the C ABI, so a typo in a field name must
///   be a loud `ModelError::Shape`, never a silently dropped setting.
/// * Derive `JsonSchema`; the UI is generated from it.
/// * Model semantics, not syntax. Never put raw text, spans, or comments-as-
///   formatting in here — that is the `Doc`'s job, and duplicating it breaks
///   invariant 2.
/// * Every field needs a doc comment: `missing_docs` is on and the text is what
///   the schema shows.
///
/// `Entry` has a hand-written `arbitrary::Arbitrary` impl under the `fuzzing`
/// feature instead of a derive — see it below.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The section name for a `[section]` header; `None` for a `key = value`
    /// directive.
    pub section: Option<String>,
    /// The parameter name: possibly multi-word (`guest ok`), case-insensitive
    /// per smb.conf(5). Empty for a section header.
    pub key: String,
    /// The value, up to the end of the line; `%` macros are kept verbatim.
    /// Empty for a section header.
    pub value: String,
}

/// The typed model of `/etc/samba/smb.conf`: its entries, in file order.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The entries, in the order they appear in the file.
    pub entries: Vec<Entry>,
}

/// Builds a fuzz-friendly name: 1–8 characters of `[a-z0-9_-]`, the shape of
/// every real section name (`global`, `homes`, `print$`) and of every word of a
/// multi-word parameter name.
#[cfg(feature = "fuzzing")]
fn arbitrary_name(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_-";
    let len = u.int_in_range(1..=8usize)?;
    let mut name = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        name.push(char::from(byte));
    }
    Ok(name)
}

/// Builds a fuzz-friendly parameter key: one to three words joined by single
/// spaces, the shape of every real key (`workgroup`, `guest ok`,
/// `server min protocol`), and never one carrying `=` — the fuzz `edit` target
/// has no use for a key that `parse_entry` would split differently.
#[cfg(feature = "fuzzing")]
fn arbitrary_key(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    let words = u.int_in_range(1..=3usize)?;
    let mut key = arbitrary_name(u)?;
    for _ in 1..words {
        key.push(' ');
        key.push_str(&arbitrary_name(u)?);
    }
    Ok(key)
}

/// Builds a fuzz-friendly value: 0–12 characters of the alphabet real values
/// use, including the delimiters this format treats as ordinary data (`%`,
/// `=`, `[`, `]`, `;`), so the fuzz `edit` target exercises them instead of
/// only the alphabet-shaped cases.
#[cfg(feature = "fuzzing")]
fn arbitrary_value(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._%=/[];-";
    let len = u.int_in_range(0..=12usize)?;
    let mut value = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        value.push(char::from(byte));
    }
    Ok(value)
}

/// A fuzz-friendly `Arbitrary` for [`Entry`]: derived generation would produce
/// keys and values carrying arbitrary bytes, most of which `apply` rejects
/// (correctly — invariant 5) before ever reaching the matching or rendering
/// logic the `fuzz_samba_edit` target wants to exercise. This constrains
/// sections, keys and values to the shapes the file really accepts, and picks
/// the header/directive split explicitly.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for Entry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if bool::arbitrary(u)? {
            Ok(Entry {
                section: Some(arbitrary_name(u)?),
                key: String::new(),
                value: String::new(),
            })
        } else {
            Ok(Entry {
                section: None,
                key: arbitrary_key(u)?,
                value: arbitrary_value(u)?,
            })
        }
    }
}

// ------------------------------------------------------------ parsing / rendering

/// Parses one line as an entry, or `None` when it is not one.
///
/// A line is a section header when it is `[<name>]` after trimming, the name
/// being the text between the brackets, itself trimmed. Otherwise it is a
/// directive when it carries an `=`: key is the text before the first `=`,
/// value the text after, both trimmed. Keys and values with surrounding
/// whitespace normalize away because that whitespace is insignificant
/// (smb.conf(5)); a header with an empty name (`[]`) or a directive with an
/// empty key (`= value`) is refused and stays [`LineKind::Unknown`] rather
/// than being silently re-shaped — the same posture `parse_client` takes in
/// the `nfs` module.
fn parse_entry(raw: &str) -> Option<Entry> {
    let trimmed = raw.trim();
    if trimmed.ends_with('\\') {
        return None;
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let name = inner.trim();
        if name.is_empty() {
            return None;
        }
        return Some(Entry {
            section: Some(name.to_owned()),
            key: String::new(),
            value: String::new(),
        });
    }
    let (key, value) = trimmed.split_once('=')?;
    if key.trim().is_empty() {
        return None;
    }
    Some(Entry {
        section: None,
        key: key.trim().to_owned(),
        value: value.trim().to_owned(),
    })
}

/// Classifies a line for the lossless document model.
///
/// The classifier is a pure function of the line text alone: `Document` re-runs
/// it after every edit, so a context-dependent classifier would make `apply`
/// non-deterministic. `Directive` means exactly "`parse_entry` succeeds" —
/// `to_model` and `apply` both walk `Directive` lines, and if the two disagree
/// invariant 2 breaks.
///
/// A leading-whitespace line that carries no `=`, `[` or comment marker — a
/// wrapped continuation of the previous value, as smb.conf(5) allows — cannot
/// stand on its own and is `Unknown`, so `apply` copies it through byte for
/// byte instead of guessing at it.
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

/// Renders an entry as a line, refusing anything that would not survive a
/// round trip.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when the rendered line carries `\n`, `\r` or
/// NUL (invariant 5), and [`EditError::Unsupported`] when the rendered line
/// does not parse back to the same entry — an empty key, an empty section
/// name, a value that is not already trimmed, or a key carrying `=` (the
/// rendered line would split at the wrong `=`).
fn render_line(entry: &Entry) -> Result<String, EditError> {
    if let Some(name) = &entry.section {
        if name.contains('[') || name.contains(']') || name.contains('/') || name.ends_with('\\') {
            return Err(EditError::Unsupported {
                message: format!("section name would not round-trip: {name:?}"),
            });
        }
    } else if entry.key.starts_with('[')
        || entry.key.starts_with('/')
        || entry.key.starts_with('#')
        || entry.key.starts_with(';')
        || entry.key.ends_with('\\')
        || entry.value.ends_with('\\')
    {
        return Err(EditError::Unsupported {
            message: format!("entry would not round-trip due to smb.conf syntax: {entry:?}"),
        });
    }
    let raw = if let Some(name) = &entry.section {
        format!("[{name}]")
    } else if entry.value.is_empty() {
        format!("{} =", entry.key)
    } else {
        format!("{} = {}", entry.key, entry.value)
    };
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

/// Samba is a Linux-only target here: the `samba_server` BSD rc script is
/// listed for portability, but the deferred BSD tier is not a supported backend
/// yet.
fn samba_backend_detect(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

static TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/samba/smb.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: samba_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/samba/smb.conf.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: samba_backend_detect,
    },
];

/// The upstream validator run against the candidate file before it is
/// installed: `testparm -s` parses a configuration file without starting any
/// daemon (`-s` suppresses the interactive press-enter prompt); the file to
/// check is given as the last argument, where [`ArgTemplate::TempFile`] is
/// replaced by the path of the candidate.
static CHECKS: &[ExternalCheck] = &[ExternalCheck {
    program: PathSpec::new("/usr/bin/testparm"),
    args: &[ArgTemplate::Literal("-s"), ArgTemplate::TempFile],
    expects: CheckExpectation::ExitZero,
}];

/// The services a change to these files affects. systemd names the classic
/// file/printer server `smb.service` on most distributions and
/// `samba.service` where the distribution runs the AD DC binary instead;
/// `samba` is the `OpenRC` script and `samba_server` the FreeBSD rc script.
/// `actions` lists what the admin may ask for after an apply, most preferred
/// first — smbd reloads its configuration on SIGHUP, so a full restart is
/// rarely required.
static SERVICES: &[ServiceBinding] = &[ServiceBinding {
    units: UnitNames {
        systemd: &["smb.service", "samba.service"],
        openrc: &["samba"],
        bsdrc: &["samba_server"],
    },
    actions: &[ServiceAction::Reload, ServiceAction::Restart],
}];

/// Keep every value here in sync with `upstream.toml`; the unit test below
/// fails when they drift. `commit_confirm` is `false` because a bad smb.conf
/// degrades file sharing but cannot lock the admin out of the host (ADR-012).
static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "samba",
    display_name_id: MessageId::new("samba-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "samba",
        repo_url: "https://git.samba.org/samba.git",
        tracked_version: "4.24.7",
        // Samba publishes no release atom feed, so the descriptor carries
        // `None` and upstream-watch falls back to comparing tags in `repo_url`.
        release_feed: None,
        docs: &["https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html"],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: false,
    security_notes: &[MessageId::new("samba-note-guest-access")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `entries`.
static ENTRIES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("samba-tip-entries"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: Some("4.24"),
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].section`.
static SECTION_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("samba-tip-section"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: Some("4.24"),
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].key`.
static KEY_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("samba-tip-key"),
    recommendation: None,
    security_impact: SecurityImpact::High,
    since: Some("4.24"),
    deprecated_in: None,
    requires_restart: true,
};

/// UI hints for `entries[].value`.
static VALUE_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("samba-tip-value"),
    recommendation: Some(MessageId::new("samba-rec-value")),
    security_impact: SecurityImpact::High,
    since: Some("4.24"),
    deprecated_in: None,
    requires_restart: true,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `SambaModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema.
///
/// The JSON pointers depend on the shape `schemars` generates. `apply_hints`
/// returns `false` when a pointer resolves to nothing, and the test below turns
/// that into a failure — do not drop the assertion, a silently unattached hint
/// is invisible in the UI.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/entries", &ENTRIES_HINTS),
        ("/$defs/Entry/properties/section", &SECTION_HINTS),
        ("/$defs/Entry/properties/key", &KEY_HINTS),
        ("/$defs/Entry/properties/value", &VALUE_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: a directive has no parameter name.
const EMPTY_KEY: MessageId = MessageId::new("samba-empty-key");
/// Fluent id: a section header is empty.
const EMPTY_SECTION: MessageId = MessageId::new("samba-empty-section");
/// Fluent id: a key carries syntax that would inject a section or comment.
const BAD_KEY: MessageId = MessageId::new("samba-bad-key");
/// Fluent id: a value ends with a backslash and would swallow the next line.
const BAD_VALUE: MessageId = MessageId::new("samba-bad-value");
/// Fluent id: a section name contains syntax that would not round-trip.
const BAD_SECTION: MessageId = MessageId::new("samba-bad-section");
/// Fluent id: `guest ok = yes` invites unauthenticated clients.
const GUEST_OK: MessageId = MessageId::new("samba-guest-ok");
/// Fluent id: `map to guest` is not `Never`.
const MAP_TO_GUEST: MessageId = MessageId::new("samba-map-to-guest");
/// Fluent id: `server min protocol` is below `SMB3_00`.
const MIN_PROTOCOL: MessageId = MessageId::new("samba-min-protocol");
/// Fluent id: `smb encrypt` is not `required`.
const SMB_ENCRYPT: MessageId = MessageId::new("samba-smb-encrypt");
/// Fluent id: `restrict anonymous` is below 2.
const RESTRICT_ANONYMOUS: MessageId = MessageId::new("samba-restrict-anonymous");
/// Fluent id: `server signing` is not `mandatory`.
const REC_SERVER_SIGNING: MessageId = MessageId::new("samba-rec-server-signing");
/// Fluent id: `load printers` is not `no`.
const REC_LOAD_PRINTERS: MessageId = MessageId::new("samba-rec-load-printers");
/// Fluent id: no `interfaces` directive binds samba to explicit addresses.
const REC_INTERFACES: MessageId = MessageId::new("samba-rec-interfaces");
/// Fluent id: a share exposes writes through a writable alias.
const WRITABLE_EXPOSURE: MessageId = MessageId::new("samba-writable-exposure");
/// Fluent id: a share runs a command with root privileges.
const ROOT_COMMAND: MessageId = MessageId::new("samba-root-command");

/// Checks one entry's shape: a directive needs a key, a header a name. Both
/// can only fail for a model that arrived through the JSON API — `parse_entry`
/// refuses both shapes in the file — so this is the loud defense in depth for
/// API callers, exactly like `EMPTY_HOST` in the `nfs` module.
fn validate_entry(entry: &Entry, index: usize, out: &mut Diagnostics) {
    if let Some(name) = &entry.section {
        if name.is_empty() {
            out.push(
                Diagnostic::new(Severity::Error, EMPTY_SECTION)
                    .with_field(FieldPath::new(format!("entries/{index}/section"))),
            );
        } else if name.contains('[')
            || name.contains(']')
            || name.contains('/')
            || name.ends_with('\\')
        {
            out.push(
                Diagnostic::new(Severity::Error, BAD_SECTION)
                    .with_field(FieldPath::new(format!("entries/{index}/section")))
                    .with_arg("section", name.clone()),
            );
        }
    } else {
        if entry.key.is_empty() {
            out.push(
                Diagnostic::new(Severity::Error, EMPTY_KEY)
                    .with_field(FieldPath::new(format!("entries/{index}/key"))),
            );
        } else if entry.key.starts_with('[')
            || entry.key.starts_with('/')
            || entry.key.starts_with('#')
            || entry.key.starts_with(';')
            || entry.key.ends_with('\\')
        {
            out.push(
                Diagnostic::new(Severity::Error, BAD_KEY)
                    .with_field(FieldPath::new(format!("entries/{index}/key")))
                    .with_arg("key", entry.key.clone()),
            );
        }
        if entry.value.ends_with('\\') {
            out.push(
                Diagnostic::new(Severity::Error, BAD_VALUE)
                    .with_field(FieldPath::new(format!("entries/{index}/value")))
                    .with_arg("value", entry.value.clone()),
            );
        }
    }
}

/// The last matching directive in `section`, with the global value as fallback.
fn value_of_in_section<'a>(
    entries: &'a [Entry],
    section: Option<&str>,
    keys: &[&str],
) -> Option<&'a str> {
    let find = |wanted: Option<&str>| {
        let mut current = None;
        entries.iter().rev().find_map(|entry| {
            if let Some(name) = &entry.section {
                current = Some(name.as_str());
                return None;
            }
            let in_section = match (current, wanted) {
                (None, None) => true,
                (Some(current), Some(wanted)) => current.eq_ignore_ascii_case(wanted),
                _ => false,
            };
            (in_section && keys.iter().any(|key| entry.key.eq_ignore_ascii_case(key)))
                .then_some(entry.value.as_str())
        })
    };
    let is_global = section.is_none_or(|name| name.eq_ignore_ascii_case("global"));
    if is_global {
        find(Some("global")).or_else(|| find(None))
    } else {
        find(section).or_else(|| find(Some("global")).or_else(|| find(None)))
    }
}

/// Whether the effective value in `section` differs from `wanted`.
fn offending<'a>(
    entries: &'a [Entry],
    section: Option<&str>,
    keys: &[&str],
    wanted: &str,
) -> Option<&'a str> {
    value_of_in_section(entries, section, keys).filter(|value| !value.eq_ignore_ascii_case(wanted))
}

/// The rank of a `server min protocol` token, lowest first, or `None` when it
/// is not one of the protocol names smb.conf(5) documents. [`SMB3_BASE_RANK`]
/// is `SMB3_00`; anything lower is an SMB1-era or pre-SMB3 level.
const SMB3_BASE_RANK: u8 = 4;

fn protocol_rank(value: &str) -> Option<u8> {
    let rank = match value.trim().to_ascii_uppercase().as_str() {
        "CORE" | "COREPLUS" | "LANMAN1" | "LANMAN2" => 0,
        "NT1" => 1,
        "SMB2_02" | "SMB2" => 2,
        "SMB2_10" => 3,
        "SMB3_00" | "SMB3" => 4,
        "SMB3_02" => 5,
        "SMB3_11" => 6,
        _ => return None,
    };
    Some(rank)
}

/// The `(unset)` marker handed to Fluent when a recommendation fires for a
/// parameter the model does not set at all.
const UNSET: &str = "(unset)";

/// Checks effective values in one section. Share values inherit `[global]`.
fn validate_scope(
    entries: &[Entry],
    section: Option<&str>,
    recommendations: bool,
    out: &mut Diagnostics,
) {
    if let Some(value) = offending(entries, section, &["guest ok", "public"], "no") {
        out.push(Diagnostic::new(Severity::Warning, GUEST_OK).with_arg("value", value.to_owned()));
    }
    if let Some(value) = offending(entries, section, &["map to guest"], "Never") {
        out.push(
            Diagnostic::new(Severity::Warning, MAP_TO_GUEST).with_arg("value", value.to_owned()),
        );
    }
    if let Some(value) = value_of_in_section(entries, section, &["server min protocol"])
        && let Some(rank) = protocol_rank(value)
        && rank < SMB3_BASE_RANK
    {
        out.push(
            Diagnostic::new(Severity::Warning, MIN_PROTOCOL).with_arg("value", value.to_owned()),
        );
    }
    if let Some(value) = offending(entries, section, &["smb encrypt"], "required") {
        out.push(
            Diagnostic::new(Severity::Warning, SMB_ENCRYPT).with_arg("value", value.to_owned()),
        );
    }
    if let Some(value) = value_of_in_section(entries, section, &["restrict anonymous"])
        && let Ok(count) = value.trim().parse::<u32>()
        && count < 2
    {
        out.push(
            Diagnostic::new(Severity::Warning, RESTRICT_ANONYMOUS)
                .with_arg("value", value.to_owned()),
        );
    }
    let writable = value_of_in_section(entries, section, &["writeable", "read only"]);
    let write_list = value_of_in_section(entries, section, &["write list"]);
    if writable.is_some_and(|value| value.eq_ignore_ascii_case("yes") || value.is_empty())
        || write_list.is_some_and(|value| !value.is_empty())
    {
        out.push(Diagnostic::new(Severity::Warning, WRITABLE_EXPOSURE));
    }
    if recommendations {
        match value_of_in_section(entries, section, &["server signing"]) {
            Some(value) if !value.eq_ignore_ascii_case("mandatory") => out.push(
                Diagnostic::new(Severity::Recommendation, REC_SERVER_SIGNING)
                    .with_arg("value", value.to_owned()),
            ),
            None => out.push(
                Diagnostic::new(Severity::Recommendation, REC_SERVER_SIGNING)
                    .with_arg("value", UNSET.to_owned()),
            ),
            _ => {}
        }
        match value_of_in_section(entries, section, &["load printers"]) {
            Some(value) if !value.eq_ignore_ascii_case("no") => out.push(
                Diagnostic::new(Severity::Recommendation, REC_LOAD_PRINTERS)
                    .with_arg("value", value.to_owned()),
            ),
            None => out.push(
                Diagnostic::new(Severity::Recommendation, REC_LOAD_PRINTERS)
                    .with_arg("value", UNSET.to_owned()),
            ),
            _ => {}
        }
        if value_of_in_section(entries, section, &["interfaces"]).is_none() {
            out.push(Diagnostic::new(Severity::Recommendation, REC_INTERFACES));
        }
    }
}

fn validate_values(entries: &[Entry], out: &mut Diagnostics) {
    let mut sections: Vec<&str> = Vec::new();
    for entry in entries {
        if let Some(section) = entry.section.as_deref()
            && !section.eq_ignore_ascii_case("global")
            && !sections
                .iter()
                .any(|known| known.eq_ignore_ascii_case(section))
        {
            sections.push(section);
        }
        if entry.section.is_none()
            && !entry.value.is_empty()
            && ["root preexec", "root postexec", "preexec", "postexec"]
                .iter()
                .any(|key| entry.key.eq_ignore_ascii_case(key))
        {
            out.push(
                Diagnostic::new(Severity::Warning, ROOT_COMMAND).with_arg("key", entry.key.clone()),
            );
        }
    }
    validate_scope(entries, None, true, out);
    for section in sections {
        validate_scope(entries, Some(section), false, out);
    }
}

// -------------------------------------------------------------------- defaults

/// Builds one entry.
fn entry(section: Option<&str>, key: &str, value: &str) -> Entry {
    Entry {
        section: section.map(str::to_owned),
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// The hardened `[global]` section, shared by every OS branch of
/// [`SambaModule::defaults`].
fn hardened_global() -> Model {
    Model {
        entries: vec![
            entry(Some("global"), "", ""),
            entry(None, "server min protocol", "SMB3_00"),
            entry(None, "server signing", "mandatory"),
            entry(None, "smb encrypt", "required"),
            entry(None, "map to guest", "Never"),
            entry(None, "restrict anonymous", "2"),
            entry(None, "load printers", "no"),
        ],
    }
}

// ----------------------------------------------------------------------- module

/// The `/etc/samba/smb.conf` config module.
pub struct SambaModule;

impl ConfigModule for SambaModule {
    const ID: &'static str = "samba";
    /// `detent_core::doc::Document` is the shared line-oriented CST and fits
    /// smb.conf: one line, one entry (a continuation line stays `Unknown`, see
    /// the crate header).
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    /// `parse` is total for line-oriented formats — it returns `Ok` for every
    /// `&str`, including empty input, lone `\r`, and embedded NUL. Invariant 6
    /// runs it over 1 MiB of adversarial bytes.
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// Projects only what the model can express, and drops nothing else —
    /// `Unknown` and `Comment` lines stay in the `Doc` and are what makes
    /// `render` lossless.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        Ok(Model {
            entries: doc
                .lines_of_kind(LineKind::Directive)
                .filter_map(|line| parse_entry(line.raw()))
                .collect(),
        })
    }

    /// The two-pass, minimal-edit shape. Pass 1 is read-only and renders every
    /// changed line before touching the document, so a rejected value (invariant
    /// 5) leaves the file exactly as it was. A line whose parsed entry already
    /// equals the model's is not rendered at all, so hand-tuned indentation
    /// survives. Pass 2 only ever touches `Directive` lines; comments, blanks
    /// and unknown directives keep their position, and new lines go after the
    /// last existing directive, not at the end of the file.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1, read-only: pair model entries with the existing directive
        // lines in order and render the ones that differ.
        let mut planned: Vec<Option<String>> = Vec::with_capacity(model.entries.len());
        for line in doc
            .lines()
            .iter()
            .filter(|line| line.kind() == LineKind::Directive)
        {
            let Some(wanted) = model.entries.get(planned.len()) else {
                break;
            };
            let unchanged = parse_entry(line.raw()).as_ref() == Some(wanted);
            planned.push(if unchanged {
                None
            } else {
                Some(render_line(wanted)?)
            });
        }
        for wanted in model.entries.iter().skip(planned.len()) {
            planned.push(Some(render_line(wanted)?));
        }

        // Pass 2: rewrite, drop the directive lines the model no longer has,
        // and append the rest after the last directive line.
        let mut report = EditReport::default();
        let mut index = 0usize;
        let mut matched = 0usize;
        let mut after_last_directive: Option<usize> = None;
        while index < doc.len() {
            if doc.lines().get(index).map(Line::kind) != Some(LineKind::Directive) {
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

    /// Every finding carries a Fluent id — never a rendered sentence, this crate
    /// does not localize (ADR-003). Errors mean the config must not be applied;
    /// warnings mean valid-but-likely-not-what-you-meant; recommendations mean
    /// fine-but-better-exists. Findings about one field carry a [`FieldPath`]
    /// (`entries/{i}/...`) so the UI can point at the control.
    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        for (index, item) in model.entries.iter().enumerate() {
            validate_entry(item, index, &mut diagnostics);
        }
        validate_values(&model.entries, &mut diagnostics);
        diagnostics
    }

    /// Secure defaults, not upstream's shipped file: a `[global]` section with
    /// the modern protocol floor — SMB3 or newer, mandatory signing, required
    /// encryption, no guest mapping, no anonymous enumeration, no printer
    /// sharing. smb.conf has no per-OS directives here, so every branch
    /// returns the same model — the match stays exhaustive so a new platform
    /// tier is a compile error here instead of a silently wrong file
    /// (ADR-013). Whatever this returns must pass `validate` with no errors;
    /// the test below asserts exactly that.
    fn defaults(profile: &HostProfile) -> Self::Model {
        match profile.os {
            Os::Linux | Os::MacOs | Os::Other => hardened_global(),
        }
    }

    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BAD_KEY, BAD_SECTION, BAD_VALUE, EMPTY_KEY, EMPTY_SECTION, Entry, GUEST_OK, MAP_TO_GUEST,
        MIN_PROTOCOL, Model, REC_INTERFACES, REC_LOAD_PRINTERS, REC_SERVER_SIGNING,
        RESTRICT_ANONYMOUS, ROOT_COMMAND, SMB_ENCRYPT, SambaModule, WRITABLE_EXPOSURE, classify,
        entry, hardened_global, parse_entry, protocol_rank, render_line, schema_with_hints,
        value_of_in_section,
    };
    use detent_core::descriptor::{
        ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, InitSystem, Os, ValidationCtx,
    };
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};

    /// `locales/en-US/core.ftl` is the source of truth for every user-facing
    /// string (PLAN §4.3). Read it directly so the test holds the landed
    /// block green, not a staging snippet (cf. chrony/mounts/nfs).
    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
    /// reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "samba-name",
            "samba-note-guest-access",
            "samba-tip-entries",
            "samba-tip-section",
            "samba-tip-key",
            "samba-tip-value",
            "samba-rec-value",
            "samba-empty-key",
            "samba-empty-section",
            "samba-guest-ok",
            "samba-map-to-guest",
            "samba-min-protocol",
            "samba-smb-encrypt",
            "samba-restrict-anonymous",
            "samba-rec-server-signing",
            "samba-rec-load-printers",
            "samba-rec-interfaces",
            "samba-writable-exposure",
            "samba-root-command",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = SambaModule::descriptor().upstream;
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
        // Samba publishes no release atom feed, so the descriptor carries
        // `None` and upstream-watch falls back to comparing tags in `repo_url`.
        assert_eq!(upstream.release_feed, None);
        assert!(UPSTREAM_TOML.contains("release_feed = \"\""));
        assert!(UPSTREAM_TOML.contains("[fixtures]"));
        assert!(UPSTREAM_TOML.contains("dirs = [\"samba-4.24.7\", \"edge\"]"));
    }

    fn profile(os: Os) -> HostProfile {
        HostProfile {
            os,
            init: InitSystem::None,
            hostname: "host".to_owned(),
            service_versions: std::collections::BTreeMap::new(),
            ram_mib: 0,
        }
    }

    fn has(model: &Model, id: MessageId, severity: Severity) -> bool {
        let host = profile(Os::Linux);
        let ctx = ValidationCtx::new(&host);
        SambaModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    fn model(entries: Vec<Entry>) -> Model {
        Model { entries }
    }

    // ---------------------------------------------------------------- parse_entry

    #[test]
    fn parse_entry_reads_headers_and_directives() {
        assert_eq!(parse_entry("[global]"), Some(entry(Some("global"), "", "")));
        assert_eq!(
            parse_entry("  [ homes ]  "),
            Some(entry(Some("homes"), "", ""))
        );
        assert_eq!(
            parse_entry("   guest ok   =   yes   "),
            Some(entry(None, "guest ok", "yes"))
        );
        assert_eq!(
            parse_entry("workgroup=MYGROUP"),
            Some(entry(None, "workgroup", "MYGROUP"))
        );
        // An empty value is legal (a flag-style parameter).
        assert_eq!(
            parse_entry("wide links ="),
            Some(entry(None, "wide links", ""))
        );
        // `=` inside the value belongs to the value.
        assert_eq!(
            parse_entry("add share command = /usr/bin/add-share --a=b"),
            Some(entry(None, "add share command", "/usr/bin/add-share --a=b"))
        );
    }

    #[test]
    fn parse_entry_rejects_non_entries() {
        for line in [
            "",
            "   ",
            "# comment",
            "; comment",
            "[]",
            "[bad",
            "[bad ] trailing",
            "= no-key",
            "=",
            "bare continuation",
        ] {
            assert_eq!(parse_entry(line), None, "expected {line:?} to be refused");
        }
    }

    // ------------------------------------------------------------------ classify

    #[test]
    fn classify_assigns_the_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("   "), LineKind::Blank);
        assert_eq!(classify("# comment"), LineKind::Comment);
        assert_eq!(classify(";  indented ; comment"), LineKind::Comment);
        assert_eq!(classify("  # indented"), LineKind::Comment);
        assert_eq!(classify("[global]"), LineKind::Directive);
        assert_eq!(classify("   workgroup = MYGROUP"), LineKind::Directive);
        assert_eq!(
            classify("include = /etc/samba/smb.conf.%m"),
            LineKind::Directive
        );
        // A continuation line cannot stand on its own.
        assert_eq!(classify("   192.168.1.0/24"), LineKind::Unknown);
        assert_eq!(classify("[bad"), LineKind::Unknown);
        assert_eq!(classify("[]"), LineKind::Unknown);
        assert_eq!(classify("= no-key"), LineKind::Unknown);
        assert_eq!(classify("%m"), LineKind::Unknown);
    }

    // --------------------------------------------------------------- render_line

    #[test]
    fn render_line_emits_canonical_lines() {
        assert_eq!(
            render_line(&entry(Some("homes"), "", "")),
            Ok("[homes]".to_owned())
        );
        assert_eq!(
            render_line(&entry(None, "guest ok", "yes")),
            Ok("guest ok = yes".to_owned())
        );
        assert_eq!(
            render_line(&entry(None, "wide links", "")),
            Ok("wide links =".to_owned())
        );
        // The delimiters smb.conf treats as ordinary data survive in values,
        // and `%` macros are never expanded.
        assert_eq!(
            render_line(&entry(None, "log file", "%m.%S a=b [x] ;y")),
            Ok("log file = %m.%S a=b [x] ;y".to_owned())
        );
    }

    #[test]
    fn render_line_rejects_a_line_break_in_a_value() {
        for bad in [
            entry(None, "log file", "a\nb"),
            entry(None, "log\rb", ""),
            entry(None, "key", "a\0b"),
            entry(Some("a\nb"), "", ""),
            entry(Some("a\0b"), "", ""),
        ] {
            assert!(
                matches!(render_line(&bad), Err(EditError::LineBreakInValue { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn render_line_rejects_smb_conf_syntax() {
        assert!(matches!(
            render_line(&entry(None, "log file", "a\\")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(None, "key\\", "value")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(None, "[evil] x", "y")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(None, "/evil", "y")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(None, "; comment-in-key", "y")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(None, "# comment", "y")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(Some("bad]name"), "", "")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(Some("bad[name"), "", "")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(Some("bad/"), "", "")),
            Err(EditError::Unsupported { .. })
        ));
        assert!(matches!(
            render_line(&entry(Some("trailing\\"), "", "")),
            Err(EditError::Unsupported { .. })
        ));
    }

    #[test]
    fn parse_entry_returns_none_on_continued_lines() {
        assert_eq!(parse_entry("a = b \\"), None);
        assert_eq!(parse_entry("a = b\\"), None);
        assert_eq!(parse_entry("[global] \\"), None);
    }

    #[test]
    fn render_line_rejects_values_that_would_not_round_trip() {
        for bad in [
            // Empty key: the rendered line would have no parameter name.
            entry(None, "", "yes"),
            // Empty section name.
            entry(Some(""), "", ""),
            // Untrimmed value: the rendered line would parse back to a
            // different value.
            entry(None, "key", " x"),
            entry(None, "key", "x "),
            // Untrimmed key: the rendered line would split differently.
            entry(None, " key ", "x"),
        ] {
            assert!(
                matches!(render_line(&bad), Err(EditError::Unsupported { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    // ------------------------------------------------------------------ to_model

    #[test]
    fn to_model_reads_only_directive_lines() -> Result<(), String> {
        let src =
            "; comment\n\n[global]\nworkgroup = MYGROUP\n[bad\n   192.168.1.0/24\nlog file = %m\n";
        let doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let parsed = SambaModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            parsed,
            model(vec![
                entry(Some("global"), "", ""),
                entry(None, "workgroup", "MYGROUP"),
                entry(None, "log file", "%m"),
            ])
        );
        assert_eq!(SambaModule::render(&doc), src);
        Ok(())
    }

    // --------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\n[global]\n   workgroup   =   MYGROUP\n";
        let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let model = SambaModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = SambaModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(SambaModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_directive() -> Result<(), String> {
        let src = "[global]\nworkgroup = MYGROUP\ndns proxy = no\n";
        let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "workgroup", "WORKGROUP"),
            entry(None, "dns proxy", "no"),
        ]);
        let report = SambaModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(
            SambaModule::render(&doc),
            "[global]\nworkgroup = WORKGROUP\ndns proxy = no\n"
        );
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_directives() -> Result<(), String> {
        let src = "[global]\nworkgroup = MYGROUP\nmax log size = 50\n";
        let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "workgroup", "MYGROUP"),
        ]);
        let report = SambaModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(SambaModule::render(&doc), "[global]\nworkgroup = MYGROUP\n");
        Ok(())
    }

    #[test]
    fn apply_appends_after_the_last_directive_line() -> Result<(), String> {
        let src = "[global]\nworkgroup = MYGROUP\n# trailing comment\n";
        let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let mut m = SambaModule::to_model(&doc).map_err(|e| e.to_string())?;
        m.entries.push(entry(None, "smb encrypt", "required"));
        let report = SambaModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            SambaModule::render(&doc),
            "[global]\nworkgroup = MYGROUP\nsmb encrypt = required\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_directive_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "workgroup", "MYGROUP"),
        ]);
        let report = SambaModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 2);
        assert_eq!(
            SambaModule::render(&doc),
            "# only a comment\n[global]\nworkgroup = MYGROUP\n"
        );
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        for probe in [
            entry(None, "log file", "a\nb"),
            entry(None, "log\rb", ""),
            entry(None, "key", "a\0b"),
            entry(Some("a\nb"), "", ""),
        ] {
            let src = "[global]\nworkgroup = MYGROUP\n";
            let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
            assert!(SambaModule::apply(&mut doc, &model(vec![probe])).is_err());
            assert_eq!(SambaModule::render(&doc), src);
        }
        Ok(())
    }

    // ------------------------------------------------------------------ validate

    #[test]
    fn validate_flags_smb_conf_syntax_injection() {
        assert!(has(
            &model(vec![entry(None, "[evil] x", "y")]),
            BAD_KEY,
            Severity::Error
        ));
        assert!(has(
            &model(vec![entry(None, "# comment", "y")]),
            BAD_KEY,
            Severity::Error
        ));
        assert!(has(
            &model(vec![entry(None, "key", "value\\")]),
            BAD_VALUE,
            Severity::Error
        ));
        assert!(has(
            &model(vec![entry(Some("bad]name"), "", "")]),
            BAD_SECTION,
            Severity::Error
        ));
        assert!(has(
            &model(vec![entry(Some("bad/"), "", "")]),
            BAD_SECTION,
            Severity::Error
        ));
    }

    #[test]
    fn validate_flags_an_empty_key_and_an_empty_section() {
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "", "value"),
        ]);
        assert!(has(&m, EMPTY_KEY, Severity::Error));
        let m = model(vec![entry(Some(""), "", "")]);
        assert!(has(&m, EMPTY_SECTION, Severity::Error));
    }

    #[test]
    fn validate_flags_guest_ok() {
        let m = model(vec![entry(None, "guest ok", "yes")]);
        assert!(has(&m, GUEST_OK, Severity::Warning));
        let m = model(vec![entry(None, "guest ok", "no")]);
        assert!(!has(&m, GUEST_OK, Severity::Warning));
    }

    #[test]
    fn validate_walks_share_sections_and_parameter_synonyms() {
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "public", "no"),
            entry(Some("public-share"), "", ""),
            entry(None, "PUBLIC", "yes"),
            entry(None, "write list", "alice"),
            entry(None, "root preexec", "/usr/bin/hook"),
        ]);
        assert!(has(&m, GUEST_OK, Severity::Warning));
        assert!(has(&m, WRITABLE_EXPOSURE, Severity::Warning));
        assert!(has(&m, ROOT_COMMAND, Severity::Warning));
    }

    #[test]
    fn share_override_replaces_dangerous_global_value() {
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "public", "yes"),
            entry(Some("safe"), "", ""),
            entry(None, "public", "no"),
        ]);
        assert!(has(&m, GUEST_OK, Severity::Warning));
    }

    #[test]
    fn validate_flags_map_to_guest() {
        let m = model(vec![entry(None, "map to guest", "Bad User")]);
        assert!(has(&m, MAP_TO_GUEST, Severity::Warning));
        let m = model(vec![entry(None, "map to guest", "never")]);
        assert!(!has(&m, MAP_TO_GUEST, Severity::Warning));
    }

    #[test]
    fn validate_flags_a_protocol_below_smb3() {
        let m = model(vec![entry(None, "server min protocol", "NT1")]);
        assert!(has(&m, MIN_PROTOCOL, Severity::Warning));
        let m = model(vec![entry(None, "server min protocol", "smb2_02")]);
        assert!(has(&m, MIN_PROTOCOL, Severity::Warning));
        let m = model(vec![entry(None, "server min protocol", "SMB3_00")]);
        assert!(!has(&m, MIN_PROTOCOL, Severity::Warning));
        let m = model(vec![entry(None, "server min protocol", "CORE")]);
        assert!(has(&m, MIN_PROTOCOL, Severity::Warning));
        // An unrecognized token is not ranked, so it is not flagged here —
        // `testparm` is the check that owns unknown values.
        let m = model(vec![entry(None, "server min protocol", "SOME_PROTO")]);
        assert!(!has(&m, MIN_PROTOCOL, Severity::Warning));
    }

    #[test]
    fn validate_flags_smb_encrypt_and_restrict_anonymous() {
        let m = model(vec![entry(None, "smb encrypt", "auto")]);
        assert!(has(&m, SMB_ENCRYPT, Severity::Warning));
        let m = model(vec![entry(None, "smb encrypt", "Required")]);
        assert!(!has(&m, SMB_ENCRYPT, Severity::Warning));
        let m = model(vec![entry(None, "restrict anonymous", "1")]);
        assert!(has(&m, RESTRICT_ANONYMOUS, Severity::Warning));
        let m = model(vec![entry(None, "restrict anonymous", "2")]);
        assert!(!has(&m, RESTRICT_ANONYMOUS, Severity::Warning));
        let m = model(vec![entry(None, "restrict anonymous", "no number")]);
        assert!(!has(&m, RESTRICT_ANONYMOUS, Severity::Warning));
    }

    #[test]
    fn validate_recommends_signing_printers_and_interfaces() {
        let m = model(vec![entry(None, "server signing", "auto")]);
        assert!(has(&m, REC_SERVER_SIGNING, Severity::Recommendation));
        let m = model(vec![entry(None, "server signing", "Mandatory")]);
        assert!(!has(&m, REC_SERVER_SIGNING, Severity::Recommendation));
        let m = model(vec![entry(None, "load printers", "yes")]);
        assert!(has(&m, REC_LOAD_PRINTERS, Severity::Recommendation));
        let m = model(vec![]);
        assert!(has(&m, REC_SERVER_SIGNING, Severity::Recommendation));
        assert!(has(&m, REC_LOAD_PRINTERS, Severity::Recommendation));
        assert!(has(&m, REC_INTERFACES, Severity::Recommendation));
        let m = model(vec![
            entry(None, "server signing", "mandatory"),
            entry(None, "load printers", "no"),
            entry(None, "interfaces", "127.0.0.1/8"),
        ]);
        assert!(!has(&m, REC_SERVER_SIGNING, Severity::Recommendation));
        assert!(!has(&m, REC_LOAD_PRINTERS, Severity::Recommendation));
        assert!(!has(&m, REC_INTERFACES, Severity::Recommendation));
    }

    #[test]
    fn value_of_takes_the_last_occurrence_case_insensitively() {
        let m = model(vec![
            entry(None, "guest ok", "no"),
            entry(None, "GUEST OK", "yes"),
        ]);
        assert_eq!(
            value_of_in_section(&m.entries, None, &["guest ok"]),
            Some("yes")
        );
        assert_eq!(
            value_of_in_section(&m.entries, None, &["GUEST OK"]),
            Some("yes")
        );
        assert_eq!(value_of_in_section(&m.entries, None, &["missing"]), None);
    }

    #[test]
    fn protocol_rank_follows_the_documented_order() {
        assert_eq!(protocol_rank("NT1"), Some(1));
        assert_eq!(protocol_rank("smb2_02"), Some(2));
        assert_eq!(protocol_rank("SMB3_00"), Some(4));
        assert_eq!(protocol_rank("SMB3_11"), Some(6));
        assert_eq!(protocol_rank("garbage"), None);
    }

    // ------------------------------------------------------------------ defaults

    #[test]
    fn defaults_are_identical_on_every_operating_system() {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            assert_eq!(SambaModule::defaults(&profile(os)), hardened_global());
        }
        assert_eq!(
            SambaModule::defaults(&profile(Os::Linux)).entries,
            vec![
                entry(Some("global"), "", ""),
                entry(None, "server min protocol", "SMB3_00"),
                entry(None, "server signing", "mandatory"),
                entry(None, "smb encrypt", "required"),
                entry(None, "map to guest", "Never"),
                entry(None, "restrict anonymous", "2"),
                entry(None, "load printers", "no"),
            ]
        );
    }

    #[test]
    fn defaults_are_valid_and_apply_to_an_empty_file() -> Result<(), String> {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            let host = profile(os);
            let ctx = ValidationCtx::new(&host);
            let model = SambaModule::defaults(&host);
            assert!(!SambaModule::validate(&model, &ctx).has_errors());
            let mut doc = SambaModule::parse("").map_err(|e| e.to_string())?;
            let report = SambaModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report.added, model.entries.len());
            let rendered = SambaModule::render(&doc);
            assert_eq!(
                rendered,
                "[global]\nserver min protocol = SMB3_00\nserver signing = mandatory\nsmb encrypt = required\nmap to guest = Never\nrestrict anonymous = 2\nload printers = no\n"
            );
            let back =
                SambaModule::to_model(&SambaModule::parse(&rendered).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            assert_eq!(back, model);
        }
        Ok(())
    }

    // ---------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_checks_and_backend() {
        let descriptor = SambaModule::descriptor();
        assert_eq!(descriptor.id, SambaModule::ID);
        assert_eq!(descriptor.targets.len(), 2);
        assert_eq!(descriptor.targets.first().map(|t| t.mode), Some(0o644));
        assert_eq!(
            descriptor.checks,
            &[ExternalCheck {
                program: detent_core::descriptor::PathSpec::new("/usr/bin/testparm"),
                args: &[ArgTemplate::Literal("-s"), ArgTemplate::TempFile],
                expects: CheckExpectation::ExitZero,
            }] as &[ExternalCheck]
        );
        assert!(!descriptor.commit_confirm);
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux)));
            assert!(!(target.backend_detect)(&profile(Os::MacOs)));
            assert!(!(target.backend_detect)(&profile(Os::Other)));
        }
        let services = descriptor.services;
        assert_eq!(services.len(), 1);
        let units = services.first().map(|binding| binding.units);
        assert_eq!(
            units.map(|units| units.systemd),
            Some(&["smb.service", "samba.service"][..])
        );
        assert_eq!(units.map(|units| units.openrc), Some(&["samba"][..]));
        assert_eq!(units.map(|units| units.bsdrc), Some(&["samba_server"][..]));
    }

    // -------------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, SambaModule::schema());
        for pointer in [
            "/properties/entries",
            "/$defs/Entry/properties/section",
            "/$defs/Entry/properties/key",
            "/$defs/Entry/properties/value",
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

    // ------------------------------------------------------- derived trait impls

    /// Exercises the derived impls the module's own logic never calls. Coverage
    /// is 100 % lines for `crates/modules/` (PLAN §6.2), and a derive with no
    /// caller is the usual reason a module misses it.
    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let m = model(vec![
            entry(Some("global"), "", ""),
            entry(None, "guest ok", "yes"),
        ]);
        assert_eq!(m.clone(), m);
        assert!(format!("{m:?}").contains("guest"));
        assert_eq!(Model::default(), Model { entries: vec![] });
        let json = serde_json::to_value(&m).unwrap_or_default();
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(m));
        assert!(
            serde_json::from_str::<Entry>(r#"{"section":null,"key":"k","value":"v","x":1}"#)
                .is_err(),
            "deny_unknown_fields must reject unknown keys"
        );
        assert_eq!(
            serde_json::from_str::<Entry>(r#"{"section":null,"key":"k","value":"v"}"#).ok(),
            Some(entry(None, "k", "v"))
        );
    }

    // --------------------------------------------------------------- adversarial

    /// These are the shapes that broke real parsers: no trailing newline, CRLF,
    /// NUL, one very long line, and a file large enough that a super-linear
    /// `apply` shows up as a timeout.
    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "[s{i}]");
        }
        for src in [
            "[global]\nworkgroup = MYGROUP",
            "[global]\r\nworkgroup = MYGROUP\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
            "\u{feff}[global]\nname = café\n",
            "[global]\rkey = value",
            "[global]\n[not-a-section\nkey = value\n",
        ] {
            let mut doc = SambaModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(SambaModule::render(&doc), src);
            let model = SambaModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = SambaModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(SambaModule::render(&doc), src);
        }
        Ok(())
    }

    // ------------------------------------------------------------------ fuzzing

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_key_builds_multi_word_keys() {
        use super::arbitrary_key;
        use arbitrary::Unstructured;
        // The leading byte drives `int_in_range(1..=3)`; the zeros make every
        // word a one-character name, so the loop that joins them runs twice.
        let mut u = Unstructured::new(&[2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let key = arbitrary_key(&mut u).unwrap_or_default();
        assert!(key.contains(' '), "expected a multi-word key, got {key:?}");
        assert!(!key.starts_with(' '));
        assert!(!key.ends_with(' '));
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_entries_are_well_shaped_and_apply_cleanly() -> Result<(), String> {
        use arbitrary::{Arbitrary, Unstructured};

        // Enough varied bytes to drive several name, key and value lengths,
        // both arms of `Entry::arbitrary` (header and directive), and empty
        // and non-empty value lists.
        let buffers: &[&[u8]] = &[
            &[0; 64],
            &[0xff; 64],
            &(0u8..80).collect::<Vec<u8>>(),
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 1, 2, 3, 4, 5, 6, 7, 8,
            ],
        ];
        for data in buffers {
            let mut u = Unstructured::new(data);
            let m = Model::arbitrary(&mut u).unwrap_or_default();
            for e in &m.entries {
                if let Some(name) = &e.section {
                    assert!(!name.is_empty(), "generated empty section in {e:?}");
                    assert!(!name.contains(char::is_whitespace));
                } else {
                    assert!(!e.key.is_empty(), "generated empty key in {e:?}");
                    assert!(!e.key.starts_with(' '));
                    assert!(!e.key.ends_with(' '));
                }
            }
            let mut doc = SambaModule::parse("").map_err(|e| e.to_string())?;
            let report = SambaModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
            assert_eq!(report.added, m.entries.len());
        }
        Ok(())
    }
}
