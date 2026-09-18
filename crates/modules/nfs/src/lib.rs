//! The `nfs` module: `/etc/exports` and the `/etc/exports.d` drop-in directory,
//! the NFS server export table maintained by `nfs-utils` (`exportfs`).
//!
//! Every line of `/etc/exports` is blank, a `#` comment, or one export point
//! followed by a whitespace-separated list of clients, each optionally carrying
//! a comma-separated option list in parentheses: `<path> <host>(<opt,...>)
//! [<host>(<opts>)…]`. No whitespace is allowed between a client and its option
//! list. A client with no parentheses takes the file's default options, and a
//! lone path exports to nobody — both are legal and both are modeled.
//!
//! What is deliberately *not* modeled, and therefore stays
//! [`LineKind::Unknown`]:
//!
//! * lines that do not start with `/` — backslash-continued entries, quoted
//!   export names with spaces (`"/srv/with space"`), the `-` default-options
//!   specifications, and plain garbage;
//! * lines with unbalanced or nested parentheses (`h(rw`, `@(g)(sec=krb5p)`),
//!   because one client token has exactly one option list;
//! * anything carrying `#` outside the line-leading comment position.
//!
//! All of these are kept verbatim and never rewritten, so hand-written kerberos
//! setups survive every edit this module makes.
//!
//! # Formatting policy
//!
//! Hand-aligned columns are common in this file, so a line is left byte for byte
//! alone whenever the export parsed from it equals the export in the model. Only
//! lines that actually change are re-rendered, as
//! `<path> <host>(<opts joined by commas>)` with single-space joins.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time. `detent-platform`
//! owns every file operation (PLAN §2.1).

use detent_core::descriptor::{
    ExternalCheck, FieldHints, HostProfile, ModuleDescriptor, Os, Owner, PathSpec, SecurityImpact,
    ServiceAction, ServiceBinding, Target, TargetKind, UiGroup, UnitNames, Upstream, ValidationCtx,
    apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, Line, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};

// ------------------------------------------------------------------------- model

/// One client of an export: a host and the options it is served with.
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
/// `Client` and `Export` have hand-written `arbitrary::Arbitrary` impls under
/// the `fuzzing` feature instead of derives — see them below.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Client {
    /// The client specification: a host name, an address, an address/netmask
    /// pair, a wildcard pattern, `*` (every client), or a `@netgroup`.
    pub host: String,
    /// This client's comma-separated export options, e.g. `["rw", "sync"]`.
    /// An empty list means "take the file's defaults" and renders with no
    /// parentheses at all.
    pub options: Vec<String>,
}

/// One export point and the clients allowed to mount it, in file order.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Export {
    /// The export point: an absolute directory path, as written in the file.
    pub path: String,
    /// The clients allowed to mount this path, in the order they appear on the
    /// line. Match order matters: the first matching client specification wins.
    pub clients: Vec<Client>,
}

/// The typed model of `/etc/exports`: its exports, in file order.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The exports, in the order they appear in the file.
    pub entries: Vec<Export>,
}

/// Builds an RFC 1123-shaped client host: 1–12 characters of the alphabet real
/// client specifications use (names, addresses, `*`, `?`, `@netgroup`,
/// `address/netmask`), never a paren or a whitespace (the fuzz `edit` target
/// never needs wildcards-with-options quoting to exercise `apply`).
#[cfg(feature = "fuzzing")]
fn arbitrary_host(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789*?@.-/";
    let len = u.int_in_range(1..=12usize)?;
    let mut host = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        host.push(char::from(byte));
    }
    Ok(host)
}

/// Builds an absolute export point: `/` followed by one to three segments of
/// letters, digits, `.` and `_`, never a segment with whitespace or parens.
#[cfg(feature = "fuzzing")]
fn arbitrary_path(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._";
    let segments = u.int_in_range(1..=3usize)?;
    let mut path = String::from("/");
    for segment in 0..segments {
        if segment > 0 {
            path.push('/');
        }
        let len = u.int_in_range(1..=8usize)?;
        for _ in 0..len {
            let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
            let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
            path.push(char::from(byte));
        }
    }
    Ok(path)
}

/// Builds one export option: 1–10 characters of `[a-z0-9_]`, the shape of every
/// real option token (`rw`, `sync`, `no_root_squash`, `fsid=0`'s value side is
/// folded into the token alphabet).
#[cfg(feature = "fuzzing")]
fn arbitrary_option(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_=";
    let len = u.int_in_range(1..=10usize)?;
    let mut option = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        option.push(char::from(byte));
    }
    Ok(option)
}

/// A fuzz-friendly `Arbitrary` for [`Client`]: derived generation would produce
/// hosts and options carrying arbitrary bytes, most of which `apply` rejects
/// (correctly — invariant 5) before ever reaching the matching or rendering logic
/// the `fuzz_nfs_edit` target wants to exercise. This constrains hosts and
/// options to the shapes the file format really accepts instead.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for Client {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let host = arbitrary_host(u)?;
        let count = u.int_in_range(0..=4usize)?;
        let mut options = Vec::with_capacity(count);
        for _ in 0..count {
            options.push(arbitrary_option(u)?);
        }
        Ok(Self { host, options })
    }
}

/// A fuzz-friendly `Arbitrary` for [`Export`], for the same reason as
/// [`Client`]'s impl: paths and hosts are constrained to the file's real shapes.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for Export {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let path = arbitrary_path(u)?;
        let count = u.int_in_range(0..=3usize)?;
        let mut clients = Vec::with_capacity(count);
        for _ in 0..count {
            clients.push(Client::arbitrary(u)?);
        }
        Ok(Self { path, clients })
    }
}

// ------------------------------------------------------------ parsing / rendering

/// Parses one client token, or `None` when it is not one.
///
/// A token is `<host>` or `<host>(<opt,...>)` with **no** whitespace between the
/// host and its option list (exports(5)), and at most one option list per token:
/// a trailing `(…)` group after the first, as in the deprecated
/// `@(netgroup)(sec=krb5p)` spelling, is not a client. An option list with a
/// stray paren inside (`h(rw))`, `h(a,(b))`) is also refused — such a line stays
/// [`LineKind::Unknown`] rather than being silently re-shaped.
fn parse_client(token: &str) -> Option<Client> {
    let (host, options_raw) = match token.split_once('(') {
        Some((host, rest)) => {
            let options_raw = rest.strip_suffix(')')?;
            if options_raw.contains(['(', ')']) {
                return None;
            }
            (host, options_raw)
        }
        None => (token, ""),
    };
    // A host never carries `"` or `#`: the first is the marker of a quoted
    // export name this module does not model, the second starts a comment, and
    // neither may be silently swallowed.
    if host.is_empty() || host.contains(['#', '"']) {
        return None;
    }
    let options: Vec<String> = options_raw
        .split(',')
        .filter(|option| !option.is_empty())
        .map(str::to_owned)
        .collect();
    Some(Client {
        host: host.to_owned(),
        options,
    })
}

/// Parses one line as an export, or `None` when it is not one.
///
/// A line is an export when it starts with an absolute path followed by zero or
/// more client tokens. A line that does not start with `/` — a bare word, a
/// quoted path with spaces, a `-` default-options specification — is not an
/// export and stays [`LineKind::Unknown`].
fn parse_export(raw: &str) -> Option<Export> {
    let mut tokens = raw.split_whitespace();
    let path = tokens.next()?;
    if !path.starts_with('/') {
        return None;
    }
    let clients: Vec<Client> = tokens.map(parse_client).collect::<Option<Vec<_>>>()?;
    Some(Export {
        path: path.to_owned(),
        clients,
    })
}

/// Classifies a line for the lossless document model.
///
/// The classifier is a pure function of the line text alone: `Document` re-runs
/// it after every edit, so a context-dependent classifier would make `apply`
/// non-deterministic. `Directive` means exactly "`parse_export` succeeds" —
/// `to_model` and `apply` both walk `Directive` lines, and if the two disagree
/// invariant 2 breaks.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with('#') {
        LineKind::Comment
    } else if parse_export(raw).is_some() {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

/// Renders an export as a line, refusing anything that would not survive a round
/// trip.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when the rendered line carries `\n`, `\r` or
/// NUL (invariant 5), and [`EditError::Unsupported`] when the rendered line does
/// not parse back to the same export — a path containing whitespace, a host or
/// option containing whitespace, `(`, `)`, `#` or a comma, or a value that is not
/// already trimmed.
fn render_line(export: &Export) -> Result<String, EditError> {
    let mut raw = export.path.clone();
    for client in &export.clients {
        raw.push(' ');
        raw.push_str(&client.host);
        if !client.options.is_empty() {
            raw.push('(');
            raw.push_str(&client.options.join(","));
            raw.push(')');
        }
    }
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue { value: raw });
    }
    if parse_export(&raw).as_ref() != Some(export) {
        return Err(EditError::Unsupported {
            message: format!("export does not round-trip through the file format: {raw:?}"),
        });
    }
    Ok(raw)
}

// -------------------------------------------------------------------- descriptor

/// NFS is a Linux-only target here: the `nfsd` BSD rc script is listed for
/// portability, but the deferred BSD tier is not a supported backend yet.
fn nfs_backend_detect(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

static NFS_TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/exports"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: nfs_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/exports.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: nfs_backend_detect,
    },
];

/// `exportfs` has no file-test mode: every invocation that reads a file
/// (`exportfs -ra`) mutates the kernel's live export state, so it can validate a
/// candidate only by already having applied it. That makes it a commit step, not
/// a candidate check — so the check list is empty (as `hosts` does) and the
/// platform layer falls back to the service reload/restart the descriptor
/// already declares.
static NFS_CHECKS: &[ExternalCheck] = &[];

static NFS_SERVICES: &[ServiceBinding] = &[ServiceBinding {
    units: UnitNames {
        systemd: &["nfs-server.service"],
        openrc: &["nfs"],
        bsdrc: &["nfsd"],
    },
    actions: &[ServiceAction::Reload, ServiceAction::Restart],
}];

static NFS_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "nfs",
    display_name_id: MessageId::new("nfs-name"),
    targets: NFS_TARGETS,
    upstream: Upstream {
        project: "nfs-utils",
        // The assignment's candidate URLs were verified and are dead:
        // `https://git.linux-nfs.org/?p=nfs-utils.git` is 404 and the kernel.org
        // mirror does not exist. This is the live cgit repository; its tag list
        // carries `nfs-utils-2-9-2` as the newest non-rc stable release.
        repo_url: "https://git.linux-nfs.org/?p=steved/nfs-utils.git",
        tracked_version: "2.9.2",
        // nfs-utils publishes no release atom feed, so the descriptor carries
        // `None` and upstream-watch falls back to comparing tags in `repo_url`.
        release_feed: None,
        docs: &["https://man7.org/linux/man-pages/man5/exports.5.html"],
    },
    services: NFS_SERVICES,
    checks: NFS_CHECKS,
    commit_confirm: false,
    security_notes: &[MessageId::new("nfs-note-live-state")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `entries`.
static ENTRIES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("nfs-tip-entries"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].path`.
static PATH_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("nfs-tip-path"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].clients`.
static CLIENTS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("nfs-tip-clients"),
    recommendation: None,
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].clients[].host`.
static HOST_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("nfs-tip-host"),
    recommendation: None,
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].clients[].options`.
static OPTIONS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("nfs-tip-options"),
    recommendation: Some(MessageId::new("nfs-rec-options")),
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: true,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `NfsModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/entries", &ENTRIES_HINTS),
        ("/$defs/Export/properties/path", &PATH_HINTS),
        ("/$defs/Export/properties/clients", &CLIENTS_HINTS),
        ("/$defs/Client/properties/host", &HOST_HINTS),
        ("/$defs/Client/properties/options", &OPTIONS_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: an export point is empty.
const EMPTY_PATH: MessageId = MessageId::new("nfs-empty-path");
/// Fluent id: an export point is not absolute.
const RELATIVE_PATH: MessageId = MessageId::new("nfs-relative-path");
/// Fluent id: a client specification is empty.
const EMPTY_HOST: MessageId = MessageId::new("nfs-empty-host");
/// Fluent id: an option token could not have come from a real exports file.
const INVALID_OPTION: MessageId = MessageId::new("nfs-invalid-option");
/// Fluent id: `no_root_squash` hands the client root privileges on the export.
const NO_ROOT_SQUASH: MessageId = MessageId::new("nfs-no-root-squash");
/// Fluent id: the export is reachable with `sec=sys`, i.e. no cryptographic
/// protection.
const SEC_SYS_ONLY: MessageId = MessageId::new("nfs-sec-sys-only");
/// Fluent id: the export is world-writable.
const WORLD_EXPORT: MessageId = MessageId::new("nfs-world-export");
/// Fluent id: neither `subtree_check` nor `no_subtree_check` is explicit.
const SUBTREE_UNDECIDED: MessageId = MessageId::new("nfs-subtree-undecided");
/// Fluent id: neither `root_squash` nor `no_root_squash` is explicit.
const ROOT_SQUASH_UNDECIDED: MessageId = MessageId::new("nfs-root-squash-undecided");
/// Fluent id: neither `sync` nor `async` is explicit.
const SYNC_UNDECIDED: MessageId = MessageId::new("nfs-sync-undecided");

/// Whether `option` is a well-formed option token: non-empty, no whitespace and
/// no parentheses.
///
/// The real grammar (exports(5)) is a comma-separated list of bare tokens inside
/// one parenthesized group, so a token that carries whitespace or a paren could
/// only have arrived by hand through the JSON API — and could not survive a
/// round trip through the file.
fn is_valid_option(option: &str) -> bool {
    !option.is_empty() && !option.contains(char::is_whitespace) && !option.contains(['(', ')'])
}

/// The security flavors a `sec=` option lists, when one is present.
fn sec_flavors(options: &[String]) -> Option<Vec<&str>> {
    let sec = options.iter().find(|option| option.starts_with("sec="))?;
    Some(sec.split_once('=')?.1.split(':').collect())
}

/// Whether the flavors are free of `krb5`, `krb5i` and `krb5p`, i.e. the export
/// negotiates only `sys`.
fn is_sys_only(flavors: &[&str]) -> bool {
    !flavors.is_empty() && !flavors.iter().any(|f| f.starts_with("krb5"))
}

/// Checks one export's path and every client on its line.
fn validate_export(export: &Export, index: usize, diagnostics: &mut Diagnostics) {
    let path_field = FieldPath::new(format!("entries/{index}/path"));
    if export.path.is_empty() {
        diagnostics.push(Diagnostic::new(Severity::Error, EMPTY_PATH).with_field(path_field));
    } else if !export.path.starts_with('/') {
        diagnostics.push(
            Diagnostic::new(Severity::Error, RELATIVE_PATH)
                .with_field(path_field)
                .with_arg("path", export.path.clone()),
        );
    }
    for (client_index, client) in export.clients.iter().enumerate() {
        validate_client(client, index, client_index, diagnostics);
    }
}

/// Checks one client of one export: shape errors first, then the classic
/// footguns (`no_root_squash`, world-writable exports, `sec=sys`), then the
/// explicitness recommendations.
fn validate_client(client: &Client, index: usize, client_index: usize, out: &mut Diagnostics) {
    let host_field = FieldPath::new(format!("entries/{index}/clients/{client_index}/host"));
    if client.host.is_empty() {
        out.push(Diagnostic::new(Severity::Error, EMPTY_HOST).with_field(host_field));
    }
    for (option_index, option) in client.options.iter().enumerate() {
        let field = FieldPath::new(format!(
            "entries/{index}/clients/{client_index}/options/{option_index}"
        ));
        if !is_valid_option(option) {
            out.push(
                Diagnostic::new(Severity::Error, INVALID_OPTION)
                    .with_field(field.clone())
                    .with_arg("option", option.clone()),
            );
        }
        if option == "no_root_squash" {
            out.push(
                Diagnostic::new(Severity::Warning, NO_ROOT_SQUASH)
                    .with_field(field.clone())
                    .with_arg("host", client.host.clone()),
            );
        }
        if option == "rw" && client.host == "*" {
            out.push(
                Diagnostic::new(Severity::Warning, WORLD_EXPORT)
                    .with_field(field)
                    .with_arg("host", client.host.clone()),
            );
        }
    }
    if let Some(flavors) = sec_flavors(&client.options)
        && is_sys_only(&flavors)
    {
        out.push(
            Diagnostic::new(Severity::Warning, SEC_SYS_ONLY)
                .with_field(FieldPath::new(format!(
                    "entries/{index}/clients/{client_index}/options"
                )))
                .with_arg("host", client.host.clone()),
        );
    }
    let has = |wanted: &[&str]| {
        client
            .options
            .iter()
            .any(|option| wanted.contains(&option.as_str()))
    };
    if !has(&["subtree_check", "no_subtree_check"]) {
        out.push(
            Diagnostic::new(Severity::Recommendation, SUBTREE_UNDECIDED)
                .with_field(FieldPath::new(format!(
                    "entries/{index}/clients/{client_index}/options"
                )))
                .with_arg("host", client.host.clone()),
        );
    }
    if !has(&["root_squash", "no_root_squash"]) {
        out.push(
            Diagnostic::new(Severity::Recommendation, ROOT_SQUASH_UNDECIDED)
                .with_field(FieldPath::new(format!(
                    "entries/{index}/clients/{client_index}/options"
                )))
                .with_arg("host", client.host.clone()),
        );
    }
    if !has(&["sync", "async"]) {
        out.push(
            Diagnostic::new(Severity::Recommendation, SYNC_UNDECIDED)
                .with_field(FieldPath::new(format!(
                    "entries/{index}/clients/{client_index}/options"
                )))
                .with_arg("host", client.host.clone()),
        );
    }
}

// ----------------------------------------------------------------------- module

/// The `/etc/exports` config module.
pub struct NfsModule;

impl ConfigModule for NfsModule {
    const ID: &'static str = "nfs";
    /// `detent_core::doc::Document` is the shared line-oriented CST and fits the
    /// exports format: one line, one export (backslash-continued entries stay
    /// `Unknown`, see the crate header).
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &NFS_DESCRIPTOR
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
                .filter_map(|line| parse_export(line.raw()))
                .collect(),
        })
    }

    /// The two-pass, minimal-edit shape. Pass 1 is read-only and renders every
    /// changed line before touching the document, so a rejected value (invariant
    /// 5) leaves the file exactly as it was. A line whose parsed export already
    /// equals the model's is not rendered at all, so hand-aligned columns
    /// survive. Pass 2 only ever touches `Directive` lines; comments, blanks and
    /// unknown directives keep their position, and new lines go after the last
    /// existing export, not at the end of the file.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1, read-only: pair model exports with the existing export lines
        // in order and render the ones that differ.
        let mut planned: Vec<Option<String>> = Vec::with_capacity(model.entries.len());
        for line in doc
            .lines()
            .iter()
            .filter(|line| line.kind() == LineKind::Directive)
        {
            let Some(wanted) = model.entries.get(planned.len()) else {
                break;
            };
            let unchanged = parse_export(line.raw()).as_ref() == Some(wanted);
            planned.push(if unchanged {
                None
            } else {
                Some(render_line(wanted)?)
            });
        }
        for wanted in model.entries.iter().skip(planned.len()) {
            planned.push(Some(render_line(wanted)?));
        }

        // Pass 2: rewrite, drop the export lines the model no longer has, and
        // append the rest after the last export line.
        let mut report = EditReport::default();
        let mut index = 0usize;
        let mut matched = 0usize;
        let mut after_last_export: Option<usize> = None;
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
            after_last_export = Some(index);
        }
        let mut at = after_last_export.unwrap_or_else(|| doc.len());
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
            validate_export(item, index, &mut diagnostics);
        }
        diagnostics
    }

    /// Exports are host-specific: there is no export point that is safe to
    /// assume for a host this tool has never inspected, so the default model is
    /// an empty `entries` list. That is not a cop-out — an empty `/etc/exports`
    /// is a valid file (upstream's own sample starts commented out) that exports
    /// nothing, which is exactly the conservative posture for a fresh host; the
    /// conformance suite asserts it passes `validate` and applies cleanly.
    fn defaults(_profile: &HostProfile) -> Self::Model {
        Model { entries: vec![] }
    }

    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Client, EMPTY_HOST, EMPTY_PATH, Export, INVALID_OPTION, Model, NFS_DESCRIPTOR,
        NO_ROOT_SQUASH, NfsModule, RELATIVE_PATH, ROOT_SQUASH_UNDECIDED, SEC_SYS_ONLY,
        SUBTREE_UNDECIDED, SYNC_UNDECIDED, WORLD_EXPORT, classify, is_valid_option, parse_client,
        parse_export, render_line, schema_with_hints, sec_flavors,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};

    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");
    /// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
    /// reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    /// Builds one client.
    fn client(host: &str, options: &[&str]) -> Client {
        Client {
            host: host.to_owned(),
            options: options.iter().map(|option| (*option).to_owned()).collect(),
        }
    }

    /// Builds one export.
    fn export(path: &str, clients: &[Client]) -> Export {
        Export {
            path: path.to_owned(),
            clients: clients.to_vec(),
        }
    }

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "nfs-name",
            "nfs-note-live-state",
            "nfs-tip-entries",
            "nfs-tip-path",
            "nfs-tip-clients",
            "nfs-tip-host",
            "nfs-tip-options",
            "nfs-rec-options",
            "nfs-empty-path",
            "nfs-relative-path",
            "nfs-empty-host",
            "nfs-invalid-option",
            "nfs-no-root-squash",
            "nfs-sec-sys-only",
            "nfs-world-export",
            "nfs-subtree-undecided",
            "nfs-root-squash-undecided",
            "nfs-sync-undecided",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = NFS_DESCRIPTOR.upstream;
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
        // nfs-utils publishes no release atom feed, so the descriptor carries
        // `None` and upstream-watch falls back to comparing tags in `repo_url`.
        assert_eq!(upstream.release_feed, None);
        assert!(UPSTREAM_TOML.contains("release_feed = \"\""));
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
        NfsModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    fn model(entries: Vec<Export>) -> Model {
        Model { entries }
    }

    // --------------------------------------------------------------- parse_client

    #[test]
    fn parse_client_reads_a_host_with_and_without_options() {
        assert_eq!(
            parse_client("host.lan(rw,sync)"),
            Some(client("host.lan", &["rw", "sync"]))
        );
        assert_eq!(parse_client("*"), Some(client("*", &[])));
        assert_eq!(parse_client("h()"), Some(client("h", &[])));
        assert_eq!(parse_client("@trusted(sec=krb5p:krb5i)"), {
            Some(client("@trusted", &["sec=krb5p:krb5i"]))
        });
    }

    #[test]
    fn parse_client_rejects_bad_tokens() {
        assert_eq!(parse_client(""), None);
        assert_eq!(parse_client("#"), None);
        assert_eq!(parse_client("h(rw"), None);
        assert_eq!(parse_client("h(rw))"), None);
        assert_eq!(parse_client("h(a,(b))"), None);
        assert_eq!(parse_client("@(trusted)(sec=krb5p)"), None);
    }

    // --------------------------------------------------------------- parse_export

    #[test]
    fn parse_export_reads_a_path_and_its_clients() {
        assert_eq!(
            parse_export("/srv/nfs4 192.168.1.0/24(rw,sync,no_subtree_check)"),
            Some(export(
                "/srv/nfs4",
                &[client(
                    "192.168.1.0/24",
                    &["rw", "sync", "no_subtree_check"]
                )]
            ))
        );
        assert_eq!(
            parse_export("  /srv/a  h(rw)   g(rw)  "),
            Some(export(
                "/srv/a",
                &[client("h", &["rw"]), client("g", &["rw"])]
            ))
        );
    }

    #[test]
    fn parse_export_rejects_non_exports() {
        assert_eq!(parse_export(""), None);
        assert_eq!(parse_export("# comment"), None);
        assert_eq!(parse_export("lonely"), None);
        assert_eq!(parse_export("- h(rw)"), None);
        assert_eq!(parse_export("/srv/half h(rw"), None);
        assert_eq!(parse_export("1.2.3.4"), None);
    }

    // -------------------------------------------------------------------- classify

    #[test]
    fn classify_assigns_the_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("  # indented"), LineKind::Comment);
        assert_eq!(classify("/srv/a h(rw)"), LineKind::Directive);
        assert_eq!(classify("/srv/half h(rw"), LineKind::Unknown);
        assert_eq!(classify("mountd-mounts"), LineKind::Unknown);
    }

    // ----------------------------------------------------------------- render_line

    #[test]
    fn render_line_emits_single_space_joins() {
        assert_eq!(
            render_line(&export(
                "/srv/nfs4",
                &[client("192.168.1.0/24", &["rw", "sync"])]
            )),
            Ok("/srv/nfs4 192.168.1.0/24(rw,sync)".to_owned())
        );
        // A client with no options renders without parentheses at all.
        assert_eq!(
            render_line(&export("/srv/a", &[client("*", &[])])),
            Ok("/srv/a *".to_owned())
        );
    }

    #[test]
    fn render_line_rejects_a_line_break_in_a_value() {
        for bad in [
            export("/srv/a", &[client("h", &["a\nb"])]),
            export("/srv/a", &[client("h\rb", &[])]),
            export("/a\0b", &[]),
        ] {
            assert!(
                matches!(render_line(&bad), Err(EditError::LineBreakInValue { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn render_line_rejects_values_that_would_not_round_trip() {
        for bad in [
            export("a b", &[client("h", &[])]),
            export("relative", &[client("h", &[])]),
            export("/srv/a", &[client("h g", &[])]),
            export("/srv/a", &[client("h(", &[])]),
            export("/srv/a", &[client("h", &["a b"])]),
            export("/srv/a", &[client("h", &["a,b"])]),
        ] {
            assert!(
                matches!(render_line(&bad), Err(EditError::Unsupported { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    // ------------------------------------------------------------------- to_model

    #[test]
    fn to_model_reads_only_directive_lines() -> Result<(), String> {
        let src = "# comment\n\n/srv/a h(rw)\n/srv/half h(rw\n/srv/b g(rw)\n";
        let doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let parsed = NfsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            parsed,
            model(vec![
                export("/srv/a", &[client("h", &["rw"])]),
                export("/srv/b", &[client("g", &["rw"])]),
            ])
        );
        assert_eq!(NfsModule::render(&doc), src);
        Ok(())
    }

    // ---------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\n/srv/a   h(rw)\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let model = NfsModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = NfsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(NfsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_export() -> Result<(), String> {
        let src = "/srv/a h(rw)\n/srv/b g(rw)\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![
            export("/srv/a", &[client("h", &["ro", "sync"])]),
            export("/srv/b", &[client("g", &["rw"])]),
        ]);
        let report = NfsModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(NfsModule::render(&doc), "/srv/a h(ro,sync)\n/srv/b g(rw)\n");
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_exports() -> Result<(), String> {
        let src = "/srv/a h(rw)\n/srv/b g(rw)\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![export("/srv/a", &[client("h", &["rw"])])]);
        let report = NfsModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(NfsModule::render(&doc), "/srv/a h(rw)\n");
        Ok(())
    }

    #[test]
    fn apply_appends_after_the_last_export_line() -> Result<(), String> {
        let src = "/srv/a h(rw)\n# trailing comment\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let mut m = NfsModule::to_model(&doc).map_err(|e| e.to_string())?;
        m.entries.push(export("/srv/b", &[client("g", &["ro"])]));
        let report = NfsModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            NfsModule::render(&doc),
            "/srv/a h(rw)\n/srv/b g(ro)\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_export_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![export("/srv/a", &[client("h", &["rw"])])]);
        let report = NfsModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(NfsModule::render(&doc), "# only a comment\n/srv/a h(rw)\n");
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        let src = "/srv/a h(rw)\n";
        let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
        let m = model(vec![export("/srv/a", &[client("h", &["a\nb"])])]);
        assert!(NfsModule::apply(&mut doc, &m).is_err());
        assert_eq!(NfsModule::render(&doc), src);
        Ok(())
    }

    // ------------------------------------------------------------------- validate

    #[test]
    fn is_valid_option_follows_the_documented_rule() {
        assert!(is_valid_option("rw"));
        assert!(is_valid_option("no_root_squash"));
        assert!(is_valid_option("sec=krb5p:krb5i"));
        assert!(!is_valid_option(""));
        assert!(!is_valid_option("rw sync"));
        assert!(!is_valid_option("rw("));
        assert!(!is_valid_option("rw)"));
    }

    #[test]
    fn validate_flags_an_empty_path() {
        let m = model(vec![export("", &[client("h", &[])])]);
        assert!(has(&m, EMPTY_PATH, Severity::Error));
    }

    #[test]
    fn validate_flags_a_relative_path() {
        let m = model(vec![export("srv/a", &[client("h", &[])])]);
        assert!(has(&m, RELATIVE_PATH, Severity::Error));
    }

    #[test]
    fn validate_flags_an_empty_host() {
        let m = model(vec![export("/srv/a", &[client("", &[])])]);
        assert!(has(&m, EMPTY_HOST, Severity::Error));
    }

    #[test]
    fn validate_flags_an_unbalanced_paren_shaped_option() {
        let paren_option = client("h", &["rw("]);
        let m = model(vec![export("/srv/a", &[paren_option])]);
        assert!(has(&m, INVALID_OPTION, Severity::Error));
        let space_option = client("h", &[" "]);
        let spaced = model(vec![export("/srv/a", &[space_option])]);
        assert!(has(&spaced, INVALID_OPTION, Severity::Error));
    }

    #[test]
    fn validate_flags_no_root_squash() {
        let m = model(vec![export(
            "/srv/a",
            &[client(
                "h",
                &["rw", "no_root_squash", "sync", "no_subtree_check"],
            )],
        )]);
        assert!(has(&m, NO_ROOT_SQUASH, Severity::Warning));
    }

    #[test]
    fn validate_flags_sec_sys_only() {
        let m = model(vec![export(
            "/srv/a",
            &[client(
                "h",
                &["rw", "sec=sys", "sync", "no_subtree_check", "root_squash"],
            )],
        )]);
        assert!(has(&m, SEC_SYS_ONLY, Severity::Warning));
        assert_eq!(sec_flavors(&["sec=sys".to_owned()]), Some(vec!["sys"]));
    }

    #[test]
    fn validate_allows_sec_with_a_krb5_flavor() {
        let m = model(vec![export(
            "/srv/a",
            &[client(
                "h",
                &[
                    "rw",
                    "sec=sys:krb5p",
                    "sync",
                    "no_subtree_check",
                    "root_squash",
                ],
            )],
        )]);
        assert!(!has(&m, SEC_SYS_ONLY, Severity::Warning));
    }

    #[test]
    fn validate_flags_a_world_writable_export() {
        let m = model(vec![export(
            "/srv/a",
            &[client(
                "*",
                &["rw", "sync", "no_subtree_check", "root_squash"],
            )],
        )]);
        assert!(has(&m, WORLD_EXPORT, Severity::Warning));
    }

    #[test]
    fn validate_recommends_explicit_subtree_root_squash_and_sync() {
        let m = model(vec![export("/srv/a", &[client("h", &["rw"])])]);
        assert!(has(&m, SUBTREE_UNDECIDED, Severity::Recommendation));
        assert!(has(&m, ROOT_SQUASH_UNDECIDED, Severity::Recommendation));
        assert!(has(&m, SYNC_UNDECIDED, Severity::Recommendation));
    }

    #[test]
    fn validate_accepts_a_clean_export() {
        let m = model(vec![export(
            "/srv/a",
            &[client(
                "h.lan",
                &["rw", "sync", "no_subtree_check", "root_squash"],
            )],
        )]);
        assert!(!has(&m, EMPTY_PATH, Severity::Error));
        assert!(!has(&m, RELATIVE_PATH, Severity::Error));
        assert!(!has(&m, EMPTY_HOST, Severity::Error));
        assert!(!has(&m, INVALID_OPTION, Severity::Error));
        assert!(!has(&m, NO_ROOT_SQUASH, Severity::Warning));
        assert!(!has(&m, SEC_SYS_ONLY, Severity::Warning));
        assert!(!has(&m, WORLD_EXPORT, Severity::Warning));
        assert!(!has(&m, SUBTREE_UNDECIDED, Severity::Recommendation));
        assert!(!has(&m, ROOT_SQUASH_UNDECIDED, Severity::Recommendation));
        assert!(!has(&m, SYNC_UNDECIDED, Severity::Recommendation));
    }

    // -------------------------------------------------------------------- defaults

    #[test]
    fn defaults_are_an_empty_file_on_every_operating_system() {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            assert_eq!(NfsModule::defaults(&profile(os)), Model { entries: vec![] });
        }
    }

    #[test]
    fn defaults_are_valid_and_apply_to_an_empty_file() -> Result<(), String> {
        let host = profile(Os::Linux);
        let ctx = ValidationCtx::new(&host);
        let model = NfsModule::defaults(&host);
        assert!(!NfsModule::validate(&model, &ctx).has_errors());
        let mut doc = NfsModule::parse("").map_err(|e| e.to_string())?;
        let report = NfsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(NfsModule::render(&doc), "");
        Ok(())
    }

    // ----------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_and_backend() {
        let descriptor = NfsModule::descriptor();
        assert_eq!(descriptor.id, NfsModule::ID);
        assert_eq!(descriptor.targets.len(), 2);
        assert_eq!(
            descriptor.checks,
            &[] as &[detent_core::descriptor::ExternalCheck]
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
            Some(&["nfs-server.service"][..])
        );
        assert_eq!(units.map(|units| units.openrc), Some(&["nfs"][..]));
        assert_eq!(units.map(|units| units.bsdrc), Some(&["nfsd"][..]));
    }

    // --------------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, NfsModule::schema());
        for pointer in [
            "/properties/entries",
            "/$defs/Export/properties/path",
            "/$defs/Export/properties/clients",
            "/$defs/Client/properties/host",
            "/$defs/Client/properties/options",
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

    // -------------------------------------------------- derived trait impls

    /// Exercises the derived impls the module's own logic never calls. Coverage
    /// is 100 % lines for `crates/modules/` (PLAN §6.2), and a derive with no
    /// caller is the usual reason a module misses it.
    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let m = model(vec![export("/srv/a", &[client("h", &["rw"])])]);
        assert_eq!(m.clone(), m);
        assert!(format!("{m:?}").contains("rw"));
        assert_eq!(Model::default(), Model { entries: vec![] });
        let json = serde_json::to_value(&m).unwrap_or_default();
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(m));
        assert!(
            serde_json::from_str::<Client>(r#"{"host":"h","options":[],"x":1}"#).is_err(),
            "deny_unknown_fields must reject unknown keys"
        );
    }

    // ------------------------------------------------------------- adversarial

    /// These are the shapes that broke real parsers: no trailing newline, CRLF,
    /// NUL, one very long line, and a file large enough that a super-linear
    /// `apply` shows up as a timeout.
    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "/srv/d{i} h(rw)");
        }
        for src in [
            "/srv/a h(rw)",
            "/srv/a h(rw)\r\n/srv/b g(rw)\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
        ] {
            let mut doc = NfsModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(NfsModule::render(&doc), src);
            let model = NfsModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = NfsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(NfsModule::render(&doc), src);
        }
        Ok(())
    }

    // --------------------------------------------------------------------- fuzzing

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_exports_are_well_shaped_and_apply_cleanly() -> Result<(), String> {
        use arbitrary::{Arbitrary, Unstructured};

        // Enough varied bytes to drive several host, path and option lengths,
        // empty and non-empty option lists, and both the single- and
        // multi-client arms of `Export::arbitrary`.
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
                assert!(e.path.starts_with('/'), "generated path {e:?}");
                for c in &e.clients {
                    assert!(!c.host.is_empty(), "generated empty host in {e:?}");
                    assert!(!c.host.contains(char::is_whitespace));
                }
            }
            let mut doc = NfsModule::parse("").map_err(|e| e.to_string())?;
            let report = NfsModule::apply(&mut doc, &m).map_err(|e| e.to_string())?;
            assert_eq!(report.added, m.entries.len());
        }
        Ok(())
    }
}
