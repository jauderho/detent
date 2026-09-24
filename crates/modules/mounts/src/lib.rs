//! The `mounts` module: `/etc/fstab`, the static file system table
//! (`fstab(5)`, upstream util-linux).
//!
//! Every line of `/etc/fstab` is blank, a `#` comment, or one entry with
//! exactly six whitespace-separated fields: `spec mountpoint fstype options
//! dump pass`. A line that does not split into six fields, or whose `dump` or
//! `pass` column is not a number, is kept as [`LineKind::Unknown`] and is never
//! rewritten — that is how future column formats and editor droppings survive
//! an edit.
//!
//! # Formatting policy
//!
//! An entry line is left byte for byte alone whenever the entry parsed from it
//! equals the entry in the model, so hand-aligned columns and odd spacing
//! survive. Only lines that actually change are re-rendered, as
//! `spec mountpoint fstype options dump pass` with single spaces and the
//! options joined with `,`.
//!
//! # No I/O
//!
//! Like every module crate this one is pure: fixtures used by its tests are
//! `include_str!`ed, nothing is read from disk at run time. `detent-platform`
//! owns every file operation (PLAN §2.1).

use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, FieldHints, HostProfile, ModuleDescriptor, Os,
    Owner, PathSpec, SecurityImpact, ServiceBinding, Target, TargetKind, UiGroup, Upstream,
    ValidationCtx, apply_hints,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, Line, LineKind};
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};

// ------------------------------------------------------------------------- model

/// One fstab entry, in model (not syntax) form.
///
/// `fstab(5)` records six columns; this struct models them. Options are stored
/// as the list of comma-separated option words, because every consumer
/// (mount(8), `findmnt --verify`, systemd) treats the commas as syntax, not
/// meaning.
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
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// What is mounted: a device node, `UUID=…`/`LABEL=…`, an NFS export, or
    /// `none` for swap.
    pub spec: String,
    /// Where it is mounted, or `none`/`swap` for swap.
    pub mountpoint: String,
    /// The filesystem type (`ext4`, `swap`, `nfs4`, …).
    pub fstype: String,
    /// The mount options, in file order, one word each.
    pub options: Vec<String>,
    /// The dump(8) backup frequency; almost always `0`.
    pub dump: u8,
    /// The fsck pass number: `1` for root, `2` for other checked filesystems,
    /// `0` to skip.
    pub pass: u8,
}

/// The typed model of `/etc/fstab`: its entries, in file order.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The entries, in the order they appear in the file.
    pub entries: Vec<Entry>,
}

// ------------------------------------------------------------ parsing / rendering

/// Parses one line as an fstab entry, or `None` when it is not one.
///
/// This is the whole grammar of the format: exactly six whitespace-separated
/// fields (`spec mountpoint fstype options dump pass`), the last two numeric.
/// A line with fewer or more fields, or a non-numeric `dump`/`pass`, stays
/// [`LineKind::Unknown`] and `apply` copies it through untouched — that is how
/// formats this module does not understand survive an edit.
///
/// Kept total: it takes any `&str`, never panics, and never allocates
/// unboundedly.
fn parse_entry(raw: &str) -> Option<Entry> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut fields = trimmed.split_whitespace();
    let spec = fields.next()?;
    let mountpoint = fields.next()?;
    let fstype = fields.next()?;
    let options = fields.next()?;
    let dump = fields.next()?;
    let pass = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let (dump, pass) = (dump.parse::<u8>().ok()?, pass.parse::<u8>().ok()?);
    Some(Entry {
        spec: spec.to_owned(),
        mountpoint: mountpoint.to_owned(),
        fstype: fstype.to_owned(),
        options: options.split(',').map(str::to_owned).collect(),
        dump,
        pass,
    })
}

/// Classifies a line for the lossless document model.
///
/// The classifier must be a pure function of the line text alone: `Document`
/// re-runs it after every edit, so a context-dependent classifier would make
/// `apply` non-deterministic. `Directive` must mean "`parse_entry` succeeds" —
/// `to_model` and `apply` both walk `Directive` lines, and if the two
/// disagreed, invariant 2 would break.
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

/// Renders an entry as one fstab line, refusing anything that would not survive
/// a round trip.
///
/// Both guards matter. The first is invariant 5 (directive injection): a value
/// carrying `\n`, `\r` or NUL is **rejected**, never escaped away and never
/// written. The second is the general form of the same idea — the rendered line
/// must parse back to the entry it came from, or the edit would silently mean
/// something else. Whitespace inside a field would split the line into more
/// columns, and an empty spec or options list would shorten it below six, so
/// both are refused here and reported by [`validate`](ConfigModule::validate).
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when any field carries `\n`, `\r` or NUL, and
/// [`EditError::Unsupported`] when the rendered line does not parse back to the
/// same entry.
fn render_entry(entry: &Entry) -> Result<String, EditError> {
    let raw = format!(
        "{} {} {} {} {} {}",
        entry.spec,
        entry.mountpoint,
        entry.fstype,
        entry.options.join(","),
        entry.dump,
        entry.pass
    );
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

/// Whether this backend is the right one for `profile`.
///
/// fstab is a Linux format (`/etc/fstab.d` drop-ins are systemd's), so the
/// module only claims Linux hosts.
fn detect_backend(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

/// The files this module owns. Paths are `&'static` templates and are **never**
/// user-supplied (PLAN §2.3): a request can select a module, it can never name
/// the file the module writes. `/etc/fstab.d` is systemd's drop-in directory
/// for fstab fragments.
static TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/fstab"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: detect_backend,
    },
    Target {
        path: PathSpec::new("/etc/fstab.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: detect_backend,
    },
];

/// The upstream validator run against the candidate file before it is
/// installed: `findmnt --verify` (util-linux) checks an fstab for consistency.
/// [`ArgTemplate::TempFile`] is replaced by the path of the candidate.
static CHECKS: &[ExternalCheck] = &[ExternalCheck {
    program: PathSpec::new("/usr/bin/findmnt"),
    args: &[
        ArgTemplate::Literal("--verify"),
        ArgTemplate::Literal("--tab-file"),
        ArgTemplate::TempFile,
    ],
    expects: CheckExpectation::ExitZero,
}];

/// The services a change to these files affects. Applying a fstab change means
/// a daemon-reload plus mounting the new entries, both driven by the
/// operations layer's monitor — there is no daemon unit to bind, so this stays
/// empty (`hosts` does the same for the same reason).
static SERVICES: &[ServiceBinding] = &[];

/// The descriptor. `commit_confirm` is `true` because a bad fstab can leave
/// the host unbootable at the next restart (ADR-012): every apply needs a
/// second confirmation.
static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "mounts",
    display_name_id: MessageId::new("mounts-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "util-linux",
        repo_url: "https://github.com/util-linux/util-linux.git",
        tracked_version: "2.42.3",
        release_feed: Some("https://github.com/util-linux/util-linux/releases.atom"),
        docs: &["https://man7.org/linux/man-pages/man5/fstab.5.html"],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: true,
    security_notes: &[MessageId::new("mounts-note-boot")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `entries`.
///
/// Appendix A requires `x-detent` hints on **every** field, and the test below
/// asserts every pointer resolves. `group` decides Basic vs Advanced in the UI,
/// `security_impact` drives the warning styling, and `recommendation` is the
/// Fluent id of the callout shown when the current value is worse than the
/// recommended one.
static ENTRIES_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("mounts-tip-entries"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].spec`.
static SPEC_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("mounts-tip-spec"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].mountpoint`.
static MOUNTPOINT_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("mounts-tip-mountpoint"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].fstype`.
static FSTYPE_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("mounts-tip-fstype"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].options`.
static OPTIONS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("mounts-tip-options"),
    recommendation: Some(MessageId::new("mounts-rec-options")),
    security_impact: SecurityImpact::High,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].dump`.
static DUMP_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("mounts-tip-dump"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `entries[].pass`.
static PASS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Advanced,
    tooltip: MessageId::new("mounts-tip-pass"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `MountsModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema.
///
/// The pointers depend on the shape `schemars` generates. `apply_hints` returns
/// `false` when a pointer resolves to nothing, and the test below turns that
/// into a failure — do not drop the assertion, a silently unattached hint is
/// invisible in the UI.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/entries", &ENTRIES_HINTS),
        ("/$defs/Entry/properties/spec", &SPEC_HINTS),
        ("/$defs/Entry/properties/mountpoint", &MOUNTPOINT_HINTS),
        ("/$defs/Entry/properties/fstype", &FSTYPE_HINTS),
        ("/$defs/Entry/properties/options", &OPTIONS_HINTS),
        ("/$defs/Entry/properties/dump", &DUMP_HINTS),
        ("/$defs/Entry/properties/pass", &PASS_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: an entry has no spec column.
const EMPTY_SPEC: MessageId = MessageId::new("mounts-empty-spec");
/// Fluent id: an entry has no mount point column.
const EMPTY_MOUNTPOINT: MessageId = MessageId::new("mounts-empty-mountpoint");
/// Fluent id: the fstype column carries characters no filesystem type uses.
const INVALID_FSTYPE: MessageId = MessageId::new("mounts-invalid-fstype");
/// Fluent id: the pass column is above the two passes fsck defines.
const PASS_TOO_HIGH: MessageId = MessageId::new("mounts-pass-too-high");
/// Fluent id: the root entry is not scheduled in fsck pass 1.
const ROOT_PASS: MessageId = MessageId::new("mounts-root-pass");
/// Fluent id: a removable mount lacks `nofail`.
const MISSING_NOFAIL: MessageId = MessageId::new("mounts-missing-nofail");
/// Fluent id: a data mount lacks the suid/device/exec guards.
const MISSING_GUARDS: MessageId = MessageId::new("mounts-missing-guards");
/// Fluent id: a network mount lacks the `x-systemd.automount` hint.
const NETWORK_AUTOMOUNT: MessageId = MessageId::new("mounts-network-automount");
/// Fluent id: `noauto` is set without `user`.
const NOAUTO_WITHOUT_USER: MessageId = MessageId::new("mounts-noauto-without-user");
/// Fluent id: a non-critical mount can hold up boot without an escape option.
const MISSING_BOOT_ESCAPE: MessageId = MessageId::new("mounts-missing-boot-escape");
/// Fluent id: a critical boot mount is marked not to mount.
const CRITICAL_NO_AUTO: MessageId = MessageId::new("mounts-critical-noauto");

/// Whether `mountpoint` is required before the system can continue booting.
fn is_boot_critical(mountpoint: &str) -> bool {
    matches!(mountpoint, "/" | "/boot" | "/efi")
        || mountpoint.starts_with("/boot/")
        || mountpoint.starts_with("/efi/")
}

/// Whether `fstype` is shaped like a filesystem type (`ext4`, `nfs4`,
/// `fuseblk`).
///
/// fstab(5) types are alphanumeric plus `.`/`-`/`_`; anything else means the
/// line was mis-split or hand-mangled. This checks the characters, not the
/// (endless) set of real filesystem names — a value this module accepts but
/// mount(8) rejects is caught by the [`ExternalCheck`], which is what
/// `findmnt --verify` is for.
fn is_valid_fstype(fstype: &str) -> bool {
    !fstype.is_empty()
        && fstype
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Filesystems that expose kernel state: they carry no user data, so the
/// `nosuid`/`nodev`/`noexec` guards do not apply to them. `tmpfs` is
/// deliberately absent — it holds user data (`/dev/shm`), and is exactly the
/// mount people forget to guard.
fn is_kernel_state_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "mqueue"
            | "cgroup"
            | "cgroup2"
            | "autofs"
            | "efivarfs"
            | "bpf"
            | "debugfs"
            | "tracefs"
            | "configfs"
            | "fusectl"
            | "hugetlbfs"
    )
}

/// Whether the entry mounts removable or transient media that may not be there
/// at boot: a mount point under `/media` or `/mnt`, or a USB-stick filesystem
/// type.
fn is_removable(entry: &Entry) -> bool {
    entry.mountpoint.starts_with("/media")
        || entry.mountpoint.starts_with("/mnt")
        // ponytail: ntfs3 (the modern in-kernel driver) is not listed yet; add
        // it when a tracked host uses it instead of `ntfs`
        || matches!(entry.fstype.as_str(), "vfat" | "exfat" | "ntfs")
}

/// Filesystems that need the network to be up before they can mount.
fn is_network_fstype(fstype: &str) -> bool {
    matches!(fstype, "nfs" | "nfs4" | "cifs" | "smbfs")
}

/// The suid/device/exec guards every user-writable data mount should carry.
const MOUNT_GUARDS: [&str; 3] = ["nosuid", "nodev", "noexec"];

/// Which of [`MOUNT_GUARDS`] `options` does not set.
fn missing_guards(options: &[String]) -> Vec<&'static str> {
    MOUNT_GUARDS
        .into_iter()
        .filter(|guard| !options.iter().any(|option| option == *guard))
        .collect()
}

/// Whether a non-critical mount is allowed to defer or skip mounting.
fn has_boot_escape(options: &[String]) -> bool {
    options
        .iter()
        .any(|option| option == "nofail" || option == "noauto")
}
/// Checks one entry against the fstab(5) rules and the hardening conventions.
///
/// * [`Severity::Error`] — the entry is invalid and must not be applied (empty
///   columns, an fstype shape no filesystem type uses, a fsck pass above 2).
/// * [`Severity::Warning`] — valid, but likely not what the admin meant (root
///   not in fsck pass 1, a local mount without `nofail`/`noauto`, critical
///   mounts disabled with `noauto`, removable media without `nofail`, or data
///   mounts without guards).
/// * [`Severity::Recommendation`] — fine, but a better option exists
///   (`x-systemd.automount` on network filesystems, `noauto` without `user`).
fn validate_entry(entry: &Entry, index: usize, diagnostics: &mut Diagnostics) {
    let field = |name: &str| FieldPath::new(format!("entries/{index}/{name}"));
    let has = |option: &str| entry.options.iter().any(|set| set == option);

    if entry.spec.is_empty() {
        diagnostics.push(
            Diagnostic::new(Severity::Error, EMPTY_SPEC)
                .with_field(field("spec"))
                .with_arg("index", index.to_string()),
        );
    }
    if entry.mountpoint.is_empty() {
        diagnostics.push(
            Diagnostic::new(Severity::Error, EMPTY_MOUNTPOINT)
                .with_field(field("mountpoint"))
                .with_arg("index", index.to_string()),
        );
    }
    if !is_valid_fstype(&entry.fstype) {
        diagnostics.push(
            Diagnostic::new(Severity::Error, INVALID_FSTYPE)
                .with_field(field("fstype"))
                .with_arg("fstype", entry.fstype.clone()),
        );
    }
    if entry.pass > 2 {
        diagnostics.push(
            Diagnostic::new(Severity::Error, PASS_TOO_HIGH)
                .with_field(field("pass"))
                .with_arg("index", index.to_string())
                .with_arg("pass", entry.pass.to_string()),
        );
    }
    if entry.mountpoint == "/" && entry.pass != 1 {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, ROOT_PASS)
                .with_field(field("pass"))
                .with_arg("pass", entry.pass.to_string()),
        );
    }
    let boot_critical = is_boot_critical(&entry.mountpoint);
    if boot_critical && has("noauto") {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, CRITICAL_NO_AUTO)
                .with_field(field("options"))
                .with_arg("mountpoint", entry.mountpoint.clone()),
        );
    }
    if !boot_critical
        && entry.mountpoint != "none"
        && entry.fstype != "swap"
        && !is_kernel_state_fstype(&entry.fstype)
        && !has_boot_escape(&entry.options)
    {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, MISSING_BOOT_ESCAPE)
                .with_field(field("options"))
                .with_arg("mountpoint", entry.mountpoint.clone()),
        );
    }
    if is_removable(entry) && !has("nofail") {
        diagnostics.push(
            Diagnostic::new(Severity::Warning, MISSING_NOFAIL)
                .with_field(field("options"))
                .with_arg("mountpoint", entry.mountpoint.clone()),
        );
    }
    if entry.mountpoint != "/" && entry.fstype != "swap" && !is_kernel_state_fstype(&entry.fstype) {
        let missing = missing_guards(&entry.options);
        if !missing.is_empty() {
            diagnostics.push(
                Diagnostic::new(Severity::Warning, MISSING_GUARDS)
                    .with_field(field("options"))
                    .with_arg("mountpoint", entry.mountpoint.clone())
                    .with_arg("missing", missing.join(", ")),
            );
        }
    }
    if is_network_fstype(&entry.fstype) && !has("x-systemd.automount") {
        diagnostics.push(
            Diagnostic::new(Severity::Recommendation, NETWORK_AUTOMOUNT)
                .with_field(field("options"))
                .with_arg("mountpoint", entry.mountpoint.clone()),
        );
    }
    if has("noauto") && !has("user") {
        diagnostics.push(
            Diagnostic::new(Severity::Recommendation, NOAUTO_WITHOUT_USER)
                .with_field(field("options"))
                .with_arg("mountpoint", entry.mountpoint.clone()),
        );
    }
}

// ----------------------------------------------------------------------- module

/// The `/etc/fstab` config module.
pub struct MountsModule;

impl ConfigModule for MountsModule {
    /// The stable id. It appears in URLs, the CLI, the audit log, the
    /// `module-mounts` feature name, the Fluent id prefix, `fixtures/mounts/`
    /// and the fuzz target names, so it is effectively public API.
    const ID: &'static str = "mounts";

    /// `detent_core::doc::Document` is the shared line-oriented CST and fits
    /// fstab: one line, one entry, no continuations (ADR-008).
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    /// `parse` is total: it returns `Ok` for every `&str`, including empty
    /// input, lone `\r`, and embedded NUL; it never panics (invariant 6 runs it
    /// over 1 MiB of adversarial bytes).
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// Projects only what the model can express, and drops nothing else —
    /// `Unknown` and `Comment` lines stay in the `Doc` and are what makes
    /// `render` lossless. `to_model` and `apply` must agree about which lines
    /// are entries, or invariant 2 fails.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        Ok(Model {
            entries: doc
                .lines_of_kind(LineKind::Directive)
                .filter_map(|line| parse_entry(line.raw()))
                .collect(),
        })
    }

    /// The two-pass minimal-edit shape, worth copying verbatim; only
    /// `parse_entry`/`render_entry` are format-specific.
    ///
    /// * Pass 1 is read-only. Rendering every changed line **before** touching
    ///   the document means a rejected value (invariant 5) leaves the file
    ///   exactly as it was — a half-applied fstab is worse than a refused one.
    /// * A line whose parsed entry already equals the model's is not rendered
    ///   at all, so hand-aligned columns and unusual spacing survive. That is
    ///   what makes invariant 2 (`apply(doc, to_model(doc))` changes nothing,
    ///   and reports `EditReport::default()`) hold.
    /// * Pass 2 only ever touches `Directive` lines: comments, blanks and
    ///   unknown lines keep their position.
    /// * New lines go after the last existing entry, not at the end of the
    ///   file, so a trailing comment block stays trailing.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1, read-only: pair model entries with the existing entry lines in
        // order and render the ones that differ.
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
                Some(render_entry(wanted)?)
            });
        }
        for wanted in model.entries.iter().skip(planned.len()) {
            planned.push(Some(render_entry(wanted)?));
        }

        // Pass 2: rewrite, drop the entry lines the model no longer has, and
        // append the rest after the last entry line.
        let mut report = EditReport::default();
        let mut index = 0usize;
        let mut matched = 0usize;
        let mut after_last_entry: Option<usize> = None;
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
            after_last_entry = Some(index);
        }
        let mut at = after_last_entry.unwrap_or_else(|| doc.len());
        for raw in planned.iter().skip(matched).flatten() {
            doc.insert_line(at, raw)?;
            at = at.saturating_add(1);
            report.added = report.added.saturating_add(1);
        }
        Ok(report)
    }

    /// Checks a model, returning errors, warnings and recommendations as Fluent
    /// ids — never a rendered sentence, this crate does not localize (ADR-003).
    /// Every finding about one entry carries a [`FieldPath`] so the UI can
    /// point at the control, and every value that appears in the message is
    /// passed as a named argument, so translators can reorder them.
    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        for (index, entry) in model.entries.iter().enumerate() {
            validate_entry(entry, index, &mut diagnostics);
        }
        diagnostics
    }

    /// Host-appropriate defaults.
    ///
    /// Deliberately empty. An fstab names *this* host's filesystems; the only
    /// models that could be invented are dishonest — a `UUID=` root entry with a
    /// fabricated UUID would brick the boot, and a guessed device node would
    /// not survive the next reboot order. So [`Self::defaults`] returns an empty
    /// model: it validates with no errors, applies to an empty file as a no-op,
    /// and leaves provisioning an fstab (from `blkid` output or a provisioning
    /// system) to the admin.
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
        CRITICAL_NO_AUTO, DESCRIPTOR, EMPTY_MOUNTPOINT, EMPTY_SPEC, Entry, INVALID_FSTYPE,
        MISSING_BOOT_ESCAPE, MISSING_GUARDS, MISSING_NOFAIL, MOUNT_GUARDS, Model, MountsModule,
        NETWORK_AUTOMOUNT, NOAUTO_WITHOUT_USER, PASS_TOO_HIGH, ROOT_PASS, classify,
        is_valid_fstype, missing_guards, parse_entry, render_entry, schema_with_hints,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};

    /// `locales/en-US/core.ftl` is the source of truth for every user-facing
    /// string (PLAN §4.3). This test is what keeps a raw id from reaching the
    /// UI: list every `MessageId` this crate constructs — display name,
    /// security notes, tooltips, recommendations and diagnostics.
    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// Keeps `upstream.toml` and the descriptor from drifting.
    /// `upstream-watch` reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "mounts-name",
            "mounts-note-boot",
            "mounts-tip-entries",
            "mounts-tip-spec",
            "mounts-tip-mountpoint",
            "mounts-tip-fstype",
            "mounts-tip-options",
            "mounts-tip-dump",
            "mounts-tip-pass",
            "mounts-rec-options",
            "mounts-empty-spec",
            "mounts-empty-mountpoint",
            "mounts-invalid-fstype",
            "mounts-pass-too-high",
            "mounts-root-pass",
            "mounts-missing-nofail",
            "mounts-missing-guards",
            "mounts-network-automount",
            "mounts-noauto-without-user",
            "mounts-missing-boot-escape",
            "mounts-critical-noauto",
        ] {
            assert!(
                CORE_FTL.contains(&format!("{id} =")),
                "locales/en-US/core.ftl is missing `{id} =`"
            );
        }
    }

    #[test]
    fn upstream_toml_matches_the_descriptor() {
        let upstream = DESCRIPTOR.upstream;
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
        assert!(
            upstream
                .release_feed
                .is_some_and(|feed| UPSTREAM_TOML.contains(feed))
        );
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

    fn host() -> HostProfile {
        profile(Os::Linux, "host")
    }

    /// Builds an expected entry.
    fn entry(
        spec: &str,
        mountpoint: &str,
        fstype: &str,
        options: &[&str],
        dump: u8,
        pass: u8,
    ) -> Entry {
        Entry {
            spec: spec.to_owned(),
            mountpoint: mountpoint.to_owned(),
            fstype: fstype.to_owned(),
            options: options.iter().map(|option| (*option).to_owned()).collect(),
            dump,
            pass,
        }
    }

    fn has(model: &Model, id: MessageId, severity: Severity) -> bool {
        let host = host();
        let ctx = ValidationCtx::new(&host);
        MountsModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    // --------------------------------------------------------------- parse_entry

    #[test]
    fn parse_entry_reads_six_fields() {
        assert_eq!(
            parse_entry("  UUID=abc   /   ext4   defaults,nodev   0   1  "),
            Some(entry("UUID=abc", "/", "ext4", &["defaults", "nodev"], 0, 1))
        );
    }

    #[test]
    fn parse_entry_rejects_non_entries() {
        assert_eq!(parse_entry(""), None);
        assert_eq!(parse_entry("   "), None);
        assert_eq!(parse_entry("# comment"), None);
        assert_eq!(parse_entry("UUID=x / ext4 defaults"), None);
        assert_eq!(parse_entry("tmpfs /dev/shm tmpfs defaults 0 0 extra"), None);
        assert_eq!(parse_entry("/dev/sdb1 /mnt ext4 defaults zero one"), None);
        assert_eq!(parse_entry("UUID=x / ext4 defaults 0"), None);
    }

    #[test]
    fn parse_entry_splits_options_on_commas() {
        assert_eq!(
            parse_entry("a / ext4 defaults,nosuid,nodev 0 2"),
            Some(entry(
                "a",
                "/",
                "ext4",
                &["defaults", "nosuid", "nodev"],
                0,
                2
            ))
        );
        assert_eq!(
            parse_entry("a / ext4 , 0 0"),
            Some(entry("a", "/", "ext4", &["", ""], 0, 0))
        );
    }

    // -------------------------------------------------------------------- classify

    #[test]
    fn classify_assigns_the_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("  # indented"), LineKind::Comment);
        assert_eq!(classify("UUID=x / ext4 defaults 0 1"), LineKind::Directive);
        assert_eq!(
            classify("tmpfs /dev/shm tmpfs defaults 0 0 extra"),
            LineKind::Unknown
        );
        assert_eq!(classify("not an fstab line"), LineKind::Unknown);
    }

    // ----------------------------------------------------------------- render_entry

    #[test]
    fn render_entry_emits_single_spaces_and_joined_options() {
        assert_eq!(
            render_entry(&entry("UUID=x", "/", "ext4", &["defaults", "nodev"], 0, 1)),
            Ok("UUID=x / ext4 defaults,nodev 0 1".to_owned())
        );
    }

    #[test]
    fn render_entry_rejects_a_line_break_in_any_field() {
        for bad in [
            entry("a\nb", "/", "ext4", &["defaults"], 0, 1),
            entry("a", "/m\rb", "ext4", &["defaults"], 0, 1),
            entry("a", "/", "ext\0", &["defaults"], 0, 1),
            entry("a", "/", "ext4", &["a\nb"], 0, 1),
        ] {
            assert!(
                matches!(render_entry(&bad), Err(EditError::LineBreakInValue { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn render_entry_rejects_values_that_would_not_round_trip() {
        for bad in [
            entry("", "/", "ext4", &["defaults"], 0, 1),
            entry("a", "", "ext4", &["defaults"], 0, 1),
            entry("a b", "/", "ext4", &["defaults"], 0, 1),
            entry("a", "/m p", "ext4", &["defaults"], 0, 1),
            entry("a", "/", "ex t4", &["defaults"], 0, 1),
            entry("a", "/", "ext4", &["a b"], 0, 1),
            entry("a", "/", "ext4", &["a,b"], 0, 1),
            entry("#a", "/", "ext4", &["defaults"], 0, 1),
        ] {
            assert!(
                matches!(render_entry(&bad), Err(EditError::Unsupported { .. })),
                "expected {bad:?} to be refused"
            );
        }
    }

    // ------------------------------------------------------------------- to_model

    #[test]
    fn to_model_reads_only_entry_lines() -> Result<(), String> {
        let src =
            "# comment\n\nUUID=x / ext4 defaults 0 1\ngarbage\nUUID=y /home ext4 defaults 0 2\n";
        let doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = MountsModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            model.entries,
            vec![
                entry("UUID=x", "/", "ext4", &["defaults"], 0, 1),
                entry("UUID=y", "/home", "ext4", &["defaults"], 0, 2),
            ]
        );
        assert_eq!(MountsModule::render(&doc), src);
        Ok(())
    }

    // ---------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\nUUID=x /       ext4       defaults       0       1\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = MountsModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(MountsModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_entry() -> Result<(), String> {
        let src = "UUID=x / ext4 defaults 0 1\nUUID=y /home ext4 defaults 0 2\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![
                entry("UUID=x", "/", "ext4", &["defaults"], 0, 1),
                entry("UUID=y", "/home", "ext4", &["defaults", "nodev"], 0, 2),
            ],
        };
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(
            MountsModule::render(&doc),
            "UUID=x / ext4 defaults 0 1\nUUID=y /home ext4 defaults,nodev 0 2\n"
        );
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_entries() -> Result<(), String> {
        let src = "UUID=x / ext4 defaults 0 1\nUUID=y /home ext4 defaults 0 2\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("UUID=x", "/", "ext4", &["defaults"], 0, 1)],
        };
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(MountsModule::render(&doc), "UUID=x / ext4 defaults 0 1\n");
        Ok(())
    }

    #[test]
    fn apply_appends_after_the_last_entry_line() -> Result<(), String> {
        let src = "UUID=x / ext4 defaults 0 1\n# trailing comment\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = MountsModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.entries.push(entry(
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            &["defaults", "nosuid", "nodev"],
            0,
            0,
        ));
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            MountsModule::render(&doc),
            "UUID=x / ext4 defaults 0 1\ntmpfs /dev/shm tmpfs defaults,nosuid,nodev 0 0\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_entry_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("UUID=x", "/", "ext4", &["defaults"], 0, 1)],
        };
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            MountsModule::render(&doc),
            "# only a comment\nUUID=x / ext4 defaults 0 1\n"
        );
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        let src = "UUID=x / ext4 defaults 0 1\n";
        let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            entries: vec![entry("a\nb", "/", "ext4", &["defaults"], 0, 1)],
        };
        assert!(MountsModule::apply(&mut doc, &model).is_err());
        assert_eq!(MountsModule::render(&doc), src);
        Ok(())
    }

    // ------------------------------------------------------------------- validate

    #[test]
    fn is_valid_fstype_follows_the_documented_rule() {
        assert!(is_valid_fstype("ext4"));
        assert!(is_valid_fstype("nfs4"));
        assert!(is_valid_fstype("fuseblk"));
        assert!(is_valid_fstype("cgroup2"));
        assert!(!is_valid_fstype(""));
        assert!(!is_valid_fstype("ex t4"));
        assert!(!is_valid_fstype("ext4!"));
    }

    #[test]
    fn missing_guards_lists_what_is_absent() {
        let none: Vec<String> = vec![];
        assert_eq!(missing_guards(&none), MOUNT_GUARDS.to_vec());
        assert_eq!(
            missing_guards(&["defaults".to_owned(), "nosuid".to_owned()]),
            vec!["nodev", "noexec"]
        );
        assert!(
            missing_guards(
                &MOUNT_GUARDS
                    .iter()
                    .map(|g| (*g).to_owned())
                    .collect::<Vec<_>>()
            )
            .is_empty()
        );
    }

    #[test]
    fn validate_flags_an_invalid_fstype() {
        let model = Model {
            entries: vec![entry("a", "/", "ext4!", &["defaults"], 0, 1)],
        };
        assert!(has(&model, INVALID_FSTYPE, Severity::Error));
    }

    #[test]
    fn validate_flags_empty_spec_and_mountpoint() {
        let model = Model {
            entries: vec![
                entry("", "/", "ext4", &["defaults"], 0, 1),
                entry("a", "", "ext4", &["defaults"], 0, 1),
            ],
        };
        assert!(has(&model, EMPTY_SPEC, Severity::Error));
        assert!(has(&model, EMPTY_MOUNTPOINT, Severity::Error));
    }

    #[test]
    fn validate_flags_a_pass_above_fsck_maximum() {
        let model = Model {
            entries: vec![entry("a", "/", "ext4", &["defaults"], 0, 3)],
        };
        assert!(has(&model, PASS_TOO_HIGH, Severity::Error));
    }

    #[test]
    fn validate_flags_a_root_entry_outside_pass_one() {
        let model = Model {
            entries: vec![entry("a", "/", "ext4", &["defaults"], 0, 2)],
        };
        assert!(has(&model, ROOT_PASS, Severity::Warning));
        let ok = Model {
            entries: vec![entry("a", "/", "ext4", &["defaults"], 0, 1)],
        };
        assert!(!has(&ok, ROOT_PASS, Severity::Warning));
    }

    #[test]
    fn validate_flags_removable_media_without_nofail() {
        for removable in [
            entry("a", "/media/usb0", "vfat", &["defaults"], 0, 0),
            entry("a", "/mnt/backup", "ext4", &["defaults"], 0, 2),
            entry("a", "/dvd", "ntfs", &["defaults"], 0, 0),
            entry("a", "/dvd", "exfat", &["defaults"], 0, 0),
        ] {
            let model = Model {
                entries: vec![removable],
            };
            assert!(has(&model, MISSING_NOFAIL, Severity::Warning));
        }
        let has_nofail = Model {
            entries: vec![entry(
                "a",
                "/media/usb0",
                "vfat",
                &["defaults", "nofail"],
                0,
                0,
            )],
        };
        assert!(!has(&has_nofail, MISSING_NOFAIL, Severity::Warning));
        let not_removable = Model {
            entries: vec![entry("a", "/srv", "ext4", &["defaults"], 0, 2)],
        };
        assert!(!has(&not_removable, MISSING_NOFAIL, Severity::Warning));
    }

    #[test]
    fn validate_flags_boot_blockers_and_critical_noauto() {
        let blocked = Model {
            entries: vec![entry(
                "server:/data",
                "/srv/data",
                "nfs4",
                &["defaults"],
                0,
                0,
            )],
        };
        assert!(has(&blocked, MISSING_BOOT_ESCAPE, Severity::Warning));
        let escaped = Model {
            entries: vec![entry(
                "server:/data",
                "/srv/data",
                "nfs4",
                &["defaults", "nofail"],
                0,
                0,
            )],
        };
        assert!(!has(&escaped, MISSING_BOOT_ESCAPE, Severity::Warning));
        for mountpoint in ["/", "/boot", "/efi/EFI"] {
            let model = Model {
                entries: vec![entry(
                    "a",
                    mountpoint,
                    "ext4",
                    &["defaults", "noauto"],
                    0,
                    1,
                )],
            };
            assert!(has(&model, CRITICAL_NO_AUTO, Severity::Warning));
        }
    }

    #[test]
    fn validate_flags_data_mounts_without_guards() {
        let model = Model {
            entries: vec![entry("a", "/srv", "ext4", &["defaults"], 0, 2)],
        };
        assert!(has(&model, MISSING_GUARDS, Severity::Warning));
        // tmpfs holds user data, so /dev/shm needs the guards too.
        let shm = Model {
            entries: vec![entry("tmpfs", "/dev/shm", "tmpfs", &["defaults"], 0, 0)],
        };
        assert!(has(&shm, MISSING_GUARDS, Severity::Warning));
        let guarded = Model {
            entries: vec![entry(
                "tmpfs",
                "/dev/shm",
                "tmpfs",
                &["defaults", "nosuid", "nodev", "noexec"],
                0,
                0,
            )],
        };
        assert!(!has(&guarded, MISSING_GUARDS, Severity::Warning));
        // Root, swap and kernel-state filesystems are exempt.
        for exempt in [
            entry("a", "/", "ext4", &["defaults"], 0, 1),
            entry("a", "none", "swap", &["sw"], 0, 0),
            entry("proc", "/proc", "proc", &["defaults"], 0, 0),
        ] {
            let model = Model {
                entries: vec![exempt],
            };
            assert!(!has(&model, MISSING_GUARDS, Severity::Warning));
        }
    }

    #[test]
    fn validate_recommends_automount_for_network_filesystems() {
        let nfs = Model {
            entries: vec![entry(
                "server:/share",
                "/mnt/nas",
                "nfs",
                &["defaults", "nofail", "noexec", "nodev", "nosuid"],
                0,
                0,
            )],
        };
        assert!(has(&nfs, NETWORK_AUTOMOUNT, Severity::Recommendation));
        let hinted = Model {
            entries: vec![entry(
                "server:/share",
                "/mnt/nas",
                "nfs",
                &["x-systemd.automount", "nofail", "noexec", "nodev", "nosuid"],
                0,
                0,
            )],
        };
        assert!(!has(&hinted, NETWORK_AUTOMOUNT, Severity::Recommendation));
        let not_network = Model {
            entries: vec![entry("a", "/srv", "ext4", &["defaults"], 0, 2)],
        };
        assert!(!has(
            &not_network,
            NETWORK_AUTOMOUNT,
            Severity::Recommendation
        ));
    }

    #[test]
    fn validate_recommends_user_alongside_noauto() {
        let model = Model {
            entries: vec![entry(
                "/dev/cdrom",
                "/media/cdrom",
                "iso9660",
                &["noauto", "nofail", "noexec", "nodev", "nosuid"],
                0,
                0,
            )],
        };
        assert!(has(&model, NOAUTO_WITHOUT_USER, Severity::Recommendation));
        let with_user = Model {
            entries: vec![entry(
                "/dev/cdrom",
                "/media/cdrom",
                "iso9660",
                &["noauto", "user", "noexec", "nodev", "nosuid"],
                0,
                0,
            )],
        };
        assert!(!has(
            &with_user,
            NOAUTO_WITHOUT_USER,
            Severity::Recommendation
        ));
    }

    #[test]
    fn validate_accepts_a_hardened_model() {
        let model = Model {
            entries: vec![
                entry("UUID=root", "/", "ext4", &["defaults"], 0, 1),
                entry(
                    "tmpfs",
                    "/dev/shm",
                    "tmpfs",
                    &["defaults", "nosuid", "nodev"],
                    0,
                    0,
                ),
            ],
        };
        let host = profile(Os::Linux, "host");
        let ctx = ValidationCtx::new(&host);
        let diagnostics = MountsModule::validate(&model, &ctx);
        assert!(!diagnostics.has_errors());
        assert!(diagnostics.iter().all(|d| d.severity != Severity::Error));
    }

    // ------------------------------------------------------------------- defaults

    #[test]
    fn defaults_are_empty_and_valid() {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            let host = profile(os, "node1");
            assert_eq!(MountsModule::defaults(&host), Model { entries: vec![] });
            let ctx = ValidationCtx::new(&host);
            let diagnostics = MountsModule::validate(&MountsModule::defaults(&host), &ctx);
            assert!(!diagnostics.has_errors());
        }
    }

    #[test]
    fn defaults_apply_to_an_empty_file_as_a_noop() -> Result<(), String> {
        let host = profile(Os::Linux, "host");
        let model = MountsModule::defaults(&host);
        let mut doc = MountsModule::parse("").map_err(|e| e.to_string())?;
        let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(MountsModule::render(&doc), "");
        assert_eq!(
            MountsModule::to_model(&doc).map_err(|e| e.to_string())?,
            model
        );
        Ok(())
    }

    // ----------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_and_backend() {
        let descriptor = MountsModule::descriptor();
        assert_eq!(descriptor.id, MountsModule::ID);
        assert!(descriptor.commit_confirm);
        assert!(descriptor.services.is_empty());
        assert_eq!(descriptor.targets.len(), 2);
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux, "h")));
            assert!(!(target.backend_detect)(&profile(Os::MacOs, "h")));
        }
    }

    // --------------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, MountsModule::schema());
        for pointer in [
            "/properties/entries",
            "/$defs/Entry/properties/spec",
            "/$defs/Entry/properties/mountpoint",
            "/$defs/Entry/properties/fstype",
            "/$defs/Entry/properties/options",
            "/$defs/Entry/properties/dump",
            "/$defs/Entry/properties/pass",
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

    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let model = Model {
            entries: vec![entry("UUID=x", "/", "ext4", &["defaults"], 0, 1)],
        };
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("ext4"));
        assert_eq!(Model::default(), Model { entries: vec![] });
        let json = serde_json::to_value(&model).unwrap_or_default();
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(model));
        assert!(serde_json::from_str::<Entry>(
            r#"{"spec":"a","mountpoint":"/","fstype":"ext4","options":[],"dump":0,"pass":1,"x":1}"#
        )
        .is_err());
    }

    // ------------------------------------------------------------- adversarial

    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "dev-{i} /mp/{i} ext4 defaults 0 1");
        }
        for src in [
            "UUID=x / ext4 defaults 0 1",
            "UUID=x / ext4 defaults 0 1\r\nUUID=y /home ext4 defaults 0 2\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
        ] {
            let mut doc = MountsModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(MountsModule::render(&doc), src);
            let model = MountsModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = MountsModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(MountsModule::render(&doc), src);
        }
        Ok(())
    }

    // --------------------------------------------------------------------- fuzzing

    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_builds_a_model() {
        use arbitrary::{Arbitrary, Unstructured};
        let data: Vec<u8> = (0u8..64).collect();
        let mut u = Unstructured::new(&data);
        assert!(Model::arbitrary(&mut u).is_ok());
        assert!(Entry::arbitrary_take_rest(Unstructured::new(&data)).is_ok());
        assert!(<Model as Arbitrary>::size_hint(0).1.is_none());
    }
}
