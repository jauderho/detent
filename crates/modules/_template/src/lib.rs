//! The `TEMPLATE` module: `/etc/TEMPLATE.conf`, a fictional line-oriented
//! `key value` format, kept as the copy-me skeleton for a new config module.
//!
//! TODO(doc): rewrite this header for the real format. State, in this order:
//! what a line can be, what is deliberately *not* modeled (and therefore stays
//! [`LineKind::Unknown`]), and the formatting policy `apply` follows. The `hosts`
//! module (`crates/modules/hosts/src/lib.rs`) is the worked example this file is
//! a stripped-down copy of; read it alongside `docs/MODULE_GUIDE.md`.
//!
//! Every line of `/etc/TEMPLATE.conf` is blank, a `#` comment, or a directive
//! `<key> <value…>` where the key is one word and the value runs to the end of
//! the line. A line that is not one of those — a key with no value, say — is
//! kept as [`LineKind::Unknown`] and is never rewritten.
//!
//! # Formatting policy
//!
//! A line is left byte for byte alone whenever the setting parsed from it equals
//! the setting in the model, so hand alignment and odd spacing survive. Only
//! lines that actually change are re-rendered, as `<key> <value>`.
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
use std::collections::BTreeSet;

// ------------------------------------------------------------------------- model

/// One `key value` setting.
///
/// TODO(model): replace with the real model types.
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
pub struct Setting {
    /// The directive name: one word, no whitespace.
    pub key: String,
    /// The value, up to the end of the line.
    pub value: String,
}

/// The typed model of `/etc/TEMPLATE.conf`: its settings, in file order.
///
/// TODO(model): a `Vec` of settings in file order is the right shape for a
/// format where order matters and duplicates are legal. If the real format is a
/// set of named options instead, use named fields (`Option<T>` for "not present")
/// so the schema is a form rather than a list — but then `apply` must still leave
/// unknown directives alone.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The settings, in the order they appear in the file.
    pub settings: Vec<Setting>,
}

// ------------------------------------------------------------ parsing / rendering

/// Parses one line as a setting, or `None` when it is not one.
///
/// TODO(parse): this is the whole grammar of the fictional format. Replace it,
/// and keep it total: it takes any `&str` and returns `Option`, never panics, and
/// never allocates unboundedly. Anything it rejects becomes
/// [`LineKind::Unknown`], which `apply` copies through untouched — that is how
/// directives this module does not understand survive an edit.
fn parse_setting(raw: &str) -> Option<Setting> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (key, value) = trimmed.split_once(char::is_whitespace)?;
    // `trimmed` has no trailing whitespace, so `value` is never empty here and an
    // `is_empty` guard would be dead code — PLAN §6.2 forbids unreachable lines
    // (100 % line coverage, no exclusion markers). A key with no value fails the
    // `?` above instead, and stays `Unknown`.
    let value = value.trim();
    Some(Setting {
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

/// Classifies a line for the lossless document model.
///
/// TODO(classify): the four buckets are fixed by `detent-core`; what belongs in
/// each is format-specific. Two rules matter:
///
/// * The classifier must be a pure function of the line text alone. `Document`
///   re-runs it after every edit, so a classifier that depended on context would
///   make `apply` non-deterministic.
/// * `Directive` must mean "`parse_setting` succeeds". `to_model` and `apply`
///   both walk `Directive` lines; if the two disagree, invariant 2 breaks.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with('#') {
        LineKind::Comment
    } else if parse_setting(raw).is_some() {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

/// Renders a setting as a line, refusing anything that would not survive a round
/// trip.
///
/// TODO(render): keep both guards. The first is invariant 5 (directive
/// injection): a value carrying `\n`, `\r` or NUL is **rejected**, never escaped
/// away and never written. The second is the general form of the same idea — if
/// the rendered line does not parse back to the setting it came from, the edit
/// would silently mean something else, so refuse it. Formats with quoting rules
/// quote here instead of refusing, but must still re-parse-check the result.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when the key or value carries `\n`, `\r` or
/// NUL, and [`EditError::Unsupported`] when the rendered line does not parse back
/// to the same setting — an empty value, a key containing whitespace, a key that
/// starts with `#`, or a value that is not already trimmed.
fn render_line(setting: &Setting) -> Result<String, EditError> {
    let raw = format!("{} {}", setting.key, setting.value);
    if raw.contains(['\n', '\r', '\0']) {
        return Err(EditError::LineBreakInValue { value: raw });
    }
    if parse_setting(&raw).as_ref() != Some(setting) {
        return Err(EditError::Unsupported {
            message: format!("setting does not round-trip through the file format: {raw:?}"),
        });
    }
    Ok(raw)
}

// -------------------------------------------------------------------- descriptor

/// Whether this backend is the right one for `profile`.
///
/// TODO(descriptor): a format that exists on every supported OS returns `true`
/// unconditionally (see `hosts`). A format with per-distribution backends gets
/// one [`Target`] per backend, each with its own detector, and the operations
/// layer picks the first that matches.
fn detect_backend(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

/// TODO(descriptor): the files this module owns. Paths are `&'static` templates
/// and are **never** user-supplied (PLAN §2.3): a request can select a module, it
/// can never name the file the module writes. `mode` and `owner` are what the
/// platform layer enforces after an atomic write.
static TARGETS: &[Target] = &[Target {
    path: PathSpec::new("/etc/TEMPLATE.conf"),
    kind: TargetKind::File,
    mode: 0o644,
    owner: Owner::Root,
    backend_detect: detect_backend,
}];

/// TODO(descriptor): the upstream validator run against the candidate file before
/// it is installed, e.g. `chronyd -p -f <tmp>` or `testparm -s <tmp>`.
/// [`ArgTemplate::TempFile`] is replaced by the path of the candidate. Leave the
/// slice empty (`&[]`, as `hosts` does) when the format has no validator — never
/// invent one.
static CHECKS: &[ExternalCheck] = &[ExternalCheck {
    program: PathSpec::new("/usr/sbin/TEMPLATE"),
    args: &[ArgTemplate::Literal("--test"), ArgTemplate::TempFile],
    expects: CheckExpectation::ExitZero,
}];

/// TODO(descriptor): the services a change to these files affects. Give every
/// init system its alternatives, most preferred first — distributions disagree
/// (`chronyd.service` on Fedora, `chrony.service` on Debian). `actions` lists
/// what the admin may ask for after an apply, most preferred first. A module
/// that configures no daemon uses `&[]`.
static SERVICES: &[ServiceBinding] = &[ServiceBinding {
    units: UnitNames {
        systemd: &["TEMPLATE.service"],
        openrc: &["TEMPLATE"],
        bsdrc: &["TEMPLATE"],
    },
    actions: &[ServiceAction::Reload, ServiceAction::Restart],
}];

/// TODO(descriptor): keep every value here in sync with `upstream.toml`; the unit
/// test below fails when they drift. Set `commit_confirm: true` only for a module
/// that can lock the admin out of the host (network configuration); it makes
/// every apply need a second confirmation (ADR-012).
static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "TEMPLATE",
    display_name_id: MessageId::new("TEMPLATE-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "TEMPLATE-project",
        repo_url: "https://example.invalid/TEMPLATE.git",
        tracked_version: "0.0",
        release_feed: Some("https://example.invalid/TEMPLATE/tags?format=atom"),
        docs: &["https://example.invalid/TEMPLATE.5.html"],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: false,
    security_notes: &[MessageId::new("TEMPLATE-note-precedence")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `settings`.
///
/// TODO(hints): Appendix A requires `x-detent` hints on **every** field, and the
/// test below asserts every pointer resolves. `group` decides Basic vs Advanced
/// in the UI, `security_impact` drives the warning styling, `since` /
/// `deprecated_in` hide or flag options against the version detected in
/// [`HostProfile`], and `recommendation` is the Fluent id of the callout shown
/// when the current value is worse than the recommended one.
static SETTINGS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("TEMPLATE-tip-settings"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `settings[].key`.
static KEY_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("TEMPLATE-tip-key"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: None,
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `settings[].value`.
static VALUE_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("TEMPLATE-tip-value"),
    recommendation: Some(MessageId::new("TEMPLATE-rec-value")),
    security_impact: SecurityImpact::High,
    since: Some("0.0"),
    deprecated_in: None,
    requires_restart: true,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `TemplateModule::schema()` and, through `Dyn`,
/// [`DynModule::schema_json`](detent_core::module::DynModule::schema_json) see
/// the hinted schema.
///
/// TODO(hints): the JSON pointers depend on the shape `schemars` generates.
/// `apply_hints` returns `false` when a pointer resolves to nothing, and the test
/// below turns that into a failure — do not drop the assertion, a silently
/// unattached hint is invisible in the UI.
fn schema_with_hints() -> serde_json::Value {
    let mut schema = schemars::schema_for!(Model).to_value();
    for (pointer, hints) in [
        ("/properties/settings", &SETTINGS_HINTS),
        ("/$defs/Setting/properties/key", &KEY_HINTS),
        ("/$defs/Setting/properties/value", &VALUE_HINTS),
    ] {
        let _applied: bool = apply_hints(&mut schema, pointer, hints);
    }
    schema
}

// ------------------------------------------------------------------- validation

/// Fluent id: a key is not a valid directive name.
const INVALID_KEY: MessageId = MessageId::new("TEMPLATE-invalid-key");
/// Fluent id: the same key is set twice.
const DUPLICATE_KEY: MessageId = MessageId::new("TEMPLATE-duplicate-key");
/// Fluent id: the file has grown past the point where drop-ins are better.
const TOO_MANY_SETTINGS: MessageId = MessageId::new("TEMPLATE-too-many-settings");

/// Above this many settings, `validate` recommends drop-in files instead.
const SETTING_COUNT_ADVICE_THRESHOLD: usize = 100;

/// Whether `key` is a valid directive name.
///
/// TODO(validate): replace with the format's real rule and cite the upstream
/// documentation for it in this doc comment. Never hand-roll a rule the upstream
/// parser does not have: a value this module rejects but the daemon accepts is a
/// bug report, and a value this module accepts but the daemon rejects is caught
/// only by the [`ExternalCheck`], which may not be installed.
fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphabetic())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------- defaults

/// Builds one default setting.
fn setting(key: &str, value: &str) -> Setting {
    Setting {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

// ----------------------------------------------------------------------- module

/// The `/etc/TEMPLATE.conf` config module.
///
/// TODO(rename): `TemplateModule` and the `TEMPLATE` id are placeholders; see
/// `crates/modules/_template/README.md` for the two `sed` commands that rename
/// both.
pub struct TemplateModule;

impl ConfigModule for TemplateModule {
    /// TODO(id): the stable id. It appears in URLs, the CLI, the audit log, the
    /// `module-<id>` feature name, the Fluent id prefix, `fixtures/<id>/` and the
    /// fuzz target names, so it is effectively public API. Lowercase, no spaces.
    const ID: &'static str = "TEMPLATE";
    /// TODO(doc): `detent_core::doc::Document` is the shared line-oriented CST and
    /// fits every line-based format. A format with a richer grammar (INI, YAML,
    /// JSON) defines its own CST type in this crate and implements
    /// `detent_core::module::LosslessDoc` for it — reusing `Span` and
    /// `Diagnostic`, but not `Document` (ADR-008).
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    /// TODO(parse): `parse` is total for line-oriented formats — it returns `Ok`
    /// for every `&str`, including empty input, lone `\r`, and embedded NUL. Only
    /// a module over a stricter grammar returns `ParseError`, and even then it
    /// must never panic: invariant 6 runs it over 1 MiB of adversarial bytes.
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// TODO(to-model): project only what the model can express, and drop nothing
    /// else — `Unknown` and `Comment` lines stay in the `Doc` and are what makes
    /// `render` lossless. `to_model` must agree with `apply` about which lines
    /// are settings, or invariant 2 fails.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        Ok(Model {
            settings: doc
                .lines_of_kind(LineKind::Directive)
                .filter_map(|line| parse_setting(line.raw()))
                .collect(),
        })
    }

    /// TODO(apply): this two-pass shape is the minimal-edit pattern and is worth
    /// copying verbatim; only `parse_setting`/`render_line` are format-specific.
    ///
    /// * Pass 1 is read-only. Rendering every changed line **before** touching the
    ///   document means a rejected value (invariant 5) leaves the file exactly as
    ///   it was — a half-applied config is worse than a refused one.
    /// * A line whose parsed setting already equals the model's is not rendered at
    ///   all, so hand-aligned columns and unusual spacing survive. That is what
    ///   makes invariant 2 (`apply(doc, to_model(doc))` changes nothing, and
    ///   reports `EditReport::default()`) hold.
    /// * Pass 2 only ever touches `Directive` lines: comments, blanks and unknown
    ///   directives keep their position.
    /// * New lines go after the last existing setting, not at the end of the file,
    ///   so a trailing comment block stays trailing.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        // Pass 1, read-only: pair model settings with the existing directive lines
        // in order and render the ones that differ.
        let mut planned: Vec<Option<String>> = Vec::with_capacity(model.settings.len());
        for line in doc
            .lines()
            .iter()
            .filter(|line| line.kind() == LineKind::Directive)
        {
            let Some(wanted) = model.settings.get(planned.len()) else {
                break;
            };
            let unchanged = parse_setting(line.raw()).as_ref() == Some(wanted);
            planned.push(if unchanged {
                None
            } else {
                Some(render_line(wanted)?)
            });
        }
        for wanted in model.settings.iter().skip(planned.len()) {
            planned.push(Some(render_line(wanted)?));
        }

        // Pass 2: rewrite, drop the directive lines the model no longer has, and
        // append the rest after the last directive line.
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

    /// TODO(validate): a module needs at least one of each severity, and every
    /// finding carries a Fluent id — never a rendered sentence, this crate does
    /// not localize (ADR-003). Attach a [`FieldPath`] whenever the finding is
    /// about one field so the UI can point at the control, and pass every value
    /// that appears in the message as a named argument, so translators can
    /// reorder them.
    ///
    /// * [`Severity::Error`] — the config is invalid and must not be applied.
    /// * [`Severity::Warning`] — valid, but likely not what the admin meant.
    /// * [`Severity::Recommendation`] — fine, but a better option exists.
    ///
    /// `ctx` carries the [`HostProfile`]; use it to make findings host-aware
    /// (e.g. flag an option newer than the installed service version) rather than
    /// warning about things that cannot apply to this host.
    fn validate(model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (index, item) in model.settings.iter().enumerate() {
            if !is_valid_key(&item.key) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, INVALID_KEY)
                        .with_field(FieldPath::new(format!("settings/{index}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
            if !seen.insert(item.key.to_ascii_lowercase()) {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, DUPLICATE_KEY)
                        .with_field(FieldPath::new(format!("settings/{index}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
        }
        if model.settings.len() > SETTING_COUNT_ADVICE_THRESHOLD {
            diagnostics.push(
                Diagnostic::new(Severity::Recommendation, TOO_MANY_SETTINGS)
                    .with_field(FieldPath::new("settings"))
                    .with_arg("count", model.settings.len().to_string()),
            );
        }
        diagnostics
    }

    /// TODO(defaults): "smart, secure defaults for this host" (PLAN §2.3), not an
    /// empty model and not upstream's shipped file. Branch on
    /// [`HostProfile::os`](detent_core::descriptor::HostProfile) — and on
    /// `init`, `hostname`, `ram_mib` or a detected service version when the format
    /// needs them. Match on `Os` exhaustively rather than using a `_` arm, so a
    /// new platform tier is a compile error here instead of a silently wrong file
    /// (ADR-013). Whatever this returns must pass `validate` with no errors; the
    /// test below asserts exactly that.
    fn defaults(profile: &HostProfile) -> Self::Model {
        let mut settings = vec![setting("mode", "strict")];
        match profile.os {
            Os::Linux => settings.push(setting("backend", "systemd")),
            Os::MacOs => settings.push(setting("backend", "launchd")),
            Os::Other => settings.push(setting("backend", "none")),
        }
        if !profile.hostname.is_empty() {
            settings.push(setting("node-name", profile.hostname.as_str()));
        }
        Model { settings }
    }

    /// TODO(hints): a module with no `x-detent` hints can drop this override
    /// and rely on the trait's default (the bare `schemars` schema).
    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DESCRIPTOR, DUPLICATE_KEY, INVALID_KEY, Model, Setting, TOO_MANY_SETTINGS, TemplateModule,
        classify, is_valid_key, parse_setting, render_line, schema_with_hints, setting,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};

    /// TODO(fluent): `locales/en-US/core.ftl` is the source of truth for every
    /// user-facing string (PLAN §4.3). This test is what keeps a raw id from
    /// reaching the UI: list every `MessageId` this crate constructs — display
    /// name, security notes, tooltips, recommendations and diagnostics — and add
    /// the matching lines to `core.ftl` (the README's `locale-snippet.ftl` step
    /// does that in one command).
    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// TODO(upstream): keeps `upstream.toml` and the descriptor from drifting.
    /// `upstream-watch` reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "TEMPLATE-name",
            "TEMPLATE-note-precedence",
            "TEMPLATE-tip-settings",
            "TEMPLATE-tip-key",
            "TEMPLATE-tip-value",
            "TEMPLATE-rec-value",
            "TEMPLATE-invalid-key",
            "TEMPLATE-duplicate-key",
            "TEMPLATE-too-many-settings",
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

    fn has(model: &Model, id: MessageId, severity: Severity) -> bool {
        let host = profile(Os::Linux, "host");
        let ctx = ValidationCtx::new(&host);
        TemplateModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    // --------------------------------------------------------------- parse_setting

    #[test]
    fn parse_setting_reads_a_key_and_a_value() {
        assert_eq!(
            parse_setting("  mode   strict  "),
            Some(setting("mode", "strict"))
        );
        assert_eq!(parse_setting("mode a  b"), Some(setting("mode", "a  b")));
    }

    #[test]
    fn parse_setting_rejects_non_settings() {
        assert_eq!(parse_setting(""), None);
        assert_eq!(parse_setting("   "), None);
        assert_eq!(parse_setting("# comment"), None);
        assert_eq!(parse_setting("lonely"), None);
        assert_eq!(parse_setting("lonely   "), None);
    }

    // -------------------------------------------------------------------- classify

    #[test]
    fn classify_assigns_the_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("  # indented"), LineKind::Comment);
        assert_eq!(classify("mode strict"), LineKind::Directive);
        assert_eq!(classify("lonely"), LineKind::Unknown);
    }

    // ----------------------------------------------------------------- render_line

    #[test]
    fn render_line_emits_a_single_space() {
        assert_eq!(
            render_line(&setting("mode", "strict")),
            Ok("mode strict".to_owned())
        );
    }

    #[test]
    fn render_line_rejects_a_line_break_in_a_value() {
        assert_eq!(
            render_line(&setting("mode", "a\nb")),
            Err(EditError::LineBreakInValue {
                value: "mode a\nb".to_owned()
            })
        );
    }

    #[test]
    fn render_line_rejects_values_that_would_not_round_trip() {
        for bad in [
            setting("mode", ""),
            setting("has space", "v"),
            setting("#mode", "v"),
            setting("mode", " padded"),
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
        let src = "# comment\n\nmode strict\nlonely\nbackend systemd\n";
        let doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = TemplateModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            model.settings,
            vec![setting("mode", "strict"), setting("backend", "systemd")]
        );
        assert_eq!(TemplateModule::render(&doc), src);
        Ok(())
    }

    // ---------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\nmode      strict\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = TemplateModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(TemplateModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_setting() -> Result<(), String> {
        let src = "mode strict\nbackend systemd\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("mode", "loose"), setting("backend", "systemd")],
        };
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(
            TemplateModule::render(&doc),
            "mode loose\nbackend systemd\n"
        );
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_settings() -> Result<(), String> {
        let src = "mode strict\nbackend systemd\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("mode", "strict")],
        };
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(TemplateModule::render(&doc), "mode strict\n");
        Ok(())
    }

    #[test]
    fn apply_appends_after_the_last_directive_line() -> Result<(), String> {
        let src = "mode strict\n# trailing comment\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = TemplateModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.settings.push(setting("backend", "systemd"));
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            TemplateModule::render(&doc),
            "mode strict\nbackend systemd\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_directive_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("mode", "strict")],
        };
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            TemplateModule::render(&doc),
            "# only a comment\nmode strict\n"
        );
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        let src = "mode strict\n";
        let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("mode", "a\nb")],
        };
        assert!(TemplateModule::apply(&mut doc, &model).is_err());
        assert_eq!(TemplateModule::render(&doc), src);
        Ok(())
    }

    // ------------------------------------------------------------------- validate

    #[test]
    fn is_valid_key_follows_the_documented_rule() {
        assert!(is_valid_key("mode"));
        assert!(is_valid_key("node-name_2"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("2fast"));
        assert!(!is_valid_key("mode!"));
    }

    #[test]
    fn validate_flags_an_invalid_key() {
        let model = Model {
            settings: vec![setting("2fast", "v")],
        };
        assert!(has(&model, INVALID_KEY, Severity::Error));
    }

    #[test]
    fn validate_flags_a_duplicate_key_case_insensitively() {
        let model = Model {
            settings: vec![setting("Mode", "a"), setting("mode", "b")],
        };
        assert!(has(&model, DUPLICATE_KEY, Severity::Warning));
    }

    #[test]
    fn validate_accepts_distinct_valid_keys() {
        let model = Model {
            settings: vec![setting("mode", "a"), setting("backend", "b")],
        };
        assert!(!has(&model, INVALID_KEY, Severity::Error));
        assert!(!has(&model, DUPLICATE_KEY, Severity::Warning));
        assert!(!has(&model, TOO_MANY_SETTINGS, Severity::Recommendation));
    }

    #[test]
    fn validate_recommends_drop_ins_past_the_threshold() {
        let settings = (0..=100)
            .map(|i| setting(&format!("key-{i}"), "v"))
            .collect();
        let model = Model { settings };
        assert!(has(&model, TOO_MANY_SETTINGS, Severity::Recommendation));
    }

    // ------------------------------------------------------------------- defaults

    #[test]
    fn defaults_branch_on_the_operating_system() {
        for (os, backend) in [
            (Os::Linux, "systemd"),
            (Os::MacOs, "launchd"),
            (Os::Other, "none"),
        ] {
            let model = TemplateModule::defaults(&profile(os, "node1"));
            assert_eq!(
                model.settings,
                vec![
                    setting("mode", "strict"),
                    setting("backend", backend),
                    setting("node-name", "node1"),
                ]
            );
        }
    }

    #[test]
    fn defaults_without_a_hostname_skip_the_node_name() {
        let model = TemplateModule::defaults(&profile(Os::Linux, ""));
        assert_eq!(
            model.settings,
            vec![setting("mode", "strict"), setting("backend", "systemd")]
        );
    }

    #[test]
    fn defaults_are_valid_and_apply_to_an_empty_file() -> Result<(), String> {
        let host = profile(Os::Linux, "node1");
        let ctx = ValidationCtx::new(&host);
        let model = TemplateModule::defaults(&host);
        assert!(!TemplateModule::validate(&model, &ctx).has_errors());
        let mut doc = TemplateModule::parse("").map_err(|e| e.to_string())?;
        let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, model.settings.len());
        assert_eq!(
            TemplateModule::render(&doc),
            "mode strict\nbackend systemd\nnode-name node1\n"
        );
        Ok(())
    }

    // ----------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_and_backend() {
        let descriptor = TemplateModule::descriptor();
        assert_eq!(descriptor.id, TemplateModule::ID);
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux, "h")));
            assert!(!(target.backend_detect)(&profile(Os::MacOs, "h")));
        }
    }

    // --------------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, TemplateModule::schema());
        for pointer in [
            "/properties/settings",
            "/$defs/Setting/properties/key",
            "/$defs/Setting/properties/value",
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

    /// TODO(tests): exercises the derived impls the module's own logic never
    /// calls. Coverage is 100 % lines for `crates/modules/` (PLAN §6.2), and a
    /// derive with no caller is the usual reason a module misses it.
    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let model = Model {
            settings: vec![setting("mode", "strict")],
        };
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("strict"));
        assert_eq!(Model::default(), Model { settings: vec![] });
        let json = serde_json::to_value(&model).unwrap_or_default();
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(model));
        assert!(serde_json::from_str::<Setting>(r#"{"key":"k","value":"v","x":1}"#).is_err());
    }

    // ------------------------------------------------------------- adversarial

    /// TODO(tests): keep an adversarial block. These are the shapes that broke
    /// real parsers: no trailing newline, CRLF, NUL, one very long line, and a
    /// file large enough that a super-linear `apply` shows up as a timeout.
    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "key-{i} v");
        }
        for src in [
            "mode strict",
            "mode strict\r\nbackend systemd\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
        ] {
            let mut doc = TemplateModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(TemplateModule::render(&doc), src);
            let model = TemplateModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = TemplateModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(TemplateModule::render(&doc), src);
        }
        Ok(())
    }

    // --------------------------------------------------------------------- fuzzing

    /// TODO(fuzzing): the derived `Arbitrary` generates arbitrary `String`s, so
    /// most generated models are refused by `render_line` and the
    /// `fuzz_TEMPLATE_edit` target spends its budget on the rejection path. If
    /// that shows up as poor coverage in a fuzz run, hand-write `Arbitrary` to
    /// emit format-shaped values instead — `hosts` does exactly that for its
    /// RFC 1123 hostnames.
    #[cfg(feature = "fuzzing")]
    #[test]
    fn arbitrary_builds_a_model() {
        use arbitrary::{Arbitrary, Unstructured};
        let data: Vec<u8> = (0u8..64).collect();
        let mut u = Unstructured::new(&data);
        assert!(Model::arbitrary(&mut u).is_ok());
        assert!(Setting::arbitrary_take_rest(Unstructured::new(&data)).is_ok());
        assert!(<Model as Arbitrary>::size_hint(0).1.is_none());
    }
}
