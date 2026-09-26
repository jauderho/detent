//! The `chrony` module: `chronyd`'s configuration file (`chrony.conf`), a
//! line-oriented `key value` format.
//!
//! Every line of `chrony.conf` is blank, a comment line (`!`, `;`, `#` or `%`
//! after zero or more spaces — chrony.conf(5)), or a directive `<key>
//! <value…>` where the key is one word and the value runs to the end of the
//! line. A few directives (`rtcsync`, `rtconutc`, `manual`, `noclientlog`,
//! `nosystemcert`) take no value at all; they parse to a [`Setting`] with an
//! empty `value`. A line that is not one of those — a single word that is not
//! a valueless directive, say — is kept as [`LineKind::Unknown`] and is never
//! rewritten. The module does not model the *meaning* of any directive: the
//! model is the generic key/value pair, which is what keeps `apply` lossless
//! across chrony releases that add directives this crate has never heard of.
//!
//! # Formatting policy
//!
//! A line is left byte for byte alone whenever the setting parsed from it
//! equals the setting in the model, so hand alignment and odd spacing survive.
//! Only lines that actually change are re-rendered, as `<key> <value>`.
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
use detent_core::module::{ConfigModule, EditError, EditReport, ModelError, ParseError};
use std::collections::BTreeSet;

// ------------------------------------------------------------------------- model

/// One `key value` setting.
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
    /// The directive name: one word, no whitespace, case-insensitive per
    /// chrony.conf(5).
    pub key: String,
    /// The value, up to the end of the line. Empty for a valueless directive
    /// such as `rtcsync`.
    pub value: String,
}

/// The typed model of `chrony.conf`: its settings, in file order.
///
/// A `Vec` of settings in file order is the right shape for a format where
/// order matters and duplicates are legal — chrony.conf(5): "if a directive is
/// specified multiple times, only the last one will be effective", yet some
/// directives (`server`, `pool`, `allow`, `log`) are repeatable on purpose.
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

/// Directive names that take no value at all (chrony.conf(5), 4.9).
const BARE_DIRECTIVES: &[&str] = &[
    "manual",
    "noclientlog",
    "nosystemcert",
    "rtconutc",
    "rtcsync",
];

/// Whether `key` is a directive that takes no value.
fn is_bare_directive(key: &str) -> bool {
    BARE_DIRECTIVES
        .iter()
        .any(|bare| bare.eq_ignore_ascii_case(key))
}

/// Whether `c` starts a comment line (chrony.conf(5): `!`, `;`, `#`, `%`).
fn is_comment_char(c: char) -> bool {
    matches!(c, '!' | ';' | '#' | '%')
}

/// Parses one line as a setting, or `None` when it is not one.
///
/// This is the whole grammar of the format. It is total: it takes any `&str`
/// and returns `Option`, never panics, and never allocates unboundedly.
/// Anything it rejects becomes [`LineKind::Unknown`], which `apply` copies
/// through untouched — that is how directives this module does not understand
/// survive an edit. Blank and comment lines are rejected here too, so
/// [`classify`] can rely on `parse_setting` alone below them.
fn parse_setting(raw: &str) -> Option<Setting> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with(is_comment_char) {
        return None;
    }
    let Some((key, value)) = trimmed.split_once(char::is_whitespace) else {
        // A single word: a valueless directive if it is one of
        // [`BARE_DIRECTIVES`], garbage otherwise. The `rtcsync` family must
        // parse here because `validate` and `defaults` both talk about it;
        // every other bare word stays `Unknown`.
        return is_bare_directive(trimmed).then(|| Setting {
            key: trimmed.to_owned(),
            value: String::new(),
        });
    };
    // `trimmed` has no trailing whitespace, so `value` is never only spaces and
    // a second `trim` of it is always a no-op — PLAN §6.2 forbids unreachable
    // lines (100 % line coverage, no exclusion markers). A value this short
    // still needs the leading whitespace removed, which `split_once` left in.
    let value = value.trim_start();
    Some(Setting {
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

/// Classifies a line for the lossless document model.
///
/// The four buckets are fixed by `detent-core`; what belongs in each is
/// format-specific. Two rules matter:
///
/// * The classifier must be a pure function of the line text alone. `Document`
///   re-runs it after every edit, so a classifier that depended on context would
///   make `apply` non-deterministic.
/// * `Directive` must mean "`parse_setting` succeeds". `to_model` and `apply`
///   both walk `Directive` lines; if the two disagree, invariant 2 breaks.
fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.trim_start().starts_with(is_comment_char) {
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
/// The first guard is invariant 5 (directive injection): a value carrying
/// `\n`, `\r` or NUL is **rejected**, never escaped away and never written. The
/// second is the general form of the same idea — if the rendered line does not
/// parse back to the setting it came from, the edit would silently mean
/// something else, so refuse it. chrony has no quoting rules, so there is
/// nothing to quote here; the re-parse check is the whole safety net.
///
/// # Errors
///
/// [`EditError::LineBreakInValue`] when the key or value carries `\n`, `\r` or
/// NUL, and [`EditError::Unsupported`] when the rendered line does not parse back
/// to the same setting — an empty value on a directive that is not valueless, a
/// key containing whitespace, or a key that starts with a comment character.
fn render_line(setting: &Setting) -> Result<String, EditError> {
    let raw = if setting.value.is_empty() {
        setting.key.clone()
    } else {
        format!("{} {}", setting.key, setting.value)
    };
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
/// chrony.conf lives at the compiled-in Linux path on every distribution this
/// module targets; macOS builds of chronyd use a different prefix
/// (`/opt/homebrew/etc/chrony.conf`), which is not this module's target.
fn chrony_backend_detect(profile: &HostProfile) -> bool {
    profile.os == Os::Linux
}

/// The files this module owns. Paths are `&'static` templates and are **never**
/// user-supplied (PLAN §2.3): a request can select a module, it can never name
/// the file the module writes. `mode` and `owner` are what the platform layer
/// enforces after an atomic write.
static TARGETS: &[Target] = &[
    Target {
        path: PathSpec::new("/etc/chrony/chrony.conf"),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: chrony_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/chrony/sources.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: chrony_backend_detect,
    },
    Target {
        path: PathSpec::new("/etc/chrony/conf.d"),
        kind: TargetKind::DropInDir,
        mode: 0o755,
        owner: Owner::Root,
        backend_detect: chrony_backend_detect,
    },
];

/// The upstream validator run against the candidate file before it is
/// installed: `chronyd -p` parses a configuration file without starting the
/// daemon (`-f` names it, [`ArgTemplate::TempFile`] is replaced by the path of
/// the candidate).
static CHECKS: &[ExternalCheck] = &[ExternalCheck {
    program: PathSpec::new("/usr/sbin/chronyd"),
    args: &[
        ArgTemplate::Literal("-p"),
        ArgTemplate::Literal("-f"),
        ArgTemplate::TempFile,
    ],
    expects: CheckExpectation::ExitZero,
}];

/// The services a change to these files affects. systemd names it
/// `chronyd.service` on Fedora/RHEL and `chrony.service` on Debian;
/// `chronyd` is the unit name everywhere else. `actions` lists what the admin
/// may ask for after an apply, most preferred first — chronyd reloads its
/// configuration on `SIGHUP`, so a full restart is never required.
static SERVICES: &[ServiceBinding] = &[ServiceBinding {
    units: UnitNames {
        systemd: &["chronyd.service", "chrony.service"],
        openrc: &["chronyd"],
        bsdrc: &["chronyd"],
    },
    actions: &[ServiceAction::Reload, ServiceAction::Restart],
}];

/// Keep every value here in sync with `upstream.toml`; the unit test below
/// fails when they drift. `commit_confirm` is `false` because a bad chrony
/// config degrades time keeping but cannot lock the admin out of the host
/// (ADR-012).
static DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "chrony",
    display_name_id: MessageId::new("chrony-name"),
    targets: TARGETS,
    upstream: Upstream {
        project: "chrony",
        repo_url: "https://gitlab.com/chrony/chrony.git",
        tracked_version: "4.9",
        release_feed: None,
        docs: &["https://chrony-project.org/doc/stable/chrony.conf.html"],
    },
    services: SERVICES,
    checks: CHECKS,
    commit_confirm: false,
    security_notes: &[MessageId::new("chrony-note-precedence")],
};

// ------------------------------------------------------------------ schema hints

/// UI hints for `settings`.
///
/// Appendix A requires `x-detent` hints on **every** field, and the test below
/// asserts every pointer resolves. `group` decides Basic vs Advanced in the UI,
/// `security_impact` drives the warning styling, `since` / `deprecated_in`
/// hide or flag options against the version detected in [`HostProfile`], and
/// `recommendation` is the Fluent id of the callout shown when the current
/// value is worse than the recommended one.
static SETTINGS_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("chrony-tip-settings"),
    recommendation: None,
    security_impact: SecurityImpact::Low,
    since: Some("4.9"),
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `settings[].key`.
static KEY_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("chrony-tip-key"),
    recommendation: None,
    security_impact: SecurityImpact::None,
    since: Some("4.9"),
    deprecated_in: None,
    requires_restart: false,
};

/// UI hints for `settings[].value`.
static VALUE_HINTS: FieldHints = FieldHints {
    group: UiGroup::Basic,
    tooltip: MessageId::new("chrony-tip-value"),
    recommendation: Some(MessageId::new("chrony-rec-value")),
    security_impact: SecurityImpact::High,
    since: Some("4.9"),
    deprecated_in: None,
    requires_restart: false,
};

/// Attaches the `x-detent` UI hints to the bare `schemars` schema of [`Model`].
///
/// Used by [`ConfigModule::schema`](detent_core::module::ConfigModule::schema),
/// so both `ChronyModule::schema()` and, through `Dyn`,
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
const PRIVILEGED_DIRECTIVE: MessageId = MessageId::new("chrony-privileged-directive");
const INVALID_KEY: MessageId = MessageId::new("chrony-invalid-key");
/// Fluent id: the same key is set twice.
const DUPLICATE_KEY: MessageId = MessageId::new("chrony-duplicate-key");
/// Fluent id: the file has grown past the point where drop-ins are better.
const TOO_MANY_SETTINGS: MessageId = MessageId::new("chrony-too-many-settings");
/// Fluent id: `allow 0.0.0.0/0` serves time to the whole internet.
const ALLOW_OPEN: MessageId = MessageId::new("chrony-allow-open");
/// Fluent id: `makestep` is missing.
const MISSING_MAKESTEP: MessageId = MessageId::new("chrony-missing-makestep");
/// Fluent id: `rtcsync` is missing.
const MISSING_RTCSYNC: MessageId = MessageId::new("chrony-missing-rtcsync");
/// Fluent id: a pool is used without the `nts` option.
const REC_NTS: MessageId = MessageId::new("chrony-rec-nts");
/// Fluent id: `cmdport` is left enabled.
const CMDPORT_OPEN: MessageId = MessageId::new("chrony-cmdport-open");
/// Fluent id: a directive loads external files or runs an external program.
const EXTERNAL_DIRECTIVE: MessageId = MessageId::new("chrony-external-directive");

/// Above this many settings, `validate` recommends drop-in files instead.
const SETTING_COUNT_ADVICE_THRESHOLD: usize = 100;

/// Whether `key` is a valid directive name.
///
/// chrony.conf(5): directive names are case-insensitive, and every one upstream
/// ships is a run of ASCII letters and digits (`makestep`, `maxupdateskew`,
/// `rtcsync`, …) with no separators. A key outside that shape is a typo or a
/// foreign fragment, and chronyd would refuse the file — reject it here so the
/// admin sees the error before the [`ExternalCheck`] does.
fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphabetic())
        && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether the model sets `key` (case-insensitive, chrony is).
fn has_key(model: &Model, key: &str) -> bool {
    model
        .settings
        .iter()
        .any(|item| item.key.eq_ignore_ascii_case(key))
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

/// The `chrony.conf` config module.
pub struct ChronyModule;

impl ConfigModule for ChronyModule {
    /// The stable id. It appears in URLs, the CLI, the audit log, the
    /// `module-chrony` feature name, the Fluent id prefix, `fixtures/chrony/`
    /// and the fuzz target names, so it is effectively public API. Lowercase,
    /// no spaces.
    const ID: &'static str = "chrony";
    /// `detent_core::doc::Document` is the shared line-oriented CST and fits
    /// every line-based format. A format with a richer grammar (INI, YAML,
    /// JSON) defines its own CST type in this crate and implements
    /// `detent_core::module::LosslessDoc` for it — reusing `Span` and
    /// `Diagnostic`, but not `Document` (ADR-008).
    type Doc = Document;
    type Model = Model;

    fn descriptor() -> &'static ModuleDescriptor {
        &DESCRIPTOR
    }

    /// `parse` is total for line-oriented formats — it returns `Ok` for every
    /// `&str`, including empty input, lone `\r`, and embedded NUL. Only a
    /// module over a stricter grammar returns `ParseError`, and even then it
    /// must never panic: invariant 6 runs it over 1 MiB of adversarial bytes.
    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    /// Project only what the model can express, and drop nothing else —
    /// `Unknown` and `Comment` lines stay in the `Doc` and are what makes
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

    /// This two-pass shape is the minimal-edit pattern.
    ///
    /// * Pass 1 is read-only. Rendering every changed line **before** touching
    ///   the document means a rejected value (invariant 5) leaves the file
    ///   exactly as it was — a half-applied config is worse than a refused one.
    /// * A line whose parsed setting already equals the model's is not rendered
    ///   at all, so hand-aligned columns and unusual spacing survive. That is
    ///   what makes invariant 2 (`apply(doc, to_model(doc))` changes nothing,
    ///   and reports `EditReport::default()`) hold.
    /// * Pass 2 only ever touches `Directive` lines: comments, blanks and
    ///   unknown directives keep their position.
    /// * Settings are aligned with the model ([`Document::edit_entries`]), so
    ///   dropping or adding one never rewrites or moves another, and the whole
    ///   edit is one pass over the file. A new setting goes directly after the
    ///   one before it, so a trailing comment block stays trailing.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        doc.edit_entries(&model.settings, parse_setting, render_line, |_| false)
    }

    /// A module needs at least one of each severity, and every finding carries a
    /// Fluent id — never a rendered sentence, this crate does not localize
    /// (ADR-003). Attach a [`FieldPath`] whenever the finding is about one field
    /// so the UI can point at the control, and pass every value that appears in
    /// the message as a named argument, so translators can reorder them.
    ///
    /// * [`Severity::Error`] — the config is invalid and must not be applied.
    /// * [`Severity::Warning`] — valid, but likely not what the admin meant.
    /// * [`Severity::Recommendation`] — fine, but a better option exists.
    ///
    /// `ctx` carries the [`HostProfile`]; chrony's own rules are host-agnostic,
    /// so nothing here branches on it.
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
            if ["include", "includedir", "confdir", "sourcedir", "script"]
                .iter()
                .any(|key| item.key.eq_ignore_ascii_case(key))
            {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, EXTERNAL_DIRECTIVE)
                        .with_field(FieldPath::new(format!("settings/{index}/key")))
                        .with_arg("key", item.key.clone()),
                );
            }
            if ["pidfile", "user"]
                .iter()
                .any(|key| item.key.eq_ignore_ascii_case(key))
            {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, PRIVILEGED_DIRECTIVE)
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
            if item.key.eq_ignore_ascii_case("allow")
                && matches!(item.value.as_str(), "0.0.0.0/0" | "::/0")
            {
                diagnostics.push(
                    Diagnostic::new(Severity::Warning, ALLOW_OPEN)
                        .with_field(FieldPath::new(format!("settings/{index}/value")))
                        .with_arg("value", item.value.clone()),
                );
            }
            if item.key.eq_ignore_ascii_case("pool")
                && !item
                    .value
                    .split_whitespace()
                    .any(|word| word.eq_ignore_ascii_case("nts"))
            {
                let pool = item.value.split_whitespace().next().unwrap_or("");
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, REC_NTS)
                        .with_field(FieldPath::new(format!("settings/{index}/value")))
                        .with_arg("pool", pool.to_owned()),
                );
            }
            if item.key.eq_ignore_ascii_case("cmdport")
                && item
                    .value
                    .split_whitespace()
                    .next()
                    .and_then(|port| port.parse::<u16>().ok())
                    .is_some_and(|port| port != 0)
            {
                let port = item.value.split_whitespace().next().unwrap_or("");
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, CMDPORT_OPEN)
                        .with_field(FieldPath::new(format!("settings/{index}/value")))
                        .with_arg("port", port.to_owned()),
                );
            }
        }
        for (key, id) in [("makestep", MISSING_MAKESTEP), ("rtcsync", MISSING_RTCSYNC)] {
            if !has_key(model, key) {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, id)
                        .with_field(FieldPath::new("settings")),
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

    /// "Smart, secure defaults for this host" (PLAN §2.3), not an empty model
    /// and not upstream's shipped file: an NTS-capable pool, a short makestep
    /// window, kernel RTC sync, and the command port disabled. chrony.conf has
    /// no per-OS directives, so every branch returns the same model — the match
    /// stays exhaustive so a new platform tier is a compile error here instead
    /// of a silently wrong file (ADR-013). Whatever this returns must pass
    /// `validate` with no errors; the test below asserts exactly that.
    fn defaults(profile: &HostProfile) -> Self::Model {
        let settings = match profile.os {
            // chrony.conf has no per-OS directives, so every branch shares one
            // model; the match stays exhaustive over `Os` without a `_` arm so
            // a new platform tier is a compile error here (ADR-013).
            Os::Linux | Os::MacOs | Os::Other => default_settings(),
        };
        Model { settings }
    }

    /// A module with no `x-detent` hints can drop this override and rely on the
    /// trait's default (the bare `schemars` schema).
    fn schema() -> serde_json::Value {
        schema_with_hints()
    }
}

/// The default settings, shared by every OS branch of [`ChronyModule::defaults`].
fn default_settings() -> Vec<Setting> {
    vec![
        setting("pool", "time.cloudflare.com iburst nts"),
        setting("makestep", "1 3"),
        setting("rtcsync", ""),
        setting("cmdport", "0"),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOW_OPEN, CMDPORT_OPEN, ChronyModule, DESCRIPTOR, DUPLICATE_KEY, EXTERNAL_DIRECTIVE,
        INVALID_KEY, MISSING_MAKESTEP, MISSING_RTCSYNC, Model, PRIVILEGED_DIRECTIVE, REC_NTS,
        Setting, TOO_MANY_SETTINGS, classify, is_bare_directive, is_valid_key, parse_setting,
        render_line, schema_with_hints, setting,
    };
    use detent_core::descriptor::{HostProfile, InitSystem, Os, ValidationCtx};
    use detent_core::diag::{MessageId, Severity};
    use detent_core::doc::LineKind;
    use detent_core::module::{ConfigModule, EditError, EditReport};

    /// `locales/en-US/core.ftl` is the source of truth for every user-facing
    /// string (PLAN §4.3). This test is what keeps a raw id from reaching the
    /// UI: list every `MessageId` this crate constructs — display name,
    /// security notes, tooltips, recommendations and diagnostics — and add the
    /// matching lines to `core.ftl`.
    const CORE_FTL: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// Keeps `upstream.toml` and the descriptor from drifting. `upstream-watch`
    /// reads the TOML; the UI reads the descriptor.
    const UPSTREAM_TOML: &str = include_str!("../upstream.toml");

    #[test]
    fn every_message_id_has_a_locale_entry() {
        for id in [
            "chrony-name",
            "chrony-note-precedence",
            "chrony-tip-settings",
            "chrony-tip-key",
            "chrony-tip-value",
            "chrony-rec-value",
            "chrony-rec-nts",
            "chrony-invalid-key",
            "chrony-duplicate-key",
            "chrony-too-many-settings",
            "chrony-allow-open",
            "chrony-missing-makestep",
            "chrony-missing-rtcsync",
            "chrony-cmdport-open",
            "chrony-external-directive",
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
        assert_eq!(upstream.release_feed, None);
        assert!(UPSTREAM_TOML.contains("release_feed = \"\""));
        assert!(UPSTREAM_TOML.contains("[fixtures]"));
        assert!(UPSTREAM_TOML.contains("dirs = [\"chrony-4.9\", \"edge\"]"));
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
        ChronyModule::validate(model, &ctx)
            .iter()
            .any(|d| d.id.as_str() == id.as_str() && d.severity == severity)
    }

    // --------------------------------------------------------------- parse_setting

    #[test]
    fn parse_setting_reads_a_key_and_a_value() {
        assert_eq!(
            parse_setting("  makestep   1 3  "),
            Some(setting("makestep", "1 3"))
        );
        assert_eq!(
            parse_setting("pool a.b  c\td"),
            Some(setting("pool", "a.b  c\td"))
        );
        assert_eq!(parse_setting("rtcsync"), Some(setting("rtcsync", "")));
        assert_eq!(parse_setting("  rtcsync  "), Some(setting("rtcsync", "")));
    }

    #[test]
    fn parse_setting_rejects_non_settings() {
        for line in [
            "",
            "   ",
            "# comment",
            "! comment",
            "; comment",
            "% comment",
            "lonely",
            "lonely   ",
            "#tag 5",
        ] {
            assert_eq!(parse_setting(line), None, "expected {line:?} to be refused");
        }
    }

    #[test]
    fn is_bare_directive_is_case_insensitive() {
        for bare in [
            "rtcsync",
            "RTCSync",
            "manual",
            "noclientlog",
            "nosystemcert",
            "rtconutc",
        ] {
            assert!(is_bare_directive(bare));
        }
        assert!(!is_bare_directive("makestep"));
        assert!(!is_bare_directive("garbage"));
        assert!(!is_bare_directive(""));
    }

    // -------------------------------------------------------------------- classify

    #[test]
    fn classify_assigns_the_four_buckets() {
        assert_eq!(classify(""), LineKind::Blank);
        assert_eq!(classify("  # indented"), LineKind::Comment);
        assert_eq!(classify("; chrony accepts this"), LineKind::Comment);
        assert_eq!(classify("%! too"), LineKind::Comment);
        assert_eq!(classify("makestep 1 3"), LineKind::Directive);
        assert_eq!(classify("rtcsync"), LineKind::Directive);
        assert_eq!(classify("lonely"), LineKind::Unknown);
    }

    // ----------------------------------------------------------------- render_line

    #[test]
    fn render_line_emits_a_single_space() {
        assert_eq!(
            render_line(&setting("makestep", "1 3")),
            Ok("makestep 1 3".to_owned())
        );
        assert_eq!(
            render_line(&setting("rtcsync", "")),
            Ok("rtcsync".to_owned())
        );
    }

    #[test]
    fn render_line_rejects_a_line_break_in_a_value() {
        assert_eq!(
            render_line(&setting("makestep", "a\nb")),
            Err(EditError::LineBreakInValue {
                value: "makestep a\nb".to_owned()
            })
        );
    }

    #[test]
    fn render_line_rejects_values_that_would_not_round_trip() {
        for bad in [
            setting("makestep", ""),
            setting("has space", "v"),
            setting("#makestep", "v"),
            setting("makestep", " padded"),
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
        let src = "# comment\n\nmakestep 1 3\nlonely\nrtcsync\n";
        let doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = ChronyModule::to_model(&doc).map_err(|e| e.to_string())?;
        assert_eq!(
            model.settings,
            vec![setting("makestep", "1 3"), setting("rtcsync", "")]
        );
        assert_eq!(ChronyModule::render(&doc), src);
        Ok(())
    }

    // ---------------------------------------------------------------------- apply

    #[test]
    fn apply_keeps_untouched_lines_byte_identical() -> Result<(), String> {
        let src = "# comment\nmakestep     1 3\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = ChronyModule::to_model(&doc).map_err(|e| e.to_string())?;
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report, EditReport::default());
        assert_eq!(ChronyModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn apply_rewrites_only_the_changed_setting() -> Result<(), String> {
        let src = "makestep 1 3\nrtcsync\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("makestep", "0 0"), setting("rtcsync", "")],
        };
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.changed_lines, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(ChronyModule::render(&doc), "makestep 0 0\nrtcsync\n");
        Ok(())
    }

    #[test]
    fn apply_removes_dropped_settings() -> Result<(), String> {
        let src = "makestep 1 3\nrtcsync\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("makestep", "1 3")],
        };
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.removed, 1);
        assert_eq!(ChronyModule::render(&doc), "makestep 1 3\n");
        Ok(())
    }

    #[test]
    fn apply_appends_after_the_last_directive_line() -> Result<(), String> {
        let src = "makestep 1 3\n# trailing comment\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = ChronyModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.settings.push(setting("rtcsync", ""));
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            ChronyModule::render(&doc),
            "makestep 1 3\nrtcsync\n# trailing comment\n"
        );
        Ok(())
    }

    #[test]
    fn apply_appends_at_the_end_when_there_are_no_directive_lines() -> Result<(), String> {
        let src = "# only a comment\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("makestep", "1 3")],
        };
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(report.added, 1);
        assert_eq!(
            ChronyModule::render(&doc),
            "# only a comment\nmakestep 1 3\n"
        );
        Ok(())
    }

    #[test]
    fn apply_rejects_an_injected_value_leaving_the_document_untouched() -> Result<(), String> {
        let src = "makestep 1 3\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let model = Model {
            settings: vec![setting("makestep", "a\nb")],
        };
        assert!(ChronyModule::apply(&mut doc, &model).is_err());
        assert_eq!(ChronyModule::render(&doc), src);
        Ok(())
    }

    #[test]
    fn deleting_the_first_entry_rewrites_no_other_line() -> Result<(), String> {
        let src = "server a.example iburst\nmakestep     1 3\n# note\nrtcsync\n";
        let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
        let mut model = ChronyModule::to_model(&doc).map_err(|e| e.to_string())?;
        model.settings.remove(0);
        let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
        assert_eq!(
            report,
            EditReport {
                changed_lines: 0,
                added: 0,
                removed: 1,
            }
        );
        assert_eq!(
            ChronyModule::render(&doc),
            "makestep     1 3\n# note\nrtcsync\n"
        );
        Ok(())
    }

    /// The fastest of three runs of `apply` with an empty model on a file of
    /// `lines` settings. Checks that every line goes.
    fn time_empty_apply(lines: usize) -> Result<std::time::Duration, String> {
        let src = "server ntp.example iburst\n".repeat(lines);
        let mut fastest = std::time::Duration::MAX;
        for _ in 0..3 {
            let mut doc = ChronyModule::parse(&src).map_err(|e| e.to_string())?;
            let started = std::time::Instant::now();
            let report =
                ChronyModule::apply(&mut doc, &Model::default()).map_err(|e| e.to_string())?;
            fastest = fastest.min(started.elapsed());
            assert_eq!(report.removed, lines);
            assert_eq!(ChronyModule::render(&doc), "");
        }
        Ok(fastest)
    }

    #[test]
    fn apply_is_linear_in_file_size() -> Result<(), String> {
        // M21: ten times the lines must cost far less than a hundred times the
        // time. Linear work gives a ratio near 10, quadratic work near 100. A
        // ratio, not an absolute bound, so a slow or loaded runner still passes.
        let small = time_empty_apply(5_000)?;
        let large = time_empty_apply(50_000)?;
        assert!(
            large < small.saturating_mul(30),
            "5k lines took {small:?}, 50k lines took {large:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------- validate

    #[test]
    fn is_valid_key_follows_the_documented_rule() {
        assert!(is_valid_key("makestep"));
        assert!(is_valid_key("rtcsync"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("2fast"));
        assert!(!is_valid_key("makestep!"));
        assert!(!is_valid_key("max-updateskew"));
    }

    #[test]
    fn validate_flags_an_invalid_key() {
        let model = Model {
            settings: vec![setting("2fast", "v")],
        };
        assert!(has(&model, INVALID_KEY, Severity::Error));
    }

    #[test]
    fn validate_rejects_external_file_and_script_directives() {
        for key in ["include", "includedir", "confdir", "sourcedir", "script"] {
            let model = Model {
                settings: vec![setting(key, "/tmp/untrusted")],
            };
            assert!(has(&model, EXTERNAL_DIRECTIVE, Severity::Error), "{key}");
        }
    }

    /// `pidfile` names a file chronyd writes as root and `user` picks the
    /// account it runs as: both are flagged for review at plan time.
    #[test]
    fn validate_warns_on_include_directive() {
        for key in ["pidfile", "PidFile", "user"] {
            let model = Model {
                settings: vec![setting(key, "/tmp/x")],
            };
            assert!(
                has(&model, PRIVILEGED_DIRECTIVE, Severity::Warning),
                "{key}"
            );
        }
        let model = Model {
            settings: vec![setting("makestep", "1 3")],
        };
        assert!(!has(&model, PRIVILEGED_DIRECTIVE, Severity::Warning));
    }

    #[test]
    fn validate_flags_a_duplicate_key_case_insensitively() {
        let model = Model {
            settings: vec![setting("Makestep", "1 3"), setting("makestep", "0 0")],
        };
        assert!(has(&model, DUPLICATE_KEY, Severity::Warning));
    }

    #[test]
    fn validate_flags_an_open_allow() {
        for value in ["0.0.0.0/0", "::/0"] {
            let model = Model {
                settings: vec![setting("allow", value)],
            };
            assert!(has(&model, ALLOW_OPEN, Severity::Warning), "allow {value}");
        }
        let scoped = Model {
            settings: vec![setting("allow", "192.168.0.0/16")],
        };
        assert!(!has(&scoped, ALLOW_OPEN, Severity::Warning));
    }

    #[test]
    fn validate_recommends_nts_on_a_plain_pool() {
        let model = Model {
            settings: vec![setting("pool", "2.pool.ntp.org iburst")],
        };
        assert!(has(&model, REC_NTS, Severity::Recommendation));
        let nts = Model {
            settings: vec![setting("pool", "time.cloudflare.com iburst nts")],
        };
        assert!(!has(&nts, REC_NTS, Severity::Recommendation));
    }

    #[test]
    fn validate_recommends_makestep_and_rtcsync_when_missing() {
        assert!(has(
            &Model { settings: vec![] },
            MISSING_MAKESTEP,
            Severity::Recommendation
        ));
        assert!(has(
            &Model { settings: vec![] },
            MISSING_RTCSYNC,
            Severity::Recommendation
        ));
        let full = Model {
            settings: vec![setting("makestep", "1 3"), setting("rtcsync", "")],
        };
        assert!(!has(&full, MISSING_MAKESTEP, Severity::Recommendation));
        assert!(!has(&full, MISSING_RTCSYNC, Severity::Recommendation));
    }

    #[test]
    fn validate_recommends_disabling_a_nonzero_cmdport() {
        let open = Model {
            settings: vec![setting("cmdport", "323")],
        };
        assert!(has(&open, CMDPORT_OPEN, Severity::Recommendation));
        let closed = Model {
            settings: vec![setting("cmdport", "0")],
        };
        assert!(!has(&closed, CMDPORT_OPEN, Severity::Recommendation));
    }

    #[test]
    fn validate_accepts_distinct_valid_keys() {
        let model = Model {
            settings: vec![setting("makestep", "1 3"), setting("rtcsync", "")],
        };
        assert!(!has(&model, INVALID_KEY, Severity::Error));
        assert!(!has(&model, DUPLICATE_KEY, Severity::Warning));
        assert!(!has(&model, TOO_MANY_SETTINGS, Severity::Recommendation));
    }

    #[test]
    fn validate_recommends_drop_ins_past_the_threshold() {
        let settings = (0..=100)
            .map(|i| setting(&format!("key{i}"), "v"))
            .collect();
        let model = Model { settings };
        assert!(has(&model, TOO_MANY_SETTINGS, Severity::Recommendation));
    }

    // ------------------------------------------------------------------- defaults

    #[test]
    fn defaults_branch_on_the_operating_system() {
        let linux = ChronyModule::defaults(&profile(Os::Linux, ""));
        for os in [Os::MacOs, Os::Other] {
            assert_eq!(ChronyModule::defaults(&profile(os, "")), linux);
        }
        assert_eq!(
            linux.settings,
            vec![
                setting("pool", "time.cloudflare.com iburst nts"),
                setting("makestep", "1 3"),
                setting("rtcsync", ""),
                setting("cmdport", "0"),
            ]
        );
    }

    #[test]
    fn defaults_are_valid_and_apply_to_an_empty_file() -> Result<(), String> {
        for os in [Os::Linux, Os::MacOs, Os::Other] {
            let host = profile(os, "node1");
            let ctx = ValidationCtx::new(&host);
            let model = ChronyModule::defaults(&host);
            assert!(!ChronyModule::validate(&model, &ctx).has_errors());
            let mut doc = ChronyModule::parse("").map_err(|e| e.to_string())?;
            let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report.added, model.settings.len());
            let rendered = ChronyModule::render(&doc);
            assert_eq!(
                rendered,
                "pool time.cloudflare.com iburst nts\nmakestep 1 3\nrtcsync\ncmdport 0\n"
            );
            let back =
                ChronyModule::to_model(&ChronyModule::parse(&rendered).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            assert_eq!(back, model);
        }
        Ok(())
    }

    // ----------------------------------------------------------------- descriptor

    #[test]
    fn descriptor_declares_its_targets_and_backend() {
        let descriptor = ChronyModule::descriptor();
        assert_eq!(descriptor.id, ChronyModule::ID);
        assert_eq!(descriptor.targets.len(), 3);
        for target in descriptor.targets {
            assert!((target.backend_detect)(&profile(Os::Linux, "h")));
            assert!(!(target.backend_detect)(&profile(Os::MacOs, "h")));
        }
        assert_eq!(descriptor.checks.len(), 1);
        assert!(!descriptor.commit_confirm);
    }

    // --------------------------------------------------------------------- schema

    #[test]
    fn schema_with_hints_attaches_every_hint() {
        let schema = schema_with_hints();
        assert_eq!(schema, ChronyModule::schema());
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

    /// Exercises the derived impls the module's own logic never calls. Coverage
    /// is 100 % lines for `crates/modules/` (PLAN §6.2), and a derive with no
    /// caller is the usual reason a module misses it.
    #[test]
    fn model_supports_debug_clone_default_and_serde() {
        let model = Model {
            settings: vec![setting("makestep", "1 3")],
        };
        assert_eq!(model.clone(), model);
        assert!(format!("{model:?}").contains("makestep"));
        assert_eq!(Model::default(), Model { settings: vec![] });
        let json = serde_json::to_value(&model).unwrap_or_default();
        assert_eq!(serde_json::from_value::<Model>(json).ok(), Some(model));
        assert!(serde_json::from_str::<Setting>(r#"{"key":"k","value":"v","x":1}"#).is_err());
    }

    // ------------------------------------------------------------- adversarial

    /// Keep an adversarial block. These are the shapes that broke real parsers:
    /// no trailing newline, CRLF, NUL, one very long line, and a file large
    /// enough that a super-linear `apply` shows up as a timeout.
    #[test]
    fn adversarial_inputs_round_trip() -> Result<(), String> {
        use std::fmt::Write as _;
        let long_line = format!("{}\n", "x".repeat(1024 * 1024));
        let mut many = String::new();
        for i in 0..10_000u32 {
            let _ = writeln!(many, "key{i} v");
        }
        for src in [
            "makestep 1 3",
            "makestep 1 3\r\nrtcsync\r\n",
            "\0\n",
            "\r\n",
            long_line.as_str(),
            many.as_str(),
        ] {
            let mut doc = ChronyModule::parse(src).map_err(|e| e.to_string())?;
            assert_eq!(ChronyModule::render(&doc), src);
            let model = ChronyModule::to_model(&doc).map_err(|e| e.to_string())?;
            let report = ChronyModule::apply(&mut doc, &model).map_err(|e| e.to_string())?;
            assert_eq!(report, EditReport::default());
            assert_eq!(ChronyModule::render(&doc), src);
        }
        Ok(())
    }

    // --------------------------------------------------------------------- fuzzing

    /// The derived `Arbitrary` generates arbitrary `String`s, so most generated
    /// models are refused by `render_line` and the `fuzz_chrony_edit` target
    /// spends its budget on the rejection path. If that shows up as poor
    /// coverage in a fuzz run, hand-write `Arbitrary` to emit format-shaped
    /// values instead — `hosts` does exactly that for its RFC 1123 hostnames.
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
