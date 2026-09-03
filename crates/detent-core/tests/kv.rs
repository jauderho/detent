//! End-to-end exercise of the module SDK.
//!
//! `KvModule` is a complete, correct `key=value` module: it is what the
//! `module_conformance!` macro is run against, so the macro itself is covered.
//! `BadModule` is a deliberately broken module used to prove that each conformance
//! check actually rejects the violation it claims to detect — without it the harness
//! could pass vacuously.

use detent_core::conformance::{
    Exercised, check_apply_is_noop, check_bounded_parse, check_edit_fidelity, check_idempotent,
    check_injection_rejected, check_not_vacuous, check_render_parse_roundtrip,
};
use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, InitSystem, ModuleDescriptor, Os,
    Owner, PathSpec, ServiceAction, ServiceBinding, Target, TargetKind, UnitNames, Upstream,
    ValidationCtx,
};
use detent_core::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use detent_core::doc::{Document, LineKind};
use detent_core::module::{
    ConfigModule, Dyn, DynModule, EditError, EditReport, LosslessDoc, ModelError, ParseError,
};
use proptest::prelude::Strategy;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------- the good module

/// `key=value`, one per line, `#` comments, everything else preserved verbatim.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KvModel {
    /// The directives, keyed by name.
    pub pairs: BTreeMap<String, String>,
}

/// A `key=value` config module.
pub struct KvModule;

fn classify(raw: &str) -> LineKind {
    if raw.trim().is_empty() {
        LineKind::Blank
    } else if raw.starts_with('#') {
        LineKind::Comment
    } else if raw.contains('=') {
        LineKind::Directive
    } else {
        LineKind::Unknown
    }
}

fn key_of(raw: &str) -> &str {
    raw.split_once('=').map_or(raw, |(key, _)| key)
}

static KV_TARGETS: &[Target] = &[Target {
    path: PathSpec::new("/etc/kv.conf"),
    kind: TargetKind::File,
    mode: 0o644,
    owner: Owner::Root,
    backend_detect: kv_backend_detect,
}];

fn kv_backend_detect(profile: &HostProfile) -> bool {
    profile.os != Os::Other
}

static KV_DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    id: "kv",
    display_name_id: MessageId::new("kv-name"),
    targets: KV_TARGETS,
    upstream: Upstream {
        project: "kv",
        repo_url: "https://example.invalid/kv",
        tracked_version: "1.0",
        release_feed: None,
        docs: &["https://example.invalid/kv/docs"],
    },
    services: &[ServiceBinding {
        units: UnitNames {
            systemd: &["kv.service"],
            openrc: &["kv"],
            bsdrc: &["kv"],
        },
        actions: &[ServiceAction::Reload],
    }],
    checks: &[ExternalCheck {
        program: PathSpec::new("/usr/bin/true"),
        args: &[ArgTemplate::Literal("--check"), ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    }],
    commit_confirm: false,
    security_notes: &[MessageId::new("kv-note")],
};

impl ConfigModule for KvModule {
    const ID: &'static str = "kv";
    type Doc = Document;
    type Model = KvModel;

    fn descriptor() -> &'static ModuleDescriptor {
        &KV_DESCRIPTOR
    }

    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        Ok(Document::parse(src, classify))
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        let mut pairs = BTreeMap::new();
        for line in doc.lines_of_kind(LineKind::Directive) {
            let (key, value) = line.raw().split_once('=').unwrap_or((line.raw(), ""));
            if pairs.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(ModelError::Unrepresentable {
                    message: format!("duplicate key {key:?}"),
                    span: Some(line.span()),
                });
            }
        }
        Ok(KvModel { pairs })
    }

    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError> {
        let mut report = EditReport::default();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut idx = 0usize;
        while let Some(line) = doc.lines().get(idx) {
            if line.kind() != LineKind::Directive {
                idx = idx.saturating_add(1);
                continue;
            }
            let key = key_of(line.raw()).to_owned();
            let Some(value) = model.pairs.get(&key).filter(|_| !seen.contains(&key)) else {
                doc.remove_line(idx)?;
                report.removed = report.removed.saturating_add(1);
                continue;
            };
            let desired = format!("{key}={value}");
            if line.raw() != desired {
                doc.replace_raw(idx, &desired)?;
                report.changed_lines = report.changed_lines.saturating_add(1);
            }
            seen.insert(key);
            idx = idx.saturating_add(1);
        }
        for (key, value) in &model.pairs {
            if !seen.contains(key) {
                doc.insert_line(doc.len(), &format!("{key}={value}"))?;
                report.added = report.added.saturating_add(1);
            }
        }
        Ok(report)
    }

    fn validate(model: &Self::Model, ctx: &ValidationCtx<'_>) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        for (index, (key, value)) in model.pairs.iter().enumerate() {
            if key.is_empty() || key.contains(['=', ' ', '#']) {
                diagnostics.push(
                    Diagnostic::new(Severity::Error, MessageId::new("kv-invalid-key"))
                        .with_field(FieldPath::new(format!("pairs/{index}")))
                        .with_arg("key", key.clone()),
                );
            }
            if value.is_empty() {
                diagnostics.push(
                    Diagnostic::new(Severity::Recommendation, MessageId::new("kv-empty-value"))
                        .with_field(FieldPath::new(format!("pairs/{index}"))),
                );
            }
        }
        if ctx.profile.ram_mib < 64 {
            diagnostics.push(Diagnostic::new(
                Severity::Warning,
                MessageId::new("kv-low-memory"),
            ));
        }
        diagnostics
    }

    fn defaults(profile: &HostProfile) -> Self::Model {
        let mut pairs = BTreeMap::new();
        pairs.insert("ram_mib".to_owned(), profile.ram_mib.to_string());
        if !profile.hostname.is_empty() {
            pairs.insert("hostname".to_owned(), profile.hostname.clone());
        }
        KvModel { pairs }
    }
}

// ------------------------------------------------------------ conformance harness

/// A fixture with duplicate keys: `to_model` cannot express it, which exercises the
/// "no model, nothing to apply" path of invariant 2.
const FIXTURE_DUPLICATES: &str = "# dup\nsame=1\nsame=2\n";
const FIXTURE_TYPICAL: &str =
    "# comment\r\n\r\nserver = a.example\r\nport=123\r\nnot a directive\r\n";
const FIXTURE_NO_TRAILING_NEWLINE: &str = "alpha=1\nbeta=2";

fn model_strategy() -> impl Strategy<Value = KvModel> {
    proptest::collection::btree_map("[a-z]{1,4}", "[a-z0-9 =]{0,5}", 0..4)
        .prop_map(|pairs| KvModel { pairs })
}

fn probe(value: &str) -> KvModel {
    KvModel {
        pairs: BTreeMap::from([("probe".to_owned(), value.to_owned())]),
    }
}

detent_core::module_conformance!(
    KvModule,
    fixtures = [
        FIXTURE_DUPLICATES,
        FIXTURE_TYPICAL,
        FIXTURE_NO_TRAILING_NEWLINE
    ],
    model_strategy = model_strategy(),
    injection_probes = [probe("a\nb"), probe("a\rb"), probe("a\0b")],
);

// -------------------------------------------------------------- the broken module

/// A document that can carry a "tainted" tag so a broken `apply` can be observed.
#[derive(Debug, PartialEq, Eq)]
pub struct BadDoc {
    text: String,
    tag: u32,
}

impl LosslessDoc for BadDoc {
    fn render(&self) -> String {
        let mut out = self.text.clone();
        if self.text.contains("!render") {
            out.push('x');
        }
        if self.text.contains("!rfail") {
            out.push_str("!parse");
        }
        out
    }
}

/// A module that violates whichever invariant its input text asks it to, selected by
/// a marker in the source. Markers are used only by these tests.
pub struct BadModule;

impl ConfigModule for BadModule {
    const ID: &'static str = "bad";
    type Doc = BadDoc;
    type Model = KvModel;

    fn descriptor() -> &'static ModuleDescriptor {
        &KV_DESCRIPTOR
    }

    fn parse(src: &str) -> Result<Self::Doc, ParseError> {
        if src.contains("!parse") {
            return Err(ParseError::Malformed {
                message: "marker".to_owned(),
                span: None,
            });
        }
        Ok(BadDoc {
            text: src.to_owned(),
            tag: 0,
        })
    }

    fn render(doc: &Self::Doc) -> String {
        doc.render()
    }

    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError> {
        if doc.text.contains("!model") || doc.tag == 1 {
            return Err(ModelError::Unrepresentable {
                message: "marker".to_owned(),
                span: None,
            });
        }
        Ok(KvModel::default())
    }

    fn apply(doc: &mut Self::Doc, _model: &Self::Model) -> Result<EditReport, EditError> {
        if doc.text.contains("!applyerr") {
            return Err(EditError::Unsupported {
                message: "marker".to_owned(),
            });
        }
        if doc.text.contains("!mutate") {
            doc.text.push('z');
        }
        if doc.text.contains("!aftermodel") {
            doc.tag = 1;
        }
        if doc.text.contains("!requal") {
            doc.tag = 7;
        }
        if doc.text.contains("!report") {
            return Ok(EditReport {
                changed_lines: 1,
                added: 0,
                removed: 0,
            });
        }
        Ok(EditReport::default())
    }

    fn validate(_model: &Self::Model, _ctx: &ValidationCtx<'_>) -> Diagnostics {
        Diagnostics::new()
    }

    /// Host-aware just enough to prove `check_not_vacuous` catches a module
    /// whose defaults do not read back: `apply`/`to_model` never see `profile`
    /// or a hostname marker, so a non-empty result here can never round-trip.
    fn defaults(profile: &HostProfile) -> Self::Model {
        let mut pairs = BTreeMap::new();
        if !profile.hostname.is_empty() {
            pairs.insert("hostname".to_owned(), profile.hostname.clone());
        }
        KvModel { pairs }
    }

    /// Overrides the default `schema()` to prove an override reaches
    /// `DynModule::schema_json` through `Dyn`, the way a real module attaches
    /// `x-detent` hints.
    fn schema() -> serde_json::Value {
        let mut schema = schemars::schema_for!(KvModel).to_value();
        if let Some(object) = schema.as_object_mut() {
            object.insert("x-detent-marker".to_owned(), serde_json::json!(true));
        }
        schema
    }
}

// ------------------------------------------------------------------------- tests

fn profile() -> HostProfile {
    HostProfile {
        os: Os::Linux,
        init: InitSystem::Systemd,
        hostname: "gps1".to_owned(),
        service_versions: BTreeMap::from([("kv".to_owned(), "1.0".to_owned())]),
        ram_mib: 1024,
    }
}

fn model(pairs: &[(&str, &str)]) -> KvModel {
    KvModel {
        pairs: pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

#[test]
fn to_model_reads_directives_and_rejects_duplicates() {
    let doc = KvModule::parse("# c\nport=123\n\nplain line\nserver = a\n")
        .unwrap_or_else(|_| Document::parse("", classify));
    assert_eq!(
        KvModule::to_model(&doc),
        Ok(model(&[("port", "123"), ("server ", " a")]))
    );

    let dup = Document::parse(FIXTURE_DUPLICATES, classify);
    assert!(matches!(
        KvModule::to_model(&dup),
        Err(ModelError::Unrepresentable { .. })
    ));

    let no_equals = Document::parse("", classify);
    assert_eq!(KvModule::to_model(&no_equals), Ok(KvModel::default()));
}

#[test]
fn apply_is_a_minimal_edit() {
    let mut doc = Document::parse("# keep\nalpha=1\nbeta=2\nplain\n", classify);
    let report = KvModule::apply(&mut doc, &model(&[("alpha", "9"), ("gamma", "3")]));
    assert_eq!(
        report,
        Ok(EditReport {
            changed_lines: 1,
            added: 1,
            removed: 1
        })
    );
    assert_eq!(KvModule::render(&doc), "# keep\nalpha=9\nplain\ngamma=3\n");
}

#[test]
fn apply_collapses_duplicate_directives() {
    let mut doc = Document::parse(FIXTURE_DUPLICATES, classify);
    assert_eq!(
        KvModule::apply(&mut doc, &model(&[("same", "7")])),
        Ok(EditReport {
            changed_lines: 1,
            added: 0,
            removed: 1
        })
    );
    assert_eq!(KvModule::render(&doc), "# dup\nsame=7\n");
    assert_eq!(KvModule::to_model(&doc), Ok(model(&[("same", "7")])));
}

#[test]
fn apply_rejects_injected_line_breaks() {
    let mut doc = Document::parse("probe=ok\n", classify);
    assert_eq!(
        KvModule::apply(&mut doc, &probe("a\nb")),
        Err(EditError::LineBreakInValue {
            value: "probe=a\nb".to_owned()
        })
    );
    let mut empty = Document::parse("", classify);
    assert_eq!(
        KvModule::apply(&mut empty, &probe("a\0b")),
        Err(EditError::LineBreakInValue {
            value: "probe=a\0b".to_owned()
        })
    );
}

#[test]
fn validate_reports_every_severity() {
    let host = profile();
    let ctx = ValidationCtx::new(&host);
    assert!(KvModule::validate(&model(&[("ok", "1")]), &ctx).is_empty());

    let bad = KvModule::validate(&model(&[("bad key", "1"), ("empty", "")]), &ctx);
    assert_eq!(bad.len(), 2);
    assert!(bad.has_errors());
    assert_eq!(
        bad.iter().next().map(|d| d.id.as_str()),
        Some("kv-invalid-key")
    );

    let small = HostProfile {
        ram_mib: 32,
        ..profile()
    };
    let low = KvModule::validate(&KvModel::default(), &ValidationCtx::new(&small));
    assert_eq!(low.len(), 1);
    assert!(!low.has_errors());
}

#[test]
fn defaults_depend_on_the_host() {
    assert_eq!(
        KvModule::defaults(&profile()),
        model(&[("ram_mib", "1024"), ("hostname", "gps1")])
    );
    assert_eq!(
        KvModule::defaults(&HostProfile::default()),
        model(&[("ram_mib", "0")])
    );
}

#[test]
fn descriptor_is_reachable_and_detects_the_backend() {
    assert_eq!(KvModule::descriptor().id, "kv");
    assert_eq!(BadModule::descriptor().id, "kv");
    let detect = KV_TARGETS.first().map(|t| t.backend_detect);
    assert_eq!(detect.map(|f| f(&profile())), Some(true));
    assert_eq!(detect.map(|f| f(&HostProfile::default())), Some(false));
}

#[test]
fn dyn_adapter_speaks_json() {
    let module: Box<dyn DynModule> = Box::new(Dyn::<KvModule>::new());
    assert_eq!(module.id(), "kv");
    assert_eq!(module.descriptor().id, "kv");
    assert!(module.schema_json().pointer("/properties/pairs").is_some());

    let parsed = module.parse_to_model_json("a=1\n# c\n");
    assert_eq!(parsed.ok(), Some(serde_json::json!({"pairs": {"a": "1"}})));

    let applied = module.apply_json("a=1\n", &serde_json::json!({"pairs": {"a": "2"}}));
    assert_eq!(applied.ok(), Some("a=2\n".to_owned()));

    let host = profile();
    let diagnostics = module.validate_json(
        &serde_json::json!({"pairs": {"a": ""}}),
        &ValidationCtx::new(&host),
    );
    assert_eq!(diagnostics.map(|d| d.len()).ok(), Some(1));

    assert_eq!(
        module.defaults_json(&HostProfile::default()).ok(),
        Some(serde_json::json!({"pairs": {"ram_mib": "0"}}))
    );
}

/// `ConfigModule::schema` is a provided method: a module that never overrides
/// it gets the bare `schemars` schema, and one that does (`BadModule`, here)
/// has the override reach callers through `Dyn`/`DynModule::schema_json`
/// exactly like every other trait method.
#[test]
fn schema_flows_through_dyn_default_and_override() {
    let default_module: Box<dyn DynModule> = Box::new(Dyn::<KvModule>::new());
    let bare = schemars::schema_for!(KvModel).to_value();
    assert_eq!(default_module.schema_json(), bare);
    assert_eq!(KvModule::schema(), bare);

    let overridden: Box<dyn DynModule> = Box::new(Dyn::<BadModule>::new());
    assert_eq!(
        overridden.schema_json().get("x-detent-marker"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(BadModule::schema(), overridden.schema_json());
    assert_ne!(overridden.schema_json(), default_module.schema_json());
}

#[test]
fn dyn_adapter_maps_every_failure_to_an_error() {
    let kv: Dyn<KvModule> = Dyn::default();
    let bad: Dyn<BadModule> = Dyn::new();

    let shape = kv.apply_json("a=1\n", &serde_json::json!({"unknown": 1}));
    assert_eq!(
        shape.err().map(|e| e.message_id().as_str()),
        Some("core-model-shape")
    );

    let shape = kv.validate_json(&serde_json::json!([]), &ValidationCtx::new(&profile()));
    assert_eq!(
        shape.err().map(|e| e.message_id().as_str()),
        Some("core-model-shape")
    );

    let injected = kv.apply_json("", &serde_json::json!({"pairs": {"probe": "a\nb"}}));
    let injected = injected.err();
    assert_eq!(
        injected.as_ref().map(|e| e.message_id().as_str()),
        Some("core-edit-line-break")
    );
    assert!(
        injected
            .map(|e| e.to_string())
            .unwrap_or_default()
            .contains("line break")
    );

    assert_eq!(
        bad.parse_to_model_json("!parse")
            .err()
            .map(|e| e.message_id().as_str()),
        Some("core-parse-malformed")
    );
    assert_eq!(
        bad.apply_json("!parse", &serde_json::json!({"pairs": {}}))
            .err()
            .map(|e| e.message_id().as_str()),
        Some("core-parse-malformed")
    );
    assert_eq!(
        bad.parse_to_model_json("!model")
            .err()
            .map(|e| e.message_id().as_str()),
        Some("core-model-unrepresentable")
    );
    assert!(bad.schema_json().pointer("/properties/pairs").is_some());
    assert_eq!(bad.id(), "bad");
    assert_eq!(bad.descriptor().id, "kv");
    assert_eq!(
        bad.defaults_json(&HostProfile::default()).ok(),
        Some(serde_json::json!({"pairs": {}}))
    );
    assert_eq!(
        bad.validate_json(
            &serde_json::json!({"pairs": {}}),
            &ValidationCtx::new(&profile())
        )
        .map(|d| d.len())
        .ok(),
        Some(0)
    );
}

/// Every conformance check must actually reject the violation it names; otherwise the
/// macro would pass vacuously for a broken module.
#[test]
fn conformance_checks_catch_violations() {
    let m = model(&[("a", "1")]);
    let empty = KvModel::default();

    // Invariant 1.
    assert!(check_render_parse_roundtrip::<BadModule>("!parse").is_err());
    assert!(check_render_parse_roundtrip::<BadModule>("!render").is_err());
    assert_eq!(check_render_parse_roundtrip::<BadModule>("plain"), Ok(()));

    // Invariant 2.
    assert!(check_apply_is_noop::<BadModule>("!parse").is_err());
    assert_eq!(
        check_apply_is_noop::<BadModule>("!model"),
        Ok(Exercised::No)
    );
    assert!(check_apply_is_noop::<BadModule>("!applyerr").is_err());
    assert!(check_apply_is_noop::<BadModule>("!mutate").is_err());
    assert!(check_apply_is_noop::<BadModule>("!report").is_err());
    assert_eq!(
        check_apply_is_noop::<BadModule>("plain"),
        Ok(Exercised::Yes)
    );

    // Invariant 3.
    assert!(check_edit_fidelity::<BadModule>("!parse", &m).is_err());
    assert_eq!(
        check_edit_fidelity::<BadModule>("!applyerr", &m),
        Ok(Exercised::No)
    );
    assert!(check_edit_fidelity::<BadModule>("!aftermodel", &empty).is_err());
    assert!(check_edit_fidelity::<BadModule>("plain", &m).is_err());
    assert_eq!(
        check_edit_fidelity::<BadModule>("plain", &empty),
        Ok(Exercised::Yes)
    );

    // Invariant 4.
    assert!(check_idempotent::<BadModule>("!parse", &empty).is_err());
    assert_eq!(
        check_idempotent::<BadModule>("!applyerr", &empty),
        Ok(Exercised::No)
    );
    assert!(check_idempotent::<BadModule>("!rfail", &empty).is_err());
    assert!(check_idempotent::<BadModule>("!requal", &empty).is_err());
    assert_eq!(
        check_idempotent::<BadModule>("plain", &empty),
        Ok(Exercised::Yes)
    );

    // Invariant 5.
    assert!(check_injection_rejected::<BadModule>("!parse", &probe("a\nb")).is_err());
    assert!(check_injection_rejected::<BadModule>("plain", &probe("a\nb")).is_err());
    assert_eq!(
        check_injection_rejected::<BadModule>("!applyerr", &probe("a\nb")),
        Ok(())
    );

    // Invariant 6 on a module that satisfies it.
    assert_eq!(check_bounded_parse::<KvModule>(7), Ok(()));
}

/// `check_not_vacuous` is what stops a module that refuses every edit from
/// passing the conformance suite by never actually exercising `apply`.
#[test]
fn check_not_vacuous_catches_a_module_that_refuses_every_edit() {
    let profile = HostProfile {
        os: Os::Linux,
        init: InitSystem::Systemd,
        hostname: "detent-test".to_owned(),
        service_versions: BTreeMap::new(),
        ram_mib: 1024,
    };

    // "plain" has a representable model (empty `KvModel`) and `apply` accepts
    // it, so the good module is not vacuous.
    assert_eq!(check_not_vacuous::<KvModule>(&["a=1\n"], &profile), Ok(()));

    // `BadModule::apply` refuses every input whose text contains `!applyerr`,
    // so a fixture built from that marker has a model but is never actually
    // applied — the vacuousness check must fail, not skip it.
    assert!(check_not_vacuous::<BadModule>(&["!applyerr"], &profile).is_err());

    // No fixture with a representable model at all is caught the same way.
    assert!(check_not_vacuous::<BadModule>(&["!model"], &profile).is_err());

    // The fixture loop is satisfied ("plain" has a model `apply` accepts), but
    // `BadModule::defaults` reports a hostname `apply`/`to_model` cannot
    // reproduce — a module whose defaults do not round-trip must fail too.
    assert!(check_not_vacuous::<BadModule>(&["plain"], &profile).is_err());
}
