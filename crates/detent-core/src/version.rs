//! Dotted numeric version comparison, for `since`-gated options.
//!
//! A version is a run of dot-separated decimal numbers at the start of the
//! text. Anything after that run is ignored, so `4.19.5-Debian` is `4.19.5`.
//! Text with no such run, an empty component (`4..9`) or a component that
//! overflows `u64` is not a version: every function here answers `None`
//! ("unknown") for it, never a guess.

use crate::descriptor::HostProfile;
use crate::diag::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
use serde_json::Value;
use std::cmp::Ordering;

/// Fluent id: an option needs a newer service than the one installed.
pub const VERSION_TOO_OLD: MessageId = MessageId::new("core-version-too-old");
/// Fluent id: the installed version is unknown, so the option may not work.
pub const VERSION_UNKNOWN: MessageId = MessageId::new("core-version-unknown");

/// The numeric components of `text`, or `None` when it is not a version.
fn components(text: &str) -> Option<Vec<u64>> {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let run = text.get(..end)?.trim_end_matches('.');
    run.split('.').map(|part| part.parse().ok()).collect()
}

/// Compares two versions numerically, component by component.
///
/// Missing trailing components count as `0`, so `4.9` equals `4.9.0` and
/// `4.10` is greater than `4.9`. `None` when either side is not a version.
#[must_use]
pub fn compare(left: &str, right: &str) -> Option<Ordering> {
    let left = components(left)?;
    let right = components(right)?;
    for index in 0..left.len().max(right.len()) {
        let l = left.get(index).copied().unwrap_or(0);
        let r = right.get(index).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            unequal => return Some(unequal),
        }
    }
    Some(Ordering::Equal)
}

/// Whether `installed` is at least `required`. `None` when either side is not
/// a version.
#[must_use]
pub fn at_least(installed: &str, required: &str) -> Option<bool> {
    compare(installed, required).map(Ordering::is_ge)
}

/// The finding for one option that needs `service` at `since` or later, or
/// `None` when the installed version is new enough.
///
/// A known version that is older is an error: the service would refuse the
/// file. A version that was not detected, or does not parse, is only a
/// warning: the option may be fine, and a host where detection failed must
/// not be blocked.
#[must_use]
pub fn since_diagnostic(
    profile: &HostProfile,
    service: &str,
    option: &str,
    since: &str,
    field: FieldPath,
) -> Option<Diagnostic> {
    let unknown = || {
        Diagnostic::new(Severity::Warning, VERSION_UNKNOWN)
            .with_field(field.clone())
            .with_arg("option", option)
            .with_arg("since", since)
            .with_arg("service", service)
    };
    let Some(installed) = profile.service_version(service) else {
        return Some(unknown());
    };
    match at_least(installed, since) {
        Some(true) => None,
        Some(false) => Some(
            Diagnostic::new(Severity::Error, VERSION_TOO_OLD)
                .with_field(field)
                .with_arg("option", option)
                .with_arg("since", since)
                .with_arg("service", service)
                .with_arg("installed", installed),
        ),
        None => Some(unknown()),
    }
}

/// The findings for every option set in `model` whose schema node carries an
/// `x-detent.since` newer than the installed `service`.
///
/// `schema` is the module's hinted schema. An option is "set" when its value is
/// present and not `null`; an empty array sets nothing. Each finding names the
/// option by its field path, such as `entries/0/key`.
#[must_use]
pub fn since_gate(
    schema: &Value,
    model: &Value,
    profile: &HostProfile,
    service: &str,
) -> Diagnostics {
    let mut found = Vec::new();
    collect(schema, schema, model, "", 0, &mut found);
    found
        .into_iter()
        .filter_map(|(path, since)| {
            since_diagnostic(profile, service, &path, since, FieldPath::new(&path))
        })
        .collect()
}

/// How far [`collect`] follows `$ref` and nesting. A cyclic schema stops here.
const MAX_SCHEMA_DEPTH: usize = 16;

/// Walks `schema` and `value` together and records `(field path, since)` for
/// every set value whose schema node has `x-detent.since`.
fn collect<'a>(
    root: &'a Value,
    schema: &'a Value,
    value: &Value,
    path: &str,
    depth: usize,
    found: &mut Vec<(String, &'a str)>,
) {
    let unset = value.is_null() || value.as_array().is_some_and(Vec::is_empty);
    if depth > MAX_SCHEMA_DEPTH || unset {
        return;
    }
    let next = depth.saturating_add(1);
    if let Some(since) = schema.pointer("/x-detent/since").and_then(Value::as_str) {
        let entry = (path.to_owned(), since);
        if !found.contains(&entry) {
            found.push(entry);
        }
    }
    if let Some(target) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix('#'))
        .and_then(|pointer| root.pointer(pointer))
    {
        collect(root, target, value, path, next, found);
    }
    for keyword in ["anyOf", "oneOf", "allOf"] {
        for branch in schema
            .get(keyword)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect(root, branch, value, path, next, found);
        }
    }
    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object(),
    ) {
        for (name, property) in properties {
            if let Some(child) = object.get(name) {
                collect(root, property, child, &join_path(path, name), next, found);
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for (index, child) in array.iter().enumerate() {
            collect(
                root,
                items,
                child,
                &join_path(path, &index.to_string()),
                next,
                found,
            );
        }
    }
}

fn join_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_owned()
    } else {
        format!("{base}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VERSION_TOO_OLD, VERSION_UNKNOWN, at_least, compare, since_diagnostic, since_gate,
    };
    use crate::descriptor::HostProfile;
    use crate::diag::{Diagnostic, FieldPath, MessageId, Severity};
    use serde_json::json;
    use std::cmp::Ordering;

    const CORE_FTL: &str = include_str!("../../../locales/en-US/core.ftl");

    fn host(versions: &[(&str, &str)]) -> HostProfile {
        HostProfile {
            service_versions: versions
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..HostProfile::default_for_tests()
        }
    }

    #[test]
    fn compares_numerically_not_textually() {
        assert_eq!(compare("4.10", "4.9"), Some(Ordering::Greater));
        assert_eq!(compare("4.9", "4.10"), Some(Ordering::Less));
        assert_eq!(compare("4.19.5", "4.24"), Some(Ordering::Less));
        assert_eq!(compare("10.0", "9.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn missing_trailing_components_are_zero() {
        assert_eq!(compare("4.9", "4.9.0"), Some(Ordering::Equal));
        assert_eq!(compare("4.9.0.0", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("4.9", "4.9.1"), Some(Ordering::Less));
        assert_eq!(compare("4", "4.0.0"), Some(Ordering::Equal));
    }

    #[test]
    fn leading_zeros_do_not_change_the_value() {
        assert_eq!(compare("4.09", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("04.9", "4.9"), Some(Ordering::Equal));
    }

    #[test]
    fn suffixes_after_the_numeric_run_are_ignored() {
        assert_eq!(compare("4.19.5-Debian", "4.19.5"), Some(Ordering::Equal));
        assert_eq!(compare("4.5+dfsg", "4.5"), Some(Ordering::Equal));
        assert_eq!(compare("4.9rc1", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("  4.9 ", "4.9"), Some(Ordering::Equal));
        assert_eq!(compare("4.9.", "4.9"), Some(Ordering::Equal));
    }

    #[test]
    fn text_without_a_leading_numeric_run_is_unknown() {
        for bad in ["", " ", "abc", "v4.9", "-4.9", ".9", "4..9", "Version 4.9"] {
            assert_eq!(compare(bad, "4.9"), None, "left {bad:?}");
            assert_eq!(compare("4.9", bad), None, "right {bad:?}");
            assert_eq!(at_least(bad, "4.9"), None, "at_least {bad:?}");
        }
    }

    #[test]
    fn a_component_that_overflows_is_unknown() {
        assert_eq!(compare("4.99999999999999999999999", "4.9"), None);
    }

    #[test]
    fn at_least_includes_equal() {
        assert_eq!(at_least("4.9", "4.9"), Some(true));
        assert_eq!(at_least("4.10", "4.9"), Some(true));
        assert_eq!(at_least("4.5", "4.9"), Some(false));
        assert_eq!(at_least("4.19.5-Debian", "4.24"), Some(false));
    }

    #[test]
    fn an_old_version_is_an_error_naming_everything() {
        let found = since_diagnostic(
            &host(&[("chrony", "4.5")]),
            "chrony",
            "ntsservercert",
            "4.9",
            FieldPath::new("settings/2/key"),
        );
        let expected = Diagnostic::new(Severity::Error, VERSION_TOO_OLD)
            .with_field(FieldPath::new("settings/2/key"))
            .with_arg("option", "ntsservercert")
            .with_arg("since", "4.9")
            .with_arg("service", "chrony")
            .with_arg("installed", "4.5");
        assert_eq!(found, Some(expected));
    }

    #[test]
    fn a_new_enough_version_is_fine() {
        for installed in ["4.9", "4.10", "5.0", "4.9.1"] {
            let found = since_diagnostic(
                &host(&[("chrony", installed)]),
                "chrony",
                "x",
                "4.9",
                FieldPath::new("x"),
            );
            assert_eq!(found, None, "{installed}");
        }
    }

    #[test]
    fn an_undetected_version_is_a_warning_not_an_error() {
        let found = since_diagnostic(
            &host(&[]),
            "chrony",
            "ntsservercert",
            "4.9",
            FieldPath::new("settings/2/key"),
        );
        let expected = Diagnostic::new(Severity::Warning, VERSION_UNKNOWN)
            .with_field(FieldPath::new("settings/2/key"))
            .with_arg("option", "ntsservercert")
            .with_arg("since", "4.9")
            .with_arg("service", "chrony");
        assert_eq!(found, Some(expected));
    }

    #[test]
    fn an_unparsable_version_is_a_warning_not_an_error() {
        let found = since_diagnostic(
            &host(&[("chrony", "garbled")]),
            "chrony",
            "x",
            "4.9",
            FieldPath::new("x"),
        );
        assert_eq!(
            found.map(|d| (d.severity, d.id)),
            Some((Severity::Warning, VERSION_UNKNOWN))
        );
    }

    #[test]
    fn a_version_of_another_service_does_not_count() {
        let found = since_diagnostic(
            &host(&[("samba", "4.30")]),
            "chrony",
            "x",
            "4.9",
            FieldPath::new("x"),
        );
        assert_eq!(found.map(|d| d.id), Some(VERSION_UNKNOWN));
    }

    fn gated_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "plain": { "type": "string" },
                "tls": { "type": ["string", "null"], "x-detent": { "since": "4.9" } },
                "entries": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/Entry" }
                },
                "opt": {
                    "anyOf": [{ "$ref": "#/$defs/Entry" }, { "type": "null" }],
                    "x-detent": { "since": "4.20" }
                },
                "loop": { "$ref": "#/$defs/Loop" }
            },
            "$defs": {
                "Entry": {
                    "type": "object",
                    "properties": {
                        "key": { "type": "string" },
                        "flag": { "type": "boolean", "x-detent": { "since": "5.0" } }
                    }
                },
                "Loop": {
                    "type": "object",
                    "properties": { "again": { "$ref": "#/$defs/Loop" } }
                }
            }
        })
    }

    fn fields(diags: &crate::diag::Diagnostics) -> Vec<(Severity, String)> {
        diags
            .iter()
            .map(|d| {
                (
                    d.severity,
                    d.field
                        .as_ref()
                        .map(|f| f.as_str().to_owned())
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn the_gate_reports_only_set_options_that_are_too_new() {
        let model = json!({
            "plain": "a",
            "tls": "on",
            "entries": [{ "key": "k", "flag": true }, { "key": "k2" }],
            "opt": null
        });
        let found = since_gate(&gated_schema(), &model, &host(&[("svc", "4.5")]), "svc");
        assert_eq!(
            fields(&found),
            vec![
                (Severity::Error, "entries/0/flag".to_owned()),
                (Severity::Error, "tls".to_owned()),
            ]
        );
        let last = found.iter().last().and_then(|d| d.args.get("option"));
        assert_eq!(last.map(String::as_str), Some("tls"));
    }

    #[test]
    fn the_gate_follows_refs_and_any_of() {
        let model = json!({ "opt": { "key": "k" } });
        let found = since_gate(&gated_schema(), &model, &host(&[("svc", "4.5")]), "svc");
        assert_eq!(fields(&found), vec![(Severity::Error, "opt".to_owned())]);
    }

    #[test]
    fn the_gate_is_silent_for_unset_options_and_new_enough_hosts() {
        let unset = json!({ "plain": "a", "tls": null, "entries": [] });
        assert!(since_gate(&gated_schema(), &unset, &host(&[("svc", "4.5")]), "svc").is_empty());
        let set = json!({ "tls": "on", "entries": [{ "flag": true }] });
        assert!(since_gate(&gated_schema(), &set, &host(&[("svc", "5.0")]), "svc").is_empty());
    }

    #[test]
    fn the_gate_warns_when_the_version_is_unknown() {
        let model = json!({ "tls": "on" });
        let found = since_gate(&gated_schema(), &model, &host(&[]), "svc");
        assert_eq!(fields(&found), vec![(Severity::Warning, "tls".to_owned())]);
    }

    #[test]
    fn the_gate_stops_on_a_ref_cycle() {
        let model = json!({ "loop": { "again": { "again": { "again": {} } } } });
        assert!(since_gate(&gated_schema(), &model, &host(&[]), "svc").is_empty());
    }

    #[test]
    fn the_gate_ignores_a_ref_it_cannot_resolve() {
        let schema =
            json!({ "properties": { "a": { "$ref": "https://x/y" }, "b": { "$ref": "#/nope" } } });
        let model = json!({ "a": 1, "b": 2 });
        assert!(since_gate(&schema, &model, &host(&[]), "svc").is_empty());
    }

    #[test]
    fn a_root_level_hint_is_reported_once_even_when_reachable_twice() {
        let schema = json!({
            "x-detent": { "since": "9.0" },
            "allOf": [{ "$ref": "#/$defs/A" }],
            "$defs": { "A": { "x-detent": { "since": "9.0" } } }
        });
        let found = since_gate(&schema, &json!({}), &host(&[("svc", "1.0")]), "svc");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn every_message_id_has_a_locale_entry() {
        let missing: Vec<&str> = [VERSION_TOO_OLD, VERSION_UNKNOWN]
            .into_iter()
            .filter(|id| !CORE_FTL.contains(&format!("\n{} =", id.as_str())))
            .map(MessageId::as_str)
            .collect();
        assert_eq!(missing, Vec::<&str>::new());
    }
}
