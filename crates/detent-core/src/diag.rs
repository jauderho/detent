//! Diagnostics produced by module validation.
//!
//! A diagnostic carries a Fluent **message id** and its arguments, never a rendered
//! sentence: this crate does not localize. `detent-i18n` turns
//! `(MessageId, args)` into text for a locale, so the same diagnostic can be shown in
//! the web UI, printed by the CLI, and returned over the C ABI.

use crate::doc::Span;
use std::collections::BTreeMap;

/// How much a diagnostic matters.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The configuration is invalid and must not be applied.
    Error,
    /// The configuration is valid but likely wrong.
    Warning,
    /// The configuration is fine; a better option exists.
    Recommendation,
}

/// The id of a Fluent message in `locales/<lang>/core.ftl`.
///
/// Always a compile-time constant, so a module cannot accidentally emit a message
/// that has no translation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct MessageId(&'static str);

impl MessageId {
    /// Wraps a Fluent message id.
    #[must_use]
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The underlying id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A path to a field inside a module's model, in the style of a JSON pointer without
/// the leading slash: `"entries/3/hostnames/0"`.
///
/// The UI uses it to attach a diagnostic to the control that produced it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct FieldPath(String);

impl FieldPath {
    /// Wraps a field path.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// The underlying path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One validation finding.
///
/// Built with [`Diagnostic::new`] and refined with the `with_*` methods; every field
/// beyond severity and id is optional because not every finding maps to a field or a
/// byte range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct Diagnostic {
    /// How much this finding matters.
    pub severity: Severity,
    /// The Fluent id of the message.
    pub id: MessageId,
    /// The model field this finding is about, if any.
    pub field: Option<FieldPath>,
    /// The byte range in the source file this finding is about, if any.
    pub span: Option<Span>,
    /// Named arguments for the Fluent message, sorted for deterministic output.
    pub args: BTreeMap<String, String>,
}

impl Diagnostic {
    /// Creates a diagnostic with no field, span or arguments.
    #[must_use]
    pub const fn new(severity: Severity, id: MessageId) -> Self {
        Self {
            severity,
            id,
            field: None,
            span: None,
            args: BTreeMap::new(),
        }
    }

    /// Attaches the model field this finding is about.
    #[must_use]
    pub fn with_field(mut self, field: FieldPath) -> Self {
        self.field = Some(field);
        self
    }

    /// Attaches the source range this finding is about.
    #[must_use]
    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Adds a Fluent argument.
    #[must_use]
    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }
}

/// The findings from one call to `ConfigModule::validate`, in the order they were
/// produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct Diagnostics(Vec<Diagnostic>);

impl Diagnostics {
    /// An empty set of findings.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a finding.
    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.0.push(diagnostic);
    }

    /// Whether any finding has [`Severity::Error`]. A model with errors must not be
    /// applied.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.0.iter().any(|d| d.severity == Severity::Error)
    }

    /// Number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no findings at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the findings.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.0.iter()
    }
}

impl FromIterator<Diagnostic> for Diagnostics {
    fn from_iter<T: IntoIterator<Item = Diagnostic>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Diagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Diagnostics, FieldPath, MessageId, Severity};
    use crate::doc::Span;

    const BAD_IP: MessageId = MessageId::new("hosts-invalid-ip");

    fn sample() -> Diagnostic {
        Diagnostic::new(Severity::Error, BAD_IP)
            .with_field(FieldPath::new("entries/3/ip"))
            .with_span(Span::new(4, 9))
            .with_arg("value", "999.1.1.1")
    }

    #[test]
    fn builder_fills_every_field() {
        let d = sample();
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(d.id.as_str(), "hosts-invalid-ip");
        assert_eq!(
            d.field.as_ref().map(FieldPath::as_str),
            Some("entries/3/ip")
        );
        assert_eq!(d.span, Some(Span::new(4, 9)));
        assert_eq!(d.args.get("value").map(String::as_str), Some("999.1.1.1"));
        assert_eq!(d.clone(), d);
        assert!(format!("{d:?}").contains("hosts-invalid-ip"));
    }

    #[test]
    fn collection_tracks_errors() {
        let mut set = Diagnostics::new();
        assert!(set.is_empty());
        assert!(!set.has_errors());
        assert_eq!(set, Diagnostics::default());
        set.push(Diagnostic::new(Severity::Warning, MessageId::new("w")));
        assert!(!set.has_errors());
        set.push(sample());
        assert!(set.has_errors());
        assert_eq!(set.len(), 2);
        assert_eq!(set.iter().count(), 2);
        assert_eq!((&set).into_iter().count(), 2);
        assert_eq!(set.clone().into_iter().count(), 2);
        let collected: Diagnostics = set.clone().into_iter().collect();
        assert_eq!(collected, set);
        assert!(format!("{set:?}").contains('w'));
    }

    #[test]
    fn serializes_for_the_api() {
        let set: Diagnostics = std::iter::once(sample()).collect();
        let json = serde_json::to_value(&set).unwrap_or_default();
        assert_eq!(
            json.pointer("/0/severity").and_then(|v| v.as_str()),
            Some("error")
        );
        assert_eq!(
            json.pointer("/0/id").and_then(|v| v.as_str()),
            Some("hosts-invalid-ip")
        );
        assert_eq!(
            json.pointer("/0/field").and_then(|v| v.as_str()),
            Some("entries/3/ip")
        );
        assert_eq!(
            json.pointer("/0/args/value").and_then(|v| v.as_str()),
            Some("999.1.1.1")
        );

        for schema in [
            schemars::schema_for!(Diagnostics),
            schemars::schema_for!(Diagnostic),
            schemars::schema_for!(Severity),
            schemars::schema_for!(MessageId),
            schemars::schema_for!(FieldPath),
        ] {
            assert!(!schema.to_value().is_null());
        }
        assert_eq!(
            serde_json::from_str::<Severity>("\"recommendation\"").ok(),
            Some(Severity::Recommendation)
        );
        assert_eq!(
            serde_json::from_str::<FieldPath>("\"a/b\"")
                .as_ref()
                .map(FieldPath::as_str)
                .ok(),
            Some("a/b")
        );
    }
}
