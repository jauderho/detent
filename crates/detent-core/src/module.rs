//! The module SDK: the [`ConfigModule`] trait every module crate implements, its
//! error types, and the object-safe [`DynModule`] adapter the rest of the workspace
//! consumes.
//!
//! Generics stay inside the module crate. `detent-ops`, `detent-web` and `detent-ffi`
//! only ever see `dyn DynModule`, which speaks JSON.

use crate::descriptor::{HostProfile, ModuleDescriptor, ValidationCtx};
use crate::diag::{Diagnostics, MessageId};
use crate::doc::Span;
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::marker::PhantomData;

/// A concrete syntax tree that can reproduce the text it was parsed from.
///
/// `PartialEq` and `Debug` are required because invariant 4 ("rendered output
/// re-parses to the same `Doc`") is checked by comparing documents.
pub trait LosslessDoc: std::fmt::Debug + PartialEq {
    /// Reconstructs the document text.
    fn render(&self) -> String;
}

/// How much a call to `ConfigModule::apply` changed, for the audit log and the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, schemars::JsonSchema)]
pub struct EditReport {
    /// Lines whose text was rewritten in place.
    pub changed_lines: usize,
    /// Lines added.
    pub added: usize,
    /// Lines removed.
    pub removed: usize,
}

/// A file that could not be parsed.
///
/// Line-oriented modules never produce this — their `parse` is total. Modules over a
/// stricter grammar (INI, YAML, JSON) may.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input does not match the format's grammar.
    #[error("malformed input: {message}")]
    Malformed {
        /// Human-readable detail, for the log; the UI shows the message id.
        message: String,
        /// Where the problem is, when it is localized to a range.
        span: Option<Span>,
    },
}

impl ParseError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Malformed { .. } => MessageId::new("core-parse-malformed"),
        }
    }
}

/// A document could not be projected onto the typed model, or JSON could not be
/// projected onto it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// The JSON did not match the model's schema. Carries serde's message.
    #[error("model does not match its schema: {message}")]
    Shape {
        /// serde's error text.
        message: String,
    },
    /// The document holds something the model cannot express.
    #[error("document cannot be represented as a model: {message}")]
    Unrepresentable {
        /// Human-readable detail.
        message: String,
        /// Where the offending content is, when it is localized to a range.
        span: Option<Span>,
    },
}

/// A `serde_json` failure is always a shape mismatch: JSON that does not match the
/// module's model. Modules rely on this so malformed input produces a diagnostic
/// rather than a panic.
impl From<serde_json::Error> for ModelError {
    fn from(error: serde_json::Error) -> Self {
        Self::Shape {
            message: error.to_string(),
        }
    }
}

impl ModelError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Shape { .. } => MessageId::new("core-model-shape"),
            Self::Unrepresentable { .. } => MessageId::new("core-model-unrepresentable"),
        }
    }
}

/// An edit could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    /// The value contains `\n`, `\r` or NUL and would have broken out of its line.
    /// This is invariant 5: directive injection is rejected, never escaped away
    /// silently.
    #[error("value contains a line break or NUL and cannot be written: {value:?}")]
    LineBreakInValue {
        /// The rejected value.
        value: String,
    },
    /// A line index does not exist.
    #[error("line index {index} is out of range for a document of {len} lines")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The document's line count.
        len: usize,
    },
    /// The module cannot express this model as an edit of this document.
    #[error("edit not supported: {message}")]
    Unsupported {
        /// Human-readable detail.
        message: String,
    },
}

impl EditError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::LineBreakInValue { .. } => MessageId::new("core-edit-line-break"),
            Self::IndexOutOfRange { .. } => MessageId::new("core-edit-index-out-of-range"),
            Self::Unsupported { .. } => MessageId::new("core-edit-unsupported"),
        }
    }
}

/// One config file format, parsed losslessly and edited minimally.
///
/// Implementors must satisfy the six invariants checked by
/// [`module_conformance!`](crate::module_conformance):
///
/// 1. `render(parse(s)) == s` for every `s`.
/// 2. `apply(doc, to_model(doc))` changes nothing.
/// 3. `to_model(apply(parse(s), m)) == m` for every valid model `m`.
/// 4. Rendered output re-parses to the same `Doc`.
/// 5. Values containing `\n`, `\r` or NUL are rejected, never emitted raw.
/// 6. `parse` completes in bounded time on 1 MiB of adversarial input.
pub trait ConfigModule: Send + Sync + 'static {
    /// Stable id, e.g. `"chrony"`. Used in URLs, the CLI, the audit log and feature
    /// names.
    const ID: &'static str;

    /// The lossless concrete syntax tree: comments, whitespace, order and unknown
    /// directives all survive.
    type Doc: LosslessDoc;

    /// The typed model exposed to the UI, the API and the C ABI.
    type Model: Serialize + DeserializeOwned + JsonSchema + PartialEq + Clone + std::fmt::Debug;

    /// Static metadata: targets, upstream tracking, service bindings, external checks.
    fn descriptor() -> &'static ModuleDescriptor;

    /// Parses source text. Never panics and, for line-oriented formats, never fails.
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the input does not match the format's grammar.
    fn parse(src: &str) -> Result<Self::Doc, ParseError>;

    /// Renders a document back to text such that `render(parse(s)) == s`.
    fn render(doc: &Self::Doc) -> String;

    /// Projects a document onto the typed model.
    ///
    /// # Errors
    ///
    /// [`ModelError`] when the document holds something the model cannot express.
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError>;

    /// Rewrites `doc` to match `model`, touching as few lines as possible.
    ///
    /// # Errors
    ///
    /// [`EditError`] when a value would break out of its line (invariant 5) or the
    /// edit cannot be expressed.
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError>;

    /// Checks a model, returning errors, warnings and recommendations as Fluent ids.
    fn validate(model: &Self::Model, ctx: &ValidationCtx<'_>) -> Diagnostics;

    /// Secure, host-appropriate defaults.
    fn defaults(profile: &HostProfile) -> Self::Model;

    /// The JSON Schema of `Self::Model`, including any `x-detent` UI hints.
    ///
    /// The default is the bare `schemars` schema. A module that attaches
    /// `x-detent` hints (via [`crate::descriptor::apply_hints`]) overrides this
    /// instead of exposing a separate free function, so
    /// [`DynModule::schema_json`] and any direct caller of the trait see the
    /// same schema.
    #[must_use]
    fn schema() -> Value {
        schemars::schema_for!(Self::Model).to_value()
    }
}

/// Anything that can go wrong behind the JSON adapter.
#[derive(Debug, thiserror::Error)]
pub enum DynError {
    /// The source file could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The JSON model was not shaped like the module's model.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// The edit was rejected.
    #[error(transparent)]
    Edit(#[from] EditError),
}

impl DynError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Parse(ref e) => e.message_id(),
            Self::Model(ref e) => e.message_id(),
            Self::Edit(ref e) => e.message_id(),
        }
    }
}

/// The object-safe, JSON-in/JSON-out view of a [`ConfigModule`].
///
/// Obtained with [`Dyn::new`]. This is what the operations layer, the web API and the
/// C ABI hold; none of them names a module's concrete `Doc` or `Model`.
pub trait DynModule: Send + Sync {
    /// The module's stable id.
    fn id(&self) -> &'static str;

    /// The module's static metadata.
    fn descriptor(&self) -> &'static ModuleDescriptor;

    /// The JSON Schema of the module's model, including `x-detent` hints.
    fn schema_json(&self) -> Value;

    /// Parses `src` and returns the model as JSON.
    ///
    /// # Errors
    ///
    /// [`DynError::Parse`] or [`DynError::Model`].
    fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError>;

    /// Applies `model_json` to `src` and returns the rendered result.
    ///
    /// # Errors
    ///
    /// [`DynError::Parse`], [`DynError::Model`] (including a JSON shape mismatch) or
    /// [`DynError::Edit`].
    fn apply_json(&self, src: &str, model_json: &Value) -> Result<String, DynError>;

    /// Validates `model_json` against the host in `ctx`.
    ///
    /// # Errors
    ///
    /// [`DynError::Model`] when the JSON is not shaped like the module's model.
    fn validate_json(
        &self,
        model_json: &Value,
        ctx: &ValidationCtx<'_>,
    ) -> Result<Diagnostics, DynError>;

    /// The module's defaults for `profile`, as JSON.
    ///
    /// # Errors
    ///
    /// [`DynError::Model`] if the default model cannot be serialized.
    fn defaults_json(&self, profile: &HostProfile) -> Result<Value, DynError>;
}

/// Adapts a [`ConfigModule`] to [`DynModule`].
pub struct Dyn<M: ConfigModule>(PhantomData<fn() -> M>);

impl<M: ConfigModule> Dyn<M> {
    /// Creates the adapter. Zero-sized.
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<M: ConfigModule> Default for Dyn<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// Deserializes JSON into a module's model, turning any serde failure into
/// [`ModelError::Shape`] rather than a panic.
fn model_from_json<M: ConfigModule>(value: &Value) -> Result<M::Model, ModelError> {
    serde_json::from_value(value.clone()).map_err(ModelError::from)
}

/// Serializes a module's model, turning any serde failure into [`ModelError::Shape`].
fn model_to_json<T: Serialize>(value: &T) -> Result<Value, ModelError> {
    serde_json::to_value(value).map_err(ModelError::from)
}

impl<M: ConfigModule> DynModule for Dyn<M> {
    fn id(&self) -> &'static str {
        M::ID
    }

    fn descriptor(&self) -> &'static ModuleDescriptor {
        M::descriptor()
    }

    fn schema_json(&self) -> Value {
        M::schema()
    }

    fn parse_to_model_json(&self, src: &str) -> Result<Value, DynError> {
        let doc = M::parse(src)?;
        let model = M::to_model(&doc)?;
        Ok(model_to_json(&model)?)
    }

    fn apply_json(&self, src: &str, model_json: &Value) -> Result<String, DynError> {
        let mut doc = M::parse(src)?;
        let model = model_from_json::<M>(model_json)?;
        M::apply(&mut doc, &model)?;
        Ok(M::render(&doc))
    }

    fn validate_json(
        &self,
        model_json: &Value,
        ctx: &ValidationCtx<'_>,
    ) -> Result<Diagnostics, DynError> {
        let model = model_from_json::<M>(model_json)?;
        Ok(M::validate(&model, ctx))
    }

    fn defaults_json(&self, profile: &HostProfile) -> Result<Value, DynError> {
        Ok(model_to_json(&M::defaults(profile))?)
    }
}

#[cfg(test)]
mod tests {
    use super::{DynError, EditError, EditReport, ModelError, ParseError};
    use crate::doc::Span;

    #[test]
    fn errors_carry_message_ids_and_display_text() {
        let parse = ParseError::Malformed {
            message: "unbalanced quote".to_owned(),
            span: Some(Span::new(0, 1)),
        };
        assert_eq!(parse.message_id().as_str(), "core-parse-malformed");
        assert_eq!(parse.to_string(), "malformed input: unbalanced quote");

        let shape = ModelError::Shape {
            message: "missing field `ip`".to_owned(),
        };
        assert_eq!(shape.message_id().as_str(), "core-model-shape");
        assert_eq!(
            shape.to_string(),
            "model does not match its schema: missing field `ip`"
        );

        let unrep = ModelError::Unrepresentable {
            message: "two values".to_owned(),
            span: None,
        };
        assert_eq!(unrep.message_id().as_str(), "core-model-unrepresentable");
        assert_eq!(
            unrep.to_string(),
            "document cannot be represented as a model: two values"
        );

        let brk = EditError::LineBreakInValue {
            value: "a\nb".to_owned(),
        };
        assert_eq!(brk.message_id().as_str(), "core-edit-line-break");
        assert!(brk.to_string().contains("a\\nb"));

        let oob = EditError::IndexOutOfRange { index: 4, len: 2 };
        assert_eq!(oob.message_id().as_str(), "core-edit-index-out-of-range");
        assert_eq!(
            oob.to_string(),
            "line index 4 is out of range for a document of 2 lines"
        );

        let unsupported = EditError::Unsupported {
            message: "cannot reorder".to_owned(),
        };
        assert_eq!(unsupported.message_id().as_str(), "core-edit-unsupported");
        assert_eq!(
            unsupported.to_string(),
            "edit not supported: cannot reorder"
        );

        assert_eq!(
            DynError::from(parse.clone()).message_id().as_str(),
            "core-parse-malformed"
        );
        assert_eq!(
            DynError::from(shape).message_id().as_str(),
            "core-model-shape"
        );
        assert_eq!(
            DynError::from(oob.clone()).message_id().as_str(),
            "core-edit-index-out-of-range"
        );
        assert_eq!(
            DynError::from(parse).to_string(),
            "malformed input: unbalanced quote"
        );
        assert!(format!("{:?}", DynError::from(oob)).contains("IndexOutOfRange"));
        assert_eq!(unrep.clone(), unrep);
        assert_eq!(brk.clone(), brk);
        assert_eq!(unsupported.clone(), unsupported);
    }

    #[test]
    fn edit_report_defaults_to_no_change() {
        let report = EditReport::default();
        assert_eq!(
            report,
            EditReport {
                changed_lines: 0,
                added: 0,
                removed: 0
            }
        );
        assert_eq!(
            serde_json::to_value(report).unwrap_or_default(),
            serde_json::json!({"changed_lines": 0, "added": 0, "removed": 0})
        );
        assert!(!schemars::schema_for!(EditReport).to_value().is_null());
        assert!(format!("{report:?}").contains("changed_lines"));
    }
}
