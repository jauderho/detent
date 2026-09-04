//! Localized message lookup for the CLI (PLAN §4.3).
//!
//! [`Messages`] resolves a [`MessageId`] against two catalogues, in order:
//!
//! 1. `locales/en-US/cli.ftl`, compiled in here, which holds every id the CLI
//!    itself emits (`cli-…`);
//! 2. [`detent_i18n::Localizer`], which owns `core.ftl`/`web.ftl` and therefore
//!    every module diagnostic (`hosts-…`) and operations error (`ops-…`).
//!
//! # Why the CLI carries its own bundle (deviation, PLAN §4.3)
//!
//! `cli.ftl` is listed in PLAN §4.3 alongside `core.ftl` and `web.ftl`, but
//! `detent-i18n`'s `CATALOGUE` compiles in only the latter two, and this task
//! must not modify that crate. Rather than have every CLI string degrade to its
//! bare id, the bundle for `cli.ftl` is built here with the same `fluent-bundle`
//! primitives and the same bidi-isolation stripping `detent-i18n` documents, and
//! everything else — locale negotiation, the `en-US` fallback, diagnostic
//! rendering — is delegated to [`detent_i18n::Localizer`] rather than
//! reimplemented. The one-line fix is to add
//! `include_str!("../../../locales/en-US/cli.ftl")` to that crate's `CATALOGUE`
//! and drop this bundle; see the Phase 3 report.

use detent_core::diag::{Diagnostics, MessageId, Severity};
use detent_i18n::Localizer;
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

/// The CLI's own message catalogue, compiled in (PLAN §4.3: no runtime locale
/// directory can be assumed on an appliance).
pub const CLI_FTL: &str = include_str!("../../../locales/en-US/cli.ftl");

/// Fluent's bidirectional isolation marks, stripped from every rendered string:
/// a terminal renders them as garbage where a browser hides them.
const BIDI_MARKS: [char; 2] = ['\u{2068}', '\u{2069}'];

/// Renders every message the CLI prints.
pub struct Messages {
    cli: FluentBundle<FluentResource>,
    core: Localizer,
}

impl std::fmt::Debug for Messages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Messages")
            .field("locale", &self.core.locale())
            .finish_non_exhaustive()
    }
}

impl Messages {
    /// Negotiates `requested` (a BCP-47 tag from `--locale`), or the process
    /// environment when it is `None`.
    #[must_use]
    pub fn new(requested: Option<&str>) -> Self {
        let core = match requested.and_then(|tag| tag.parse::<LanguageIdentifier>().ok()) {
            Some(langid) => Localizer::new(&[langid]),
            None => Localizer::for_env(),
        };
        Self {
            cli: build_cli_bundle(),
            core,
        }
    }

    /// The negotiated locale tag, e.g. `en-US`.
    #[must_use]
    pub const fn locale(&self) -> &'static str {
        self.core.locale()
    }

    /// Renders `id` with no arguments.
    #[must_use]
    pub fn get(&self, id: MessageId) -> String {
        self.resolve(id, None)
    }

    /// Renders `id`, substituting `args`.
    #[must_use]
    pub fn format(&self, id: MessageId, args: &[(&str, &str)]) -> String {
        let mut fluent = FluentArgs::with_capacity(args.len());
        for (key, value) in args {
            fluent.set(*key, *value);
        }
        self.resolve(id, Some(&fluent))
    }

    /// Whether `id` resolves to real text rather than degrading to the id.
    ///
    /// Test-only: nothing in an output path asks this, because a missing id
    /// already degrades to itself. The tests use it to assert that every id the
    /// CLI can emit is actually in a catalogue.
    #[cfg(test)]
    #[must_use]
    pub fn has(&self, id: MessageId) -> bool {
        self.cli
            .get_message(id.as_str())
            .and_then(|message| message.value())
            .is_some()
            || self.core.has(&id)
    }

    /// Renders every diagnostic, each prefixed with its localized severity.
    #[must_use]
    pub fn diagnostics(&self, diagnostics: &Diagnostics) -> Vec<String> {
        diagnostics
            .iter()
            .map(|diagnostic| {
                let severity = self.get(severity_id(diagnostic.severity));
                let text = self.core.render(diagnostic);
                format!("{severity}: {text}")
            })
            .collect()
    }

    /// CLI catalogue first, then everything `detent-i18n` knows.
    fn resolve(&self, id: MessageId, args: Option<&FluentArgs<'_>>) -> String {
        let from_cli = self
            .cli
            .get_message(id.as_str())
            .and_then(|message| message.value())
            .map(|pattern| {
                let mut errors = Vec::new();
                self.cli
                    .format_pattern(pattern, args, &mut errors)
                    .into_owned()
            });
        match from_cli {
            Some(text) => strip_bidi(&text),
            None => match args {
                Some(args) => self.core.get_args(&id, args),
                None => self.core.get(&id),
            },
        }
    }
}

/// The Fluent id naming a severity.
const fn severity_id(severity: Severity) -> MessageId {
    match severity {
        Severity::Error => MessageId::new("cli-severity-error"),
        Severity::Warning => MessageId::new("cli-severity-warning"),
        Severity::Recommendation => MessageId::new("cli-severity-recommendation"),
    }
}

/// Parses [`CLI_FTL`], keeping whatever Fluent recovers from a malformed file
/// rather than failing to start; `the_cli_catalogue_parses_cleanly` guards the
/// compiled-in file against ever actually being malformed.
fn build_cli_bundle() -> FluentBundle<FluentResource> {
    let langid: LanguageIdentifier = "en-US".parse().unwrap_or_default();
    let mut bundle = FluentBundle::new(vec![langid]);
    let resource = match FluentResource::try_new(CLI_FTL.to_owned()) {
        Ok(resource) | Err((resource, _)) => resource,
    };
    let _ = bundle.add_resource(resource);
    bundle
}

/// Removes Fluent's FSI/PDI marks.
fn strip_bidi(text: &str) -> String {
    text.chars().filter(|c| !BIDI_MARKS.contains(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::{CLI_FTL, Messages, build_cli_bundle, severity_id, strip_bidi};
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use fluent_bundle::FluentResource;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_cli_catalogue_parses_cleanly() {
        let parsed = FluentResource::try_new(CLI_FTL.to_owned());
        let errors = parsed.as_ref().err().map(|(_, errors)| errors);
        assert!(parsed.is_ok(), "locales/en-US/cli.ftl: {errors:?}");
        assert!(!format!("{:?}", build_cli_bundle().locales).is_empty());
    }

    #[test]
    fn cli_ids_come_from_the_cli_catalogue() {
        let messages = Messages::new(None);
        let text = messages.format(
            MessageId::new("cli-applied"),
            &[("module", "hosts"), ("path", "/etc/hosts")],
        );
        assert!(text.contains("hosts"), "{text}");
        assert!(text.contains("/etc/hosts"), "{text}");
        assert!(messages.has(MessageId::new("cli-applied")));
    }

    #[test]
    fn core_ids_come_from_detent_i18n() {
        let messages = Messages::new(Some("en-US"));
        assert_eq!(messages.get(MessageId::new("hosts-name")), "hosts");
        assert_eq!(
            messages.format(MessageId::new("hosts-invalid-hostname"), &[("name", "x")]),
            "`x` is not a valid hostname."
        );
        assert!(messages.has(MessageId::new("ops-unknown-module")));
    }

    #[test]
    fn an_unknown_id_degrades_to_the_id_itself() {
        let messages = Messages::new(None);
        assert_eq!(
            messages.get(MessageId::new("no-such-id-anywhere")),
            "no-such-id-anywhere"
        );
        assert!(!messages.has(MessageId::new("no-such-id-anywhere")));
    }

    #[test]
    fn a_requested_locale_negotiates_and_an_unusable_one_falls_back() {
        // The only compiled-in locale is en-US, so everything negotiates to it;
        // what this proves is that the tag is parsed and passed through rather
        // than ignored, and that neither an unknown tag nor a malformed one
        // panics or changes the result.
        for tag in [Some("en-US"), Some("de-DE"), Some("!!!"), None] {
            let messages = Messages::new(tag);
            assert_eq!(messages.locale(), "en-US");
            assert!(
                !messages
                    .get(MessageId::new("cli-severity-error"))
                    .is_empty()
            );
        }
        assert!(format!("{:?}", Messages::new(None)).contains("en-US"));
    }

    #[test]
    fn diagnostics_are_rendered_with_a_localized_severity() -> R {
        let messages = Messages::new(None);
        let diagnostics: Diagnostics = [
            Diagnostic::new(Severity::Error, MessageId::new("hosts-no-hostnames")),
            Diagnostic::new(Severity::Warning, MessageId::new("hosts-invalid-hostname"))
                .with_arg("name", "bad host"),
            Diagnostic::new(
                Severity::Recommendation,
                MessageId::new("hosts-missing-localhost"),
            ),
        ]
        .into_iter()
        .collect();
        let rendered = messages.diagnostics(&diagnostics);
        assert_eq!(rendered.len(), 3);
        let first = rendered.first().ok_or("three lines were rendered")?;
        assert!(first.starts_with(&messages.get(severity_id(Severity::Error))));
        assert!(first.contains("no hostnames"));
        let second = rendered.get(1).ok_or("three lines were rendered")?;
        assert!(second.contains("bad host"));
        assert!(messages.diagnostics(&Diagnostics::new()).is_empty());
        Ok(())
    }

    #[test]
    fn severity_ids_are_distinct_and_all_defined() {
        let messages = Messages::new(None);
        let ids = [
            severity_id(Severity::Error),
            severity_id(Severity::Warning),
            severity_id(Severity::Recommendation),
        ];
        for id in ids {
            assert!(messages.has(id), "{} is undefined", id.as_str());
        }
        assert_ne!(ids[0].as_str(), ids[1].as_str());
        assert_ne!(ids[1].as_str(), ids[2].as_str());
    }

    #[test]
    fn rendered_text_never_carries_bidi_isolation_marks() {
        let messages = Messages::new(None);
        let text = messages.format(
            MessageId::new("cli-applied"),
            &[("module", "hosts"), ("path", "/etc/hosts")],
        );
        assert!(!text.contains('\u{2068}') && !text.contains('\u{2069}'));
        assert_eq!(strip_bidi("\u{2068}a\u{2069}b"), "ab");
    }
}
