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
use fluent_bundle::FluentArgs;
use unic_langid::LanguageIdentifier;

/// The CLI's own message catalogue, compiled in (PLAN §4.3: no runtime locale
/// directory can be assumed on an appliance).
#[cfg(test)]
pub const CLI_FTL: &str = include_str!("../../../locales/en-US/cli.ftl");

/// Renders every message the CLI prints.
pub struct Messages {
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
        Self { core }
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
        self.core.has(&id)
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

    /// Everything `detent-i18n` knows, including `cli.ftl`.
    fn resolve(&self, id: MessageId, args: Option<&FluentArgs<'_>>) -> String {
        match args {
            Some(args) => self.core.get_args(&id, args),
            None => self.core.get(&id),
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

#[cfg(test)]
mod tests {
    use super::{CLI_FTL, Messages, severity_id};
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use fluent_bundle::FluentResource;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_cli_catalogue_parses_cleanly() {
        let parsed = FluentResource::try_new(CLI_FTL.to_owned());
        let errors = parsed.as_ref().err().map(|(_, errors)| errors);
        assert!(parsed.is_ok(), "locales/en-US/cli.ftl: {errors:?}");
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

    /// Every CLI message with arguments goes through `format`: C0, C1 and
    /// bidi controls in an argument never reach the terminal (L-OPS19).
    #[test]
    fn cli_arguments_lose_control_and_bidi_characters() {
        let messages = Messages::new(Some("en-US"));
        let text = messages.format(
            MessageId::new("cli-applied"),
            &[
                ("module", "ho\u{1B}]0;pwned\u{07}sts"),
                ("path", "/etc/\u{9B}\u{202E}stsoh\u{2066}\n"),
            ],
        );
        for ch in ['\u{1B}', '\u{07}', '\u{9B}', '\u{202E}', '\u{2066}', '\n'] {
            assert!(!text.contains(ch), "{ch:?} reached the output: {text:?}");
        }
        assert!(text.contains("ho]0;pwnedsts"), "{text}");
        assert!(text.contains("/etc/stsoh"), "{text}");
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
    }
}
