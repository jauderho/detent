//! Fluent message loader (embedded locales), used by the CLI, the web layer, and
//! diagnostics rendering.
//!
//! [`Localizer`] negotiates a requested locale list against the locales compiled
//! into this binary and renders [`MessageId`]s (from `detent_core::diag`) and
//! [`Diagnostic`]s to text, always falling back to `en-US` and never panicking.
//!
//! # `i18n-embed` substitution (ADR‑003 deviation)
//!
//! `docs/PLAN.md` §4.3 and `docs/adr/ADR-003-i18n-fluent.md` name `i18n-embed` (with
//! `rust-embed`) as the Rust-side loader. This crate embeds the `locales/` tree
//! with its own build script and [`include_str!`] instead, for two reasons
//! specific to `detent`:
//!
//! 1. **No runtime locale directory can be assumed.** `detent` runs as a daemon on
//!    appliances (`docs/PLAN.md` §1.1) with no guarantee a `locales/` directory
//!    exists anywhere on disk at startup, so locales must be compiled in, not
//!    loaded from a path.
//! 2. **Size budget.** `docs/PLAN.md` §4.1 puts this crate in every binary
//!    (including the CLI-only build with the smallest budget). `rust-embed`'s
//!    derive and its runtime `Cow<[u8]>` lookups add a second, more general
//!    embedding mechanism on top of what `include_str!` already does for free.
//!
//! # The catalogue is generated
//!
//! `build.rs` scans `locales/*/`, checks that each directory holds `core.ftl`,
//! `web.ftl` and `cli.ftl`, and writes `CATALOGUE` into `$OUT_DIR`. Adding a
//! locale is adding a directory: no Rust edit. The pseudo-locale (`qps-*`) is
//! left out by rule. `locale_scan.rs` holds the rules and their tests.
//!
//! # The text is stored compressed
//!
//! `build.rs` packs every `.ftl` file as raw DEFLATE (`miniz_oxide`, safe Rust, one
//! small dependency) and the binary embeds only the packed bytes. A [`Localizer`]
//! inflates the negotiated locale and the `en-US` fallback on first use, once per
//! file; the other locales are never unpacked. Fluent text packs to about a third,
//! so twelve locales take about the space four would as plain text.
//!
//! # Bidi isolation
//!
//! Fluent wraps interpolated values in FSI/PDI marks (U+2068, U+2069) by default, so
//! that a right-to-left value embedded in a left-to-right sentence (or vice versa)
//! keeps the surrounding sentence's direction stable. That is the right default for
//! a browser, which renders bidi marks invisibly. It is the wrong default for a
//! terminal or a log line, where the marks either render as visible garbage or are
//! silently eaten depending on the terminal, and for diagnostics that get compared
//! or grepped as plain text. Every rendering path in this crate ([`Localizer::get`],
//! [`Localizer::get_args`], [`Localizer::render`], [`Localizer::render_all`]) strips
//! them unconditionally, so callers always get plain text back.

use detent_core::diag::{Diagnostic, Diagnostics, MessageId};
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use unic_langid::LanguageIdentifier;

/// One embedded `.ftl` file: its raw DEFLATE bytes and the length of the text.
///
/// `build.rs` makes one `static` of this for every file of every locale. The text
/// is inflated the first time something asks for it and kept, so a process pays
/// only for the locales it renders (the negotiated one and the `en-US` fallback),
/// and only once.
struct Packed {
    /// Length in bytes of the inflated text; also the cap on the inflater's output.
    len: usize,
    /// The file as raw DEFLATE.
    deflated: &'static [u8],
    /// The inflated text, set on first use.
    text: OnceLock<Box<str>>,
}

impl Packed {
    /// A file that is still compressed.
    const fn new(len: usize, deflated: &'static [u8]) -> Self {
        Self {
            len,
            deflated,
            text: OnceLock::new(),
        }
    }

    /// The `.ftl` text. A blob that fails to inflate, to the recorded length or to
    /// UTF-8, gives an empty text instead of a panic, so that every id of the file
    /// degrades to its `en-US` text. `build.rs` proves each blob inflates, and
    /// `embedded_files_inflate_to_the_files_on_disk` proves it again in CI.
    fn text(&self) -> &str {
        self.text.get_or_init(|| {
            decompress_to_vec_with_limit(self.deflated, self.len)
                .ok()
                .filter(|bytes| bytes.len() == self.len)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default()
                .into_boxed_str()
        })
    }

    /// Whether the text has been inflated yet.
    #[cfg(test)]
    fn is_inflated(&self) -> bool {
        self.text.get().is_some()
    }
}

/// One compiled-in locale: a BCP‑47 tag and the compressed Fluent source of the
/// `.ftl` files under `locales/<tag>/`.
struct LocaleSource {
    /// BCP‑47 locale tag, matching the `locales/<tag>/` directory name.
    tag: &'static str,
    /// The `.ftl` files for this locale, in the order added to the bundle.
    files: &'static [&'static Packed],
}

impl LocaleSource {
    /// The text of every file, inflating whatever is not yet.
    fn texts(&self) -> Vec<&'static str> {
        self.files.iter().map(|file| file.text()).collect()
    }
}

/// The locale tag used as the ultimate fallback and the source of truth for message
/// ids (`docs/adr/ADR-003-i18n-fluent.md`).
const EN_US_TAG: &str = "en-US";

// `CATALOGUE`: every locale compiled into this binary, sorted by tag, generated
// by `build.rs` from the directories under `locales/`. `web.ftl` is part of each
// locale only with the `web` feature: only the web server and its API look those
// ids up. `catalogue_locales_have_id_parity_with_en_us` (below) enforces that each
// locale defines exactly the ids `en-US` defines, no more and no fewer.
include!(concat!(env!("OUT_DIR"), "/catalogue.rs"));

/// The `.ftl` texts of the `en-US` catalogue entry.
fn en_us_files() -> Vec<&'static str> {
    CATALOGUE
        .iter()
        .find(|locale| locale.tag == EN_US_TAG)
        .map(LocaleSource::texts)
        .unwrap_or_default()
}

/// Parses `.ftl` sources into a bundle for `tag`, tolerating parse errors in any
/// single file (the resource Fluent recovers, minus the malformed entries, is still
/// added) rather than panicking. `all_locales_parse_cleanly` (in tests) guards every
/// compiled-in file against ever actually having a parse error.
fn build_bundle(tag: &str, files: &[&str]) -> FluentBundle<FluentResource> {
    let langid: LanguageIdentifier = tag.parse().unwrap_or_default();
    let mut bundle = FluentBundle::new(vec![langid]);
    for file in files {
        let resource = match FluentResource::try_new((*file).to_owned()) {
            Ok(resource) | Err((resource, _)) => resource,
        };
        // A duplicate id across a locale's own files is a translator bug, not a
        // reason to crash the daemon; the first definition wins and the rest are
        // silently ignored, same as Fluent's own bundle semantics.
        let _ = bundle.add_resource(resource);
    }
    bundle
}

/// Requested tags that map to a shipped locale the language alone does not pick.
///
/// A key is `language`, `language-Script`, `language-REGION` or
/// `language-Script-REGION`, in that canonical case. [`alias_candidates`] tries the
/// most specific key first, so a script wins over a region (`zh-Hant-CN` is
/// Traditional). A target that is not compiled in is skipped. A bare language that
/// has no row here picks the first compiled-in locale of that language.
///
/// The same table is in `web/src/i18n/index.tsx`; keep the two in step.
const ALIASES: &[(&str, &str)] = &[
    ("en", "en-US"),
    ("en-AU", "en-GB"),
    ("en-HK", "en-GB"),
    ("en-IE", "en-GB"),
    ("en-IN", "en-GB"),
    ("en-NZ", "en-GB"),
    ("en-SG", "en-GB"),
    ("en-ZA", "en-GB"),
    ("zh", "zh-CN"),
    ("zh-Hans", "zh-CN"),
    ("zh-SG", "zh-CN"),
    ("zh-Hant", "zh-TW"),
    ("zh-HK", "zh-TW"),
    ("zh-MO", "zh-TW"),
    ("pt", "pt-BR"),
    ("es", "es-ES"),
];

/// The [`ALIASES`] keys for `tag`, most specific first.
fn alias_candidates(tag: &LanguageIdentifier) -> Vec<String> {
    let language = tag.language.as_str();
    let script = tag.script.map(|s| s.as_str().to_owned());
    let region = tag.region.map(|r| r.as_str().to_owned());
    let mut keys = Vec::with_capacity(4);
    if let (Some(script), Some(region)) = (&script, &region) {
        keys.push(format!("{language}-{script}-{region}"));
    }
    if let Some(script) = &script {
        keys.push(format!("{language}-{script}"));
    }
    if let Some(region) = &region {
        keys.push(format!("{language}-{region}"));
    }
    keys.push(language.to_owned());
    keys
}

/// The compiled-in locale that [`ALIASES`] names for `tag`, if there is one.
fn alias_match<'a>(
    tag: &LanguageIdentifier,
    available: &[(&'a str, LanguageIdentifier)],
) -> Option<&'a str> {
    alias_candidates(tag).iter().find_map(|key| {
        let (_, target) = ALIASES.iter().find(|(from, _)| from == key)?;
        available
            .iter()
            .find(|(name, _)| name == target)
            .map(|(name, _)| *name)
    })
}

/// Picks the best available locale tag for `requested`, trying an exact tag match
/// for every requested locale (in priority order) before falling back, for every
/// requested locale in the same order, to an [`ALIASES`] row (`zh-HK` is `zh-TW`,
/// `en-AU` is `en-GB`) and then to the first available locale of the same language
/// (`de-AT` negotiates against a compiled `de-DE`). Returns `None` only when
/// `available` is empty or none of `requested` matches anything in it.
fn negotiate<'a>(
    requested: &[LanguageIdentifier],
    available: &[(&'a str, LanguageIdentifier)],
) -> Option<&'a str> {
    requested
        .iter()
        .find_map(|req| {
            available
                .iter()
                .find(|(_, tag)| tag == req)
                .map(|(tag, _)| *tag)
        })
        .or_else(|| {
            requested.iter().find_map(|req| {
                alias_match(req, available).or_else(|| {
                    available
                        .iter()
                        .find(|(_, tag)| tag.language == req.language)
                        .map(|(tag, _)| *tag)
                })
            })
        })
}

/// Reads a POSIX locale environment variable value, ignoring `C`/`POSIX` and
/// stripping a trailing `.<codeset>` and/or `@<modifier>` (e.g. `de_DE.UTF-8@euro`
/// negotiates as `de_DE`, then `de-DE` once the parser normalizes the separator).
/// Returns `None` for empty, `C`/`POSIX`, or otherwise-unparseable values.
fn parse_posix_locale_value(value: &str) -> Option<LanguageIdentifier> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("C") || value.eq_ignore_ascii_case("POSIX") {
        return None;
    }
    let value = value.split('@').next().unwrap_or(value);
    let value = value.split('.').next().unwrap_or(value);
    if value.is_empty() {
        return None;
    }
    value.parse().ok()
}

/// Resolves the single requested locale from `LC_ALL`, `LC_MESSAGES`, `LANG` values
/// (in that precedence order, matching POSIX locale resolution): the first variable
/// that is set to a non-empty, non-`C`/`POSIX`, parseable value wins. A variable set
/// to `C`/`POSIX`, empty, or unparseable is treated as unset and the next variable in
/// precedence is tried.
///
/// Pure and side-effect free (it does not read the environment itself) so it can be
/// exhaustively unit tested without mutating process environment, which requires
/// `unsafe` under edition 2024 and is forbidden in this crate
/// (`unsafe_code = "forbid"`, `docs/PLAN.md` §4.1).
fn resolve_env_locale(vars: [Option<&str>; 3]) -> Option<LanguageIdentifier> {
    vars.into_iter()
        .flatten()
        .find_map(parse_posix_locale_value)
}

/// Strips Fluent's bidirectional isolation marks. See the crate-level "Bidi
/// isolation" docs for why every rendering path in this crate does this
/// unconditionally.
fn strip_bidi_isolation(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
        .collect()
}

/// Formats `id` (with optional `args`) against `bundle`, stripping bidi isolation
/// marks. Returns `None` when the bundle has no message with that id, or the message
/// has no value pattern (an attributes-only message).
fn render_from_bundle(
    bundle: &FluentBundle<FluentResource>,
    id: &str,
    args: Option<&FluentArgs<'_>>,
) -> Option<String> {
    let message = bundle.get_message(id)?;
    let pattern = message.value()?;
    let mut errors = Vec::new();
    let value = bundle.format_pattern(pattern, args, &mut errors);
    Some(strip_bidi_isolation(&value))
}

/// Whether `bundle` has a message with a value pattern for `id`.
fn message_has_value(bundle: &FluentBundle<FluentResource>, id: &str) -> bool {
    bundle.get_message(id).and_then(|m| m.value()).is_some()
}

/// Sanitises a Fluent argument value for terminal/log output: strips C0/C1
/// controls and Unicode bidi controls that could otherwise affect terminal
/// rendering or enable visual spoofing. Fluent's own FSI/PDI (U+2068/U+2069)
/// are stripped later by `strip_bidi_isolation`, but we also strip them here
/// so the raw value never reaches the bundle.
fn sanitize_arg_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            if c.is_control() {
                return false;
            }
            !matches!(
                *c,
                '\u{061C}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
        })
        .collect()
}

/// Builds an owned [`FluentArgs`] from a [`Diagnostic`]'s string-keyed, string-valued
/// argument map.
fn fluent_args(map: &BTreeMap<String, String>) -> FluentArgs<'static> {
    let mut args = FluentArgs::with_capacity(map.len());
    for (key, value) in map {
        args.set(key.clone(), sanitize_arg_value(value));
    }
    args
}

/// Renders [`MessageId`]s and [`Diagnostic`]s to text for one negotiated locale,
/// falling back to `en-US` for any id missing in that locale, and to the bare id
/// text for an id missing everywhere.
///
/// Construct with [`Localizer::new`] (explicit requested locales),
/// [`Localizer::for_env`] (from `LC_ALL`/`LC_MESSAGES`/`LANG`), or
/// [`Localizer::en_us`] (always `en-US`, no negotiation).
pub struct Localizer {
    tag: &'static str,
    active: FluentBundle<FluentResource>,
    fallback: Option<FluentBundle<FluentResource>>,
}

impl Localizer {
    /// Builds a `Localizer` whose active locale is `tag`/`files` and whose fallback
    /// is the compiled-in `en-US` (or no fallback, if `tag` already is `en-US`).
    fn from_files(tag: &'static str, files: &[&str]) -> Self {
        let active = build_bundle(tag, files);
        let fallback = if tag == EN_US_TAG {
            None
        } else {
            Some(build_bundle(EN_US_TAG, &en_us_files()))
        };
        Self {
            tag,
            active,
            fallback,
        }
    }

    /// Negotiates `requested` against the compiled-in locales (exact tag match, then
    /// a documented alias such as `zh-HK` to `zh-TW`, then the same language), falling
    /// back to `en-US` when nothing matches.
    #[must_use]
    pub fn new(requested: &[LanguageIdentifier]) -> Self {
        let available: Vec<(&'static str, LanguageIdentifier)> = CATALOGUE
            .iter()
            .map(|locale| (locale.tag, locale.tag.parse().unwrap_or_default()))
            .collect();
        let tag = negotiate(requested, &available).unwrap_or(EN_US_TAG);
        let files = CATALOGUE
            .iter()
            .find(|locale| locale.tag == tag)
            .map(LocaleSource::texts)
            .unwrap_or_default();
        Self::from_files(tag, &files)
    }

    /// Builds a `Localizer` from `LC_ALL`, `LC_MESSAGES`, `LANG` (in that precedence,
    /// ignoring `C`/`POSIX` and stripping `.<codeset>`/`@<modifier>` suffixes),
    /// negotiated as in [`Localizer::new`].
    #[must_use]
    pub fn for_env() -> Self {
        let lc_all = std::env::var("LC_ALL").ok();
        let lc_messages = std::env::var("LC_MESSAGES").ok();
        let lang = std::env::var("LANG").ok();
        let requested: Vec<LanguageIdentifier> =
            resolve_env_locale([lc_all.as_deref(), lc_messages.as_deref(), lang.as_deref()])
                .into_iter()
                .collect();
        Self::new(&requested)
    }

    /// Builds a `Localizer` fixed to `en-US`, with no negotiation.
    #[must_use]
    pub fn en_us() -> Self {
        Self::from_files(EN_US_TAG, &en_us_files())
    }

    /// The negotiated locale tag this `Localizer` renders (e.g. `"en-US"`).
    #[must_use]
    pub const fn locale(&self) -> &'static str {
        self.tag
    }

    /// Renders `id` with no arguments, falling back to `en-US` and then to the bare
    /// id text (see the type docs).
    #[must_use]
    pub fn get(&self, id: &MessageId) -> String {
        self.resolve(id.as_str(), None)
    }

    /// Renders `id` substituting `args`, falling back to `en-US` and then to the
    /// bare id text (see the type docs). String arguments lose their control
    /// and bidi characters first, as in [`Localizer::render`].
    #[must_use]
    pub fn get_args(&self, id: &MessageId, args: &FluentArgs<'_>) -> String {
        let mut clean = FluentArgs::with_capacity(args.iter().count());
        for (key, value) in args.iter() {
            match value {
                FluentValue::String(text) => clean.set(key, sanitize_arg_value(text)),
                other => clean.set(key, other.clone()),
            }
        }
        self.resolve(id.as_str(), Some(&clean))
    }

    /// Whether `id` resolves to a real message (in the active locale or the `en-US`
    /// fallback), i.e. whether [`Localizer::get`]/[`Localizer::get_args`] would
    /// return translated text rather than degrading to the bare id.
    #[must_use]
    pub fn has(&self, id: &MessageId) -> bool {
        let id = id.as_str();
        message_has_value(&self.active, id)
            || self
                .fallback
                .as_ref()
                .is_some_and(|bundle| message_has_value(bundle, id))
    }

    /// Renders one diagnostic's message text, mapping `diagnostic.args` onto
    /// [`FluentArgs`]. Does not include severity, field, or span — callers that want
    /// those combine them with the rendered text themselves.
    #[must_use]
    pub fn render(&self, diagnostic: &Diagnostic) -> String {
        let args = fluent_args(&diagnostic.args);
        self.get_args(&diagnostic.id, &args)
    }

    /// Renders every diagnostic in `diagnostics`, in order.
    #[must_use]
    pub fn render_all(&self, diagnostics: &Diagnostics) -> Vec<String> {
        diagnostics.iter().map(|d| self.render(d)).collect()
    }

    /// Shared implementation of [`Localizer::get`]/[`Localizer::get_args`].
    fn resolve(&self, id: &str, args: Option<&FluentArgs<'_>>) -> String {
        if let Some(text) = render_from_bundle(&self.active, id, args) {
            return text;
        }
        if let Some(text) = self
            .fallback
            .as_ref()
            .and_then(|bundle| render_from_bundle(bundle, id, args))
        {
            return text;
        }
        id.to_owned()
    }
}

#[cfg(test)]
#[path = "../locale_scan.rs"]
mod locale_scan;

#[cfg(test)]
mod tests {
    use super::{
        ALIASES, CATALOGUE, EN_US_TAG, Localizer, Packed, build_bundle, negotiate,
        parse_posix_locale_value, resolve_env_locale, strip_bidi_isolation,
    };
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use fluent_bundle::{FluentArgs, FluentResource};
    use std::collections::{BTreeMap, BTreeSet};
    use unic_langid::LanguageIdentifier;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // ---- test-only helpers: message id extraction and parity checking ----
    //
    // These mirror what a Fluent parser would tell us about top-level message ids,
    // without depending on `fluent_syntax::ast` directly: `fluent-bundle` does not
    // re-export that module, so naming its `Entry`/`Message` types here would
    // require adding `fluent-syntax` to this crate's `Cargo.toml` as a direct
    // dependency, which is not among the dependencies this crate is scoped to use.
    // A message entry is an identifier (`[a-zA-Z][a-zA-Z0-9_-]*`) at column 0 of a
    // line, followed by optional whitespace and `=` — terms (`-id = …`), comments
    // (`#`/`##`/`###`), and indented pattern continuations never start a line with a
    // bare ASCII letter, so they are excluded by construction. Cross-checked against
    // the real Fluent parser by `all_locales_parse_cleanly` and
    // `fixture_locale_parses_cleanly` below.

    fn message_id_on_line(line: &str) -> Option<&str> {
        let mut chars = line.char_indices();
        let (_, first) = chars.next()?;
        if !first.is_ascii_alphabetic() {
            return None;
        }
        let end = chars
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
            .map_or(line.len(), |(i, _)| i);
        let id = line.get(..end)?;
        let rest = line.get(end..)?.trim_start();
        if rest.starts_with('=') {
            Some(id)
        } else {
            None
        }
    }

    #[test]
    fn message_id_on_line_covers_every_line_shape() {
        assert_eq!(message_id_on_line(""), None); // empty line
        assert_eq!(message_id_on_line("# a comment"), None); // comment, not alphabetic-start
        assert_eq!(message_id_on_line("-a-term = value"), None); // term, not alphabetic-start
        assert_eq!(message_id_on_line("    indented = continuation"), None); // not alphabetic-start
        assert_eq!(message_id_on_line("just some words"), None); // alphabetic-start, no `=`
        assert_eq!(message_id_on_line("hosts-name = hosts"), Some("hosts-name"));
        assert_eq!(message_id_on_line("hosts-name=hosts"), Some("hosts-name")); // no space before `=`
    }

    fn message_ids(source: &str) -> BTreeSet<&str> {
        source.lines().filter_map(message_id_on_line).collect()
    }

    fn locale_message_ids<'a>(files: &[&'a str]) -> BTreeSet<&'a str> {
        files.iter().flat_map(|f| message_ids(f)).collect()
    }

    /// Ids present in `reference` but not `other`, and ids present in `other` but not
    /// `reference` — both sorted, both empty when the two sets agree.
    fn id_parity(reference: &BTreeSet<&str>, other: &BTreeSet<&str>) -> (Vec<String>, Vec<String>) {
        let missing = reference
            .difference(other)
            .map(|s| (*s).to_owned())
            .collect();
        let extra = other
            .difference(reference)
            .map(|s| (*s).to_owned())
            .collect();
        (missing, extra)
    }

    // ---- catalogue-wide gate: every compiled-in locale matches en-US exactly ----

    #[test]
    fn catalogue_locales_have_id_parity_with_en_us() -> TestResult {
        let en_us = CATALOGUE
            .iter()
            .find(|l| l.tag == EN_US_TAG)
            .ok_or("en-US missing from CATALOGUE")?;
        let reference = locale_message_ids(&en_us.texts());
        for locale in CATALOGUE {
            let ids = locale_message_ids(&locale.texts());
            let (missing, extra) = id_parity(&reference, &ids);
            assert!(
                missing.is_empty() && extra.is_empty(),
                "{}: missing from locale {missing:?}, extra in locale (absent from en-US) {extra:?}",
                locale.tag,
            );
        }
        Ok(())
    }

    /// Placeable variable names (`{$name`) per message id: the variables from the
    /// message's own line through the indented or closing-brace lines after it.
    fn message_placeables<'a>(files: &[&'a str]) -> BTreeMap<&'a str, BTreeSet<&'a str>> {
        let mut out: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for file in files {
            let mut current: Option<&str> = None;
            for line in file.lines() {
                if let Some(id) = message_id_on_line(line) {
                    current = Some(id);
                    out.entry(id).or_default();
                } else if !(line.starts_with(char::is_whitespace) || line.starts_with('}')) {
                    current = None;
                }
                let Some(id) = current else { continue };
                for part in line.split("{$").skip(1) {
                    let end = part
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                        .unwrap_or(part.len());
                    if let (Some(set), Some(name)) = (out.get_mut(id), part.get(..end)) {
                        set.insert(name);
                    }
                }
            }
        }
        out
    }

    #[test]
    fn message_placeables_reads_selectors_and_continuation_lines() {
        let source = "a = {$x} {$y}\nb = plain\nc = {$n ->\n    [one] one\n   *[other] {$n} in {$w}\n}\n## {$no}\n";
        let got = message_placeables(&[source]);
        assert_eq!(got.get("a"), Some(&BTreeSet::from(["x", "y"])));
        assert_eq!(got.get("b"), Some(&BTreeSet::new()));
        assert_eq!(got.get("c"), Some(&BTreeSet::from(["n", "w"])));
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn catalogue_locales_use_the_same_placeables_as_en_us() -> TestResult {
        let en_us = CATALOGUE
            .iter()
            .find(|l| l.tag == EN_US_TAG)
            .ok_or("en-US missing from CATALOGUE")?;
        let reference = message_placeables(&en_us.texts());
        for locale in CATALOGUE {
            let got = message_placeables(&locale.texts());
            let drift: Vec<String> = reference
                .iter()
                .filter(|(id, vars)| got.get(*id).is_some_and(|other| other != *vars))
                .map(|(id, vars)| format!("{id}: expected {vars:?}, found {:?}", got.get(id)))
                .collect();
            assert!(drift.is_empty(), "{}: {drift:#?}", locale.tag);
        }
        Ok(())
    }

    #[test]
    fn web_messages_are_compiled_in_only_with_the_web_feature() {
        // `login-title` exists only in web.ftl.
        let id = MessageId::new("login-title");
        for tag in ["en-US", "de-DE", "ja-JP"] {
            let localizer = Localizer::new(&[langid(tag)]);
            assert_eq!(localizer.has(&id), cfg!(feature = "web"), "{tag}");
        }
    }

    /// The catalogue is exactly the locale directories: adding `locales/<tag>/`
    /// with the three files is the whole change, and a directory cannot be left out.
    #[test]
    fn catalogue_is_the_set_of_locale_directories() -> TestResult {
        let locales = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../locales");
        let on_disk = super::locale_scan::scan(&locales)?;
        let compiled: Vec<&str> = CATALOGUE.iter().map(|l| l.tag).collect();
        assert_eq!(compiled, on_disk);
        assert!(compiled.contains(&EN_US_TAG));
        for tag in &compiled {
            assert!(tag.parse::<LanguageIdentifier>().is_ok(), "{tag}");
            assert_eq!(
                tag.parse::<LanguageIdentifier>()?.to_string(),
                *tag,
                "the directory name must be the canonical tag"
            );
        }
        Ok(())
    }

    #[test]
    fn every_locale_lists_all_three_files() {
        for locale in CATALOGUE {
            // `web.ftl` is compiled in only with the `web` feature.
            let want = if cfg!(feature = "web") { 3 } else { 2 };
            assert_eq!(locale.files.len(), want, "{}", locale.tag);
        }
    }

    #[test]
    fn all_locales_parse_cleanly() {
        for locale in CATALOGUE {
            for (idx, file) in locale.texts().iter().enumerate() {
                let result = FluentResource::try_new((*file).to_owned());
                // Computed eagerly (not inside the `assert!` message, which `assert!`
                // only evaluates on failure) so this line reports covered even on the
                // expected, passing path.
                let parse_errors = result.as_ref().err().map(|(_, errors)| errors);
                assert!(result.is_ok(), "{}[{idx}]: {parse_errors:?}", locale.tag);
            }
        }
    }

    /// The compressed copy in the binary is the file on disk, byte for byte, for every
    /// locale: nothing is lost, reordered or cut by the pack and inflate round trip.
    #[test]
    fn embedded_files_inflate_to_the_files_on_disk() -> TestResult {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../locales");
        let names: Vec<&str> = super::locale_scan::REQUIRED_FILES
            .into_iter()
            .filter(|name| cfg!(feature = "web") || *name != "web.ftl")
            .collect();
        for locale in CATALOGUE {
            assert_eq!(locale.files.len(), names.len(), "{}", locale.tag);
            for (packed, name) in locale.files.iter().zip(&names) {
                let on_disk = std::fs::read_to_string(root.join(locale.tag).join(name))?;
                assert_eq!(packed.text(), on_disk, "{}/{name}", locale.tag);
                assert!(
                    packed.deflated.len() < on_disk.len(),
                    "{}/{name} did not shrink",
                    locale.tag
                );
            }
        }
        Ok(())
    }

    fn leak(bytes: Vec<u8>) -> &'static [u8] {
        Box::leak(bytes.into_boxed_slice())
    }

    #[test]
    fn text_is_inflated_on_first_use_and_only_once() {
        let source = "hello = Hello, world\n";
        let packed = Packed::new(
            source.len(),
            leak(miniz_oxide::deflate::compress_to_vec(source.as_bytes(), 10)),
        );
        assert!(!packed.is_inflated());
        let first = packed.text();
        assert_eq!(first, source);
        assert!(packed.is_inflated());
        assert!(
            std::ptr::eq(first, packed.text()),
            "the text was inflated twice"
        );
    }

    #[test]
    fn a_damaged_blob_gives_empty_text_and_never_panics() {
        let source = "hello = Hello, world\n";
        let good = miniz_oxide::deflate::compress_to_vec(source.as_bytes(), 10);
        // A length that is too short (over the cap) and too long (under-filled).
        for len in [source.len() - 1, source.len() + 1] {
            assert_eq!(Packed::new(len, leak(good.clone())).text(), "", "len {len}");
        }
        // Bytes that are not DEFLATE, and a truncated stream.
        assert_eq!(Packed::new(8, &[0xFF; 8]).text(), "");
        let cut = good.get(..good.len() / 2).unwrap_or_default().to_vec();
        assert_eq!(Packed::new(source.len(), leak(cut)).text(), "");
        // DEFLATE that holds bytes which are not UTF-8.
        let bad = miniz_oxide::deflate::compress_to_vec(&[0xC3, 0x28], 10);
        assert_eq!(Packed::new(2, leak(bad)).text(), "");
    }

    // ---- fixture-based proof that the parity mechanism catches both directions ----

    const PLOC_FIXTURE: &str = include_str!("../tests/fixtures/qps-ploc/core.ftl");

    #[test]
    fn fixture_locale_parses_cleanly() {
        let result = FluentResource::try_new(PLOC_FIXTURE.to_owned());
        let parse_errors = result.as_ref().err().map(|(_, errors)| errors);
        assert!(result.is_ok(), "{parse_errors:?}");
    }

    #[test]
    fn id_parity_catches_missing_and_extra_ids() -> TestResult {
        let en_us = CATALOGUE
            .iter()
            .find(|l| l.tag == EN_US_TAG)
            .ok_or("en-US missing from CATALOGUE")?;
        let reference = locale_message_ids(&en_us.texts());
        let ploc_ids = message_ids(PLOC_FIXTURE);

        let (missing, extra) = id_parity(&reference, &ploc_ids);

        assert!(
            !missing.is_empty(),
            "expected the fixture to be missing ids"
        );
        assert!(
            missing.iter().any(|id| id == "hosts-too-many-entries"),
            "expected hosts-too-many-entries to be reported missing, got {missing:?}"
        );
        assert_eq!(
            extra,
            vec!["qps-ploc-only-fixture-id".to_owned()],
            "expected exactly the deliberately-added id to be reported extra"
        );

        // And the reverse comparison (fixture as reference) reports nothing missing
        // from itself and nothing extra in itself: id_parity is symmetric plumbing,
        // not special-cased to en-US.
        let (self_missing, self_extra) = id_parity(&ploc_ids, &ploc_ids);
        assert!(self_missing.is_empty() && self_extra.is_empty());
        Ok(())
    }

    /// A `Localizer` whose active locale is the deliberately-partial `qps-ploc`
    /// fixture, with the real `en-US` catalogue entry attached as fallback exactly
    /// as `Localizer::new` would attach it to any non-`en-US` active locale. Built
    /// via the crate's own `from_files`/`build_bundle`, not hand-rolled, so this
    /// exercises the real fallback wiring end-to-end through the public API — the
    /// only way to do that today, since the real compiled `CATALOGUE` currently has
    /// only `en-US` and `Localizer::new` therefore always negotiates to `en-US`.
    static PLOC_FILES: [&str; 1] = [PLOC_FIXTURE];

    fn ploc_localizer() -> Localizer {
        Localizer::from_files("qps-ploc", &PLOC_FILES)
    }

    #[test]
    fn falls_back_to_en_us_for_id_missing_in_active_locale() {
        let localizer = ploc_localizer();
        assert_eq!(localizer.locale(), "qps-ploc");

        // Translated in the fixture: active locale wins.
        assert_eq!(localizer.get(&MessageId::new("hosts-name")), "[hosts]");

        // Not translated in the fixture: falls back to en-US's text. No `count` arg
        // is supplied, so the fallback message's placeholder renders as `{$count}`
        // (see get_args_missing_argument_renders_a_visible_placeholder for why).
        assert_eq!(
            localizer.get(&MessageId::new("hosts-too-many-entries")),
            "this file has {$count} entries; consider dns instead."
        );
    }

    #[test]
    fn has_is_true_via_fallback_and_false_for_unknown_id() {
        let localizer = ploc_localizer();
        assert!(localizer.has(&MessageId::new("hosts-name"))); // active
        assert!(localizer.has(&MessageId::new("hosts-too-many-entries"))); // fallback
        assert!(!localizer.has(&MessageId::new("does-not-exist-anywhere")));
    }

    // ---- negotiation ----

    fn langid(tag: &str) -> LanguageIdentifier {
        tag.parse().unwrap_or_default()
    }

    fn available(tags: &[&'static str]) -> Vec<(&'static str, LanguageIdentifier)> {
        tags.iter().map(|t| (*t, langid(t))).collect()
    }

    #[test]
    fn negotiate_exact_match() {
        let available = available(&["en-US", "de", "fr-CA"]);
        let requested = [langid("de")];
        assert_eq!(negotiate(&requested, &available), Some("de"));
    }

    #[test]
    fn negotiate_language_only_match() {
        let available = available(&["en-US", "de"]);
        let requested = [langid("de-AT")];
        assert_eq!(negotiate(&requested, &available), Some("de"));
    }

    #[test]
    fn negotiate_prefers_exact_over_language_only_across_requested_list() {
        // First requested locale only has a language-only match; second requested
        // locale has an exact match. Exact-match pass runs over the whole requested
        // list before the language-only pass, so the exact hit wins even though it
        // is second in priority.
        let available = available(&["en-US", "de"]);
        let requested = [langid("de-AT"), langid("en-US")];
        assert_eq!(negotiate(&requested, &available), Some("en-US"));
    }

    #[test]
    fn negotiate_no_match_returns_none() {
        let available = available(&["en-US"]);
        let requested = [langid("ja")];
        assert_eq!(negotiate(&requested, &available), None);
    }

    #[test]
    fn negotiate_empty_requested_returns_none() {
        let available = available(&["en-US"]);
        assert_eq!(negotiate(&[], &available), None);
    }

    /// The twelve locales the project ships (owner decision, 2026-10-10).
    const SHIPPED: [&str; 12] = [
        "bn-BD", "de-DE", "en-GB", "en-US", "es-ES", "fr-FR", "hi-IN", "ja-JP", "pt-BR", "ru-RU",
        "zh-CN", "zh-TW",
    ];

    #[test]
    fn regional_and_script_tags_negotiate_to_the_documented_locale() {
        let available = available(&SHIPPED);
        for (requested, expected) in [
            ("en", "en-US"),
            ("en-US", "en-US"),
            ("en-CA", "en-US"),
            ("en-GB", "en-GB"),
            ("en-AU", "en-GB"),
            ("en-NZ", "en-GB"),
            ("en-IE", "en-GB"),
            ("en-IN", "en-GB"),
            ("zh", "zh-CN"),
            ("zh-CN", "zh-CN"),
            ("zh-Hans", "zh-CN"),
            ("zh-Hans-CN", "zh-CN"),
            ("zh-SG", "zh-CN"),
            ("zh-TW", "zh-TW"),
            ("zh-Hant", "zh-TW"),
            ("zh-Hant-TW", "zh-TW"),
            ("zh-HK", "zh-TW"),
            ("zh-Hant-HK", "zh-TW"),
            ("zh-MO", "zh-TW"),
            ("zh-Hant-CN", "zh-TW"),
            ("pt", "pt-BR"),
            ("pt-PT", "pt-BR"),
            ("es", "es-ES"),
            ("es-MX", "es-ES"),
            ("es-419", "es-ES"),
            ("de", "de-DE"),
            ("de-AT", "de-DE"),
            ("de-CH", "de-DE"),
            ("fr", "fr-FR"),
            ("fr-CA", "fr-FR"),
            ("ja", "ja-JP"),
            ("ru", "ru-RU"),
            ("hi", "hi-IN"),
            ("bn", "bn-BD"),
            ("bn-IN", "bn-BD"),
        ] {
            assert_eq!(
                negotiate(&[langid(requested)], &available),
                Some(expected),
                "{requested}"
            );
        }
        // No Arabic or other right-to-left locale ships, so those fall through.
        for requested in ["ar", "ar-SA", "he", "ko-KR", "sv"] {
            assert_eq!(
                negotiate(&[langid(requested)], &available),
                None,
                "{requested}"
            );
        }
    }

    #[test]
    fn an_alias_to_a_locale_that_is_not_compiled_in_uses_the_language() {
        // Only the locales that ship today: en-GB and zh-TW are not there yet.
        let available = available(&["en-US", "de-DE", "zh-CN"]);
        for (requested, expected) in [("en-AU", "en-US"), ("zh-HK", "zh-CN"), ("zh-Hant", "zh-CN")]
        {
            assert_eq!(
                negotiate(&[langid(requested)], &available),
                Some(expected),
                "{requested}"
            );
        }
    }

    #[test]
    fn exact_matches_still_beat_aliases_across_the_requested_list() {
        let available = available(&SHIPPED);
        assert_eq!(
            negotiate(&[langid("zh-HK"), langid("en-US")], &available),
            Some("en-US")
        );
        assert_eq!(
            negotiate(&[langid("zh-HK"), langid("fr-CA")], &available),
            Some("zh-TW")
        );
    }

    #[test]
    fn every_alias_row_is_canonical_and_points_at_a_shipped_locale() {
        for (from, to) in ALIASES {
            assert_eq!(langid(from).to_string(), *from, "{from} is not canonical");
            assert!(SHIPPED.contains(to), "{from} -> {to} is not shipped");
        }
    }

    #[test]
    fn new_falls_back_to_en_us_when_nothing_compiled_matches() {
        let localizer = Localizer::new(&[langid("ko-KR"), langid("sv")]);
        assert_eq!(localizer.locale(), "en-US");
    }

    #[test]
    fn new_negotiates_the_shipped_translations() {
        assert_eq!(Localizer::new(&[langid("de")]).locale(), "de-DE");
        assert_eq!(Localizer::new(&[langid("de-AT")]).locale(), "de-DE");
        assert_eq!(Localizer::new(&[langid("ja-JP")]).locale(), "ja-JP");
        // The first requested locale that matches anything wins.
        assert_eq!(
            Localizer::new(&[langid("ko-KR"), langid("ja"), langid("de")]).locale(),
            "ja-JP"
        );
    }

    #[test]
    fn de_and_ja_render_translated_text_with_arguments() {
        let id = MessageId::new("hosts-invalid-hostname");
        let mut args = FluentArgs::new();
        args.set("name", "bad.host");
        for (tag, needle) in [("de-DE", "Hostname"), ("ja-JP", "ホスト名")] {
            let localizer = Localizer::new(&[langid(tag)]);
            let text = localizer.get_args(&id, &args);
            assert!(text.contains("`bad.host`"), "{tag}: {text:?}");
            assert!(text.contains(needle), "{tag}: {text:?}");
        }
    }

    #[test]
    fn de_and_ja_keep_the_bare_id_for_an_unknown_id() {
        for tag in ["de-DE", "ja-JP"] {
            let localizer = Localizer::new(&[langid(tag)]);
            let id = MessageId::new("no-such-message-id");
            assert!(!localizer.has(&id));
            assert_eq!(localizer.get(&id), "no-such-message-id");
        }
    }

    #[test]
    fn new_negotiates_exact_en_us() {
        let localizer = Localizer::new(&[langid("en-US")]);
        assert_eq!(localizer.locale(), "en-US");
    }

    #[test]
    fn en_us_constructor_has_no_separate_fallback_bundle() {
        let localizer = Localizer::en_us();
        assert_eq!(localizer.locale(), "en-US");
        assert!(localizer.fallback.is_none());
    }

    // ---- env parsing ----

    #[test]
    fn parse_posix_locale_value_plain_tag() -> TestResult {
        assert_eq!(parse_posix_locale_value("de-DE"), Some("de-DE".parse()?));
        Ok(())
    }

    #[test]
    fn parse_posix_locale_value_strips_codeset_and_modifier() -> TestResult {
        assert_eq!(
            parse_posix_locale_value("de_DE.UTF-8@euro"),
            Some("de-DE".parse()?)
        );
        assert_eq!(
            parse_posix_locale_value("de_DE.UTF-8"),
            Some("de-DE".parse()?)
        );
        assert_eq!(
            parse_posix_locale_value("de_DE@euro"),
            Some("de-DE".parse()?)
        );
        Ok(())
    }

    #[test]
    fn parse_posix_locale_value_ignores_c_and_posix() {
        assert_eq!(parse_posix_locale_value("C"), None);
        assert_eq!(parse_posix_locale_value("c"), None);
        assert_eq!(parse_posix_locale_value("POSIX"), None);
        assert_eq!(parse_posix_locale_value("posix"), None);
    }

    #[test]
    fn parse_posix_locale_value_empty_and_malformed() {
        assert_eq!(parse_posix_locale_value(""), None);
        assert_eq!(parse_posix_locale_value("   "), None);
        // A trailing '@'/'.' with nothing before it strips to empty.
        assert_eq!(parse_posix_locale_value("@euro"), None);
        assert_eq!(parse_posix_locale_value(".UTF-8"), None);
        // Contains characters no BCP-47 subtag can have.
        assert_eq!(parse_posix_locale_value("!!!not a locale!!!"), None);
    }

    #[test]
    fn resolve_env_locale_precedence_lc_all_wins() -> TestResult {
        let resolved = resolve_env_locale([Some("de-DE"), Some("fr-FR"), Some("ja-JP")]);
        assert_eq!(resolved, Some("de-DE".parse()?));
        Ok(())
    }

    #[test]
    fn resolve_env_locale_falls_through_c_posix_empty_and_unset() -> TestResult {
        // LC_ALL is "C" (ignored), LC_MESSAGES unset, LANG is usable.
        assert_eq!(
            resolve_env_locale([Some("C"), None, Some("ja-JP")]),
            Some("ja-JP".parse()?)
        );
        // LC_ALL empty, LC_MESSAGES "POSIX", LANG usable.
        assert_eq!(
            resolve_env_locale([Some(""), Some("POSIX"), Some("fr-CA")]),
            Some("fr-CA".parse()?)
        );
        // Nothing usable anywhere.
        assert_eq!(resolve_env_locale([None, Some("C"), Some("")]), None);
        Ok(())
    }

    #[test]
    fn for_env_does_not_panic() {
        // Exercises the real std::env::var reads; this crate cannot mutate process
        // environment (see resolve_env_locale's docs), so this only proves the
        // wrapper runs cleanly under whatever locale the test process actually has,
        // not a specific outcome. The precedence/parsing logic itself is covered
        // exhaustively above via resolve_env_locale.
        let localizer = Localizer::for_env();
        assert!(!localizer.locale().is_empty());
    }

    // ---- get / get_args / has / unknown id ----

    #[test]
    fn get_unknown_id_returns_the_id_itself() {
        let localizer = Localizer::en_us();
        assert_eq!(
            localizer.get(&MessageId::new("no-such-message-id")),
            "no-such-message-id"
        );
        assert!(!localizer.has(&MessageId::new("no-such-message-id")));
    }

    #[test]
    fn get_known_id_renders_text() {
        let localizer = Localizer::en_us();
        assert_eq!(localizer.get(&MessageId::new("hosts-name")), "hosts");
        assert!(localizer.has(&MessageId::new("hosts-name")));
    }

    #[test]
    fn get_args_substitutes_a_present_argument() {
        let localizer = Localizer::en_us();
        let mut args = FluentArgs::new();
        args.set("name", "bad.host");
        let text = localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &args);
        assert_eq!(text, "`bad.host` is not a valid hostname.");
    }

    #[test]
    fn get_args_missing_argument_renders_a_visible_placeholder() {
        let localizer = Localizer::en_us();
        let args = FluentArgs::new(); // hosts-invalid-hostname wants "name"; absent.
        let text = localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &args);
        assert_eq!(text, "`{$name}` is not a valid hostname.");
    }

    #[test]
    fn get_args_extra_argument_is_ignored() {
        let localizer = Localizer::en_us();
        let mut args = FluentArgs::new();
        args.set("name", "bad.host");
        args.set("unused_extra_arg", "ignored");
        let text = localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &args);
        assert_eq!(text, "`bad.host` is not a valid hostname.");
    }

    // ---- bidi isolation stripping ----

    #[test]
    fn strip_bidi_isolation_removes_fsi_pdi() {
        let marked = "`\u{2068}bad.host\u{2069}` is not a valid hostname.";
        assert_eq!(
            strip_bidi_isolation(marked),
            "`bad.host` is not a valid hostname."
        );
        assert_eq!(strip_bidi_isolation("no marks here"), "no marks here");
    }

    #[test]
    fn get_args_output_never_contains_bidi_isolation_marks() {
        let localizer = Localizer::en_us();
        let mut args = FluentArgs::new();
        args.set("name", "bad.host");
        let text = localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &args);
        assert!(!text.contains('\u{2068}'));
        assert!(!text.contains('\u{2069}'));
    }

    // ---- Diagnostic / Diagnostics rendering ----

    fn diagnostic_for(severity: Severity) -> Diagnostic {
        Diagnostic::new(severity, MessageId::new("hosts-invalid-hostname"))
            .with_arg("name", "bad.host")
    }

    #[test]
    fn render_works_for_every_severity() {
        let localizer = Localizer::en_us();
        for severity in [Severity::Error, Severity::Warning, Severity::Recommendation] {
            let text = localizer.render(&diagnostic_for(severity));
            assert_eq!(text, "`bad.host` is not a valid hostname.");
        }
    }

    #[test]
    fn render_all_preserves_order() {
        let localizer = Localizer::en_us();
        let diagnostics: Diagnostics = [
            Diagnostic::new(Severity::Error, MessageId::new("hosts-no-hostnames")),
            diagnostic_for(Severity::Warning),
        ]
        .into_iter()
        .collect();
        let rendered = localizer.render_all(&diagnostics);
        assert_eq!(
            rendered,
            vec![
                "this entry has no hostnames.".to_owned(),
                "`bad.host` is not a valid hostname.".to_owned(),
            ]
        );
    }

    #[test]
    fn render_all_empty_diagnostics_is_empty() {
        let localizer = Localizer::en_us();
        assert!(localizer.render_all(&Diagnostics::new()).is_empty());
    }

    #[test]
    fn render_unknown_id_degrades_to_the_id() {
        let localizer = Localizer::en_us();
        let diagnostic = Diagnostic::new(Severity::Error, MessageId::new("totally-unknown-id"));
        assert_eq!(localizer.render(&diagnostic), "totally-unknown-id");
    }

    // ---- build_bundle tolerates a malformed resource without panicking ----

    #[test]
    fn build_bundle_does_not_panic_on_malformed_ftl() {
        let files = ["this is not = = valid ftl {{{"];
        // Must not panic; whatever it manages to salvage is fine.
        let _bundle = build_bundle("en-US", &files);
    }

    #[test]
    fn get_args_neutralises_control_and_bidi_chars_in_args() {
        let localizer = Localizer::en_us();
        let mut args = FluentArgs::new();
        args.set("name", EVIL_ARG);
        let text = localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &args);
        for ch in EVIL_CHARS {
            assert!(
                !text.contains(ch),
                "get_args output still contains control/bidi char {ch:?}: {text:?}"
            );
        }
        assert_eq!(text, "`bad.host` is not a valid hostname.");

        // A number argument is passed through as a number.
        let mut numbers = FluentArgs::new();
        numbers.set("name", 42);
        assert_eq!(
            localizer.get_args(&MessageId::new("hosts-invalid-hostname"), &numbers),
            "`42` is not a valid hostname."
        );
    }

    /// C0, DEL, C1 and every Unicode bidi control, then a payload.
    const EVIL_ARG: &str = "\u{00}\u{01}\u{1B}\u{1F}\u{7F}\u{80}\u{9B}\u{9F}\u{061C}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}bad.host";
    const EVIL_CHARS: [char; 20] = [
        '\u{00}', '\u{01}', '\u{1B}', '\u{1F}', '\u{7F}', '\u{80}', '\u{9B}', '\u{9F}', '\u{061C}',
        '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
        '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];

    #[test]
    fn render_neutralises_control_and_bidi_chars_in_args() {
        let localizer = Localizer::en_us();
        let evil_real = "\u{00}\u{01}\u{1F}\u{7F}\u{80}\u{9F}\u{061C}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}bad.host";
        let diagnostic = Diagnostic::new(Severity::Error, MessageId::new("hosts-invalid-hostname"))
            .with_arg("name", evil_real);
        let text = localizer.render(&diagnostic);
        for ch in [
            '\u{00}', '\u{01}', '\u{1F}', '\u{7F}', '\u{80}', '\u{9F}', '\u{061C}', '\u{200E}',
            '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}',
            '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert!(
                !text.contains(ch),
                "render output still contains control/bidi char {ch:?}"
            );
        }
        assert!(
            text.contains("bad.host"),
            "sanitised output lost payload: {text:?}"
        );
    }
}
