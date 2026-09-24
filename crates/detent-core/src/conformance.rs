//! The six invariants every [`ConfigModule`] must satisfy, as reusable checks plus a
//! macro that wires them into a module crate's test suite.
//!
//! Each check returns `Result<(), String>` instead of panicking, so a caller can use
//! `assert_eq!(check(..), Ok(()))` and get the explanation in the failure message
//! whether it runs inside `#[test]` or inside `proptest!`.
//!
//! # Usage
//!
//! Add `proptest` to the module crate's `[dev-dependencies]`, then:
//!
//! ```ignore
//! detent_core::module_conformance!(
//!     HostsModule,
//!     fixtures = [include_str!("../../../fixtures/hosts/glibc/hosts")],
//!     model_strategy = crate::model_strategy(),
//!     injection_probes = [crate::probe_with_newline(), crate::probe_with_nul()],
//! );
//! ```

use crate::descriptor::{HostProfile, ValidationCtx};
use crate::module::ConfigModule;

/// Whether a conformance check's central assertion actually ran, or the input
/// had no representable model and was skipped.
///
/// [`check_apply_is_noop`], [`check_edit_fidelity`] and [`check_idempotent`]
/// each skip an input `to_model`/`apply` cannot use, so they can report `Ok`
/// without ever exercising the module. Reporting which happened is what lets
/// [`check_not_vacuous`] tell a genuinely-passing suite from a vacuously
/// passing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exercised {
    /// The check's central assertion ran.
    Yes,
    /// The input was skipped: it had no representable model, or the module
    /// refused to apply it.
    No,
}

/// Inputs every module is checked against by name, chosen to break naive parsers:
/// empty input, missing trailing newline, mixed and lone terminators, embedded NUL,
/// and non-ASCII text.
#[must_use]
pub fn adversarial_inputs() -> &'static [&'static str] {
    &[
        "",
        "\n",
        "\r",
        "\r\n",
        "\n\r\n\n",
        " ",
        "\t\t",
        "x",
        "x\n",
        "x\r\n",
        "x\ry\n",
        "\0",
        "x\0y\n",
        "# comment only\n",
        "  # indented comment\r\n\r\n",
        "é日\n\n",
        "a\nb\r\nc\n\nd",
    ]
}

/// Deterministic pseudo-random text of at least `len` bytes, built from a fixed
/// linear congruential generator so a failure always reproduces.
///
/// The alphabet mixes delimiters, terminators, NUL, non-ASCII text, and
/// newline-heavy text. The last two entries ensure generated source is
/// genuinely multi-line rather than relying on proptest's random choice of `\n`.
#[must_use]
pub fn pseudo_random_input(len: usize, seed: u64) -> String {
    const ALPHABET: [char; 16] = [
        'a', 'Z', '0', ' ', '\t', '#', '=', ':', '"', '\\', '/', '\n', '\r', '\0', 'é', '日',
    ];
    const MULTILINE: &str = "first line\nsecond line\nthird line\n";
    let mut state = seed;
    let mut out = String::with_capacity(len.saturating_add(MULTILINE.len()));
    if len > 0 {
        out.push_str(MULTILINE);
    }
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let index = usize::try_from((state >> 33) & 0x0f).unwrap_or(0);
        out.push(ALPHABET.get(index).copied().unwrap_or('a'));
    }
    out
}

/// Invariant 1: `render(parse(s)) == s`.
///
/// # Errors
///
/// The rendered text differs from the input, or `parse` rejected the input at all —
/// `parse` is contractually total.
pub fn check_render_parse_roundtrip<M: ConfigModule>(src: &str) -> Result<(), String> {
    let doc = M::parse(src).map_err(|e| format!("{}: parse failed: {e}", M::ID))?;
    let rendered = M::render(&doc);
    if rendered != src {
        return Err(format!(
            "{}: render(parse(s)) != s: {rendered:?} != {src:?}",
            M::ID
        ));
    }
    Ok(())
}

/// Invariant 2: applying a document's own model back to it changes nothing, and says
/// so in its [`EditReport`](crate::module::EditReport).
///
/// Documents whose semantics the model cannot express are skipped, since there is no
/// model to apply.
///
/// # Errors
///
/// `apply` failed, changed the text, or reported edits it did not make.
pub fn check_apply_is_noop<M: ConfigModule>(src: &str) -> Result<Exercised, String> {
    let mut doc = M::parse(src).map_err(|e| format!("{}: parse failed: {e}", M::ID))?;
    let Ok(model) = M::to_model(&doc) else {
        return Ok(Exercised::No);
    };
    let before = M::render(&doc);
    let report = M::apply(&mut doc, &model)
        .map_err(|e| format!("{}: apply(doc, to_model(doc)) failed: {e}", M::ID))?;
    let after = M::render(&doc);
    if after != before {
        return Err(format!(
            "{}: apply(doc, to_model(doc)) changed the document",
            M::ID
        ));
    }
    if report != crate::module::EditReport::default() {
        return Err(format!(
            "{}: apply(doc, to_model(doc)) reported {report:?}",
            M::ID
        ));
    }
    Ok(Exercised::Yes)
}

/// Invariant 3: `to_model(apply(parse(s), m)) == m`.
///
/// Models the module refuses to apply are skipped; rejection is invariant 5's
/// business, not this one's.
///
/// # Errors
///
/// The model read back from the edited document differs from the one applied.
pub fn check_edit_fidelity<M: ConfigModule>(
    src: &str,
    model: &M::Model,
) -> Result<Exercised, String> {
    let mut doc = M::parse(src).map_err(|e| format!("{}: parse failed: {e}", M::ID))?;
    if M::apply(&mut doc, model).is_err() {
        return Ok(Exercised::No);
    }
    let back =
        M::to_model(&doc).map_err(|e| format!("{}: to_model after apply failed: {e}", M::ID))?;
    if &back != model {
        return Err(format!(
            "{}: to_model(apply(doc, m)) != m: {back:?} != {model:?}",
            M::ID
        ));
    }
    Ok(Exercised::Yes)
}

/// Invariant 4: an edited document's rendered output re-parses to an equal document.
///
/// # Errors
///
/// The re-parsed document differs from the one that produced the text.
pub fn check_idempotent<M: ConfigModule>(src: &str, model: &M::Model) -> Result<Exercised, String> {
    let mut doc = M::parse(src).map_err(|e| format!("{}: parse failed: {e}", M::ID))?;
    if M::apply(&mut doc, model).is_err() {
        return Ok(Exercised::No);
    }
    let rendered = M::render(&doc);
    let reparsed = M::parse(&rendered)
        .map_err(|e| format!("{}: reparse of rendered text failed: {e}", M::ID))?;
    if reparsed != doc {
        return Err(format!(
            "{}: parse(render(doc)) != doc for {rendered:?}",
            M::ID
        ));
    }
    Ok(Exercised::Yes)
}

/// Invariant 5: a model carrying `\n`, `\r` or NUL in a value must be rejected by
/// `apply`, never written out raw.
///
/// # Errors
///
/// `apply` accepted the probe.
pub fn check_injection_rejected<M: ConfigModule>(
    src: &str,
    probe: &M::Model,
) -> Result<(), String> {
    let mut doc = M::parse(src).map_err(|e| format!("{}: parse failed: {e}", M::ID))?;
    let profile = HostProfile::default_for_tests();
    let diagnostics = M::validate(probe, &ValidationCtx::new(&profile));
    if M::apply(&mut doc, probe).is_ok() {
        return Err(format!(
            "{}: apply accepted an injection probe: {probe:?}; validation returned {diagnostics:?}",
            M::ID
        ));
    }
    let rendered = M::render(&doc);
    M::parse(&rendered).map_err(|e| {
        format!(
            "{}: rejecting an injection probe left unparsable text {rendered:?}: {e}",
            M::ID
        )
    })?;
    Ok(())
}

/// Add an embedded newline to the first string in a serialized model.
///
/// Returns `None` for models with no string field. The conformance macro uses
/// this to exercise invariant 5 with generated models rather than only fixed
/// hand-written probes.
#[must_use]
pub fn with_embedded_newline<M: ConfigModule>(model: &M::Model) -> Option<M::Model> {
    fn inject(value: &mut serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(text) => {
                text.push_str("\nsecond line");
                true
            }
            serde_json::Value::Array(items) => items.iter_mut().any(inject),
            serde_json::Value::Object(fields) => fields.values_mut().any(inject),
            _ => false,
        }
    }

    let mut value = serde_json::to_value(model).ok()?;
    if !inject(&mut value) {
        return None;
    }
    serde_json::from_value(value).ok()
}

/// Invariant 6: `parse` handles 1 MiB of adversarial input without hanging or
/// panicking, and still round-trips it.
///
/// There is no timing assertion: a super-linear parser fails by exhausting the test
/// harness timeout, which is what the fuzz job measures properly.
///
/// # Errors
///
/// The 1 MiB input did not round-trip.
pub fn check_bounded_parse<M: ConfigModule>(seed: u64) -> Result<(), String> {
    let input = pseudo_random_input(1024 * 1024, seed);
    check_render_parse_roundtrip::<M>(&input)
}

/// Whether the conformance suite actually exercised the module, rather than
/// passing because every check found nothing to check.
///
/// Requires at least one of `fixtures` to produce a model `apply` accepts (so
/// invariant 2 ran for real at least once — a fixture the module cannot
/// represent, such as one testing the "no model" skip path, is allowed among
/// the rest), and requires `M::defaults(profile)` to apply cleanly to an empty
/// document and read back unchanged. A module that refuses every edit fails
/// this even though it may satisfy invariants 1–6 vacuously.
///
/// # Errors
///
/// A fixture with a representable model was rejected by its own `apply`, no
/// fixture had a representable model at all, or the module's own defaults
/// could not be applied to an empty document and read back unchanged.
pub fn check_not_vacuous<M: ConfigModule>(
    fixtures: &[&str],
    profile: &HostProfile,
) -> Result<(), String> {
    let mut any_exercised = false;
    for fixture in fixtures {
        if check_apply_is_noop::<M>(fixture)? == Exercised::Yes {
            any_exercised = true;
        }
    }
    if !any_exercised {
        return Err(format!(
            "{}: no fixture had a representable model; apply was never exercised",
            M::ID
        ));
    }

    let defaults = M::defaults(profile);
    let mut doc = M::parse("").map_err(|e| format!("{}: parse(\"\") failed: {e}", M::ID))?;
    M::apply(&mut doc, &defaults)
        .map_err(|e| format!("{}: apply(parse(\"\"), defaults) failed: {e}", M::ID))?;
    let back = M::to_model(&doc)
        .map_err(|e| format!("{}: to_model after applying defaults failed: {e}", M::ID))?;
    if back != defaults {
        return Err(format!(
            "{}: to_model(apply(parse(\"\"), defaults)) != defaults",
            M::ID
        ));
    }
    Ok(())
}

/// Generates the conformance test suite for a [`ConfigModule`].
///
/// Expands to a `#[cfg(test)] mod module_conformance` containing one test per
/// invariant. Invariants 1–4 are also driven by `proptest`, so the calling crate must
/// have `proptest` in its `[dev-dependencies]`.
///
/// # Parameters
///
/// * `$module` — the type implementing [`ConfigModule`](crate::module::ConfigModule).
/// * `fixtures` — `&'static str` slices of real upstream config files, normally
///   `include_str!`; the macro does no I/O.
/// * `model_strategy` — an expression producing a `proptest` `Strategy` of valid
///   models.
/// * `injection_probes` — expressions producing models whose values contain `\n`,
///   `\r` or NUL. At least one is required.
///
/// # Examples
///
/// ```ignore
/// detent_core::module_conformance!(
///     KvModule,
///     fixtures = [include_str!("fixture.conf")],
///     model_strategy = model_strategy(),
///     injection_probes = [probe("a\nb")],
/// );
/// ```
#[macro_export]
macro_rules! module_conformance {
    (
        $module:ty,
        fixtures = [$($fixture:expr),* $(,)?],
        model_strategy = $strategy:expr,
        injection_probes = [$($probe:expr),+ $(,)?] $(,)?
    ) => {
        #[cfg(test)]
        mod module_conformance {
            use super::*;

            fn conformance_cases() -> Vec<&'static str> {
                let mut cases = $crate::conformance::adversarial_inputs().to_vec();
                cases.extend_from_slice(&[$($fixture,)*]);
                cases
            }

            #[test]
            fn invariant_1_render_parse_roundtrip() {
                for case in conformance_cases() {
                    let r = $crate::conformance::check_render_parse_roundtrip::<$module>(case);
                    assert_eq!(r, Ok(()));
                }
            }

            #[test]
            fn invariant_2_apply_of_own_model_is_a_noop() {
                for case in conformance_cases() {
                    let r = $crate::conformance::check_apply_is_noop::<$module>(case);
                    assert!(r.is_ok(), "{r:?}");
                }
            }

            #[test]
            fn conformance_is_not_vacuous() {
                let fixtures = [$($fixture,)*];
                let profile = $crate::descriptor::HostProfile::default_for_tests();
                let r = $crate::conformance::check_not_vacuous::<$module>(&fixtures, &profile);
                assert_eq!(r, Ok(()));
            }

            #[test]
            fn invariant_5_injection_probes_are_rejected() {
                for probe in [$($probe,)+] {
                    for case in conformance_cases() {
                        let r = $crate::conformance::check_injection_rejected::<$module>(case, &probe);
                        assert_eq!(r, Ok(()));
                    }
                }
            }

            #[test]
            fn invariant_6_one_mib_of_adversarial_input() {
                let r = $crate::conformance::check_bounded_parse::<$module>(0x5eed_0000_1234_abcd);
                assert_eq!(r, Ok(()));
            }



            ::proptest::proptest! {
                #[test]
                fn invariant_1_render_parse_roundtrip_prop(src in ".*") {
                    let r = $crate::conformance::check_render_parse_roundtrip::<$module>(&src);
                    ::proptest::prop_assert_eq!(r, Ok(()));
                }

                #[test]
                fn invariant_2_apply_of_own_model_is_a_noop_prop(src in ".*") {
                    let r = $crate::conformance::check_apply_is_noop::<$module>(&src);
                    ::proptest::prop_assert!(r.is_ok());
                }

                #[test]
                fn invariant_3_edit_fidelity_prop(src in ".*", model in $strategy) {
                    let r = $crate::conformance::check_edit_fidelity::<$module>(&src, &model);
                    ::proptest::prop_assert!(r.is_ok());
                }

                #[test]
                fn invariant_4_render_reparse_idempotence_prop(src in ".*", model in $strategy) {
                    let r = $crate::conformance::check_idempotent::<$module>(&src, &model);
                    ::proptest::prop_assert!(r.is_ok());
                }

                #[test]
                fn generated_models_cover_embedded_newlines(model in $strategy) {
                    let Some(probe) = $crate::conformance::with_embedded_newline::<$module>(&model) else {
                        return Err(::proptest::test_runner::TestCaseError::reject(
                            "model has no string field",
                        ));
                    };
                    for case in conformance_cases() {
                        let result = $crate::conformance::check_injection_rejected::<$module>(case, &probe);
                        ::proptest::prop_assert!(result.is_ok());
                    }
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{adversarial_inputs, pseudo_random_input};

    #[test]
    fn adversarial_inputs_cover_the_hard_cases() {
        let cases = adversarial_inputs();
        assert!(cases.contains(&""));
        assert!(cases.iter().any(|s| s.contains('\0')));
        assert!(cases.iter().any(|s| s.contains("\r\n")));
        assert!(cases.iter().any(|s| !s.ends_with('\n') && !s.is_empty()));
        assert!(cases.iter().any(|s| s.matches('\n').count() >= 2));
    }

    #[test]
    fn pseudo_random_input_is_deterministic_and_sized() {
        let a = pseudo_random_input(4096, 1);
        assert_eq!(a, pseudo_random_input(4096, 1));
        assert_ne!(a, pseudo_random_input(4096, 2));
        assert!(a.len() >= 4096);
        assert!(!a.contains('!'));
        assert!(a.contains('\n'));
        assert_eq!(pseudo_random_input(0, 1), "");
        assert!(a.matches('\n').count() >= 2);
    }
}
