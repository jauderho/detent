//! `fuzz_TEMPLATE_edit`: an arbitrary document edited with an arbitrary model
//! reads back exactly that model (invariant 3), whatever the starting document
//! looked like.
//!
//! TODO(fuzz): see the header of `fuzz_TEMPLATE_parse.rs` for the move-and-rename
//! steps. This target is the one that needs the module crate's `fuzzing` feature:
//! `detent-module-<id> = { path = "../crates/modules/<id>", features = ["fuzzing"] }`.
//! If the run reports most cases rejected by `apply`, hand-write `Arbitrary` for
//! the model so it emits format-shaped values (see `hosts`).

#![no_main]

use arbitrary::Arbitrary;
use detent_core::module::ConfigModule;
use detent_module_TEMPLATE::{Model, TemplateModule};
use libfuzzer_sys::fuzz_target;

/// One fuzz case: an arbitrary starting document and the model to apply to it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    source: &'a str,
    model: Model,
}

fuzz_target!(|input: Input| {
    let Ok(mut doc) = TemplateModule::parse(input.source) else {
        return;
    };
    if TemplateModule::apply(&mut doc, &input.model).is_err() {
        return;
    }
    let rendered = TemplateModule::render(&doc);
    let Ok(reparsed) = TemplateModule::parse(&rendered) else {
        panic!("re-parse of applied document failed for {rendered:?}");
    };
    let Ok(model_again) = TemplateModule::to_model(&reparsed) else {
        panic!("to_model after apply failed for {rendered:?}");
    };
    assert_eq!(
        model_again, input.model,
        "to_model(parse(render(apply(doc, m)))) != m"
    );
});
