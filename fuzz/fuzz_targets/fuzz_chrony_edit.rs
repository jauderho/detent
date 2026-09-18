//! `fuzz_chrony_edit`: an arbitrary document edited with an arbitrary model
//! reads back exactly that model (invariant 3), whatever the starting document
//! looked like.

#![no_main]

use arbitrary::Arbitrary;
use detent_core::module::ConfigModule;
use detent_module_chrony::{ChronyModule, Model};
use libfuzzer_sys::fuzz_target;

/// One fuzz case: an arbitrary starting document and the model to apply to it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    source: &'a str,
    model: Model,
}

fuzz_target!(|input: Input| {
    let Ok(mut doc) = ChronyModule::parse(input.source) else {
        return;
    };
    if ChronyModule::apply(&mut doc, &input.model).is_err() {
        return;
    }
    let rendered = ChronyModule::render(&doc);
    let Ok(reparsed) = ChronyModule::parse(&rendered) else {
        panic!("re-parse of applied document failed for {rendered:?}");
    };
    let Ok(model_again) = ChronyModule::to_model(&reparsed) else {
        panic!("to_model after apply failed for {rendered:?}");
    };
    assert_eq!(
        model_again, input.model,
        "to_model(parse(render(apply(doc, m)))) != m"
    );
});
