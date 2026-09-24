//! `fuzz_network_edit`: an arbitrary document edited with an arbitrary model
//! reads back exactly that model (invariant 3), whatever the starting document
//! looked like.

#![no_main]

use arbitrary::Arbitrary;
use detent_core::descriptor::{HostProfile, ValidationCtx};
use detent_core::module::ConfigModule;
use detent_module_network::{Model, NetworkModule};
use libfuzzer_sys::fuzz_target;

/// One fuzz case: an arbitrary starting document and the model to apply to it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    source: &'a str,
    model: Model,
}

fuzz_target!(|input: Input| {
    let Ok(mut doc) = NetworkModule::parse(input.source) else {
        return;
    };
    if NetworkModule::validate(
        &input.model,
        &ValidationCtx::new(&HostProfile::default_for_tests()),
    )
    .has_errors()
    {
        return;
    }
    if NetworkModule::apply(&mut doc, &input.model).is_err() {
        return;
    }
    let rendered = NetworkModule::render(&doc);
    let Ok(reparsed) = NetworkModule::parse(&rendered) else {
        panic!("re-parse of applied document failed for {rendered:?}");
    };
    let Ok(model_again) = NetworkModule::to_model(&reparsed) else {
        panic!("to_model after apply failed for {rendered:?}");
    };
    assert_eq!(
        model_again, input.model,
        "to_model(parse(render(apply(doc, m)))) != m"
    );
});
