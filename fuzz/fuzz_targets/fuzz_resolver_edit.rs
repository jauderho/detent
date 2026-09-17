//! `fuzz_resolver_edit`: an arbitrary document edited with an arbitrary model
//! reads back exactly that model (invariant 3), whatever the starting document
//! looked like. The module crate's hand-written `Arbitrary` impls emit
//! format-shaped values, so most cases reach `apply` instead of its rejection
//! path.

#![no_main]

use arbitrary::Arbitrary;
use detent_core::module::ConfigModule;
use detent_module_resolver::{Model, ResolverModule};
use libfuzzer_sys::fuzz_target;

/// One fuzz case: an arbitrary starting document and the model to apply to it.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    source: &'a str,
    model: Model,
}

fuzz_target!(|input: Input| {
    let Ok(mut doc) = ResolverModule::parse(input.source) else {
        return;
    };
    if ResolverModule::apply(&mut doc, &input.model).is_err() {
        return;
    }
    let rendered = ResolverModule::render(&doc);
    let Ok(reparsed) = ResolverModule::parse(&rendered) else {
        panic!("re-parse of applied document failed for {rendered:?}");
    };
    let Ok(model_again) = ResolverModule::to_model(&reparsed) else {
        panic!("to_model after apply failed for {rendered:?}");
    };
    assert_eq!(
        model_again, input.model,
        "to_model(parse(render(apply(doc, m)))) != m"
    );
});
