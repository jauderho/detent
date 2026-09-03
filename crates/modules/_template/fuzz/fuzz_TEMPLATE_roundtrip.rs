//! `fuzz_TEMPLATE_roundtrip`: a document's own model, applied back to it, survives
//! a render/parse/to_model round trip unchanged (invariants 2–4 together).
//!
//! TODO(fuzz): see the header of `fuzz_TEMPLATE_parse.rs` for the move-and-rename
//! steps. Nothing in the body below is format-specific.

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_TEMPLATE::TemplateModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(mut doc) = TemplateModule::parse(src) else {
        return;
    };
    let Ok(model) = TemplateModule::to_model(&doc) else {
        return;
    };
    if TemplateModule::apply(&mut doc, &model).is_err() {
        return;
    }
    let rendered = TemplateModule::render(&doc);
    let Ok(reparsed) = TemplateModule::parse(&rendered) else {
        panic!("re-parse of rendered text failed for {rendered:?}");
    };
    let Ok(model_again) = TemplateModule::to_model(&reparsed) else {
        panic!("to_model after re-parse failed for {rendered:?}");
    };
    assert_eq!(
        model_again, model,
        "to_model(parse(render(apply(doc, to_model(doc))))) != to_model(doc)"
    );
});
