//! `fuzz_samba_roundtrip`: a document's own model, applied back to it, survives a
//! render/parse/to_model round trip unchanged (invariants 2–4 together).

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_samba::SambaModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(mut doc) = SambaModule::parse(src) else {
        return;
    };
    let Ok(model) = SambaModule::to_model(&doc) else {
        return;
    };
    if SambaModule::apply(&mut doc, &model).is_err() {
        return;
    }
    let rendered = SambaModule::render(&doc);
    let Ok(reparsed) = SambaModule::parse(&rendered) else {
        panic!("re-parse of rendered text failed for {rendered:?}");
    };
    let Ok(model_again) = SambaModule::to_model(&reparsed) else {
        panic!("to_model after re-parse failed for {rendered:?}");
    };
    assert_eq!(
        model_again, model,
        "to_model(parse(render(apply(doc, to_model(doc))))) != to_model(doc)"
    );
});
