//! `fuzz_TEMPLATE_parse`: `TemplateModule::parse` never panics on arbitrary bytes,
//! and whatever it produces renders back to exactly the bytes it was given
//! (invariant 1).
//!
//! TODO(fuzz): move this file to `fuzz/fuzz_targets/` with `TEMPLATE` replaced by
//! the module id (see crates/modules/_template/README.md), add the `[[bin]]` entry
//! and the path dependency in `fuzz/Cargo.toml`, and seed
//! `fuzz/corpus/fuzz_<id>_parse/` from `fixtures/<id>/`.

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_template::TemplateModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = TemplateModule::parse(src) else {
        return;
    };
    assert_eq!(TemplateModule::render(&doc), src, "render(parse(s)) != s");
});
