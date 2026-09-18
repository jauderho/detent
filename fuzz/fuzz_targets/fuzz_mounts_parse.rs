//! `fuzz_mounts_parse`: `MountsModule::parse` never panics on arbitrary bytes,
//! and whatever it produces renders back to exactly the bytes it was given
//! (invariant 1).

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_mounts::MountsModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = MountsModule::parse(src) else {
        return;
    };
    assert_eq!(MountsModule::render(&doc), src, "render(parse(s)) != s");
});
