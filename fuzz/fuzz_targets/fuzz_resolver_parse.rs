//! `fuzz_resolver_parse`: `ResolverModule::parse` never panics on arbitrary bytes,
//! and whatever it produces renders back to exactly the bytes it was given
//! (invariant 1).

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_resolver::ResolverModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = ResolverModule::parse(src) else {
        return;
    };
    assert_eq!(ResolverModule::render(&doc), src, "render(parse(s)) != s");
});
