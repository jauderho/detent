//! `fuzz_dhcp_parse`: `DhcpModule::parse` never panics on arbitrary bytes,
//! and whatever it produces renders back to exactly the bytes it was given
//! (invariant 1).

#![no_main]

use detent_core::module::ConfigModule;
use detent_module_dhcp::DhcpModule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = DhcpModule::parse(src) else {
        return;
    };
    assert_eq!(DhcpModule::render(&doc), src, "render(parse(s)) != s");
});
