//! `fuzz_acme_json`: RFC 8555 order/authorization/problem JSON as served by
//! the CA must parse to `Ok` on valid shapes and `Err` — never a panic — on
//! arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    detent_acme::fuzz_acme_json(data);
});
