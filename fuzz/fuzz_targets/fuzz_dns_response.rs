//! `fuzz_dns_response`: DNS provider list/RRset bodies arrive from provider
//! APIs over the network, so malformed JSON must map to `Err`, never to a
//! panic; the RFC 2136 message builder must likewise refuse oversized input
//! with `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Split once: the body under test and the TXT value it is searched for.
    let (body, value) = match text.find('\0') {
        Some(i) => (&text[..i], &text[i + 1..]),
        None => (text, "digest-value-42"),
    };
    detent_acme::fuzz_provider_response(body, value);
});
