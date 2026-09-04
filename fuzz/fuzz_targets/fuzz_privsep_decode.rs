//! `fuzz_privsep_decode`: `decode` never panics on arbitrary bytes for either
//! [`Request`] or [`Response`], and a value that did decode survives an
//! encode/decode round trip unchanged.

#![no_main]

use detent_platform::privsep::proto::{Request, Response, decode, encode};
use libfuzzer_sys::fuzz_target;

fn check<T>(data: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let Ok(value) = decode::<T>(data) else {
        return;
    };
    // `data` is bounded by `MAX_FRAME` (checked inside `decode`), but a
    // freshly built value re-encoding larger than that would still not be a
    // panic, just an oversize report; skip it rather than asserting success.
    let Ok(reencoded) = encode(&value) else {
        return;
    };
    let Ok(again) = decode::<T>(&reencoded) else {
        panic!("re-decoding a message this process just encoded failed");
    };
    assert_eq!(again, value, "encode(decode(x)) did not round-trip");
}

fuzz_target!(|data: &[u8]| {
    check::<Request>(data);
    check::<Response>(data);
});
