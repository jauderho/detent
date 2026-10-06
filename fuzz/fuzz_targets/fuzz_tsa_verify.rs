//! `fuzz_tsa_verify`: an RFC 3161 timestamp response arrives inside a
//! downloaded Sigstore bundle, so `verify_timestamp` must refuse malformed
//! DER with `Err`, never panic. Random input never carries a valid signature
//! by the embedded timestamp authority, so it must never verify either.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(trust) = detent_update::trust::embedded() else {
        return;
    };
    for tsa in &trust.tsas {
        assert!(detent_update::tsa::verify_timestamp(data, b"fuzz", tsa).is_err());
    }
});
