//! `fuzz_bundle_parse`: a Sigstore bundle is downloaded from the release
//! server, so `bundle::parse` must refuse malformed input with `Err`, never
//! panic; a bundle that parses must go through `verify` against the embedded
//! trust root without a panic either.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(decoded) = detent_update::bundle::parse(data) else {
        return;
    };
    let Ok(trust) = detent_update::trust::embedded() else {
        return;
    };
    let _ = detent_update::verify::verify(&decoded, &[0; 32], "v0.0.1-rc.2", &trust);
});
