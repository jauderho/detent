//! Tests for `libdetent`. Each test exercises one or more C ABI entry points
//! end-to-end against the `hosts` module, which is the only one that
//! implements `ConfigModule` in Phase 1. The C example in `examples/ffi-c/`
//! covers the same flows against the C ABI itself.

#![allow(clippy::expect_used, clippy::unwrap_used, unsafe_code)]

use detent_ffi::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

const FIXTURE: &str = include_str!("../../../fixtures/hosts/glibc-2.42/debian-default.hosts");

fn c_str(s: &str) -> CString {
    // No NUL: input is a compile-time-literal ASCII file path.
    let bytes = s.as_bytes().to_vec();
    let mut with_nul = bytes;
    with_nul.push(0);
    // SAFETY: caller supplies a NUL-free ASCII string; the appended byte
    // keeps `from_vec_with_nul` honest.
    unsafe { CString::from_vec_with_nul_unchecked(with_nul) }
}

fn cstr_len(s: &CString) -> usize {
    // CString excludes the trailing NUL; matches `c_char`-sliced FFI lengths.
    s.as_bytes().len()
}

fn ptr_to_chars(p: *mut c_char) -> CString {
    // SAFETY: `p` came from one of our returning functions, which are
    // NUL-terminated and exclusively ours. `detent_free` would clobber it
    // for tests that retain, so we copy into a fresh owned CString.
    if p.is_null() {
        CString::new("").unwrap_or_else(|_| unreachable!("empty has no NUL"))
    } else {
        unsafe { CStr::from_ptr(p) }.to_owned()
    }
}

fn err_msg() -> String {
    let p = detent_last_error_message();
    if p.is_null() {
        "<no last error>".to_owned()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

#[test]
fn abi_version_matches_header() {
    assert_eq!(detent_abi_version(), DETENT_ABI_VERSION);
}

#[test]
fn module_list_round_trips_through_json() {
    let ptr = detent_module_list();
    assert!(!ptr.is_null(), "{}", err_msg());
    let s = ptr_to_chars(ptr).to_string_lossy().into_owned();
    let parsed: Vec<String> = serde_json::from_str(&s).unwrap_or_default();
    assert!(parsed.iter().any(|id| id == "hosts"));
    unsafe {
        detent_free(ptr);
    }
}

#[test]
fn detent_last_error_is_reset_on_success() {
    let ptr = detent_module_list();
    unsafe {
        detent_free(ptr);
    }
    assert!(detent_last_error_message().is_null());
    assert_eq!(detent_last_error(), DETENT_OK);
}

#[test]
fn parse_and_round_trip_render() {
    let module_id = c_str("hosts");
    // SAFETY: module_id is a live NUL-terminated CString; FIXTURE is a valid
    // `&str` slice readable for its length.
    let doc = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    assert!(!doc.is_null(), "{}", err_msg());

    // SAFETY: `doc` is a live handle just returned by `detent_parse`.
    let rendered_ptr = unsafe { detent_render(doc) };
    let rendered = ptr_to_chars(rendered_ptr).to_string_lossy().into_owned();
    // hosts module satisfies invariant 4: render(parse(s)) == s
    assert_eq!(rendered, FIXTURE);
    unsafe {
        detent_free(rendered_ptr);
    }
    unsafe {
        detent_free(doc);
    }
}

#[test]
fn to_model_json_returns_host_entries() {
    let module_id = c_str("hosts");
    // SAFETY: same live-pointer argument as `parse_and_round_trip_render`.
    let doc = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    assert!(!doc.is_null(), "{}", err_msg());
    // SAFETY: `doc` is a live handle just returned by `detent_parse`.
    let model_ptr = unsafe { detent_to_model_json(doc) };
    assert!(!model_ptr.is_null(), "{}", err_msg());
    let s = ptr_to_chars(model_ptr).to_string_lossy().into_owned();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
    let entries = v
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty(), "expected fixture to carry entries");
    unsafe {
        detent_free(model_ptr);
    }
    unsafe {
        detent_free(doc);
    }
}

#[test]
fn apply_json_round_trips_losslessly() {
    let module_id = c_str("hosts");
    // SAFETY: same live-pointer argument as `parse_and_round_trip_render`.
    let doc = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    // SAFETY: `doc` is a live handle just returned by `detent_parse`.
    let model_ptr = unsafe { detent_to_model_json(doc) };
    assert!(!model_ptr.is_null(), "{}", err_msg());
    let model_cstr = ptr_to_chars(model_ptr);
    let model_json_str = model_cstr.to_string_lossy().into_owned();

    // SAFETY: module_id/model buffers are live CStrings; FIXTURE is a valid
    // slice; the model buffer is readable for its computed length.
    let rendered_ptr = unsafe {
        detent_apply_json(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
            model_cstr.as_ptr().cast::<c_char>(),
            model_json_str.len(),
        )
    };
    assert!(!rendered_ptr.is_null(), "{}", err_msg());
    let rendered = ptr_to_chars(rendered_ptr).to_string_lossy().into_owned();
    assert_eq!(rendered, FIXTURE);
    unsafe {
        detent_free(rendered_ptr);
    }
    unsafe {
        detent_free(model_ptr);
    }
    unsafe {
        detent_free(doc);
    }
}

#[test]
fn schema_json_is_a_valid_json_schema_with_hints() {
    let module_id = c_str("hosts");
    // SAFETY: module_id is a live NUL-terminated CString.
    let schema_ptr = unsafe { detent_schema_json(module_id.as_ptr().cast::<c_char>()) };
    assert!(!schema_ptr.is_null(), "{}", err_msg());
    let s = ptr_to_chars(schema_ptr).to_string_lossy().into_owned();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
    assert_eq!(
        v.get("type").and_then(|t| t.as_str()).unwrap_or(""),
        "object"
    );
    unsafe {
        detent_free(schema_ptr);
    }
}

#[test]
fn defaults_json_for_a_linux_profile_is_non_empty() {
    let module_id = c_str("hosts");
    let profile = c_str("{\"os\":\"linux\",\"init\":\"systemd\",\"hostname\":\"detent-test\"}");
    // SAFETY: both are live NUL-terminated CStrings; profile readable for
    // its computed length.
    let defaults_ptr = unsafe {
        detent_defaults_json(
            module_id.as_ptr().cast::<c_char>(),
            profile.as_ptr().cast::<c_char>(),
            cstr_len(&profile),
        )
    };
    assert!(!defaults_ptr.is_null(), "{}", err_msg());
    let s = ptr_to_chars(defaults_ptr).to_string_lossy().into_owned();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
    let entries = v
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty(), "expected defaults to carry entries");
    unsafe {
        detent_free(defaults_ptr);
    }
}

#[test]
fn validate_json_returns_diagnostics_array() {
    let module_id = c_str("hosts");
    let model = c_str("{\"entries\":[]}");
    let hostname = c_str("detent-test");
    // SAFETY: all three are live NUL-terminated CStrings; model/hostname
    // readable for their computed lengths.
    let diags_ptr = unsafe {
        detent_validate_json(
            module_id.as_ptr().cast::<c_char>(),
            model.as_ptr().cast::<c_char>(),
            cstr_len(&model),
            0, // Os::Linux
            1, // InitSystem::Systemd
            hostname.as_ptr().cast::<c_char>(),
            cstr_len(&hostname),
            1024,
        )
    };
    assert!(!diags_ptr.is_null(), "{}", err_msg());
    let s = ptr_to_chars(diags_ptr).to_string_lossy().into_owned();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
    assert!(v.is_array());
    unsafe {
        detent_free(diags_ptr);
    }
}

#[test]
fn parse_with_unknown_module_sets_code_and_message() {
    let module_id = c_str("does-not-exist");
    // SAFETY: module_id is a live NUL-terminated CString; FIXTURE is a valid
    // slice readable for its length.
    let ptr = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    assert!(ptr.is_null());
    assert_eq!(detent_last_error(), DETENT_ERR_UNKNOWN_MODULE);
    let msg = detent_last_error_message();
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .into_owned();
    assert!(s.contains("does-not-exist"), "last_error was: {s}");
}

#[test]
fn last_error_state_is_thread_local() {
    let module_id = c_str("does-not-exist");
    // SAFETY: both pointers are live for the duration of the call.
    let ptr = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    assert!(ptr.is_null());
    assert_eq!(detent_last_error(), DETENT_ERR_UNKNOWN_MODULE);
    let other_thread = std::thread::spawn(|| detent_last_error()).join();
    assert_eq!(other_thread.unwrap(), DETENT_OK);
    assert_eq!(detent_last_error(), DETENT_ERR_UNKNOWN_MODULE);
}

#[test]
fn free_null_preserves_the_current_error() {
    let module_id = c_str("does-not-exist");
    // SAFETY: both pointers are live for the duration of the call.
    let ptr = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        )
    };
    assert!(ptr.is_null());
    let message = err_msg();
    unsafe {
        detent_free(std::ptr::null_mut());
    }
    assert_eq!(detent_last_error(), DETENT_ERR_UNKNOWN_MODULE);
    assert_eq!(err_msg(), message);
}

#[test]
fn free_foreign_pointer_is_silent() {
    let fake = c_str("placeholder");
    // Foreign pointer: header tag mismatch → detent_free leaves it alone.
    // No crash means the tag discrimination worked.
    unsafe { detent_free(fake.as_ptr().cast::<c_char>().cast_mut()) };
}

/// M13 / ADR-010: hostile inputs never panic across the boundary. Every
/// entry point maps NULL, invalid UTF-8, and unknown handles to NULL +
/// last-error instead of unwinding (lints make panics structurally
/// impossible; this test pins the observable half of that guarantee).
#[test]
fn hostile_inputs_never_panic_and_report_errors() {
    use std::ptr::{null, null_mut};
    // SAFETY: every `unsafe` block below upholds the callee's contract —
    // NULL pointers, a live 2-byte buffer, a live module id, or a handle
    // just returned by `detent_parse` — so each call is defined (refused
    // with NULL + last-error) rather than UB.
    unsafe {
        // NULL pointers on every pointer-taking entry point.
        assert!(detent_parse(null(), null(), 0).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_render(null_mut()).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_to_model_json(null_mut()).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_apply_json(null(), null(), 0, null(), 0).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_validate_json(null(), null(), 0, 0, 0, null(), 0, 0).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_defaults_json(null(), null(), 0).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        assert!(detent_schema_json(null()).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
        let bad = [0xFFu8, 0xFE];
        let module_id = c_str("hosts");
        assert!(
            detent_parse(
                module_id.as_ptr().cast::<c_char>(),
                bad.as_ptr().cast::<c_char>(),
                bad.len(),
            )
            .is_null()
        );
        assert_eq!(detent_last_error(), DETENT_ERR_INVALID_UTF8);
        // Use-after-free: freed handle renders to NULL, double free is silent.
        let doc = detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            FIXTURE.len(),
        );
        assert!(!doc.is_null(), "{}", err_msg());
        detent_free(doc);
        detent_free(doc);
        assert!(detent_render(doc).is_null());
        assert_eq!(detent_last_error(), DETENT_ERR_NULL_ARGUMENT);
    }
}

#[test]
fn oversized_length_is_refused() {
    // L-BIN11: from_raw_parts requires len <= isize::MAX; the FFI must
    // refuse an oversized length without attempting allocation.
    let module_id = c_str("hosts");
    let oversized = isize::MAX as usize + 1;
    // SAFETY: module_id is a live NUL-terminated CString; FIXTURE's
    // allocation is valid but we claim an oversized length — the callee
    // must not dereference past its real size because it checks the length
    // first and returns NULL.
    let ptr = unsafe {
        detent_parse(
            module_id.as_ptr().cast::<c_char>(),
            FIXTURE.as_ptr().cast::<c_char>(),
            oversized,
        )
    };
    assert!(ptr.is_null(), "oversized len must be refused with NULL");
    assert_eq!(detent_last_error(), DETENT_ERR_INTERNAL);
    assert!(!detent_last_error_message().is_null());
}
