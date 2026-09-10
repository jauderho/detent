//! `fuzz_api_json`: the `/api/v1` request-body surface (`ModelRequest`,
//! `ApplyRequest`, `ServiceActionRequest`) and the path-parameter validators
//! in `detent_web::api` (`well_formed_id`, `check_depth`).
//!
//! Properties asserted:
//! * Deserializing any of the three body types from arbitrary bytes never
//!   panics.
//! * `#[serde(deny_unknown_fields)]` holds: a body that is otherwise valid
//!   for a type, with one extra field grafted on, is always rejected.
//! * `well_formed_id` never panics, and an id it accepts has the properties
//!   the check exists for: it cannot walk a path, carry a separator, a
//!   percent-escape or a NUL, and it is already case-folded.
//! * `json_depth` reports the depth the harness actually built, so the guard
//!   cannot be talked past by a value one level deeper than it measures.
//!
//! Where an assertion would only restate the implementation it checks, it is
//! marked as such and kept solely for its no-panic value.

#![no_main]

use arbitrary::Arbitrary;
use detent_web::api::modules::{ApplyRequest, ModelRequest};
use detent_web::api::services::ServiceActionRequest;
use detent_web::api::{MAX_ID_LEN, MAX_JSON_DEPTH, check_depth, json_depth, well_formed_id};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

/// One fuzz case, over every part of the body/id/depth surface.
#[derive(Debug, Arbitrary)]
struct Input<'a> {
    /// Raw bytes, tried as the body of each request type in turn.
    body: &'a [u8],
    /// Tried against [`well_formed_id`].
    id: &'a str,
    /// Turned into a field name no real body type declares, to check
    /// `deny_unknown_fields`.
    unknown_field_suffix: &'a str,
    /// How many array levels to nest a value, to probe the depth guard at
    /// and around `MAX_JSON_DEPTH`.
    depth: u8,
}

/// `check_depth` must reject `value` exactly when `json_depth` says it is
/// past the bound, and `json_depth` must not panic on any shape.
///
/// This pair is deliberately weak on its own — `check_depth` is written as
/// `json_depth(v) > MAX_JSON_DEPTH`, so agreement between them is a
/// restatement, not a test. It is here only for the no-panic property.
/// [`assert_depth_is_measured_correctly`] is the assertion with teeth.
fn assert_depth_guard_agrees(value: &Value) {
    let depth = json_depth(value);
    assert_eq!(check_depth(value).is_err(), depth > MAX_JSON_DEPTH);
}

/// `json_depth` must report the depth the harness actually built.
///
/// The ground truth comes from the harness, not from the function under
/// test: `nest` wrapped a scalar in exactly `levels` arrays, so the depth is
/// `levels + 1` and nothing else. `json_depth` walks an explicit stack with
/// `saturating_add`, which is exactly the shape that goes off by one, and a
/// depth under-reported by one is a guard that admits a payload one level
/// deeper than `MAX_JSON_DEPTH` allows.
fn assert_depth_is_measured_correctly(value: &Value, levels: usize) {
    let expected = levels.saturating_add(1);
    assert_eq!(
        json_depth(value),
        expected,
        "a scalar wrapped in {levels} array(s) should measure {expected} deep"
    );
}

/// `valid`, plus one field no declared type owns, must fail to deserialize
/// as `T` — that is what `#[serde(deny_unknown_fields)]` promises.
fn assert_unknown_field_is_rejected<T>(mut valid: Value, field_name: &str, field_value: Value)
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    let Value::Object(map) = &mut valid else {
        return;
    };
    map.insert(field_name.to_owned(), field_value);
    assert!(
        serde_json::from_value::<T>(valid).is_err(),
        "a body with the unknown field {field_name:?} was accepted"
    );
}

fuzz_target!(|input: Input<'_>| {
    // Deserializing arbitrary bytes as any of the three body types must
    // never panic, whatever they contain.
    let _ = serde_json::from_slice::<ModelRequest>(input.body);
    let _ = serde_json::from_slice::<ApplyRequest>(input.body);
    let _ = serde_json::from_slice::<ServiceActionRequest>(input.body);

    // `deny_unknown_fields`: an otherwise-valid body carrying one extra
    // field, whose name is guaranteed not to collide with a real one
    // (`x_` is not a prefix of `model`, `expected_hash`, `service_action`,
    // `confirm_secs` or `action`), must be rejected.
    let field_name = format!("x_{}", input.unknown_field_suffix);
    let field_value = Value::Bool(true);
    assert_unknown_field_is_rejected::<ModelRequest>(
        json!({ "model": {} }),
        &field_name,
        field_value.clone(),
    );
    assert_unknown_field_is_rejected::<ApplyRequest>(
        json!({ "model": {} }),
        &field_name,
        field_value.clone(),
    );
    assert_unknown_field_is_rejected::<ServiceActionRequest>(
        json!({ "action": "restart" }),
        &field_name,
        field_value,
    );

    // `well_formed_id`: never panics (proven just by returning), and never
    // accepts an id outside its documented shape.
    // `well_formed_id`: never panics, and an id it accepts has the
    // properties the check exists to guarantee.
    //
    // Restating the predicate here — "every byte is in the allowed set" —
    // would assert nothing, since that is how the predicate is written.
    // These are its *consequences* instead: an accepted id cannot walk a
    // path, cannot carry a separator or a percent-escape, is already
    // lowercase so two ids cannot differ only by case, and is short enough
    // that it can never be the multi-kilobyte string a hostile caller would
    // rather send.
    if well_formed_id(input.id) {
        let id = input.id;
        assert!(!id.is_empty() && id.len() <= MAX_ID_LEN, "{id:?}");
        assert!(!id.contains('/') && !id.contains('\\'), "{id:?} is a path");
        assert!(!id.contains('.'), "{id:?} can reach a parent directory");
        assert!(!id.contains('%'), "{id:?} carries a percent-escape");
        assert!(!id.contains('\0'), "{id:?} carries a NUL");
        assert_eq!(id, id.to_ascii_lowercase(), "{id:?} is not case-folded");
        assert!(id.is_ascii(), "{id:?} is not ASCII");
        assert!(
            !id.starts_with(['-', '_']),
            "{id:?} starts with a separator"
        );
    }

    // The depth guard, over whatever JSON the fuzzer's own bytes happen to
    // parse as...
    if let Ok(value) = serde_json::from_slice::<Value>(input.body) {
        assert_depth_guard_agrees(&value);
    }
    // ...and over a value nested to a depth chosen to land on and around
    // `MAX_JSON_DEPTH`, since arbitrary bytes rarely nest that deep on
    // their own.
    let levels = usize::from(input.depth % 40);
    let mut nested = json!(0);
    for _ in 0..levels {
        nested = json!([nested]);
    }
    assert_depth_guard_agrees(&nested);
    assert_depth_is_measured_correctly(&nested, levels);
});
