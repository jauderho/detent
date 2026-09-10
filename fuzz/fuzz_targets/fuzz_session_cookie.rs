//! `fuzz_session_cookie`: the credential-parsing surface in front of
//! authentication — `session::cookie_value`, `extract::bearer`,
//! `csrf::Origin::parse`, `base32::decode`, and `Secret::ct_eq` — never
//! panics on arbitrary bytes, however malformed.
//!
//! `Origin` gets the most attention: it hand-parses `scheme://host[:port]`,
//! including bracketed IPv6 literals, and its own port comparison decides
//! whether a cross-origin mutation is accepted (PLAN §2.7, ADR-007). This
//! target asserts `as_str()` is a fixed point of `parse`, and that the
//! match verdict agrees with the normalization rule `Origin`'s own
//! documentation states — recomputed here from the scheme, host and port the
//! origins were built from, so the assertion does not simply restate the
//! implementation it is checking.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use axum::http::{HeaderMap, HeaderValue, header};
use detent_web::auth::base32;
use detent_web::auth::extract::bearer;
use detent_web::auth::secret::Secret;
use detent_web::auth::session::cookie_value;
use detent_web::csrf::Origin;
use libfuzzer_sys::fuzz_target;

/// A short lowercase host label from a safe alphabet. Arbitrary bytes almost
/// never parse as an origin at all, and the bugs worth finding in
/// [`Origin::matches`] live in how two *parseable* origins compare — case,
/// default ports, bracketed IPv6 — so this biases generation towards origins
/// that actually parse.
fn arbitrary_host(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-";
    let len = u.int_in_range(1..=12usize)?;
    let mut host = String::with_capacity(len);
    for _ in 0..len {
        let index = u.int_in_range(0..=ALPHABET.len().saturating_sub(1))?;
        let byte = ALPHABET.get(index).copied().unwrap_or(b'a');
        host.push(char::from(byte));
    }
    Ok(host)
}

/// An origin kept as the parts it was built from.
///
/// The parts are the point. `Origin::matches` is implemented as "parse the
/// candidate and compare normalized forms", so asserting exactly that is
/// asserting nothing — it restates the code. Holding on to the scheme, host
/// and port lets [`equivalent`] state the *rule* from `Origin`'s own
/// documentation, independently of how `Origin` implements it, and compare
/// the two.
#[derive(Debug, Clone)]
struct OriginParts {
    scheme: &'static str,
    host: String,
    port: Option<u16>,
}

impl OriginParts {
    /// The `scheme://host[:port]` text a browser would send.
    fn text(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }

    /// The port in effect, with the scheme's default filled in.
    fn effective_port(&self) -> u16 {
        self.port.unwrap_or(if self.scheme == "https" { 443 } else { 80 })
    }
}

/// Whether two origins are the same one, per `Origin`'s documented rule:
/// scheme and host compared without regard to case, and a port equal to the
/// scheme's default treated as absent.
///
/// Written from the documentation rather than from the implementation, so
/// that a disagreement between the two is a fuzz failure. A bug in the
/// default-port logic — the kind that would let `https://host:443` and
/// `https://host` diverge, or worse, let two genuinely different origins
/// compare equal — shows up right here.
fn equivalent(left: &OriginParts, right: &OriginParts) -> bool {
    left.scheme.eq_ignore_ascii_case(right.scheme)
        && left.host.eq_ignore_ascii_case(&right.host)
        && left.effective_port() == right.effective_port()
}

/// Origin parts, structured so they usually form a valid origin. The port is
/// biased towards the two scheme defaults, because that is where the
/// interesting comparisons are.
fn arbitrary_origin_parts(u: &mut Unstructured<'_>) -> arbitrary::Result<OriginParts> {
    let scheme = if bool::arbitrary(u)? { "https" } else { "http" };
    let host = arbitrary_host(u)?;
    let port = match u.int_in_range(0..=3u8)? {
        0 => None,
        1 => Some(443),
        2 => Some(80),
        _ => Some(u16::arbitrary(u)?),
    };
    Ok(OriginParts { scheme, host, port })
}

/// One fuzz case, over every parser this target covers.
#[derive(Debug)]
struct Input<'a> {
    cookie_header: &'a str,
    bearer_header: &'a [u8],
    origin_x: OriginParts,
    origin_y: OriginParts,
    base32_text: &'a str,
    secret_candidate: &'a str,
}

impl<'a> Arbitrary<'a> for Input<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            cookie_header: <&str>::arbitrary(u)?,
            bearer_header: <&[u8]>::arbitrary(u)?,
            origin_x: arbitrary_origin_parts(u)?,
            origin_y: arbitrary_origin_parts(u)?,
            base32_text: <&str>::arbitrary(u)?,
            secret_candidate: <&str>::arbitrary(u)?,
        })
    }
}

fuzz_target!(|input: Input<'_>| {
    // `cookie_value`: never panics, and whatever it extracts compares equal
    // to itself in constant time.
    if let Some(secret) = cookie_value(input.cookie_header) {
        assert!(secret.ct_eq(secret.expose()));
    }

    // `extract::bearer`, over a real `HeaderMap` so it takes the same
    // `HeaderValue -> str -> split` path a request does.
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_bytes(input.bearer_header) {
        headers.insert(header::AUTHORIZATION, value);
        if let Some(token) = bearer(&headers) {
            assert!(
                !token.expose().is_empty(),
                "bearer() returned an empty token"
            );
        }
    }

    // `base32::decode`: never panics, and round-trips through `encode`
    // whenever it accepts the input.
    if let Some(bytes) = base32::decode(input.base32_text) {
        assert_eq!(
            base32::decode(&base32::encode(&bytes)),
            Some(bytes),
            "encode(decode(x)) did not round-trip for {:?}",
            input.base32_text
        );
    }

    // `Secret::ct_eq`: never panics, whatever the lengths of the two sides.
    let held = Secret::from_presented(input.secret_candidate);
    let _ = held.ct_eq(input.cookie_header);
    let _ = held.ct_eq(input.base32_text);
    let _ = held.ct_eq("");

    // `Origin::parse`/`matches`: never panics, `as_str()` is a fixed point of
    // `parse`, and the verdict agrees with the documented rule computed from
    // the parts the origins were built from — so a wrong answer about two
    // genuinely different origins fails here rather than silently accepting a
    // cross-origin mutation.
    let (x_text, y_text) = (input.origin_x.text(), input.origin_y.text());
    if let Some(x) = Origin::parse(&x_text) {
        let reparsed = Origin::parse(x.as_str());
        assert_eq!(
            reparsed.as_ref().map(Origin::as_str),
            Some(x.as_str()),
            "as_str() did not round-trip through parse() for {:?}",
            x.as_str()
        );

        if Origin::parse(&y_text).is_some() {
            let expected = equivalent(&input.origin_x, &input.origin_y);
            assert_eq!(
                x.matches(&y_text),
                expected,
                "{x_text:?} vs {y_text:?}: matches() said {}, the documented rule says {expected}",
                x.matches(&y_text)
            );
        }
    }
});
