//! Base32 (RFC 4648 §6), because a TOTP secret has to be typeable.
//!
//! Forty lines and no dependency. The alphabet is `A-Z2-7`; [`encode`] emits
//! no padding, which is what every authenticator application expects in an
//! `otpauth://` URI, and [`decode`] accepts padding, lowercase and both
//! anyway, because operators type these by hand.
//!
//! # Guarantees
//!
//! * **Round trip.** `decode(encode(b)) == Some(b)` for every input, checked
//!   by a test over the RFC 4648 §10 vectors and over random data.
//! * **A malformed secret is `None`, never a panic.** Every index is bounds
//!   checked (`clippy::indexing_slicing` is denied in this workspace) and
//!   every shift is explicit.
//! * **Non-canonical input is refused.** Trailing bits that are not zero, and
//!   a length that no byte string could have produced, both decode to `None`
//!   rather than to a value that would re-encode differently.

/// The RFC 4648 §6 alphabet.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `bytes` as unpadded base32.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5).saturating_mul(8));
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let index = usize::from((buffer >> bits) & 0x1f);
            if let Some(&symbol) = ALPHABET.get(index) {
                out.push(char::from(symbol));
            }
        }
    }
    if bits > 0 {
        let index = usize::from((buffer << (5_u32.saturating_sub(bits))) & 0x1f);
        if let Some(&symbol) = ALPHABET.get(index) {
            out.push(char::from(symbol));
        }
    }
    out
}

/// Decode base32, accepting lowercase and trailing `=` padding.
///
/// Returns `None` for a symbol outside the alphabet, for a length that no
/// byte string encodes to, and for leftover bits that are not zero.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(5) / 8);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    let mut ended = false;
    for symbol in text.bytes() {
        if symbol == b'=' {
            // Padding may only ever be trailing.
            ended = true;
            continue;
        }
        if ended {
            return None;
        }
        let value = symbol_value(symbol)?;
        buffer = (buffer << 5) | u16::from(value);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            let byte = u8::try_from((buffer >> bits) & 0xff).ok()?;
            out.push(byte);
        }
    }
    // A group can leave at most four bits over, and they must be zero, or the
    // text was not produced by encoding any byte string.
    if bits >= 5 || (buffer & (1_u16 << bits).saturating_sub(1)) != 0 {
        return None;
    }
    Some(out)
}

/// The five-bit value of one base32 symbol, case-insensitively.
const fn symbol_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(symbol.wrapping_sub(b'a')),
        b'2'..=b'7' => Some(symbol.wrapping_sub(b'2').wrapping_add(26)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// RFC 4648 §10, with the padding this encoder deliberately omits kept in
    /// the expectation so the vectors are recognisable.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ];

    #[test]
    fn the_rfc_4648_test_vectors_encode_without_padding() {
        for (plain, padded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), padded.trim_end_matches('='));
        }
    }

    #[test]
    fn the_rfc_4648_test_vectors_decode_padded_and_unpadded() -> R {
        for (plain, padded) in VECTORS {
            assert_eq!(
                decode(padded).ok_or("padded vector did not decode")?,
                plain.as_bytes()
            );
            assert_eq!(
                decode(padded.trim_end_matches('=')).ok_or("unpadded vector did not decode")?,
                plain.as_bytes()
            );
            assert_eq!(
                decode(&padded.to_lowercase()).ok_or("lowercase vector did not decode")?,
                plain.as_bytes()
            );
        }
        Ok(())
    }

    #[test]
    fn every_byte_string_round_trips() -> R {
        for len in 0_usize..40 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i.wrapping_mul(37).wrapping_add(11) % 256).unwrap_or(0))
                .collect();
            let text = encode(&bytes);
            assert!(!text.contains('='));
            assert_eq!(decode(&text).ok_or("round trip failed")?, bytes);
        }
        Ok(())
    }

    #[test]
    fn malformed_input_decodes_to_nothing() {
        for text in [
            "1",          // not in the alphabet
            "M!",         // not in the alphabet
            "MZXW6YTB=A", // padding in the middle
            "A",          // five bits is not a byte
            "MB",         // leftover bits that are not zero
            "ABCDEFGHI",  // nine symbols: forty-five bits, five of them set
        ] {
            assert_eq!(decode(text), None, "{text:?} decoded");
        }
    }

    #[test]
    fn a_twenty_byte_secret_is_thirty_two_symbols() {
        let secret = [0x5a_u8; 20];
        let text = encode(&secret);
        assert_eq!(text.len(), 32);
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        );
    }
}
