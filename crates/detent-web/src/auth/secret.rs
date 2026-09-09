//! One type for every bearer string this crate holds: session ids, CSRF
//! tokens, API tokens.
//!
//! ```text
//!   getrandom ──▶ [u8; N] ──▶ hex ──▶ Secret ──┬─▶ expose()  (deliberate)
//!                                              ├─▶ ct_eq()   (constant time)
//!                                              └─▶ Debug     ("<redacted>")
//! ```
//!
//! # Guarantees
//!
//! * **A `Secret` cannot reach a log by accident.** It has no `Display`, no
//!   `Serialize`, and a `Debug` that prints `Secret(<redacted>)`. Reading the
//!   value takes a call named [`Secret::expose`], which is greppable.
//! * **Comparison is constant time in the value.** [`Secret::ct_eq`] runs
//!   `subtle`'s comparison over the bytes. Lengths are fixed by construction
//!   and are not secret, so an early `false` on a length mismatch leaks
//!   nothing an attacker did not already supply.
//! * **The buffer is wiped on drop**, so a freed session id does not linger in
//!   the allocator's free list.

use std::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::AuthError;

/// Bytes of entropy behind every secret this module mints: 32, per PLAN §2.7
/// for session ids and API tokens alike.
pub const SECRET_BYTES: usize = 32;

/// A random bearer string, rendered as lowercase hex.
///
/// Deliberately not `PartialEq`: the only comparison a secret should ever be
/// subjected to is [`Secret::ct_eq`], and deriving `==` would make the
/// variable-time one the easy one to reach for.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// [`SECRET_BYTES`] bytes from the system CSPRNG, as 64 lowercase hex
    /// digits.
    ///
    /// # Errors
    ///
    /// [`AuthError::Entropy`] when the system cannot produce random bytes.
    /// There is no fallback on purpose: a predictable session id is worse
    /// than a failed login.
    pub fn random() -> Result<Self, AuthError> {
        let mut bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
        getrandom::fill(bytes.as_mut_slice())?;
        Ok(Self(Zeroizing::new(hex(bytes.as_slice()))))
    }

    /// Wrap a string that is already a secret — a value parsed out of a
    /// request header or a cookie.
    #[must_use]
    pub fn from_presented(value: &str) -> Self {
        Self(Zeroizing::new(value.to_owned()))
    }

    /// The value itself. Named so that every use of it is easy to find.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether `candidate` equals this secret, compared in constant time.
    #[must_use]
    pub fn ct_eq(&self, candidate: &str) -> bool {
        let ours = self.0.as_bytes();
        let theirs = candidate.as_bytes();
        if ours.len() != theirs.len() {
            return false;
        }
        ours.ct_eq(theirs).into()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

/// One lowercase hex digit from the low four bits of `value`.
const fn hex_digit(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

/// `n` bytes from the system CSPRNG.
///
/// # Errors
///
/// [`AuthError::Entropy`] when the system cannot produce random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{SECRET_BYTES, Secret, hex, random_bytes};

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_secret_is_64_lowercase_hex_digits_and_never_repeats() -> R {
        let first = Secret::random()?;
        assert_eq!(first.expose().len(), SECRET_BYTES.saturating_mul(2));
        assert!(
            first
                .expose()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(first.expose(), Secret::random()?.expose());
        Ok(())
    }

    #[test]
    fn the_debug_output_is_only_the_word_redacted() -> R {
        // How a secret is usually printed: as a field of something else.
        #[derive(Debug)]
        struct Holder {
            id: Secret,
        }

        let secret = Secret::random()?;
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains(secret.expose()));
        let holder = Holder { id: secret.clone() };
        let rendered = format!("{holder:?}");
        assert!(!rendered.contains(secret.expose()), "{rendered}");
        // The holder really does carry the secret — otherwise the assertion
        // above would pass for the boring reason.
        assert!(holder.id.ct_eq(secret.expose()));
        Ok(())
    }

    #[test]
    fn comparison_accepts_only_the_exact_value() -> R {
        let secret = Secret::random()?;
        assert!(secret.ct_eq(secret.expose()));
        assert!(!secret.ct_eq(""));
        assert!(!secret.ct_eq("short"));
        let mut wrong = secret.expose().to_owned();
        wrong.replace_range(0..1, if wrong.starts_with('a') { "b" } else { "a" });
        assert!(!secret.ct_eq(&wrong));
        // A longer candidate with the right prefix is refused too.
        assert!(!secret.ct_eq(&format!("{}0", secret.expose())));

        let presented = Secret::from_presented(secret.expose());
        assert!(presented.ct_eq(secret.expose()));
        Ok(())
    }

    #[test]
    fn hex_renders_every_nibble() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(
            hex(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]),
            "123456789abcde"
        );
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn random_bytes_fills_the_whole_array() -> R {
        let bytes: [u8; 16] = random_bytes()?;
        assert_eq!(bytes.len(), 16);
        let again: [u8; 16] = random_bytes()?;
        assert_ne!(bytes, again);
        Ok(())
    }
}
