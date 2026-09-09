//! RFC 6238 time-based one-time passwords, with replay refused.
//!
//! ```text
//!   TotpSecret (20 random bytes) ──▶ base32 ──▶ otpauth:// ──▶ QR (Phase 5)
//!            │
//!            ├─ code_at(counter)  = HMAC-SHA1 ─▶ dynamic truncation ─▶ 6 digits
//!            │
//!   verify(code, now, last_counter):  counter ∈ {t-1, t, t+1}
//!                                     and counter > last_counter
//! ```
//!
//! The UI lands in Phase 5; this is the backend PLAN Phase 4 asks for.
//!
//! # Guarantees
//!
//! * **A code is accepted once.** The caller stores the counter this module
//!   returns and passes it back as `last_counter`; a counter that is not
//!   strictly greater is refused. `SameSite=Strict` does not help against
//!   somebody who watched the operator's screen, and a ±1 window means a code
//!   stays valid for up to 90 seconds without this.
//! * **Comparison is constant time**, through [`Secret::ct_eq`].
//! * **The secret never renders.** [`TotpSecret`] and [`OtpAuthUri`] both
//!   print `<redacted>`, and the base32 form comes back as a [`Secret`].
//! * **SHA-1 is deliberate and confined.** RFC 6238 and every authenticator
//!   application speak HMAC-SHA1; nothing else in this workspace may.

use std::fmt;
use std::fmt::Write as _;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha1::Sha1;
use zeroize::Zeroizing;

use super::AuthError;
use super::base32;
use super::secret::Secret;

/// Seconds in one TOTP step (RFC 6238's `X`).
pub const STEP_SECS: u64 = 30;

/// Digits in a code.
pub const DIGITS: u32 = 6;

/// Steps either side of the current one that are still accepted.
pub const WINDOW_STEPS: u64 = 1;

/// Bytes in a generated secret. Twenty is the HMAC-SHA1 block-independent
/// recommendation of RFC 4226 §4 and what authenticator applications expect.
pub const SECRET_BYTES: usize = 20;

/// Shortest secret this build will accept from an operator: 128 bits, the
/// floor RFC 4226 §4 requirement R6 sets.
pub const MIN_SECRET_BYTES: usize = 16;

/// Issuer shown in an authenticator application.
pub const ISSUER: &str = "detent";

/// `10^DIGITS`, the modulus applied to the truncated HMAC.
const MODULUS: u32 = 1_000_000;

/// A shared TOTP secret.
#[derive(Clone)]
pub struct TotpSecret(Zeroizing<Vec<u8>>);

impl TotpSecret {
    /// A fresh [`SECRET_BYTES`]-byte secret from the system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`AuthError::Entropy`] when the system cannot produce random bytes.
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(Zeroizing::new(
            super::secret::random_bytes::<SECRET_BYTES>()?.to_vec(),
        )))
    }

    /// Parse the base32 form an operator typed or a store held.
    ///
    /// # Errors
    ///
    /// [`AuthError::TotpSecretInvalid`] when `text` is not base32, or decodes
    /// to nothing.
    pub fn from_base32(text: &str) -> Result<Self, AuthError> {
        let bytes = base32::decode(text).ok_or(AuthError::TotpSecretInvalid)?;
        // RFC 4226 §4 R6: at least 128 bits of shared secret.
        if bytes.len() < MIN_SECRET_BYTES {
            return Err(AuthError::TotpSecretInvalid);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// The base32 form, for storage and for operator entry.
    #[must_use]
    pub fn to_base32(&self) -> Secret {
        Secret::from_presented(&base32::encode(&self.0))
    }

    /// The `otpauth://` URI a Phase 5 QR code is drawn from.
    ///
    /// `account` is the user name; it and the issuer are percent-encoded, so
    /// a name with a `:` or a space cannot break the label.
    #[must_use]
    pub fn otpauth_uri(&self, account: &str) -> OtpAuthUri {
        let label = format!(
            "{}:{}",
            percent_encode(ISSUER.as_bytes()),
            percent_encode(account.as_bytes())
        );
        OtpAuthUri(Zeroizing::new(format!(
            "otpauth://totp/{label}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
            self.to_base32().expose(),
            percent_encode(ISSUER.as_bytes()),
        )))
    }

    /// The code for one counter value, zero-padded to [`DIGITS`] digits.
    #[must_use]
    pub fn code_at(&self, counter: u64) -> Secret {
        // HMAC accepts a key of any length, so `new_from_slice` cannot
        // actually fail here; folding the impossible error into the value
        // keeps an untestable branch out of the module.
        let tag = Hmac::<Sha1>::new_from_slice(&self.0)
            .map(|mut mac| {
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes()
            })
            .unwrap_or_default();

        // RFC 4226 §5.4 dynamic truncation: the low nibble of the last byte
        // selects a four-byte window, which is always inside a 20-byte tag.
        let offset = usize::from(tag.last().copied().unwrap_or(0) & 0x0f);
        let mut value: u32 = 0;
        for step in 0_usize..4 {
            let byte = tag.get(offset.saturating_add(step)).copied().unwrap_or(0);
            value = (value << 8) | u32::from(byte);
        }
        let digits = (value & 0x7fff_ffff) % MODULUS;
        Secret::from_presented(&format!("{digits:06}"))
    }

    /// Whether `code` is valid at `unix_secs`, and which counter it belongs
    /// to.
    ///
    /// `last_counter` is the counter this user's previous accepted code came
    /// from. A code from that counter or an earlier one is refused however
    /// well it verifies — that is the replay guard, and it is why the accepted
    /// counter comes back for the caller to store.
    ///
    /// Returns `None` for a wrong, malformed, expired or replayed code: one
    /// answer, so the caller cannot turn the difference into an oracle.
    #[must_use]
    pub fn verify(&self, code: &str, unix_secs: u64, last_counter: Option<u64>) -> Option<u64> {
        let step = unix_secs / STEP_SECS;
        let mut accepted: Option<u64> = None;
        // Every candidate is evaluated: no early exit, so the work done does
        // not depend on which step matched.
        let first = step.saturating_sub(WINDOW_STEPS);
        for offset in 0..=WINDOW_STEPS.saturating_mul(2) {
            let counter = first.saturating_add(offset);
            let matches = self.code_at(counter).ct_eq(code);
            let fresh = last_counter.is_none_or(|last| counter > last);
            if matches && fresh {
                accepted = Some(counter);
            }
        }
        accepted
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

/// An `otpauth://` URI. It contains the shared secret, so it is one.
#[derive(Clone)]
pub struct OtpAuthUri(Zeroizing<String>);

impl OtpAuthUri {
    /// The URI itself, for the one response that is allowed to carry it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OtpAuthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpAuthUri(<redacted>)")
    }
}

/// Percent-encode everything that is not an RFC 3986 unreserved character.
fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{DIGITS, ISSUER, STEP_SECS, TotpSecret, percent_encode};
    use crate::auth::AuthError;
    use crate::auth::base32;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// RFC 6238 appendix B's HMAC-SHA1 seed: the ASCII string
    /// `12345678901234567890`.
    const RFC_SEED: &[u8; 20] = b"12345678901234567890";

    fn rfc_secret() -> Result<TotpSecret, AuthError> {
        TotpSecret::from_base32(&base32::encode(RFC_SEED))
    }

    #[test]
    fn the_rfc_6238_test_vectors_produce_the_published_codes() -> R {
        // Appendix B, truncated to the six digits this build uses.
        let cases = [
            (59_u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        let secret = rfc_secret()?;
        for (unix_secs, expected) in cases {
            let counter = unix_secs / STEP_SECS;
            assert_eq!(
                secret.code_at(counter).expose(),
                expected,
                "t={unix_secs} counter={counter}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_code_is_six_digits() -> R {
        let secret = TotpSecret::generate()?;
        for counter in 0_u64..50 {
            let code = secret.code_at(counter);
            assert_eq!(
                u32::try_from(code.expose().len()).unwrap_or_default(),
                DIGITS
            );
            assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
        }
        Ok(())
    }

    #[test]
    fn the_window_accepts_one_step_either_side_and_no_more() -> R {
        let secret = rfc_secret()?;
        let now = 1_111_111_111_u64;
        let step = now / STEP_SECS;
        for (counter, accepted) in [
            (step.saturating_sub(2), false),
            (step.saturating_sub(1), true),
            (step, true),
            (step.saturating_add(1), true),
            (step.saturating_add(2), false),
        ] {
            let code = secret.code_at(counter);
            assert_eq!(
                secret.verify(code.expose(), now, None) == Some(counter),
                accepted,
                "counter {counter} at t={now}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_code_cannot_be_used_twice() -> R {
        let secret = rfc_secret()?;
        let now = 1_111_111_111_u64;
        let step = now / STEP_SECS;
        let code = secret.code_at(step);

        let accepted = secret
            .verify(code.expose(), now, None)
            .ok_or("the first use was refused")?;
        assert_eq!(accepted, step);
        // The same code again, with the counter recorded: refused.
        assert_eq!(secret.verify(code.expose(), now, Some(accepted)), None);
        // And so is the previous step's code, which the window would
        // otherwise still accept.
        let previous = secret.code_at(step.saturating_sub(1));
        assert_eq!(secret.verify(previous.expose(), now, Some(accepted)), None);
        // The next step's code is still fresh.
        let next = secret.code_at(step.saturating_add(1));
        assert_eq!(
            secret.verify(next.expose(), now, Some(accepted)),
            Some(step.saturating_add(1))
        );
        Ok(())
    }

    #[test]
    fn a_wrong_or_malformed_code_is_refused() -> R {
        let secret = rfc_secret()?;
        for code in ["", "000000", "12345", "1234567", "abcdef", "  050471"] {
            assert_eq!(
                secret.verify(code, 1_111_111_111, None),
                None,
                "{code:?} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn a_secret_round_trips_through_base32_and_rejects_rubbish() -> R {
        let secret = TotpSecret::generate()?;
        let text = secret.to_base32();
        let parsed = TotpSecret::from_base32(text.expose())?;
        assert_eq!(parsed.code_at(1).expose(), secret.code_at(1).expose());

        // Valid base32, but only five bytes: too short to be a secret.
        for bad in ["", "1", "not base32!", "====", "MZXW6YTB"] {
            match TotpSecret::from_base32(bad) {
                Err(AuthError::TotpSecretInvalid) => {}
                other => return Err(format!("{bad:?} gave {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn the_otpauth_uri_carries_the_secret_and_the_parameters() -> R {
        let secret = rfc_secret()?;
        let uri = secret.otpauth_uri("alice");
        let text = uri.expose();
        assert!(text.starts_with("otpauth://totp/detent:alice?"), "{text}");
        assert!(text.contains(&format!("secret={}", secret.to_base32().expose())));
        assert!(text.contains(&format!("issuer={ISSUER}")));
        assert!(text.contains("algorithm=SHA1"));
        assert!(text.contains("digits=6"));
        assert!(text.contains("period=30"));
        Ok(())
    }

    #[test]
    fn a_label_cannot_be_broken_by_a_hostile_account_name() -> R {
        let secret = rfc_secret()?;
        let uri = secret.otpauth_uri("a b:c?d&e");
        assert!(
            uri.expose()
                .starts_with("otpauth://totp/detent:a%20b%3Ac%3Fd%26e?"),
            "{}",
            uri.expose()
        );
        assert_eq!(percent_encode(b"aA0-._~"), "aA0-._~");
        assert_eq!(percent_encode(b"/"), "%2F");
        Ok(())
    }

    #[test]
    fn neither_the_secret_nor_the_uri_renders_in_debug() -> R {
        let secret = rfc_secret()?;
        let base32 = secret.to_base32();
        let uri = secret.otpauth_uri("alice");
        let rendered = format!("{secret:?} {uri:?} {base32:?}");
        assert_eq!(
            rendered,
            "TotpSecret(<redacted>) OtpAuthUri(<redacted>) Secret(<redacted>)"
        );
        assert!(!rendered.contains(base32.expose()));
        assert!(!rendered.contains("12345678901234567890"));
        Ok(())
    }
}
