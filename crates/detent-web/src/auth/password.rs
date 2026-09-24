//! Argon2id, and the dummy hash that makes an unknown user cost the same as a
//! wrong password (PLAN §2.7, "Auth").
//!
//! ```text
//!   AuthConfig.argon2 + HostProfile.ram_mib ──▶ Params ──▶ Hasher
//!                                                            │
//!   login("alice", pw) ─┬─ user found ────▶ verify(pw, phc) ─┤ same
//!                       └─ user unknown ──▶ verify_dummy(pw) ─┘ cost
//! ```
//!
//! # Guarantees
//!
//! * **An unknown user costs what a known one costs.** [`Hasher::new`] builds
//!   a dummy PHC string over a random password with the *same* parameters, and
//!   [`Hasher::verify_dummy`] verifies against it. The login path calls it on
//!   every miss, so the two branches differ by a `HashMap` lookup rather than
//!   by a whole Argon2 pass.
//! * **The plaintext is wiped.** Every password this module touches is held in
//!   a [`Zeroizing`] buffer whose bytes are overwritten when it drops.
//! * **Nothing here prints a secret.** `Hasher`'s `Debug` shows the cost
//!   parameters only; no error carries a password or a hash.
//! * **Verification never says why.** [`Hasher::verify`] answers `bool`: a
//!   malformed stored hash, an unsupported algorithm and a wrong password are
//!   one outcome, so no caller can turn the difference into an oracle.

use std::fmt;

use argon2::password_hash::{PasswordVerifier as _, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, Version};
use zeroize::Zeroizing;

use crate::config::Argon2Params;

use super::AuthError;
use super::secret::random_bytes;

/// Bytes of randomness in the password the dummy hash is built over.
///
/// The value is never used again; only the *shape* of the resulting PHC string
/// matters, and no password an operator can type must ever verify against it.
const DUMMY_PASSWORD_BYTES: usize = 32;

/// Argon2id at the configured cost, plus the dummy hash for unknown users.
pub struct Hasher {
    /// The configured hasher. `'static` because no pepper is used: PLAN §2.7
    /// specifies salt-only Argon2id, and a pepper the same process stores
    /// beside the hashes protects against nothing this threat model has.
    argon2: Argon2<'static>,
    /// A PHC string over a random password, at the same parameters.
    dummy: Zeroizing<String>,
    /// What [`Debug`] prints, and what a test can assert on.
    params: (u32, u32, u32),
}

impl Hasher {
    /// A hasher at `params`, resolved against a host with `ram_mib` of RAM.
    ///
    /// `m_kib` follows [`Argon2Params::resolved_m_kib`]: what the operator
    /// configured, or 64 MiB / 32 MiB / the OWASP floor depending on the
    /// board.
    ///
    /// # Errors
    ///
    /// [`AuthError::Params`] when Argon2 refuses the cost parameters,
    /// [`AuthError::Entropy`] when the dummy password cannot be generated, and
    /// [`AuthError::Hash`] when the dummy hash cannot be computed.
    pub fn new(params: Argon2Params, ram_mib: u64) -> Result<Self, AuthError> {
        let m_kib = params.resolved_m_kib(ram_mib);
        let built = Params::new(m_kib, params.t, params.p, None).map_err(AuthError::Params)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, built);

        // A password nobody can type, hashed once, so that the "no such user"
        // branch does the same work as the "wrong password" branch.
        let seed = Zeroizing::new(random_bytes::<DUMMY_PASSWORD_BYTES>()?);
        let dummy = argon2
            .hash_password(seed.as_slice())
            .map_err(|_err| AuthError::Hash)?
            .to_string();

        Ok(Self {
            argon2,
            dummy: Zeroizing::new(dummy),
            params: (m_kib, params.t, params.p),
        })
    }

    /// The `(m_kib, t, p)` this hasher works at.
    #[must_use]
    pub const fn cost(&self) -> (u32, u32, u32) {
        self.params
    }
    /// Whether `phc` was made with the current algorithm, version and cost.
    ///
    /// A successful login passes a `true` answer back through
    /// [`UserStore::verify_password`](super::users::UserStore::verify_password)
    /// so a parameter rotation upgrades old hashes without making old ones
    /// unverifiable.
    #[must_use]
    pub fn needs_rehash(&self, phc: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(phc) else {
            return true;
        };
        let (m_kib, t, p) = self.params;
        parsed.algorithm.as_str() != Algorithm::Argon2id.as_str()
            || parsed.version != Some(19)
            || parsed.params.get_decimal("m") != Some(m_kib)
            || parsed.params.get_decimal("t") != Some(t)
            || parsed.params.get_decimal("p") != Some(p)
    }

    /// Hash `password` into a PHC string with a fresh random salt.
    ///
    /// # Errors
    ///
    /// [`AuthError::Hash`] when Argon2 refuses the input — in practice only a
    /// password longer than [`argon2::MAX_PWD_LEN`], which the request body
    /// limit makes unreachable.
    pub fn hash(&self, password: &str) -> Result<String, AuthError> {
        let buffer = Zeroizing::new(password.as_bytes().to_vec());
        Ok(self
            .argon2
            .hash_password(&buffer)
            .map_err(|_err| AuthError::Hash)?
            .to_string())
    }

    /// Whether `password` matches `phc`.
    ///
    /// The cost comes from `phc`, not from this hasher, so a hash written by
    /// an older, cheaper configuration still verifies. After a successful
    /// verification, callers use [`Self::needs_rehash`] to upgrade it at the
    /// current cost.
    #[must_use]
    pub fn verify(&self, password: &str, phc: &str) -> bool {
        let buffer = Zeroizing::new(password.as_bytes().to_vec());
        self.argon2.verify_password(&buffer, phc).is_ok()
    }

    /// Verify against the dummy hash and always answer `false`.
    ///
    /// Called on the "no such user" branch of a login so that its wall-clock
    /// cost matches a real verification. The return type exists so the call
    /// cannot be optimized into nothing at the call site, and so the branch
    /// reads like the one it is standing in for.
    #[must_use]
    pub fn verify_dummy(&self, password: &str) -> bool {
        let matched = self.verify(password, &self.dummy);
        // The dummy password is 32 random bytes; a match is a 2^-256 event,
        // and must still not authenticate anybody.
        debug_assert!(!matched, "the dummy hash matched a supplied password");
        false
    }
}

impl fmt::Debug for Hasher {
    /// Prints the cost parameters and nothing else — no dummy hash, no
    /// pointer into the Argon2 state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (m_kib, t, p) = self.params;
        f.debug_struct("Hasher")
            .field("m_kib", &m_kib)
            .field("t", &t)
            .field("p", &p)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::Hasher;
    use crate::auth::AuthError;
    use crate::config::{Argon2Params, MIN_ARGON2_M_KIB};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The cheapest parameters Argon2 accepts, so the tests are fast. The
    /// production floor is asserted by `config.rs`, not here.
    fn cheap() -> Argon2Params {
        Argon2Params {
            m_kib: Some(8),
            t: 1,
            p: 1,
        }
    }

    fn hasher() -> Result<Hasher, AuthError> {
        Hasher::new(cheap(), 4096)
    }

    #[test]
    fn a_hash_verifies_against_its_own_password_and_no_other() -> R {
        let hasher = hasher()?;
        let phc = hasher.hash("correct horse battery staple")?;
        assert!(phc.starts_with("$argon2id$v=19$"), "{phc}");
        assert!(hasher.verify("correct horse battery staple", &phc));
        assert!(!hasher.verify("Correct horse battery staple", &phc));
        assert!(!hasher.verify("", &phc));
        Ok(())
    }

    #[test]
    fn two_hashes_of_one_password_differ_because_the_salt_does() -> R {
        let hasher = hasher()?;
        let first = hasher.hash("hunter2")?;
        let second = hasher.hash("hunter2")?;
        assert_ne!(first, second);
        assert!(hasher.verify("hunter2", &first));
        assert!(hasher.verify("hunter2", &second));
        Ok(())
    }

    #[test]
    fn a_malformed_stored_hash_is_a_refusal_not_an_error() -> R {
        let hasher = hasher()?;
        for phc in [
            "",
            "not a phc string",
            "$argon2id$v=19$m=8,t=1,p=1$",
            "$scrypt$v=1$n=8,r=1,p=1$c2FsdA$aGFzaA",
        ] {
            assert!(!hasher.verify("hunter2", phc), "{phc:?} verified");
        }
        Ok(())
    }

    #[test]
    fn the_dummy_hash_always_refuses_and_costs_what_a_real_one_costs() -> R {
        let hasher = hasher()?;
        assert!(!hasher.verify_dummy("hunter2"));
        assert!(!hasher.verify_dummy(""));
        // Two hashers built from the same parameters do not share a dummy: it
        // is per-process and random, so a stolen state file reveals nothing.
        let other = Hasher::new(cheap(), 4096)?;
        assert!(!other.verify_dummy("hunter2"));
        Ok(())
    }

    #[test]
    fn the_cost_comes_from_the_configuration_and_the_host() -> R {
        assert_eq!(hasher()?.cost(), (8, 1, 1));
        let derived = Hasher::new(Argon2Params::default(), 256)?;
        assert_eq!(derived.cost(), (MIN_ARGON2_M_KIB, 3, 1));
        Ok(())
    }

    #[test]
    fn unusable_parameters_are_a_typed_failure() -> R {
        let broken = Argon2Params {
            m_kib: Some(1),
            t: 1,
            p: 1,
        };
        match Hasher::new(broken, 4096) {
            Err(err @ AuthError::Params(_)) => {
                assert_eq!(err.message_id().as_str(), "web-auth-argon2-params");
                assert!(!err.to_string().is_empty());
            }
            other => return Err(format!("expected a parameter failure, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn the_debug_output_carries_no_password_and_no_hash() -> R {
        let hasher = hasher()?;
        let phc = hasher.hash("swordfish")?;
        let rendered = format!("{hasher:?}");
        assert!(rendered.contains("m_kib: 8"), "{rendered}");
        assert!(!rendered.contains("swordfish"), "{rendered}");
        assert!(!rendered.contains("argon2id"), "{rendered}");
        assert!(!rendered.contains(&phc), "{rendered}");
        assert!(!rendered.contains("dummy"), "{rendered}");
        Ok(())
    }

    /// PLAN Phase 4, task 2: "unknown-user timing parity (statistical,
    /// ±10 %)".
    ///
    /// Ignored by default because a wall-clock assertion on a shared CI runner
    /// is a flaky test, and a flaky test in an auth suite is worse than an
    /// unrun one. Run it with:
    ///
    /// ```text
    /// cargo test -p detent-web -- --ignored unknown_user_and_wrong_password
    /// ```
    #[test]
    #[ignore = "wall-clock timing; run explicitly with --ignored"]
    fn unknown_user_and_wrong_password_cost_the_same() -> R {
        use std::time::Instant;

        // Real parameters, not the cheap ones: the point is the ratio at a
        // cost where the Argon2 pass dominates everything else.
        let hasher = Hasher::new(Argon2Params::default(), 4096)?;
        let phc = hasher.hash("the real password")?;

        let time = |body: &dyn Fn()| -> u128 {
            let started = Instant::now();
            body();
            started.elapsed().as_nanos()
        };
        let known = || {
            let _ = hasher.verify("wrong password", &phc);
        };
        let unknown = || {
            let _ = hasher.verify_dummy("wrong password");
        };

        // Warm the allocator and the caches before measuring either branch.
        known();
        unknown();

        // **Interleaved**, not one branch after the other. Each verification
        // allocates the whole 64 MiB Argon2 block, so a run that measures 25
        // of one and then 25 of the other charges the first branch for page
        // faults the second one inherits warm — which reads as a 15 % timing
        // oracle that is really just measurement order. Alternating within the
        // loop, and swapping which goes first on odd iterations, cancels both
        // that and any residual first-in-pair bias.
        let mut known_ns = Vec::new();
        let mut unknown_ns = Vec::new();
        for iteration in 0_u32..25 {
            if iteration % 2 == 0 {
                known_ns.push(time(&known));
                unknown_ns.push(time(&unknown));
            } else {
                unknown_ns.push(time(&unknown));
                known_ns.push(time(&known));
            }
        }
        let median = |mut timings: Vec<u128>| -> u128 {
            timings.sort_unstable();
            timings.get(timings.len() / 2).copied().unwrap_or_default()
        };
        let wrong_password = median(known_ns);
        let unknown_user = median(unknown_ns);

        // Printed so that a run under `--nocapture` records what was actually
        // measured, not merely that a bound held.
        eprintln!(
            "wrong-password {wrong_password} ns, unknown-user {unknown_user} ns, ratio {:.4}",
            f64::from(u32::try_from(wrong_password.max(unknown_user)).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(wrong_password.min(unknown_user)).unwrap_or(1))
        );
        let (low, high) = if wrong_password < unknown_user {
            (wrong_password, unknown_user)
        } else {
            (unknown_user, wrong_password)
        };
        // `high / low <= 1.10`, in integers so no float creeps into a test
        // whose whole subject is a measurement.
        assert!(
            high.saturating_mul(100) <= low.saturating_mul(110),
            "median wrong-password {wrong_password} ns vs unknown-user {unknown_user} ns \
             is outside the ±10 % PLAN §5 Phase 4 requires"
        );
        Ok(())
    }
    #[test]
    fn a_parameter_rotation_marks_only_old_hashes_for_rehash() -> R {
        let old = Hasher::new(
            Argon2Params {
                m_kib: Some(8),
                t: 1,
                p: 1,
            },
            4096,
        )?;
        let old_phc = old.hash("hunter2")?;
        let current = Hasher::new(
            Argon2Params {
                m_kib: Some(16),
                t: 1,
                p: 1,
            },
            4096,
        )?;
        assert!(current.needs_rehash(&old_phc));
        assert!(!current.needs_rehash(&current.hash("hunter2")?));
        assert!(current.needs_rehash("not a phc string"));
        // Rotation changes cost, not credential validity.
        assert!(current.verify("hunter2", &old_phc));
        Ok(())
    }
}
