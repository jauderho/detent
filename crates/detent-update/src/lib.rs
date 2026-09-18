//! `detent-update`: the self-update client and in-tree Sigstore verifier
//! (PLAN §2.9, ADR-005, ADR-014).
//!
//! ```text
//!   GitHub releases ──▶ fetch ──▶ policy ──▶ bundle ──▶ verify ──▶ trust
//!                                              (strict v0.3)  6 steps   (embedded,
//!                                                                        refuse-closed)
//! ```
//!
//! * [`fetch`] is the single shared hyper-rustls client behind a mockable
//!   [`fetch::Transport`] seam — no `reqwest`, no second TLS stack (ADR-009);
//! * [`policy`] is the release-selection policy (semver, downgrade refusal,
//!   age gate, security bypass);
//! * [`bundle`] parses the v0.3 Sigstore bundle under a 1 MiB cap;
//! * [`verify`] runs the six ordered verification steps of ADR-014 with zero
//!   I/O and refuses closed: every [`VerificationError`] aborts the update,
//!   never an unverified install;
//! * [`trust`] embeds the Fulcio roots and Rekor log key at build time from
//!   the `trust/` files — placeholders until the first tagged release, so
//!   this build refuses every update with
//!   [`VerificationError::TrustRootUnavailable`];
//! * [`update`] is the flow: [`update::check`] for `detent update --check`,
//!   [`update::prepare`] through the verified, self-testable candidate, with
//!   the privileged swap (`ReplaceBinary`) still unwired.
//!
//! The verifier itself is fully offline (ADR-014): bundles carry certificate
//! chain, DSSE signature and Rekor inclusion proof, so nothing but the
//! download ever touches the network.

pub mod bundle;
pub mod fetch;
pub mod policy;
pub mod trust;
pub mod update;
pub mod verify;

pub use bundle::{Decoded, Statement, Subject, SubjectDigest};
pub use fetch::{FetchError, Transport};
pub use policy::{Candidate, Policy, PolicyError};
pub use trust::TrustRoot;
pub use update::{Candidate as StagedUpdate, CheckReport, FeatureSet, UpdateError};
pub use verify::VerificationError;
