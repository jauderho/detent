//! device-attest-01 attestor seam: build the CBOR payload, caller sends it.
//!
//! The seam mirrors [`crate::DnsProvider`]: an [`Attestor`] produces the
//! attestation object for a device key, and the caller — not the attestor —
//! drives the ACME order through `instant-acme`'s experimental
//! `send_device_attestation`. The seam types are sync and std-only so the
//! first attestor (a test double) needs no hardware; the TPM 2.0 backend
//! (`tss-esapi`) arrives later behind the `acme-attest` feature.

use crate::AcmeError;

/// Builds the raw attestation object (`att_obj`) for a device key.
///
/// Implementations format the payload the CA expects — the TPM 2.0 backend
/// AK-signs `TPM2_Certify` over the new key — and return it as the CBOR bytes
/// `instant-acme` base64url-encodes into `DeviceAttestation`. The caller
/// owns retry timing and the order itself, exactly like [`crate::DnsProvider`].
pub trait Attestor: Send + Sync {
    /// Build the CBOR attestation object for `key_id` and `key_authorization`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the attestor cannot sign for this key.
    fn attest(&self, key_id: &str, key_authorization: &str) -> Result<Vec<u8>, AcmeError>;
}

/// Deterministic test double: the payload is `key_id/key_authorization`,
/// so a driver test can assert what the attestor saw.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct TestAttestor;

#[cfg(test)]
impl Attestor for TestAttestor {
    fn attest(&self, key_id: &str, key_authorization: &str) -> Result<Vec<u8>, AcmeError> {
        if key_id.is_empty() || key_authorization.is_empty() {
            return Err(AcmeError::Config(
                "test attestor needs a non-empty key id and key authorization".to_owned(),
            ));
        }
        Ok(format!("{key_id}/{key_authorization}").into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_attestor_encodes_what_it_saw() {
        let att_obj = TestAttestor
            .attest("ak-1", "authz-token")
            .expect("test attestor with non-empty inputs");
        assert_eq!(att_obj, b"ak-1/authz-token");
    }

    #[test]
    fn test_attestor_refuses_empty_inputs() {
        assert!(TestAttestor.attest("", "authz-token").is_err());
        assert!(TestAttestor.attest("ak-1", "").is_err());
    }

    #[test]
    fn attestor_is_object_safe() {
        fn boxed(_: Box<dyn Attestor>) {}
        boxed(Box::new(TestAttestor));
    }
}
