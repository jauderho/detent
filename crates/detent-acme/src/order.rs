//! ACME dns-01 order flow: account creation, challenge presentation, issuance.
//!
//! The seam mirrors [`crate::DnsProvider`]: a [`DnsProvider`] publishes the
//! TXT records, this module drives the RFC 8555 order lifecycle through
//! `instant-acme`. Async on purpose — `instant-acme` is an async client and
//! the workspace already depends on tokio; wrapping it in a sync shim would
//! embed a runtime in the library.
//!
//! No sleeps live here: the caller steps [`present_challenges`],
//! [`wait_ready`], and [`finalize`] through their retry loops.

use crate::{AcmeError, DnsProvider, DnsRecord};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use std::path::Path;

/// Runs the dns-01 challenge presentation step of an order.
///
/// For every still-pending authorization it computes the dns-01 TXT record,
/// hands it to `provider` (present + propagation check), and marks the
/// challenge ready with the ACME server. Authorizations that are already
/// valid are skipped. `publish` is a synchronous callback between present
/// and propagation for providers that need a push (e.g. challtestsrv); pass
/// `|_| Ok(())` when the provider alone is authoritative.
///
/// # Errors
///
/// [`AcmeError::Acme`] when instant-acme or the provider fails.
pub async fn present_challenges(
    order: &mut Order,
    provider: &dyn DnsProvider,
    publish: &dyn Fn(&DnsRecord) -> Result<(), AcmeError>,
) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(AcmeError::from)?;
        if !matches!(authz.status, AuthorizationStatus::Pending) {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or(AcmeError::NoDns01Challenge)?;
        let domain = challenge.identifier().to_string();
        let record = DnsRecord::new(
            format!("_acme-challenge.{domain}"),
            challenge.key_authorization().dns_value(),
        )?;
        provider.present(&record)?;
        publish(&record)?;
        provider.wait_propagated(&record)?;
        challenge.set_ready().await.map_err(AcmeError::from)?;
    }
    Ok(())
}

/// Polls the order until the server reports `ready` or `invalid`.
///
/// The retry policy owns the timing: no sleeps in this library.
///
/// # Errors
///
/// [`AcmeError::Acme`] on API errors or timeout.
pub async fn wait_ready(order: &mut Order, policy: &RetryPolicy) -> Result<OrderStatus, AcmeError> {
    order.poll_ready(policy).await.map_err(AcmeError::from)
}

/// Finalizes a `ready` order and returns the PEM certificate chain.
///
/// The CSR is generated with the `rcgen` feature of instant-acme; the
/// returned chain is the leaf followed by intermediates.
///
/// # Errors
///
/// [`AcmeError::Acme`] when finalization or the certificate download fails.
pub async fn finalize(
    order: &mut Order,
    policy: &RetryPolicy,
) -> Result<(String, String), AcmeError> {
    let private_key_pem = order.finalize().await.map_err(AcmeError::from)?;
    let cert_chain_pem = order
        .poll_certificate(policy)
        .await
        .map_err(AcmeError::from)?;
    Ok((cert_chain_pem, private_key_pem))
}

/// Creates (or restores) an ACME account and issues a new dns-01 order.
///
/// The account credentials are serialized to `credentials_path` with `0600`
/// permissions on first use and restored from it afterwards, so repeated
/// runs reuse one ACME account.
///
/// # Errors
///
/// [`AcmeError::Acme`] on API errors, [`AcmeError::Io`] on credential
/// persistence failures.
pub async fn account_and_order(
    directory_url: &str,
    domains: &[&str],
    credentials_path: &Path,
    ca_root: Option<&Path>,
) -> Result<(Account, Order), AcmeError> {
    let account = load_or_create_account(directory_url, credentials_path, ca_root).await?;
    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns((*d).to_owned()))
        .collect();
    let order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(AcmeError::from)?;
    Ok((account, order))
}

/// Restores an account from the credential file, or creates a new one and
/// persists the credentials atomically with `0600` permissions.
async fn load_or_create_account(
    directory_url: &str,
    credentials_path: &Path,
    ca_root: Option<&Path>,
) -> Result<Account, AcmeError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let builder = match ca_root {
        Some(pem) => Account::builder_with_root(pem).map_err(AcmeError::from)?,
        None => Account::builder().map_err(AcmeError::from)?,
    };

    if let Ok(json) = std::fs::read_to_string(credentials_path) {
        let credentials: AccountCredentials = serde_json::from_str(&json)
            .map_err(|e| AcmeError::Credentials(format!("deserialize: {e}")))?;
        return builder
            .from_credentials(credentials)
            .await
            .map_err(AcmeError::from);
    }

    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await
        .map_err(AcmeError::from)?;

    let json = serde_json::to_string(&credentials)
        .map_err(|e| AcmeError::Credentials(format!("serialize: {e}")))?;
    // Atomic 0600 write, same pattern as HookProvider: pid-suffixed temp
    // file in the target directory, then rename, so a crash never leaves a
    // partial credential file readable under the umask.
    if let Some(parent) = credentials_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = credentials_path.with_extension(format!("{}.tmp", std::process::id()));
    let write = || -> Result<(), AcmeError> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(json.as_bytes())?;
        std::fs::rename(&tmp, credentials_path)?;
        Ok(())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use instant_acme::{AuthorizationState, ChallengeStatus, OrderState, OrderStatus, Problem};

    // Recorded instant-acme fixtures: RFC 8555 order/authorization JSON as
    // Pebble serves it, trimmed to the fields the driver reads. No network.
    const ORDER_PENDING: &str = r#"{
        "status": "pending",
        "authorizations": [],
        "finalize": "https://pebble/finalize/1",
        "certificate": null
    }"#;
    const AUTHZ_PENDING: &str = r#"{
        "identifier": {"type": "dns", "value": "example.com"},
        "status": "pending",
        "challenges": [{
            "type": "dns-01",
            "url": "https://pebble/chall/1",
            "token": "token-1",
            "status": "pending"
        }]
    }"#;

    #[test]
    fn order_state_fixture_parses_and_transitions() -> Result<(), String> {
        let state: OrderState =
            serde_json::from_str(ORDER_PENDING).map_err(|e| format!("fixture must parse: {e}"))?;
        assert!(matches!(state.status, OrderStatus::Pending));
        assert!(state.certificate.is_none());
        Ok(())
    }

    #[test]
    fn authorization_fixture_parses_and_offers_dns01() -> Result<(), String> {
        let authz: AuthorizationState =
            serde_json::from_str(AUTHZ_PENDING).map_err(|e| format!("fixture must parse: {e}"))?;
        assert!(matches!(authz.status, AuthorizationStatus::Pending));
        let ch = authz
            .challenges
            .first()
            .ok_or_else(|| "fixture must offer a challenge".to_owned())?;
        assert!(matches!(ch.r#type, ChallengeType::Dns01));
        assert!(matches!(ch.status, ChallengeStatus::Pending));
        assert_eq!(ch.token, "token-1");
        Ok(())
    }

    #[test]
    fn dns_record_from_challenge_path_shape() -> Result<(), String> {
        // RFC 8555 §8.4: the TXT name is _acme-challenge.<domain> and the
        // value is base64url(SHA-256(keyauthz)) — alphanumeric, '-' and '_'.
        let r = DnsRecord::new(
            "_acme-challenge.example.com",
            "aGlfcGFzc2VkLXRoaXMtdGV4dC1jaGFyYWN0ZXItY2xhc3M",
        )
        .map_err(|e| format!("record must validate: {e}"))?;
        assert_eq!(r.fqdn(), "_acme-challenge.example.com");
        assert!(
            r.value()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        Ok(())
    }

    #[test]
    fn no_dns01_challenge_maps_to_error() -> Result<(), String> {
        let authz: AuthorizationState = serde_json::from_str(
            r#"{"identifier":{"type":"dns","value":"x.com"},"status":"pending","challenges":[{"type":"http-01","url":"u","token":"t","status":"pending"}]}"#,
        )
        .map_err(|e| format!("fixture must parse: {e}"))?;
        let has_dns01 = authz
            .challenges
            .iter()
            .any(|c| matches!(c.r#type, ChallengeType::Dns01));
        assert!(!has_dns01);
        Ok(())
    }

    #[test]
    fn problem_fixture_parses() -> Result<(), String> {
        let p: Problem = serde_json::from_str(
            r#"{"type":"urn:ietf:params:acme:error:dns","detail":"no TXT","status":400}"#,
        )
        .map_err(|e| format!("fixture must parse: {e}"))?;
        assert_eq!(p.status, Some(400));
        Ok(())
    }
}
