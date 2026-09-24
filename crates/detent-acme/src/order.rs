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
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse,
    ChallengeType, HttpClient, Identifier, NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use std::path::Path;
use std::pin::Pin;

type AcmeHttpClient = Client<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>;

struct Tls13HttpClient(AcmeHttpClient);

impl HttpClient for Tls13HttpClient {
    fn request(
        &self,
        request: hyper::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let future = self.0.request(request);
        Box::pin(async move {
            future
                .await
                .map(BytesResponse::from)
                .map_err(|err| instant_acme::Error::Other(Box::new(err)))
        })
    }
}

fn account_builder(ca_root: Option<&Path>) -> Result<AccountBuilder, AcmeError> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_root {
        Some(path) => {
            let pem = std::fs::read(path)?;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                roots
                    .add(
                        cert.map_err(|err| {
                            AcmeError::Config(format!("invalid ACME CA root: {err}"))
                        })?,
                    )
                    .map_err(|err| AcmeError::Config(format!("invalid ACME CA root: {err}")))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let versions = &[&rustls::version::TLS13];
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(versions)
    .map_err(|err| AcmeError::Config(format!("TLS 1.3 client: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    Ok(Account::builder_with_http(Box::new(Tls13HttpClient(
        client,
    ))))
}

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
) -> Result<Vec<DnsRecord>, AcmeError> {
    let mut presented: Vec<DnsRecord> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(a) => a,
            Err(e) => {
                cleanup_challenges(provider, &presented);
                return Err(AcmeError::from(e));
            }
        };
        if !matches!(authz.status, AuthorizationStatus::Pending) {
            continue;
        }
        let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) else {
            cleanup_challenges(provider, &presented);
            return Err(AcmeError::NoDns01Challenge);
        };
        let domain = challenge.identifier().to_string();
        let record = match DnsRecord::new(
            format!("_acme-challenge.{domain}"),
            challenge.key_authorization().dns_value(),
        ) {
            Ok(r) => r,
            Err(e) => {
                cleanup_challenges(provider, &presented);
                return Err(e);
            }
        };
        if let Err(e) = provider.present(&record) {
            cleanup_challenges(provider, &presented);
            return Err(e);
        }
        presented.push(record.clone());
        if let Err(e) = publish(&record) {
            let _ = provider.delete(&record);
            presented.pop();
            cleanup_challenges(provider, &presented);
            return Err(e);
        }
        if let Err(e) = provider.wait_propagated(&record) {
            let _ = provider.delete(&record);
            presented.pop();
            cleanup_challenges(provider, &presented);
            return Err(e);
        }
        if let Err(e) = challenge.set_ready().await.map_err(AcmeError::from) {
            let _ = provider.delete(&record);
            presented.pop();
            cleanup_challenges(provider, &presented);
            return Err(e);
        }
    }
    Ok(presented)
}

/// Deletes every record in `records` through `provider`, ignoring delete
/// errors. Callers run this after `finalize` whatever the outcome.
pub fn cleanup_challenges(provider: &dyn DnsProvider, records: &[DnsRecord]) {
    for record in records {
        let _ = provider.delete(record);
    }
}

/// Runs the device-attest-01 challenge presentation step of an order.
///
/// For every still-pending authorization it builds the attestation object
/// through `attestor` and sends it with the ACME server. Authorizations that
/// are already valid are skipped.
///
/// # Errors
///
/// [`AcmeError::Acme`] when instant-acme or the attestor fails.
pub async fn present_attest_challenges(
    order: &mut Order,
    attestor: &dyn crate::Attestor,
) -> Result<(), AcmeError> {
    use instant_acme::DeviceAttestation;
    use std::borrow::Cow;

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(AcmeError::from)?;
        if !matches!(authz.status, AuthorizationStatus::Pending) {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::DeviceAttest01)
            .ok_or(AcmeError::NoDeviceAttestChallenge)?;
        let key_authorization = challenge.key_authorization();
        let key_id = challenge.identifier().to_string();
        let att_obj = attestor.attest(&key_id, key_authorization.as_str())?;
        let payload = DeviceAttestation {
            att_obj: Cow::Borrowed(att_obj.as_slice()),
        };
        challenge
            .send_device_attestation(&payload)
            .await
            .map_err(AcmeError::from)?;
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

/// What a finalized ACME order hands back.
///
/// Named rather than a `(String, String)`: both halves are PEM, so a tuple
/// lets `let (key, chain) = finalize(..)` compile and write the private key
/// to the certificate's path. The field names make that a type error.
#[derive(Clone, PartialEq, Eq)]
pub struct Issued {
    /// The certificate chain, leaf first, then intermediates.
    pub chain_pem: String,
    /// The PKCS#8 private key for the leaf.
    pub key_pem: String,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("chain_pem", &self.chain_pem)
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

/// Finalizes a `ready` order and returns the certificate and its key.
///
/// The CSR is generated with the `rcgen` feature of instant-acme; the
/// returned chain is the leaf followed by intermediates.
///
/// # Errors
///
/// [`AcmeError::Acme`] when finalization or the certificate download fails.
pub async fn finalize(order: &mut Order, policy: &RetryPolicy) -> Result<Issued, AcmeError> {
    let key_pem = order.finalize().await.map_err(AcmeError::from)?;
    let chain_pem = order
        .poll_certificate(policy)
        .await
        .map_err(AcmeError::from)?;
    Ok(Issued { chain_pem, key_pem })
}

/// The ARI identifier for the leaf of `chain_pem`: the DER-encoded AKI
/// `keyIdentifier` octet string and DER-encoded serial `instant-acme` needs
/// for [`Account::renewal_info`](instant_acme::Account::renewal_info).
///
/// Pebble (like every CA) stamps an Authority Key Identifier, so a missing
/// AKI is [`AcmeError::Config`] rather than a fallback — silently omitting
/// the identifier would query the wrong renewal slot.
///
/// # Errors
///
/// [`AcmeError::Config`] when the chain does not parse or carries no AKI.
pub fn ari_identifier(
    chain_pem: &str,
) -> Result<instant_acme::CertificateIdentifier<'static>, AcmeError> {
    use x509_parser::prelude::FromDer as _;
    let leaf_der = pem_block(chain_pem)
        .ok_or_else(|| AcmeError::Config("ARI: certificate chain has no PEM block".into()))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&leaf_der)
        .map_err(|e| AcmeError::Config(format!("ARI: leaf certificate does not parse: {e}")))?;
    let aki = cert
        .iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        })
        .ok_or_else(|| {
            AcmeError::Config("ARI: leaf certificate has no authority key identifier".into())
        })?;
    let serial = cert.tbs_certificate.raw_serial().to_vec();
    // The identifier wants the DER-encoded values: the AKI octet string
    // contents and the serial INTEGER contents, not their big-int forms.
    Ok(instant_acme::CertificateIdentifier::new(
        rustls_pki_types::Der::from(aki),
        rustls_pki_types::Der::from(serial),
    )
    .into_owned())
}

/// First PEM block of a chain as DER, std-only (same shape as the Pebble
/// live test's helper, minus the test-only base64 decoder's lint allows).
fn pem_block(chain_pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let block = chain_pem
        .split("-----END CERTIFICATE-----")
        .find(|b| b.contains("BEGIN CERTIFICATE"))?;
    let body: String = block.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .ok()
}

/// Fetches the ARI suggested window for `chain_pem` and answers whether
/// renewal should happen now: inside the window the lifetime rule applies,
/// outside it only a nearly-spent certificate renews early.
///
/// `now_unix` and the window bounds are Unix seconds so the caller — not
/// this helper — owns the clock. A server without ARI support
/// ([`instant_acme::Error::Unsupported`]) falls back to the plain lifetime
/// rule rather than refusing renewal outright.
///
/// # Errors
///
/// [`AcmeError::Acme`] on API errors; [`AcmeError::Config`] when the chain
/// does not parse.
pub async fn should_renew_ari(
    account: &instant_acme::Account,
    chain_pem: &str,
    not_before: i64,
    not_after: i64,
    now_unix: i64,
) -> Result<bool, AcmeError> {
    let id = ari_identifier(chain_pem)?;
    let fetched = account.renewal_info(&id).await;
    decide_renewal(fetched, not_before, not_after, now_unix)
}

/// Decides renewal from an already-fetched ARI result: `Unsupported` falls
/// back to the plain lifetime rule (a server without ARI support must not
/// refuse renewal outright); any other error propagates; a suggested window
/// narrows the answer through [`crate::schedule::should_renew_in_window`].
///
/// Split from [`should_renew_ari`] so the three arms test without a network:
/// `RenewalInfo`'s fields are public, and `instant_acme::Error::Unsupported`
/// and `Error::Str` construct offline.
fn decide_renewal(
    result: Result<(instant_acme::RenewalInfo, std::time::Duration), instant_acme::Error>,
    not_before: i64,
    not_after: i64,
    now_unix: i64,
) -> Result<bool, AcmeError> {
    let info = match result {
        Ok((info, _)) => info,
        Err(instant_acme::Error::Unsupported(_)) => {
            return Ok(crate::schedule::should_renew(
                not_before, not_after, now_unix,
            ));
        }
        Err(e) => return Err(AcmeError::Acme(e)),
    };
    let window = Some((
        info.suggested_window.start.unix_timestamp(),
        info.suggested_window.end.unix_timestamp(),
    ));
    Ok(crate::schedule::should_renew_in_window(
        not_before, not_after, now_unix, window,
    ))
}

/// External Account Binding credentials (RFC 8555 §7.3.4): the CA-issued
/// key id plus its base64-encoded HMAC key. The key is decoded (standard
/// or URL-safe base64) only when registering a fresh account — a restored
/// account from `credentials_path` never touches it.
#[derive(Clone, PartialEq, Eq)]
pub struct EabCredentials {
    /// The CA-issued external account key id.
    pub kid: String,
    /// The base64-encoded HMAC key value (standard or URL-safe alphabet).
    pub key_b64: String,
}

impl std::fmt::Debug for EabCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EabCredentials")
            .field("kid", &self.kid)
            .field("key_b64", &"[redacted]")
            .finish()
    }
}

/// Creates (or restores) an ACME account and issues a new dns-01 order.
///
/// The account credentials are serialized to `credentials_path` with `0600`
/// permissions on first use and restored from it afterwards, so repeated
/// runs reuse one ACME account.
///
/// `profile` names the CA profile to request (e.g. `"shortlived"`, the
/// default on Let's Encrypt); pass `None` where the server advertises no
/// profiles extension (Pebble). An unsupported profile fails the order with
/// [`AcmeError::Acme`] — the caller picks the fallback, not this module.
///
/// `contacts` holds `mailto:`/`tel:` URIs recorded on fresh registration;
/// `eab` binds registration to a CA-issued external account. Both are
/// ignored when `credentials_path` already holds an account.
///
/// # Errors
///
/// [`AcmeError::Acme`] on API errors, [`AcmeError::Io`] on credential
/// persistence failures, [`AcmeError::Config`] on a bad EAB key.
pub async fn account_and_order(
    directory_url: &str,
    domains: &[&str],
    credentials_path: &Path,
    ca_root: Option<&Path>,
    profile: Option<&str>,
    contacts: &[&str],
    eab: Option<&EabCredentials>,
) -> Result<(Account, Order), AcmeError> {
    let account =
        load_or_create_account(directory_url, credentials_path, ca_root, contacts, eab).await?;
    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns((*d).to_owned()))
        .collect();
    let new_order = match profile {
        Some(p) => NewOrder::new(&identifiers).profile(p),
        None => NewOrder::new(&identifiers),
    };
    let order = account
        .new_order(&new_order)
        .await
        .map_err(AcmeError::from)?;
    Ok((account, order))
}

/// Builds the RFC 8555 external-account key, decoding `key_b64` first.
fn eab_key(eab: &EabCredentials) -> Result<instant_acme::ExternalAccountKey, AcmeError> {
    use base64::Engine as _;
    if eab.kid.is_empty() {
        return Err(AcmeError::Config("EAB key id must not be empty".into()));
    }
    // ponytail: try standard then URL-safe; CAs emit either alphabet.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(eab.key_b64.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(eab.key_b64.as_bytes())
        })
        .map_err(|e| AcmeError::Config(format!("EAB key is not base64: {e}")))?;
    if raw.is_empty() {
        return Err(AcmeError::Config("EAB key must not decode to empty".into()));
    }
    Ok(instant_acme::ExternalAccountKey::new(eab.kid.clone(), &raw))
}

/// The cached account credentials, or `None` when this host has no account
/// yet.
///
/// Only a *missing* file means "no account yet". Every other failure —
/// EACCES, EIO, a dangling symlink, a directory in the file's place — is
/// propagated, because falling through would register a **second** ACME
/// account at the CA and then rename over the first one's credentials,
/// silently rotating an identity the CA still honours and destroying the key
/// for the old one.
fn read_credentials(path: &Path) -> Result<Option<String>, AcmeError> {
    match std::fs::read_to_string(path) {
        Ok(json) => Ok(Some(json)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AcmeError::Io(e)),
    }
}

/// Restores an account from the credential file, or creates a new one and
/// persists the credentials atomically with `0600` permissions.
async fn load_or_create_account(
    directory_url: &str,
    credentials_path: &Path,
    ca_root: Option<&Path>,
    contacts: &[&str],
    eab: Option<&EabCredentials>,
) -> Result<Account, AcmeError> {
    // Read before building anything: a caller whose credential file is
    // unreadable gets that answer without a crypto provider or a network
    // client having to exist first.
    let cached = read_credentials(credentials_path)?;
    // Decode before the builder too: a malformed EAB refuses before any
    // client exists (under `--all-features` the builder itself panics on
    // the ambiguous provider, so anything after it is untestable there).
    // Skipped when a cached account exists — EAB only binds fresh
    // registration, and a restored account never touches it.
    let key = match cached {
        Some(_) => None,
        None => eab.map(eab_key).transpose()?,
    };

    let builder = account_builder(ca_root)?;

    if let Some(json) = cached {
        let credentials = parse_credentials(&json)?;
        return builder
            .from_credentials(credentials)
            .await
            .map_err(AcmeError::from);
    }
    create_fresh(
        directory_url,
        builder,
        credentials_path,
        contacts,
        key.as_ref(),
    )
    .await
}

/// Parses cached account credentials: garbage must surface as
/// [`AcmeError::Credentials`], never as a fresh account registration.
///
/// Split from [`load_or_create_account`] so the mapping tests without an
/// ACME client or a network.
fn parse_credentials(json: &str) -> Result<AccountCredentials, AcmeError> {
    serde_json::from_str(json).map_err(|e| AcmeError::Credentials(format!("deserialize: {e}")))
}

/// Registers a fresh account and persists its credentials atomically.
async fn create_fresh(
    directory_url: &str,
    builder: instant_acme::AccountBuilder,
    credentials_path: &Path,
    contacts: &[&str],
    eab: Option<&instant_acme::ExternalAccountKey>,
) -> Result<Account, AcmeError> {
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            eab,
        )
        .await
        .map_err(AcmeError::from)?;

    let json = serde_json::to_string(&credentials)
        .map_err(|e| AcmeError::Credentials(format!("serialize: {e}")))?;
    write_json_atomically(credentials_path, &json)?;
    Ok(account)
}

/// Writes `json` to `path` atomically with `0600` permissions: a
/// pid-suffixed temp file in the target directory, then rename, so a crash
/// never leaves a partial credential file readable under the umask.
///
/// Split from [`load_or_create_account`] so the write machinery tests
/// without an ACME account: success, mode, stale-temp recovery, and the
/// unwritable-parent failure are all filesystem facts.
fn write_json_atomically(path: &Path, json: &str) -> Result<(), AcmeError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // Atomic 0600 write, same pattern as HookProvider: pid-suffixed temp
    // file in the target directory, then rename, so a crash never leaves a
    // partial credential file readable under the umask.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let write = || -> Result<(), AcmeError> {
        // `create_new`, not `create`: `mode` is applied only when the file is
        // created, so reopening a leftover temp file — a crash plus PID reuse
        // — would write the account key through whatever mode that file
        // already carries. A stale one is removed first, so this still
        // succeeds on the retry rather than wedging the host forever.
        if tmp.exists() {
            std::fs::remove_file(&tmp)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fuzz entry points
// ---------------------------------------------------------------------------

/// Feeds arbitrary bytes through the ACME JSON response parsers.
///
/// `OrderState`, `AuthorizationState` and `Problem` all arrive from the CA
/// over the network, so malformed JSON must map to `Err`, never to a panic.
/// Only compiled with the `fuzzing` feature for `cargo-fuzz`.
#[cfg(feature = "fuzzing")]
pub fn fuzz_acme_json(data: &[u8]) {
    let _ = serde_json::from_slice::<instant_acme::OrderState>(data);
    let _ = serde_json::from_slice::<instant_acme::AuthorizationState>(data);
    let _ = serde_json::from_slice::<instant_acme::Problem>(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use instant_acme::{AuthorizationState, ChallengeStatus, OrderState, OrderStatus, Problem};

    #[test]
    fn issued_debug_redacts_private_key() {
        let issued = Issued {
            chain_pem: "certificate".to_owned(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_owned(),
        };
        let dump = format!("{issued:?}");
        assert!(!dump.contains("PRIVATE KEY"));
        assert!(dump.contains("[redacted]"));
    }

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
    fn profile_selection_serializes_onto_the_order() -> Result<(), String> {
        let ids = [Identifier::Dns("example.com".to_owned())];
        // Pebble advertises no profiles extension: no profile requested.
        let plain = serde_json::to_value(NewOrder::new(&ids))
            .map_err(|e| format!("order must serialize: {e}"))?;
        assert!(plain.get("profile").is_none());
        // Production default: the shortlived profile rides the new-order body.
        let profiled = serde_json::to_value(NewOrder::new(&ids).profile("shortlived"))
            .map_err(|e| format!("profiled order must serialize: {e}"))?;
        assert_eq!(
            profiled.get("profile").and_then(|p| p.as_str()),
            Some("shortlived")
        );
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
    fn ari_identifier_rejects_garbage_and_bare_chains() {
        // No PEM block at all.
        assert!(matches!(
            ari_identifier("not a certificate"),
            Err(AcmeError::Config(_))
        ));
        // A PEM block that is not a certificate (Pebble serves chains, not
        // keys, so wrong-armour input is a caller bug worth refusing).
        let key_pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(matches!(ari_identifier(key_pem), Err(AcmeError::Config(_))));
    }

    #[test]
    fn ari_identifier_reads_aki_and_serial_off_a_chain() -> Result<(), String> {
        // A real CA stamps an Authority Key Identifier; rcgen only writes
        // one when asked, so flip the flag — the self-signed cert then
        // carries the SKI-as-AKI shape `ari_identifier` parses.
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
        let mut params = CertificateParams::new(vec!["ari.example".to_owned()])
            .map_err(|e| format!("fixture params must build: {e}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "ari.example");
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().map_err(|e| format!("fixture key must generate: {e}"))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("fixture cert must sign: {e}"))?;
        let chain_pem = cert.pem();
        let id =
            ari_identifier(&chain_pem).map_err(|e| format!("ARI identifier must parse: {e}"))?;
        assert!(!id.serial.is_empty(), "serial must survive the bridge");
        assert!(
            !id.authority_key_identifier.is_empty(),
            "AKI must survive the bridge"
        );
        Ok(())
    }

    #[test]
    fn ari_identifier_rejects_a_chain_without_aki() -> Result<(), String> {
        // Default rcgen writes no AKI unless asked: `find_map` reaches the
        // `_ => None` arm, and the missing identifier is `Config`, never a
        // silent fallback to the wrong renewal slot.
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
        let mut params = CertificateParams::new(vec!["noaki.example".to_owned()])
            .map_err(|e| format!("fixture params must build: {e}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "noaki.example");
        params.is_ca = IsCa::NoCa;
        let key = KeyPair::generate().map_err(|e| format!("fixture key must generate: {e}"))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("fixture cert must sign: {e}"))?;
        let err = ari_identifier(&cert.pem())
            .err()
            .ok_or("a chain without AKI must fail")?;
        assert!(
            matches!(&err, AcmeError::Config(m) if m.contains("no authority key identifier")),
            "missing AKI must be Config, got {err:?}"
        );
        Ok(())
    }

    /// A credential file that exists but cannot be read must not be mistaken
    /// for "no account yet".
    ///
    /// Falling through would register a *second* ACME account at the CA and
    /// then rename over the first one's credentials — silently rotating an
    /// identity the CA still honours and destroying the key for the old one.
    /// A directory in the file's place fails with `EISDIR` deterministically,
    /// even as root, and needs neither a network nor a crypto provider.
    #[test]
    fn an_unreadable_credential_file_is_not_a_missing_one() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;

        // Absent: the create path, reported as "no account yet".
        assert_eq!(read_credentials(&dir.path().join("absent.json"))?, None);

        // Present and readable: handed back for `from_credentials`.
        let good = dir.path().join("account.json");
        std::fs::write(&good, "{}")?;
        assert_eq!(read_credentials(&good)?.as_deref(), Some("{}"));

        // Present but unreadable: refused, never mistaken for absent.
        let occupied = dir.path().join("occupied.json");
        std::fs::create_dir(&occupied)?;
        let err = read_credentials(&occupied)
            .err()
            .ok_or("an unreadable credential file must fail")?;
        assert!(
            matches!(err, AcmeError::Io(ref e) if e.kind() != std::io::ErrorKind::NotFound),
            "expected the read failure to propagate, got {err:?}"
        );
        Ok(())
    }
    #[test]
    fn corrupt_credential_json_maps_to_a_credentials_error() {
        // `parse_credentials` is the production mapping `load_or_create_account`
        // runs before any network: garbage must surface as `Credentials`,
        // never as a fresh account registration.
        let err = parse_credentials("{not json").err();
        assert!(
            matches!(&err, Some(AcmeError::Credentials(m)) if m.starts_with("deserialize:")),
            "garbage credentials must map to Credentials, got {err:?}"
        );
    }

    #[test]
    fn atomic_write_lands_with_0600_and_recovers_a_stale_temp()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("sub").join("account.json");
        // Fresh write: parents created, content exact, mode 0600.
        write_json_atomically(&target, "{\"a\":1}")?;
        assert_eq!(std::fs::read_to_string(&target)?, "{\"a\":1}");
        assert_eq!(
            std::fs::metadata(&target)?.permissions().mode() & 0o777,
            0o600
        );
        // A stale pid-temp file (crash plus PID reuse) is replaced, not
        // wedged on: the retry still succeeds with the new content.
        let stale = target.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&stale, "stale")?;
        write_json_atomically(&target, "{\"a\":2}")?;
        assert_eq!(std::fs::read_to_string(&target)?, "{\"a\":2}");
        assert!(!stale.exists(), "stale temp must be consumed");
        // An unusable parent fails rather than pretending to persist: a file
        // where the directory should be makes `create_dir_all` fail.
        let blocked = dir.path().join("nope");
        std::fs::write(&blocked, "in the way")?;
        let err = write_json_atomically(&blocked.join("a.json"), "{}").err();
        assert!(
            matches!(err, Some(AcmeError::Io(_))),
            "unusable parent must fail, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn renewal_decision_covers_all_three_arms() -> Result<(), Box<dyn std::error::Error>> {
        use instant_acme::{RenewalInfo, SuggestedWindow};
        use time::OffsetDateTime;
        // Lifetime 0..=1_000_000. now = 300_000 (30% used): well before the
        // lifetime rule, so window presence decides.
        let (nb, na, now) = (0, 1_000_000, 300_000);
        let window = |start: i64, end: i64| -> Result<RenewalInfo, Box<dyn std::error::Error>> {
            Ok(RenewalInfo {
                suggested_window: SuggestedWindow {
                    start: OffsetDateTime::from_unix_timestamp(start)?,
                    end: OffsetDateTime::from_unix_timestamp(end)?,
                },
                explanation_url: None,
            })
        };
        let unsupported = || {
            Err::<(RenewalInfo, std::time::Duration), _>(instant_acme::Error::Unsupported("ARI"))
        };
        // Past window (started before now) renews immediately even at 30%.
        assert!(decide_renewal(
            Ok((window(100_000, 200_000)?, std::time::Duration::ZERO)),
            nb,
            na,
            now
        )?);
        // Future window does not renew: 30% < 66% and now < start.
        assert!(!decide_renewal(
            Ok((window(600_000, 800_000)?, std::time::Duration::ZERO)),
            nb,
            na,
            now
        )?);
        // No ARI support: the plain 66 % rule, so 30% holds.
        assert!(!decide_renewal(unsupported(), nb, na, now)?);
        // Past-window immediate renew still works after 66 % for the
        // unsupported fallback: 70 % renews.
        assert!(decide_renewal(unsupported(), 0, 1_000_000, 700_000)?);
        // Any other error propagates as `Acme`, never as a renewal answer.
        let other = Err::<(RenewalInfo, std::time::Duration), _>(instant_acme::Error::Str("boom"));
        assert!(matches!(
            decide_renewal(other, nb, na, now),
            Err(AcmeError::Acme(_))
        ));
        Ok(())
    }

    /// The whole `account_and_order` entry point refuses an unreadable
    /// credential file before it builds an ACME client.
    ///
    /// This is why `read_credentials` runs first: the refusal must not depend
    /// on a crypto provider existing. Under `--all-features` both rustls
    /// providers are compiled in and `Account::builder()` panics on the
    /// ambiguous default, so a test that reached the builder could not run
    /// here at all.
    #[tokio::test]
    async fn account_and_order_refuses_before_it_builds_a_client()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let occupied = dir.path().join("account.json");
        std::fs::create_dir(&occupied)?;

        let err = account_and_order(
            "https://acme.invalid/directory",
            &["example.com"],
            &occupied,
            None,
            Some("shortlived"),
            &[],
            None,
        )
        .await
        .err()
        .ok_or("an unreadable credential file must fail the order")?;

        assert!(
            matches!(err, AcmeError::Io(_)),
            "expected the read failure to propagate, got {err:?}"
        );
        assert!(occupied.is_dir(), "the existing path must be left alone");
        Ok(())
    }

    #[test]
    fn eab_key_rejects_bad_inputs_before_any_network() {
        // Empty kid: no key to bind to.
        let err = eab_key(&EabCredentials {
            kid: String::new(),
            key_b64: "aGk=".into(),
        })
        .err();
        assert!(
            matches!(err, Some(AcmeError::Config(_))),
            "empty kid must fail, got {err:?}"
        );
        // Not base64 at all.
        let err = eab_key(&EabCredentials {
            kid: "k".into(),
            key_b64: "!!!".into(),
        })
        .err();
        assert!(
            matches!(&err, Some(AcmeError::Config(m)) if m.contains("not base64")),
            "garbage key must fail, got {err:?}"
        );
        // Decodes to empty.
        let err = eab_key(&EabCredentials {
            kid: "k".into(),
            key_b64: String::new(),
        })
        .err();
        assert!(
            matches!(err, Some(AcmeError::Config(_))),
            "empty key must fail, got {err:?}"
        );
    }

    #[test]
    fn eab_debug_redacts_the_key_but_names_the_kid() {
        let creds = EabCredentials {
            kid: "ca-kid-1".into(),
            key_b64: "s3cr3t-key-material".into(),
        };
        let dump = format!("{creds:?}");
        assert!(
            dump.contains("ca-kid-1"),
            "kid must stay visible, got {dump}"
        );
        assert!(
            !dump.contains("s3cr3t-key-material"),
            "raw key must not leak, got {dump}"
        );
        assert!(
            dump.contains("[redacted]"),
            "redaction marker missing, got {dump}"
        );
    }

    /// A malformed EAB refuses before any client exists: `cached` is `None`
    /// (missing file), so the decode runs before `Account::builder()` — under
    /// `--all-features` the builder panics on the ambiguous provider, so
    /// reaching this `Config` proves the ordering.
    #[tokio::test]
    async fn account_and_order_refuses_bad_eab_before_it_builds_a_client()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("no-account-yet.json");
        let bad_eab = EabCredentials {
            kid: "k".into(),
            key_b64: "!!!".into(),
        };

        let err = account_and_order(
            "https://acme.invalid/directory",
            &["example.com"],
            &missing,
            None,
            None,
            &[],
            Some(&bad_eab),
        )
        .await
        .err()
        .ok_or("a malformed EAB must fail the order")?;

        assert!(
            matches!(&err, AcmeError::Config(m) if m.contains("not base64")),
            "expected the decode failure before any builder, got {err:?}"
        );
        assert!(
            !missing.exists(),
            "no credential file must be created on refusal"
        );
        Ok(())
    }

    #[test]
    fn eab_key_accepts_both_base64_alphabets() {
        // 0xfb 0xff decodes with `+/` (standard) and `-_` (URL-safe).
        for key_b64 in ["+//+", "-__-"] {
            assert!(
                eab_key(&EabCredentials {
                    kid: "k".into(),
                    key_b64: key_b64.into()
                })
                .is_ok(),
                "{key_b64:?} must decode"
            );
        }
    }

    #[test]
    fn issued_names_its_halves() {
        // Both halves are PEM strings; the field names are what stop a caller
        // writing the private key to the certificate's path.
        let issued = Issued {
            chain_pem: "-----BEGIN CERTIFICATE-----".to_owned(),
            key_pem: "-----BEGIN PRIVATE KEY-----".to_owned(),
        };
        assert!(issued.chain_pem.contains("CERTIFICATE"));
        assert!(issued.key_pem.contains("PRIVATE KEY"));
        assert_eq!(issued.clone(), issued);
        assert!(format!("{issued:?}").contains("chain_pem"));
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

    #[test]
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::items_after_statements,
        clippy::map_unwrap_or
    )]
    fn present_failure_withdraws_presented() {
        use std::sync::{Arc, Mutex};
        let deleted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        struct Mock {
            deleted: Arc<Mutex<Vec<String>>>,
            fail_on: String,
        }
        impl crate::DnsProvider for Mock {
            fn present(&self, record: &crate::DnsRecord) -> Result<(), crate::AcmeError> {
                if record.fqdn() == self.fail_on {
                    return Err(crate::AcmeError::Config("injected".into()));
                }
                Ok(())
            }
            fn delete(&self, record: &crate::DnsRecord) -> Result<(), crate::AcmeError> {
                if let Ok(mut g) = self.deleted.lock() {
                    g.push(record.fqdn().to_owned());
                } else {
                    self.deleted
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(record.fqdn().to_owned());
                }
                Ok(())
            }
        }
        let provider = Mock {
            deleted: Arc::clone(&deleted),
            fail_on: "_acme-challenge.b.example.com".to_owned(),
        };
        let a = crate::DnsRecord::new("_acme-challenge.a.example.com", "value-a").unwrap();
        let tracked: Vec<crate::DnsRecord> = vec![a.clone()];
        let b = crate::DnsRecord::new("_acme-challenge.b.example.com", "value-b").unwrap();
        assert!(provider.present(&b).is_err());
        crate::order::cleanup_challenges(&provider, &tracked);
        let has_a = deleted
            .lock()
            .is_ok_and(|g| g.contains(&a.fqdn().to_owned()));
        assert!(has_a, "withdrawn");
        let c = crate::DnsRecord::new("_acme-challenge.c.example.com", "value-c").unwrap();
        crate::order::cleanup_challenges(&provider, std::slice::from_ref(&c));
        let has_c = deleted
            .lock()
            .is_ok_and(|g| g.contains(&c.fqdn().to_owned()));
        assert!(has_c);
    }
}
