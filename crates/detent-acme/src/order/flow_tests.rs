//! Order-flow tests over a scripted ACME server.
//!
//! The seam is `instant_acme::HttpClient`, the same one production uses for
//! its TLS 1.3 client (`account_builder`). [`FakeAcme`] answers each request
//! from a script of RFC 8555 replies in Pebble's wire format, so the real
//! `instant-acme` code builds a real [`Order`] and [`present_challenges`],
//! [`wait_ready`] and [`finalize`] run unchanged. The client signs its
//! requests (JWS) but does not verify anything the server sends beyond
//! status, `Replay-Nonce`, `Location` and the JSON body, so a script needs
//! no keys of its own.

use super::*;
use hyper::{Method, Response};
use instant_acme::Problem;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

const DIRECTORY: &str = "https://acme.test/dir";
const NEW_NONCE: &str = "https://acme.test/nonce-plz";
const NEW_ACCOUNT: &str = "https://acme.test/sign-me-up";
const NEW_ORDER: &str = "https://acme.test/order-plz";
const ACCOUNT_ID: &str = "https://acme.test/my-account/1";
const ORDER_URL: &str = "https://acme.test/my-order/1";
const FINALIZE_URL: &str = "https://acme.test/finalize-order/1";
const CERT_URL: &str = "https://acme.test/certZ/1";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One scripted HTTP answer.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
}

impl Reply {
    fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            location: None,
        }
    }

    /// An RFC 7807 problem document, as Pebble sends it.
    fn problem(status: u16, kind: &str, detail: &str) -> Self {
        Self {
            status,
            body: format!(
                r#"{{"type":"urn:ietf:params:acme:error:{kind}","detail":"{detail}","status":{status}}}"#
            ),
            location: None,
        }
    }
}

#[derive(Default)]
struct Script {
    /// Replies per URL, in order; the last one repeats.
    replies: HashMap<String, VecDeque<Reply>>,
    /// Every request seen, as `"METHOD url"`.
    log: Vec<String>,
    /// The decoded JWS payload of every POST, as `(url, payload)`.
    payloads: Vec<(String, String)>,
    nonces: u64,
}

/// A scripted ACME server behind the `instant_acme::HttpClient` seam.
#[derive(Clone, Default)]
struct FakeAcme(Arc<Mutex<Script>>);

impl FakeAcme {
    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `replies` for `url`; the last one answers every later request.
    fn on(&self, url: &str, replies: impl IntoIterator<Item = Reply>) {
        self.script()
            .replies
            .entry(url.to_owned())
            .or_default()
            .extend(replies);
    }

    fn log(&self) -> Vec<String> {
        self.script().log.clone()
    }

    /// The decoded JWS payloads sent to `url` by POST, in order.
    fn payloads_to(&self, url: &str) -> Vec<String> {
        self.script()
            .payloads
            .iter()
            .filter(|(u, _)| u == url)
            .map(|(_, p)| p.clone())
            .collect()
    }

    fn posts_to(&self, url: &str) -> usize {
        let wanted = format!("POST {url}");
        self.script().log.iter().filter(|l| **l == wanted).count()
    }

    /// Restores an account the way production does (`from_credentials`,
    /// which fetches the directory) and opens a new order for `domains`.
    async fn account_and_order(
        &self,
        domains: &[&str],
        authz_urls: &[String],
    ) -> Result<(Account, Order), Box<dyn std::error::Error>> {
        let (account, order, _) = self
            .account_and_profiled_order(domains, authz_urls, &[], None)
            .await?;
        Ok((account, order))
    }

    /// As [`Self::account_and_order`], for a directory that advertises
    /// `advertised` profiles and an operator who configured `configured`.
    /// Returns the profile the order requested.
    async fn account_and_profiled_order(
        &self,
        domains: &[&str],
        authz_urls: &[String],
        advertised: &[&str],
        configured: Option<&str>,
    ) -> Result<(Account, Order, Option<String>), Box<dyn std::error::Error>> {
        use base64::Engine as _;
        let profiles: serde_json::Map<String, serde_json::Value> = advertised
            .iter()
            .map(|name| ((*name).to_owned(), serde_json::json!("a profile")))
            .collect();
        let key = rcgen::KeyPair::generate()?;
        let credentials: AccountCredentials = serde_json::from_value(serde_json::json!({
            "id": ACCOUNT_ID,
            "key_pkcs8": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key.serialize_der()),
            "directory": DIRECTORY,
        }))?;
        self.on(
            DIRECTORY,
            [Reply::ok(
                serde_json::json!({
                    "newNonce": NEW_NONCE,
                    "newAccount": NEW_ACCOUNT,
                    "newOrder": NEW_ORDER,
                    "revokeCert": "https://acme.test/revoke-cert",
                    "keyChange": "https://acme.test/rollover-account-key",
                    "meta": { "profiles": profiles },
                })
                .to_string(),
            )],
        );
        self.on(
            NEW_ORDER,
            [Reply {
                status: 201,
                body: order_json("pending", authz_urls, None),
                location: Some(ORDER_URL.to_owned()),
            }],
        );
        let account = Account::builder_with_http(Box::new(self.clone()))
            .from_credentials(credentials)
            .await?;
        let (order, chosen) = new_order_for(&account, domains, configured).await?;
        Ok((account, order, chosen))
    }
}

impl FakeAcme {
    /// Stores the decoded JWS payload of a POST body. A body that is not a
    /// JWS with a base64url payload is stored as an empty string.
    async fn record_payload(&self, url: &str, body: BodyWrapper<Bytes>) {
        use base64::Engine as _;
        use http_body_util::BodyExt as _;
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(never) => match never {},
        };
        let payload = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|jws| jws.get("payload")?.as_str().map(str::to_owned))
            .and_then(|b64| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(b64)
                    .ok()
            })
            .and_then(|raw| String::from_utf8(raw).ok())
            .unwrap_or_default();
        self.script().payloads.push((url.to_owned(), payload));
    }
}

impl HttpClient for FakeAcme {
    fn request(
        &self,
        request: hyper::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let url = request.uri().to_string();
        let method = request.method().clone();
        let body = request.into_body();
        let (reply, nonce) = {
            let mut script = self.script();
            script.log.push(format!("{method} {url}"));
            script.nonces = script.nonces.saturating_add(1);
            let nonce = format!("nonce-{}", script.nonces);
            let reply = if method == Method::HEAD && url == NEW_NONCE {
                Some(Reply::ok(""))
            } else {
                script.replies.get_mut(&url).and_then(|queue| {
                    if queue.len() > 1 {
                        queue.pop_front()
                    } else {
                        queue.front().cloned()
                    }
                })
            };
            (reply, nonce)
        };
        let this = self.clone();
        Box::pin(async move {
            if method == Method::POST {
                this.record_payload(&url, body).await;
            }
            let reply = reply.ok_or_else(|| {
                instant_acme::Error::Other(format!("fake ACME: nothing scripted for {url}").into())
            })?;
            let mut response = Response::builder()
                .status(reply.status)
                .header("Replay-Nonce", nonce);
            if let Some(location) = reply.location {
                response = response.header("Location", location);
            }
            let response = response
                .body(BodyWrapper::from(reply.body.into_bytes()))
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            Ok(BytesResponse::from(response))
        })
    }
}

fn order_json(status: &str, authz_urls: &[String], certificate: Option<&str>) -> String {
    serde_json::json!({
        "status": status,
        "expires": "2030-01-01T00:00:00Z",
        "identifiers": [],
        "authorizations": authz_urls,
        "finalize": FINALIZE_URL,
        "certificate": certificate,
    })
    .to_string()
}

/// An `invalid` order carrying the problem that failed it.
fn failed_order_json(authz_urls: &[String], kind: &str, detail: &str) -> String {
    serde_json::json!({
        "status": "invalid",
        "expires": "2030-01-01T00:00:00Z",
        "identifiers": [],
        "authorizations": authz_urls,
        "finalize": FINALIZE_URL,
        "error": {
            "type": format!("urn:ietf:params:acme:error:{kind}"),
            "detail": detail,
            "status": 403,
        },
    })
    .to_string()
}

fn authz_url(n: usize) -> String {
    format!("https://acme.test/authZ/{n}")
}

fn chall_url(n: usize, kind: &str) -> String {
    format!("https://acme.test/chalZ/{n}/{kind}")
}

fn token(n: usize) -> String {
    format!("token-{n}")
}

/// An authorization for `domain` offering `kinds`, as Pebble serves it.
fn authz_json(n: usize, domain: &str, status: &str, kinds: &[&str]) -> String {
    let challenges: Vec<serde_json::Value> = kinds
        .iter()
        .map(|kind| {
            serde_json::json!({
                "type": kind,
                "url": chall_url(n, kind),
                "token": token(n),
                "status": "pending",
            })
        })
        .collect();
    serde_json::json!({
        "status": status,
        "identifier": {"type": "dns", "value": domain},
        "challenges": challenges,
        "expires": "2030-01-01T00:00:00Z",
    })
    .to_string()
}

/// Like [`authz_json`], for a wildcard order: the server reports the base
/// domain with `"wildcard": true` (RFC 8555 §7.1.4).
fn wildcard_authz_json(
    n: usize,
    domain: &str,
    kinds: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut authz: serde_json::Value =
        serde_json::from_str(&authz_json(n, domain, "pending", kinds))?;
    authz
        .as_object_mut()
        .ok_or("the authorization fixture is a JSON object")?
        .insert("wildcard".to_owned(), serde_json::Value::Bool(true));
    Ok(authz.to_string())
}

/// The challenge object Pebble returns once a challenge is marked ready.
fn challenge_processing(n: usize, kind: &str) -> Reply {
    Reply::ok(
        serde_json::json!({
            "type": kind,
            "url": chall_url(n, kind),
            "token": token(n),
            "status": "processing",
        })
        .to_string(),
    )
}

/// A fast retry policy: the tests own no clocks, only bounded polling.
fn quick_policy() -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_millis(1))
        .backoff(1.0)
        .timeout(Duration::from_secs(5))
}

// ---------------------------------------------------------------------------
// wait_ready
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wait_ready_answers_ready() -> TestResult {
    let fake = FakeAcme::default();
    let (_account, mut order) = fake.account_and_order(&["a.example"], &[]).await?;
    fake.on(ORDER_URL, [Reply::ok(order_json("ready", &[], None))]);

    let status = wait_ready(&mut order, &quick_policy()).await?;

    assert_eq!(status, OrderStatus::Ready);
    assert_eq!(fake.posts_to(ORDER_URL), 1);
    Ok(())
}

#[tokio::test]
async fn wait_ready_polls_a_pending_order_until_ready() -> TestResult {
    let fake = FakeAcme::default();
    let (_account, mut order) = fake.account_and_order(&["a.example"], &[]).await?;
    fake.on(
        ORDER_URL,
        [
            Reply::ok(order_json("pending", &[], None)),
            Reply::ok(order_json("pending", &[], None)),
            Reply::ok(order_json("ready", &[], None)),
        ],
    );

    let status = wait_ready(&mut order, &quick_policy()).await?;

    assert_eq!(status, OrderStatus::Ready);
    assert_eq!(fake.posts_to(ORDER_URL), 3, "two pending polls, then ready");
    Ok(())
}

#[tokio::test]
async fn wait_ready_answers_invalid_and_surfaces_an_order_error() -> TestResult {
    let fake = FakeAcme::default();
    let (_account, mut order) = fake.account_and_order(&["a.example"], &[]).await?;
    fake.on(ORDER_URL, [Reply::ok(order_json("invalid", &[], None))]);
    assert_eq!(
        wait_ready(&mut order, &quick_policy()).await?,
        OrderStatus::Invalid
    );

    // An order that carries a problem is an error, not a status.
    let fake = FakeAcme::default();
    let (_account, mut order) = fake.account_and_order(&["a.example"], &[]).await?;
    fake.on(
        ORDER_URL,
        [Reply::ok(failed_order_json(
            &[],
            "unauthorized",
            "no TXT record",
        ))],
    );
    let err = wait_ready(&mut order, &quick_policy())
        .await
        .err()
        .ok_or("an order error must fail wait_ready")?;
    assert!(
        matches!(&err, AcmeError::Acme(instant_acme::Error::Api(p)) if p.detail.as_deref() == Some("no TXT record")),
        "expected the order's problem, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn wait_ready_gives_up_at_the_retry_limit() -> TestResult {
    let fake = FakeAcme::default();
    let (_account, mut order) = fake.account_and_order(&["a.example"], &[]).await?;
    fake.on(ORDER_URL, [Reply::ok(order_json("pending", &[], None))]);
    let policy = RetryPolicy::new()
        .initial_delay(Duration::from_millis(1))
        .backoff(2.0)
        .timeout(Duration::from_millis(50));

    let err = wait_ready(&mut order, &policy)
        .await
        .err()
        .ok_or("an order that stays pending must time out")?;

    assert!(
        matches!(err, AcmeError::Acme(instant_acme::Error::Timeout(_))),
        "expected a timeout, got {err:?}"
    );
    assert!(fake.posts_to(ORDER_URL) >= 1, "it polled before giving up");
    Ok(())
}

// ---------------------------------------------------------------------------
// finalize
// ---------------------------------------------------------------------------

const CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\naW50ZXJtZWRpYXRl\n-----END CERTIFICATE-----\n";

/// A ready order for `a.example` whose authorization is already valid.
async fn ready_order(fake: &FakeAcme) -> Result<Order, Box<dyn std::error::Error>> {
    let authz = [authz_url(1)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(1, "a.example", "valid", &["dns-01"]))],
    );
    let (_account, order) = fake.account_and_order(&["a.example"], &authz).await?;
    Ok(order)
}

#[tokio::test]
async fn finalize_returns_the_chain_and_a_fresh_key() -> TestResult {
    let fake = FakeAcme::default();
    let mut order = ready_order(&fake).await?;
    let authz = [authz_url(1)];
    fake.on(
        FINALIZE_URL,
        [Reply::ok(order_json("processing", &authz, None))],
    );
    fake.on(
        ORDER_URL,
        [
            Reply::ok(order_json("processing", &authz, None)),
            Reply::ok(order_json("valid", &authz, Some(CERT_URL))),
        ],
    );
    fake.on(CERT_URL, [Reply::ok(CHAIN_PEM)]);

    let issued = finalize(&mut order, &quick_policy()).await?;

    assert_eq!(issued.chain_pem, CHAIN_PEM);
    assert!(
        issued.key_pem.contains("BEGIN PRIVATE KEY"),
        "the CSR key comes back as PKCS#8 PEM"
    );
    assert_eq!(fake.posts_to(FINALIZE_URL), 1);
    assert_eq!(fake.posts_to(CERT_URL), 1);
    Ok(())
}

#[tokio::test]
async fn finalize_surfaces_an_error_answer() -> TestResult {
    let fake = FakeAcme::default();
    let mut order = ready_order(&fake).await?;
    fake.on(
        FINALIZE_URL,
        [Reply::problem(403, "badCSR", "CSR names do not match")],
    );

    let err = finalize(&mut order, &quick_policy())
        .await
        .err()
        .ok_or("a refused finalize must fail")?;

    assert!(
        matches!(&err, AcmeError::Acme(instant_acme::Error::Api(Problem { detail: Some(d), .. })) if d == "CSR names do not match"),
        "expected the CA's problem, got {err:?}"
    );
    assert_eq!(fake.posts_to(CERT_URL), 0, "no download after a refusal");
    Ok(())
}

#[tokio::test]
async fn finalize_surfaces_an_order_that_fails_while_processing() -> TestResult {
    let fake = FakeAcme::default();
    let mut order = ready_order(&fake).await?;
    let authz = [authz_url(1)];
    fake.on(
        FINALIZE_URL,
        [Reply::ok(order_json("processing", &authz, None))],
    );
    fake.on(
        ORDER_URL,
        [Reply::ok(failed_order_json(
            &authz,
            "serverInternal",
            "issuance failed",
        ))],
    );

    let err = finalize(&mut order, &quick_policy())
        .await
        .err()
        .ok_or("an order that fails in processing must fail finalize")?;

    assert!(
        matches!(&err, AcmeError::Acme(instant_acme::Error::Api(p)) if p.detail.as_deref() == Some("issuance failed")),
        "expected the order's problem, got {err:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// finish_order (the wait_ready -> finalize tail of `issue`)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finish_order_refuses_an_order_that_is_not_ready() -> TestResult {
    let fake = FakeAcme::default();
    let mut order = ready_order(&fake).await?;
    fake.on(
        ORDER_URL,
        [Reply::ok(order_json("invalid", &[authz_url(1)], None))],
    );

    let err = finish_order(&mut order, &quick_policy())
        .await
        .err()
        .ok_or("an invalid order must not be finalized")?;

    assert!(
        matches!(err, AcmeError::InvalidOrder(OrderStatus::Invalid)),
        "expected InvalidOrder, got {err:?}"
    );
    assert_eq!(fake.posts_to(FINALIZE_URL), 0);
    Ok(())
}

#[tokio::test]
async fn finish_order_finalizes_a_ready_order() -> TestResult {
    let fake = FakeAcme::default();
    let mut order = ready_order(&fake).await?;
    let authz = [authz_url(1)];
    fake.on(FINALIZE_URL, [Reply::ok(order_json("valid", &authz, None))]);
    fake.on(
        ORDER_URL,
        [
            Reply::ok(order_json("ready", &authz, None)),
            Reply::ok(order_json("valid", &authz, Some(CERT_URL))),
        ],
    );
    fake.on(CERT_URL, [Reply::ok(CHAIN_PEM)]);

    let issued = finish_order(&mut order, &quick_policy()).await?;

    assert_eq!(issued.chain_pem, CHAIN_PEM);
    Ok(())
}

// ---------------------------------------------------------------------------
// present_attest_challenges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn present_attest_challenges_sends_each_attestation() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1), authz_url(2)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(
            1,
            "device-1",
            "pending",
            &["device-attest-01"],
        ))],
    );
    fake.on(
        &authz_url(2),
        [Reply::ok(authz_json(
            2,
            "device-2",
            "valid",
            &["device-attest-01"],
        ))],
    );
    fake.on(
        &chall_url(1, "device-attest-01"),
        [challenge_processing(1, "device-attest-01")],
    );
    let (_account, mut order) = fake.account_and_order(&["device-1"], &authz).await?;

    present_attest_challenges(&mut order, &crate::attest::TestAttestor).await?;

    assert_eq!(fake.posts_to(&chall_url(1, "device-attest-01")), 1);
    assert_eq!(
        fake.posts_to(&chall_url(2, "device-attest-01")),
        0,
        "a valid authorization is skipped"
    );
    Ok(())
}

#[tokio::test]
async fn present_attest_challenges_refuses_without_a_device_attest_challenge() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(1, "device-1", "pending", &["dns-01"]))],
    );
    let (_account, mut order) = fake.account_and_order(&["device-1"], &authz).await?;

    let err = present_attest_challenges(&mut order, &crate::attest::TestAttestor)
        .await
        .err()
        .ok_or("an authorization without device-attest-01 must fail")?;

    assert!(
        matches!(err, AcmeError::NoDeviceAttestChallenge),
        "got {err:?}"
    );
    assert!(
        !fake
            .log()
            .iter()
            .any(|l| l.starts_with("POST https://acme.test/chalZ/")),
        "no challenge was answered"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// present_challenges (M18)
// ---------------------------------------------------------------------------

/// Where a [`RecordingProvider`] (or the `publish` callback) refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refuse {
    Nothing,
    Present,
    Propagation,
}

/// A provider that records what it was asked to do, and refuses `refuse`
/// for `refuse_fqdn` only.
struct RecordingProvider {
    presented: Mutex<Vec<DnsRecord>>,
    deleted: Mutex<Vec<DnsRecord>>,
    refuse: Refuse,
    refuse_fqdn: &'static str,
}

impl RecordingProvider {
    fn new(refuse: Refuse, refuse_fqdn: &'static str) -> Self {
        Self {
            presented: Mutex::new(Vec::new()),
            deleted: Mutex::new(Vec::new()),
            refuse,
            refuse_fqdn,
        }
    }

    fn presented(&self) -> Vec<DnsRecord> {
        self.presented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The deleted record names, sorted: cleanup order is not the contract.
    fn deleted_fqdns(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .deleted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|r| r.fqdn().to_owned())
            .collect();
        names.sort();
        names
    }
}

impl DnsProvider for RecordingProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        if self.refuse == Refuse::Present && record.fqdn() == self.refuse_fqdn {
            return Err(AcmeError::Config("present refused".to_owned()));
        }
        self.presented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.clone());
        Ok(())
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.deleted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.clone());
        Ok(())
    }

    fn wait_propagated(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        if self.refuse == Refuse::Propagation && record.fqdn() == self.refuse_fqdn {
            return Err(AcmeError::NotPropagated("not yet".to_owned()));
        }
        Ok(())
    }
}

/// The dns-01 record for authorization `n`, computed independently of
/// `present_challenges` (RFC 8555 §8.4): the TXT value is
/// base64url(SHA-256(token "." thumbprint)) under `_acme-challenge.<domain>`.
fn expected_record(account: &Account, n: usize, domain: &str) -> Result<DnsRecord, AcmeError> {
    use base64::Engine as _;
    let key_authorization = format!("{}.{}", token(n), account.key_thumbprint());
    let digest =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key_authorization.as_bytes());
    DnsRecord::new(
        format!("_acme-challenge.{domain}"),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()),
    )
}

#[tokio::test]
async fn present_challenges_publishes_each_dns01_record() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1), authz_url(2), authz_url(3)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(
            1,
            "a.example",
            "pending",
            &["http-01", "dns-01", "tls-alpn-01"],
        ))],
    );
    fake.on(
        &authz_url(2),
        [Reply::ok(authz_json(
            2,
            "b.example",
            "pending",
            &["dns-01"],
        ))],
    );
    fake.on(
        &authz_url(3),
        [Reply::ok(authz_json(3, "c.example", "valid", &["dns-01"]))],
    );
    fake.on(&chall_url(1, "dns-01"), [challenge_processing(1, "dns-01")]);
    fake.on(&chall_url(2, "dns-01"), [challenge_processing(2, "dns-01")]);
    let (account, mut order) = fake
        .account_and_order(&["a.example", "b.example", "c.example"], &authz)
        .await?;
    let provider = RecordingProvider::new(Refuse::Nothing, "");
    let published: Mutex<Vec<DnsRecord>> = Mutex::new(Vec::new());
    let publish = |record: &DnsRecord| -> Result<(), AcmeError> {
        published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.clone());
        Ok(())
    };

    let records = present_challenges(&mut order, &provider, &publish).await?;

    let expected = vec![
        expected_record(&account, 1, "a.example")?,
        expected_record(&account, 2, "b.example")?,
    ];
    assert_eq!(records, expected, "one record per pending identifier");
    assert_eq!(
        *published.lock().unwrap_or_else(PoisonError::into_inner),
        expected,
        "publish saw each record, with the right name and value"
    );
    assert_eq!(provider.presented(), expected);
    assert!(provider.deleted_fqdns().is_empty(), "nothing withdrawn");
    assert_eq!(fake.posts_to(&chall_url(1, "dns-01")), 1);
    assert_eq!(fake.posts_to(&chall_url(2, "dns-01")), 1);
    assert_eq!(
        fake.posts_to(&chall_url(3, "dns-01")),
        0,
        "a valid authorization is skipped"
    );
    assert_eq!(fake.posts_to(&chall_url(1, "http-01")), 0);
    assert_eq!(fake.posts_to(&chall_url(1, "tls-alpn-01")), 0);
    Ok(())
}

#[tokio::test]
async fn present_challenges_refuses_an_authorization_without_dns01() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1), authz_url(2)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(
            1,
            "a.example",
            "pending",
            &["dns-01"],
        ))],
    );
    fake.on(
        &authz_url(2),
        [Reply::ok(authz_json(
            2,
            "b.example",
            "pending",
            &["http-01", "tls-alpn-01"],
        ))],
    );
    fake.on(&chall_url(1, "dns-01"), [challenge_processing(1, "dns-01")]);
    let (_account, mut order) = fake
        .account_and_order(&["a.example", "b.example"], &authz)
        .await?;
    let provider = RecordingProvider::new(Refuse::Nothing, "");

    let err = present_challenges(&mut order, &provider, &|_| Ok(()))
        .await
        .err()
        .ok_or("an authorization without dns-01 must fail")?;

    assert!(matches!(err, AcmeError::NoDns01Challenge), "got {err:?}");
    assert_eq!(
        provider.deleted_fqdns(),
        ["_acme-challenge.a.example"],
        "the record already presented is withdrawn"
    );
    assert_eq!(fake.posts_to(&chall_url(2, "http-01")), 0);
    assert_eq!(fake.posts_to(&chall_url(2, "tls-alpn-01")), 0);
    Ok(())
}

/// Where the second of three authorizations fails.
#[derive(Clone, Copy, Debug)]
enum Stage {
    FetchAuthorization,
    Present,
    Publish,
    Propagation,
    SetReady,
}

#[tokio::test]
async fn present_challenges_stops_at_the_first_error_and_withdraws_its_records() -> TestResult {
    const B: &str = "_acme-challenge.b.example";
    for stage in [
        Stage::FetchAuthorization,
        Stage::Present,
        Stage::Publish,
        Stage::Propagation,
        Stage::SetReady,
    ] {
        let fake = FakeAcme::default();
        let authz = [authz_url(1), authz_url(2), authz_url(3)];
        fake.on(
            &authz_url(1),
            [Reply::ok(authz_json(
                1,
                "a.example",
                "pending",
                &["dns-01"],
            ))],
        );
        fake.on(
            &authz_url(2),
            [match stage {
                Stage::FetchAuthorization => Reply::problem(500, "serverInternal", "authz lost"),
                _ => Reply::ok(authz_json(2, "b.example", "pending", &["dns-01"])),
            }],
        );
        fake.on(
            &authz_url(3),
            [Reply::ok(authz_json(
                3,
                "c.example",
                "pending",
                &["dns-01"],
            ))],
        );
        fake.on(&chall_url(1, "dns-01"), [challenge_processing(1, "dns-01")]);
        fake.on(
            &chall_url(2, "dns-01"),
            [match stage {
                Stage::SetReady => Reply::problem(403, "unauthorized", "challenge refused"),
                _ => challenge_processing(2, "dns-01"),
            }],
        );
        let (_account, mut order) = fake
            .account_and_order(&["a.example", "b.example", "c.example"], &authz)
            .await?;
        let provider = RecordingProvider::new(
            match stage {
                Stage::Present => Refuse::Present,
                Stage::Propagation => Refuse::Propagation,
                _ => Refuse::Nothing,
            },
            B,
        );
        let publish = |record: &DnsRecord| -> Result<(), AcmeError> {
            if matches!(stage, Stage::Publish) && record.fqdn() == B {
                return Err(AcmeError::Config("publish refused".to_owned()));
            }
            Ok(())
        };

        let err = present_challenges(&mut order, &provider, &publish)
            .await
            .err()
            .ok_or_else(|| format!("{stage:?}: the flow must fail"))?;

        // The error is the one the failing step returned, unchanged.
        let expected = match stage {
            Stage::FetchAuthorization => {
                "API error: authz lost (urn:ietf:params:acme:error:serverInternal)"
            }
            Stage::Present => "dns provider error: present refused",
            Stage::Publish => "dns provider error: publish refused",
            Stage::Propagation => "dns-01 record not yet propagated: not yet",
            Stage::SetReady => {
                "API error: challenge refused (urn:ietf:params:acme:error:unauthorized)"
            }
        };
        assert_eq!(err.to_string(), expected, "{stage:?}");
        // Every record that was presented is withdrawn again.
        let mut withdrawn: Vec<String> = provider
            .presented()
            .iter()
            .map(|r| r.fqdn().to_owned())
            .collect();
        withdrawn.sort();
        assert_eq!(provider.deleted_fqdns(), withdrawn, "{stage:?}");
        assert!(
            withdrawn.iter().any(|f| f == "_acme-challenge.a.example"),
            "{stage:?}: the first record was presented, then withdrawn"
        );
        // The flow stopped: b's challenge was answered only where answering
        // it was the failing step, and the third authorization was never
        // fetched.
        let answered_b = usize::from(matches!(stage, Stage::SetReady));
        assert_eq!(
            fake.posts_to(&chall_url(2, "dns-01")),
            answered_b,
            "{stage:?}"
        );
        assert_eq!(fake.posts_to(&authz_url(3)), 0, "{stage:?}");
    }
    Ok(())
}

#[tokio::test]
async fn present_challenges_puts_a_wildcard_record_at_the_base_domain() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1)];
    fake.on(
        &authz_url(1),
        [Reply::ok(wildcard_authz_json(
            1,
            "example.com",
            &["dns-01"],
        )?)],
    );
    fake.on(&chall_url(1, "dns-01"), [challenge_processing(1, "dns-01")]);
    let (account, mut order) = fake.account_and_order(&["*.example.com"], &authz).await?;
    let provider = RecordingProvider::new(Refuse::Nothing, "");

    let records = present_challenges(&mut order, &provider, &|_| Ok(())).await?;

    // RFC 8555 §8.4: no `*.` in the TXT name.
    let expected = vec![expected_record(&account, 1, "example.com")?];
    assert_eq!(records, expected);
    assert_eq!(provider.presented(), expected);
    assert_eq!(fake.posts_to(&chall_url(1, "dns-01")), 1);
    Ok(())
}

#[tokio::test]
async fn present_challenges_publishes_apex_and_wildcard_at_one_name() -> TestResult {
    let fake = FakeAcme::default();
    let authz = [authz_url(1), authz_url(2)];
    fake.on(
        &authz_url(1),
        [Reply::ok(authz_json(
            1,
            "example.com",
            "pending",
            &["dns-01"],
        ))],
    );
    fake.on(
        &authz_url(2),
        [Reply::ok(wildcard_authz_json(
            2,
            "example.com",
            &["dns-01"],
        )?)],
    );
    fake.on(&chall_url(1, "dns-01"), [challenge_processing(1, "dns-01")]);
    fake.on(&chall_url(2, "dns-01"), [challenge_processing(2, "dns-01")]);
    let (account, mut order) = fake
        .account_and_order(&["example.com", "*.example.com"], &authz)
        .await?;
    let provider = RecordingProvider::new(Refuse::Nothing, "");

    let records = present_challenges(&mut order, &provider, &|_| Ok(())).await?;

    let apex = expected_record(&account, 1, "example.com")?;
    let wildcard = expected_record(&account, 2, "example.com")?;
    assert_ne!(apex.value(), wildcard.value(), "two different values");
    assert_eq!(records, vec![apex, wildcard]);
    assert_eq!(provider.presented(), records);
    cleanup_challenges(&provider, &records);
    assert_eq!(
        provider.deleted_fqdns(),
        vec!["_acme-challenge.example.com"; 2],
        "cleanup withdraws both records"
    );
    assert_eq!(
        *provider
            .deleted
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        records
    );
    Ok(())
}

/// The new-order body a fake directory that advertises `advertised` got from
/// an operator who configured `configured`, and the profile the order named.
async fn new_order_body(
    advertised: &[&str],
    configured: Option<&str>,
) -> Result<(serde_json::Value, Option<String>), Box<dyn std::error::Error>> {
    let fake = FakeAcme::default();
    let (_, _, chosen) = fake
        .account_and_profiled_order(&["example.com"], &[authz_url(1)], advertised, configured)
        .await?;
    let payloads = fake.payloads_to(NEW_ORDER);
    let [payload] = payloads.as_slice() else {
        return Err(format!("expected one new-order POST, got {}", payloads.len()).into());
    };
    Ok((serde_json::from_str(payload)?, chosen))
}

#[tokio::test]
async fn an_advertised_shortlived_profile_rides_the_new_order() -> TestResult {
    let (body, chosen) = new_order_body(&["classic", "shortlived"], None).await?;
    assert_eq!(body.get("profile"), Some(&serde_json::json!("shortlived")));
    assert_eq!(chosen.as_deref(), Some("shortlived"));
    Ok(())
}

#[tokio::test]
async fn a_directory_without_shortlived_gets_no_profile_field() -> TestResult {
    for advertised in [&[][..], &["default"]] {
        let (body, chosen) = new_order_body(advertised, None).await?;
        assert!(body.get("profile").is_none(), "{body}");
        assert_eq!(chosen, None);
    }
    Ok(())
}

#[tokio::test]
async fn a_configured_profile_wins_over_the_advertised_default() -> TestResult {
    let (body, _) = new_order_body(&["classic", "shortlived"], Some("classic")).await?;
    assert_eq!(body.get("profile"), Some(&serde_json::json!("classic")));
    Ok(())
}
