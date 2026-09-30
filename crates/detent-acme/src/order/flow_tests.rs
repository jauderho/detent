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
        use base64::Engine as _;
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
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns((*d).to_owned()))
            .collect();
        let order = account.new_order(&NewOrder::new(&identifiers)).await?;
        Ok((account, order))
    }
}

impl HttpClient for FakeAcme {
    fn request(
        &self,
        request: hyper::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let url = request.uri().to_string();
        let (reply, nonce) = {
            let mut script = self.script();
            script.log.push(format!("{} {url}", request.method()));
            script.nonces = script.nonces.saturating_add(1);
            let nonce = format!("nonce-{}", script.nonces);
            let reply = if request.method() == Method::HEAD && url == NEW_NONCE {
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
        Box::pin(async move {
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
