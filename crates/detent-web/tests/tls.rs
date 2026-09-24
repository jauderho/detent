//! The TLS 1.3-only claim, proved over real handshakes (PLAN §2.7, Phase 4
//! task 1).
//!
//! Every test starts a real [`Server`] on `127.0.0.1:0` with a real bootstrap
//! certificate and connects to it with a real `tokio_rustls::TlsConnector`.
//! Nothing here is mocked, because the property under test — "TLS 1.2 cannot
//! be negotiated" — is a property of the handshake and of nothing else.
//!
//! The client in `a_tls12_only_client_is_refused` is *capable* of TLS 1.2:
//! `detent-web`'s dev-dependencies switch rustls' `tls12` feature on for test
//! builds precisely so the refusal is the server's doing and not an absence of
//! code. `cargo build` leaves that feature off, so the shipped binary cannot
//! speak TLS 1.2 at all.
//!
//! The crate denies `clippy::unwrap_used`/`expect_used`/`panic` in every
//! target, tests included, so each test returns [`TestResult`] and propagates
//! with `?`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use detent_web::auth::ClientIp;
use detent_web::config::Config;
use detent_web::healthz;
use detent_web::server::Server;
use detent_web::tls::{
    ALPN_H2_HTTP11, CertStore, CertifiedKeyPair, bootstrap_self_signed, crypto_provider,
    server_config_from_store,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The name the bootstrap certificate is asked for and connected to.
const HOST: &str = "localhost";

/// A running server: where it listens, what certificate it serves, and how to
/// stop it.
struct Running {
    /// Address to connect to.
    addr: SocketAddr,
    /// The certificate the client must trust.
    cert: CertifiedKeyPair,
    /// The resolver the server answers handshakes from; retained so a test
    /// can swap the certificate without restarting the server.
    store: Arc<CertStore>,
    /// Resolves to stop the accept loop.
    stop: oneshot::Sender<()>,
    /// Completes when `serve` has returned.
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stop the server and wait for it.
    async fn shutdown(self) -> TestResult {
        drop(self.stop);
        self.task.await?;
        Ok(())
    }
}

/// Start a server on an ephemeral loopback port, allowing `max_connections`.
async fn start(max_connections: u32) -> Result<Running, Box<dyn std::error::Error>> {
    let cert = bootstrap_self_signed(&[HOST.to_owned()])?;
    let store = Arc::new(CertStore::new(&cert)?);
    let tls = server_config_from_store(Arc::clone(&store), ALPN_H2_HTTP11)?;

    let mut config = Config::default();
    config.listen.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.listen.max_connections = max_connections;
    config.validate()?;

    let server = Server::bind(&config, tls, healthz()).await?;
    let addr = server.local_addr();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve(async move {
                // Either an explicit stop or a dropped sender ends the loop.
                let _ = stopped.await;
            })
            .await;
    });
    Ok(Running {
        addr,
        cert,
        store,
        stop,
        task,
    })
}

/// A client configuration that trusts exactly `cert` and speaks exactly
/// `versions`, offering `alpn`.
fn client_config(
    cert: &CertifiedKeyPair,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.cert_der().to_vec()))?;
    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(versions)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

/// Connect and complete the handshake, or fail.
async fn connect(
    running: &Running,
    config: ClientConfig,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(running.addr).await?;
    let name = ServerName::try_from(HOST)?.to_owned();
    Ok(connector.connect(name, stream).await?)
}

#[tokio::test]
async fn a_tls13_client_negotiates_tls13_and_h2() -> TestResult {
    let running = start(8).await?;
    let config = client_config(&running.cert, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    let stream = connect(&running, config).await?;

    let (_io, session) = stream.get_ref();
    assert_eq!(session.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(session.alpn_protocol(), Some(&b"h2"[..]));

    drop(stream);
    running.shutdown().await
}

#[tokio::test]
async fn a_tls12_only_client_is_refused() -> TestResult {
    let running = start(8).await?;
    let config = client_config(&running.cert, &[&rustls::version::TLS12], ALPN_H2_HTTP11)?;
    let refused = connect(&running, config).await;
    assert!(
        refused.is_err(),
        "a TLS 1.2-only client completed a handshake"
    );

    // The listener is still healthy afterwards: a rejected handshake must not
    // take the accept loop with it.
    let good = client_config(&running.cert, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    let stream = connect(&running, good).await?;
    let (_io, session) = stream.get_ref();
    assert_eq!(session.protocol_version(), Some(ProtocolVersion::TLSv1_3));

    drop(stream);
    running.shutdown().await
}

#[tokio::test]
async fn healthz_answers_over_http11_with_the_security_headers() -> TestResult {
    let running = start(8).await?;
    let config = client_config(&running.cert, &[&rustls::version::TLS13], &[b"http/1.1"])?;
    let mut stream = connect(&running, config).await?;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"http/1.1"[..]),
        "the server must be able to fall back to HTTP/1.1"
    );

    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let response = String::from_utf8_lossy(&raw);

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
    for header in [
        "content-security-policy:",
        "x-content-type-options: nosniff",
        "referrer-policy: no-referrer",
        "permissions-policy:",
        "cross-origin-opener-policy: same-origin",
        "cross-origin-resource-policy: same-origin",
        "cross-origin-embedder-policy: require-corp",
        "strict-transport-security: max-age=63072000; includeSubDomains",
        "x-request-id:",
    ] {
        // hyper emits header names lowercase, so the needles are literal.
        assert!(
            response.contains(header),
            "{header} missing from:\n{response}"
        );
    }
    // `/healthz` is not under `/api/`, so it must not be stamped `no-store`.
    assert!(
        !response.to_lowercase().contains("cache-control"),
        "{response}"
    );

    running.shutdown().await
}

#[tokio::test]
async fn a_connection_over_the_cap_is_dropped_without_a_handshake() -> TestResult {
    let running = start(1).await?;
    let config = client_config(&running.cert, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;

    // The first connection's handshake completing proves its permit is held.
    let held = connect(&running, config.clone()).await?;

    let refused =
        tokio::time::timeout(Duration::from_secs(5), connect(&running, config.clone())).await?;
    assert!(refused.is_err(), "a second connection got a handshake");

    // Freeing the permit lets the next one through.
    drop(held);
    let mut allowed = None;
    for _ in 0_u8..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if let Ok(stream) = connect(&running, config.clone()).await {
            allowed = Some(stream);
            break;
        }
    }
    assert!(
        allowed.is_some(),
        "the permit was never released back to the pool"
    );
    drop(allowed);

    running.shutdown().await
}

#[tokio::test]
async fn a_client_that_speaks_no_tls_at_all_is_dropped_quietly() -> TestResult {
    let running = start(8).await?;

    // Plain HTTP into a TLS port: the handshake fails and the loop survives.
    let mut plain = TcpStream::connect(running.addr).await?;
    plain.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut sink)).await?;
    drop(plain);

    let config = client_config(&running.cert, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    let stream = connect(&running, config).await?;
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );

    drop(stream);
    running.shutdown().await
}

#[tokio::test]
async fn an_untrusting_client_is_refused_by_its_own_verifier() -> TestResult {
    let running = start(8).await?;
    // A different self-signed certificate: the client trusts the wrong root.
    let stranger = bootstrap_self_signed(&[HOST.to_owned()])?;
    let config = client_config(&stranger, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    assert!(connect(&running, config).await.is_err());

    running.shutdown().await
}

#[tokio::test]
async fn a_swapped_certificate_serves_without_a_restart() -> TestResult {
    // Phase 6 Task 5, proved over real handshakes: `CertStore::replace`
    // changes what the live resolver answers, and both sides of the swap
    // complete TLS 1.3 with the certificate they were offered.
    let running = start(8).await?;
    let before = client_config(&running.cert, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    let stream = connect(&running, before).await?;
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    drop(stream);

    let renewed = bootstrap_self_signed(&[HOST.to_owned()])?;
    running.store.replace(&renewed)?;
    let after = client_config(&renewed, &[&rustls::version::TLS13], ALPN_H2_HTTP11)?;
    let stream = connect(&running, after).await?;
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    drop(stream);

    running.shutdown().await
}
#[tokio::test]
async fn the_peer_address_reaches_the_handlers() -> TestResult {
    let cert = bootstrap_self_signed(&[HOST.to_owned()])?;
    let store = Arc::new(CertStore::new(&cert)?);
    let tls = server_config_from_store(Arc::clone(&store), ALPN_H2_HTTP11)?;
    let mut config = Config::default();
    config.listen.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.listen.max_connections = 8;
    config.validate()?;
    let router = detent_web::server::harden(
        Router::new().route(
            "/ip",
            get(|ClientIp(ip): ClientIp| async move { ip.to_string() }),
        ),
        Duration::from_secs(30),
    );
    let server = Server::bind(&config, tls, router).await?;
    let addr = server.local_addr();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = stopped.await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client_cfg = client_config(&cert, &[&rustls::version::TLS13], &[b"http/1.1"])?;
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(HOST.to_owned())?;
    let mut stream = connector.connect(server_name, tcp).await?;
    stream
        .write_all(b"GET /ip HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let response = String::from_utf8_lossy(&raw);
    assert!(
        response.contains("127.0.0.1"),
        "expected peer 127.0.0.1 in response, got: {response}"
    );
    assert!(
        !response.contains(&Ipv4Addr::UNSPECIFIED.to_string()),
        "should not fall back to unspecified, got: {response}"
    );
    drop(stop);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    Ok(())
}
#[tokio::test]
async fn an_idle_connection_does_not_hold_a_permit() -> TestResult {
    let cert = bootstrap_self_signed(&[HOST.to_owned()])?;
    let store = Arc::new(CertStore::new(&cert)?);
    let tls = server_config_from_store(Arc::clone(&store), ALPN_H2_HTTP11)?;
    let mut config = Config::default();
    config.listen.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.listen.max_connections = 1;
    config.validate()?;
    let mut server = Server::bind(&config, tls, healthz()).await?;
    server.header_read_timeout = Duration::from_millis(200);
    server.max_connection_lifetime = Duration::from_millis(450);
    let addr = server.local_addr();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = stopped.await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client_cfg = client_config(&cert, &[&rustls::version::TLS13], &[b"http/1.1"])?;
    let connector = TlsConnector::from(Arc::new(client_cfg.clone()));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(HOST.to_owned())?;
    let idle = connector.connect(server_name.clone(), tcp).await?;
    // Longer than header timeout, so the idle connection is closed and its permit freed.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mut last_err: Option<String> = None;
    let mut got_ok = false;
    let mut last_response = String::new();
    for _ in 0..15 {
        match TcpStream::connect(addr).await {
            Ok(tcp2) => match TlsConnector::from(Arc::new(client_cfg.clone()))
                .connect(server_name.clone(), tcp2)
                .await
            {
                Ok(mut stream2) => {
                    if stream2
                        .write_all(
                            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .is_ok()
                        && stream2.flush().await.is_ok()
                    {
                        let mut raw = Vec::new();
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            stream2.read_to_end(&mut raw),
                        )
                        .await;
                        let response = String::from_utf8_lossy(&raw).into_owned();
                        last_response = response.clone();
                        if response.contains("200 OK") {
                            got_ok = true;
                            break;
                        }
                        last_err = Some(format!("non-200 response: {response}"));
                    } else {
                        last_err = Some("write failed".to_owned());
                    }
                }
                Err(e) => last_err = Some(format!("tls connect failed: {e}")),
            },
            Err(e) => last_err = Some(format!("tcp connect failed: {e}")),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !got_ok {
        return Err(format!(
            "second client never got 200 after idle timeout: {} last response: {last_response}",
            last_err.unwrap_or_else(|| "unknown".to_owned())
        )
        .into());
    }
    drop(idle);
    drop(stop);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    Ok(())
}
