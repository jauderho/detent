//! The post-swap health check (PLAN §2.9 step 5): did the restarted service
//! actually come back?
//!
//! A swap that installs a binary which cannot serve is worse than no swap at
//! all, so the updater asks the listener itself rather than trusting the init
//! system's exit code. `/healthz` is unauthenticated and its body is a
//! constant, so this needs no credential and leaks nothing.
//!
//! TLS is pinned to the certificate the listener serves, read off disk: the
//! only peer this ever talks to is our own loopback listener, and pinning is
//! both stricter and simpler than carrying a CA set. Verification is never
//! disabled — a health check that accepts any certificate would also accept
//! whatever replaced the service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::update::UpdateError;

/// How long to keep asking before calling the restart a failure.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// How long to wait between attempts.
const INTERVAL: Duration = Duration::from_millis(500);

/// The name the listener is asked for. Every certificate detent serves
/// carries it (`detent-web`'s `ALWAYS_SANS`), including the bootstrap one.
const SERVER_NAME: &str = "localhost";

/// Polls `https://localhost:<port>/healthz` until it answers 200, or
/// `deadline` passes.
///
/// `pinned_cert_der` is the DER of the certificate the listener serves; it is
/// the sole trust anchor for this connection.
///
/// # Errors
///
/// [`UpdateError::Unhealthy`] when the deadline passes without a 200, and
/// when the pinned certificate cannot be used as a trust anchor.
pub fn wait_healthy(
    addr: SocketAddr,
    pinned_cert_der: &[u8],
    deadline: Duration,
) -> Result<(), UpdateError> {
    ensure_provider();
    let tls = client_config(pinned_cert_der)?;
    let started = Instant::now();
    // `>=` on the elapsed time, so a zero deadline still makes exactly one
    // attempt: "check it now" must mean check, not skip. `last` needs no
    // initial value: the match below either returns or assigns it.
    let mut last;
    loop {
        match probe(addr, &tls) {
            Ok(()) => return Ok(()),
            Err(reason) => last = reason,
        }
        if started.elapsed() >= deadline {
            return Err(UpdateError::Unhealthy {
                waited_secs: deadline.as_secs(),
                reason: last,
            });
        }
        std::thread::sleep(INTERVAL);
    }
}

/// A TLS configuration trusting exactly one certificate.
fn client_config(pinned_cert_der: &[u8]) -> Result<Arc<rustls::ClientConfig>, UpdateError> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            pinned_cert_der.to_vec(),
        ))
        .map_err(|err| UpdateError::Unhealthy {
            waited_secs: 0,
            reason: format!("the serving certificate is not usable as a trust anchor: {err}"),
        })?;
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Install the process-wide rustls `CryptoProvider` once (first call wins).
///
/// `rustls::ClientConfig` needs a process default when both `aws-lc-rs` and
/// `ring` are compiled in (`--all-features`); without one every health probe
/// panics. `fetch.rs` builds its client with an explicit provider, so only
/// this pinned-loopback path needs the default.
fn ensure_provider() {
    use std::sync::Once;
    static PROVIDER: Once = Once::new();
    PROVIDER.call_once(|| {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let _ = provider.install_default();
    });
}

/// One `GET /healthz`. `Ok(())` only on a 2xx.
fn probe(addr: SocketAddr, tls: &Arc<rustls::ClientConfig>) -> Result<(), String> {
    use std::io::{Read as _, Write as _};

    let name = rustls_pki_types::ServerName::try_from(SERVER_NAME)
        .map_err(|err| format!("server name: {err}"))?
        .to_owned();
    let mut session = rustls::ClientConnection::new(Arc::clone(tls), name)
        .map_err(|err| format!("tls session: {err}"))?;
    let mut socket = std::net::TcpStream::connect_timeout(&addr, INTERVAL)
        .map_err(|err| format!("connect: {err}"))?;
    socket
        .set_read_timeout(Some(INTERVAL))
        .map_err(|err| format!("timeout: {err}"))?;
    let mut stream = rustls::Stream::new(&mut session, &mut socket);

    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|err| format!("request: {err}"))?;

    // The status line is all that matters, and it arrives first; the body is
    // a constant nobody reads. Cap the read so a wedged peer cannot hold the
    // updater open past its own deadline.
    let mut buf = [0_u8; 64];
    let read = stream
        .read(&mut buf)
        .map_err(|err| format!("response: {err}"))?;
    let head = String::from_utf8_lossy(buf.get(..read).unwrap_or_default()).to_string();
    if head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.0 2") {
        Ok(())
    } else {
        Err(format!("answered {:?}", head.lines().next().unwrap_or("")))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// A self-signed `localhost` certificate, and a server that speaks TLS
    /// 1.3 on a loopback port and answers `status` once.
    fn server(status: &'static str) -> (SocketAddr, Vec<u8>, std::thread::JoinHandle<()>) {
        let cert = rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()])
            .expect("self-signed fixture");
        let cert_der = cert.cert.der().to_vec();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls_pki_types::CertificateDer::from(cert_der.clone())],
                    key,
                )
                .expect("server config");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let Ok(mut session) = rustls::ServerConnection::new(Arc::new(config)) else {
                return;
            };
            let mut stream = rustls::Stream::new(&mut session, &mut socket);
            let mut buf = [0_u8; 256];
            let _ = stream.read(&mut buf);
            let _ = write!(stream, "{status}\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        (addr, cert_der, handle)
    }

    #[test]
    fn a_serving_listener_is_healthy() {
        let (addr, cert, handle) = server("HTTP/1.1 200 OK");
        assert!(wait_healthy(addr, &cert, DEADLINE).is_ok());
        let _ = handle.join();
    }

    #[test]
    fn a_listener_answering_anything_else_is_not_healthy() {
        let (addr, cert, handle) = server("HTTP/1.1 503 Service Unavailable");
        // Zero deadline: one attempt, and the single-shot server has one
        // answer to give. A 503 is a running process that cannot serve —
        // exactly the case the rollback exists for.
        let err = wait_healthy(addr, &cert, Duration::ZERO).expect_err("503 is not healthy");
        assert!(matches!(err, UpdateError::Unhealthy { .. }), "{err:?}");
        assert!(err.to_string().contains("503"), "{err}");
        let _ = handle.join();
    }

    #[test]
    fn a_closed_port_is_not_healthy() {
        // Bound then dropped, so the port is closed and nothing can answer.
        let addr = TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr");
        let cert = rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()])
            .expect("fixture")
            .cert
            .der()
            .to_vec();
        let err = wait_healthy(addr, &cert, Duration::ZERO).expect_err("closed port");
        assert!(matches!(err, UpdateError::Unhealthy { .. }), "{err:?}");
    }

    #[test]
    fn an_unpinnable_certificate_refuses_closed() {
        // Not a certificate at all: without a trust anchor there is no way to
        // check health, and that must fail rather than skip the check.
        let err = wait_healthy(
            "127.0.0.1:1".parse().expect("addr"),
            b"not a certificate",
            Duration::ZERO,
        )
        .expect_err("garbage is not a trust anchor");
        assert!(err.to_string().contains("trust anchor"), "{err}");
    }

    #[test]
    fn the_wrong_certificate_is_not_trusted() {
        // A listener serving a certificate other than the pinned one must not
        // pass: the check is what proves *our* service came back.
        let (addr, _, handle) = server("HTTP/1.1 200 OK");
        let other = rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()])
            .expect("fixture")
            .cert
            .der()
            .to_vec();
        let err = wait_healthy(addr, &other, Duration::ZERO).expect_err("wrong cert");
        assert!(matches!(err, UpdateError::Unhealthy { .. }), "{err:?}");
        let _ = handle.join();
    }
}
