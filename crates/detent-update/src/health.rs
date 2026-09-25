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
    use rustls::pki_types::CertificateDer;

    // The pinned cert must be a parseable certificate; otherwise there is no
    // way to check health and that must fail closed with the same wording the
    // previous `RootCertStore::add` path used.
    let cert = CertificateDer::from(pinned_cert_der.to_vec());
    if webpki::EndEntityCert::try_from(&cert).is_err() {
        return Err(UpdateError::Unhealthy {
            waited_secs: 0,
            reason: "the serving certificate is not usable as a trust anchor: BadEncoding"
                .to_owned(),
        });
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(PinnedVerifier {
        pinned: pinned_cert_der.to_vec(),
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| UpdateError::Unhealthy {
            waited_secs: 0,
            reason: format!("TLS 1.3 client config: {err}"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinnedVerifier {
    pinned: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
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
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 server config")
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
            // Drain the request to the end of its headers before answering.
            // A single read can stop mid-headers (loaded CI splits the
            // flight); answering and closing early RSTs the client, whose
            // next handshake write surfaces as EPIPE from its own read.
            let mut seen = Vec::new();
            let mut buf = [0_u8; 256];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 {
                    return;
                }
                seen.extend_from_slice(buf.get(..n).unwrap_or_default());
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
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
    fn a_ca_issued_leaf_without_localhost_is_healthy_when_pinned() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        // CA that signs the leaf.
        let mut ca_params = CertificateParams::new(Vec::default()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let _ = ca_cert.der().to_vec();
        let issuer = Issuer::new(ca_params, ca_key);
        // Leaf for a public name, deliberately without localhost.
        let mut leaf_params =
            CertificateParams::new(vec!["example.com".to_owned()]).expect("leaf params");
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");
        let leaf_der = leaf_cert.der().to_vec();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 server config")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls_pki_types::CertificateDer::from(leaf_der.clone())],
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
            let mut seen = Vec::new();
            let mut buf = [0_u8; 256];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 {
                    return;
                }
                seen.extend_from_slice(buf.get(..n).unwrap_or_default());
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        // Pinned to the CA-issued leaf's DER: the probe must accept it even
        // though the name is not localhost and the issuer is not a trust
        // anchor in the webpki sense. Pin equality is the only check.
        assert!(wait_healthy(addr, &leaf_der, Duration::ZERO).is_ok());
        let _ = handle.join();
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
