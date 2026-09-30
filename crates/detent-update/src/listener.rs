//! One HTTPS request to this host's own detent listener (`detent cert
//! renew`).
//!
//! The client posture of [`crate::health`]: TLS 1.3 only, a blocking std
//! socket, and certificate verification that no caller can turn off. The
//! caller names the one trust anchor:
//!
//! * [`Anchor::Served`] — the certificate the listener serves, read off
//!   disk. The peer must present exactly it, and it must be valid for the
//!   server name (checked before any byte is sent).
//! * [`Anchor::CaPem`] — CA certificates in PEM: ordinary webpki path and
//!   name validation.
//!
//! The caller builds the request bytes, so a credential in them stays in
//! the caller's zeroed buffer. No error here quotes the request.

use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate};

/// The largest answer (head and body) [`exchange`] reads, in bytes.
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// What the client trusts.
#[derive(Debug, Clone, Copy)]
pub enum Anchor<'a> {
    /// The DER certificate the listener serves: the only one accepted.
    Served(&'a [u8]),
    /// One or more CA certificates in PEM.
    CaPem(&'a [u8]),
}

/// The listener's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status code.
    pub status: u16,
    /// The body, as framed by `Content-Length`. Empty without one.
    pub body: Vec<u8>,
}

/// Why [`exchange`] failed. No variant carries request bytes.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    /// The trust anchor cannot be used.
    #[error("the trust anchor is not usable: {0}")]
    Anchor(String),
    /// The server name is not a name, or the served certificate does not
    /// hold it.
    #[error("the trusted certificate is not valid for {0:?}")]
    Name(String),
    /// No TCP connection.
    #[error("cannot connect: {0}")]
    Connect(String),
    /// The TLS handshake failed, for example on an untrusted certificate.
    #[error("the TLS handshake failed: {0}")]
    Tls(String),
    /// The request could not be sent, or the answer is not usable HTTP.
    #[error("the exchange failed: {0}")]
    Exchange(String),
}

/// The first DNS name in the subject alternative names of `cert_der` that
/// is not a wildcard: the name to ask for when the address is an IP.
#[must_use]
pub fn first_dns_name(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let names = cert.subject_alternative_name().ok()??;
    names
        .value
        .general_names
        .iter()
        .find_map(|name| match name {
            GeneralName::DNSName(dns) if !dns.starts_with('*') => Some((*dns).to_owned()),
            _ => None,
        })
}

/// Connects to `addr`, verifies the listener as `server_name` against
/// `anchor`, sends `request` and reads one HTTP/1.1 answer.
///
/// `timeout` bounds the connect and each read and write.
///
/// # Errors
///
/// A [`ListenerError`] for each failure; see the variants.
pub fn exchange(
    addr: SocketAddr,
    server_name: &str,
    anchor: Anchor<'_>,
    request: &[u8],
    timeout: Duration,
) -> Result<Answer, ListenerError> {
    let name = ServerName::try_from(server_name)
        .map_err(|_| ListenerError::Name(server_name.to_owned()))?
        .to_owned();
    let config = match anchor {
        Anchor::Served(der) => served_config(der, &name, server_name)?,
        Anchor::CaPem(pem) => ca_config(pem)?,
    };
    let mut session = rustls::ClientConnection::new(config, name)
        .map_err(|err| ListenerError::Tls(err.to_string()))?;
    let mut socket = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|err| ListenerError::Connect(err.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|err| ListenerError::Connect(err.to_string()))?;
    while session.is_handshaking() {
        session
            .complete_io(&mut socket)
            .map_err(|err| ListenerError::Tls(err.to_string()))?;
    }
    let mut stream = rustls::Stream::new(&mut session, &mut socket);
    stream
        .write_all(request)
        .and_then(|()| stream.flush())
        .map_err(|err| ListenerError::Exchange(format!("sending the request: {err}")))?;
    read_answer(&mut stream)
}

/// [`crate::health`]'s pinned configuration, after checking that `der` is
/// valid for `name`.
fn served_config(
    der: &[u8],
    name: &ServerName<'static>,
    shown: &str,
) -> Result<Arc<rustls::ClientConfig>, ListenerError> {
    let config = crate::health::pinned_client_config(der).map_err(ListenerError::Anchor)?;
    let cert = CertificateDer::from(der);
    webpki::EndEntityCert::try_from(&cert)
        .map_err(|err| ListenerError::Anchor(err.to_string()))?
        .verify_is_valid_for_subject_name(name)
        .map_err(|_| ListenerError::Name(shown.to_owned()))?;
    Ok(config)
}

/// A TLS 1.3 configuration whose roots are the certificates in `pem`.
fn ca_config(pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, ListenerError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|err| ListenerError::Anchor(err.to_string()))?;
        roots
            .add(cert)
            .map_err(|err| ListenerError::Anchor(err.to_string()))?;
    }
    if roots.is_empty() {
        return Err(ListenerError::Anchor(
            "the PEM holds no certificate".to_owned(),
        ));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| ListenerError::Anchor(format!("TLS 1.3 client config: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Reads one answer: the head, then exactly `Content-Length` body bytes,
/// at most [`MAX_ANSWER_BYTES`] in all. It never waits for the peer to
/// close, so a peer that closes without `close_notify` after a complete
/// answer is not an error.
fn read_answer(stream: &mut impl Read) -> Result<Answer, ListenerError> {
    let failed = |why: &str| ListenerError::Exchange(why.to_owned());
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at.saturating_add(4);
        }
        if raw.len() >= MAX_ANSWER_BYTES {
            return Err(failed("the answer is too large"));
        }
        let read = read_some(stream, &mut buf)?;
        if read == 0 {
            return Err(failed(
                "the connection closed before the answer's head ended",
            ));
        }
        raw.extend_from_slice(buf.get(..read).unwrap_or_default());
    };
    let head = std::str::from_utf8(raw.get(..head_end).unwrap_or_default())
        .map_err(|_| failed("the answer's head is not text"))?;
    let status = parse_status(head).ok_or_else(|| failed("the answer has no HTTP status"))?;
    let Some(length) = content_length(head)? else {
        return Ok(Answer {
            status,
            body: Vec::new(),
        });
    };
    if head_end.saturating_add(length) > MAX_ANSWER_BYTES {
        return Err(failed("the answer is too large"));
    }
    let end = head_end.saturating_add(length);
    while raw.len() < end {
        let read = read_some(stream, &mut buf)?;
        if read == 0 {
            return Err(failed(
                "the connection closed before the answer's body ended",
            ));
        }
        raw.extend_from_slice(buf.get(..read).unwrap_or_default());
    }
    Ok(Answer {
        status,
        body: raw.get(head_end..end).unwrap_or_default().to_vec(),
    })
}

/// One read. A close without `close_notify` counts as a close: the
/// framing, not the close, says whether the answer is complete.
fn read_some(stream: &mut impl Read, buf: &mut [u8]) -> Result<usize, ListenerError> {
    match stream.read(buf) {
        Ok(read) => Ok(read),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(err) => Err(ListenerError::Exchange(format!(
            "reading the answer: {err}"
        ))),
    }
}

/// The status code of an `HTTP/1.x NNN reason` status line.
fn parse_status(head: &str) -> Option<u16> {
    let mut parts = head.lines().next()?.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts
        .next()?
        .parse::<u16>()
        .ok()
        .filter(|status| (100..600).contains(status))
}

/// The `Content-Length` value, `None` without one.
///
/// # Errors
///
/// [`ListenerError::Exchange`] for a value that is not a number, or two
/// values that differ.
fn content_length(head: &str) -> Result<Option<usize>, ListenerError> {
    let mut found = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let value = value.trim().parse::<usize>().map_err(|_| {
            ListenerError::Exchange("the answer's Content-Length is not a number".to_owned())
        })?;
        if found.is_some_and(|seen| seen != value) {
            return Err(ListenerError::Exchange(
                "the answer has two different Content-Length values".to_owned(),
            ));
        }
        found = Some(value);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A one-shot server: its address and the thread that returns the request it read.
    type OneShot = (SocketAddr, std::thread::JoinHandle<Vec<u8>>);

    const REQUEST: &[u8] = b"POST /x HTTP/1.1\r\nHost: box.example\r\nContent-Length: 0\r\n\r\n";

    /// A certificate for `names` and a TLS 1.3 server config that serves it.
    fn served(
        names: &[&str],
    ) -> Result<(Vec<u8>, rustls::ServerConfig), Box<dyn std::error::Error>> {
        let key = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )?
        .self_signed(&key)?;
        let config = server_config(cert.der().to_vec(), &key)?;
        Ok((cert.der().to_vec(), config))
    }

    fn server_config(
        der: Vec<u8>,
        key: &rcgen::KeyPair,
    ) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
        Ok(rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )?)
    }

    /// Serves one connection: reads the request head, writes `answer`, and
    /// hands back the request it read.
    fn serve_once(
        config: rustls::ServerConfig,
        answer: Vec<u8>,
    ) -> Result<OneShot, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let Ok((mut socket, _)) = listener.accept() else {
                return seen;
            };
            let Ok(mut session) = rustls::ServerConnection::new(Arc::new(config)) else {
                return seen;
            };
            let mut stream = rustls::Stream::new(&mut session, &mut socket);
            let mut buf = [0_u8; 1024];
            while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return seen,
                    Ok(read) => seen.extend_from_slice(buf.get(..read).unwrap_or_default()),
                }
            }
            let _ = stream.write_all(&answer);
            let _ = stream.flush();
            seen
        });
        Ok((addr, handle))
    }

    fn joined(handle: std::thread::JoinHandle<Vec<u8>>) -> Result<Vec<u8>, String> {
        handle
            .join()
            .map_err(|_| "server thread panicked".to_owned())
    }

    const TIMEOUT: Duration = Duration::from_secs(10);

    #[test]
    fn the_served_certificate_is_trusted_and_the_answer_is_framed() -> R {
        let (der, config) = served(&["box.example"])?;
        let (addr, handle) = serve_once(
            config,
            b"HTTP/1.1 202 Accepted\r\ncontent-length: 17\r\n\r\n{\"requested\":true}trailing"
                .to_vec(),
        )?;
        let answer = exchange(addr, "box.example", Anchor::Served(&der), REQUEST, TIMEOUT)?;
        assert_eq!(answer.status, 202);
        assert_eq!(answer.body, b"{\"requested\":true".to_vec());
        assert_eq!(joined(handle)?, REQUEST.to_vec());
        Ok(())
    }

    #[test]
    fn another_certificate_fails_the_handshake() -> R {
        let (_, config) = served(&["box.example"])?;
        let (other, _) = served(&["box.example"])?;
        let (addr, handle) = serve_once(config, b"HTTP/1.1 202 A\r\n\r\n".to_vec())?;
        let err = exchange(
            addr,
            "box.example",
            Anchor::Served(&other),
            REQUEST,
            TIMEOUT,
        )
        .err()
        .ok_or("a different certificate was trusted")?;
        assert!(matches!(err, ListenerError::Tls(_)), "{err:?}");
        // The request never left the client.
        assert!(joined(handle)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_name_the_served_certificate_lacks_is_refused_before_connecting() -> R {
        let (der, _) = served(&["box.example"])?;
        // Nothing listens here: the refusal must come first.
        let addr = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        for name in ["other.example", "not a name"] {
            let err = exchange(addr, name, Anchor::Served(&der), REQUEST, TIMEOUT)
                .err()
                .ok_or("an unlisted name was accepted")?;
            assert!(matches!(err, ListenerError::Name(_)), "{name}: {err:?}");
            assert!(err.to_string().contains(name), "{err}");
        }
        let err = exchange(
            addr,
            "box.example",
            Anchor::Served(b"junk"),
            REQUEST,
            TIMEOUT,
        )
        .err()
        .ok_or("junk was trusted")?;
        assert!(matches!(err, ListenerError::Anchor(_)), "{err:?}");
        Ok(())
    }

    #[test]
    fn a_ca_anchor_validates_the_chain_and_the_name() -> R {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let mut ca_params = CertificateParams::new(Vec::default())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate()?;
        let ca_pem = ca_params.self_signed(&ca_key)?.pem();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate()?;
        let leaf = CertificateParams::new(vec!["box.example".to_owned()])?
            .signed_by(&leaf_key, &issuer)?;

        let (addr, handle) = serve_once(
            server_config(leaf.der().to_vec(), &leaf_key)?,
            b"HTTP/1.1 409 Conflict\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        )?;
        let answer = exchange(
            addr,
            "box.example",
            Anchor::CaPem(ca_pem.as_bytes()),
            REQUEST,
            TIMEOUT,
        )?;
        assert_eq!(
            (answer.status, answer.body.as_slice()),
            (409, b"{}".as_slice())
        );
        joined(handle)?;

        // The same chain, asked for a name the leaf does not hold.
        let (addr, handle) = serve_once(
            server_config(leaf.der().to_vec(), &leaf_key)?,
            b"HTTP/1.1 202 A\r\n\r\n".to_vec(),
        )?;
        let err = exchange(
            addr,
            "other.example",
            Anchor::CaPem(ca_pem.as_bytes()),
            REQUEST,
            TIMEOUT,
        )
        .err()
        .ok_or("a name outside the leaf was accepted")?;
        assert!(matches!(err, ListenerError::Tls(_)), "{err:?}");
        joined(handle)?;

        for pem in [
            b"".as_slice(),
            b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        ] {
            let err = exchange(addr, "box.example", Anchor::CaPem(pem), REQUEST, TIMEOUT)
                .err()
                .ok_or("an unusable PEM was trusted")?;
            assert!(matches!(err, ListenerError::Anchor(_)), "{err:?}");
        }
        Ok(())
    }

    #[test]
    fn a_closed_port_is_a_connect_failure() -> R {
        let (der, _) = served(&["box.example"])?;
        let addr = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let err = exchange(addr, "box.example", Anchor::Served(&der), REQUEST, TIMEOUT)
            .err()
            .ok_or("a closed port answered")?;
        assert!(matches!(err, ListenerError::Connect(_)), "{err:?}");
        Ok(())
    }

    #[test]
    fn unusable_answers_are_refused() -> R {
        for (answer, why) in [
            (
                b"HTTP/1.1 202 A\r\n".to_vec(),
                "closed before the answer's head",
            ),
            (b"SMTP 220 hi\r\n\r\n".to_vec(), "no HTTP status"),
            (b"HTTP/1.1 999 X\r\n\r\n".to_vec(), "no HTTP status"),
            (b"HTTP/1.1 \xff\r\n\r\n".to_vec(), "not text"),
            (
                b"HTTP/1.1 200 A\r\nContent-Length: x\r\n\r\n".to_vec(),
                "not a number",
            ),
            (
                b"HTTP/1.1 200 A\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n".to_vec(),
                "two different",
            ),
            (
                b"HTTP/1.1 200 A\r\nContent-Length: 5\r\n\r\n{}".to_vec(),
                "body ended",
            ),
            (
                b"HTTP/1.1 200 A\r\nContent-Length: 99999\r\n\r\n".to_vec(),
                "too large",
            ),
            (vec![b'x'; MAX_ANSWER_BYTES.saturating_add(10)], "too large"),
        ] {
            let (der, config) = served(&["box.example"])?;
            let (addr, handle) = serve_once(config, answer)?;
            let err = exchange(addr, "box.example", Anchor::Served(&der), REQUEST, TIMEOUT)
                .err()
                .ok_or(why)?;
            assert!(matches!(err, ListenerError::Exchange(_)), "{why}: {err:?}");
            assert!(err.to_string().contains(why), "{why}: {err}");
            joined(handle)?;
        }
        Ok(())
    }

    #[test]
    fn an_answer_without_a_length_has_an_empty_body() -> R {
        let (der, config) = served(&["box.example"])?;
        let (addr, handle) = serve_once(
            config,
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\ncontent-length: 2\r\nX: y\r\nno colon\r\n\r\n{}"
                .to_vec(),
        )?;
        let answer = exchange(addr, "box.example", Anchor::Served(&der), REQUEST, TIMEOUT)?;
        assert_eq!((answer.status, answer.body.len()), (401, 2));
        joined(handle)?;

        let (der, config) = served(&["box.example"])?;
        let (addr, handle) = serve_once(config, b"HTTP/1.0 503 Busy\r\n\r\nignored".to_vec())?;
        let answer = exchange(addr, "box.example", Anchor::Served(&der), REQUEST, TIMEOUT)?;
        assert_eq!(
            answer,
            Answer {
                status: 503,
                body: Vec::new()
            }
        );
        joined(handle)?;
        Ok(())
    }

    #[test]
    fn the_first_plain_dns_name_is_chosen() -> R {
        let (der, _) = served(&["*.example", "box.example", "localhost"])?;
        assert_eq!(first_dns_name(&der).as_deref(), Some("box.example"));
        let (der, _) = served(&["127.0.0.1"])?;
        assert_eq!(first_dns_name(&der), None);
        assert_eq!(first_dns_name(b"junk"), None);
        Ok(())
    }
}
