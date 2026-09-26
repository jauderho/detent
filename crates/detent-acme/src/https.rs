//! The HTTPS transport the networked dns-01 providers send their API calls
//! through: hyper + hyper-rustls, TLS 1.3 only, `https://` only, the same
//! client stack the ACME order flow uses.
//!
//! [`DnsProvider`](crate::DnsProvider) is synchronous and the order flow calls
//! it from inside its async runtime, so every request runs on its own scoped
//! thread with a private current-thread runtime. Each request has one
//! deadline for connect, send and the whole response, and the response body
//! is capped. Error text names the method and URL only: request headers carry
//! the provider credentials and never reach an error or a log.

use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::AcmeError;
use crate::providers::HttpRequest;

/// One deadline for connect, request and the complete response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Provider API answers are small JSON documents; anything larger is refused.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Sends provider API requests over HTTPS.
pub(crate) struct HttpsTransport {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    timeout: Duration,
}

impl HttpsTransport {
    /// A transport that trusts the webpki roots, as the public provider APIs
    /// need.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the TLS 1.3 client cannot be built.
    pub(crate) fn new() -> Result<Self, AcmeError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots, REQUEST_TIMEOUT)
    }

    fn with_roots(roots: rustls::RootCertStore, timeout: Duration) -> Result<Self, AcmeError> {
        // No idle pool: each request runs on a runtime that ends with it, so
        // a pooled connection would outlive the runtime that drives it.
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(crate::order::tls13_connector(roots)?);
        Ok(Self { client, timeout })
    }

    /// Sends `request` and returns `(status, body)`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] naming the method and URL when the request
    /// cannot be built, the connection or TLS handshake fails, the deadline
    /// passes, or the body is too large or not UTF-8.
    pub(crate) fn send(&self, request: &HttpRequest) -> Result<(u16, String), AcmeError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|err| fail(request, &format!("runtime: {err}")))?;
                    runtime.block_on(async {
                        tokio::time::timeout(self.timeout, self.exchange(request))
                            .await
                            .map_err(|_| fail(request, "timed out"))?
                    })
                })
                .join()
                .map_err(|_| fail(request, "transport thread panicked"))?
        })
    }

    async fn exchange(&self, request: &HttpRequest) -> Result<(u16, String), AcmeError> {
        let mut builder = hyper::Request::builder()
            .method(request.method)
            .uri(request.url.as_str())
            .header(hyper::header::USER_AGENT, "detent-acme");
        if !request.body.is_empty() {
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        for (name, value) in &request.headers {
            builder = builder.header(*name, value.as_str());
        }
        // The build error can quote a header value, and header values are
        // credentials: report a fixed text only.
        let built = builder
            .body(Full::new(Bytes::from(request.body.clone())))
            .map_err(|_| fail(request, "request could not be built"))?;
        let response = self
            .client
            .request(built)
            .await
            .map_err(|err| fail(request, &error_chain(&err)))?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|err| fail(request, &format!("response body: {err}")))?
            .to_bytes();
        let body = String::from_utf8(body.to_vec())
            .map_err(|_| fail(request, "response body is not UTF-8"))?;
        Ok((status, body))
    }
}

fn fail(request: &HttpRequest, reason: &str) -> AcmeError {
    AcmeError::Config(format!("{} {}: {reason}", request.method, request.url))
}

/// The error and its sources on one line: hyper's top-level text alone
/// ("client error (Connect)") does not say what failed.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// What the fake server does after it reads one request.
    enum Reply {
        /// Answer with this status and body.
        With(u16, Vec<u8>),
        /// Hold the connection open and never answer.
        Silent,
    }

    struct Server {
        port: u16,
        roots: rustls::RootCertStore,
        seen: std::thread::JoinHandle<Result<String, String>>,
    }

    /// A one-shot TLS 1.3 server for `localhost` on a free port. It returns
    /// the raw request head and body it read.
    fn serve_once(reply: Reply) -> Result<Server, Box<dyn std::error::Error>> {
        let key = rcgen::KeyPair::generate()?;
        let cert =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&key)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone())?;
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let seen = std::thread::spawn(move || -> Result<String, String> {
            let (mut tcp, _) = listener.accept().map_err(|e| e.to_string())?;
            let mut conn =
                rustls::ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut raw = Vec::new();
            let mut buf = [0_u8; 4096];
            let head_end = loop {
                let n = tls.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("client closed before the request ended".to_owned());
                }
                raw.extend_from_slice(buf.get(..n).unwrap_or_default());
                if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at.saturating_add(4);
                }
            };
            let head =
                String::from_utf8_lossy(raw.get(..head_end).unwrap_or_default()).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            while raw.len() < head_end.saturating_add(length) {
                let n = tls.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(buf.get(..n).unwrap_or_default());
            }
            match reply {
                Reply::With(status, body) => {
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    tls.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
                    tls.write_all(&body).map_err(|e| e.to_string())?;
                    tls.flush().map_err(|e| e.to_string())?;
                    conn.send_close_notify();
                    let _ = conn.complete_io(&mut tcp);
                }
                Reply::Silent => {
                    // Wait for the client to give up and close.
                    let _ = tls.read(&mut buf);
                }
            }
            Ok(String::from_utf8_lossy(&raw).into_owned())
        });
        Ok(Server { port, roots, seen })
    }

    fn request(url: String, secret: &str, body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST",
            url,
            headers: vec![("Authorization", format!("Bearer {secret}"))],
            body: body.to_owned(),
        }
    }

    fn joined(server: Server) -> Result<String, Box<dyn std::error::Error>> {
        server
            .seen
            .join()
            .map_err(|_| "server thread panicked")?
            .map_err(Into::into)
    }

    #[test]
    fn a_request_round_trips_over_tls13() -> R {
        let server = serve_once(Reply::With(201, br#"{"ok":true}"#.to_vec()))?;
        let transport = HttpsTransport::with_roots(server.roots.clone(), REQUEST_TIMEOUT)?;
        let url = format!("https://localhost:{}/zones/records?x=1", server.port);
        let (status, body) = transport.send(&request(url, "tok-1", r#"{"a":1}"#))?;
        assert_eq!((status, body.as_str()), (201, r#"{"ok":true}"#));
        let seen = joined(server)?.to_ascii_lowercase();
        assert!(
            seen.starts_with("post /zones/records?x=1 http/1.1\r\n"),
            "{seen}"
        );
        assert!(seen.contains("authorization: bearer tok-1\r\n"), "{seen}");
        assert!(
            seen.contains("content-type: application/json\r\n"),
            "{seen}"
        );
        assert!(seen.contains("user-agent: detent-acme\r\n"), "{seen}");
        assert!(seen.ends_with("\r\n\r\n{\"a\":1}"), "{seen}");
        Ok(())
    }

    #[test]
    fn a_bodyless_request_sends_no_content_type() -> R {
        let server = serve_once(Reply::With(200, b"[]".to_vec()))?;
        let transport = HttpsTransport::with_roots(server.roots.clone(), REQUEST_TIMEOUT)?;
        let url = format!("https://localhost:{}/list", server.port);
        let mut get = request(url, "tok", "");
        get.method = "GET";
        assert_eq!(transport.send(&get)?, (200, "[]".to_owned()));
        let seen = joined(server)?.to_ascii_lowercase();
        assert!(!seen.contains("content-type:"), "{seen}");
        Ok(())
    }

    #[test]
    fn a_request_works_from_inside_an_async_runtime() -> R {
        let server = serve_once(Reply::With(200, b"{}".to_vec()))?;
        let transport = HttpsTransport::with_roots(server.roots.clone(), REQUEST_TIMEOUT)?;
        let url = format!("https://localhost:{}/update", server.port);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let answer = runtime.block_on(async { transport.send(&request(url, "tok", "{}")) })?;
        assert_eq!(answer, (200, "{}".to_owned()));
        joined(server)?;
        Ok(())
    }

    #[test]
    fn plain_http_is_refused_without_a_connection() -> R {
        let transport = HttpsTransport::new()?;
        let url = "http://127.0.0.1:9/update".to_owned();
        let err = transport
            .send(&request(url, "s3cr3t-token", "{}"))
            .err()
            .ok_or("plain http must fail")?;
        let text = err.to_string();
        assert!(text.contains("POST http://127.0.0.1:9/update"), "{text}");
        assert!(!text.contains("s3cr3t-token"), "{text}");
        Ok(())
    }

    #[test]
    fn an_untrusted_certificate_is_refused_and_the_error_holds_no_secret() -> R {
        let server = serve_once(Reply::With(200, b"{}".to_vec()))?;
        // Trust the public roots only: the self-signed test cert is not in them.
        let transport = HttpsTransport::new()?;
        let url = format!("https://localhost:{}/update", server.port);
        let err = transport
            .send(&request(url, "s3cr3t-token", "{}"))
            .err()
            .ok_or("an untrusted server must fail")?;
        let text = err.to_string();
        assert!(text.contains("certificate"), "{text}");
        assert!(!text.contains("s3cr3t-token"), "{text}");
        drop(server.seen.join());
        Ok(())
    }

    #[test]
    fn a_silent_server_hits_the_deadline() -> R {
        let server = serve_once(Reply::Silent)?;
        let transport =
            HttpsTransport::with_roots(server.roots.clone(), Duration::from_millis(300))?;
        let url = format!("https://localhost:{}/update", server.port);
        let err = transport
            .send(&request(url, "tok", "{}"))
            .err()
            .ok_or("a silent server must time out")?;
        assert!(err.to_string().ends_with(": timed out"), "{err}");
        joined(server)?;
        Ok(())
    }

    #[test]
    fn an_oversize_response_is_refused() -> R {
        let server = serve_once(Reply::With(200, vec![b'a'; MAX_RESPONSE_BYTES + 1]))?;
        let transport = HttpsTransport::with_roots(server.roots.clone(), REQUEST_TIMEOUT)?;
        let url = format!("https://localhost:{}/list", server.port);
        let err = transport
            .send(&request(url, "tok", ""))
            .err()
            .ok_or("an oversize body must fail")?;
        assert!(err.to_string().contains("response body"), "{err}");
        drop(server.seen.join());
        Ok(())
    }

    #[test]
    fn a_non_utf8_response_is_refused() -> R {
        let server = serve_once(Reply::With(200, vec![0xff, 0xfe]))?;
        let transport = HttpsTransport::with_roots(server.roots.clone(), REQUEST_TIMEOUT)?;
        let url = format!("https://localhost:{}/list", server.port);
        let err = transport
            .send(&request(url, "tok", ""))
            .err()
            .ok_or("a non-UTF-8 body must fail")?;
        assert!(err.to_string().ends_with("not UTF-8"), "{err}");
        joined(server)?;
        Ok(())
    }

    #[test]
    fn a_header_value_the_request_builder_refuses_is_not_quoted() -> R {
        let transport = HttpsTransport::new()?;
        let bad = request("https://localhost:9/x".to_owned(), "s3cr3t\ntoken", "");
        let text = transport
            .send(&bad)
            .err()
            .ok_or("a bad header value must fail")?
            .to_string();
        assert!(text.ends_with("request could not be built"), "{text}");
        assert!(!text.contains("s3cr3t"), "{text}");
        Ok(())
    }

    #[derive(Debug)]
    struct Wrap(std::io::Error);

    impl std::fmt::Display for Wrap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("outer")
        }
    }

    impl std::error::Error for Wrap {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_joins_every_source() {
        assert_eq!(
            error_chain(&Wrap(std::io::Error::other("cause"))),
            "outer: cause"
        );
    }
}
