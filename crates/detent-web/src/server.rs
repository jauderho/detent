//! The listener: TCP, then TLS 1.3, then HTTP/2 or HTTP/1.1, then axum.
//!
//! ```text
//!   TcpListener ──▶ Semaphore permit ──▶ TlsAcceptor ──▶ hyper auto ──▶ Router
//!        │                 │                  │                          │
//!    accept loop      cap, no permit      handshake            harden(): request id,
//!    survives an      ⇒ dropped, no        timeout             §2.7 headers, timeout,
//!    accept error       handshake                              256 KiB body limit
//! ```
//!
//! # Guarantees
//!
//! * **One bad client cannot take the service down.** An accept failure, a
//!   failed or slow handshake, and a connection that dies mid-response are all
//!   logged at `debug` and dropped; the loop continues.
//! * **The connection cap is a cap, not a queue.** A connection that arrives
//!   with no permit free is closed immediately, before any TLS work is done,
//!   so an attacker cannot make the server spend handshakes it does not have
//!   capacity to serve.
//! * **The access log carries no secrets.** Method, path *without its query
//!   string*, status, duration and request id — never a query, never a header,
//!   never a body.
//! * **Shutdown is graceful.** The future stops the accept loop, then in-flight
//!   connections are told to finish and given [`SHUTDOWN_GRACE`] to do it.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use detent_core::diag::MessageId;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument as _, debug, info, info_span};

use crate::config::Config;
use crate::headers::security_headers;

/// Largest request body any handler will see (PLAN §2.7, "Input").
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// How long a client has to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long in-flight connections have to finish after shutdown is asked for.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// How long a client may take to send request headers (H9, slowloris).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2 keep-alive ping interval.
pub const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// HTTP/2 keep-alive timeout.
pub const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent HTTP/2 streams.
pub const H2_MAX_CONCURRENT_STREAMS: u32 = 32;

/// Maximum lifetime of a single connection.
pub const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(600);

/// Header the per-request id is echoed in.
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Bytes of randomness in a request id; rendered as 32 lowercase hex digits.
const REQUEST_ID_BYTES: usize = 16;

/// Body of `/healthz`. Constant, and deliberately says nothing about the
/// build: the endpoint is unauthenticated (PLAN Phase 4).
const HEALTHZ_BODY: &str = "ok";

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Why the listener could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// The configured address could not be bound — in use, or not permitted.
    #[error("{addr} could not be listened on: {source}")]
    Bind {
        /// The address from `[listen] addr`.
        addr: SocketAddr,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The socket bound but its own address could not be read back, so
    /// nothing could be printed for the operator.
    #[error("the listening address could not be read back: {source}")]
    LocalAddr {
        /// The underlying failure.
        source: std::io::Error,
    },
}

impl ServerError {
    /// The Fluent id describing this failure.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Bind { .. } => MessageId::new("web-server-bind-failed"),
            Self::LocalAddr { .. } => MessageId::new("web-server-address-unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// The unauthenticated `/healthz` route.
///
/// Constant body, no version, no build information, no host name: it answers
/// "this process is serving" and nothing an unauthenticated scanner could use.
/// `detent update` health-checks against it after a self-update (PLAN §2.9).
pub fn healthz() -> Router {
    Router::new().route("/healthz", get(|| async { HEALTHZ_BODY }))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// 32 lowercase hex digits from [`REQUEST_ID_BYTES`] bytes of system entropy.
///
/// A request id is a log correlation aid, not a security control, so a system
/// that cannot produce entropy yields a constant marker rather than stopping
/// the request or panicking.
fn request_id() -> String {
    let mut bytes = [0_u8; REQUEST_ID_BYTES];
    let hex_len = REQUEST_ID_BYTES.saturating_mul(2);
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(hex_len);
    }
    let mut out = String::with_capacity(hex_len);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

/// One lowercase hex digit from the low four bits of `value`.
const fn hex_digit(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

/// Attach a request id, run the request inside a span, echo the id back, and
/// emit one structured access log line.
///
/// The path is taken from `Uri::path()`, which excludes the query string; that
/// is deliberate and must stay that way (PLAN Phase 4: "no query strings with
/// secrets"). No header is logged either.
pub async fn trace_request(request: Request, next: Next) -> Response {
    let id = request_id();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let span = info_span!("request", request_id = %id, method = %method, path = %path);
    let started = Instant::now();

    let mut response = next.run(request).instrument(span.clone()).await;

    let elapsed = started.elapsed();
    span.in_scope(|| {
        info!(
            status = response.status().as_u16(),
            duration_ms = elapsed.as_millis(),
            "request"
        );
    });
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

/// Wrap `router` in the standard middleware stack.
///
/// Outermost first, as a request meets them: the access log and request id,
/// the §2.7 headers, the per-request timeout, and the body limit. The order
/// matters — the headers layer sits outside the timeout so that a timed-out
/// request still answers with the full header set.
pub fn harden(router: Router, request_timeout: Duration) -> Router {
    router
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(trace_request))
}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

/// A bound socket, a TLS configuration, and the router to serve.
pub struct Server {
    /// The bound socket.
    listener: TcpListener,
    /// Address the socket actually got, resolved once at bind time so
    /// [`local_addr`](Self::local_addr) cannot fail.
    local_addr: SocketAddr,
    /// TLS 1.3 acceptor, shared by every connection.
    acceptor: TlsAcceptor,
    /// The router, already wrapped by [`harden`].
    router: Router,
    /// One permit per allowed concurrent connection.
    permits: Arc<Semaphore>,
    /// Header read timeout (H9), configurable for tests.
    pub header_read_timeout: Duration,
    /// HTTP/2 keep-alive interval.
    pub h2_keep_alive_interval: Duration,
    /// HTTP/2 keep-alive timeout.
    pub h2_keep_alive_timeout: Duration,
    /// HTTP/2 max concurrent streams.
    pub h2_max_concurrent_streams: u32,
    /// Maximum connection lifetime.
    pub max_connection_lifetime: Duration,
}

impl std::fmt::Debug for Server {
    /// `TlsAcceptor` and `Router` are not `Debug`; the address and the
    /// connection cap are the only parts worth printing anyway.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local_addr)
            .field("permits", &self.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind `config.listen.addr` and prepare to serve `router` over `tls`.
    ///
    /// `router` is wrapped by [`harden`] here; callers pass their routes
    /// unadorned.
    ///
    /// # Errors
    ///
    /// [`ServerError::Bind`] when the address cannot be bound,
    /// [`ServerError::LocalAddr`] when the bound address cannot be read back.
    pub async fn bind(
        config: &Config,
        tls: rustls::ServerConfig,
        router: Router,
    ) -> Result<Self, ServerError> {
        let addr = config.listen.addr;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ServerError::Bind { addr, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| ServerError::LocalAddr { source })?;
        // A `u32` always fits a `usize` on the targets this ships on; the
        // fallback exists so the conversion needs no `unwrap`.
        let permits = usize::try_from(config.listen.max_connections).unwrap_or(usize::MAX);
        Ok(Self {
            listener,
            local_addr,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            router: harden(
                router,
                Duration::from_secs(config.listen.request_timeout_secs),
            ),
            permits: Arc::new(Semaphore::new(permits)),
            header_read_timeout: HEADER_READ_TIMEOUT,
            h2_keep_alive_interval: H2_KEEP_ALIVE_INTERVAL,
            h2_keep_alive_timeout: H2_KEEP_ALIVE_TIMEOUT,
            h2_max_concurrent_streams: H2_MAX_CONCURRENT_STREAMS,
            max_connection_lifetime: MAX_CONNECTION_LIFETIME,
        })
    }

    /// The address the socket is actually on — the configured one, or the one
    /// the kernel chose when the configuration asked for port 0.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept and serve until `shutdown` resolves.
    ///
    /// Returns once the accept loop has stopped and in-flight connections have
    /// either finished or run out of [`SHUTDOWN_GRACE`].
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) {
        let Self {
            listener,
            local_addr,
            acceptor,
            router,
            permits,
            header_read_timeout,
            h2_keep_alive_interval,
            h2_keep_alive_timeout,
            h2_max_concurrent_streams,
            max_connection_lifetime,
        } = self;
        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(header_read_timeout);
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(h2_keep_alive_interval))
            .keep_alive_timeout(h2_keep_alive_timeout)
            .max_concurrent_streams(Some(h2_max_concurrent_streams));
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);
        debug!(%local_addr, "serving");

        loop {
            let accepted = tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    // A per-connection accept failure (EMFILE, ECONNABORTED)
                    // must not end the service.
                    debug!(?error, "accept failed");
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                debug!(%peer, "connection cap reached; refusing without a handshake");
                drop(stream);
                continue;
            };

            let acceptor = acceptor.clone();
            let router = router.clone();
            let watcher = graceful.watcher();
            let builder = builder.clone();
            tokio::spawn(async move {
                // Held for the life of the connection.
                let _permit = permit;
                let tls =
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => tls,
                        Ok(Err(error)) => {
                            debug!(%peer, ?error, "tls handshake failed");
                            return;
                        }
                        Err(_elapsed) => {
                            debug!(%peer, "tls handshake timed out");
                            return;
                        }
                    };
                let requested = Arc::new(AtomicBool::new(false));
                let seen = Arc::clone(&requested);
                let svc = tower::ServiceExt::map_request(
                    router,
                    move |mut req: axum::http::Request<hyper::body::Incoming>| {
                        seen.store(true, Ordering::Relaxed);
                        req.extensions_mut().insert(ConnectInfo(peer));
                        req
                    },
                );
                let service = TowerToHyperService::new(svc);
                let connection = builder
                    .serve_connection(TokioIo::new(tls), service)
                    .into_owned();
                // The auto builder reads to sniff the protocol with no
                // deadline, and hyper's header timeout does not cover that
                // read, so a peer that completes the handshake and then sends
                // nothing would hold its permit for the whole lifetime. Its
                // first request must arrive within the header timeout (H9).
                tokio::select! {
                    outcome = tokio::time::timeout(
                        max_connection_lifetime,
                        watcher.watch(connection),
                    ) => match outcome {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => debug!(%peer, ?error, "connection ended"),
                        Err(_) => debug!(%peer, "connection lifetime exceeded"),
                    },
                    () = no_request_by(&requested, header_read_timeout) => {
                        debug!(%peer, "no request before the header timeout");
                    }
                }
            });
        }

        // Stop accepting before waiting, so a client cannot keep the shutdown
        // open by connecting again.
        drop(listener);
        tokio::select! {
            () = graceful.shutdown() => debug!("all connections finished"),
            () = tokio::time::sleep(SHUTDOWN_GRACE) => {
                debug!("shutdown grace expired with connections still open");
            }
        }
    }
}

/// Resolves at `deadline` unless a request has arrived by then; otherwise
/// never (H9).
async fn no_request_by(requested: &AtomicBool, deadline: Duration) {
    tokio::time::sleep(deadline).await;
    if requested.load(Ordering::Relaxed) {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HEALTHZ_BODY, MAX_BODY_BYTES, Server, ServerError, X_REQUEST_ID, harden, healthz,
        request_id,
    };
    use crate::config::Config;
    use crate::tls::{ALPN_H2_HTTP11, bootstrap_self_signed, server_config};

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use tower::ServiceExt as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../locales/en-US/core.ftl");

    fn app() -> Router {
        harden(
            healthz().route("/echo", post(|body: String| async move { body })),
            Duration::from_secs(30),
        )
    }

    #[tokio::test]
    async fn healthz_answers_a_constant_body_and_nothing_else() -> R {
        let response = app()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64).await?;
        assert_eq!(&body[..], HEALTHZ_BODY.as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn every_response_carries_a_request_id() -> R {
        let response = app()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?;
        let id = response
            .headers()
            .get(X_REQUEST_ID)
            .ok_or("no request id")?
            .to_str()?
            .to_owned();
        assert_eq!(id.len(), 32);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        let second = app()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?;
        assert_ne!(
            second
                .headers()
                .get(X_REQUEST_ID)
                .map(|v| v.to_str())
                .transpose()?,
            Some(id.as_str())
        );
        Ok(())
    }

    #[test]
    fn a_request_id_is_32_lowercase_hex_digits() {
        let id = request_id();
        assert_eq!(id.len(), 32);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(request_id(), request_id());
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused() -> R {
        let ok = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .body(Body::from(vec![b'x'; 1024]))?,
            )
            .await?;
        assert_eq!(ok.status(), StatusCode::OK);

        let too_big = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .body(Body::from(vec![b'x'; MAX_BODY_BYTES + 1]))?,
            )
            .await?;
        assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn a_slow_handler_is_timed_out_with_the_security_headers_intact() -> R {
        let router = harden(
            Router::new().route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    "never"
                }),
            ),
            Duration::from_millis(50),
        );
        let response = router
            .oneshot(Request::builder().uri("/slow").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(
            response
                .headers()
                .contains_key(axum::http::header::CONTENT_SECURITY_POLICY)
        );
        Ok(())
    }

    #[tokio::test]
    async fn bind_reports_the_address_it_actually_got() -> R {
        let mut config = Config::default();
        config.listen.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let tls = server_config(&bootstrap_self_signed(&[])?, ALPN_H2_HTTP11)?;
        let server = Server::bind(&config, tls, healthz()).await?;
        let addr = server.local_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(addr.port(), 0);

        // The manual `Debug` shows the address and the free permits, and
        // nothing that could carry a key or a request.
        let rendered = format!("{server:?}");
        assert!(rendered.contains(&addr.to_string()), "{rendered}");
        assert!(rendered.contains("permits"), "{rendered}");
        Ok(())
    }

    #[tokio::test]
    async fn a_port_that_cannot_be_bound_is_reported() -> R {
        let mut config = Config::default();
        config.listen.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let tls = server_config(&bootstrap_self_signed(&[])?, ALPN_H2_HTTP11)?;
        let first = Server::bind(&config, tls, healthz()).await?;

        // Bind the same port a second time: the OS refuses.
        config.listen.addr = first.local_addr();
        let tls = server_config(&bootstrap_self_signed(&[])?, ALPN_H2_HTTP11)?;
        match Server::bind(&config, tls, healthz()).await {
            Err(err @ ServerError::Bind { .. }) => {
                assert_eq!(err.message_id().as_str(), "web-server-bind-failed");
                assert!(!err.to_string().is_empty());
            }
            other => return Err(format!("expected a bind error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn every_error_variant_has_a_catalogued_message_id() {
        let cases: Vec<(ServerError, &str)> = vec![(
            ServerError::LocalAddr {
                source: std::io::Error::from(std::io::ErrorKind::NotConnected),
            },
            "web-server-address-unknown",
        )];
        for (error, id) in cases {
            assert_eq!(error.message_id().as_str(), id);
            assert!(!error.to_string().is_empty());
            assert!(!format!("{error:?}").is_empty());
            assert!(
                CATALOGUE
                    .lines()
                    .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id)),
                "`{id}` is missing from core.ftl"
            );
        }
        assert!(CATALOGUE.lines().any(|line| {
            line.split('=')
                .next()
                .is_some_and(|k| k.trim() == "web-server-bind-failed")
        }));
    }
}
