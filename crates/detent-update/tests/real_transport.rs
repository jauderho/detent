//! H18: `RealTransport` follows 302 to the asset, refuses redirect to http, caps redirects.

#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use detent_update::fetch::Transport;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;

fn make_pair() -> (ServerConfig, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("rcgen");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    let certs = vec![CertificateDer::from(cert_der.clone())];
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(key_der.into());
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls13")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (config, cert_der)
}

#[test]
fn follows_302() {
    let (server_config, cert_der) = make_pair();
    let roots = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).expect("add root");
        roots
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let port = addr.port();

    let handle = thread::spawn(move || {
        // Same drain-to-end-of-headers discipline as caps_redirect_loop:
        // answer only after the full request arrived, flush before close.
        fn serve_once(stream: &mut std::net::TcpStream, server_config: &ServerConfig, resp: &[u8]) {
            let mut conn =
                rustls::ServerConnection::new(Arc::new(server_config.clone())).expect("conn");
            conn.complete_io(stream).expect("handshake");
            let mut seen = Vec::new();
            loop {
                conn.complete_io(stream).expect("drain request");
                let mut buf = [0u8; 4096];
                let n = conn.reader().read(&mut buf).expect("read headers");
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(buf.get(..n).expect("read count within buffer"));
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            conn.writer().write_all(resp).expect("write");
            let _ = conn.complete_io(stream);
            conn.send_close_notify();
        }
        let (mut stream, _) = listener.accept().expect("accept1");
        let resp1 = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://localhost:{port}/asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        serve_once(&mut stream, &server_config, resp1.as_bytes());
        drop(stream);
        let (mut stream2, _) = listener.accept().expect("accept2");
        let body = b"hello-asset";
        let resp2 = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut full = resp2.into_bytes();
        full.extend_from_slice(body);
        serve_once(&mut stream2, &server_config, &full);
    });

    let transport = detent_update::fetch::RealTransport::with_roots(roots).expect("transport");
    let url = format!("https://localhost:{port}/releases");
    let mut out = Vec::new();
    let n = transport.get(&url, 1 << 20, &mut out).expect("follow 302");
    assert_eq!(
        usize::try_from(n).expect("byte count fits usize"),
        b"hello-asset".len()
    );
    assert_eq!(out, b"hello-asset");
    let _ = handle.join();
}

#[test]
fn refuses_redirect_to_http() {
    let (server_config, cert_der) = make_pair();
    let roots = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).expect("add root");
        roots
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut conn = rustls::ServerConnection::new(Arc::new(server_config)).expect("conn");
        conn.complete_io(&mut stream).expect("handshake");
        let mut seen = Vec::new();
        loop {
            conn.complete_io(&mut stream).expect("drain request");
            let mut buf = [0u8; 4096];
            let n = conn.reader().read(&mut buf).expect("read headers");
            if n == 0 {
                break;
            }
            seen.extend_from_slice(buf.get(..n).expect("read count within buffer"));
            if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let resp = "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        conn.writer().write_all(resp.as_bytes()).expect("write");
        let _ = conn.complete_io(&mut stream);
        conn.send_close_notify();
    });
    let transport = detent_update::fetch::RealTransport::with_roots(roots).expect("transport");
    let url = format!("https://localhost:{}/releases", addr.port());
    let mut out = Vec::new();
    let err = transport
        .get(&url, 1 << 20, &mut out)
        .expect_err("must refuse http redirect");
    let msg = err.to_string();
    assert!(
        msg.contains("non-https") || msg.contains("refused"),
        "unexpected error: {msg}"
    );
    let _ = handle.join();
}

#[test]
fn caps_redirect_loop() {
    let (server_config, cert_der) = make_pair();
    let roots = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).expect("add root");
        roots
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let port = addr.port();
    let handle = thread::spawn(move || {
        // Read one HTTP request to the end of its headers, then answer.
        // A single 4 KB read can stop mid-headers and leave the client
        // blocked writing its request while this side waits to write the
        // response: a deadlock that surfaces as a 30 s client timeout
        // (macOS CI). The cap under test is untouched; only the stub drains
        // the request fully and flushes the response before closing.
        fn serve_redirect(
            stream: &mut std::net::TcpStream,
            server_config: &ServerConfig,
            port: u16,
        ) {
            let mut conn =
                rustls::ServerConnection::new(Arc::new(server_config.clone())).expect("conn");
            conn.complete_io(stream).expect("handshake");
            let mut seen = Vec::new();
            loop {
                conn.complete_io(stream).expect("drain request");
                let mut buf = [0u8; 4096];
                let n = conn.reader().read(&mut buf).expect("read headers");
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(buf.get(..n).expect("read count within buffer"));
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: https://localhost:{port}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            conn.writer().write_all(resp.as_bytes()).expect("write");
            let _ = conn.complete_io(stream);
            conn.send_close_notify();
        }
        for _ in 0..6 {
            let (mut stream, _) = listener.accept().expect("accept");
            serve_redirect(&mut stream, &server_config, port);
        }
    });
    let transport = detent_update::fetch::RealTransport::with_roots(roots).expect("transport");
    let url = format!("https://localhost:{port}/start");
    let mut out = Vec::new();
    let err = transport
        .get(&url, 1 << 20, &mut out)
        .expect_err("loop must be refused");
    assert!(
        err.to_string().contains("too many redirects"),
        "unexpected error: {err}"
    );
    let _ = handle.join();
}
