//! `detent cert renew`: ask the running server to renew its certificate now.
//!
//! ```text
//!   --token-file / DETENT_TOKEN ──▶ Zeroizing token
//!   [listen] or --url ────────────▶ address + server name
//!   tls.cert_dir or --ca-file ────▶ the one trust anchor
//!                    │
//!                    ▼
//!   POST /api/v1/system/cert/renew, Authorization: Bearer (TLS 1.3)
//! ```
//!
//! There is no local bypass: the request is the web console's button, so it
//! gets the same `write` scope check, the same `cert_renew_requested` audit
//! record and the same one-forced-order-per-hour limit in the acme process.
//!
//! The token never comes from argv. A token file is refused unless it is a
//! regular file (opened `O_NOFOLLOW`), owned by the effective uid, with no
//! group or other permission bit — the checks `secrets.toml` gets. The token
//! lives in [`Zeroizing`] buffers, and no message, error or log line quotes
//! it or the `Authorization` header: the request is built here and handed to
//! [`detent_update::listener`] as bytes, whose errors never quote them.

use std::ffi::OsString;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use detent_core::diag::MessageId;
#[cfg(feature = "mcp")]
use detent_ops::OpsError;
use detent_update::listener::{self, Anchor, Answer};
use zeroize::Zeroizing;

use crate::cli::{HttpsUrl, RenewArgs};
use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams, report_web_config_error};

/// The environment variable read when `--token-file` is not given.
pub const TOKEN_ENV: &str = "DETENT_TOKEN";

/// The largest token file read, in bytes.
const MAX_TOKEN_BYTES: u64 = 4096;

/// The largest `--ca-file` read, in bytes.
const MAX_CA_BYTES: u64 = 1 << 20;

/// Bounds the connect and each read and write.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Permission bits for group and other. Any of them set is refused.
const GROUP_OTHER_BITS: u32 = 0o077;

/// Why no token was loaded.
#[derive(Debug, PartialEq, Eq)]
enum TokenError {
    /// Neither `--token-file` nor [`TOKEN_ENV`] was given.
    NoSource,
    /// The source was given but is not usable.
    Refused {
        /// The path, or [`TOKEN_ENV`].
        source: String,
        /// Why, in English, without any token byte.
        reason: String,
    },
}

/// The server to ask: where to connect, the name to verify, and the `Host`.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    addr: SocketAddr,
    name: String,
    host: String,
}

/// What the answer means for the operator.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `202`: the acme process got the request.
    Requested,
    /// `401`/`403`: the token is unknown, expired or read-only.
    TokenRefused,
    /// `409`: `tls.bootstrap` is not `acme`.
    NotAcme,
    /// Any other status, with the server's message id when it sent one.
    ServerError(Option<String>),
}

/// `detent cert renew`.
///
/// `env_token` is the value of [`TOKEN_ENV`], passed in so that tests need
/// not change the process environment.
///
/// # Errors
///
/// Whatever the streams report.
pub fn run(
    args: &RenewArgs,
    dryrun: bool,
    env_token: Option<OsString>,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let token = match load_token(args.token_file.as_deref(), env_token) {
        Ok(token) => token,
        Err(TokenError::NoSource) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-no-token"),
                &[("var", TOKEN_ENV)],
            )?;
            return Ok(Exit::Usage);
        }
        Err(TokenError::Refused { source, reason }) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-bad-token"),
                &[("source", &source), ("reason", &reason)],
            )?;
            return Ok(Exit::Failed);
        }
    };

    // A missing `detent.toml` is the documented defaults, so this also
    // works on a host with `--url` and `--ca-file` and no config.
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => return report_web_config_error(&err, settings, renderer, streams),
    };
    let prepared = match prepare(&config, args.url.as_ref(), args.ca_file.as_deref()) {
        Ok(prepared) => prepared,
        Err(err) => return report_unreached(&err, renderer, streams),
    };
    let address = prepared.target.addr.to_string();

    if dryrun {
        renderer.line(
            streams.out,
            MessageId::new("cli-dryrun-cert-renew"),
            &[("address", &address), ("name", &prepared.target.name)],
        )?;
        return Ok(Exit::Ok);
    }

    match ask(&prepared, &token) {
        Ok(answer) => report(&answer, &address, renderer, streams),
        Err(err) => report_unreached(&err, renderer, streams),
    }
}

/// Why the server was not asked.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unreached {
    /// The `--ca-file` cannot be read.
    CaUnreadable { path: PathBuf, reason: String },
    /// `tls.cert_dir` holds no certificate.
    CertMissing { path: PathBuf },
    /// `tls.cert_dir` cannot be read.
    CertUnreadable { path: PathBuf, reason: String },
    /// No connection: the name did not resolve, or the connect, the
    /// handshake or the exchange failed. `address` is the one shown.
    Connect { address: String, reason: String },
}

/// Where to connect and what to trust, resolved and ready to ask.
#[derive(Debug)]
pub(crate) struct Prepared {
    target: Target,
    /// The CA PEM (`--ca-file`) when `ca`, else the served certificate's DER.
    trust: Vec<u8>,
    ca: bool,
}

impl Prepared {
    /// The one trust anchor.
    fn anchor(&self) -> Anchor<'_> {
        if self.ca {
            Anchor::CaPem(&self.trust)
        } else {
            Anchor::Served(&self.trust)
        }
    }
}

/// The certificate the server serves from `cert_dir`.
///
/// # Errors
///
/// [`Unreached::CertMissing`] or [`Unreached::CertUnreadable`].
pub(crate) fn served_pair(cert_dir: &Path) -> Result<detent_web::CertifiedKeyPair, Unreached> {
    match detent_web::serving_pair(cert_dir) {
        Ok(Some(pair)) => Ok(pair),
        Ok(None) => Err(Unreached::CertMissing {
            path: cert_dir.to_path_buf(),
        }),
        Err(err) => Err(Unreached::CertUnreadable {
            path: cert_dir.to_path_buf(),
            reason: err.to_string(),
        }),
    }
}

/// Resolve the address and the trust anchor from `config`: `ca_file`, else
/// the certificate the server serves from `tls.cert_dir`; `url`, else the
/// configured `listen` address.
///
/// # Errors
///
/// An [`Unreached`] that names what is missing.
pub(crate) fn prepare(
    config: &detent_web::Config,
    url: Option<&HttpsUrl>,
    ca_file: Option<&Path>,
) -> Result<Prepared, Unreached> {
    let (trust, ca) = if let Some(path) = ca_file {
        let pem = read_ca_file(path).map_err(|reason| Unreached::CaUnreadable {
            path: path.to_path_buf(),
            reason,
        })?;
        (pem, true)
    } else {
        let pair = served_pair(&config.tls.cert_dir)?;
        (pair.cert_der().to_vec(), false)
    };
    let listen = config.listen.addr;
    let served = (!ca).then_some(trust.as_slice());
    let target = resolve(url, listen, served).map_err(|reason| Unreached::Connect {
        address: url.map_or_else(|| loopback_for(listen).to_string(), HttpsUrl::authority),
        reason,
    })?;
    Ok(Prepared { target, trust, ca })
}

/// Send the renewal request with `token` and read the answer. The request
/// lives in a zeroed buffer that is dropped before this returns; no error
/// quotes it.
///
/// # Errors
///
/// [`Unreached::Connect`].
pub(crate) fn ask(prepared: &Prepared, token: &str) -> Result<Answer, Unreached> {
    let request = renew_request(&prepared.target.host, token);
    listener::exchange(
        prepared.target.addr,
        &prepared.target.name,
        prepared.anchor(),
        &request,
        TIMEOUT,
    )
    .map_err(|err| Unreached::Connect {
        address: prepared.target.addr.to_string(),
        reason: err.to_string(),
    })
}

/// Ask the server that `config` describes to renew now, as the holder of
/// `token`: what `detent cert renew` does, for a caller that has no
/// streams. Only `202` is `Ok`.
///
/// # Errors
///
/// [`OpsError::Cert`], whose message id is the one `detent cert renew` prints
/// for the same failure, and whose text names the address.
#[cfg(feature = "mcp")]
pub(crate) fn request(config: &detent_web::Config, token: &str) -> Result<(), OpsError> {
    let prepared = prepare(config, None, None).map_err(into_ops)?;
    let answer = ask(&prepared, token).map_err(into_ops)?;
    accepted(&answer, &prepared.target.addr.to_string())
}

/// `Ok` for `202`; else the [`OpsError::Cert`] for what the server at
/// `address` answered.
#[cfg(feature = "mcp")]
fn accepted(answer: &Answer, address: &str) -> Result<(), OpsError> {
    let (id, reason) = match outcome(answer) {
        Outcome::Requested => return Ok(()),
        Outcome::TokenRefused => (
            "cli-cert-renew-token-refused",
            format!(
                "the server at {address} refused the token (HTTP {}); it needs write scope",
                answer.status
            ),
        ),
        Outcome::NotAcme => (
            "cli-cert-renew-not-acme",
            format!("the server at {address} runs no ACME process (`tls.bootstrap` is not `acme`)"),
        ),
        Outcome::ServerError(Some(server_id)) => (
            "cli-cert-renew-server-error",
            format!(
                "the server at {address} answered HTTP {}: {server_id}",
                answer.status
            ),
        ),
        Outcome::ServerError(None) => (
            "cli-cert-renew-server-error-bare",
            format!("the server at {address} answered HTTP {}", answer.status),
        ),
    };
    Err(OpsError::Cert {
        id: MessageId::new(id),
        reason,
    })
}

/// `err` as the operation layer's error, with the id the CLI prints.
#[cfg(feature = "mcp")]
pub(crate) fn into_ops(err: Unreached) -> OpsError {
    let (id, reason) = match err {
        Unreached::CaUnreadable { path, reason } => (
            "cli-cert-renew-ca-unreadable",
            format!("the CA file {} could not be read: {reason}", path.display()),
        ),
        Unreached::CertMissing { path } => (
            "cli-cert-missing",
            format!("no certificate is stored in {}", path.display()),
        ),
        Unreached::CertUnreadable { path, reason } => (
            "cli-cert-unreadable",
            format!(
                "the certificate in {} could not be read: {reason}",
                path.display()
            ),
        ),
        Unreached::Connect { address, reason } => (
            "cli-cert-renew-unreachable",
            format!("could not talk to the server at {address}: {reason}"),
        ),
    };
    OpsError::Cert {
        id: MessageId::new(id),
        reason,
    }
}

/// Prints why the server was not asked.
///
/// # Errors
///
/// Whatever the streams report.
fn report_unreached(
    err: &Unreached,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    match err {
        Unreached::CaUnreadable { path, reason } => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-ca-unreadable"),
                &[("path", &path.display().to_string()), ("reason", reason)],
            )?;
            Ok(Exit::Failed)
        }
        Unreached::CertMissing { path } => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-cert-missing"),
                &[("path", &path.display().to_string())],
            )?;
            Ok(Exit::Failed)
        }
        Unreached::CertUnreadable { path, reason } => {
            crate::cert::cert_unreadable(path, reason, renderer, streams)
        }
        Unreached::Connect { address, reason } => unreachable(address, reason, renderer, streams),
    }
}

/// The token from `file`, else from `env`.
fn load_token(file: Option<&Path>, env: Option<OsString>) -> Result<Zeroizing<String>, TokenError> {
    if let Some(path) = file {
        let refused = |reason: String| TokenError::Refused {
            source: path.display().to_string(),
            reason,
        };
        let bytes = read_private_file(path, MAX_TOKEN_BYTES).map_err(refused)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| refused("the file is not UTF-8 text".to_owned()))?;
        return checked_token(text).map_err(refused);
    }
    let refused = |reason: String| TokenError::Refused {
        source: TOKEN_ENV.to_owned(),
        reason,
    };
    match env {
        Some(value) if !value.is_empty() => {
            let value = Zeroizing::new(
                value
                    .into_string()
                    .map_err(|_| refused("the value is not UTF-8 text".to_owned()))?,
            );
            checked_token(&value).map_err(refused)
        }
        _ => Err(TokenError::NoSource),
    }
}

/// `text` without surrounding white space, if it can go in a header: one
/// to 1024 visible ASCII characters.
fn checked_token(text: &str) -> Result<Zeroizing<String>, String> {
    let token = text.trim();
    if token.is_empty() {
        return Err("it is empty".to_owned());
    }
    if token.len() > 1024 || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("it is not a token: expected one line of visible ASCII".to_owned());
    }
    Ok(Zeroizing::new(token.to_owned()))
}

/// Reads a file only this user can read: opened `O_NOFOLLOW`, a regular
/// file, owned by the effective uid, no group or other bit, at most `cap`
/// bytes. The error is the reason, in English.
fn read_private_file(path: &Path, cap: u64) -> Result<Zeroizing<Vec<u8>>, String> {
    read_owned_by(path, cap, rustix::process::geteuid().as_raw())
}

/// [`read_private_file`], with the owner the file must have given as `uid`.
fn read_owned_by(path: &Path, cap: u64, uid: u32) -> Result<Zeroizing<Vec<u8>>, String> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;

    // `NONBLOCK`: opening a FIFO must not hang; it is refused below.
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err("the file does not exist".to_owned()),
        Err(Errno::LOOP) => return Err("it is a symlink; it must be a regular file".to_owned()),
        Err(err) => return Err(std::io::Error::from(err).to_string()),
    };
    let file = std::fs::File::from(fd);
    let meta = file.metadata().map_err(|err| err.to_string())?;
    if !meta.is_file() {
        return Err("it is not a regular file".to_owned());
    }
    if meta.uid() != uid {
        return Err(format!(
            "it is owned by uid {}; it must be owned by uid {uid}",
            meta.uid()
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & GROUP_OTHER_BITS != 0 {
        return Err(format!(
            "it has mode {mode:o}; group and other must have no access (use 0600)"
        ));
    }
    // One allocation, never grown, so no copy is left in a freed buffer.
    let limit = cap.saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(limit).unwrap_or(usize::MAX),
    ));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
        return Err(format!("it is larger than {cap} bytes"));
    }
    Ok(bytes)
}

/// The `--ca-file` PEM, at most [`MAX_CA_BYTES`]. It is public, so only
/// its size is checked; a bad PEM is refused by the TLS client.
fn read_ca_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let mut pem = Vec::new();
    file.take(MAX_CA_BYTES.saturating_add(1))
        .read_to_end(&mut pem)
        .map_err(|err| err.to_string())?;
    if u64::try_from(pem.len()).unwrap_or(u64::MAX) > MAX_CA_BYTES {
        return Err(format!("it is larger than {MAX_CA_BYTES} bytes"));
    }
    Ok(pem)
}

/// `addr`, with a wildcard IP replaced by loopback of the same family: a
/// server bound to every address is reached on this host's own.
const fn loopback_for(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// Where to connect and which name to verify.
///
/// Without `url`, the configured `listen` address (a wildcard on loopback)
/// and the served certificate's first DNS name. With `url`, its host: a DNS
/// name is verified as given; an IP is verified as the served certificate's
/// first DNS name when it is loopback and the served certificate is the
/// anchor, else as the IP.
///
/// # Errors
///
/// The reason, in English: no DNS name to verify, or a host that does not
/// resolve.
fn resolve(
    url: Option<&HttpsUrl>,
    listen: SocketAddr,
    served: Option<&[u8]>,
) -> Result<Target, String> {
    let served_name = || {
        served.and_then(listener::first_dns_name).ok_or_else(|| {
            "the served certificate names no DNS host to verify; pass --url with a name it holds"
                .to_owned()
        })
    };
    let Some(url) = url else {
        let addr = loopback_for(listen);
        let name = served_name()?;
        let host = format!("{name}:{}", addr.port());
        return Ok(Target { addr, name, host });
    };
    let host = url.authority();
    if let Ok(ip) = url.host.parse::<IpAddr>() {
        let name = if ip.is_loopback() && served.is_some() {
            served_name()?
        } else {
            ip.to_string()
        };
        return Ok(Target {
            addr: SocketAddr::new(ip, url.port),
            name,
            host,
        });
    }
    let addr = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|err| format!("{} did not resolve: {err}", url.host))?
        .next()
        .ok_or_else(|| format!("{} did not resolve to an address", url.host))?;
    Ok(Target {
        addr,
        name: url.host.clone(),
        host,
    })
}

/// The request, built in one zeroed buffer of its final size.
fn renew_request(host: &str, token: &str) -> Zeroizing<Vec<u8>> {
    const END: &[u8] = b"\r\n\r\n";
    let parts: [&[u8]; 6] = [
        b"POST ",
        detent_web::api::system::CERT_RENEW_PATH.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\nAuthorization: Bearer ",
        token.as_bytes(),
    ];
    let len = parts
        .iter()
        .map(|part| part.len())
        .fold(END.len(), usize::saturating_add);
    let mut request = Zeroizing::new(Vec::with_capacity(len));
    for part in parts {
        request.extend_from_slice(part);
    }
    request.extend_from_slice(END);
    request
}

/// What `answer` means.
fn outcome(answer: &Answer) -> Outcome {
    match answer.status {
        202 => Outcome::Requested,
        401 | 403 => Outcome::TokenRefused,
        409 => Outcome::NotAcme,
        _ => Outcome::ServerError(message_id(&answer.body)),
    }
}

/// The `message_id` of an error body, when it looks like a Fluent id.
fn message_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let id = value.get("message_id")?.as_str()?;
    let fluent_id = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    fluent_id.then(|| id.to_owned())
}

/// Prints what the server's answer means.
///
/// # Errors
///
/// Whatever the streams report.
fn report(
    answer: &Answer,
    address: &str,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let outcome = outcome(answer);
    let status = answer.status.to_string();
    if renderer.json {
        let (name, id) = match &outcome {
            Outcome::Requested => ("requested", None),
            Outcome::TokenRefused => ("token_refused", None),
            Outcome::NotAcme => ("not_acme", None),
            Outcome::ServerError(id) => ("server_error", id.as_deref()),
        };
        let text = serde_json::to_string_pretty(&serde_json::json!({
            "outcome": name,
            "status": answer.status,
            "message_id": id,
            "address": address,
        }))
        .map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        match &outcome {
            Outcome::Requested => {
                renderer.line(streams.out, MessageId::new("cli-cert-renew-requested"), &[])?;
            }
            Outcome::TokenRefused => renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-token-refused"),
                &[("status", &status)],
            )?,
            Outcome::NotAcme => renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-not-acme"),
                &[],
            )?,
            Outcome::ServerError(Some(id)) => renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-server-error"),
                &[("status", &status), ("message_id", id)],
            )?,
            Outcome::ServerError(None) => renderer.line(
                streams.notes,
                MessageId::new("cli-cert-renew-server-error-bare"),
                &[("status", &status)],
            )?,
        }
    }
    Ok(if outcome == Outcome::Requested {
        Exit::Ok
    } else {
        Exit::Failed
    })
}

/// The server could not be asked: say where, and why.
///
/// # Errors
///
/// Whatever the streams report.
fn unreachable(
    address: &str,
    reason: &str,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    if renderer.json {
        let text = serde_json::to_string_pretty(&serde_json::json!({
            "outcome": "unreachable",
            "status": null,
            "message_id": null,
            "address": address,
            "reason": reason,
        }))
        .map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.line(
            streams.notes,
            MessageId::new("cli-cert-renew-unreachable"),
            &[("address", address), ("reason", reason)],
        )?;
    }
    Ok(Exit::Failed)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::cli::{RenewArgs, parse_https_url};
    use crate::i18n::Messages;

    type R = Result<(), Box<dyn std::error::Error>>;

    const TOKEN: &str = "SECRET-renew-token-4be17c09d3a2f5e8";

    fn write_mode(path: &Path, text: &[u8], mode: u32) -> R {
        std::fs::write(path, text)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn refused(result: Result<Zeroizing<String>, TokenError>) -> Result<String, String> {
        match result {
            Err(TokenError::Refused { reason, .. }) => Ok(reason),
            Err(TokenError::NoSource) => Err("no source".to_owned()),
            Ok(_) => Err("a token was accepted".to_owned()),
        }
    }

    #[test]
    fn a_private_token_file_is_read_and_trimmed() -> R {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("token");
        write_mode(&path, format!("  {TOKEN}\n").as_bytes(), 0o600)?;
        let token = load_token(Some(&path), Some(OsString::from("from-env")))
            .map_err(|err| format!("{err:?}"))?;
        // The file wins over the environment.
        assert_eq!(token.as_str(), TOKEN);
        Ok(())
    }

    #[test]
    fn unsafe_or_unusable_token_files_are_refused() -> R {
        let dir = tempfile::TempDir::new()?;
        let good = dir.path().join("good");
        write_mode(&good, TOKEN.as_bytes(), 0o600)?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&good, &link)?;
        let shared = dir.path().join("shared");
        write_mode(&shared, TOKEN.as_bytes(), 0o640)?;
        let other = dir.path().join("other");
        write_mode(&other, TOKEN.as_bytes(), 0o604)?;
        let empty = dir.path().join("empty");
        write_mode(&empty, b" \n", 0o600)?;
        let two = dir.path().join("two");
        write_mode(&two, b"one two\n", 0o600)?;
        let binary = dir.path().join("binary");
        write_mode(&binary, b"\xff\xfe", 0o600)?;
        let large = dir.path().join("large");
        write_mode(&large, &vec![b'a'; 5000], 0o600)?;
        let long = dir.path().join("long");
        write_mode(&long, &vec![b'a'; 1025], 0o600)?;
        for (path, why) in [
            (link, "symlink"),
            (shared, "mode 640"),
            (other, "mode 604"),
            (dir.path().join("absent"), "does not exist"),
            (dir.path().to_path_buf(), "not a regular file"),
            (good.join("below"), "Not a directory"),
            (empty, "empty"),
            (two, "not a token"),
            (binary, "not UTF-8"),
            (large, "larger than 4096"),
            (long, "not a token"),
        ] {
            let reason = refused(load_token(Some(&path), None))?;
            assert!(reason.contains(why), "{}: {reason}", path.display());
            assert!(!reason.contains(TOKEN), "{reason}");
        }
        Ok(())
    }

    #[test]
    fn a_token_file_owned_by_another_user_is_refused() -> R {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("token");
        write_mode(&path, TOKEN.as_bytes(), 0o600)?;
        let euid = rustix::process::geteuid().as_raw();
        let reason = read_owned_by(&path, MAX_TOKEN_BYTES, euid.wrapping_add(1))
            .err()
            .ok_or("a file of another owner was read")?;
        assert!(reason.contains("owned by uid"), "{reason}");
        Ok(())
    }

    #[test]
    fn the_environment_is_the_fallback_and_neither_is_a_usage_error() -> R {
        let token = load_token(None, Some(OsString::from(format!("{TOKEN}\n"))))
            .map_err(|err| format!("{err:?}"))?;
        assert_eq!(token.as_str(), TOKEN);
        assert_eq!(load_token(None, None).err(), Some(TokenError::NoSource));
        assert_eq!(
            load_token(None, Some(OsString::new())).err(),
            Some(TokenError::NoSource)
        );
        let reason = refused(load_token(None, Some(OsString::from("a\r\nX-Evil: 1"))))?;
        assert!(reason.contains("not a token"), "{reason}");
        let reason = refused(load_token(
            None,
            Some(std::os::unix::ffi::OsStringExt::from_vec(vec![0xff])),
        ))?;
        assert!(reason.contains("not UTF-8"), "{reason}");
        match load_token(None, Some(OsString::from(" "))) {
            Err(TokenError::Refused { source, .. }) => assert_eq!(source, TOKEN_ENV),
            other => return Err(format!("{other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_wildcard_listen_address_is_reached_on_loopback() -> R {
        for (listen, reached) in [
            ("0.0.0.0:3333", "127.0.0.1:3333"),
            ("[::]:3333", "[::1]:3333"),
            ("192.0.2.7:3333", "192.0.2.7:3333"),
            ("[2001:db8::1]:1", "[2001:db8::1]:1"),
        ] {
            assert_eq!(loopback_for(listen.parse()?), reached.parse()?, "{listen}");
        }
        Ok(())
    }

    fn served_cert(names: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = rcgen::KeyPair::generate()?;
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        Ok(rcgen::CertificateParams::new(names)?
            .self_signed(&key)?
            .der()
            .to_vec())
    }

    #[test]
    fn the_target_follows_listen_or_url_and_names_a_san() -> R {
        let der = served_cert(&["box.example", "localhost", "127.0.0.1"])?;
        let listen: SocketAddr = "0.0.0.0:3333".parse()?;
        let target = resolve(None, listen, Some(&der))?;
        assert_eq!(
            target,
            Target {
                addr: "127.0.0.1:3333".parse()?,
                name: "box.example".to_owned(),
                host: "box.example:3333".to_owned(),
            }
        );

        let url = parse_https_url("https://[::1]:4444")?;
        let target = resolve(Some(&url), listen, Some(&der))?;
        assert_eq!(target.addr, "[::1]:4444".parse()?);
        assert_eq!(
            (target.name.as_str(), target.host.as_str()),
            ("box.example", "[::1]:4444")
        );
        // With a CA anchor there is no served certificate to name.
        let target = resolve(Some(&url), listen, None)?;
        assert_eq!(target.name, "::1");

        let url = parse_https_url("https://192.0.2.7:5555")?;
        let target = resolve(Some(&url), listen, Some(&der))?;
        assert_eq!(
            (target.addr, target.name.as_str()),
            ("192.0.2.7:5555".parse()?, "192.0.2.7")
        );

        let url = parse_https_url("https://localhost:6666")?;
        let target = resolve(Some(&url), listen, Some(&der))?;
        assert!(target.addr.ip().is_loopback(), "{target:?}");
        assert_eq!(
            (target.name.as_str(), target.addr.port()),
            ("localhost", 6666)
        );

        let url = parse_https_url("https://no-such-host.invalid")?;
        let reason = resolve(Some(&url), listen, Some(&der))
            .err()
            .ok_or("an .invalid host resolved")?;
        assert!(reason.contains("no-such-host.invalid"), "{reason}");

        let ip_only = served_cert(&["127.0.0.1"])?;
        let reason = resolve(None, listen, Some(&ip_only))
            .err()
            .ok_or("a certificate with no DNS name was accepted")?;
        assert!(reason.contains("names no DNS host"), "{reason}");
        Ok(())
    }

    #[test]
    fn the_request_carries_the_token_only_in_its_header() {
        let request = renew_request("box.example:3333", TOKEN);
        let text = String::from_utf8_lossy(&request);
        assert!(
            text.starts_with(
                "POST /api/v1/system/cert/renew HTTP/1.1\r\nHost: box.example:3333\r\n"
            )
        );
        assert!(text.contains(&format!("\r\nAuthorization: Bearer {TOKEN}\r\n")));
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(text.matches(TOKEN).count(), 1);
        // Built at its final size: no reallocation left a copy behind.
        assert_eq!(request.len(), request.capacity());
    }

    fn answer(status: u16, body: &str) -> Answer {
        Answer {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn each_status_maps_to_its_outcome() {
        let error = |id: &str| format!("{{\"code\":\"x\",\"message_id\":\"{id}\"}}");
        for (status, body, expected) in [
            (202, "{\"requested\":true}".to_owned(), Outcome::Requested),
            (
                401,
                error("web-auth-invalid-credentials"),
                Outcome::TokenRefused,
            ),
            (403, error("web-denied-scope"), Outcome::TokenRefused),
            (409, error("web-cert-renew-not-acme"), Outcome::NotAcme),
            (
                503,
                error("web-cert-renew-unavailable"),
                Outcome::ServerError(Some("web-cert-renew-unavailable".to_owned())),
            ),
            (500, String::new(), Outcome::ServerError(None)),
            (200, "{}".to_owned(), Outcome::ServerError(None)),
            (418, error("Not An Id\u{1b}[2J"), Outcome::ServerError(None)),
            (418, error(&"a".repeat(65)), Outcome::ServerError(None)),
            (418, error(""), Outcome::ServerError(None)),
            (
                418,
                "{\"message_id\":7}".to_owned(),
                Outcome::ServerError(None),
            ),
        ] {
            assert_eq!(outcome(&answer(status, &body)), expected, "{status} {body}");
        }
    }

    /// The operation layer's error for each answer: one id per outcome, and
    /// text that names the address, the status and the server's own id.
    #[cfg(feature = "mcp")]
    #[test]
    fn each_answer_maps_to_an_ops_error_with_its_own_id() -> R {
        let error = |id: &str| format!("{{\"code\":\"x\",\"message_id\":\"{id}\"}}");
        assert!(accepted(&answer(202, "{\"requested\":true}"), "127.0.0.1:3333").is_ok());
        for (status, body, id, text) in [
            (
                401,
                error("web-auth-invalid-credentials"),
                "cli-cert-renew-token-refused",
                "refused the token (HTTP 401)",
            ),
            (
                403,
                error("web-denied-scope"),
                "cli-cert-renew-token-refused",
                "refused the token (HTTP 403)",
            ),
            (
                409,
                error("web-cert-renew-not-acme"),
                "cli-cert-renew-not-acme",
                "runs no ACME process",
            ),
            (
                503,
                error("web-cert-renew-unavailable"),
                "cli-cert-renew-server-error",
                "answered HTTP 503: web-cert-renew-unavailable",
            ),
            (
                500,
                String::new(),
                "cli-cert-renew-server-error-bare",
                "answered HTTP 500",
            ),
        ] {
            match accepted(&answer(status, &body), "127.0.0.1:3333") {
                Err(OpsError::Cert { id: got, reason }) => {
                    assert_eq!(got.as_str(), id, "{status}");
                    assert!(reason.contains("127.0.0.1:3333"), "{reason}");
                    assert!(reason.contains(text), "{reason}");
                }
                other => return Err(format!("{status}: {other:?}").into()),
            }
        }
        Ok(())
    }

    /// Every way the server is not asked keeps the id the CLI prints for it.
    #[cfg(feature = "mcp")]
    #[test]
    fn each_failure_to_ask_maps_to_an_ops_error_with_its_own_id() -> R {
        let path = PathBuf::from("/var/lib/detent/certs");
        for (why, id, text) in [
            (
                Unreached::CaUnreadable {
                    path: PathBuf::from("/ca.pem"),
                    reason: "gone".to_owned(),
                },
                "cli-cert-renew-ca-unreadable",
                "/ca.pem could not be read: gone",
            ),
            (
                Unreached::CertMissing { path: path.clone() },
                "cli-cert-missing",
                "no certificate is stored in /var/lib/detent/certs",
            ),
            (
                Unreached::CertUnreadable {
                    path,
                    reason: "denied".to_owned(),
                },
                "cli-cert-unreadable",
                "could not be read: denied",
            ),
            (
                Unreached::Connect {
                    address: "127.0.0.1:1".to_owned(),
                    reason: "refused".to_owned(),
                },
                "cli-cert-renew-unreachable",
                "the server at 127.0.0.1:1: refused",
            ),
        ] {
            let OpsError::Cert { id: got, reason } = into_ops(why) else {
                return Err("not a certificate error".into());
            };
            assert_eq!(got.as_str(), id);
            assert!(reason.contains(text), "{reason}");
        }
        Ok(())
    }

    fn renderer(messages: &Messages, json: bool) -> Renderer<'_> {
        Renderer {
            messages,
            json,
            verbose: true,
        }
    }

    fn reported(
        answer: &Answer,
        json: bool,
    ) -> Result<(Exit, String, String), Box<dyn std::error::Error>> {
        let messages = Messages::new(Some("en-US"));
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = report(
            answer,
            "127.0.0.1:3333",
            &renderer(&messages, json),
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        Ok((exit, String::from_utf8(out)?, String::from_utf8(notes)?))
    }

    #[test]
    fn each_outcome_prints_its_message_and_exit() -> R {
        let error = |id: &str| format!("{{\"message_id\":\"{id}\"}}");
        for (status, body, exit, text, json) in [
            (
                202,
                String::new(),
                Exit::Ok,
                "renewal requested",
                "requested",
            ),
            (
                403,
                error("web-denied-scope"),
                Exit::Failed,
                "needs write scope",
                "token_refused",
            ),
            (
                409,
                error("web-cert-renew-not-acme"),
                Exit::Failed,
                "no ACME process",
                "not_acme",
            ),
            (
                503,
                error("web-cert-renew-unavailable"),
                Exit::Failed,
                "HTTP 503: web-cert-renew-unavailable",
                "server_error",
            ),
            (
                500,
                String::new(),
                Exit::Failed,
                "HTTP 500.",
                "server_error",
            ),
        ] {
            let (got, out, notes) = reported(&answer(status, &body), false)?;
            assert_eq!(got, exit, "{status}");
            assert!(
                format!("{out}{notes}").contains(text),
                "{status}: {out}{notes}"
            );
            if exit == Exit::Ok {
                assert!(notes.is_empty(), "{notes}");
            } else {
                assert!(out.is_empty(), "{out}");
            }

            let (got, out, _) = reported(&answer(status, &body), true)?;
            assert_eq!(got, exit, "{status}");
            let parsed: serde_json::Value = serde_json::from_str(&out)?;
            assert_eq!(
                parsed.pointer("/outcome").and_then(|v| v.as_str()),
                Some(json)
            );
            assert_eq!(
                parsed
                    .pointer("/status")
                    .and_then(serde_json::Value::as_u64),
                Some(u64::from(status))
            );
            assert_eq!(
                parsed.pointer("/address").and_then(|v| v.as_str()),
                Some("127.0.0.1:3333")
            );
        }
        Ok(())
    }

    /// Runs the command against `settings` with `env` as [`TOKEN_ENV`].
    fn run_with(
        args: &RenewArgs,
        dryrun: bool,
        env: Option<&str>,
        settings: &Settings,
        json: bool,
    ) -> Result<(Exit, String, String), Box<dyn std::error::Error>> {
        let messages = Messages::new(Some("en-US"));
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            args,
            dryrun,
            env.map(OsString::from),
            settings,
            &renderer(&messages, json),
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        Ok((exit, String::from_utf8(out)?, String::from_utf8(notes)?))
    }

    fn args(url: Option<&str>, ca_file: Option<&Path>) -> Result<RenewArgs, String> {
        Ok(RenewArgs {
            token_file: None,
            url: url.map(parse_https_url).transpose()?,
            ca_file: ca_file.map(Path::to_path_buf),
        })
    }

    /// A state root whose `detent.toml` listens on a closed loopback port,
    /// with a bootstrap certificate for `box.example` in `certs`.
    fn closed_server(dir: &Path) -> Result<(Settings, SocketAddr), Box<dyn std::error::Error>> {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let cert_dir = dir.join("certs");
        detent_web::tls::store_bootstrap(
            &cert_dir,
            &detent_web::bootstrap_self_signed(&["box.example".to_owned()])?,
        )?;
        std::fs::write(
            dir.join("detent.toml"),
            format!(
                "[listen]\naddr = \"{addr}\"\n[tls]\ncert_dir = {:?}\n",
                cert_dir.display().to_string()
            ),
        )?;
        Ok((
            Settings {
                state_root: dir.to_path_buf(),
                config_path: dir.join("detent.toml"),
            },
            addr,
        ))
    }

    #[test]
    fn no_token_is_a_usage_error_and_a_bad_one_fails() -> R {
        let dir = tempfile::TempDir::new()?;
        let (settings, _) = closed_server(dir.path())?;
        let (exit, out, notes) = run_with(&args(None, None)?, false, None, &settings, false)?;
        assert_eq!(exit, Exit::Usage);
        assert!(out.is_empty(), "{out}");
        assert!(
            notes.contains("--token-file") && notes.contains(TOKEN_ENV),
            "{notes}"
        );
        assert!(notes.contains("detent token create"), "{notes}");

        let (exit, _, notes) = run_with(&args(None, None)?, false, Some("a b"), &settings, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(
            notes.contains(TOKEN_ENV) && notes.contains("not a token"),
            "{notes}"
        );
        Ok(())
    }

    #[test]
    fn the_config_the_certificate_and_the_ca_file_must_be_readable() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("detent.toml"), b"[listen\n")?;
        let settings = Settings {
            state_root: dir.path().to_path_buf(),
            config_path: dir.path().join("detent.toml"),
        };
        let (exit, _, notes) = run_with(&args(None, None)?, false, Some(TOKEN), &settings, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("detent.toml"), "{notes}");

        std::fs::write(
            dir.path().join("detent.toml"),
            format!(
                "[tls]\ncert_dir = {:?}\n",
                dir.path().join("none").display().to_string()
            ),
        )?;
        let (exit, _, notes) = run_with(&args(None, None)?, false, Some(TOKEN), &settings, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("no certificate"), "{notes}");

        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory")?;
        std::fs::write(
            dir.path().join("detent.toml"),
            format!("[tls]\ncert_dir = {:?}\n", blocker.display().to_string()),
        )?;
        let (exit, _, notes) = run_with(&args(None, None)?, false, Some(TOKEN), &settings, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("could not be read"), "{notes}");

        let absent = dir.path().join("absent-ca.pem");
        let (exit, _, notes) = run_with(
            &args(Some("https://127.0.0.1:1"), Some(&absent))?,
            false,
            Some(TOKEN),
            &settings,
            false,
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("absent-ca.pem"), "{notes}");

        let large = dir.path().join("large.pem");
        std::fs::write(&large, vec![b'a'; 1_048_577])?;
        let (exit, _, notes) = run_with(
            &args(Some("https://127.0.0.1:1"), Some(&large))?,
            false,
            Some(TOKEN),
            &settings,
            false,
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("larger than"), "{notes}");
        Ok(())
    }

    #[test]
    fn a_dry_run_names_the_target_and_sends_nothing() -> R {
        let dir = tempfile::TempDir::new()?;
        let (settings, addr) = closed_server(dir.path())?;
        let (exit, out, notes) = run_with(&args(None, None)?, true, Some(TOKEN), &settings, false)?;
        assert_eq!(exit, Exit::Ok, "{notes}");
        assert!(
            out.contains(&addr.to_string()) && out.contains("box.example"),
            "{out}"
        );
        assert!(!format!("{out}{notes}").contains(TOKEN));
        Ok(())
    }

    #[test]
    fn a_closed_port_or_a_nameless_target_names_the_address() -> R {
        let dir = tempfile::TempDir::new()?;
        let (settings, addr) = closed_server(dir.path())?;
        let (exit, out, notes) =
            run_with(&args(None, None)?, false, Some(TOKEN), &settings, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(
            notes.contains(&addr.to_string()) && notes.contains("cannot connect"),
            "{notes}"
        );

        let (exit, out, _) = run_with(&args(None, None)?, false, Some(TOKEN), &settings, true)?;
        assert_eq!(exit, Exit::Failed);
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            parsed.pointer("/outcome").and_then(|v| v.as_str()),
            Some("unreachable")
        );
        assert_eq!(
            parsed.pointer("/address").and_then(|v| v.as_str()),
            Some(addr.to_string().as_str())
        );

        let (exit, _, notes) = run_with(
            &args(Some("https://no-such-host.invalid:3333"), None)?,
            false,
            Some(TOKEN),
            &settings,
            false,
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("no-such-host.invalid:3333"), "{notes}");
        assert!(!notes.contains(TOKEN), "{notes}");
        Ok(())
    }
}
