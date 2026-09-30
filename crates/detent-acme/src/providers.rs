//! Networked dns-01 providers: RFC 2136, Cloudflare, acme-dns, deSEC.
//!
//! All four implement [`DnsProvider`] synchronously and follow the
//! [`HookProvider`](crate::HookProvider) idempotency contract: `present` is a
//! refresh, `delete` tolerates an already-gone record. An order for an apex
//! and its wildcard holds two values at one name (RFC 8555 §8.4), so
//! `present` adds its value beside the others and `delete` removes only its
//! own. A crash between the two can leave a value behind; that is harmless,
//! because an ACME server accepts a challenge when any value at the name
//! matches. Every constructor validates its inputs, so a misconfigured
//! provider cannot be built.
//!
//! Each HTTPS provider drives its API through a small transport seam. The
//! real transport is the crate's TLS 1.3 client (`https.rs`); the unit tests
//! swap in recorded fixtures. RFC 2136 builds the full UPDATE message but
//! refuses to send it unsigned (TSIG needs HMAC). None of the providers
//! sleep: propagation timing stays with the caller.

use std::fmt;

use crate::{AcmeError, DnsProvider, DnsRecord, validate_fqdn, validate_value};

// ---------------------------------------------------------------------------
// Transport seam
// ---------------------------------------------------------------------------

/// One built-but-unsent request to a provider's HTTP API.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HttpRequest {
    pub(crate) method: &'static str,
    pub(crate) url: String,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: String,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, _)| (*name, "[redacted]"))
            .collect::<Vec<_>>();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body", &self.body)
            .finish()
    }
}

/// Sends a built request and returns `(status, body)`.
type HttpTransport = dyn Fn(&HttpRequest) -> Result<(u16, String), AcmeError> + Send + Sync;

/// The real transport: [`crate::https::HttpsTransport`] over the webpki roots.
fn https_transport() -> Result<Box<HttpTransport>, AcmeError> {
    let transport = crate::https::HttpsTransport::new()?;
    Ok(Box::new(move |request: &HttpRequest| {
        transport.send(request)
    }))
}

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4/zones";

/// Publishes dns-01 records through the Cloudflare v4 API.
///
/// [`DnsProvider::present`] lists the zone's TXT records for the challenge
/// name and PUTs the existing record with our value (refresh) or POSTs a new
/// one; [`DnsProvider::delete`] removes the record carrying our value and
/// tolerates its absence. [`DnsProvider::wait_propagated`] re-runs the list
/// call and confirms our value is there.
pub struct CloudflareProvider {
    token: String,
    zone_id: String,
    send: Box<HttpTransport>,
}

impl CloudflareProvider {
    /// Creates a provider for Cloudflare zone `zone_id` using a scoped API
    /// `token`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the token is empty or non-printable, or the
    /// zone id is not a 32-character hex string.
    pub fn new(token: impl Into<String>, zone_id: impl Into<String>) -> Result<Self, AcmeError> {
        let token = token.into();
        let zone_id = zone_id.into();
        validate_value(&token).map_err(|_| {
            AcmeError::Config("cloudflare: token must be non-empty printable ASCII".into())
        })?;
        let hex32 = zone_id.len() == 32 && zone_id.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex32 {
            return Err(AcmeError::Config(format!(
                "cloudflare: zone id must be 32 hex characters, got {zone_id:?}"
            )));
        }
        Ok(Self {
            token,
            zone_id,
            send: https_transport()?,
        })
    }

    #[cfg(test)]
    fn with_transport(mut self, send: Box<HttpTransport>) -> Self {
        self.send = send;
        self
    }

    fn auth(&self) -> [(&'static str, String); 1] {
        [("Authorization", format!("Bearer {}", self.token))]
    }

    /// Lists the zone's TXT records under `record`'s name and returns the id
    /// of the one carrying our value, if any.
    fn find_own(&self, record: &DnsRecord) -> Result<Option<String>, AcmeError> {
        let send = &*self.send;
        let list = HttpRequest {
            method: "GET",
            url: format!(
                "{CLOUDFLARE_API}/{}/dns_records?type=TXT&name={}",
                self.zone_id,
                record.fqdn()
            ),
            headers: self.auth().to_vec(),
            body: String::new(),
        };
        let (status, body) = send(&list)?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Config(format!(
                "cloudflare: record list returned HTTP {status}"
            )));
        }
        cf_txt_id(&body, record.value())
    }
}

impl DnsProvider for CloudflareProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let send = &*self.send;
        let (method, url) = match self.find_own(record)? {
            Some(id) => (
                "PUT",
                format!("{CLOUDFLARE_API}/{}/dns_records/{id}", self.zone_id),
            ),
            None => (
                "POST",
                format!("{CLOUDFLARE_API}/{}/dns_records", self.zone_id),
            ),
        };
        let write = HttpRequest {
            method,
            url,
            headers: self.auth().to_vec(),
            body: serde_json::json!({
                "type": "TXT",
                "name": record.fqdn(),
                "content": record.value(),
                "ttl": 60,
            })
            .to_string(),
        };
        let (status, _) = send(&write)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(AcmeError::Config(format!(
                "cloudflare: record write returned HTTP {status}"
            )))
        }
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let Some(id) = self.find_own(record)? else {
            return Ok(()); // already gone is the success delete promises
        };
        let send = &*self.send;
        let remove = HttpRequest {
            method: "DELETE",
            url: format!("{CLOUDFLARE_API}/{}/dns_records/{id}", self.zone_id),
            headers: self.auth().to_vec(),
            body: String::new(),
        };
        let (status, _) = send(&remove)?;
        if (200..300).contains(&status) || status == 404 {
            Ok(())
        } else {
            Err(AcmeError::Config(format!(
                "cloudflare: record delete returned HTTP {status}"
            )))
        }
    }

    fn wait_propagated(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        match self.find_own(record)? {
            Some(_) => Ok(()),
            None => Err(AcmeError::NotPropagated(record.fqdn().to_owned())),
        }
    }
}

/// Finds the id of the record in a Cloudflare list response whose content is
/// `value`.
fn cf_txt_id(body: &str, value: &str) -> Result<Option<String>, AcmeError> {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AcmeError::Config(format!("cloudflare: unreadable list response: {e}")))?;
    let Some(records) = parsed.get("result").and_then(serde_json::Value::as_array) else {
        return Err(AcmeError::Config(
            "cloudflare: list response has no result array".into(),
        ));
    };
    Ok(records
        .iter()
        .find(|r| r.get("content").and_then(serde_json::Value::as_str) == Some(value))
        .and_then(|r| r.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

impl fmt::Debug for CloudflareProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareProvider")
            .field("zone_id", &self.zone_id)
            .field("token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// acme-dns
// ---------------------------------------------------------------------------

/// Publishes dns-01 records through an acme-dns server.
///
/// An acme-dns registration returns a subdomain as its `username`; updating
/// the TXT for that subdomain is a POST to `<server>/update` authenticated
/// with the matching password. [`DnsProvider::delete`] posts an empty value —
/// acme-dns has no withdraw API, and an empty TXT is the closest withdraw it
/// offers. The server is authoritative the moment the update returns, so
/// `wait_propagated` keeps the instant default.
pub struct AcmeDnsProvider {
    server: String,
    username: String,
    password: String,
    send: Box<HttpTransport>,
}

impl AcmeDnsProvider {
    /// Creates a provider for the acme-dns server at `server` (`username` is
    /// the subdomain the server handed out at registration).
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the server is not an HTTPS URL or the
    /// credentials are empty or non-printable.
    pub fn new(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, AcmeError> {
        let server = server.into();
        let username = username.into();
        let password = password.into();
        let server = server.trim_end_matches('/').to_owned();
        if !server.starts_with("https://") {
            return Err(AcmeError::Config(format!(
                "acme-dns: server must be an https:// URL, got {server:?}"
            )));
        }
        validate_value(&username).map_err(|_| {
            AcmeError::Config("acme-dns: username must be non-empty printable ASCII".into())
        })?;
        validate_value(&password).map_err(|_| {
            AcmeError::Config("acme-dns: password must be non-empty printable ASCII".into())
        })?;
        Ok(Self {
            server,
            username,
            password,
            send: https_transport()?,
        })
    }

    #[cfg(test)]
    fn with_transport(mut self, send: Box<HttpTransport>) -> Self {
        self.send = send;
        self
    }

    fn update_request(&self, txt: &str) -> HttpRequest {
        HttpRequest {
            method: "POST",
            url: format!("{}/update", self.server),
            headers: vec![
                ("X-API-User", self.username.clone()),
                ("X-API-Key", self.password.clone()),
            ],
            body: serde_json::json!({"subdomain": self.username, "txt": txt}).to_string(),
        }
    }

    fn post_update(&self, txt: &str) -> Result<(), AcmeError> {
        let send = &*self.send;
        let (status, _) = send(&self.update_request(txt))?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(AcmeError::Config(format!(
                "acme-dns: update returned HTTP {status}"
            )))
        }
    }
}

impl DnsProvider for AcmeDnsProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        // Re-posting the same TXT is the refresh; acme-dns overwrites.
        self.post_update(record.value())
    }

    fn delete(&self, _record: &DnsRecord) -> Result<(), AcmeError> {
        // No withdraw API: post the empty TXT.
        self.post_update("")
    }
}

impl fmt::Debug for AcmeDnsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeDnsProvider")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// deSEC
// ---------------------------------------------------------------------------

const DESEC_API: &str = "https://desec.io/api/v1/domains";

/// Publishes dns-01 records through the deSEC.io API.
///
/// A `PUT` replaces the `RRset` wholesale, so both calls first `GET` the
/// `RRset` and write back the whole set. [`DnsProvider::present`] `PUT`s the
/// set plus our value (a value already there is the refresh).
/// [`DnsProvider::delete`] `PUT`s the set minus our value, and `DELETE`s the
/// `RRset` only when nothing else is left in it; an absent value or `RRset`
/// is success. [`DnsProvider::wait_propagated`] reads the `RRset` back and
/// confirms our value is in it.
pub struct DeSecProvider {
    token: String,
    domain: String,
    send: Box<HttpTransport>,
}

impl DeSecProvider {
    /// Creates a provider for the deSEC zone `domain` using an API `token`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the token is empty or non-printable or the
    /// domain is not a valid DNS name.
    pub fn new(token: impl Into<String>, domain: impl Into<String>) -> Result<Self, AcmeError> {
        let token = token.into();
        let domain = domain.into();
        validate_value(&token).map_err(|_| {
            AcmeError::Config("deSEC: token must be non-empty printable ASCII".into())
        })?;
        validate_fqdn(&domain).map_err(|_| {
            AcmeError::Config(format!(
                "deSEC: domain must be a valid DNS name, got {domain:?}"
            ))
        })?;
        Ok(Self {
            token,
            domain,
            send: https_transport()?,
        })
    }

    #[cfg(test)]
    fn with_transport(mut self, send: Box<HttpTransport>) -> Self {
        self.send = send;
        self
    }

    fn auth(&self) -> [(&'static str, String); 1] {
        [("Authorization", format!("Token {}", self.token))]
    }

    /// The deSEC subname for `record`: the challenge name relative to the
    /// zone, `@` at the zone apex itself.
    fn subname<'a>(&'a self, record: &'a DnsRecord) -> Result<&'a str, AcmeError> {
        let fqdn = record.fqdn();
        if fqdn == self.domain {
            return Ok("@");
        }
        fqdn.strip_suffix(&format!(".{}", self.domain))
            .ok_or_else(|| {
                AcmeError::Config(format!(
                    "deSEC: record {fqdn:?} is outside zone {:?}",
                    self.domain
                ))
            })
    }

    fn rrset_url(&self, subname: &str) -> String {
        format!("{DESEC_API}/{}/rrsets/{subname}/TXT/", self.domain)
    }

    /// The values now in the `RRset` at `subname`, as deSEC returns them
    /// (quoted); none when the `RRset` does not exist.
    fn read_records(&self, subname: &str) -> Result<Vec<String>, AcmeError> {
        let send = &*self.send;
        let get = HttpRequest {
            method: "GET",
            url: self.rrset_url(subname),
            headers: self.auth().to_vec(),
            body: String::new(),
        };
        let (status, body) = send(&get)?;
        match status {
            404 => Ok(Vec::new()),
            200..=299 => rrset_records(&body),
            _ => Err(AcmeError::Config(format!(
                "deSEC: RRset GET returned HTTP {status}"
            ))),
        }
    }

    /// Replaces the `RRset` at `subname` with `records`, which is not empty.
    fn put_records(&self, subname: &str, records: &[String]) -> Result<(), AcmeError> {
        let send = &*self.send;
        let put = HttpRequest {
            method: "PUT",
            url: self.rrset_url(subname),
            headers: self.auth().to_vec(),
            body: serde_json::json!({
                "subname": subname,
                "type": "TXT",
                "records": records,
                "ttl": 3600,
            })
            .to_string(),
        };
        let (status, _) = send(&put)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(AcmeError::Config(format!(
                "deSEC: RRset PUT returned HTTP {status}"
            )))
        }
    }
}

impl DnsProvider for DeSecProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let subname = self.subname(record)?;
        let mut records = self.read_records(subname)?;
        if !records.iter().any(|r| is_value(r, record.value())) {
            records.push(format!("\"{}\"", record.value()));
        }
        self.put_records(subname, &records)
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let subname = self.subname(record)?;
        let records = self.read_records(subname)?;
        let kept: Vec<String> = records
            .iter()
            .filter(|r| !is_value(r, record.value()))
            .cloned()
            .collect();
        if kept.len() == records.len() {
            return Ok(()); // already gone is the success delete promises
        }
        if !kept.is_empty() {
            return self.put_records(subname, &kept);
        }
        let send = &*self.send;
        let remove = HttpRequest {
            method: "DELETE",
            url: self.rrset_url(subname),
            headers: self.auth().to_vec(),
            body: String::new(),
        };
        let (status, _) = send(&remove)?;
        if (200..300).contains(&status) || status == 404 {
            Ok(())
        } else {
            Err(AcmeError::Config(format!(
                "deSEC: RRset DELETE returned HTTP {status}"
            )))
        }
    }

    fn wait_propagated(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let subname = self.subname(record)?;
        let send = &*self.send;
        let get = HttpRequest {
            method: "GET",
            url: format!(
                "{DESEC_API}/{}/rrsets/?subname={subname}&type=TXT",
                self.domain
            ),
            headers: self.auth().to_vec(),
            body: String::new(),
        };
        let (status, body) = send(&get)?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Config(format!(
                "deSEC: RRset GET returned HTTP {status}"
            )));
        }
        if rrset_contains(&body, record.value())? {
            Ok(())
        } else {
            Err(AcmeError::NotPropagated(record.fqdn().to_owned()))
        }
    }
}

/// Whether the deSEC record `entry` (quoted or not) is `value`.
fn is_value(entry: &str, value: &str) -> bool {
    entry == value || entry.strip_prefix('"').and_then(|e| e.strip_suffix('"')) == Some(value)
}

/// The record values in a deSEC single-`RRset` response.
fn rrset_records(body: &str) -> Result<Vec<String>, AcmeError> {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AcmeError::Config(format!("deSEC: unreadable RRset response: {e}")))?;
    let unreadable = || AcmeError::Config("deSEC: RRset response has no records array".into());
    parsed
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(unreadable)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(unreadable))
        .collect()
}

/// Whether any `RRset` in a deSEC records response carries `value`.
fn rrset_contains(body: &str, value: &str) -> Result<bool, AcmeError> {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AcmeError::Config(format!("deSEC: unreadable RRset response: {e}")))?;
    let quoted = format!("\"{value}\"");
    Ok(parsed.as_array().is_some_and(|rrsets| {
        rrsets.iter().any(|rr| {
            rr.get("records")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|vals| {
                    vals.iter()
                        .any(|v| v.as_str() == Some(value) || v.as_str() == Some(&quoted))
                })
        })
    }))
}

impl fmt::Debug for DeSecProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeSecProvider")
            .field("domain", &self.domain)
            .field("token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// RFC 2136
// ---------------------------------------------------------------------------

/// Sends one DNS message to a server and returns its answer.
type DnsExchange = dyn Fn(&str, &[u8]) -> Result<Vec<u8>, AcmeError> + Send + Sync;

/// Publishes dns-01 records with RFC 2136 dynamic updates to a zone's primary
/// server.
///
/// [`DnsProvider::present`] builds one UPDATE that adds one TXT record
/// (RFC 2136 §2.5.1); [`DnsProvider::delete`] builds one UPDATE that removes
/// that one record (class NONE, §2.5.4), not the whole set. Other values at
/// the name stay. Both are idempotent by construction: adding a record that
/// exists changes nothing, and removing a record that is not there succeeds
/// (§3.4.2).
///
/// Every UPDATE is TSIG-signed (RFC 8945) and sent over TCP; the server's
/// answer must carry a valid TSIG from the same key and RCODE NOERROR (see
/// `tsig.rs`). The primary server is authoritative the moment it answers, so
/// `wait_propagated` keeps the instant default.
pub struct Rfc2136Provider {
    server: String,
    zone: String,
    key: crate::tsig::Key,
    exchange: Box<DnsExchange>,
}

impl Rfc2136Provider {
    /// Creates a provider updating `server` (`host:port`) for `zone`,
    /// authenticated with the TSIG key `key_name`/`key_value` (base64 secret).
    ///
    /// `zone` is the name of the zone holding the SOA — the one this key is
    /// authorized to update — and must be configured, not guessed. RFC 2136
    /// §2.3 requires the Zone section to name that zone exactly, and a
    /// challenge name gives no way to find it: `_acme-challenge.a.b.example`
    /// may live in `a.b.example`, `b.example` or `example`, and only an SOA
    /// lookup could tell which. A wrong guess earns NOTAUTH.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the server is empty, the zone or key name is
    /// not a valid DNS name, the key value is not non-empty base64, or the
    /// algorithm is not one of `hmac-sha224`, `hmac-sha256`, `hmac-sha384`,
    /// `hmac-sha512`.
    pub fn new(
        server: impl Into<String>,
        zone: impl Into<String>,
        key_name: impl Into<String>,
        key_value: impl Into<String>,
        tsig_algorithm: impl Into<String>,
    ) -> Result<Self, AcmeError> {
        let server = server.into();
        let zone = zone.into();
        let key_name = key_name.into();
        let key_value = key_value.into();
        let tsig_algorithm = tsig_algorithm.into();
        if server.is_empty() {
            return Err(AcmeError::Config(
                "rfc2136: server must not be empty".into(),
            ));
        }
        validate_fqdn(&zone).map_err(|_| {
            AcmeError::Config(format!(
                "rfc2136: zone must be a valid DNS name, got {zone:?}"
            ))
        })?;
        validate_fqdn(&key_name).map_err(|_| {
            AcmeError::Config(format!(
                "rfc2136: key name must be a valid DNS name, got {key_name:?}"
            ))
        })?;
        let algorithm = crate::tsig::Algorithm::parse(&tsig_algorithm).ok_or_else(|| {
            AcmeError::Config(format!(
                "rfc2136: unsupported TSIG algorithm {tsig_algorithm:?}; expected one of \
                 {} (hmac-md5 and hmac-sha1 are refused)",
                crate::tsig::Algorithm::NAMES.join(", ")
            ))
        })?;
        let key = crate::tsig::Key::new(&key_name, algorithm, &key_value)?;
        Ok(Self {
            server,
            zone,
            key,
            exchange: Box::new(crate::tsig::exchange_tcp),
        })
    }

    #[cfg(test)]
    fn with_exchange(mut self, exchange: Box<DnsExchange>) -> Self {
        self.exchange = exchange;
        self
    }

    /// Builds the UPDATE that applies `change` to `record`'s name.
    fn update(&self, record: &DnsRecord, change: Change<'_>) -> Result<Vec<u8>, AcmeError> {
        let zone = self.zone_for(record)?;
        update_message(zone, record.fqdn(), change)
    }

    /// Gives `message` a random id, signs it, sends it, and checks the
    /// server's signed answer.
    fn send_signed(&self, message: &[u8]) -> Result<(), AcmeError> {
        let id = crate::tsig::random_id()?;
        let mut message = message.to_vec();
        if let Some(header_id) = message.get_mut(..2) {
            header_id.copy_from_slice(&id.to_be_bytes());
        }
        let (signed, mac) = self.key.sign(&message, crate::tsig::now())?;
        let answer = (self.exchange)(&self.server, &signed)?;
        self.key
            .verify_response(&answer, id, &mac, crate::tsig::now())
    }
}

impl DnsProvider for Rfc2136Provider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.send_signed(&self.update(record, Change::Add(record.value()))?)
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.send_signed(&self.update(record, Change::Remove(record.value()))?)
    }
}

impl Rfc2136Provider {
    /// The configured zone, once `record` is confirmed to live inside it.
    ///
    /// An UPDATE whose Zone section does not cover the name it changes is
    /// refused by the server (RFC 2136 §3.1), so it is refused here first,
    /// with an error that names both halves.
    fn zone_for(&self, record: &DnsRecord) -> Result<&str, AcmeError> {
        let fqdn = record.fqdn();
        if fqdn == self.zone || fqdn.ends_with(&format!(".{}", self.zone)) {
            Ok(&self.zone)
        } else {
            Err(AcmeError::Config(format!(
                "rfc2136: record {fqdn:?} is outside zone {:?}",
                self.zone
            )))
        }
    }
}

use crate::tsig::encode_name;

/// TXT rdata: one or more ≤255-byte length-prefixed character-strings.
// Capacity math on bounded small ints; `saturating_*` unnecessary here.
#[allow(clippy::arithmetic_side_effects)]
fn txt_rdata(value: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(value.len() + value.len() / 255 + 1);
    for chunk in value.as_bytes().chunks(255) {
        // `chunks(255)` guarantees `len <= 255`; `u8` holds it exactly.
        #[allow(clippy::cast_possible_truncation)]
        rdata.push(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }
    rdata
}

/// One change to the TXT set at a name.
#[derive(Clone, Copy)]
enum Change<'a> {
    /// Add this value (class IN, RFC 2136 §2.5.1).
    Add(&'a str),
    /// Remove this one value (class NONE, RFC 2136 §2.5.4).
    Remove(&'a str),
}

/// Builds an RFC 2136 UPDATE message: the SOA-named `zone` in the zone
/// section and one update record. An add carries the TXT with a 60s TTL; a
/// remove carries the same rdata in class NONE with TTL 0, so it deletes that
/// one record and no other. The TSIG additional record would be appended by
/// the signer (`tsig.rs`), not here.
fn update_message(zone: &str, name: &str, change: Change<'_>) -> Result<Vec<u8>, AcmeError> {
    const HEADER: [u8; 4] = [0, 0, 0x28, 0x00]; // id 0, opcode 5 (UPDATE)
    const TYPE_SOA: [u8; 2] = [0, 6];
    const TYPE_TXT: [u8; 2] = [0, 16];
    const CLASS_IN: [u8; 2] = [0, 1];
    const CLASS_NONE: [u8; 2] = [0, 254];
    const TTL_60: [u8; 4] = [0, 0, 0, 60];
    const TTL_0: [u8; 4] = [0, 0, 0, 0];

    let (value, class, ttl) = match change {
        Change::Add(value) => (value, CLASS_IN, TTL_60),
        Change::Remove(value) => (value, CLASS_NONE, TTL_0),
    };
    let rdata = txt_rdata(value);
    let rdlen = u16::try_from(rdata.len())
        .map_err(|_| AcmeError::Config("rfc2136: TXT rdata exceeds 64 KiB".into()))?;

    let mut msg = Vec::with_capacity(160);
    msg.extend_from_slice(&HEADER);
    // Counts: zone 1, prerequisite 0, update 1, additional 0.
    msg.extend_from_slice(&[0, 1]);
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&[0, 1]);
    msg.extend_from_slice(&[0, 0]);

    encode_name(zone, &mut msg)?;
    msg.extend_from_slice(&TYPE_SOA);
    msg.extend_from_slice(&CLASS_IN);

    encode_name(name, &mut msg)?;
    msg.extend_from_slice(&TYPE_TXT);
    msg.extend_from_slice(&class);
    msg.extend_from_slice(&ttl);
    msg.extend_from_slice(&rdlen.to_be_bytes());
    msg.extend_from_slice(&rdata);
    Ok(msg)
}

impl fmt::Debug for Rfc2136Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rfc2136Provider")
            .field("server", &self.server)
            .field("zone", &self.zone)
            .field("key_name", &self.key.name())
            .field("key_value", &"[redacted]")
            .field("tsig_algorithm", &self.key.algorithm().name())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Fuzz entry points
// ---------------------------------------------------------------------------

/// Feeds arbitrary strings through the DNS provider response parsers, the
/// RFC 2136 message builder and the TSIG answer parser.
///
/// List/RRset bodies arrive from provider APIs over the network, so malformed
/// JSON must map to `Err`, never to a panic; the message builder must likewise
/// refuse oversized labels with `Err`. Only compiled with the `fuzzing`
/// feature for `cargo-fuzz`.
#[cfg(feature = "fuzzing")]
pub fn fuzz_provider_response(body: &str, value: &str) {
    let _ = cf_txt_id(body, value);
    let _ = rrset_contains(body, value);
    let _ = rrset_records(body);
    let _ = update_message(body, value, Change::Add(value));
    let _ = update_message(body, value, Change::Remove(value));
    // The RFC 2136 server answer is parsed before its MAC is checked.
    if let Ok(key) = crate::tsig::Key::new("k.example.com", crate::tsig::Algorithm::Sha256, "a2V5")
    {
        let _ = key.verify_response(body.as_bytes(), 0, value.as_bytes(), 0);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A TSIG secret: base64 of `s3cr3t-key`.
    const TSIG_B64: &str = "czNjcjN0LWtleQ==";

    fn record() -> Result<DnsRecord, AcmeError> {
        DnsRecord::new("_acme-challenge.example.com", "digest-value-42")
    }

    /// Recorded fixtures: per-call `(status, body)` responses plus a log of
    /// every request the provider built.
    struct Scripted {
        requests: Vec<HttpRequest>,
        responses: std::vec::IntoIter<Result<(u16, String), AcmeError>>,
    }

    fn scripted(responses: &[(u16, &str)]) -> (Box<HttpTransport>, Arc<Mutex<Scripted>>) {
        let script = Arc::new(Mutex::new(Scripted {
            requests: Vec::new(),
            responses: responses
                .iter()
                .map(|(status, body)| Ok((*status, (*body).to_owned())))
                .collect::<Vec<_>>()
                .into_iter(),
        }));
        let send: Box<HttpTransport> = {
            let script = Arc::clone(&script);
            Box::new(move |request: &HttpRequest| {
                let mut script = script
                    .lock()
                    .map_err(|p| AcmeError::Io(io::Error::other(p.to_string())))?;
                script.requests.push(request.clone());
                script
                    .responses
                    .next()
                    .unwrap_or_else(|| Err(AcmeError::Config("test fixture exhausted".into())))
            })
        };
        (send, script)
    }

    fn lock(
        script: &Mutex<Scripted>,
    ) -> Result<std::sync::MutexGuard<'_, Scripted>, Box<dyn std::error::Error>> {
        script
            .lock()
            .map_err(|p| AcmeError::Io(io::Error::other(p.to_string())).into())
    }

    /// The most recent recorded request.
    fn last(script: &Mutex<Scripted>) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        lock(script)?
            .requests
            .last()
            .cloned()
            .ok_or_else(|| "no request recorded".into())
    }

    fn has(haystack: &[u8], needle: &[u8]) -> bool {
        // Test inputs guarantee needle.len() ≤ haystack.len().
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn providers_are_object_safe() -> R {
        let boxed: (
            Box<dyn DnsProvider>,
            Box<dyn DnsProvider>,
            Box<dyn DnsProvider>,
            Box<dyn DnsProvider>,
        ) = (
            Box::new(CloudflareProvider::new("tok", "a".repeat(32))?),
            Box::new(AcmeDnsProvider::new("https://dns.example", "user", "pass")?),
            Box::new(DeSecProvider::new("tok", "example.com")?),
            Box::new(Rfc2136Provider::new(
                "ns1.example.com:53",
                "example.com",
                "k.example.com",
                TSIG_B64,
                "hmac-sha256",
            )?),
        );
        drop(boxed);
        Ok(())
    }

    #[test]
    fn cloudflare_present_creates_then_refreshes() -> R {
        let record = record()?;
        let (send, script) = scripted(&[
            (200, r#"{"result":[],"success":true}"#), // list: no record yet
            (200, "{}"),                              // POST create ok
            (
                200,
                r#"{"result":[{"id":"cf-1","content":"digest-value-42"}],"success":true}"#,
            ), // list: ours exists
            (200, "{}"),                              // PUT refresh ok
        ]);
        let cf = CloudflareProvider::new("cf-token-123", "a".repeat(32))?.with_transport(send);
        cf.present(&record)?;
        let first = lock(&script)?
            .requests
            .first()
            .cloned()
            .ok_or("no request recorded")?;
        assert_eq!(first.method, "GET");
        assert!(
            first
                .url
                .starts_with("https://api.cloudflare.com/client/v4/zones/")
        );
        assert!(
            first
                .url
                .contains("type=TXT&name=_acme-challenge.example.com")
        );
        assert_eq!(
            first.headers.first().map(|(h, v)| (*h, v.as_str())),
            Some(("Authorization", "Bearer cf-token-123"))
        );
        let req = last(&script)?;
        assert_eq!(req.method, "POST");

        let req = {
            cf.present(&record)?;
            last(&script)?
        };
        assert_eq!(req.method, "PUT"); // re-present is a refresh, not a duplicate
        assert!(req.url.ends_with("/dns_records/cf-1"));
        let body: serde_json::Value = serde_json::from_str(&req.body)?;
        assert_eq!(
            body.get("content").and_then(serde_json::Value::as_str),
            Some("digest-value-42")
        );
        Ok(())
    }

    #[test]
    fn cloudflare_delete_tolerates_a_missing_record() -> R {
        let (send, script) = scripted(&[(200, r#"{"result":[],"success":true}"#)]);
        let cf = CloudflareProvider::new("cf-token-123", "a".repeat(32))?.with_transport(send);
        cf.delete(&record()?)?;
        // Only the list ran; no DELETE was issued for a record that is gone.
        assert_eq!(lock(&script)?.requests.len(), 1);
        Ok(())
    }

    #[test]
    fn cloudflare_wait_propagated_confirms_or_defers() -> R {
        let (send, _) = scripted(&[(
            200,
            r#"{"result":[{"id":"cf-1","content":"digest-value-42"}]}"#,
        )]);
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?.with_transport(send);
        cf.wait_propagated(&record()?)?;

        let (send, _) = scripted(&[(200, r#"{"result":[]}"#)]);
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?.with_transport(send);
        assert!(matches!(
            cf.wait_propagated(&record()?),
            Err(AcmeError::NotPropagated(_))
        ));
        Ok(())
    }

    #[test]
    fn acme_dns_posts_updates_to_the_registered_subdomain() -> R {
        let record = record()?;
        let (send, script) = scripted(&[(200, "{}"), (200, "{}")]);
        let ad = AcmeDnsProvider::new(
            "https://auth.acme-dns.io/",
            "subdom-user",
            "s3cr3t-password",
        )?
        .with_transport(send);
        ad.present(&record)?;
        let req = last(&script)?;
        assert_eq!(req.url, "https://auth.acme-dns.io/update");
        let body: serde_json::Value = serde_json::from_str(&req.body)?;
        assert_eq!(
            body.get("subdomain").and_then(serde_json::Value::as_str),
            Some("subdom-user")
        );
        assert_eq!(
            body.get("txt").and_then(serde_json::Value::as_str),
            Some("digest-value-42")
        );

        ad.delete(&record)?;
        let req = last(&script)?;
        // No withdraw API: delete posts the empty TXT.
        let body: serde_json::Value = serde_json::from_str(&req.body)?;
        assert_eq!(
            body.get("txt").and_then(serde_json::Value::as_str),
            Some("")
        );
        assert!(
            req.headers
                .iter()
                .any(|(h, v)| *h == "X-API-Key" && v == "s3cr3t-password")
        );
        Ok(())
    }

    #[test]
    fn desec_derives_subnames_and_puts_the_union() -> R {
        let record = DnsRecord::new("_acme-challenge.sub.example.com", "digest-value-42")?;
        let (send, script) = scripted(&[
            (404, r#"{"detail":"Not found."}"#), // GET: no RRset yet
            (201, "{}"),                         // PUT
        ]);
        let ds = DeSecProvider::new("s3cr3t-token", "example.com")?.with_transport(send);
        ds.present(&record)?;
        assert_eq!(lock(&script)?.requests.len(), 2);
        let req = last(&script)?;
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.url,
            "https://desec.io/api/v1/domains/example.com/rrsets/_acme-challenge.sub/TXT/"
        );
        assert!(
            req.headers
                .iter()
                .any(|(h, v)| *h == "Authorization" && v == "Token s3cr3t-token")
        );
        let body: serde_json::Value = serde_json::from_str(&req.body)?;
        assert_eq!(
            body.get("records")
                .and_then(serde_json::Value::as_array)
                .and_then(|records| records.first())
                .and_then(serde_json::Value::as_str),
            Some("\"digest-value-42\"")
        );
        assert_eq!(
            body.get("ttl").and_then(serde_json::Value::as_u64),
            Some(3600)
        );
        Ok(())
    }

    #[test]
    fn desec_delete_tolerates_an_already_gone_rrset() -> R {
        // No RRset at all: only the read ran, nothing is written or deleted.
        let (send, script) = scripted(&[(404, r#"{"detail":"Not found."}"#)]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        ds.delete(&record()?)?;
        assert_eq!(lock(&script)?.requests.len(), 1);
        assert_eq!(last(&script)?.method, "GET");

        // The RRset vanishes between the read and the DELETE.
        let (send, script) = scripted(&[
            (200, r#"{"records":["\"digest-value-42\""]}"#),
            (404, r#"{"detail":"Not found."}"#),
        ]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        ds.delete(&record()?)?;
        assert_eq!(last(&script)?.method, "DELETE");
        Ok(())
    }

    #[test]
    fn desec_wait_propagated_confirms_or_defers() -> R {
        let (send, _) = scripted(&[(
            200,
            r#"[{"subname":"_acme-challenge","type":"TXT","records":["\"digest-value-42\""],"ttl":3600}]"#,
        )]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        ds.wait_propagated(&record()?)?;

        let (send, _) = scripted(&[(200, "[]")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.wait_propagated(&record()?),
            Err(AcmeError::NotPropagated(_))
        ));
        Ok(())
    }

    #[test]
    fn desec_rejects_a_record_outside_its_zone() -> R {
        let other = DnsRecord::new("_acme-challenge.other.org", "digest-value-42")?;
        let ds = DeSecProvider::new("tok", "example.com")?;
        assert!(matches!(ds.present(&other), Err(AcmeError::Config(_))));
        Ok(())
    }

    #[test]
    fn rfc2136_builds_the_update_wire_message() -> R {
        let msg = update_message(
            "example.com",
            "_acme-challenge.example.com",
            Change::Add("digest-value-42"),
        )?;
        // Header: id 0, opcode 5 (UPDATE), one zone entry, one update entry.
        assert!(msg.starts_with(&[0, 0, 0x28, 0x00]));
        assert_eq!(msg.get(4..6).map(<[u8]>::to_vec), Some(vec![0, 1]));
        assert_eq!(msg.get(8..10).map(<[u8]>::to_vec), Some(vec![0, 1]));
        // Zone: example.com IN SOA — the encoded name followed by SOA/IN.
        let mut zone = Vec::new();
        encode_name("example.com", &mut zone)?;
        assert!(msg.windows(zone.len()).any(|w| w == zone.as_slice()));
        assert!(has(&msg, &[0, 6, 0, 1]));
        // No class-ANY delete-all: the other values at the name stay.
        assert!(!has(&msg, &[0, 16, 0, 255]));
        // Add entry: TXT IN with a 60s TTL…
        assert!(has(&msg, &[0, 16, 0, 1, 0, 0, 0, 60]));
        // …and rdata "digest-value-42" as one 15-byte character-string.
        let mut rdata = vec![15u8];
        rdata.extend_from_slice(b"digest-value-42");
        assert!(has(&msg, &rdata));
        assert_eq!(msg.len(), 84);
        Ok(())
    }

    #[test]
    fn rfc2136_delete_message_removes_one_record() -> R {
        let msg = update_message(
            "example.com",
            "_acme-challenge.example.com",
            Change::Remove("digest-value-42"),
        )?;
        assert_eq!(msg.get(8..10).map(<[u8]>::to_vec), Some(vec![0, 1]));
        // RFC 2136 §2.5.4: TXT, class NONE (254), TTL 0, and the rdata of the
        // one record to remove — not the class-ANY delete of the whole set.
        let mut entry = vec![0, 16, 0, 254, 0, 0, 0, 0, 0, 16, 15];
        entry.extend_from_slice(b"digest-value-42");
        assert!(has(&msg, &entry));
        assert!(!has(&msg, &[0, 16, 0, 255]));
        assert!(!has(&msg, &[0, 16, 0, 1]));
        assert_eq!(msg.len(), 84);
        Ok(())
    }

    #[test]
    fn rfc2136_update_returns_the_built_message() -> R {
        // Message building is separate from signing and sending.
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?;
        let record = record()?;
        let add = r2.update(&record, Change::Add(record.value()))?;
        assert_eq!(
            add,
            update_message("example.com", record.fqdn(), Change::Add(record.value()))?
        );
        let remove = r2.update(&record, Change::Remove(record.value()))?;
        assert_ne!(remove, add, "a remove is not an add");
        Ok(())
    }

    /// One UPDATE the fake primary received: the server and the bytes.
    type Sent = (String, Vec<u8>);

    /// An exchange that plays the primary server: it checks the signed
    /// UPDATE, then answers with `rcode`, signed with the same key.
    fn tsig_server(rcode: u8, seen: Arc<Mutex<Vec<Sent>>>) -> Box<DnsExchange> {
        tsig_server_keyed(TSIG_B64.to_owned(), rcode, seen)
    }

    /// [`tsig_server`] answering with the TSIG key `key_b64`.
    fn tsig_server_keyed(
        key_b64: String,
        rcode: u8,
        seen: Arc<Mutex<Vec<Sent>>>,
    ) -> Box<DnsExchange> {
        Box::new(move |server: &str, signed: &[u8]| {
            seen.lock()
                .map_err(|p| AcmeError::Io(io::Error::other(p.to_string())))?
                .push((server.to_owned(), signed.to_vec()));
            let key =
                crate::tsig::Key::new("k.example.com", crate::tsig::Algorithm::Sha256, &key_b64)?;
            // hmac-sha256: the MAC is the 32 bytes before id, error, other len.
            let end = signed.len().saturating_sub(6);
            let mac = signed.get(end.saturating_sub(32)..end).unwrap_or_default();
            let mut answer = signed.get(..2).unwrap_or_default().to_vec();
            answer.extend_from_slice(&[0xa8, rcode, 0, 1, 0, 0, 0, 0, 0, 0]);
            answer.extend_from_slice(signed.get(12..12 + 17).unwrap_or_default());
            key.sign_answer(&answer, crate::tsig::now(), mac)
        })
    }

    #[test]
    fn rfc2136_signs_sends_and_checks_the_answer() -> R {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?
        .with_exchange(tsig_server(0, Arc::clone(&seen)));
        let record = record()?;
        r2.present(&record)?;
        r2.delete(&record)?;
        let seen = seen
            .lock()
            .map_err(|p| AcmeError::Io(io::Error::other(p.to_string())))?;
        assert_eq!(seen.len(), 2);
        for (server, signed) in seen.iter() {
            assert_eq!(server, "ns1.example.com:53");
            // ARCOUNT 1: the TSIG record, owned by the key name.
            assert_eq!(signed.get(10..12), Some(&[0, 1][..]));
            let mut owner = Vec::new();
            encode_name("k.example.com", &mut owner)?;
            assert!(has(signed, &owner), "the TSIG owner is the key name");
            assert!(!has(signed, b"s3cr3t"), "the secret is never sent");
        }
        let add = seen.first().map(|(_, m)| m.clone()).unwrap_or_default();
        assert!(has(&add, b"digest-value-42"), "present carries the value");
        Ok(())
    }

    #[test]
    fn rfc2136_reports_a_refused_or_failed_update() -> R {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?
        .with_exchange(tsig_server(9, seen));
        assert!(matches!(
            r2.present(&record()?),
            Err(AcmeError::Config(m)) if m.ends_with("RCODE NOTAUTH (9)")
        ));
        let down = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?
        .with_exchange(Box::new(|_: &str, _: &[u8]| {
            Err(AcmeError::Config(
                "rfc2136: ns1.example.com:53: cannot connect".into(),
            ))
        }));
        assert!(matches!(
            down.delete(&record()?),
            Err(AcmeError::Config(m)) if m.ends_with("cannot connect")
        ));
        Ok(())
    }

    #[test]
    fn rfc2136_uses_the_configured_zone_not_the_parent_label() -> R {
        // RFC 2136 §2.3: the Zone section names the zone holding the SOA. A
        // challenge name gives no way to find it — `_acme-challenge.a.example`
        // may live in `a.example` or in `example` — so the zone is configured.
        // Stripping the first label, which is what this used to do, would put
        // `a.example` here and earn NOTAUTH from the primary.
        let deep = DnsRecord::new("_acme-challenge.a.b.example.com", "digest-value-42")?;
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?;
        assert_eq!(r2.zone_for(&deep)?, "example.com");

        // The record must be inside the configured zone.
        let outside = DnsRecord::new("_acme-challenge.other.org", "digest-value-42")?;
        assert!(matches!(r2.zone_for(&outside), Err(AcmeError::Config(_))));
        // A near-miss that only shares a suffix as a substring is still out:
        // `notexample.com` is not inside `example.com`.
        let suffix_trap = DnsRecord::new("_acme-challenge.notexample.com", "digest-value-42")?;
        assert!(matches!(
            r2.zone_for(&suffix_trap),
            Err(AcmeError::Config(_))
        ));
        // The zone apex itself is inside its own zone.
        let apex = DnsRecord::new("example.com", "digest-value-42")?;
        assert_eq!(r2.zone_for(&apex)?, "example.com");

        // And the built message carries the configured zone in its Zone
        // section. That section starts right after the 12-byte header, so
        // compare there rather than searching: the encoded parent label
        // `b.example.com` is a *substring* of the encoded record name, and a
        // search would find it whichever zone was used.
        let msg = update_message("example.com", deep.fqdn(), Change::Add(deep.value()))?;
        let mut want = Vec::new();
        encode_name("example.com", &mut want)?;
        assert_eq!(
            msg.get(12..12 + want.len()).map(<[u8]>::to_vec),
            Some(want),
            "the zone section must hold the configured zone"
        );
        Ok(())
    }

    #[test]
    fn rfc2136_refuses_a_record_outside_its_zone_before_sending() -> R {
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?;
        let outside = DnsRecord::new("_acme-challenge.other.org", "digest-value-42")?;
        // The zone check runs before anything is signed or sent.
        for result in [r2.present(&outside), r2.delete(&outside)] {
            assert!(
                matches!(result, Err(AcmeError::Config(ref m)) if m.contains("outside zone")),
                "expected a zone error, got {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn authoritative_providers_keep_the_instant_default() -> R {
        let ad = AcmeDnsProvider::new("https://dns.example", "user", "pass")?;
        ad.wait_propagated(&record()?)?;
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?;
        r2.wait_propagated(&record()?)?;
        Ok(())
    }

    #[test]
    fn provider_api_failures_surface_instead_of_passing_silently() -> R {
        let record = record()?;

        // A non-2xx on the list call, the write, and the delete.
        let (send, _) = scripted(&[(500, "")]);
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?.with_transport(send);
        assert!(matches!(
            cf.present(&record),
            Err(AcmeError::Config(m)) if m.contains("list returned HTTP 500")
        ));

        let (send, _) = scripted(&[(200, r#"{"result":[]}"#), (403, "")]);
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?.with_transport(send);
        assert!(matches!(
            cf.present(&record),
            Err(AcmeError::Config(m)) if m.contains("write returned HTTP 403")
        ));

        let (send, _) = scripted(&[
            (
                200,
                r#"{"result":[{"id":"cf-1","content":"digest-value-42"}]}"#,
            ),
            (500, ""),
        ]);
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?.with_transport(send);
        assert!(matches!(
            cf.delete(&record),
            Err(AcmeError::Config(m)) if m.contains("delete returned HTTP 500")
        ));

        // acme-dns and deSEC report their own non-2xx too.
        let (send, _) = scripted(&[(401, "")]);
        let ad = AcmeDnsProvider::new("https://dns.example", "user", "pass")?.with_transport(send);
        assert!(matches!(
            ad.present(&record),
            Err(AcmeError::Config(m)) if m.contains("update returned HTTP 401")
        ));

        let (send, _) = scripted(&[(500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.present(&record),
            Err(AcmeError::Config(m)) if m.contains("GET returned HTTP 500")
        ));

        let (send, _) = scripted(&[(404, ""), (500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.present(&record),
            Err(AcmeError::Config(m)) if m.contains("PUT returned HTTP 500")
        ));

        let (send, _) = scripted(&[(500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.delete(&record),
            Err(AcmeError::Config(m)) if m.contains("GET returned HTTP 500")
        ));

        let (send, _) = scripted(&[(200, r#"{"records":["\"digest-value-42\""]}"#), (500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.delete(&record),
            Err(AcmeError::Config(m)) if m.contains("DELETE returned HTTP 500")
        ));

        let (send, _) = scripted(&[
            (200, r#"{"records":["\"digest-value-42\"","\"other\""]}"#),
            (500, ""),
        ]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.delete(&record),
            Err(AcmeError::Config(m)) if m.contains("PUT returned HTTP 500")
        ));

        let (send, _) = scripted(&[(500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.wait_propagated(&record),
            Err(AcmeError::Config(m)) if m.contains("GET returned HTTP 500")
        ));
        Ok(())
    }

    #[test]
    fn unreadable_api_responses_are_refused_not_guessed() -> R {
        // A 200 whose body is not the shape the API documents must fail
        // loudly: treating it as "no record" would make `present` POST a
        // duplicate and `wait_propagated` loop until the order expired.
        assert!(matches!(
            cf_txt_id("not json", "v"),
            Err(AcmeError::Config(m)) if m.contains("unreadable list response")
        ));
        assert!(matches!(
            cf_txt_id(r#"{"success":true}"#, "v"),
            Err(AcmeError::Config(m)) if m.contains("no result array")
        ));
        // A record at the name carrying somebody else's value is not ours.
        assert_eq!(
            cf_txt_id(r#"{"result":[{"id":"x","content":"other"}]}"#, "mine")?,
            None
        );
        assert!(matches!(
            rrset_contains("not json", "v"),
            Err(AcmeError::Config(m)) if m.contains("unreadable RRset response")
        ));
        // A well-formed response that simply does not carry our value.
        assert!(!rrset_contains(r#"[{"records":["other"]}]"#, "mine")?);
        // The single-RRset read refuses a body without a records array, or
        // with a record that is not a string, rather than reading it as
        // empty: an empty read would make `present` PUT over the real set.
        assert!(matches!(
            rrset_records("not json"),
            Err(AcmeError::Config(m)) if m.contains("unreadable RRset response")
        ));
        for body in ["{}", r#"{"records":"x"}"#, r#"{"records":[1]}"#, "[]"] {
            assert!(matches!(
                rrset_records(body),
                Err(AcmeError::Config(m)) if m.contains("no records array")
            ));
        }
        assert_eq!(
            rrset_records(r#"{"records":["\"a\"","b"]}"#)?,
            strings(&["\"a\"", "b"])
        );
        assert!(is_value("\"mine\"", "mine") && is_value("mine", "mine"));
        assert!(!is_value("\"other\"", "mine") && !is_value("\"mine", "mine"));
        Ok(())
    }

    #[test]
    fn desec_maps_the_zone_apex_to_the_at_subname() -> R {
        let apex = DnsRecord::new("example.com", "digest-value-42")?;
        let (send, script) = scripted(&[(404, ""), (200, "{}")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        ds.present(&apex)?;
        assert!(
            last(&script)?.url.contains("/rrsets/@/TXT/"),
            "the apex is `@`, not an empty subname: {}",
            last(&script)?.url
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Two values at one name
    //
    // An order for `example.com` and `*.example.com` holds two dns-01 values
    // at `_acme-challenge.example.com` at once (RFC 8555 §8.4). `present` must
    // add its value beside the other one, and `delete` must remove only its
    // own. Each provider runs against a fake that keeps state.
    // -----------------------------------------------------------------------

    /// Two challenge records at one name, as an apex plus wildcard order has.
    fn pair() -> Result<(DnsRecord, DnsRecord), AcmeError> {
        Ok((
            DnsRecord::new("_acme-challenge.example.com", "digest-a")?,
            DnsRecord::new("_acme-challenge.example.com", "digest-b")?,
        ))
    }

    fn sorted(mut values: Vec<String>) -> Vec<String> {
        values.sort();
        values
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn json_error(err: &serde_json::Error) -> AcmeError {
        AcmeError::Config(err.to_string())
    }

    fn poisoned<T>(err: &std::sync::PoisonError<T>) -> AcmeError {
        AcmeError::Io(io::Error::other(err.to_string()))
    }

    /// The TXT values a Cloudflare fake holds, as `(id, content)`.
    type CfZone = Arc<Mutex<Vec<(String, String)>>>;

    fn cf_content(req: &HttpRequest) -> Result<String, AcmeError> {
        let body: serde_json::Value =
            serde_json::from_str(&req.body).map_err(|e| json_error(&e))?;
        body.get("content")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AcmeError::Config("fake cloudflare: no content".into()))
    }

    /// A fake Cloudflare zone: list, create, update and delete over `held`.
    fn cloudflare_server(held: CfZone) -> Box<HttpTransport> {
        Box::new(move |req: &HttpRequest| {
            let mut held = held.lock().map_err(|p| poisoned(&p))?;
            let id = req.url.rsplit_once("/dns_records/").map(|(_, id)| id);
            match (req.method, id) {
                ("GET", _) => {
                    let result: Vec<_> = held
                        .iter()
                        .map(|(id, content)| serde_json::json!({"id": id, "content": content}))
                        .collect();
                    Ok((200, serde_json::json!({"result": result}).to_string()))
                }
                ("POST", None) => {
                    let id = format!("cf-{}", held.len());
                    held.push((id, cf_content(req)?));
                    Ok((200, "{}".to_owned()))
                }
                ("PUT", Some(id)) => {
                    let content = cf_content(req)?;
                    if let Some(entry) = held.iter_mut().find(|(have, _)| have == id) {
                        entry.1 = content;
                    }
                    Ok((200, "{}".to_owned()))
                }
                ("DELETE", Some(id)) => {
                    held.retain(|(have, _)| have != id);
                    Ok((200, "{}".to_owned()))
                }
                _ => Ok((405, String::new())),
            }
        })
    }

    #[test]
    fn cloudflare_holds_two_values_at_one_name() -> R {
        let (a, b) = pair()?;
        let held = CfZone::default();
        let cf = CloudflareProvider::new("tok", "a".repeat(32))?
            .with_transport(cloudflare_server(Arc::clone(&held)));
        let contents = || -> Result<Vec<String>, AcmeError> {
            let held = held.lock().map_err(|p| poisoned(&p))?;
            Ok(sorted(held.iter().map(|(_, c)| c.clone()).collect()))
        };
        cf.present(&a)?;
        cf.present(&b)?;
        cf.present(&a)?; // a refresh must not add a third record
        assert_eq!(contents()?, strings(&["digest-a", "digest-b"]));
        cf.delete(&a)?;
        assert_eq!(contents()?, strings(&["digest-b"]));
        cf.delete(&b)?;
        assert_eq!(contents()?, Vec::<String>::new());
        Ok(())
    }

    /// The one deSEC `RRset` a fake holds; `None` when it does not exist.
    type RrSet = Arc<Mutex<Option<Vec<String>>>>;

    /// A fake deSEC API for a single `RRset`: GET, PUT and DELETE on its URL.
    /// Like the real API, it refuses a PUT that empties the set.
    fn desec_server(rrset: RrSet) -> Box<HttpTransport> {
        Box::new(move |req: &HttpRequest| {
            let mut held = rrset.lock().map_err(|p| poisoned(&p))?;
            match req.method {
                "GET" => Ok(match held.as_ref() {
                    Some(records) => (
                        200,
                        serde_json::json!({
                            "subname": "_acme-challenge", "type": "TXT",
                            "records": records, "ttl": 3600,
                        })
                        .to_string(),
                    ),
                    None => (404, r#"{"detail":"Not found."}"#.to_owned()),
                }),
                "PUT" => {
                    let body: serde_json::Value =
                        serde_json::from_str(&req.body).map_err(|e| json_error(&e))?;
                    let records: Vec<String> = body
                        .get("records")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| AcmeError::Config("fake deSEC: no records".into()))?
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect();
                    if records.is_empty() {
                        return Ok((400, r#"{"records":["empty"]}"#.to_owned()));
                    }
                    *held = Some(records);
                    Ok((200, "{}".to_owned()))
                }
                "DELETE" => Ok(if held.take().is_some() {
                    (204, String::new())
                } else {
                    (404, r#"{"detail":"Not found."}"#.to_owned())
                }),
                _ => Ok((405, String::new())),
            }
        })
    }

    #[test]
    fn desec_holds_two_values_at_one_name() -> R {
        let (a, b) = pair()?;
        let rrset = RrSet::default();
        let ds = DeSecProvider::new("tok", "example.com")?
            .with_transport(desec_server(Arc::clone(&rrset)));
        let values = || -> Result<Option<Vec<String>>, AcmeError> {
            Ok(rrset.lock().map_err(|p| poisoned(&p))?.clone().map(sorted))
        };
        ds.present(&a)?;
        ds.present(&b)?;
        ds.present(&a)?; // a refresh must not add a second copy
        assert_eq!(values()?, Some(strings(&["\"digest-a\"", "\"digest-b\""])));
        ds.delete(&a)?;
        assert_eq!(values()?, Some(strings(&["\"digest-b\""])));
        ds.delete(&b)?;
        assert_eq!(values()?, None, "the empty RRset is deleted, not PUT");
        ds.delete(&b)?; // an already-gone value is not a failure
        Ok(())
    }

    #[test]
    fn desec_keeps_values_it_did_not_write() -> R {
        // A value left by another client, or by a crashed run, stays put.
        let (a, _) = pair()?;
        let rrset = RrSet::new(Mutex::new(Some(strings(&["\"foreign\""]))));
        let ds = DeSecProvider::new("tok", "example.com")?
            .with_transport(desec_server(Arc::clone(&rrset)));
        ds.present(&a)?;
        ds.delete(&a)?;
        let held = rrset.lock().map_err(|p| poisoned(&p))?.clone();
        assert_eq!(held, Some(strings(&["\"foreign\""])));
        Ok(())
    }

    /// The TXT rdata a fake primary holds at the challenge name.
    type Zone = Arc<Mutex<Vec<Vec<u8>>>>;

    fn take<'a>(msg: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], AcmeError> {
        let end = pos.checked_add(len);
        let bytes = end.and_then(|end| msg.get(*pos..end));
        let bytes = bytes.ok_or_else(|| AcmeError::Config("fake primary: short message".into()))?;
        *pos = pos.saturating_add(len);
        Ok(bytes)
    }

    fn take_u16(msg: &[u8], pos: &mut usize) -> Result<u16, AcmeError> {
        let bytes = <[u8; 2]>::try_from(take(msg, pos, 2)?)
            .map_err(|_| AcmeError::Config("fake primary: short message".into()))?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Skips an uncompressed name.
    fn skip_name(msg: &[u8], pos: &mut usize) -> Result<(), AcmeError> {
        loop {
            let len = usize::from(take(msg, pos, 1)?.first().copied().unwrap_or_default());
            if len == 0 {
                return Ok(());
            }
            take(msg, pos, len)?;
        }
    }

    /// Applies the TXT changes of an UPDATE message to `zone`, as RFC 2136
    /// §2.5 defines them: class IN adds a record, class ANY deletes the whole
    /// set, class NONE deletes the one record that matches.
    fn apply_update(msg: &[u8], zone: &mut Vec<Vec<u8>>) -> Result<(), AcmeError> {
        const TYPE_TXT: u16 = 16;
        const CLASS_IN: u16 = 1;
        const CLASS_NONE: u16 = 254;
        const CLASS_ANY: u16 = 255;
        let mut pos = 0;
        take(msg, &mut pos, 4)?; // id, flags
        let zocount = take_u16(msg, &mut pos)?;
        let prcount = take_u16(msg, &mut pos)?;
        let upcount = take_u16(msg, &mut pos)?;
        take(msg, &mut pos, 2)?; // adcount
        assert_eq!(prcount, 0);
        for _ in 0..zocount {
            skip_name(msg, &mut pos)?;
            take(msg, &mut pos, 4)?;
        }
        for _ in 0..upcount {
            skip_name(msg, &mut pos)?;
            let rtype = take_u16(msg, &mut pos)?;
            let class = take_u16(msg, &mut pos)?;
            take(msg, &mut pos, 4)?; // ttl
            let rdlen = take_u16(msg, &mut pos)?;
            let rdata = take(msg, &mut pos, usize::from(rdlen))?.to_vec();
            if rtype != TYPE_TXT {
                continue;
            }
            match class {
                CLASS_IN if !zone.contains(&rdata) => zone.push(rdata),
                CLASS_IN => {}
                CLASS_ANY => zone.clear(),
                CLASS_NONE => zone.retain(|held| *held != rdata),
                other => {
                    return Err(AcmeError::Config(format!("fake primary: class {other}")));
                }
            }
        }
        Ok(())
    }

    /// The signing fake primary of [`tsig_server`], with a zone behind it.
    fn tsig_zone(zone: Zone) -> Box<DnsExchange> {
        let answer = tsig_server(0, Arc::new(Mutex::new(Vec::new())));
        Box::new(move |server: &str, signed: &[u8]| {
            let mut held = zone.lock().map_err(|p| poisoned(&p))?;
            apply_update(signed, &mut held)?;
            drop(held);
            answer(server, signed)
        })
    }

    #[test]
    fn rfc2136_holds_two_values_at_one_name() -> R {
        let (a, b) = pair()?;
        let zone = Zone::default();
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            TSIG_B64,
            "hmac-sha256",
        )?
        .with_exchange(tsig_zone(Arc::clone(&zone)));
        let held = || -> Result<Vec<Vec<u8>>, AcmeError> {
            let mut held = zone.lock().map_err(|p| poisoned(&p))?.clone();
            held.sort();
            Ok(held)
        };
        r2.present(&a)?;
        r2.present(&b)?;
        r2.present(&a)?; // a refresh must not add a second copy
        assert_eq!(held()?, vec![txt_rdata("digest-a"), txt_rdata("digest-b")]);
        r2.delete(&a)?;
        assert_eq!(held()?, vec![txt_rdata("digest-b")]);
        r2.delete(&b)?;
        assert_eq!(held()?, Vec::<Vec<u8>>::new());
        r2.delete(&b)?; // an already-gone value is not a failure
        Ok(())
    }

    #[test]
    fn constructors_reject_malformed_credentials() {
        assert!(matches!(
            CloudflareProvider::new("", "a".repeat(32)),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            CloudflareProvider::new("tok", "short"),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            AcmeDnsProvider::new("auth.acme-dns.io", "user", "pass"),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            AcmeDnsProvider::new("https://dns.example", "", "pass"),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            DeSecProvider::new("tok", ".."),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            Rfc2136Provider::new(
                "ns1.example.com:53",
                "example.com",
                "bad name!",
                "key",
                "hmac-sha256"
            ),
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            Rfc2136Provider::new(
                "ns1.example.com:53",
                "example.com",
                "k.example.com",
                "key",
                "md5-but-fake"
            ),
            Err(AcmeError::Config(_))
        ));
        for weak in ["hmac-md5", "hmac-sha1"] {
            assert!(matches!(
                Rfc2136Provider::new("ns1.example.com:53", "example.com", "k.example.com", TSIG_B64, weak),
                Err(AcmeError::Config(m)) if m.contains("hmac-md5 and hmac-sha1 are refused")
            ));
        }
        assert!(matches!(
            Rfc2136Provider::new("ns1.example.com:53", "example.com", "k.example.com", "not base64!", "hmac-sha256"),
            Err(AcmeError::Config(m)) if m.ends_with("TSIG key value is not base64")
        ));
    }

    #[test]
    fn debug_output_redacts_every_secret() {
        let dumps = [
            format!(
                "{:?}",
                CloudflareProvider::new("s3cr3t-token", "a".repeat(32)).ok()
            ),
            format!(
                "{:?}",
                AcmeDnsProvider::new("https://dns.example", "subdom-user", "s3cr3t-password").ok()
            ),
            format!(
                "{:?}",
                DeSecProvider::new("s3cr3t-token", "example.com").ok()
            ),
            format!(
                "{:?}",
                Rfc2136Provider::new(
                    "ns1.example.com:53",
                    "example.com",
                    "tsig-key",
                    TSIG_B64,
                    "hmac-sha256"
                )
                .ok()
            ),
        ];
        for dump in &dumps {
            assert!(dump.starts_with("Some("), "the provider was built: {dump}");
            assert!(
                !dump.contains("s3cr3t") && !dump.contains(TSIG_B64),
                "secret material leaked in debug output: {dump}"
            );
        }
    }

    #[test]
    fn http_request_debug_redacts_header_values() {
        let request = HttpRequest {
            method: "GET",
            url: "https://example.test".to_owned(),
            headers: vec![("Authorization", "Bearer super-secret".to_owned())],
            body: "visible".to_owned(),
        };
        let dump = format!("{request:?}");
        assert!(!dump.contains("super-secret"));
        assert!(dump.contains("[redacted]"));
    }

    #[test]
    fn acme_dns_rejects_plain_http() {
        assert!(matches!(
            AcmeDnsProvider::new("http://dns.example", "user", "pass"),
            Err(AcmeError::Config(message)) if message.contains("https://")
        ));
    }

    // -----------------------------------------------------------------------
    // No secret in any text a caller can log
    //
    // `detent-acme` logs nothing itself; `detent` logs the `Display` of what
    // it returns. So every error and every `Debug` the providers can produce
    // is checked here, and `detent/src/acme.rs` checks the log itself.
    // -----------------------------------------------------------------------

    const CF_SECRET: &str = "SECRET-cf-7f3a91c2d4e60b58";
    const ACME_DNS_SECRET: &str = "SECRET-acmedns-3b9e0d17a6c2c9f4";
    const DESEC_SECRET: &str = "SECRET-desec-5a17c8e9b302d6e1";
    /// The raw TSIG key. The config carries it base64-encoded.
    const TSIG_RAW: &str = "SECRET-tsig-c04d7e12b9a35f68";

    /// Every form in which `secret` could reach a log: as written, its tail
    /// (the part that is random), base64 (both alphabets), and hex.
    fn forms(secret: &str) -> Vec<String> {
        use base64::Engine as _;
        let tail = secret.rsplit('-').next().unwrap_or(secret);
        let mut forms = vec![
            secret.to_owned(),
            tail.to_owned(),
            base64::engine::general_purpose::STANDARD.encode(secret),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
        ];
        forms.push(
            secret
                .bytes()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
                .collect::<String>(),
        );
        forms
    }

    /// Fails when `text` holds any form of any secret, in any casing.
    fn assert_clean(what: &str, text: &str, secrets: &[&str]) {
        let lowered = text.to_lowercase();
        for secret in secrets {
            for form in forms(secret) {
                assert!(
                    !lowered.contains(&form.to_lowercase()),
                    "{what} holds {form:?}: {text}"
                );
            }
        }
    }

    /// The `Display` and `Debug` of `err`, as a caller could log them.
    fn texts(err: &AcmeError) -> [String; 2] {
        [err.to_string(), format!("{err:?}")]
    }

    /// A provider answer that echoes the credential back, as a hostile or
    /// misconfigured server can.
    fn echo(secret: &str) -> String {
        format!(r#"{{"detail":"bad credential {secret}","Authorization":"Bearer {secret}"}}"#)
    }

    type Build = fn(Box<HttpTransport>) -> Result<Box<dyn DnsProvider>, AcmeError>;

    fn build_cloudflare(send: Box<HttpTransport>) -> Result<Box<dyn DnsProvider>, AcmeError> {
        Ok(Box::new(
            CloudflareProvider::new(CF_SECRET, "a".repeat(32))?.with_transport(send),
        ))
    }

    fn build_acme_dns(send: Box<HttpTransport>) -> Result<Box<dyn DnsProvider>, AcmeError> {
        Ok(Box::new(
            AcmeDnsProvider::new("https://dns.example", "sub-8e21c4", ACME_DNS_SECRET)?
                .with_transport(send),
        ))
    }

    fn build_desec(send: Box<HttpTransport>) -> Result<Box<dyn DnsProvider>, AcmeError> {
        Ok(Box::new(
            DeSecProvider::new(DESEC_SECRET, "example.com")?.with_transport(send),
        ))
    }

    /// Runs `present`, `delete` and `wait_propagated` of a provider over
    /// every failure a server can answer with, and returns every error text.
    fn http_failures(
        build: Build,
        secret: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let record = record()?;
        let hostile = echo(secret);
        let listing = format!(
            r#"{{"result":[{{"id":"id-1","content":"digest-value-42"}}],"detail":"{secret}"}}"#
        );
        let mut errors = Vec::new();
        for status in [400_u16, 401, 403, 404, 429, 500, 502] {
            for body in ["", "not json", hostile.as_str()] {
                // Each script: fail at once; pass the list call, fail the
                // write; find our record, fail the write.
                for script in [
                    vec![(status, body); 3],
                    vec![(200, r#"{"result":[]}"#), (status, body), (status, body)],
                    vec![(200, listing.as_str()), (status, body), (status, body)],
                    vec![(200, hostile.as_str()), (200, hostile.as_str())],
                ] {
                    for action in 0..3_u8 {
                        let (send, _) = scripted(&script);
                        let provider = build(send)?;
                        let outcome = match action {
                            0 => provider.present(&record),
                            1 => provider.delete(&record),
                            _ => provider.wait_propagated(&record),
                        };
                        if let Err(err) = outcome {
                            errors.extend(texts(&err));
                        }
                    }
                }
            }
        }
        // A transport that fails: the real one names the method and URL.
        let send: Box<HttpTransport> = Box::new(|request: &HttpRequest| {
            Err(AcmeError::Config(format!(
                "{} {}: connection refused",
                request.method, request.url
            )))
        });
        let provider = build(send)?;
        for outcome in [
            provider.present(&record),
            provider.delete(&record),
            provider.wait_propagated(&record),
        ] {
            if let Err(err) = outcome {
                errors.extend(texts(&err));
            }
        }
        Ok(errors)
    }

    #[test]
    fn no_http_provider_error_holds_the_credential() -> R {
        for (build, secret) in [
            (build_cloudflare as Build, CF_SECRET),
            (build_acme_dns, ACME_DNS_SECRET),
            (build_desec, DESEC_SECRET),
        ] {
            let errors = http_failures(build, secret)?;
            assert!(
                errors.len() >= 40,
                "the fixtures did not fail: {}",
                errors.len()
            );
            for text in &errors {
                assert_clean("a provider error", text, &[secret]);
            }
        }
        Ok(())
    }

    #[test]
    fn a_refused_tsig_update_holds_no_key_material() -> R {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(TSIG_RAW);
        let secrets = [TSIG_RAW, key_b64.as_str()];
        let record = record()?;
        let mut errors = Vec::new();
        let mut collect = |outcome: Result<(), AcmeError>| {
            if let Err(err) = outcome {
                errors.extend(texts(&err));
            }
        };
        let rfc2136 = |exchange: Box<DnsExchange>| {
            Rfc2136Provider::new(
                "ns1.example.com:53",
                "example.com",
                "k.example.com",
                key_b64.as_str(),
                "hmac-sha256",
            )
            .map(|provider| provider.with_exchange(exchange))
        };
        // Every RCODE, the two verbs, and a signed answer.
        for rcode in 0..=16_u8 {
            let provider = rfc2136(tsig_server_keyed(
                key_b64.clone(),
                rcode,
                Arc::new(Mutex::new(Vec::new())),
            ))?;
            collect(provider.present(&record));
            collect(provider.delete(&record));
        }
        // An answer signed with another key: the MAC does not verify.
        let provider = rfc2136(tsig_server(0, Arc::new(Mutex::new(Vec::new()))))?;
        collect(provider.present(&record));
        // Answers that are not a signed answer at all.
        let junk: [&[u8]; 4] = [b"", b"\x00", &[0_u8; 12], &[0xff_u8; 64]];
        for answer in junk {
            let answer = answer.to_vec();
            let provider = rfc2136(Box::new(move |_: &str, _: &[u8]| Ok(answer.clone())))?;
            collect(provider.present(&record));
            collect(provider.delete(&record));
        }
        // A transport that fails.
        let provider = rfc2136(Box::new(|server: &str, _: &[u8]| {
            Err(AcmeError::Config(format!(
                "rfc2136: {server}: cannot connect"
            )))
        }))?;
        collect(provider.present(&record));
        // A record outside the zone: refused before it is signed.
        let outside = DnsRecord::new("_acme-challenge.example.org", "digest-value-42")?;
        collect(provider.present(&outside));
        assert!(
            errors.len() >= 30,
            "the fixtures did not fail: {}",
            errors.len()
        );
        for text in &errors {
            assert_clean("an RFC 2136 error", text, &secrets);
        }
        Ok(())
    }

    #[test]
    fn a_rejected_credential_is_not_quoted_by_its_constructor() {
        use base64::Engine as _;
        let bad = |secret: &str| format!("{secret}\u{7}");
        let mut errors = Vec::new();
        let mut collect = |built: Result<(), AcmeError>| {
            if let Err(err) = built {
                errors.extend(texts(&err));
            }
        };
        // A credential the constructor rejects itself.
        collect(CloudflareProvider::new(bad(CF_SECRET), "a".repeat(32)).map(drop));
        collect(
            AcmeDnsProvider::new("https://dns.example", "user", bad(ACME_DNS_SECRET)).map(drop),
        );
        collect(DeSecProvider::new(bad(DESEC_SECRET), "example.com").map(drop));
        // A good credential next to a setting the constructor rejects.
        collect(CloudflareProvider::new(CF_SECRET, "short").map(drop));
        collect(AcmeDnsProvider::new("http://dns.example", "user", ACME_DNS_SECRET).map(drop));
        collect(AcmeDnsProvider::new("https://dns.example", "", ACME_DNS_SECRET).map(drop));
        collect(DeSecProvider::new(DESEC_SECRET, "..").map(drop));
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(TSIG_RAW);
        for (zone, name, algorithm) in [
            ("bad zone!", "k.example.com", "hmac-sha256"),
            ("example.com", "bad name!", "hmac-sha256"),
            ("example.com", "k.example.com", "hmac-md5"),
            ("example.com", "k.example.com", "hmac-sha1"),
            ("example.com", "k.example.com", "no-such-mac"),
        ] {
            collect(
                Rfc2136Provider::new(
                    "ns1.example.com:53",
                    zone,
                    name,
                    key_b64.as_str(),
                    algorithm,
                )
                .map(drop),
            );
        }
        // A key value that is not base64, and one that decodes to nothing.
        for value in [bad(TSIG_RAW), String::new(), "====".to_owned()] {
            collect(
                Rfc2136Provider::new(
                    "ns1.example.com:53",
                    "example.com",
                    "k.example.com",
                    value,
                    "hmac-sha256",
                )
                .map(drop),
            );
        }
        assert!(
            errors.len() >= 30,
            "the constructors accepted: {}",
            errors.len()
        );
        let secrets = [CF_SECRET, ACME_DNS_SECRET, DESEC_SECRET, TSIG_RAW];
        for text in &errors {
            assert_clean("a constructor error", text, &secrets);
            assert_clean("a constructor error", text, &[key_b64.as_str()]);
        }
    }

    #[test]
    fn debug_of_every_secret_holder_holds_no_secret() -> R {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(TSIG_RAW);
        let mut dumps = vec![
            format!("{:?}", CloudflareProvider::new(CF_SECRET, "a".repeat(32))?),
            format!(
                "{:?}",
                AcmeDnsProvider::new("https://dns.example", "sub-8e21c4", ACME_DNS_SECRET)?
            ),
            format!("{:?}", DeSecProvider::new(DESEC_SECRET, "example.com")?),
            format!(
                "{:?}",
                Rfc2136Provider::new(
                    "ns1.example.com:53",
                    "example.com",
                    "k.example.com",
                    key_b64.as_str(),
                    "hmac-sha256",
                )?
            ),
        ];
        // The request a provider builds keeps its credential in a header.
        let request = HttpRequest {
            method: "GET",
            url: "https://example.test".to_owned(),
            headers: vec![
                ("Authorization", format!("Bearer {CF_SECRET}")),
                ("X-API-Key", ACME_DNS_SECRET.to_owned()),
                ("Authorization", format!("Token {DESEC_SECRET}")),
            ],
            body: String::new(),
        };
        dumps.push(format!("{request:?}"));
        dumps.push(format!("{request:#?}"));
        // The ACME account binding key and the issued private key.
        let eab = crate::EabCredentials {
            kid: "kid-1".to_owned(),
            key_b64: key_b64.clone(),
        };
        dumps.push(format!("{eab:?}"));
        dumps.push(format!("{eab:#?}"));
        let issued = crate::Issued {
            chain_pem: "chain".to_owned(),
            key_pem: format!("-----BEGIN PRIVATE KEY-----\n{TSIG_RAW}\n-----END PRIVATE KEY-----"),
        };
        dumps.push(format!("{issued:?}"));
        dumps.push(format!("{issued:#?}"));
        for dump in &dumps {
            assert_clean(
                "a Debug dump",
                dump,
                &[CF_SECRET, ACME_DNS_SECRET, DESEC_SECRET, TSIG_RAW],
            );
            assert_clean("a Debug dump", dump, &[key_b64.as_str()]);
        }
        Ok(())
    }
}
