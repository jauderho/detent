//! Networked dns-01 providers: RFC 2136, Cloudflare, acme-dns, deSEC.
//!
//! All four implement [`DnsProvider`] synchronously and follow the
//! [`HookProvider`](crate::HookProvider) idempotency contract: `present` is a
//! refresh, `delete` tolerates an already-gone record. Every constructor
//! validates its inputs, so a misconfigured provider cannot be built.
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
/// [`DnsProvider::present`] `PUT`s the challenge `RRset` — a `PUT` replaces it
/// wholesale, which is exactly the refresh contract. [`DnsProvider::delete`]
/// `DELETE`s the `RRset` and tolerates 404. [`DnsProvider::wait_propagated`]
/// reads the `RRset` back and confirms our value is in it.
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
}

impl DnsProvider for DeSecProvider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let subname = self.subname(record)?;
        let send = &*self.send;
        let put = HttpRequest {
            method: "PUT",
            url: self.rrset_url(subname),
            headers: self.auth().to_vec(),
            body: serde_json::json!({
                "subname": subname,
                "type": "TXT",
                "records": [format!("\"{}\"", record.value())],
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

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        let subname = self.subname(record)?;
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

/// TSIG algorithms (RFC 8945 §6) this provider accepts.
const TSIG_ALGORITHMS: [&str; 6] = [
    "hmac-md5",
    "hmac-sha1",
    "hmac-sha224",
    "hmac-sha256",
    "hmac-sha384",
    "hmac-sha512",
];

/// Publishes dns-01 records with RFC 2136 dynamic updates to a zone's primary
/// server.
///
/// [`DnsProvider::present`] builds one UPDATE that replaces the challenge TXT
/// (a class-ANY delete of the old value, then the add); [`DnsProvider::delete`]
/// sends just the delete-all. Both are idempotent by construction: re-adding
/// an existing record overwrites it, and deleting a missing name succeeds.
///
/// Updates are TSIG-signed (RFC 8945): the signature is an HMAC over the
/// message plus TSIG variables, appended as an additional record. That needs
/// the `hmac` crate, which detent-acme does not depend on, so sending is
/// refused with a clear error until that dependency decision lands (ADR-011).
/// The primary server is authoritative the moment it answers, so
/// `wait_propagated` keeps the instant default.
pub struct Rfc2136Provider {
    server: String,
    zone: String,
    key_name: String,
    // Held for the future TSIG signer; never sent, and never logged.
    #[allow(dead_code)]
    key_value: String,
    tsig_algorithm: String,
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
    /// not a valid DNS name, the key value is empty or non-printable, or the
    /// algorithm is not a known TSIG HMAC.
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
        validate_value(&key_value).map_err(|_| {
            AcmeError::Config("rfc2136: key value must be non-empty printable ASCII".into())
        })?;
        if !TSIG_ALGORITHMS.contains(&tsig_algorithm.as_str()) {
            return Err(AcmeError::Config(format!(
                "rfc2136: unknown TSIG algorithm {tsig_algorithm:?}; expected one of \
                 {}",
                TSIG_ALGORITHMS.join(", ")
            )));
        }
        Ok(Self {
            server,
            zone,
            key_name,
            key_value,
            tsig_algorithm,
        })
    }

    /// Builds the UPDATE for `record`, adding `add` as the new TXT when set.
    fn update(&self, record: &DnsRecord, add: Option<&str>) -> Result<Vec<u8>, AcmeError> {
        let zone = self.zone_for(record)?;
        update_message(zone, record.fqdn(), add)
    }

    /// Signs `message` with the configured TSIG key and sends it.
    ///
    /// Always refuses today. TSIG (RFC 8945 §10.2) is an HMAC over the
    /// message plus the TSIG variables, appended as an additional record;
    /// the `hmac` crate is not a detent-acme dependency, and every sane
    /// server refuses an unauthenticated update, so refusing here is the
    /// honest answer rather than putting an unsigned message on the wire.
    ///
    /// Kept separate from [`Self::update`] so that the message building —
    /// which *is* implemented and unit-tested — has a return type that means
    /// what it says.
    fn send_signed(&self, message: &[u8]) -> Result<(), AcmeError> {
        debug_assert!(!message.is_empty(), "an UPDATE was built before sending");
        Err(AcmeError::Config(format!(
            "rfc2136: cannot sign the {} byte UPDATE for {} with key {:?} ({}): TSIG \
             signing needs the `hmac` crate, which detent-acme does not depend on \
             (new dependency awaits ADR-011). UPDATE message building is implemented \
             and unit-tested; sending unauthenticated is refused",
            message.len(),
            self.server,
            self.key_name,
            self.tsig_algorithm,
        )))
    }
}

impl DnsProvider for Rfc2136Provider {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.send_signed(&self.update(record, Some(record.value()))?)
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.send_signed(&self.update(record, None)?)
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

/// Appends `name` in wire format: length-prefixed labels, zero terminator.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), AcmeError> {
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .map_err(|_| AcmeError::Config(format!("rfc2136: DNS label too long in {name:?}")))?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

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

/// Builds an RFC 2136 UPDATE message: the SOA-named `zone` in the zone
/// section, a class-ANY delete of every TXT for `name`, and — when `add` is
/// set — the new TXT with a 60s TTL. The TSIG additional record would be
/// appended by the signer, not here.
fn update_message(zone: &str, name: &str, add: Option<&str>) -> Result<Vec<u8>, AcmeError> {
    const HEADER: [u8; 4] = [0, 0, 0x28, 0x00]; // id 0, opcode 5 (UPDATE)
    const TYPE_SOA: [u8; 2] = [0, 6];
    const TYPE_TXT: [u8; 2] = [0, 16];
    const CLASS_IN: [u8; 2] = [0, 1];
    const CLASS_ANY: [u8; 2] = [0, 255];
    const TTL_60: [u8; 4] = [0, 0, 0, 60];

    let mut msg = Vec::with_capacity(160);
    msg.extend_from_slice(&HEADER);
    // Counts: zone 1, prerequisite 0, update 1(+1), additional 0.
    let updates: u16 = if add.is_some() { 2 } else { 1 };
    msg.extend_from_slice(&[0, 1]);
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&updates.to_be_bytes());
    msg.extend_from_slice(&[0, 0]);

    encode_name(zone, &mut msg)?;
    msg.extend_from_slice(&TYPE_SOA);
    msg.extend_from_slice(&CLASS_IN);

    // Update 1: delete every TXT set for `name` (class ANY, empty rdata).
    encode_name(name, &mut msg)?;
    msg.extend_from_slice(&TYPE_TXT);
    msg.extend_from_slice(&CLASS_ANY);
    msg.extend_from_slice(&[0, 0, 0, 0]); // ttl 0
    msg.extend_from_slice(&[0, 0]); // rdlength 0

    if let Some(value) = add {
        let rdata = txt_rdata(value);
        let rdlen = u16::try_from(rdata.len())
            .map_err(|_| AcmeError::Config("rfc2136: TXT rdata exceeds 64 KiB".into()))?;
        encode_name(name, &mut msg)?;
        msg.extend_from_slice(&TYPE_TXT);
        msg.extend_from_slice(&CLASS_IN);
        msg.extend_from_slice(&TTL_60);
        msg.extend_from_slice(&rdlen.to_be_bytes());
        msg.extend_from_slice(&rdata);
    }
    Ok(msg)
}

impl fmt::Debug for Rfc2136Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rfc2136Provider")
            .field("server", &self.server)
            .field("zone", &self.zone)
            .field("key_name", &self.key_name)
            .field("key_value", &"[redacted]")
            .field("tsig_algorithm", &self.tsig_algorithm)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Fuzz entry points
// ---------------------------------------------------------------------------

/// Feeds arbitrary strings through the DNS provider response parsers and the
/// RFC 2136 message builder.
///
/// List/RRset bodies arrive from provider APIs over the network, so malformed
/// JSON must map to `Err`, never to a panic; the message builder must likewise
/// refuse oversized labels with `Err`. Only compiled with the `fuzzing`
/// feature for `cargo-fuzz`.
#[cfg(feature = "fuzzing")]
pub fn fuzz_provider_response(body: &str, value: &str) {
    let _ = cf_txt_id(body, value);
    let _ = rrset_contains(body, value);
    let _ = update_message(body, value, Some(value));
    let _ = update_message(body, value, None);
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
                "s3cr3t-key",
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
    fn desec_derives_subnames_and_replaces_wholesale() -> R {
        let record = DnsRecord::new("_acme-challenge.sub.example.com", "digest-value-42")?;
        let (send, script) = scripted(&[(201, "{}")]);
        let ds = DeSecProvider::new("s3cr3t-token", "example.com")?.with_transport(send);
        ds.present(&record)?;
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
        let (send, script) = scripted(&[(404, r#"{"detail":"Not found."}"#)]);
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
            Some("digest-value-42"),
        )?;
        // Header: id 0, opcode 5 (UPDATE), one zone entry, two update entries.
        assert!(msg.starts_with(&[0, 0, 0x28, 0x00]));
        assert_eq!(msg.get(8..10).map(<[u8]>::to_vec), Some(vec![0, 2]));
        // Zone: example.com IN SOA — the encoded name followed by SOA/IN.
        let mut zone = Vec::new();
        encode_name("example.com", &mut zone)?;
        assert!(msg.windows(zone.len()).any(|w| w == zone.as_slice()));
        assert!(has(&msg, &[0, 6, 0, 1]));
        // Delete-all entry: TXT, class ANY (255), ttl 0, empty rdata.
        assert!(has(&msg, &[0, 16, 0, 255, 0, 0, 0, 0, 0, 0]));
        // Add entry: TXT IN with a 60s TTL…
        assert!(has(&msg, &[0, 16, 0, 1, 0, 0, 0, 60]));
        // …and rdata "digest-value-42" as one 15-byte character-string.
        let mut rdata = vec![15u8];
        rdata.extend_from_slice(b"digest-value-42");
        assert!(has(&msg, &rdata));
        assert_eq!(msg.len(), 123);
        Ok(())
    }

    #[test]
    fn rfc2136_delete_message_only_withdraws() -> R {
        let msg = update_message("example.com", "_acme-challenge.example.com", None)?;
        assert_eq!(msg.len(), 68);
        assert_eq!(msg.get(8..10).map(<[u8]>::to_vec), Some(vec![0, 1]));
        assert!(!has(&msg, &[0, 16, 0, 1]));
        Ok(())
    }

    #[test]
    fn rfc2136_update_returns_the_built_message() -> R {
        // `update` used to build the message, discard it, and return `Err`
        // unconditionally — a `Result<Vec<u8>, _>` that could never be `Ok`.
        // Message building and the refusal to send are now separate, so this
        // return type means what it says.
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            "s3cr3t-key",
            "hmac-sha256",
        )?;
        let record = record()?;
        let add = r2.update(&record, Some(record.value()))?;
        assert_eq!(
            add,
            update_message("example.com", record.fqdn(), Some(record.value()))?
        );
        let withdraw = r2.update(&record, None)?;
        assert!(withdraw.len() < add.len(), "a delete carries no rdata");
        // Sending is still refused, and that is now the only refusing step.
        assert!(matches!(
            r2.send_signed(&add),
            Err(AcmeError::Config(m)) if m.contains("does not depend on")
        ));
        Ok(())
    }

    #[test]
    fn rfc2136_refuses_to_send_without_tsig() -> R {
        let r2 = Rfc2136Provider::new(
            "ns1.example.com:53",
            "example.com",
            "k.example.com",
            "s3cr3t-key",
            "hmac-sha256",
        )?;
        assert!(matches!(
            r2.present(&record()?),
            Err(AcmeError::Config(ref m)) if m.contains("does not depend on")
        ));
        assert!(matches!(
            r2.delete(&record()?),
            Err(AcmeError::Config(ref m)) if m.contains("does not depend on")
        ));
        // The refusal names the key it would have signed with, never the key.
        let refusal = match r2.present(&record()?) {
            Err(AcmeError::Config(m)) => m,
            other => return Err(format!("expected a config error, got {other:?}").into()),
        };
        assert!(refusal.contains("k.example.com"), "{refusal}");
        assert!(
            !refusal.contains("s3cr3t"),
            "the TSIG key leaked: {refusal}"
        );
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
            "s3cr3t-key",
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
        let msg = update_message("example.com", deep.fqdn(), Some(deep.value()))?;
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
            "s3cr3t-key",
            "hmac-sha256",
        )?;
        let outside = DnsRecord::new("_acme-challenge.other.org", "digest-value-42")?;
        // The zone check runs before the TSIG refusal, so the error names the
        // zone rather than the missing `hmac` crate.
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
            "s3cr3t-key",
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
            Err(AcmeError::Config(m)) if m.contains("PUT returned HTTP 500")
        ));

        let (send, _) = scripted(&[(500, "")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        assert!(matches!(
            ds.delete(&record),
            Err(AcmeError::Config(m)) if m.contains("DELETE returned HTTP 500")
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
        Ok(())
    }

    #[test]
    fn desec_maps_the_zone_apex_to_the_at_subname() -> R {
        let apex = DnsRecord::new("example.com", "digest-value-42")?;
        let (send, script) = scripted(&[(200, "{}")]);
        let ds = DeSecProvider::new("tok", "example.com")?.with_transport(send);
        ds.present(&apex)?;
        assert!(
            last(&script)?.url.contains("/rrsets/@/TXT/"),
            "the apex is `@`, not an empty subname: {}",
            last(&script)?.url
        );
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
                    "s3cr3t-key",
                    "hmac-sha256"
                )
                .ok()
            ),
        ];
        for dump in &dumps {
            assert!(
                !dump.contains("s3cr3t"),
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
}
