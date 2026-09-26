//! TSIG (RFC 8945) for the RFC 2136 provider: sign an UPDATE, send it over
//! TCP, and verify the server's signed answer.
//!
//! Only the HMAC-SHA2 algorithms are accepted. `hmac-md5` is broken and
//! `hmac-sha1` is NOT RECOMMENDED (RFC 8945 §6). MACs are full length on both
//! sides; a truncated MAC in an answer is refused. The answer's MAC is checked
//! in constant time, and its time must be within the fudge of the local clock.

use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use base64::Engine as _;

use crate::AcmeError;

/// RR type TSIG.
const TYPE_TSIG: u16 = 250;
/// Class ANY, the class of every TSIG record.
const CLASS_ANY: u16 = 255;
/// Allowed clock skew between us and the server, in seconds (RFC 8945 §10).
pub(crate) const FUDGE: u16 = 300;
/// One deadline for each of connect, write and read.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Offset of ARCOUNT in the DNS header.
const ARCOUNT_AT: usize = 10;
const HEADER_LEN: usize = 12;

/// The TSIG HMAC algorithms this client signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// Every accepted name, for error text.
    pub(crate) const NAMES: [&'static str; 4] =
        ["hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "hmac-sha224" => Some(Self::Sha224),
            "hmac-sha256" => Some(Self::Sha256),
            "hmac-sha384" => Some(Self::Sha384),
            "hmac-sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Sha224 => "hmac-sha224",
            Self::Sha256 => "hmac-sha256",
            Self::Sha384 => "hmac-sha384",
            Self::Sha512 => "hmac-sha512",
        }
    }

    const fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha224 => hmac::HMAC_SHA224,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// A TSIG key: its name, algorithm and secret. The secret lives only inside
/// the HMAC key and has no `Debug` output.
pub(crate) struct Key {
    name: String,
    algorithm: Algorithm,
    hmac: hmac::Key,
}

impl Key {
    /// Builds a key from its DNS name, algorithm and base64 secret.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the secret is not base64 or is empty. The
    /// error never quotes the secret.
    pub(crate) fn new(
        name: &str,
        algorithm: Algorithm,
        secret_b64: &str,
    ) -> Result<Self, AcmeError> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(secret_b64)
            .map_err(|_| AcmeError::Config("rfc2136: TSIG key value is not base64".into()))?;
        if secret.is_empty() {
            return Err(AcmeError::Config("rfc2136: TSIG key value is empty".into()));
        }
        Ok(Self {
            name: name.to_ascii_lowercase(),
            algorithm,
            hmac: hmac::Key::new(algorithm.hmac(), &secret),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The TSIG variables that follow the message in every MAC input
    /// (RFC 8945 §4.3.3).
    fn variables(
        &self,
        time_signed: u64,
        fudge: u16,
        error: u16,
        other: &[u8],
    ) -> Result<Vec<u8>, AcmeError> {
        let mut out = Vec::with_capacity(64);
        encode_name(&self.name, &mut out)?;
        out.extend_from_slice(&CLASS_ANY.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        encode_name(self.algorithm.name(), &mut out)?;
        out.extend_from_slice(&time48(time_signed)?);
        out.extend_from_slice(&fudge.to_be_bytes());
        out.extend_from_slice(&error.to_be_bytes());
        out.extend_from_slice(&len16(other.len())?.to_be_bytes());
        out.extend_from_slice(other);
        Ok(out)
    }

    /// Signs `message` (a complete DNS message with no TSIG record yet) and
    /// returns the signed message and its MAC.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when the message is shorter than a header or
    /// already has additional records, or a field does not fit.
    pub(crate) fn sign(
        &self,
        message: &[u8],
        time_signed: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
        self.sign_with(message, time_signed, None)
    }

    /// Signs an answer to a request signed with `request_mac`, as a server
    /// does: the request MAC leads the MAC input (RFC 8945 §4.3.2).
    #[cfg(test)]
    pub(crate) fn sign_answer(
        &self,
        message: &[u8],
        time_signed: u64,
        request_mac: &[u8],
    ) -> Result<Vec<u8>, AcmeError> {
        self.sign_with(message, time_signed, Some(request_mac))
            .map(|(signed, _)| signed)
    }

    fn sign_with(
        &self,
        message: &[u8],
        time_signed: u64,
        request_mac: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
        let id = u16_at(message, 0)?;
        if u16_at(message, ARCOUNT_AT)? != 0 {
            return Err(AcmeError::Config(
                "rfc2136: the UPDATE already has additional records".into(),
            ));
        }
        let mut ctx = hmac::Context::with_key(&self.hmac);
        if let Some(request_mac) = request_mac {
            ctx.update(&len16(request_mac.len())?.to_be_bytes());
            ctx.update(request_mac);
        }
        ctx.update(message);
        ctx.update(&self.variables(time_signed, FUDGE, 0, &[])?);
        let mac = ctx.sign().as_ref().to_vec();

        let mut rdata = Vec::with_capacity(mac.len().saturating_add(40));
        encode_name(self.algorithm.name(), &mut rdata)?;
        rdata.extend_from_slice(&time48(time_signed)?);
        rdata.extend_from_slice(&FUDGE.to_be_bytes());
        rdata.extend_from_slice(&len16(mac.len())?.to_be_bytes());
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&id.to_be_bytes());
        rdata.extend_from_slice(&0_u16.to_be_bytes()); // error
        rdata.extend_from_slice(&0_u16.to_be_bytes()); // other len

        let mut signed = message.to_vec();
        encode_name(&self.name, &mut signed)?;
        signed.extend_from_slice(&TYPE_TSIG.to_be_bytes());
        signed.extend_from_slice(&CLASS_ANY.to_be_bytes());
        signed.extend_from_slice(&0_u32.to_be_bytes());
        signed.extend_from_slice(&len16(rdata.len())?.to_be_bytes());
        signed.extend_from_slice(&rdata);
        put_u16(&mut signed, ARCOUNT_AT, 1)?;
        Ok((signed, mac))
    }

    /// Checks the server's answer to a request we signed with `request_mac`:
    /// same id, a response, a TSIG record from this key with a valid MAC and
    /// time, and RCODE NOERROR.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] naming what failed.
    pub(crate) fn verify_response(
        &self,
        response: &[u8],
        request_id: u16,
        request_mac: &[u8],
        now: u64,
    ) -> Result<(), AcmeError> {
        let bad = |why: &str| AcmeError::Config(format!("rfc2136: server answer {why}"));
        if u16_at(response, 0)? != request_id {
            return Err(bad("has the wrong message id"));
        }
        let flags = u16_at(response, 2)?;
        if flags & 0x8000 == 0 {
            return Err(bad("is not a response"));
        }
        let rcode = flags & 0x000f;
        let arcount = u16_at(response, ARCOUNT_AT)?;
        if arcount == 0 {
            return Err(bad(&format!(
                "is not signed (RCODE {} ({rcode}), not trusted)",
                rcode_name(rcode)
            )));
        }
        // Skip every record before the TSIG, which must be the last one.
        let mut at = HEADER_LEN;
        for _ in 0..u16_at(response, 4)? {
            at = skip_name(response, at)?.saturating_add(4);
        }
        let before_tsig = [
            u16_at(response, 6)?,
            u16_at(response, 8)?,
            arcount.saturating_sub(1),
        ]
        .iter()
        .map(|&n| u32::from(n))
        .sum::<u32>();
        for _ in 0..before_tsig {
            at = skip_record(response, at)?;
        }
        let tsig_at = at;
        let (owner, mut at) = read_name(response, tsig_at)?;
        if !owner.eq_ignore_ascii_case(&self.name) {
            return Err(bad("is signed with another key"));
        }
        if u16_at(response, at)? != TYPE_TSIG
            || u16_at(response, at.saturating_add(2))? != CLASS_ANY
        {
            return Err(bad("has no TSIG as its last record"));
        }
        if u32::from(u16_at(response, at.saturating_add(4))?)
            | u32::from(u16_at(response, at.saturating_add(6))?)
            != 0
        {
            return Err(bad("has a TSIG record with a non-zero TTL"));
        }
        at = at.saturating_add(8); // type, class, ttl
        let rdlen = usize::from(u16_at(response, at)?);
        at = at.saturating_add(2);
        let rdata_end = at.saturating_add(rdlen);
        if rdata_end != response.len() {
            return Err(bad("has bytes after its TSIG record"));
        }
        let (algorithm, mut at) = read_name(response, at)?;
        if !algorithm.eq_ignore_ascii_case(self.algorithm.name()) {
            return Err(bad("uses another TSIG algorithm"));
        }
        let time_signed = u48_at(response, at)?;
        let fudge = u16_at(response, at.saturating_add(6))?;
        let mac_len = usize::from(u16_at(response, at.saturating_add(8))?);
        at = at.saturating_add(10);
        let mac = slice(response, at, mac_len)?;
        at = at.saturating_add(mac_len);
        let original_id = u16_at(response, at)?;
        let error = u16_at(response, at.saturating_add(2))?;
        let other_len = usize::from(u16_at(response, at.saturating_add(4))?);
        let other = slice(response, at.saturating_add(6), other_len)?;
        if at.saturating_add(6).saturating_add(other_len) != rdata_end {
            return Err(bad("has a malformed TSIG record"));
        }
        if error != 0 {
            return Err(bad(&format!(
                "carries TSIG error {} ({error})",
                tsig_error_name(error)
            )));
        }
        if mac.len() != self.algorithm.hmac().digest_algorithm().output_len {
            return Err(bad("has a truncated or oversize MAC"));
        }

        let mut unsigned = slice(response, 0, tsig_at)?.to_vec();
        put_u16(&mut unsigned, 0, original_id)?;
        put_u16(&mut unsigned, ARCOUNT_AT, arcount.saturating_sub(1))?;
        let mut input = Vec::with_capacity(unsigned.len().saturating_add(128));
        input.extend_from_slice(&len16(request_mac.len())?.to_be_bytes());
        input.extend_from_slice(request_mac);
        input.extend_from_slice(&unsigned);
        input.extend_from_slice(&self.variables(time_signed, fudge, error, other)?);
        hmac::verify(&self.hmac, &input, mac).map_err(|_| bad("has a bad TSIG MAC"))?;

        if now.abs_diff(time_signed) > u64::from(fudge) {
            return Err(bad("is signed outside the allowed clock skew"));
        }
        if rcode != 0 {
            return Err(bad(&format!(
                "refused the UPDATE: RCODE {} ({rcode})",
                rcode_name(rcode)
            )));
        }
        Ok(())
    }
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A random message id.
pub(crate) fn random_id() -> Result<u16, AcmeError> {
    let mut id = [0_u8; 2];
    aws_lc_rs::rand::fill(&mut id)
        .map_err(|_| AcmeError::Config("rfc2136: no random message id".into()))?;
    Ok(u16::from_be_bytes(id))
}

/// Sends one length-prefixed DNS message over TCP (RFC 1035 §4.2.2) to
/// `server` (`host:port`) and returns the answer.
///
/// # Errors
///
/// [`AcmeError::Config`] naming the server when it cannot be resolved or
/// reached, or the exchange fails or times out.
pub(crate) fn exchange_tcp(server: &str, message: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let fail = |why: String| AcmeError::Config(format!("rfc2136: {server}: {why}"));
    let addrs = server
        .to_socket_addrs()
        .map_err(|err| fail(format!("cannot resolve: {err}")))?;
    let mut last = String::from("no address");
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(err) => last = err.to_string(),
        }
    }
    let mut stream = stream.ok_or_else(|| fail(format!("cannot connect: {last}")))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|err| fail(err.to_string()))?;
    let mut framed = Vec::with_capacity(message.len().saturating_add(2));
    framed.extend_from_slice(&len16(message.len())?.to_be_bytes());
    framed.extend_from_slice(message);
    stream
        .write_all(&framed)
        .map_err(|err| fail(format!("send: {err}")))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|err| fail(format!("receive: {err}")))?;
    let mut answer = vec![0_u8; usize::from(u16::from_be_bytes(len))];
    stream
        .read_exact(&mut answer)
        .map_err(|err| fail(format!("receive: {err}")))?;
    Ok(answer)
}

/// Appends `name` in uncompressed wire format.
pub(crate) fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), AcmeError> {
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .map_err(|_| AcmeError::Config(format!("rfc2136: DNS label too long in {name:?}")))?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn truncated() -> AcmeError {
    AcmeError::Config("rfc2136: server answer is truncated".into())
}

fn slice(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], AcmeError> {
    bytes
        .get(at..at.checked_add(len).ok_or_else(truncated)?)
        .ok_or_else(truncated)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, AcmeError> {
    let pair = slice(bytes, at, 2)?;
    Ok(u16::from_be_bytes([
        pair.first().copied().unwrap_or_default(),
        pair.get(1).copied().unwrap_or_default(),
    ]))
}

fn u48_at(bytes: &[u8], at: usize) -> Result<u64, AcmeError> {
    Ok(slice(bytes, at, 6)?
        .iter()
        .fold(0_u64, |acc, &byte| (acc << 8) | u64::from(byte)))
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) -> Result<(), AcmeError> {
    let end = at.checked_add(2).ok_or_else(truncated)?;
    bytes
        .get_mut(at..end)
        .ok_or_else(truncated)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn len16(len: usize) -> Result<u16, AcmeError> {
    u16::try_from(len).map_err(|_| AcmeError::Config("rfc2136: field exceeds 64 KiB".into()))
}

fn time48(seconds: u64) -> Result<[u8; 6], AcmeError> {
    if seconds >> 48 != 0 {
        return Err(AcmeError::Config(
            "rfc2136: time does not fit 48 bits".into(),
        ));
    }
    let wide = seconds.to_be_bytes();
    let mut out = [0_u8; 6];
    out.copy_from_slice(wide.get(2..).unwrap_or_default());
    Ok(out)
}

/// Skips a possibly compressed name and returns the offset after it.
fn skip_name(bytes: &[u8], mut at: usize) -> Result<usize, AcmeError> {
    loop {
        let len = *bytes.get(at).ok_or_else(truncated)?;
        match len {
            0 => return Ok(at.saturating_add(1)),
            // A compression pointer ends the name in two bytes.
            0xc0..=0xff => return slice(bytes, at, 2).map(|_| at.saturating_add(2)),
            0x40..=0xbf => {
                return Err(AcmeError::Config(
                    "rfc2136: server answer uses an unknown label type".into(),
                ));
            }
            _ => at = at.saturating_add(1).saturating_add(usize::from(len)),
        }
    }
}

/// Skips one resource record and returns the offset after it.
fn skip_record(bytes: &[u8], at: usize) -> Result<usize, AcmeError> {
    let at = skip_name(bytes, at)?.saturating_add(8);
    let rdlen = usize::from(u16_at(bytes, at)?);
    let end = at.saturating_add(2).saturating_add(rdlen);
    if end > bytes.len() {
        return Err(truncated());
    }
    Ok(end)
}

/// Reads a name that may use compression pointers and returns it with the
/// offset after it in the record. Pointers must point strictly backwards, so
/// a pointer loop cannot occur.
fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), AcmeError> {
    let mut labels = Vec::new();
    let mut at = start;
    let mut end = None;
    loop {
        let len = *bytes.get(at).ok_or_else(truncated)?;
        match len {
            0 => return Ok((labels.join("."), end.unwrap_or(at.saturating_add(1)))),
            0xc0..=0xff => {
                let target = usize::from(u16_at(bytes, at)? & 0x3fff);
                if target >= at {
                    return Err(AcmeError::Config(
                        "rfc2136: server answer has a forward name pointer".into(),
                    ));
                }
                end.get_or_insert(at.saturating_add(2));
                at = target;
            }
            0x40..=0xbf => {
                return Err(AcmeError::Config(
                    "rfc2136: server answer uses an unknown label type".into(),
                ));
            }
            _ => {
                let from = at.saturating_add(1);
                let label = slice(bytes, from, usize::from(len))?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                at = from.saturating_add(usize::from(len));
            }
        }
    }
}

const fn tsig_error_name(error: u16) -> &'static str {
    match error {
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        22 => "BADTRUNC",
        _ => "unknown",
    }
}

const fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    const TSIG_B64: &str = "ZGV0ZW50LXRzaWctdGVzdC1zZWNyZXQtMzItYnl0ZXM=";
    const T: u64 = 1_700_000_000;
    const ID: u16 = 0x1234;

    /// The UPDATE `update_message` builds for `_acme-challenge.example.com`
    /// in `example.com` with value `digest-value-42`, id 0x1234.
    const UNSIGNED: &str = "123428000001000000020000076578616d706c6503636f6d00000600010f5f61636d652d6368616c6c656e6765076578616d706c6503636f6d00001000ff0000000000000f5f61636d652d6368616c6c656e6765076578616d706c6503636f6d00001000010000003c00100f6469676573742d76616c75652d3432";
    /// `UNSIGNED` signed by this module at `T`. dnspython 2.8.0 verifies it
    /// and reports this MAC: `uv run testdata/tsig_fixture.py`.
    const SIGNED: &str = "123428000001000000020001076578616d706c6503636f6d00000600010f5f61636d652d6368616c6c656e6765076578616d706c6503636f6d00001000ff0000000000000f5f61636d652d6368616c6c656e6765076578616d706c6503636f6d00001000010000003c00100f6469676573742d76616c75652d3432016b076578616d706c6503636f6d0000fa00ff00000000003d0b686d61632d7368613235360000006553f100012c002016d6dfbd1e1f23ed45663cd8efe21233c1f64b2c616fa8034387f5532da75ab7123400000000";
    const MAC: &str = "16d6dfbd1e1f23ed45663cd8efe21233c1f64b2c616fa8034387f5532da75ab7";
    /// dnspython's signed answers to `SIGNED` at `T + 5`: NOERROR and REFUSED.
    /// The TSIG owner name is compressed (`016b c00c`).
    const ANSWER_OK: &str = "1234a8000001000000000001076578616d706c6503636f6d0000060001016bc00c00fa00ff00000000003d0b686d61632d7368613235360000006553f105012c0020e051e4d3fec2c43505626ecc378f5b7f871cb3b489270f3a3fc874890f5c4a7d123400000000";
    const ANSWER_REFUSED: &str = "1234a8050001000000000001076578616d706c6503636f6d0000060001016bc00c00fa00ff00000000003d0b686d61632d7368613235360000006553f105012c0020a8330e66a7fe9c3cc7e4d092e4682a47770b2acddccd5dbe467dce51786f34a0123400000000";

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("zz"), 16).unwrap_or(0xee)
            })
            .collect()
    }

    fn key() -> Result<Key, AcmeError> {
        Key::new("K.Example.COM", Algorithm::Sha256, TSIG_B64)
    }

    fn verify(answer: &[u8], now: u64) -> Result<(), AcmeError> {
        key()?.verify_response(answer, ID, &hex(MAC), now)
    }

    fn message(result: Result<(), AcmeError>) -> String {
        result.err().map(|err| err.to_string()).unwrap_or_default()
    }

    #[test]
    fn a_signed_update_matches_the_bytes_dnspython_verified() -> R {
        let (signed, mac) = key()?.sign(&hex(UNSIGNED), T)?;
        assert_eq!(signed, hex(SIGNED));
        assert_eq!(mac, hex(MAC));
        Ok(())
    }

    #[test]
    fn a_dnspython_signed_answer_verifies() -> R {
        verify(&hex(ANSWER_OK), T + 5)?;
        verify(&hex(ANSWER_OK), T + 5 + u64::from(FUDGE))?;
        Ok(())
    }

    #[test]
    fn a_refused_answer_reports_its_rcode() {
        let text = message(verify(&hex(ANSWER_REFUSED), T + 5));
        assert!(
            text.ends_with("refused the UPDATE: RCODE REFUSED (5)"),
            "{text}"
        );
    }

    #[test]
    fn every_changed_byte_of_a_signed_answer_is_refused() {
        let good = hex(ANSWER_OK);
        for at in 0..good.len() {
            let mut bad = good.clone();
            if let Some(byte) = bad.get_mut(at) {
                *byte ^= 0x01;
            }
            assert!(
                verify(&bad, T + 5).is_err(),
                "byte {at} changed but verified"
            );
        }
    }

    #[test]
    fn every_truncation_of_a_signed_answer_is_refused() {
        let good = hex(ANSWER_OK);
        for len in 0..good.len() {
            assert!(verify(good.get(..len).unwrap_or_default(), T + 5).is_err());
        }
    }

    #[test]
    fn an_answer_to_another_request_is_refused() -> R {
        let text = message(key()?.verify_response(&hex(ANSWER_OK), ID, &[0; 32], T + 5));
        assert!(text.ends_with("has a bad TSIG MAC"), "{text}");
        let text = message(key()?.verify_response(&hex(ANSWER_OK), ID ^ 1, &hex(MAC), T + 5));
        assert!(text.ends_with("has the wrong message id"), "{text}");
        Ok(())
    }

    #[test]
    fn an_answer_outside_the_clock_skew_is_refused() {
        let late = T + 5 + u64::from(FUDGE) + 1;
        let text = message(verify(&hex(ANSWER_OK), late));
        assert!(text.ends_with("outside the allowed clock skew"), "{text}");
    }

    #[test]
    fn an_answer_from_another_key_or_algorithm_is_refused() -> R {
        let other = Key::new("other.example.com", Algorithm::Sha256, TSIG_B64)?;
        let text = message(other.verify_response(&hex(ANSWER_OK), ID, &hex(MAC), T + 5));
        assert!(text.ends_with("is signed with another key"), "{text}");
        let sha512 = Key::new("k.example.com", Algorithm::Sha512, TSIG_B64)?;
        let text = message(sha512.verify_response(&hex(ANSWER_OK), ID, &hex(MAC), T + 5));
        assert!(text.ends_with("uses another TSIG algorithm"), "{text}");
        Ok(())
    }

    #[test]
    fn an_unsigned_answer_is_refused_and_names_its_rcode() {
        // Header only: id, QR + RCODE REFUSED, no records.
        let mut answer = vec![0x12, 0x34, 0xa8, 0x05];
        answer.extend_from_slice(&[0; 8]);
        let text = message(verify(&answer, T));
        assert!(
            text.ends_with("is not signed (RCODE REFUSED (5), not trusted)"),
            "{text}"
        );
        // A query (QR clear) is not an answer.
        let mut query = hex(ANSWER_OK);
        if let Some(flags) = query.get_mut(2) {
            *flags &= 0x7f;
        }
        assert!(message(verify(&query, T + 5)).ends_with("is not a response"));
    }

    #[test]
    fn a_tsig_error_in_the_answer_is_named() {
        let mut answer = hex(ANSWER_OK);
        // The TSIG error field is the 4th- and 3rd-last bytes.
        let at = answer.len() - 4;
        if let Some(error) = answer.get_mut(at..at + 2) {
            error.copy_from_slice(&16_u16.to_be_bytes());
        }
        let text = message(verify(&answer, T + 5));
        assert!(text.ends_with("carries TSIG error BADSIG (16)"), "{text}");
    }

    #[test]
    fn our_own_answer_signer_round_trips_with_the_verifier() -> R {
        let key = key()?;
        let (_, request_mac) = key.sign(&hex(UNSIGNED), T)?;
        // The unsigned part of dnspython's answer, re-signed here.
        let tsig_at = 12 + 17; // header + zone section
        let mut unsigned = hex(ANSWER_OK).get(..tsig_at).unwrap_or_default().to_vec();
        put_u16(&mut unsigned, ARCOUNT_AT, 0)?;
        let answer = key.sign_answer(&unsigned, T + 5, &request_mac)?;
        key.verify_response(&answer, ID, &request_mac, T + 5)?;
        Ok(())
    }

    #[test]
    fn keys_refuse_bad_secrets_without_quoting_them() {
        for secret in ["not base64!", ""] {
            let text = Key::new("k.example.com", Algorithm::Sha256, secret)
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default();
            assert!(
                text.starts_with("dns provider error: rfc2136: TSIG key value is"),
                "{text}"
            );
            if !secret.is_empty() {
                assert!(!text.contains(secret), "{text}");
            }
        }
    }

    #[test]
    fn only_the_sha2_algorithms_parse() {
        for name in Algorithm::NAMES {
            assert_eq!(Algorithm::parse(name).map(Algorithm::name), Some(name));
        }
        assert_eq!(Algorithm::parse("HMAC-SHA256"), Some(Algorithm::Sha256));
        for refused in [
            "hmac-md5",
            "hmac-md5.sig-alg.reg.int",
            "hmac-sha1",
            "gss-tsig",
            "",
        ] {
            assert_eq!(Algorithm::parse(refused), None, "{refused}");
        }
    }

    #[test]
    fn signing_refuses_a_message_that_is_too_short_or_already_signed() -> R {
        let key = key()?;
        assert!(key.sign(&[0; 11], T).is_err());
        assert!(key.sign(&hex(SIGNED), T).is_err());
        assert!(key.sign(&hex(UNSIGNED), 1 << 48).is_err());
        Ok(())
    }

    #[test]
    fn name_pointers_must_point_backwards() {
        // A pointer to itself at offset 0 and a forward pointer.
        assert!(read_name(&[0xc0, 0x00], 0).is_err());
        assert!(read_name(&[0xc0, 0x02, 0x00], 0).is_err());
        assert!(read_name(&[0x40], 0).is_err());
        assert!(skip_name(&[0x80], 0).is_err());
        let (name, end) = read_name(&[1, b'a', 0, 1, b'b', 0xc0, 0x00], 3).unwrap_or_default();
        assert_eq!((name.as_str(), end), ("b.a", 7));
    }

    #[test]
    fn random_ids_vary() -> R {
        let ids = (0..8).map(|_| random_id()).collect::<Result<Vec<_>, _>>()?;
        assert!(ids.windows(2).any(|pair| pair.first() != pair.last()));
        Ok(())
    }

    #[test]
    fn a_tcp_exchange_frames_the_message_both_ways() -> R {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let server = listener.local_addr()?.to_string();
        let echo = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let (mut stream, _) = listener.accept()?;
            let mut len = [0; 2];
            stream.read_exact(&mut len)?;
            let mut got = vec![0; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut got)?;
            stream.write_all(&[0, 3, 7, 8, 9])?;
            Ok(got)
        });
        assert_eq!(exchange_tcp(&server, b"hello")?, vec![7, 8, 9]);
        assert_eq!(echo.join().map_err(|_| "server panicked")??, b"hello");
        Ok(())
    }

    #[test]
    fn a_tcp_exchange_names_the_server_it_could_not_reach() -> R {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let server = listener.local_addr()?.to_string();
        drop(listener);
        let text = exchange_tcp(&server, b"x")
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(
            text.contains(&format!("rfc2136: {server}: cannot connect")),
            "{text}"
        );
        let text = exchange_tcp("no port here", b"x")
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(text.contains("cannot resolve"), "{text}");
        Ok(())
    }

    #[test]
    fn a_tcp_exchange_reports_a_closed_connection() -> R {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let server = listener.local_addr()?.to_string();
        let closer = std::thread::spawn(move || listener.accept().map(drop));
        let text = exchange_tcp(&server, b"x")
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(text.contains("receive"), "{text}");
        closer.join().map_err(|_| "server panicked")??;
        Ok(())
    }

    #[test]
    fn error_names_cover_the_known_codes() {
        for (code, name) in [
            (16, "BADSIG"),
            (17, "BADKEY"),
            (18, "BADTIME"),
            (22, "BADTRUNC"),
            (99, "unknown"),
        ] {
            assert_eq!(tsig_error_name(code), name);
        }
        let names = (1..=11).map(rcode_name).collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
                "NXRRSET", "NOTAUTH", "NOTZONE", "unknown"
            ]
        );
    }
}
