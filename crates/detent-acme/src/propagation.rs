//! The dns-01 propagation check: before the CA is told to validate, ask every
//! authoritative nameserver of the zone for the `_acme-challenge` TXT value.
//!
//! [`PropagationCheck`] wraps any [`DnsProvider`]. `present` and `delete` go
//! to the provider; `wait_propagated` first asks the provider (its own API
//! readback, when it has one) and then queries the zone's nameservers. It
//! answers [`AcmeError::NotPropagated`] until all of them return the value.
//! The order flow owns the polling (`PropagationWait`: doubling pauses up to
//! a cap, bounded by a timeout), so a check never sleeps.
//!
//! Servers: with `nameservers` set, exactly those are asked (split-horizon
//! DNS, a private zone, a test responder). Otherwise the zone is found by
//! asking the system resolvers (`/etc/resolv.conf`) for the NS records of the
//! name and of each parent, nearest first, and the NS host names are resolved
//! the same way. A host with an A record is queried on IPv4 only, so an
//! IPv4-only host never waits for an IPv6 address it cannot reach. A CNAME at
//! the challenge name (acme-dns, delegated challenge zones) is followed, a few
//! hops at most, and the target's zone is asked in turn.
//!
//! DNS is plain UDP, with TCP when an answer is truncated, through
//! `hickory-net` with no DNSSEC, TLS or HTTPS features. Each query runs on
//! a scoped thread with a private current-thread runtime, as the HTTPS
//! transport does, because [`DnsProvider`] is synchronous.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_net::client::ClientHandle as _;
use hickory_net::proto::op::{DnsResponse, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;

use crate::{AcmeError, DnsProvider, DnsRecord, PropagationWait};

/// The first pause between two checks.
pub const INITIAL_DELAY: Duration = Duration::from_secs(2);

/// The longest pause between two checks.
pub const MAX_DELAY: Duration = Duration::from_secs(15);

/// How long the check waits for all nameservers when `[acme]` says nothing.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// The wait for one answer from one server.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// The cap on one call into the resolver code: a UDP try, a TCP retry and the
/// connect all fit, and a dead server cannot hold the order for longer.
const CALL_TIMEOUT: Duration = Duration::from_secs(12);

/// CNAME hops followed from the challenge name.
const MAX_CNAME_HOPS: usize = 4;

/// Nameservers asked per zone; a zone has no more than a handful.
const MAX_SERVERS: usize = 8;

/// The DNS port.
const DNS_PORT: u16 = 53;

/// The TXT answer of one server for one name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxtAnswer {
    /// The TXT values at the name (the strings of one record joined).
    pub values: Vec<String>,
    /// The target of a CNAME at the name, when there is one.
    pub cname: Option<String>,
}

/// Where the check gets its facts. [`DnsAuthority`] is the real one; tests
/// put their own in.
pub trait Authority: Send + Sync {
    /// The addresses of the authoritative nameservers for `name`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Config`] when no lookup can be made at all (no system
    /// resolver), [`AcmeError::NotPropagated`] when a lookup failed.
    fn servers(&self, name: &str) -> Result<Vec<SocketAddr>, AcmeError>;

    /// The TXT values at `name` as `server` states them. A name that does not
    /// exist is an empty answer, not an error.
    ///
    /// # Errors
    ///
    /// The reason the server gave no usable answer (no reply, `REFUSED`).
    fn txt(&self, server: SocketAddr, name: &str) -> Result<TxtAnswer, String>;
}

/// Asks the zone's nameservers once and says whether all of them hold the
/// value of `record`.
///
/// # Errors
///
/// [`AcmeError::NotPropagated`] naming the servers that lack the value, or
/// the errors of [`Authority::servers`]; [`AcmeError::Config`] after too many
/// CNAME hops.
pub fn probe(authority: &dyn Authority, record: &DnsRecord) -> Result<(), AcmeError> {
    let mut name = record.fqdn().to_owned();
    for _ in 0..=MAX_CNAME_HOPS {
        let servers = authority.servers(&name)?;
        if servers.is_empty() {
            return Err(AcmeError::NotPropagated(format!(
                "{name}: no authoritative nameserver found"
            )));
        }
        let mut lacking: Vec<String> = Vec::new();
        let mut redirect: Option<String> = None;
        for server in &servers {
            match authority.txt(*server, &name) {
                Ok(answer) if answer.values.iter().any(|v| v == record.value()) => {}
                Ok(TxtAnswer {
                    values,
                    cname: Some(target),
                }) if values.is_empty() => {
                    redirect = Some(target);
                    break;
                }
                Ok(_) => lacking.push(format!("{server} (value absent)")),
                Err(why) => lacking.push(format!("{server} ({why})")),
            }
        }
        if let Some(target) = redirect {
            name = target;
            continue;
        }
        return if lacking.is_empty() {
            Ok(())
        } else {
            Err(AcmeError::NotPropagated(format!(
                "{name}: {} of {} nameservers lack the value: {}",
                lacking.len(),
                servers.len(),
                lacking.join(", ")
            )))
        };
    }
    Err(AcmeError::Config(format!(
        "{}: more than {MAX_CNAME_HOPS} CNAME hops",
        record.fqdn()
    )))
}

/// A [`DnsProvider`] that adds the nameserver check to `inner`.
pub struct PropagationCheck {
    inner: Box<dyn DnsProvider>,
    authority: Box<dyn Authority>,
    wait: PropagationWait,
}

impl PropagationCheck {
    /// Checks the real nameservers: `nameservers` when it is not empty, else
    /// the ones found through the system resolvers. `timeout` bounds the
    /// whole wait.
    #[must_use]
    pub fn new(
        inner: Box<dyn DnsProvider>,
        nameservers: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Self {
        Self::with_authority(inner, Box::new(DnsAuthority::new(nameservers)), timeout)
    }

    /// As [`PropagationCheck::new`] with the nameserver facts from
    /// `authority`.
    #[must_use]
    pub fn with_authority(
        inner: Box<dyn DnsProvider>,
        authority: Box<dyn Authority>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            authority,
            wait: PropagationWait {
                initial_delay: INITIAL_DELAY,
                max_delay: MAX_DELAY,
                timeout,
            },
        }
    }
}

impl DnsProvider for PropagationCheck {
    fn present(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.inner.present(record)
    }

    fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.inner.delete(record)
    }

    fn wait_propagated(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.inner.wait_propagated(record)?;
        probe(self.authority.as_ref(), record)
    }

    fn propagation_wait(&self) -> PropagationWait {
        self.wait
    }
}

/// Reads the `nameserver` lines of a `resolv.conf` into DNS addresses.
#[must_use]
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then_some(())?;
            let ip: IpAddr = words.next()?.parse().ok()?;
            Some(SocketAddr::new(ip, DNS_PORT))
        })
        .collect()
}

/// The real [`Authority`]: `hickory-net` over UDP and TCP.
pub struct DnsAuthority {
    /// Asked in place of the zone's own servers when not empty.
    fixed: Vec<SocketAddr>,
    /// The system resolvers; `None` reads `/etc/resolv.conf` on first use.
    resolvers: Option<Vec<SocketAddr>>,
    /// The port of the NS hosts; 53 except in tests.
    ns_port: u16,
}

impl DnsAuthority {
    /// An authority that asks `fixed`, or finds the zone's servers through
    /// `/etc/resolv.conf` when `fixed` is empty.
    #[must_use]
    pub fn new(fixed: Vec<SocketAddr>) -> Self {
        Self {
            fixed,
            resolvers: None,
            ns_port: DNS_PORT,
        }
    }

    fn system_resolvers(&self) -> Result<Vec<SocketAddr>, AcmeError> {
        if let Some(resolvers) = &self.resolvers {
            return Ok(resolvers.clone());
        }
        let text = std::fs::read_to_string("/etc/resolv.conf").map_err(|err| {
            AcmeError::Config(format!("propagation check: /etc/resolv.conf: {err}"))
        })?;
        let resolvers = parse_resolv_conf(&text);
        if resolvers.is_empty() {
            return Err(AcmeError::Config(
                "propagation check: /etc/resolv.conf has no nameserver; set \
                 [acme] propagation_nameservers"
                    .into(),
            ));
        }
        Ok(resolvers)
    }
}

impl Authority for DnsAuthority {
    fn servers(&self, name: &str) -> Result<Vec<SocketAddr>, AcmeError> {
        if !self.fixed.is_empty() {
            return Ok(self.fixed.clone());
        }
        let resolvers = self.system_resolvers()?;
        let name = parse_name(name).map_err(AcmeError::Config)?;
        let ns_port = self.ns_port;
        block_on(async move { zone_servers(&resolvers, &name, ns_port).await })?
            .map_err(AcmeError::NotPropagated)
    }

    fn txt(&self, server: SocketAddr, name: &str) -> Result<TxtAnswer, String> {
        let name = parse_name(name)?;
        block_on(async move {
            let response = query(server, &name, RecordType::TXT).await?;
            Ok(txt_answer(&response, &name))
        })
        .map_err(|err| err.to_string())?
    }
}

/// `name` as an absolute DNS name.
fn parse_name(name: &str) -> Result<Name, String> {
    let mut parsed = Name::from_ascii(name).map_err(|err| format!("{name}: {err}"))?;
    parsed.set_fqdn(true);
    Ok(parsed)
}

/// Runs `future` to its end on a scoped thread with a private current-thread
/// runtime, within [`CALL_TIMEOUT`].
fn block_on<F>(future: F) -> Result<F::Output, AcmeError>
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let fail = |what: &str| AcmeError::NotPropagated(format!("dns query: {what}"));
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| fail(&format!("runtime: {err}")))?;
                runtime.block_on(async {
                    tokio::time::timeout(CALL_TIMEOUT, future)
                        .await
                        .map_err(|_| fail("timed out"))
                })
            })
            .join()
            .map_err(|_| fail("thread panicked"))?
    })
}

/// One query to `server`: UDP, then TCP when the UDP answer is truncated.
async fn query(
    server: SocketAddr,
    name: &Name,
    record_type: RecordType,
) -> Result<DnsResponse, String> {
    let response = ask_udp(server, name, record_type).await?;
    if response.metadata.truncation {
        return ask_tcp(server, name, record_type).await;
    }
    Ok(response)
}

async fn ask_udp(
    server: SocketAddr,
    name: &Name,
    record_type: RecordType,
) -> Result<DnsResponse, String> {
    let mut client = UdpClientStream::builder(server, TokioRuntimeProvider::new())
        .with_timeout(Some(QUERY_TIMEOUT))
        .exchange();
    let answer = client.query(name.clone(), DNSClass::IN, record_type).await;
    checked(answer.map_err(|err| format!("udp: {err}"))?)
}

async fn ask_tcp(
    server: SocketAddr,
    name: &Name,
    record_type: RecordType,
) -> Result<DnsResponse, String> {
    // The provider owns the set of background tasks: `exchange` drops its
    // copy when it returns, so keep ours until the answer is in, or the
    // background task that reads the socket is aborted.
    let provider = TokioRuntimeProvider::new();
    let mut client = TcpClientStream::exchange(server, None, QUERY_TIMEOUT, None, provider.clone())
        .await
        .map_err(|err| format!("tcp: {err}"))?;
    let answer = client.query(name.clone(), DNSClass::IN, record_type).await;
    drop(provider);
    checked(answer.map_err(|err| format!("tcp: {err}"))?)
}

/// Refuses an answer that is not a usable one. A name that does not exist
/// (`NXDOMAIN`) and a name without the type (`NOERROR`, no data) are usable:
/// they say the record is not there yet.
fn checked(response: DnsResponse) -> Result<DnsResponse, String> {
    match response.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(response),
        other => Err(other.to_string()),
    }
}

/// The TXT values and the CNAME target at `name` in `response`.
fn txt_answer(response: &DnsResponse, name: &Name) -> TxtAnswer {
    let mut answer = TxtAnswer::default();
    for record in &response.answers {
        if &record.name != name {
            continue;
        }
        match &record.data {
            RData::TXT(txt) => {
                let joined: Vec<u8> = txt
                    .txt_data
                    .iter()
                    .flat_map(|s| s.iter().copied())
                    .collect();
                answer
                    .values
                    .push(String::from_utf8_lossy(&joined).into_owned());
            }
            RData::CNAME(target) => {
                answer.cname = Some(target.0.to_ascii().trim_end_matches('.').to_owned());
            }
            _ => {}
        }
    }
    answer
}

/// The first answer to `name`/`record_type` from any of `resolvers`.
async fn ask_any(
    resolvers: &[SocketAddr],
    name: &Name,
    record_type: RecordType,
) -> Result<DnsResponse, String> {
    let mut last = "no resolver".to_owned();
    for resolver in resolvers {
        match query(*resolver, name, record_type).await {
            Ok(response) => return Ok(response),
            Err(why) => last = format!("{resolver}: {why}"),
        }
    }
    Err(last)
}

/// The NS hosts of the zone that holds `name`: the NS set of the nearest
/// name, going up from `name`, that has one; then their addresses.
async fn zone_servers(
    resolvers: &[SocketAddr],
    name: &Name,
    ns_port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let mut cursor = name.clone();
    // Stop at two labels: a TLD is never the zone of a certificate name.
    while cursor.num_labels() >= 2 {
        let response = ask_any(resolvers, &cursor, RecordType::NS).await?;
        let hosts: Vec<Name> = response
            .answers
            .iter()
            .filter(|r| r.name == cursor)
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.clone()),
                _ => None,
            })
            .take(MAX_SERVERS)
            .collect();
        if !hosts.is_empty() {
            return host_addresses(resolvers, &hosts, ns_port).await;
        }
        cursor = cursor.base_name();
    }
    Err(format!("{name}: no NS records found"))
}

/// The address of each NS host, IPv4 first; IPv6 only for a host without an
/// A record.
async fn host_addresses(
    resolvers: &[SocketAddr],
    hosts: &[Name],
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let mut found: Vec<SocketAddr> = Vec::new();
    for host in hosts {
        let mut addresses: Vec<IpAddr> = Vec::new();
        for record_type in [RecordType::A, RecordType::AAAA] {
            let response = ask_any(resolvers, host, record_type).await?;
            addresses.extend(response.answers.iter().filter_map(|r| match &r.data {
                RData::A(a) if &r.name == host => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) if &r.name == host => Some(IpAddr::V6(a.0)),
                _ => None,
            }));
            if !addresses.is_empty() {
                break;
            }
        }
        for ip in addresses {
            let socket = SocketAddr::new(ip, port);
            if !found.contains(&socket) {
                found.push(socket);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    const NAME: &str = "_acme-challenge.example.test";
    const VALUE: &str = "digest-value";

    fn record() -> Result<DnsRecord, AcmeError> {
        DnsRecord::new(NAME, VALUE)
    }

    fn server(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], 53))
    }

    /// Answers from a table; a server missing from the table is down.
    #[derive(Default)]
    struct Fake {
        zone: HashMap<String, Vec<SocketAddr>>,
        txt: HashMap<(SocketAddr, String), TxtAnswer>,
    }

    impl Fake {
        fn serving(mut self, name: &str, servers: &[SocketAddr]) -> Self {
            self.zone.insert(name.to_owned(), servers.to_vec());
            self
        }

        fn holding(mut self, server: SocketAddr, name: &str, values: &[&str]) -> Self {
            let values = values.iter().map(|v| (*v).to_owned()).collect();
            self.txt.insert(
                (server, name.to_owned()),
                TxtAnswer {
                    values,
                    cname: None,
                },
            );
            self
        }

        fn redirecting(mut self, server: SocketAddr, name: &str, target: &str) -> Self {
            self.txt.insert(
                (server, name.to_owned()),
                TxtAnswer {
                    values: Vec::new(),
                    cname: Some(target.to_owned()),
                },
            );
            self
        }
    }

    impl Authority for Fake {
        fn servers(&self, name: &str) -> Result<Vec<SocketAddr>, AcmeError> {
            Ok(self.zone.get(name).cloned().unwrap_or_default())
        }

        fn txt(&self, server: SocketAddr, name: &str) -> Result<TxtAnswer, String> {
            self.txt
                .get(&(server, name.to_owned()))
                .cloned()
                .ok_or_else(|| "no reply".to_owned())
        }
    }

    #[test]
    fn every_server_holding_the_value_passes() -> R {
        let (a, b) = (server(1), server(2));
        let fake = Fake::default()
            .serving(NAME, &[a, b])
            .holding(a, NAME, &["other", VALUE])
            .holding(b, NAME, &[VALUE]);
        probe(&fake, &record()?)?;
        Ok(())
    }

    #[test]
    fn a_server_with_another_value_fails() -> R {
        let (a, b) = (server(1), server(2));
        let fake = Fake::default()
            .serving(NAME, &[a, b])
            .holding(a, NAME, &[VALUE])
            .holding(b, NAME, &["stale"]);
        let err = probe(&fake, &record()?).err().ok_or("passed")?;
        let AcmeError::NotPropagated(why) = err else {
            return Err("wrong error".into());
        };
        assert!(why.contains("1 of 2"), "{why}");
        assert!(why.contains("192.0.2.2:53"), "{why}");
        assert!(!why.contains("192.0.2.1:53"), "{why}");
        Ok(())
    }

    #[test]
    fn partial_propagation_names_the_servers_still_behind() -> R {
        let (a, b, c) = (server(1), server(2), server(3));
        // `b` has not the record yet and `c` does not answer.
        let fake = Fake::default()
            .serving(NAME, &[a, b, c])
            .holding(a, NAME, &[VALUE])
            .holding(b, NAME, &[]);
        let err = probe(&fake, &record()?).err().ok_or("passed")?;
        let AcmeError::NotPropagated(why) = err else {
            return Err("wrong error".into());
        };
        assert!(why.contains("2 of 3"), "{why}");
        assert!(why.contains("192.0.2.2:53 (value absent)"), "{why}");
        assert!(why.contains("192.0.2.3:53 (no reply)"), "{why}");
        Ok(())
    }

    #[test]
    fn a_zone_without_nameservers_fails() -> R {
        let err = probe(&Fake::default(), &record()?).err().ok_or("passed")?;
        assert!(matches!(err, AcmeError::NotPropagated(_)), "{err:?}");
        Ok(())
    }

    #[test]
    fn a_cname_is_followed_into_the_target_zone() -> R {
        let (a, b) = (server(1), server(2));
        let target = "u1.auth.example.test";
        let fake = Fake::default()
            .serving(NAME, &[a])
            .redirecting(a, NAME, target)
            .serving(target, &[b])
            .holding(b, target, &[VALUE]);
        probe(&fake, &record()?)?;
        // The same chain with the target still empty is not propagated.
        let behind = Fake::default()
            .serving(NAME, &[a])
            .redirecting(a, NAME, target)
            .serving(target, &[b])
            .holding(b, target, &[]);
        assert!(matches!(
            probe(&behind, &record()?),
            Err(AcmeError::NotPropagated(_))
        ));
        Ok(())
    }

    #[test]
    fn a_cname_loop_is_a_config_error() -> R {
        let a = server(1);
        let other = "loop.example.test";
        let fake = Fake::default()
            .serving(NAME, &[a])
            .serving(other, &[a])
            .redirecting(a, NAME, other)
            .redirecting(a, other, NAME);
        assert!(matches!(
            probe(&fake, &record()?),
            Err(AcmeError::Config(_))
        ));
        Ok(())
    }

    #[test]
    fn resolv_conf_nameservers_are_read() {
        let text = "# comment\nsearch lan\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n\
                    nameserver not-an-address\nnameserver\noptions ndots:1\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                SocketAddr::from(([192, 0, 2, 53], 53)),
                "[2001:db8::53]:53".parse().unwrap_or(server(0)),
            ]
        );
        assert!(parse_resolv_conf("").is_empty());
    }

    /// A provider that records its calls and answers `wait_propagated` from
    /// a script.
    struct Scripted {
        calls: Mutex<Vec<&'static str>>,
        waits: Mutex<Vec<Result<(), AcmeError>>>,
    }

    impl DnsProvider for Scripted {
        fn present(&self, _: &DnsRecord) -> Result<(), AcmeError> {
            self.calls
                .lock()
                .map_err(|_| AcmeError::Config("poisoned".into()))?
                .push("present");
            Ok(())
        }

        fn delete(&self, _: &DnsRecord) -> Result<(), AcmeError> {
            self.calls
                .lock()
                .map_err(|_| AcmeError::Config("poisoned".into()))?
                .push("delete");
            Ok(())
        }

        fn wait_propagated(&self, _: &DnsRecord) -> Result<(), AcmeError> {
            self.calls
                .lock()
                .map_err(|_| AcmeError::Config("poisoned".into()))?
                .push("wait");
            self.waits
                .lock()
                .map_err(|_| AcmeError::Config("poisoned".into()))?
                .pop()
                .unwrap_or(Ok(()))
        }
    }

    #[test]
    fn the_check_asks_the_provider_first_and_delegates_the_rest() -> R {
        let (a, b) = (server(1), server(2));
        let fake = Fake::default()
            .serving(NAME, &[a, b])
            .holding(a, NAME, &[VALUE])
            .holding(b, NAME, &[VALUE]);
        let inner = Scripted {
            calls: Mutex::new(Vec::new()),
            waits: Mutex::new(vec![Err(AcmeError::NotPropagated("api".into()))]),
        };
        let check = PropagationCheck::with_authority(
            Box::new(inner),
            Box::new(fake),
            Duration::from_secs(9),
        );
        let record = record()?;
        check.present(&record)?;
        // The provider's own readback fails first: the nameservers are not asked.
        assert!(matches!(
            check.wait_propagated(&record),
            Err(AcmeError::NotPropagated(why)) if why == "api"
        ));
        check.wait_propagated(&record)?;
        check.delete(&record)?;
        assert_eq!(check.propagation_wait().timeout, Duration::from_secs(9));
        assert_eq!(check.propagation_wait().initial_delay, INITIAL_DELAY);
        Ok(())
    }

    // -- The real authority against mock DNS servers on loopback ---------------

    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use hickory_net::proto::op::{Message, OpCode, Query};
    use hickory_net::proto::rr::Record;
    use hickory_net::proto::rr::rdata::{A, CNAME, NS, TXT};

    /// What a mock server answers: the code, the answers and the TC bit.
    struct Reply {
        code: ResponseCode,
        answers: Vec<Record>,
        truncated: bool,
    }

    impl Reply {
        fn answers(answers: Vec<Record>) -> Self {
            Self {
                code: ResponseCode::NoError,
                answers,
                truncated: false,
            }
        }

        fn code(code: ResponseCode) -> Self {
            Self {
                code,
                answers: Vec::new(),
                truncated: false,
            }
        }
    }

    /// A DNS server on `127.0.0.1`, UDP and TCP on one port.
    struct Mock {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        threads: Vec<std::thread::JoinHandle<()>>,
    }

    /// Gets each query and whether it came over TCP.
    type Handler = Arc<dyn Fn(&Query, bool) -> Reply + Send + Sync>;

    fn respond(handler: &Handler, request: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let request = Message::from_vec(request).ok()?;
        let query = request.queries.first()?.clone();
        let reply = handler(&query, tcp);
        let mut message = Message::response(request.metadata.id, OpCode::Query);
        message.metadata.response_code = reply.code;
        message.metadata.truncation = reply.truncated;
        message.add_query(query).add_answers(reply.answers);
        message.to_vec().ok()
    }

    impl Mock {
        fn start(handler: Handler) -> Result<Self, Box<dyn std::error::Error>> {
            let udp = UdpSocket::bind("127.0.0.1:0")?;
            let addr = udp.local_addr()?;
            let tcp = TcpListener::bind(addr)?;
            udp.set_read_timeout(Some(Duration::from_millis(25)))?;
            tcp.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let udp_thread = {
                let (stop, handler) = (Arc::clone(&stop), Arc::clone(&handler));
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1500];
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok((n, from)) = udp.recv_from(&mut buf)
                            && let Some(packet) = buf.get(..n)
                            && let Some(out) = respond(&handler, packet, false)
                        {
                            let _ = udp.send_to(&out, from);
                        }
                    }
                })
            };
            let tcp_thread = {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let Ok((mut conn, _)) = tcp.accept() else {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        };
                        let _ = conn.set_nonblocking(false);
                        let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut len = [0u8; 2];
                        if conn.read_exact(&mut len).is_err() {
                            continue;
                        }
                        let mut request = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        if conn.read_exact(&mut request).is_err() {
                            continue;
                        }
                        if let Some(out) = respond(&handler, &request, true)
                            && let Ok(n) = u16::try_from(out.len())
                        {
                            let _ = conn.write_all(&n.to_be_bytes());
                            let _ = conn.write_all(&out);
                            // Keep the connection open until the client has
                            // read the answer, as a real server does.
                            std::thread::sleep(Duration::from_millis(300));
                        }
                    }
                })
            };
            Ok(Self {
                addr,
                stop,
                threads: vec![udp_thread, tcp_thread],
            })
        }
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap_or_default()
    }

    fn txt_record(owner: &str, strings: &[&str]) -> Record {
        let data = strings.iter().map(|s| (*s).to_owned()).collect();
        Record::from_rdata(name(owner), 60, RData::TXT(TXT::new(data)))
    }

    fn authority(fixed: Vec<SocketAddr>, resolvers: Vec<SocketAddr>, ns_port: u16) -> DnsAuthority {
        DnsAuthority {
            fixed,
            resolvers: Some(resolvers),
            ns_port,
        }
    }

    #[test]
    fn txt_values_come_back_joined_and_a_missing_name_is_empty() -> R {
        let mock = Mock::start(Arc::new(|query, _| {
            let asked = query.name().to_ascii();
            if asked.starts_with("_acme-challenge.here") {
                Reply::answers(vec![txt_record(&asked, &["abc-", "def"])])
            } else if asked.starts_with("_acme-challenge.alias") {
                let target = CNAME(name("target.example.test."));
                Reply::answers(vec![Record::from_rdata(
                    name(&asked),
                    60,
                    RData::CNAME(target),
                )])
            } else if asked.starts_with("_acme-challenge.refused") {
                Reply::code(ResponseCode::Refused)
            } else {
                Reply::code(ResponseCode::NXDomain)
            }
        }))?;
        let dns = authority(vec![mock.addr], Vec::new(), 53);
        let here = dns.txt(mock.addr, "_acme-challenge.here.example.test")?;
        assert_eq!(here.values, vec!["abc-def".to_owned()]);
        let absent = dns.txt(mock.addr, "_acme-challenge.absent.example.test")?;
        assert_eq!(absent, TxtAnswer::default());
        let alias = dns.txt(mock.addr, "_acme-challenge.alias.example.test")?;
        assert_eq!(alias.cname.as_deref(), Some("target.example.test"));
        let refused = dns.txt(mock.addr, "_acme-challenge.refused.example.test");
        assert!(refused.is_err(), "REFUSED must be an error");
        Ok(())
    }

    #[test]
    fn a_truncated_udp_answer_is_asked_again_over_tcp() -> R {
        let mock = Mock::start(Arc::new(|query, tcp| {
            let asked = query.name().to_ascii();
            if tcp {
                Reply::answers(vec![txt_record(&asked, &["over-tcp"])])
            } else {
                Reply {
                    code: ResponseCode::NoError,
                    answers: Vec::new(),
                    truncated: true,
                }
            }
        }))?;
        let dns = authority(vec![mock.addr], Vec::new(), 53);
        let answer = dns.txt(mock.addr, "_acme-challenge.big.example.test")?;
        assert_eq!(answer.values, vec!["over-tcp".to_owned()]);
        Ok(())
    }

    #[test]
    fn a_silent_server_is_an_error_not_a_hang() -> R {
        // A bound socket that never answers.
        let silent = UdpSocket::bind("127.0.0.1:0")?;
        let addr = silent.local_addr()?;
        let dns = authority(vec![addr], Vec::new(), 53);
        let started = std::time::Instant::now();
        let answer = dns.txt(addr, "_acme-challenge.x.example.test");
        assert!(answer.is_err());
        assert!(started.elapsed() < CALL_TIMEOUT.saturating_add(Duration::from_secs(2)));
        Ok(())
    }

    #[test]
    fn the_zone_servers_are_found_through_the_resolver() -> R {
        // The authoritative server for example.test.
        let value = Arc::new(Mutex::new("old".to_owned()));
        let served = Arc::clone(&value);
        let authoritative = Mock::start(Arc::new(move |query, _| {
            let asked = query.name().to_ascii();
            let current = served.lock().map(|v| v.clone()).unwrap_or_default();
            Reply::answers(vec![txt_record(&asked, &[current.as_str()])])
        }))?;
        // The resolver: NS only at the apex, one A record for the host, and a
        // AAAA that must not be asked while an A exists.
        let aaaa_asked = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&aaaa_asked);
        let resolver = Mock::start(Arc::new(move |query, _| {
            let asked = query.name().to_ascii();
            match (query.query_type(), asked.as_str()) {
                (RecordType::NS, "example.test.") => Reply::answers(vec![Record::from_rdata(
                    name("example.test."),
                    60,
                    RData::NS(NS(name("ns1.example.test."))),
                )]),
                (RecordType::A, "ns1.example.test.") => Reply::answers(vec![Record::from_rdata(
                    name("ns1.example.test."),
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                )]),
                (RecordType::AAAA, _) => {
                    seen.store(true, Ordering::Relaxed);
                    Reply::answers(Vec::new())
                }
                _ => Reply::answers(Vec::new()),
            }
        }))?;
        let dns = authority(Vec::new(), vec![resolver.addr], authoritative.addr.port());
        let servers = dns.servers("_acme-challenge.www.example.test")?;
        assert_eq!(servers, vec![authoritative.addr]);
        assert!(!aaaa_asked.load(Ordering::Relaxed));

        // The whole check, through the real transport.
        let record = DnsRecord::new("_acme-challenge.www.example.test", "new")?;
        let inner = Scripted {
            calls: Mutex::new(Vec::new()),
            waits: Mutex::new(Vec::new()),
        };
        let check = PropagationCheck::with_authority(
            Box::new(inner),
            Box::new(dns),
            Duration::from_secs(5),
        );
        let err = check
            .wait_propagated(&record)
            .err()
            .ok_or("old value passed")?;
        assert!(matches!(err, AcmeError::NotPropagated(_)), "{err:?}");
        *value.lock().map_err(|_| "poisoned")? = "new".to_owned();
        check.wait_propagated(&record)?;
        Ok(())
    }

    #[test]
    fn a_zone_with_no_ns_records_is_not_propagated() -> R {
        let resolver = Mock::start(Arc::new(|_, _| Reply::answers(Vec::new())))?;
        let dns = authority(Vec::new(), vec![resolver.addr], 53);
        let err = dns
            .servers("_acme-challenge.example.test")
            .err()
            .ok_or("found servers")?;
        assert!(matches!(err, AcmeError::NotPropagated(_)), "{err:?}");
        Ok(())
    }
}
