//! The two ends of the acme channel (ADR-015), as plain functions.
//!
//! ```text
//!   acme process                               worker
//!   ────────────                               ──────
//!   acme_main ─▶ hello ─▶ run_loop             serve_installs
//!                           │ every hour           ▲
//!                           ▼                      │
//!                        renew_once ── Install ────┘ check_and_install
//!                           │  Issuer (the CA)         └─▶ install_acme
//!                           └─ Installer (AcmeClient)
//! ```
//!
//! Nothing here forks, opens a socket of its own or needs root: the CA and
//! the channel are seams ([`Issuer`], [`Installer`]), so the tests drive
//! every path in-process. `serve` wires them to `spawn_acme` and the worker.
//!
//! # Logs
//!
//! The acme process holds the dns-01 provider secret and the new private
//! key. No log line carries either: a provider error is logged by its kind
//! only, because a provider can quote its request, and the request carries
//! the secret. Only the ACME server's own error text is logged in full.

use std::future::Future;
use std::ops::ControlFlow;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use detent_acme::{
    Account, AcmeError, DnsProvider, DnsRecord, IssueRequest, Issued, RetryPolicy, Warning,
};
use detent_platform::privsep::acme::{AcmeChannelError, AcmeClient, KeyPem};
use detent_platform::privsep::spawn::{
    AcmeHandle, SandboxHooks, SpawnConfig, SpawnError, spawn_acme,
};
use detent_platform::privsep::transport::{Channel, ChannelError};
use detent_web::{AcmeConfig, CertStore, CertifiedKeyPair, TlsError};
use rustls_pki_types::CertificateDer;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Time between two checks of the served certificate.
const CHECK_INTERVAL: Duration = Duration::from_hours(1);

/// Wait before the first retry after a failure. Each further failure doubles
/// it, up to [`MAX_RETRY`].
const FIRST_RETRY: Duration = Duration::from_secs(60);

/// The longest wait between two attempts after failures.
const MAX_RETRY: Duration = CHECK_INTERVAL;

/// How one order polls the CA for a ready order and for the certificate:
/// first after one second, then at doubling delays, for at most five
/// minutes. A real CA validates dns-01 and issues in seconds to a minute;
/// the library default gives up after 30 seconds, and a failed order uses
/// up CA rate limits. Five minutes is well inside the hour between checks,
/// and the doubling keeps it to about nine polls.
pub(crate) const ORDER_POLICY: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .timeout(Duration::from_secs(300));

/// The CA: issues a certificate and tells when to renew one.
pub(crate) trait Issuer {
    /// Order and fetch a new certificate for the configured domains.
    fn issue(&mut self) -> impl Future<Output = Result<Issued, AcmeError>>;

    /// The ARI suggested renewal window of the leaf `leaf_der`, in Unix
    /// seconds, or `None` when the CA gives none.
    fn renewal_window(&mut self, leaf_der: &[u8]) -> impl Future<Output = Option<(i64, i64)>>;
}

/// The hand-over to the worker.
pub(crate) trait Installer {
    /// Ask the worker to serve `chain_pem` with `key`.
    ///
    /// # Errors
    ///
    /// As [`AcmeClient::install`].
    fn install(&mut self, chain_pem: String, key: KeyPem) -> Result<(), AcmeChannelError>;
}

impl Installer for AcmeClient {
    fn install(&mut self, chain_pem: String, key: KeyPem) -> Result<(), AcmeChannelError> {
        Self::install(self, chain_pem, key)
    }
}

/// What one renewal check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A new certificate is issued and the worker serves it.
    Renewed {
        /// The new leaf's end of validity, Unix seconds.
        not_after: i64,
    },
    /// The served certificate does not need renewal yet.
    NotDue {
        /// How much of its lifetime is used, in percent.
        used_percent: u8,
    },
}

/// An issued pair the worker has not installed yet. The loop keeps it and
/// retries the install, so a refusal does not order a new certificate: a CA
/// allows few duplicate certificates a week.
#[derive(Debug)]
pub(crate) struct Held {
    chain_pem: String,
    key: KeyPem,
    /// The leaf's end of validity, Unix seconds.
    not_after: i64,
}

/// Why one renewal check failed.
#[derive(Debug)]
pub(crate) enum RenewError {
    /// The served certificate could not be read from `cert_dir`.
    Load(TlsError),
    /// The CA or the dns-01 provider failed.
    Issue(AcmeError),
    /// The CA sent a chain whose leaf does not parse.
    Chain,
    /// The worker did not install the new certificate.
    Install(AcmeChannelError),
}

impl RenewError {
    /// A log line for this failure. It never quotes a provider's text or a
    /// PEM (see the module documentation).
    fn reason(&self) -> String {
        match self {
            Self::Load(err) => err.to_string(),
            Self::Issue(err) => issue_reason(err),
            Self::Chain => "the CA sent a certificate that does not parse".to_owned(),
            Self::Install(err) => err.to_string(),
        }
    }
}

/// A log line for an issue failure: the ACME server's own text, or a fixed
/// sentence for everything the provider or the local files report.
fn issue_reason(err: &AcmeError) -> String {
    match err {
        AcmeError::Acme(inner) => format!("the ACME server or client failed: {inner}"),
        AcmeError::InvalidOrder(status) => format!("the order ended as {status:?}"),
        AcmeError::Io(inner) => format!("a local file operation failed: {}", inner.kind()),
        AcmeError::Credentials(_) => {
            "the ACME account credentials could not be read or written".to_owned()
        }
        AcmeError::NoDns01Challenge => "the CA offered no dns-01 challenge".to_owned(),
        _ => "the dns-01 provider failed".to_owned(),
    }
}

/// The real CA: `detent_acme::issue` over the configured dns-01 provider.
///
/// The provider holds the secret from `secrets.toml`; it is built before the
/// fork and lives only in the acme process (ADR-015).
pub(crate) struct AcmeIssuer {
    provider: Box<dyn DnsProvider>,
    directory_url: String,
    domains: Vec<String>,
    credentials_path: PathBuf,
    ca_root: Option<PathBuf>,
    profile: Option<String>,
    contacts: Vec<String>,
    policy: RetryPolicy,
    /// The account of the last successful order, for ARI.
    account: Option<Account>,
}

impl AcmeIssuer {
    /// An issuer for `config` over `provider`.
    ///
    /// # Errors
    ///
    /// The name of the first `[acme]` setting that is missing:
    /// `directory_url`, `credentials_path` or `domains`.
    pub(crate) fn new(
        config: &AcmeConfig,
        provider: Box<dyn DnsProvider>,
        policy: RetryPolicy,
    ) -> Result<Self, &'static str> {
        let directory_url = config.directory_url.clone().ok_or("directory_url")?;
        let credentials_path = config.credentials_path.clone().ok_or("credentials_path")?;
        if config.domains.is_empty() {
            return Err("domains");
        }
        Ok(Self {
            provider,
            directory_url,
            domains: config.domains.clone(),
            credentials_path,
            ca_root: config.ca_root.clone(),
            profile: config.profile.clone(),
            contacts: config.contacts.clone(),
            policy,
            account: None,
        })
    }
}

impl Issuer for AcmeIssuer {
    async fn issue(&mut self) -> Result<Issued, AcmeError> {
        let domains: Vec<&str> = self.domains.iter().map(String::as_str).collect();
        let contacts: Vec<&str> = self.contacts.iter().map(String::as_str).collect();
        let request = IssueRequest {
            directory_url: &self.directory_url,
            domains: &domains,
            credentials_path: &self.credentials_path,
            ca_root: self.ca_root.as_deref(),
            profile: self.profile.as_deref(),
            contacts: &contacts,
            eab: None,
        };
        let (issued, account) = detent_acme::issue(
            &request,
            self.provider.as_ref(),
            // The provider alone publishes the record: nothing to push.
            &|_: &DnsRecord| Ok(()),
            &self.policy,
        )
        .await?;
        self.account = Some(account);
        Ok(issued)
    }

    async fn renewal_window(&mut self, leaf_der: &[u8]) -> Option<(i64, i64)> {
        let account = self.account.as_ref()?;
        let id = detent_acme::ari_identifier_der(&[CertificateDer::from(leaf_der)]).ok()?;
        let (info, _) = account.renewal_info(&id).await.ok()?;
        Some((
            info.suggested_window.start.unix_timestamp(),
            info.suggested_window.end.unix_timestamp(),
        ))
    }
}

/// Log the expiry warning for `used_percent`, if one is due.
fn warn_expiry(used_percent: u8, not_after: i64) {
    match detent_acme::warning_for(used_percent) {
        Some(Warning::Half) => tracing::warn!(
            used_percent,
            not_after,
            "half of the served certificate's lifetime is used"
        ),
        Some(Warning::Quarter) => tracing::warn!(
            used_percent,
            not_after,
            "a quarter or less of the served certificate's lifetime is left"
        ),
        None => {}
    }
}

/// One renewal check at `now`.
///
/// `served` is the stored ACME pair; `None` means the worker still serves
/// the bootstrap certificate, so a certificate is issued at once. A served
/// pair whose validity cannot be read is renewed too. Otherwise the
/// certificate is renewed when the ARI window has started, or else at two
/// thirds of its lifetime.
///
/// # Errors
///
/// [`RenewError::Issue`] when the CA fails, [`RenewError::Chain`] when it
/// sends a chain that does not parse, [`RenewError::Install`] when the
/// worker does not install the new pair. The pair is then in `held`.
pub(crate) async fn renew_once(
    now: i64,
    served: Option<&CertifiedKeyPair>,
    issuer: &mut impl Issuer,
    installer: &mut impl Installer,
    held: &mut Option<Held>,
) -> Result<Outcome, RenewError> {
    if let Some(pair) = served {
        if let Ok((not_before, not_after)) =
            detent_acme::leaf_validity_der(&[CertificateDer::from(pair.cert_der())])
        {
            let used_percent = detent_acme::percent_used(not_before, not_after, now);
            warn_expiry(used_percent, not_after);
            let window = issuer.renewal_window(pair.cert_der()).await;
            if !detent_acme::should_renew_in_window(not_before, not_after, now, window) {
                return Ok(Outcome::NotDue { used_percent });
            }
        } else {
            tracing::warn!("the served certificate's validity cannot be read");
        }
    }
    let Issued { chain_pem, key_pem } = issuer.issue().await.map_err(RenewError::Issue)?;
    let (_, not_after) =
        detent_acme::leaf_validity_pem(&chain_pem).map_err(|_| RenewError::Chain)?;
    install(
        Held {
            chain_pem,
            key: KeyPem::new(key_pem),
            not_after,
        },
        installer,
        held,
    )
}

/// Ask the worker to install `pair`; keep it in `held` when that fails.
fn install(
    pair: Held,
    installer: &mut impl Installer,
    held: &mut Option<Held>,
) -> Result<Outcome, RenewError> {
    match installer.install(pair.chain_pem.clone(), pair.key.clone()) {
        Ok(()) => Ok(Outcome::Renewed {
            not_after: pair.not_after,
        }),
        Err(err) => {
            *held = Some(pair);
            Err(RenewError::Install(err))
        }
    }
}

/// One round of the loop. A held pair that is still valid at `now` is
/// installed again and nothing is ordered. Otherwise: read the served pair
/// from `cert_dir`, then [`renew_once`].
async fn round(
    now: i64,
    cert_dir: &Path,
    issuer: &mut impl Issuer,
    installer: &mut impl Installer,
    held: &mut Option<Held>,
) -> Result<Outcome, RenewError> {
    if let Some(pair) = held.take() {
        if now <= pair.not_after {
            return install(pair, installer, held);
        }
        tracing::warn!(
            not_after = pair.not_after,
            "the held certificate expired before the worker installed it"
        );
    }
    let served = detent_web::load_acme(cert_dir).map_err(RenewError::Load)?;
    renew_once(now, served.as_ref(), issuer, installer, held).await
}

/// The renewal loop: one round at once, then one every hour.
///
/// After a failure the next round comes after [`FIRST_RETRY`], doubled for
/// each further failure up to [`MAX_RETRY`]; a success resets it. After a
/// failed install the next rounds retry that install until the pair
/// expires; only then is a new certificate ordered. `now`
/// reads the clock in Unix seconds and `sleep` waits, so a test drives the
/// rounds without real time. The loop returns when the worker closes the
/// channel: an install sees it closed, or `sleep` breaks.
pub(crate) async fn run_loop<F>(
    issuer: &mut impl Issuer,
    installer: &mut impl Installer,
    cert_dir: &Path,
    mut now: impl FnMut() -> i64,
    mut sleep: impl FnMut(Duration) -> F,
) where
    F: Future<Output = ControlFlow<()>>,
{
    let mut retry = FIRST_RETRY;
    let mut held = None;
    loop {
        let delay = match round(now(), cert_dir, issuer, installer, &mut held).await {
            Ok(outcome) => {
                if let Outcome::Renewed { not_after } = outcome {
                    tracing::info!(not_after, "the worker serves a new ACME certificate");
                }
                retry = FIRST_RETRY;
                CHECK_INTERVAL
            }
            Err(RenewError::Install(AcmeChannelError::Channel(ChannelError::Closed))) => {
                tracing::info!("the worker closed the acme channel");
                return;
            }
            Err(err) => {
                let delay = retry;
                tracing::warn!(
                    reason = %err.reason(),
                    retry_secs = delay.as_secs(),
                    "certificate renewal failed"
                );
                retry = retry.saturating_mul(2).min(MAX_RETRY);
                delay
            }
        };
        if sleep(delay).await.is_break() {
            tracing::info!("the worker closed the acme channel");
            return;
        }
    }
}

/// Waits `delay`, or less when `channel` becomes readable: the worker
/// closed its end, or sent a message out of turn. Either way the loop must
/// stop, so the acme process ends when the worker does.
///
/// `channel` is registered with the runtime for this wait only, so a
/// readiness left from an earlier answer cannot end it. Nothing is read,
/// and the blocking mode of the channel does not change. When the
/// descriptor cannot be watched, it waits the full `delay`.
pub(crate) async fn wait_or_peer(channel: BorrowedFd<'_>, delay: Duration) -> ControlFlow<()> {
    let Ok(watched) = AsyncFd::with_interest(channel, Interest::READABLE) else {
        tracing::warn!("the acme channel cannot be watched; the wait runs to its end");
        tokio::time::sleep(delay).await;
        return ControlFlow::Continue(());
    };
    tokio::select! {
        () = tokio::time::sleep(delay) => ControlFlow::Continue(()),
        _ = watched.readable() => ControlFlow::Break(()),
    }
}

/// The acme process's body, run by `spawn_acme` on its end of the channel.
///
/// Builds a current-thread runtime, greets the worker and runs
/// [`run_loop`] with the real clock. Returns `0` when the worker closed the
/// channel, `1` when the runtime or the greeting failed.
pub(crate) fn acme_main(channel: Channel, mut issuer: impl Issuer, cert_dir: &Path) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(reason = %err, "the acme process cannot start its runtime");
            return 1;
        }
    };
    // The client owns the channel; the waits watch this duplicate of it.
    let peer = match channel.as_fd().try_clone_to_owned() {
        Ok(peer) => peer,
        Err(err) => {
            tracing::error!(reason = %err, "the acme process cannot watch its channel");
            return 1;
        }
    };
    let mut client = AcmeClient::new(channel);
    if let Err(err) = client.hello() {
        tracing::error!(reason = %err, "the worker did not accept the acme process");
        return 1;
    }
    runtime.block_on(run_loop(
        &mut issuer,
        &mut client,
        cert_dir,
        detent_web::auth::extract::unix_now,
        |delay| wait_or_peer(peer.as_fd(), delay),
    ));
    0
}

/// Forks the acme process with [`spawn_acme`]. The child drops
/// `inherited` first, then runs [`acme_main`] with `issuer`; the parent gets
/// `inherited` back.
///
/// Put in `inherited` what the acme process must not keep: above all the
/// runner handle, whose channel reaches the privileged runner. `issuer`
/// holds the dns-01 provider and its secret. It moves into the child's
/// body, which the parent drops when this returns, so only the acme
/// process keeps the secret.
///
/// # Errors
///
/// As [`spawn_acme`]; the parent's `inherited` is dropped with the error.
pub(crate) fn fork_acme<T>(
    config: &SpawnConfig,
    sandbox: &dyn SandboxHooks,
    issuer: impl Issuer,
    cert_dir: PathBuf,
    inherited: T,
) -> Result<(AcmeHandle, T), SpawnError> {
    spawn_acme(config, sandbox, inherited, move |channel, inherited| {
        drop(inherited);
        acme_main(channel, issuer, &cert_dir)
    })
}

/// The worker's check of a pair from the acme process: it must parse, the
/// key must match the leaf, every one of `domains` must equal a DNS name
/// of the leaf (ASCII case-insensitive), and the leaf must be valid at
/// `now`. Then the pair is stored in `cert_dir` and served
/// from `store` ([`detent_web::install_acme`]).
///
/// # Errors
///
/// Why the pair is refused. The acme process logs the text, so it never
/// quotes the chain or the key.
pub(crate) fn check_and_install(
    chain_pem: &str,
    key: &KeyPem,
    domains: &[String],
    now: i64,
    cert_dir: &Path,
    store: &CertStore,
) -> Result<(), String> {
    if domains.is_empty() {
        return Err("no domains are configured".to_owned());
    }
    let pair =
        CertifiedKeyPair::from_acme_pem(chain_pem, key.expose()).map_err(|err| err.to_string())?;
    // Before `install_acme`, which stores the pair before it parses it.
    pair.to_certified_key().map_err(|err| err.to_string())?;
    let leaf_der = CertificateDer::from(pair.cert_der());
    let names = detent_acme::leaf_dns_names_der(std::slice::from_ref(&leaf_der))
        .map_err(|_| "the certificate names do not parse".to_owned())?;
    // Exact names, not wildcard matching: a configured `*.example.com`
    // needs the SAN `*.example.com` (dns-01 is the only way to one).
    for domain in domains {
        if !names.iter().any(|name| name.eq_ignore_ascii_case(domain)) {
            return Err(format!("the certificate does not cover {domain}"));
        }
    }
    let (not_before, not_after) =
        detent_acme::leaf_validity_der(std::slice::from_ref(&leaf_der))
            .map_err(|_| "the certificate validity does not parse".to_owned())?;
    if now < not_before {
        return Err(format!("the certificate is not valid before {not_before}"));
    }
    if now > not_after {
        return Err(format!("the certificate expired at {not_after}"));
    }
    detent_web::install_acme(cert_dir, &pair, store).map_err(|err| err.to_string())?;
    tracing::info!(
        fingerprint = %pair.fingerprint(),
        not_after,
        "the worker serves a new ACME certificate"
    );
    Ok(())
}

/// The worker's side of the acme channel: answer the acme process with
/// [`check_and_install`] at the real clock until the channel closes. Run
/// it on its own thread. When the channel fails, the worker keeps serving
/// the last certificate (ADR-015).
pub(crate) fn serve_installs(
    mut channel: Channel,
    domains: Vec<String>,
    cert_dir: PathBuf,
    store: Arc<CertStore>,
) {
    let served = detent_platform::privsep::acme::serve_acme(&mut channel, move |chain, key| {
        let now = detent_web::auth::extract::unix_now();
        check_and_install(chain, key, &domains, now, &cert_dir, &store).inspect_err(|reason| {
            tracing::warn!(%reason, "the worker refused an ACME certificate");
        })
    });
    match served {
        Ok(()) => tracing::info!("the acme process closed its channel"),
        Err(err) => tracing::warn!(
            reason = %err,
            "the acme channel failed; the worker keeps its certificate"
        ),
    }
}

/// Starts [`serve_installs`] on its own thread, as the worker does once its
/// certificate store exists. Nothing joins the thread: when it ends, the
/// worker keeps serving the last certificate.
///
/// # Errors
///
/// The thread could not be started.
pub(crate) fn spawn_installs(
    channel: Channel,
    domains: Vec<String>,
    cert_dir: PathBuf,
    store: Arc<CertStore>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("acme-installs".to_owned())
        .spawn(move || serve_installs(channel, domains, cert_dir, store))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::ops::ControlFlow;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use detent_acme::{AcmeError, Issued, RetryPolicy};
    use detent_platform::privsep::acme::{
        ACME_PROTO_VERSION, AcmeChannelError, AcmeClient, AcmeMessage, KeyPem, WorkerMessage,
    };
    use detent_platform::privsep::transport::{Channel, ChannelError};
    use detent_web::CertifiedKeyPair;

    use super::{
        AcmeIssuer, FIRST_RETRY, Installer, Issuer, MAX_RETRY, Outcome, RenewError, acme_main,
        check_and_install, renew_once, run_loop, serve_installs, spawn_installs, wait_or_peer,
    };

    type R = Result<(), Box<dyn std::error::Error>>;

    /// A stand-in secret: low entropy on purpose (CI runs gitleaks).
    const SECRET: &str = "not-a-real-token";

    /// A certificate with chosen names and validity, made at run time.
    struct Cert {
        chain_pem: String,
        key_pem: String,
        not_before: i64,
        not_after: i64,
    }

    impl Cert {
        /// Valid for ten days from 2026-01-01.
        fn new(names: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
            Self::valid(names, (2026, 1, 1), (2026, 1, 11))
        }

        fn valid(
            names: &[&str],
            from: (i32, u8, u8),
            to: (i32, u8, u8),
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let key = rcgen::KeyPair::generate()?;
            let mut params = rcgen::CertificateParams::new(
                names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            )?;
            params.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
            params.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
            let chain_pem = params.self_signed(&key)?.pem();
            let (not_before, not_after) = detent_acme::leaf_validity_pem(&chain_pem)?;
            Ok(Self {
                chain_pem,
                key_pem: key.serialize_pem(),
                not_before,
                not_after,
            })
        }

        /// The instant `percent` of the lifetime is used.
        fn at(&self, percent: i64) -> i64 {
            let lifetime = self.not_after.saturating_sub(self.not_before);
            self.not_before
                .saturating_add(lifetime.saturating_mul(percent).div_euclid(100))
        }

        fn pair(&self) -> Result<CertifiedKeyPair, detent_web::TlsError> {
            CertifiedKeyPair::from_acme_pem(&self.chain_pem, &self.key_pem)
        }

        fn issued(&self) -> Issued {
            Issued {
                chain_pem: self.chain_pem.clone(),
                key_pem: self.key_pem.clone(),
            }
        }
    }

    /// A CA that answers from a script.
    #[derive(Default)]
    struct FakeIssuer {
        results: VecDeque<Result<Issued, AcmeError>>,
        window: Option<(i64, i64)>,
        calls: usize,
    }

    impl FakeIssuer {
        fn answering(results: impl IntoIterator<Item = Result<Issued, AcmeError>>) -> Self {
            Self {
                results: results.into_iter().collect(),
                ..Self::default()
            }
        }
    }

    impl Issuer for FakeIssuer {
        fn issue(&mut self) -> impl Future<Output = Result<Issued, AcmeError>> {
            self.calls = self.calls.saturating_add(1);
            std::future::ready(
                self.results
                    .pop_front()
                    .unwrap_or_else(|| Err(AcmeError::Config("script ended".to_owned()))),
            )
        }

        fn renewal_window(&mut self, _leaf_der: &[u8]) -> impl Future<Output = Option<(i64, i64)>> {
            std::future::ready(self.window)
        }
    }

    /// A worker that answers from a script, `Ok` once the script ends.
    #[derive(Default)]
    struct FakeInstaller {
        results: VecDeque<Result<(), AcmeChannelError>>,
        installed: Vec<String>,
    }

    impl Installer for FakeInstaller {
        fn install(&mut self, chain_pem: String, _key: KeyPem) -> Result<(), AcmeChannelError> {
            self.installed.push(chain_pem);
            self.results.pop_front().unwrap_or(Ok(()))
        }
    }

    fn closed() -> AcmeChannelError {
        AcmeChannelError::Channel(ChannelError::Closed)
    }

    fn block_on<F: std::future::Future>(future: F) -> std::io::Result<F::Output> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(logged(|| runtime.block_on(future)))
    }

    /// Runs `body` under a subscriber: [`capture`]'s when one is set, else a
    /// new one whose logs are dropped.
    ///
    /// A callsite first reached on a thread with no subscriber can cache
    /// "never" for every thread (the tracing callsite cache is global), and
    /// a later [`capture`] then misses that line. So no test runs this
    /// module's code without a subscriber.
    fn logged<T>(body: impl FnOnce() -> T) -> T {
        let unset = tracing::dispatcher::get_default(|current| {
            current.is::<tracing::subscriber::NoSubscriber>()
        });
        if unset { capture(body).0 } else { body() }
    }

    /// A log sink the tests can read back.
    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("log sink poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `body` with a subscriber that records every event, and returns
    /// what it recorded.
    fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
        let logs = Logs::default();
        let sink = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, body);
        let text = logs
            .0
            .lock()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        (out, text)
    }

    #[test]
    fn the_bootstrap_certificate_is_replaced_at_once() -> R {
        let cert = Cert::new(&["a.example"])?;
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(0, None, &mut issuer, &mut installer, &mut None))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_after: cert.not_after
            })
        );
        assert_eq!(installer.installed, vec![cert.chain_pem]);
        Ok(())
    }

    #[test]
    fn a_fresh_certificate_is_not_due() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let mut issuer = FakeIssuer::default();
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(
            cert.at(1),
            Some(&pair),
            &mut issuer,
            &mut installer,
            &mut None,
        ))?;
        assert_eq!(outcome.ok(), Some(Outcome::NotDue { used_percent: 1 }));
        assert_eq!(issuer.calls, 0);
        assert!(installer.installed.is_empty());
        Ok(())
    }

    #[test]
    fn a_certificate_past_two_thirds_is_renewed() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let next = Cert::valid(&["a.example"], (2026, 1, 8), (2026, 1, 18))?;
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(
            cert.at(70),
            Some(&pair),
            &mut issuer,
            &mut installer,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_after: next.not_after
            })
        );
        assert_eq!(installer.installed, vec![next.chain_pem]);
        Ok(())
    }

    #[test]
    fn a_started_ari_window_renews_early() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let mut issuer = FakeIssuer {
            window: Some((cert.at(5), cert.at(20))),
            ..FakeIssuer::answering([Ok(cert.issued())])
        };
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(
            cert.at(10),
            Some(&pair),
            &mut issuer,
            &mut installer,
            &mut None,
        ))?;
        assert!(
            matches!(outcome, Ok(Outcome::Renewed { .. })),
            "{outcome:?}"
        );
        assert_eq!(installer.installed.len(), 1);

        // A window that has not started yet waits.
        let mut issuer = FakeIssuer {
            window: Some((cert.at(20), cert.at(30))),
            ..FakeIssuer::default()
        };
        let outcome = block_on(renew_once(
            cert.at(10),
            Some(&pair),
            &mut issuer,
            &mut installer,
            &mut None,
        ))?;
        assert_eq!(outcome.ok(), Some(Outcome::NotDue { used_percent: 10 }));
        Ok(())
    }

    #[test]
    fn a_served_pair_without_a_readable_validity_is_renewed() -> R {
        let cert = Cert::new(&["a.example"])?;
        let broken = CertifiedKeyPair::new(b"not a certificate".to_vec(), Vec::new());
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(
            0,
            Some(&broken),
            &mut issuer,
            &mut installer,
            &mut None,
        ))?;
        assert!(
            matches!(outcome, Ok(Outcome::Renewed { .. })),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn an_issue_error_installs_nothing() -> R {
        let mut issuer = FakeIssuer::answering([Err(AcmeError::NoDns01Challenge)]);
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(0, None, &mut issuer, &mut installer, &mut None))?;
        assert!(
            matches!(outcome, Err(RenewError::Issue(AcmeError::NoDns01Challenge))),
            "{outcome:?}"
        );
        assert!(installer.installed.is_empty());

        // A chain that does not parse is not sent to the worker.
        let mut issuer = FakeIssuer::answering([Ok(Issued {
            chain_pem: "no certificate here".to_owned(),
            key_pem: String::new(),
        })]);
        let outcome = block_on(renew_once(0, None, &mut issuer, &mut installer, &mut None))?;
        assert!(matches!(outcome, Err(RenewError::Chain)), "{outcome:?}");
        assert!(installer.installed.is_empty());
        Ok(())
    }

    #[test]
    fn a_refusal_by_the_worker_is_an_error() -> R {
        let cert = Cert::new(&["a.example"])?;
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller {
            results: VecDeque::from([Err(AcmeChannelError::Refused(
                "the certificate does not cover b.example".to_owned(),
            ))]),
            ..FakeInstaller::default()
        };
        let mut held = None;
        let outcome = block_on(renew_once(0, None, &mut issuer, &mut installer, &mut held))?;
        assert!(
            matches!(
                outcome,
                Err(RenewError::Install(AcmeChannelError::Refused(_)))
            ),
            "{outcome:?}"
        );
        // The pair is kept for the next round.
        let held = held.ok_or("the refused pair is not held")?;
        assert_eq!(held.chain_pem, cert.chain_pem);
        assert_eq!(held.key.expose(), cert.key_pem);
        assert_eq!(held.not_after, cert.not_after);
        Ok(())
    }

    #[test]
    fn expiry_warnings_go_to_the_log_at_half_and_a_quarter() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let mut logs = Vec::new();
        for percent in [55, 80, 10] {
            let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
            let mut installer = FakeInstaller::default();
            let (outcome, text) = capture(|| {
                block_on(renew_once(
                    cert.at(percent),
                    Some(&pair),
                    &mut issuer,
                    &mut installer,
                    &mut None,
                ))
            });
            assert!(outcome?.is_ok());
            logs.push(text);
        }
        let not_after = format!("not_after={}", cert.not_after);
        let [half, quarter, none] = logs.as_slice() else {
            return Err("three runs".into());
        };
        assert!(half.contains("WARN"), "{half}");
        assert!(half.contains("half"), "{half}");
        assert!(half.contains("used_percent=55"), "{half}");
        assert!(half.contains(&not_after), "{half}");
        assert!(quarter.contains("quarter"), "{quarter}");
        assert!(quarter.contains("used_percent=80"), "{quarter}");
        assert!(!quarter.contains("BEGIN"), "{quarter}");
        assert!(!none.contains("WARN"), "{none}");
        Ok(())
    }

    #[test]
    fn failures_back_off_from_one_minute_to_an_hour_and_a_success_resets() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert = Cert::new(&["a.example"])?;
        let failure = || Err(AcmeError::NoDns01Challenge);
        let mut script: Vec<Result<Issued, AcmeError>> = (0..8).map(|_| failure()).collect();
        script.extend([Ok(cert.issued()), failure(), Ok(cert.issued())]);
        let mut issuer = FakeIssuer::answering(script);
        let mut installer = FakeInstaller {
            results: VecDeque::from([Ok(()), Err(closed())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        block_on(run_loop(
            &mut issuer,
            &mut installer,
            dir.path(),
            || 0,
            |delay| {
                delays.push(delay);
                std::future::ready(ControlFlow::Continue(()))
            },
        ))?;
        let minutes: Vec<u64> = delays.iter().map(|d| d.as_secs() / 60).collect();
        assert_eq!(minutes, vec![1, 2, 4, 8, 16, 32, 60, 60, 60, 1]);
        assert_eq!(delays.first(), Some(&FIRST_RETRY));
        assert_eq!(delays.get(6), Some(&MAX_RETRY));
        // The loop stopped at the closed channel: nothing is left to issue.
        assert_eq!(issuer.calls, 11);
        assert!(issuer.results.is_empty());
        Ok(())
    }

    /// Runs the loop over an empty `cert_dir` with the clock reading `times`
    /// in turn, and returns the delays it slept.
    fn drive(
        issuer: &mut FakeIssuer,
        installer: &mut FakeInstaller,
        times: Vec<i64>,
    ) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let mut times = times.into_iter();
        let mut delays = Vec::new();
        let ended = block_on(async {
            tokio::time::timeout(
                Duration::from_secs(2),
                run_loop(
                    issuer,
                    installer,
                    dir.path(),
                    || times.next().unwrap_or(0),
                    |delay| {
                        delays.push(delay);
                        // A loop that should have stopped by now waits for
                        // the timeout instead of spinning.
                        let wait = tokio::time::sleep(if delays.len() > 10 {
                            Duration::from_secs(60)
                        } else {
                            Duration::ZERO
                        });
                        async move {
                            wait.await;
                            ControlFlow::Continue(())
                        }
                    },
                ),
            )
            .await
        })?;
        ended.map_err(|_| format!("the loop did not stop; slept {delays:?}"))?;
        Ok(delays)
    }

    /// A refused install must not order again: a CA allows few duplicate
    /// certificates a week. The loop retries the install of the pair it
    /// holds.
    #[test]
    fn a_refused_install_is_retried_without_a_new_order() -> R {
        let first = Cert::new(&["a.example"])?;
        let second = Cert::valid(&["a.example"], (2026, 1, 5), (2026, 1, 15))?;
        let mut issuer = FakeIssuer::answering([Ok(first.issued()), Ok(second.issued())]);
        let refused = || Err(AcmeChannelError::Refused("disk full".to_owned()));
        let mut installer = FakeInstaller {
            results: VecDeque::from([refused(), refused(), Ok(()), Err(closed())]),
            ..FakeInstaller::default()
        };
        let times = vec![first.at(1), first.at(2), first.at(3), first.at(90)];
        let delays = drive(&mut issuer, &mut installer, times)?;
        assert_eq!(
            installer.installed,
            vec![
                first.chain_pem.clone(),
                first.chain_pem.clone(),
                first.chain_pem,
                second.chain_pem
            ]
        );
        // One order for the three installs of the first pair.
        assert_eq!(issuer.calls, 2);
        assert_eq!(
            delays,
            vec![FIRST_RETRY, FIRST_RETRY.saturating_mul(2), MAX_RETRY]
        );
        Ok(())
    }

    #[test]
    fn a_held_pair_that_expired_is_ordered_again() -> R {
        let first = Cert::new(&["a.example"])?;
        let second = Cert::valid(&["a.example"], (2026, 1, 11), (2026, 1, 21))?;
        let mut issuer = FakeIssuer::answering([Ok(first.issued()), Ok(second.issued())]);
        let mut installer = FakeInstaller {
            results: VecDeque::from([
                Err(AcmeChannelError::Refused("disk full".to_owned())),
                Err(closed()),
            ]),
            ..FakeInstaller::default()
        };
        let times = vec![first.at(1), first.not_after.saturating_add(1)];
        drive(&mut issuer, &mut installer, times)?;
        assert_eq!(issuer.calls, 2);
        assert_eq!(installer.installed, vec![first.chain_pem, second.chain_pem]);
        Ok(())
    }

    #[test]
    fn a_served_certificate_that_cannot_be_read_is_a_failure() -> R {
        let dir = tempfile::TempDir::new()?;
        // A directory in the pair file's place: reading it fails.
        std::fs::create_dir(dir.path().join(detent_web::ACME_PAIR_FILE))?;
        let cert = Cert::new(&["a.example"])?;
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller {
            results: VecDeque::from([Err(closed())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let (done, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || 0,
                |delay| {
                    // Replace the unreadable file after the first failure.
                    if delays.is_empty() {
                        let _ = std::fs::remove_dir(dir.path().join(detent_web::ACME_PAIR_FILE));
                    }
                    delays.push(delay);
                    std::future::ready(ControlFlow::Continue(()))
                },
            ))
        });
        done?;
        assert_eq!(delays, vec![FIRST_RETRY]);
        assert!(logs.contains("acme.pair"), "{logs}");
        assert_eq!(issuer.calls, 1);
        Ok(())
    }

    #[test]
    fn the_loop_logs_neither_a_provider_secret_nor_a_key() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let mut issuer = FakeIssuer::answering([
            Err(AcmeError::Config(format!("the provider said {SECRET}"))),
            Err(AcmeError::NotPropagated(SECRET.to_owned())),
            Err(AcmeError::Credentials(SECRET.to_owned())),
            Err(AcmeError::InvalidValue(SECRET.to_owned())),
            Ok(Issued {
                chain_pem: format!("no certificate {SECRET}"),
                key_pem: cert.key_pem.clone(),
            }),
            Ok(cert.issued()),
        ]);
        let mut installer = FakeInstaller {
            results: VecDeque::from([Err(closed())]),
            ..FakeInstaller::default()
        };
        let (done, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || 0,
                |_| std::future::ready(ControlFlow::Continue(())),
            ))
        });
        done?;
        assert_eq!(issuer.calls, 6);
        assert!(logs.contains("renewal failed"), "{logs}");
        assert!(logs.contains("does not parse"), "{logs}");
        assert!(!logs.contains(SECRET), "{logs}");
        assert!(!logs.contains("BEGIN"), "{logs}");
        assert!(!logs.contains(cert.key_pem.trim()), "{logs}");
        Ok(())
    }

    fn acme_config(credentials_path: &std::path::Path) -> detent_web::AcmeConfig {
        detent_web::AcmeConfig {
            directory_url: Some("https://127.0.0.1:9/dir".to_owned()),
            domains: vec!["a.example".to_owned()],
            credentials_path: Some(credentials_path.to_path_buf()),
            ..detent_web::AcmeConfig::default()
        }
    }

    fn provider() -> Result<Box<dyn detent_acme::DnsProvider>, AcmeError> {
        Ok(Box::new(detent_acme::CloudflareProvider::new(
            SECRET,
            "0123456789abcdef0123456789abcdef",
        )?))
    }

    #[test]
    fn the_real_issuer_needs_a_directory_credentials_and_domains() -> R {
        let path = std::path::Path::new("/nonexistent/account.json");
        for (config, missing) in [
            (
                detent_web::AcmeConfig {
                    directory_url: None,
                    ..acme_config(path)
                },
                "directory_url",
            ),
            (
                detent_web::AcmeConfig {
                    credentials_path: None,
                    ..acme_config(path)
                },
                "credentials_path",
            ),
            (
                detent_web::AcmeConfig {
                    domains: Vec::new(),
                    ..acme_config(path)
                },
                "domains",
            ),
        ] {
            let issuer = AcmeIssuer::new(&config, provider()?, RetryPolicy::new());
            assert_eq!(issuer.err(), Some(missing));
        }
        assert!(AcmeIssuer::new(&acme_config(path), provider()?, RetryPolicy::new()).is_ok());
        Ok(())
    }

    /// The real issuer, with a real provider that holds the secret, fails
    /// before any network: its credentials path is a directory. The loop
    /// logs the failure and never the secret.
    #[test]
    fn the_real_issuer_fails_offline_and_the_log_keeps_the_secret() -> R {
        let dir = tempfile::TempDir::new()?;
        let mut issuer =
            AcmeIssuer::new(&acme_config(dir.path()), provider()?, RetryPolicy::new())?;
        assert_eq!(block_on(issuer.renewal_window(b"no account yet"))?, None);
        let mut installer = FakeInstaller::default();
        let mut rounds = 0_u32;
        let (ended, logs) = capture(|| {
            block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(1),
                    run_loop(
                        &mut issuer,
                        &mut installer,
                        dir.path(),
                        || 0,
                        |_| {
                            rounds = rounds.saturating_add(1);
                            // Stop after the first round: wait forever.
                            std::future::pending::<ControlFlow<()>>()
                        },
                    ),
                )
                .await
            })
        });
        assert!(ended?.is_err(), "the loop ended on its own");
        assert_eq!(rounds, 1);
        assert!(installer.installed.is_empty());
        assert!(logs.contains("a local file operation failed"), "{logs}");
        assert!(!logs.contains(SECRET), "{logs}");
        Ok(())
    }

    /// Runs `acme_main` against a worker thread that answers `Hello` with
    /// `version` and then closes the channel at the first `Install`.
    fn main_against(version: u16, issuer: FakeIssuer) -> Result<i32, Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let (acme_end, mut worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || -> Result<bool, ChannelError> {
            let hello = worker_end.recv::<AcmeMessage>()?;
            worker_end.send(&WorkerMessage::Hello { version })?;
            let install = worker_end.recv::<AcmeMessage>();
            Ok(matches!(hello, AcmeMessage::Hello { .. })
                && matches!(install, Ok(AcmeMessage::Install { .. })))
        });
        let status = logged(|| acme_main(acme_end, issuer, dir.path()));
        let saw = worker.join().map_err(|_| "worker thread panicked")?;
        if version == ACME_PROTO_VERSION {
            assert_eq!(saw.ok(), Some(true));
        }
        Ok(status)
    }

    #[test]
    fn acme_main_greets_installs_and_ends_when_the_worker_closes() -> R {
        let cert = Cert::new(&["a.example"])?;
        let status = main_against(
            ACME_PROTO_VERSION,
            FakeIssuer::answering([Ok(cert.issued())]),
        )?;
        assert_eq!(status, 0);
        Ok(())
    }

    #[test]
    fn acme_main_fails_when_the_worker_refuses_the_hello() -> R {
        let (status, logs) =
            capture(|| main_against(ACME_PROTO_VERSION.wrapping_add(1), FakeIssuer::default()));
        assert_eq!(status?, 1);
        assert!(logs.contains("ERROR"), "{logs}");
        Ok(())
    }

    /// The worker ends while the loop waits one minute after a failed round:
    /// the wait ends at once, and `acme_main` returns `0`.
    #[test]
    fn acme_main_ends_when_the_worker_closes_during_a_wait() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert_dir = dir.path().to_path_buf();
        let (acme_end, mut worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || -> Result<(), ChannelError> {
            worker_end.recv::<AcmeMessage>()?;
            worker_end.send(&WorkerMessage::Hello {
                version: ACME_PROTO_VERSION,
            })?;
            // The first round fails (the issuer has no script): the loop is
            // in its one-minute wait when the worker goes.
            std::thread::sleep(Duration::from_millis(200));
            drop(worker_end);
            Ok(())
        });
        let started = std::time::Instant::now();
        let (done, status) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(logged(|| {
                acme_main(acme_end, FakeIssuer::default(), &cert_dir)
            }));
        });
        let status = status
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "acme_main did not end during its wait")?;
        assert_eq!(status, 0);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        worker.join().map_err(|_| "worker thread panicked")??;
        Ok(())
    }

    #[test]
    fn a_wait_runs_to_its_end_on_a_quiet_channel_and_ends_on_a_message() -> R {
        use std::os::fd::AsFd as _;
        let (acme_end, mut worker_end) = Channel::pair()?;
        let quiet = block_on(wait_or_peer(acme_end.as_fd(), Duration::from_millis(20)))?;
        assert_eq!(quiet, ControlFlow::Continue(()));
        // A message out of turn ends the wait as a close does.
        worker_end.send(&WorkerMessage::Installed)?;
        let stirred = block_on(wait_or_peer(acme_end.as_fd(), Duration::from_secs(60)))?;
        assert_eq!(stirred, ControlFlow::Break(()));
        Ok(())
    }

    /// The runtime cannot watch a regular file: the wait still runs, to its
    /// end, and says so in the log.
    #[test]
    fn a_descriptor_that_cannot_be_watched_waits_the_full_delay() -> R {
        use std::os::fd::AsFd as _;
        let file = tempfile::tempfile()?;
        let started = std::time::Instant::now();
        let (waited, logs) =
            capture(|| block_on(wait_or_peer(file.as_fd(), Duration::from_millis(50))));
        assert_eq!(waited?, ControlFlow::Continue(()));
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(logs.contains("cannot be watched"), "{logs}");
        Ok(())
    }

    fn domains() -> Vec<String> {
        vec!["a.example".to_owned(), "b.example".to_owned()]
    }

    /// A store that serves a bootstrap certificate, and its leaf.
    fn bootstrap_store() -> Result<(detent_web::CertStore, Vec<u8>), Box<dyn std::error::Error>> {
        let pair = detent_web::bootstrap_self_signed(&[])?;
        Ok((detent_web::CertStore::new(&pair)?, pair.cert_der().to_vec()))
    }

    fn served_leaf(store: &detent_web::CertStore) -> Vec<u8> {
        store
            .current()
            .cert
            .first()
            .map(|der| der.as_ref().to_vec())
            .unwrap_or_default()
    }

    #[test]
    fn a_pair_for_every_domain_is_stored_and_served() -> R {
        let dir = tempfile::TempDir::new()?;
        let (store, bootstrap) = bootstrap_store()?;
        let cert = Cert::new(&["a.example", "b.example"])?;
        let key = KeyPem::new(cert.key_pem.clone());
        logged(|| {
            check_and_install(
                &cert.chain_pem,
                &key,
                &domains(),
                cert.at(50),
                dir.path(),
                &store,
            )
        })?;
        let leaf = cert.pair()?.cert_der().to_vec();
        assert_ne!(served_leaf(&store), bootstrap);
        assert_eq!(served_leaf(&store), leaf);
        let stored = detent_web::load_acme(dir.path())?.ok_or("no stored pair")?;
        assert_eq!(stored.cert_der(), leaf.as_slice());
        Ok(())
    }

    /// dns-01 is the only way to a wildcard certificate. A configured name
    /// must equal a subjectAltName entry: `*.example.com` covers the
    /// configured `*.example.com`, not `a.example.com`.
    #[test]
    fn a_wildcard_pair_installs_for_the_same_wildcard_only() -> R {
        let (store, bootstrap) = bootstrap_store()?;
        let cert = Cert::new(&["*.example.com"])?;
        let key = KeyPem::new(cert.key_pem.clone());
        let dir = tempfile::TempDir::new()?;
        let refused = logged(|| {
            check_and_install(
                &cert.chain_pem,
                &key,
                &["a.example.com".to_owned()],
                cert.at(50),
                dir.path(),
                &store,
            )
        });
        let reason = refused.err().ok_or("a.example.com: installed")?;
        assert!(reason.contains("does not cover a.example.com"), "{reason}");
        assert_eq!(served_leaf(&store), bootstrap);

        logged(|| {
            check_and_install(
                &cert.chain_pem,
                &key,
                &["*.EXAMPLE.com".to_owned()],
                cert.at(50),
                dir.path(),
                &store,
            )
        })?;
        assert_eq!(served_leaf(&store), cert.pair()?.cert_der());
        Ok(())
    }

    #[test]
    fn a_pair_the_worker_must_not_serve_is_refused_without_quoting_it() -> R {
        let dir = tempfile::TempDir::new()?;
        let (store, bootstrap) = bootstrap_store()?;
        let both = Cert::new(&["a.example", "b.example"])?;
        let only_a = Cert::new(&["a.example"])?;
        let other = Cert::new(&["a.example", "b.example"])?;
        let garbage = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n";
        let cases: [(&str, &str, &str, Vec<String>, i64); 7] = [
            (
                "missing domain",
                &only_a.chain_pem,
                &only_a.key_pem,
                domains(),
                only_a.at(50),
            ),
            (
                "expired",
                &both.chain_pem,
                &both.key_pem,
                domains(),
                both.not_after.saturating_add(1),
            ),
            (
                "not yet valid",
                &both.chain_pem,
                &both.key_pem,
                domains(),
                both.not_before.saturating_sub(1),
            ),
            (
                "mismatched key",
                &both.chain_pem,
                &other.key_pem,
                domains(),
                both.at(50),
            ),
            (
                "garbage chain",
                garbage,
                &both.key_pem,
                domains(),
                both.at(50),
            ),
            (
                "garbage key",
                &both.chain_pem,
                "garbage",
                domains(),
                both.at(50),
            ),
            (
                "no domains",
                &both.chain_pem,
                &both.key_pem,
                Vec::new(),
                both.at(50),
            ),
        ];
        for (case, chain, key_pem, names, now) in cases {
            let refused = logged(|| {
                check_and_install(
                    chain,
                    &KeyPem::new(key_pem.to_owned()),
                    &names,
                    now,
                    dir.path(),
                    &store,
                )
            });
            let Err(reason) = refused else {
                return Err(format!("{case}: installed").into());
            };
            let expected = match case {
                "missing domain" => "does not cover b.example",
                "expired" => "expired",
                "not yet valid" => "not valid before",
                "mismatched key" => "rejected",
                "no domains" => "no domains",
                _ => "not PEM",
            };
            assert!(reason.contains(expected), "{case}: {reason}");
            assert!(!reason.contains("BEGIN"), "{case}: {reason}");
            for line in key_pem.lines().chain(chain.lines()).filter(|l| l.len() > 8) {
                assert!(!reason.contains(line), "{case}: {reason}");
            }
            assert_eq!(served_leaf(&store), bootstrap, "{case}");
            assert!(
                !dir.path().join(detent_web::ACME_PAIR_FILE).exists(),
                "{case}"
            );
        }
        Ok(())
    }

    #[test]
    fn serve_installs_answers_the_acme_process_until_it_closes() -> R {
        let dir = tempfile::TempDir::new()?;
        let (store, _) = bootstrap_store()?;
        let store = Arc::new(store);
        // Valid around any clock this test runs on.
        let good = Cert::valid(&["a.example", "b.example"], (2020, 1, 1), (2099, 1, 1))?;
        let bad = Cert::valid(&["a.example"], (2020, 1, 1), (2099, 1, 1))?;
        let (acme_end, worker_end) = Channel::pair()?;
        let (good_chain, good_key) = (good.chain_pem.clone(), good.key_pem.clone());
        let (bad_chain, bad_key) = (bad.chain_pem.clone(), bad.key_pem.clone());
        let acme = std::thread::spawn(move || {
            let mut client = AcmeClient::new(acme_end);
            let hello = client.hello();
            let first = client.install(good_chain, KeyPem::new(good_key));
            let second = client.install(bad_chain, KeyPem::new(bad_key));
            (hello, first, second)
        });
        let ((), logs) = capture(|| {
            serve_installs(
                worker_end,
                domains(),
                dir.path().to_path_buf(),
                Arc::clone(&store),
            );
        });
        let (hello, first, second) = acme.join().map_err(|_| "acme thread panicked")?;
        assert!(hello.is_ok(), "{hello:?}");
        assert!(first.is_ok(), "{first:?}");
        assert!(
            matches!(second, Err(AcmeChannelError::Refused(ref reason)) if reason.contains("b.example")),
            "{second:?}"
        );
        let pair = good.pair()?;
        assert_eq!(served_leaf(&store), pair.cert_der());
        assert!(dir.path().join(detent_web::ACME_PAIR_FILE).exists());
        assert!(logs.contains(&pair.fingerprint()), "{logs}");
        assert!(!logs.contains("BEGIN"), "{logs}");
        Ok(())
    }

    /// The thread the worker starts: the acme process installs a good pair
    /// over the channel, and the store then serves it.
    #[test]
    fn the_worker_thread_installs_a_pair_and_the_store_serves_it() -> R {
        let dir = tempfile::TempDir::new()?;
        let (store, bootstrap) = bootstrap_store()?;
        let store = Arc::new(store);
        let good = Cert::valid(&["a.example", "b.example"], (2020, 1, 1), (2099, 1, 1))?;
        let (acme_end, worker_end) = Channel::pair()?;
        let (thread, logs) = capture(|| {
            spawn_installs(
                worker_end,
                domains(),
                dir.path().to_path_buf(),
                Arc::clone(&store),
            )
        });
        let thread = thread?;
        assert_eq!(thread.thread().name(), Some("acme-installs"), "{logs}");
        let mut client = AcmeClient::new(acme_end);
        client.hello()?;
        client.install(good.chain_pem.clone(), KeyPem::new(good.key_pem.clone()))?;
        drop(client);
        thread.join().map_err(|_| "install thread panicked")?;
        assert_ne!(served_leaf(&store), bootstrap);
        assert_eq!(served_leaf(&store), good.pair()?.cert_der());
        Ok(())
    }

    /// An issuer that records when it is dropped.
    struct Tracked(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Issuer for Tracked {
        fn issue(&mut self) -> impl Future<Output = Result<Issued, AcmeError>> {
            std::future::ready(Err(AcmeError::NoDns01Challenge))
        }

        fn renewal_window(&mut self, _leaf_der: &[u8]) -> impl Future<Output = Option<(i64, i64)>> {
            std::future::ready(None)
        }
    }

    /// After the fork the parent holds no issuer (it holds the provider
    /// and its secret) and gets back what it passed as `inherited`.
    #[test]
    fn the_parent_drops_the_issuer_at_the_fork_and_keeps_what_it_passed() -> R {
        use detent_platform::privsep::spawn::{NoSandbox, SpawnConfig};
        let dir = tempfile::TempDir::new()?;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (kept, mut peer) = Channel::pair()?;
        let (mut handle, mut kept) = logged(|| {
            super::fork_acme(
                &SpawnConfig::unprivileged(),
                &NoSandbox,
                Tracked(Arc::clone(&dropped)),
                dir.path().to_path_buf(),
                kept,
            )
        })?;
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        // The child greets; a wrong version ends it with status 1.
        let hello = handle.channel.recv::<AcmeMessage>()?;
        assert!(matches!(hello, AcmeMessage::Hello { .. }), "{hello:?}");
        handle.channel.send(&WorkerMessage::Hello {
            version: ACME_PROTO_VERSION.wrapping_add(1),
        })?;
        assert_eq!(handle.wait()?, Some(1));
        kept.send(&7_u8)?;
        assert_eq!(peer.recv::<u8>()?, 7);
        Ok(())
    }

    #[test]
    fn serve_installs_logs_a_channel_that_fails() -> R {
        let dir = tempfile::TempDir::new()?;
        let (store, bootstrap) = bootstrap_store()?;
        let store = Arc::new(store);
        let (mut acme_end, worker_end) = Channel::pair()?;
        // A `String` is not an `AcmeMessage`.
        acme_end.send(&"not a message".to_owned())?;
        let ((), logs) = capture(|| {
            serve_installs(
                worker_end,
                domains(),
                dir.path().to_path_buf(),
                Arc::clone(&store),
            );
        });
        assert!(logs.contains("WARN"), "{logs}");
        assert!(logs.contains("acme channel"), "{logs}");
        assert_eq!(served_leaf(&store), bootstrap);
        Ok(())
    }
}
