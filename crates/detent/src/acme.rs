//! The two ends of the acme channel (ADR-015), as plain functions.
//!
//! ```text
//!   acme process                               worker
//!   ────────────                               ──────
//!   acme_main ─▶ hello ─▶ run_loop             serve_installs
//!                           │ at the next check,   ▲
//!                           │ or at RenewNow ◀─────┼── (worker's renewer)
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
use detent_platform::privsep::acme::{
    AcmeChannelError, AcmeClient, AcmeRenewer, AcmeServer, KeyPem, acme_link,
};
use detent_platform::privsep::spawn::{
    AcmeHandle, SandboxHooks, SpawnConfig, SpawnError, spawn_acme,
};
use detent_platform::privsep::transport::{Channel, ChannelError};
use detent_web::{AcmeConfig, CertStore, CertifiedKeyPair, TlsError};
use rustls_pki_types::CertificateDer;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// The longest time between two checks of the served certificate. A
/// certificate due sooner is checked at its due time instead ([`next_check`]).
const CHECK_INTERVAL: Duration = Duration::from_hours(1);

/// Wait before the first retry after a failure. Each further failure doubles
/// it, up to [`MAX_RETRY`].
const FIRST_RETRY: Duration = Duration::from_secs(60);

/// The longest wait between two attempts after failures.
const MAX_RETRY: Duration = CHECK_INTERVAL;

/// The floor under [`next_check`]'s next check, even for a certificate
/// already due. It bounds the load on the CA and the worker when a due
/// certificate's renewal keeps failing to install, and it matches
/// [`FIRST_RETRY`].
const MIN_CHECK_INTERVAL: Duration = FIRST_RETRY;

/// The shortest time between two orders that a forced round (a `RenewNow`)
/// starts. Let's Encrypt allows five duplicate certificates a week for the
/// same names, and it limits failed validations per hour too; without a
/// floor, a few clicks on "renew now" use up either limit and renewal is
/// then blocked for days. A due renewal (not forced) is never held back by
/// this.
const MIN_FORCED_INTERVAL: Duration = Duration::from_hours(1);

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

/// The hand-over to the worker, and the worker's renewal requests.
pub(crate) trait Installer {
    /// Ask the worker to serve `chain_pem` with `key`.
    ///
    /// # Errors
    ///
    /// As [`AcmeClient::install`].
    fn install(&mut self, chain_pem: String, key: KeyPem) -> Result<(), AcmeChannelError>;

    /// True once when the worker asked for a renewal while `hello` or an
    /// install waited for its answer ([`AcmeClient::take_pending_renew`]).
    fn take_pending_renew(&mut self) -> bool;

    /// Read the one message the worker sent on its own, once the channel is
    /// readable. `Ok` means the worker asked for a renewal now.
    ///
    /// # Errors
    ///
    /// As [`AcmeClient::next_request`]: `Closed` when the worker closed the
    /// channel, `Protocol` for any message other than `RenewNow`.
    fn next_request(&mut self) -> Result<(), AcmeChannelError>;
}

impl Installer for AcmeClient {
    fn install(&mut self, chain_pem: String, key: KeyPem) -> Result<(), AcmeChannelError> {
        Self::install(self, chain_pem, key)
    }

    fn take_pending_renew(&mut self) -> bool {
        Self::take_pending_renew(self)
    }

    fn next_request(&mut self) -> Result<(), AcmeChannelError> {
        Self::next_request(self).map(drop)
    }
}

/// What one renewal check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A new certificate is issued and the worker serves it.
    Renewed {
        /// The new leaf's start of validity, Unix seconds.
        not_before: i64,
        /// The new leaf's end of validity, Unix seconds.
        not_after: i64,
    },
    /// The served certificate does not need renewal yet.
    NotDue {
        /// How much of its lifetime is used, in percent.
        used_percent: u8,
        /// The served leaf's start of validity, Unix seconds.
        not_before: i64,
        /// The served leaf's end of validity, Unix seconds.
        not_after: i64,
        /// Its ARI suggested renewal window, when the CA gave one.
        window: Option<(i64, i64)>,
    },
}

/// An issued pair the worker has not installed yet. The loop keeps it and
/// retries the install, so a refusal does not order a new certificate: a CA
/// allows few duplicate certificates a week.
#[derive(Debug)]
pub(crate) struct Held {
    chain_pem: String,
    key: KeyPem,
    /// The leaf's start of validity, Unix seconds.
    not_before: i64,
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

/// True when a forced order may go ahead: none has ever succeeded, or
/// [`MIN_FORCED_INTERVAL`] has passed since `last_order`. Logs the last
/// order and the next allowed time when it refuses.
fn forced_order_allowed(now: i64, last_order: Option<i64>) -> bool {
    let Some(last) = last_order else {
        return true;
    };
    let min_forced = i64::try_from(MIN_FORCED_INTERVAL.as_secs()).unwrap_or(i64::MAX);
    if now.saturating_sub(last) >= min_forced {
        return true;
    }
    tracing::info!(
        last_order = last,
        next_forced_order = last.saturating_add(min_forced),
        "a forced renewal was requested too soon after the last order; the order is skipped"
    );
    false
}

/// The next check after a round at `now`, for the certificate valid
/// `not_before`..`not_after` with ARI `window` (`None` when unknown): the
/// earlier of [`CHECK_INTERVAL`] and the time until
/// [`detent_acme::due_at`] says it is due, never under
/// [`MIN_CHECK_INTERVAL`]. A certificate already due, or one whose lifetime
/// does not parse (`not_after <= not_before`), gets the floor.
fn next_check(now: i64, not_before: i64, not_after: i64, window: Option<(i64, i64)>) -> Duration {
    let due = detent_acme::due_at(not_before, not_after, window);
    let until_due = due.saturating_sub(now).max(0);
    let cap = i64::try_from(CHECK_INTERVAL.as_secs()).unwrap_or(i64::MAX);
    let floor = i64::try_from(MIN_CHECK_INTERVAL.as_secs()).unwrap_or(0);
    let secs = until_due.min(cap).max(floor);
    Duration::from_secs(u64::try_from(secs).unwrap_or(MIN_CHECK_INTERVAL.as_secs()))
}

/// One renewal check at `now`.
///
/// `served` is the stored ACME pair; `None` means the worker still serves
/// the bootstrap certificate, so a certificate is issued at once. A served
/// pair whose validity cannot be read is renewed too. With `force` (the
/// worker asked for a renewal), a certificate is issued at once too, unless
/// one was already ordered in the last [`MIN_FORCED_INTERVAL`]
/// ([`forced_order_allowed`]); the certificate is then renewed only if it is
/// otherwise due. Otherwise the certificate is renewed when the ARI window
/// has started, or else at two thirds of its lifetime.
///
/// `last_order` is set to `now` after every successful order, whether or not
/// the worker then installs it.
///
/// # Errors
///
/// [`RenewError::Issue`] when the CA fails, [`RenewError::Chain`] when it
/// sends a chain that does not parse, [`RenewError::Install`] when the
/// worker does not install the new pair. The pair is then in `held`.
pub(crate) async fn renew_once(
    now: i64,
    served: Option<&CertifiedKeyPair>,
    force: bool,
    issuer: &mut impl Issuer,
    installer: &mut impl Installer,
    held: &mut Option<Held>,
    last_order: &mut Option<i64>,
) -> Result<Outcome, RenewError> {
    if let Some(pair) = served {
        if let Ok((not_before, not_after)) =
            detent_acme::leaf_validity_der(&[CertificateDer::from(pair.cert_der())])
        {
            let used_percent = detent_acme::percent_used(not_before, not_after, now);
            warn_expiry(used_percent, not_after);
            if !(force && forced_order_allowed(now, *last_order)) {
                let window = issuer.renewal_window(pair.cert_der()).await;
                if !detent_acme::should_renew_in_window(not_before, not_after, now, window) {
                    return Ok(Outcome::NotDue {
                        used_percent,
                        not_before,
                        not_after,
                        window,
                    });
                }
            }
        } else {
            tracing::warn!("the served certificate's validity cannot be read");
        }
    }
    let Issued { chain_pem, key_pem } = issuer.issue().await.map_err(RenewError::Issue)?;
    *last_order = Some(now);
    let (not_before, not_after) =
        detent_acme::leaf_validity_pem(&chain_pem).map_err(|_| RenewError::Chain)?;
    install(
        Held {
            chain_pem,
            key: KeyPem::new(key_pem),
            not_before,
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
            not_before: pair.not_before,
            not_after: pair.not_after,
        }),
        Err(err) => {
            *held = Some(pair);
            Err(RenewError::Install(err))
        }
    }
}

/// One round of the loop. A held pair that is still valid at `now` is
/// installed again and nothing is ordered, also when `force` is set. Otherwise:
/// read the served pair from `cert_dir`, then [`renew_once`].
async fn round(
    now: i64,
    cert_dir: &Path,
    force: bool,
    issuer: &mut impl Issuer,
    installer: &mut impl Installer,
    held: &mut Option<Held>,
    last_order: &mut Option<i64>,
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
    renew_once(
        now,
        served.as_ref(),
        force,
        issuer,
        installer,
        held,
        last_order,
    )
    .await
}

/// The delay before the next round after a successful one at `now`: logs a
/// renewal, then [`next_check`] over whichever certificate is now served (the
/// new one for [`Outcome::Renewed`], with no known ARI window yet; the served
/// one for [`Outcome::NotDue`], with its window).
fn success_delay(now: i64, outcome: Outcome) -> Duration {
    let (not_before, not_after, window) = match outcome {
        Outcome::Renewed {
            not_before,
            not_after,
        } => {
            tracing::info!(not_after, "the worker serves a new ACME certificate");
            (not_before, not_after, None)
        }
        Outcome::NotDue {
            not_before,
            not_after,
            window,
            ..
        } => (not_before, not_after, window),
    };
    let delay = next_check(now, not_before, not_after, window);
    tracing::debug!(next_check_secs = delay.as_secs(), "next renewal check");
    delay
}

/// The renewal loop: one round at once, then one at each next check
/// ([`next_check`]) — the earlier of [`CHECK_INTERVAL`] and the served
/// certificate's due time, never sooner than [`MIN_CHECK_INTERVAL`].
///
/// After a failure the next round comes after [`FIRST_RETRY`], doubled for
/// each further failure up to [`MAX_RETRY`]; a success resets it. After a
/// failed install the next rounds retry that install until the pair
/// expires; only then is a new certificate ordered. `now`
/// reads the clock in Unix seconds and `sleep` waits, so a test drives the
/// rounds without real time.
///
/// `sleep` breaks when the channel is readable; the loop then reads one
/// message ([`Installer::next_request`]). Outside a backoff wait, a
/// `RenewNow` ends the wait and starts a forced round ([`renew_once`]). A
/// `RenewNow` recorded during `hello` or an install
/// ([`Installer::take_pending_renew`]) forces the next round too, which then
/// starts without a wait. During a backoff wait (after a failure), a
/// `RenewNow` from either source does not push the wait's end back: it is
/// logged with the deadline set when the backoff began, and only the
/// remaining time to that deadline is waited out again; only the round after
/// the backoff is forced (subject to [`MIN_FORCED_INTERVAL`], via
/// [`renew_once`]). The loop returns when the worker closes the channel (an
/// install or the read sees it closed), and when the read fails in any other
/// way; that is logged.
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
    let mut last_order = None;
    // A request that arrived during `hello`.
    let mut force = requested(installer.take_pending_renew());
    loop {
        let started_at = now();
        let result = round(
            started_at,
            cert_dir,
            force,
            issuer,
            installer,
            &mut held,
            &mut last_order,
        )
        .await;
        force = requested(installer.take_pending_renew());
        let mut in_backoff = false;
        let delay = match result {
            Ok(outcome) => {
                retry = FIRST_RETRY;
                success_delay(started_at, outcome)
            }
            Err(RenewError::Install(AcmeChannelError::Channel(ChannelError::Closed))) => {
                tracing::info!("the worker closed the acme channel");
                return;
            }
            Err(err) => {
                in_backoff = true;
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
        if in_backoff {
            let delay_secs = i64::try_from(delay.as_secs()).unwrap_or(i64::MAX);
            let deadline = started_at.saturating_add(delay_secs);
            let mut renew_seen = false;
            if force {
                log_renew_during_backoff(deadline);
                renew_seen = true;
            }
            let mut wait = delay;
            loop {
                match sleep(wait).await {
                    ControlFlow::Continue(()) => break,
                    ControlFlow::Break(()) => match installer.next_request() {
                        Ok(()) => {
                            log_renew_during_backoff(deadline);
                            renew_seen = true;
                            let remaining = deadline.saturating_sub(now()).max(0);
                            wait = Duration::from_secs(u64::try_from(remaining).unwrap_or(0));
                        }
                        Err(AcmeChannelError::Channel(ChannelError::Closed)) => {
                            tracing::info!("the worker closed the acme channel");
                            return;
                        }
                        Err(err) => {
                            tracing::warn!(
                                reason = %err,
                                "the acme channel failed; renewals stop"
                            );
                            return;
                        }
                    },
                }
            }
            force = renew_seen;
            continue;
        }
        if force || sleep(delay).await.is_continue() {
            continue;
        }
        match installer.next_request() {
            Ok(()) => force = requested(true),
            Err(AcmeChannelError::Channel(ChannelError::Closed)) => {
                tracing::info!("the worker closed the acme channel");
                return;
            }
            Err(err) => {
                tracing::warn!(reason = %err, "the acme channel failed; renewals stop");
                return;
            }
        }
    }
}

/// Logs that a renewal was requested while the loop was in a backoff wait
/// whose deadline is `next_attempt`: the wait is not shortened, so the next
/// attempt stays at that same deadline.
fn log_renew_during_backoff(next_attempt: i64) {
    tracing::info!("renewal requested during backoff; the next attempt is at {next_attempt}");
}

/// `pending`, logged when it is set.
fn requested(pending: bool) -> bool {
    if pending {
        tracing::info!("renewal requested by the worker");
    }
    pending
}

/// Waits `delay`, or less when `channel` becomes readable: the worker
/// sent a message (a `RenewNow`, or anything else) or closed its end. The
/// caller then reads the channel ([`run_loop`]), so the acme process renews
/// at once, or ends when the worker does.
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
    server: AcmeServer,
    domains: Vec<String>,
    cert_dir: PathBuf,
    store: Arc<CertStore>,
) {
    let outcome = server.serve(move |chain, key| {
        let now = detent_web::auth::extract::unix_now();
        check_and_install(chain, key, &domains, now, &cert_dir, &store).inspect_err(|reason| {
            tracing::warn!(%reason, "the worker refused an ACME certificate");
        })
    });
    match outcome {
        Ok(()) => tracing::info!("the acme process closed its channel"),
        Err(err) => tracing::warn!(
            reason = %err,
            "the acme channel failed; the worker keeps its certificate"
        ),
    }
}

/// Splits the worker's end of the acme channel ([`acme_link`]) and starts
/// [`serve_installs`] with its reading half on its own thread, as the worker
/// does once its certificate store exists. The other half is the renewer
/// the web state gets. Nothing joins the thread: when it ends, the worker
/// keeps serving the last certificate, and the renewer fails.
///
/// # Errors
///
/// The channel could not be split, or the thread could not be started.
pub(crate) fn spawn_installs(
    channel: Channel,
    domains: Vec<String>,
    cert_dir: PathBuf,
    store: Arc<CertStore>,
) -> std::io::Result<(std::thread::JoinHandle<()>, WorkerRenewer)> {
    let (server, renewer) = acme_link(channel).map_err(std::io::Error::other)?;
    let thread = std::thread::Builder::new()
        .name("acme-installs".to_owned())
        .spawn(move || serve_installs(server, domains, cert_dir, store))?;
    Ok((thread, WorkerRenewer(renewer)))
}

/// The worker's [`AcmeRenewer`], behind `POST /api/v1/system/cert/renew`.
#[derive(Debug)]
pub(crate) struct WorkerRenewer(AcmeRenewer);

impl detent_web::CertRenewer for WorkerRenewer {
    fn renew_now(&self) -> Result<(), String> {
        self.0.renew_now().map_err(|err| err.to_string())
    }
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
        acme_link,
    };
    use detent_platform::privsep::transport::{Channel, ChannelError};
    use detent_web::CertifiedKeyPair;

    use super::{
        AcmeIssuer, CHECK_INTERVAL, DnsProvider, DnsRecord, FIRST_RETRY, Held, Installer, Issuer,
        MAX_RETRY, MIN_CHECK_INTERVAL, MIN_FORCED_INTERVAL, Outcome, RenewError, acme_main,
        check_and_install, next_check, renew_once, round, run_loop, serve_installs, spawn_installs,
        wait_or_peer,
    };

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn next_check_is_capped_at_check_interval_for_a_long_lived_certificate() {
        // A 90-day certificate at 10 %: two thirds is days away, so the next
        // check is the cap, not the due time.
        let lifetime = 90 * 24 * 3600;
        let not_before = 0;
        let not_after = lifetime;
        let now = lifetime / 10;
        assert_eq!(next_check(now, not_before, not_after, None), CHECK_INTERVAL);
    }

    #[test]
    fn next_check_follows_the_due_time_of_a_short_lived_certificate() {
        // A 5-minute certificate just issued: due at two thirds, 198 s in
        // (ceil(66 % of 300 s)), well under the hour cap and the floor.
        assert_eq!(next_check(0, 0, 300, None), Duration::from_secs(198));
    }

    #[test]
    fn next_check_never_goes_under_the_floor() {
        // A certificate already past its due point.
        assert_eq!(next_check(1_000, 0, 300, None), MIN_CHECK_INTERVAL);
        // A broken lifetime is always due.
        assert_eq!(next_check(0, 300, 0, None), MIN_CHECK_INTERVAL);
    }

    #[test]
    fn next_check_follows_an_ari_window() {
        // A window starting in 10 minutes, well inside a long lifetime.
        let window = Some((600, 100_000));
        assert_eq!(
            next_check(0, 0, 90 * 24 * 3600, window),
            Duration::from_secs(600)
        );
        // A window that has already started: the floor.
        let started = Some((-10, 100_000));
        assert_eq!(
            next_check(0, 0, 90 * 24 * 3600, started),
            MIN_CHECK_INTERVAL
        );
    }

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

        /// Valid for 5 minutes from 2026-01-01: a CI-profile-like lifetime
        /// (slice S2), short enough that its due time is well under
        /// [`CHECK_INTERVAL`].
        fn short_lived(names: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
            let key = rcgen::KeyPair::generate()?;
            let mut params = rcgen::CertificateParams::new(
                names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            )?;
            let start = rcgen::date_time_ymd(2026, 1, 1);
            params.not_before = start;
            params.not_after = start.replace_minute(5)?;
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
        /// What each `take_pending_renew` answers; `false` once it ends.
        pending: VecDeque<bool>,
        /// What each `next_request` answers; a closed channel once it ends.
        requests: VecDeque<Result<(), AcmeChannelError>>,
    }

    impl Installer for FakeInstaller {
        fn install(&mut self, chain_pem: String, _key: KeyPem) -> Result<(), AcmeChannelError> {
            self.installed.push(chain_pem);
            self.results.pop_front().unwrap_or(Ok(()))
        }

        fn take_pending_renew(&mut self) -> bool {
            self.pending.pop_front().unwrap_or(false)
        }

        fn next_request(&mut self) -> Result<(), AcmeChannelError> {
            self.requests.pop_front().unwrap_or_else(|| Err(closed()))
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
        let outcome = block_on(renew_once(
            0,
            None,
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: cert.not_before,
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
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::NotDue {
                used_percent: 1,
                not_before: cert.not_before,
                not_after: cert.not_after,
                window: None,
            })
        );
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
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: next.not_before,
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
            false,
            &mut issuer,
            &mut installer,
            &mut None,
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
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::NotDue {
                used_percent: 10,
                not_before: cert.not_before,
                not_after: cert.not_after,
                window: Some((cert.at(20), cert.at(30))),
            })
        );
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
            false,
            &mut issuer,
            &mut installer,
            &mut None,
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
        let outcome = block_on(renew_once(
            0,
            None,
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
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
        let outcome = block_on(renew_once(
            0,
            None,
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
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
        let outcome = block_on(renew_once(
            0,
            None,
            false,
            &mut issuer,
            &mut installer,
            &mut held,
            &mut None,
        ))?;
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
                    false,
                    &mut issuer,
                    &mut installer,
                    &mut None,
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
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || 0,
                |delay| {
                    delays.push(delay);
                    std::future::ready(ControlFlow::Continue(()))
                },
            ))
        });
        ended?;
        assert!(logs.contains("certificate renewal failed"), "{logs}");
        assert!(logs.contains("retry_secs=60"), "{logs}");
        assert!(
            logs.contains("the worker serves a new ACME certificate"),
            "{logs}"
        );
        let minutes: Vec<u64> = delays.iter().map(|d| d.as_secs() / 60).collect();
        assert_eq!(minutes, vec![1, 2, 4, 8, 16, 32, 60, 60, 60, 1]);
        assert_eq!(delays.first(), Some(&FIRST_RETRY));
        assert_eq!(delays.get(6), Some(&MAX_RETRY));
        // The loop stopped at the closed channel: nothing is left to issue.
        assert_eq!(issuer.calls, 11);
        assert!(issuer.results.is_empty());
        Ok(())
    }

    /// A short-lived certificate (slice S2's target) is checked near its own
    /// due time, not after the full hour: the bootstrap round issues it, and
    /// the next sleep is its two-thirds point (198 s of a 300 s lifetime),
    /// not [`CHECK_INTERVAL`].
    #[test]
    fn a_short_lived_certificate_is_rechecked_near_its_due_time() -> R {
        let cert = Cert::short_lived(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller::default();
        let mut delays = Vec::new();
        let (ended, _logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || cert.not_before,
                |delay| {
                    delays.push(delay);
                    // Breaks at once: `next_request` then sees the default
                    // `FakeInstaller`'s empty queue as a closed channel, so
                    // the loop ends after this one round instead of reissuing
                    // (the fake install never writes `cert_dir`).
                    std::future::ready(ControlFlow::Break(()))
                },
            ))
        });
        ended?;
        assert_eq!(delays, vec![Duration::from_secs(198)]);
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

    // -----------------------------------------------------------------------
    // Log capture (PLAN Phase 6 task 2): no secret reaches the log.
    // -----------------------------------------------------------------------

    const CF_SECRET: &str = "SECRET-cf-7f3a91c2d4e60b58";
    const ACME_DNS_SECRET: &str = "SECRET-acmedns-3b9e0d17a6c2c9f4";
    /// The raw TSIG key. The provider is given it base64-encoded.
    const TSIG_RAW: &str = "SECRET-tsig-c04d7e12b9a35f68";
    /// The text of an ACME account file: a private key the log must not show.
    const ACCOUNT_KEY: &str = "SECRET-account-key-91be44d07c3a5f28";

    /// Base64 of `bytes` (`urlsafe` picks the URL alphabet, no padding).
    fn base64(bytes: &[u8], urlsafe: bool) -> String {
        let alphabet: &[u8] = if urlsafe {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut group = [0_u8; 3];
            for (slot, byte) in group.iter_mut().zip(chunk) {
                *slot = *byte;
            }
            let word = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for shift in [18_u32, 12, 6, 0]
                .into_iter()
                .take(chunk.len().saturating_add(1))
            {
                let sextet = word.checked_shr(shift).map_or(0, |bits| bits & 0x3f);
                out.push(char::from(
                    alphabet.get(sextet as usize).copied().unwrap_or(b'?'),
                ));
            }
            if !urlsafe {
                for _ in chunk.len()..3 {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Every form in which `secret` could reach a log: as written, its
    /// random tail, base64 (both alphabets) and hex.
    fn forms(secret: &str) -> Vec<String> {
        let tail = secret.rsplit('-').next().unwrap_or(secret);
        vec![
            secret.to_owned(),
            tail.to_owned(),
            base64(secret.as_bytes(), false),
            base64(secret.as_bytes(), true),
            secret
                .bytes()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
                .collect(),
        ]
    }

    /// Fails when `text` holds any form of any of `secrets`, in any casing.
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

    #[test]
    fn the_secret_finder_sees_every_form() {
        // The finder itself must fail on a leak, or the checks below prove
        // nothing.
        assert_eq!(
            base64(b"any carnal pleas", false),
            "YW55IGNhcm5hbCBwbGVhcw=="
        );
        assert_eq!(base64(b"any carnal pleas", true), "YW55IGNhcm5hbCBwbGVhcw");
        assert_eq!(base64(b"ab", false), "YWI=");
        for form in forms(CF_SECRET) {
            let leaked = std::panic::catch_unwind(|| {
                assert_clean(
                    "a line",
                    &format!("token={}", form.to_uppercase()),
                    &[CF_SECRET],
                );
            });
            assert!(leaked.is_err(), "{form} was not found");
        }
    }

    /// An issuer that publishes and withdraws a challenge record through a
    /// real provider, as the order flow does, and orders no certificate: it
    /// fails with the provider's error, or answers `then` once `providers`
    /// is empty. The errors it saw are kept for the checks.
    struct ProviderIssuer {
        providers: VecDeque<Box<dyn DnsProvider>>,
        then: Option<Issued>,
        errors: Vec<String>,
    }

    impl Issuer for ProviderIssuer {
        fn issue(&mut self) -> impl Future<Output = Result<Issued, AcmeError>> {
            let outcome = match self.providers.pop_front() {
                Some(provider) => DnsRecord::new("_acme-challenge.box.example", "digest-value-42")
                    .and_then(|record| {
                        provider.present(&record)?;
                        provider.delete(&record)
                    })
                    .and_then(|()| Err(AcmeError::Config("the provider did not fail".to_owned()))),
                None => self
                    .then
                    .take()
                    .ok_or_else(|| AcmeError::Config("script ended".to_owned())),
            };
            if let Err(err) = &outcome {
                self.errors.push(err.to_string());
                self.errors.push(format!("{err:?}"));
            }
            std::future::ready(outcome)
        }

        fn renewal_window(&mut self, _leaf_der: &[u8]) -> impl Future<Output = Option<(i64, i64)>> {
            std::future::ready(None)
        }
    }

    /// The loop over the providers that reach the network in this build's
    /// tests: their errors come from the real transports (a refused
    /// connection), not from a fixture.
    #[test]
    fn a_failed_present_through_a_real_provider_leaves_no_secret_in_the_log() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let tsig_b64 = base64(TSIG_RAW.as_bytes(), false);
        let providers: VecDeque<Box<dyn DnsProvider>> = VecDeque::from([
            Box::new(detent_acme::AcmeDnsProvider::new(
                "https://127.0.0.1:1",
                "sub-8e21c4",
                ACME_DNS_SECRET,
            )?) as Box<dyn DnsProvider>,
            Box::new(detent_acme::Rfc2136Provider::new(
                "127.0.0.1:1",
                "box.example",
                "k.box.example",
                tsig_b64.as_str(),
                "hmac-sha256",
            )?),
        ]);
        let mut issuer = ProviderIssuer {
            providers,
            then: Some(cert.issued()),
            errors: Vec::new(),
        };
        let mut installer = FakeInstaller::default();
        let mut waits = 0_u32;
        let (done, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || 0,
                |_| {
                    // Two failed rounds and the success, then stop.
                    waits = waits.saturating_add(1);
                    std::future::ready(if waits < 3 {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    })
                },
            ))
        });
        done?;
        assert_eq!(installer.installed.len(), 1);
        // The failures were real: each names its server.
        assert_eq!(issuer.errors.len(), 4, "{:?}", issuer.errors);
        assert!(
            issuer
                .errors
                .iter()
                .all(|text| text.contains("127.0.0.1:1")),
            "{:?}",
            issuer.errors
        );
        let secrets = [ACME_DNS_SECRET, TSIG_RAW, tsig_b64.as_str()];
        for text in &issuer.errors {
            assert_clean("a provider error", text, &secrets);
        }
        // The loop logged the failures, the refusal and the success.
        assert_eq!(logs.matches("renewal failed").count(), 2, "{logs}");
        assert!(logs.contains("the dns-01 provider failed"), "{logs}");
        assert!(logs.contains("serves a new ACME certificate"), "{logs}");
        assert_clean("the log", &logs, &secrets);
        assert!(!logs.contains("BEGIN"), "{logs}");
        assert!(!logs.contains(cert.key_pem.trim()), "{logs}");
        Ok(())
    }

    /// The types the acme process holds print without their secret, and
    /// `secrets.toml` errors quote no line of the file.
    #[test]
    fn the_debug_of_every_type_that_holds_a_secret_is_redacted() -> R {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new()?;
        let write = |name: &str, text: &str| -> Result<std::path::PathBuf, std::io::Error> {
            let path = dir.path().join(name);
            std::fs::write(&path, text)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(path)
        };
        let mut dumps = Vec::new();
        // The secrets file, loaded and printed.
        let secrets = detent_web::secrets::load(&write(
            "good.toml",
            &format!("[acme]\ndns_provider = \"{CF_SECRET}\"\n"),
        )?)?;
        dumps.push(format!("{secrets:?}"));
        dumps.push(format!("{secrets:#?}"));
        dumps.push(format!("{:?}", secrets.dns_provider()));
        // Files the loader refuses, each holding the secret on a line.
        for (name, text) in [
            (
                "bad-type.toml",
                format!("[acme]\ndns_provider = 7 # {CF_SECRET}\n"),
            ),
            ("bad-key.toml", format!("[acme]\n{CF_SECRET} = \"x\"\n")),
            (
                "bad-table.toml",
                format!("[{CF_SECRET}]\ndns_provider = \"x\"\n"),
            ),
            (
                "bad-syntax.toml",
                format!("[acme\ndns_provider = \"{CF_SECRET}\"\n"),
            ),
            (
                "bad-utf8.toml",
                format!("[acme]\ndns_provider = \"{CF_SECRET}\u{1}\"\n"),
            ),
        ] {
            let err = detent_web::secrets::load(&write(name, &text)?)
                .err()
                .ok_or_else(|| format!("{name} was accepted"))?;
            dumps.push(err.to_string());
            dumps.push(format!("{err:?}"));
        }
        // The pair the acme process installs, and what it holds meanwhile.
        let cert = Cert::new(&["a.example"])?;
        let key = KeyPem::new(cert.key_pem.clone());
        let held = Held {
            chain_pem: cert.chain_pem.clone(),
            key: key.clone(),
            not_before: cert.not_before,
            not_after: cert.not_after,
        };
        for text in [
            format!("{key:?}"),
            format!("{held:?}"),
            format!("{held:#?}"),
        ] {
            assert!(!text.contains("PRIVATE KEY"), "{text}");
            assert!(!text.contains(cert.key_pem.trim()), "{text}");
        }
        dumps.push(format!("{:?}", cert.issued()));
        // `[acme]` and its provider hold no secret; they print as they are.
        dumps.push(format!(
            "{:?}",
            detent_web::AcmeConfig {
                provider: Some(detent_web::DnsProviderConfig::Cloudflare {
                    zone_id: "0123456789abcdef0123456789abcdef".to_owned(),
                }),
                ..acme_config(dir.path())
            }
        ));
        // An error that carries a provider's text prints as the loop logs it.
        for err in [
            RenewError::Issue(AcmeError::Config(format!("said {CF_SECRET}"))),
            RenewError::Issue(AcmeError::Credentials(ACCOUNT_KEY.to_owned())),
            RenewError::Chain,
        ] {
            dumps.push(err.reason());
        }
        for dump in &dumps {
            assert_clean("a dump", dump, &[CF_SECRET, ACCOUNT_KEY]);
        }
        assert!(dumps.iter().any(|dump| dump.contains("[redacted]")));
        Ok(())
    }

    /// Account files with a private key in them that the client refuses
    /// (a wrong shape, and a key that is not a key): neither the error nor
    /// the log quotes the file.
    #[test]
    fn an_unusable_account_file_is_never_logged() -> R {
        for (text, logged) in [
            (
                // Not the shape of an account: the parser rejects it.
                format!(
                    r#"{{"id":"{ACCOUNT_KEY}","key_pkcs8":{{"k":"{ACCOUNT_KEY}"}},"directory":7}}"#
                ),
                "the ACME account credentials could not be read",
            ),
            (
                // The shape of an account, with a key the client rejects.
                format!(r#"{{"id":"{ACCOUNT_KEY}","key_pkcs8":"{ACCOUNT_KEY}","directory":"x"}}"#),
                "the ACME server or client failed",
            ),
            (
                // Not JSON at all.
                format!("{ACCOUNT_KEY} {{"),
                "the ACME account credentials could not be read",
            ),
        ] {
            let dir = tempfile::TempDir::new()?;
            let account = dir.path().join("account.json");
            std::fs::write(&account, &text)?;
            let mut issuer =
                AcmeIssuer::new(&acme_config(&account), provider()?, RetryPolicy::new())?;
            let mut installer = FakeInstaller::default();
            let mut failure = None;
            let (done, logs) = capture(|| {
                block_on(async {
                    failure = issuer.issue().await.err();
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        run_loop(
                            &mut issuer,
                            &mut installer,
                            dir.path(),
                            || 0,
                            |_| std::future::pending::<ControlFlow<()>>(),
                        ),
                    )
                    .await
                })
            });
            assert!(done?.is_err(), "the loop ended on its own: {text}");
            let failure = failure.ok_or("the account file was accepted")?;
            let secrets = [ACCOUNT_KEY, CF_SECRET];
            assert_clean("the error", &failure.to_string(), &secrets);
            assert_clean("the error", &format!("{failure:?}"), &secrets);
            assert!(logs.contains(logged), "{logs}");
            assert_clean("the log", &logs, &secrets);
        }
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
        // A message ends the wait as a close does; the loop then reads it.
        worker_end.send(&WorkerMessage::Installed)?;
        let stirred = block_on(wait_or_peer(acme_end.as_fd(), Duration::from_secs(60)))?;
        assert_eq!(stirred, ControlFlow::Break(()));
        Ok(())
    }

    /// A directory whose stored ACME pair is `cert`.
    fn served_dir(cert: &Cert) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let (store, _) = bootstrap_store()?;
        let pair = cert.pair()?;
        logged(|| detent_web::install_acme(dir.path(), &pair, &store))?;
        Ok(dir)
    }

    #[test]
    fn a_forced_check_renews_a_certificate_that_is_not_due() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let mut issuer = FakeIssuer::answering([Ok(cert.issued())]);
        let mut installer = FakeInstaller::default();
        let outcome = block_on(renew_once(
            cert.at(1),
            Some(&pair),
            true,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut None,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: cert.not_before,
                not_after: cert.not_after
            })
        );
        assert_eq!(issuer.calls, 1);
        assert_eq!(installer.installed, vec![cert.chain_pem]);
        Ok(())
    }

    /// A forced check within [`MIN_FORCED_INTERVAL`] of the last order does
    /// not order again: it falls back to the ordinary due check, and the
    /// certificate is not due, so nothing is issued.
    #[test]
    fn a_forced_check_within_the_min_interval_orders_nothing() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let mut issuer = FakeIssuer::default();
        let mut installer = FakeInstaller::default();
        let now = cert.at(1);
        let min_interval = i64::try_from(MIN_FORCED_INTERVAL.as_secs())?;
        let mut last_order = Some(now.saturating_sub(min_interval).saturating_add(1));
        let (outcome, logs) = capture(|| {
            block_on(renew_once(
                now,
                Some(&pair),
                true,
                &mut issuer,
                &mut installer,
                &mut None,
                &mut last_order,
            ))
        });
        assert_eq!(
            outcome?.ok(),
            Some(Outcome::NotDue {
                used_percent: 1,
                not_before: cert.not_before,
                not_after: cert.not_after,
                window: None,
            })
        );
        assert_eq!(issuer.calls, 0);
        assert!(installer.installed.is_empty());
        assert!(logs.contains("too soon after the last order"), "{logs}");
        Ok(())
    }

    /// A forced check once [`MIN_FORCED_INTERVAL`] has passed since the last
    /// order orders again.
    #[test]
    fn a_forced_check_after_the_min_interval_orders_again() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let next = Cert::valid(&["a.example"], (2026, 1, 8), (2026, 1, 18))?;
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let mut installer = FakeInstaller::default();
        let now = cert.at(1);
        let min_interval = i64::try_from(MIN_FORCED_INTERVAL.as_secs())?;
        let mut last_order = Some(now.saturating_sub(min_interval));
        let outcome = block_on(renew_once(
            now,
            Some(&pair),
            true,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut last_order,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: next.not_before,
                not_after: next.not_after
            })
        );
        assert_eq!(issuer.calls, 1);
        assert_eq!(last_order, Some(now));
        Ok(())
    }

    /// A due renewal (not forced) orders even inside
    /// [`MIN_FORCED_INTERVAL`] of the last order: the interval only holds
    /// back a forced order.
    #[test]
    fn a_due_renewal_is_never_held_back_by_the_forced_order_interval() -> R {
        let cert = Cert::new(&["a.example"])?;
        let pair = cert.pair()?;
        let next = Cert::valid(&["a.example"], (2026, 1, 8), (2026, 1, 18))?;
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let mut installer = FakeInstaller::default();
        let now = cert.at(70);
        let outcome = block_on(renew_once(
            now,
            Some(&pair),
            false,
            &mut issuer,
            &mut installer,
            &mut None,
            &mut Some(now),
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: next.not_before,
                not_after: next.not_after
            })
        );
        assert_eq!(issuer.calls, 1);
        Ok(())
    }

    /// A held pair is retried, and nothing is ordered, even when the round
    /// is forced and the forced order is itself refused by the interval:
    /// the held pair is not a new order.
    #[test]
    fn a_held_pair_is_retried_when_a_forced_round_is_refused_an_order() -> R {
        let dir = tempfile::TempDir::new()?;
        let cert = Cert::new(&["a.example"])?;
        let mut issuer = FakeIssuer::default();
        let mut installer = FakeInstaller::default();
        let mut held = Some(Held {
            chain_pem: cert.chain_pem.clone(),
            key: KeyPem::new(cert.key_pem.clone()),
            not_before: cert.not_before,
            not_after: cert.not_after,
        });
        let now = cert.at(1);
        let mut last_order = Some(now);
        let outcome = block_on(round(
            now,
            dir.path(),
            true,
            &mut issuer,
            &mut installer,
            &mut held,
            &mut last_order,
        ))?;
        assert_eq!(
            outcome.ok(),
            Some(Outcome::Renewed {
                not_before: cert.not_before,
                not_after: cert.not_after
            })
        );
        assert_eq!(issuer.calls, 0);
        assert_eq!(installer.installed, vec![cert.chain_pem]);
        assert!(held.is_none());
        Ok(())
    }

    /// Two `RenewNow` within `MIN_FORCED_INTERVAL` of each other, both
    /// arriving while the served certificate is not due: the first orders,
    /// the second is refused and logged as too soon, and the loop goes on.
    #[test]
    fn two_renew_now_within_the_interval_order_only_once() -> R {
        let cert = Cert::new(&["a.example"])?;
        let next = Cert::valid(&["a.example"], (2026, 1, 2), (2026, 1, 12))?;
        let dir = served_dir(&cert)?;
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let mut installer = FakeInstaller {
            requests: VecDeque::from([Ok(()), Ok(())]),
            ..FakeInstaller::default()
        };
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || cert.at(1),
                |_delay| std::future::ready(ControlFlow::Break(())),
            ))
        });
        ended?;
        assert_eq!(issuer.calls, 1);
        assert_eq!(installer.installed, vec![next.chain_pem]);
        assert!(logs.contains("too soon after the last order"), "{logs}");
        assert!(
            logs.contains("the worker closed the acme channel"),
            "{logs}"
        );
        Ok(())
    }

    /// A `RenewNow` that arrives after `MIN_FORCED_INTERVAL` has passed
    /// since the last order starts a second order.
    #[test]
    fn a_renew_now_after_the_interval_orders_again() -> R {
        let cert = Cert::new(&["a.example"])?;
        let first = Cert::valid(&["a.example"], (2026, 1, 2), (2026, 1, 12))?;
        let second = Cert::valid(&["a.example"], (2026, 1, 3), (2026, 1, 13))?;
        let dir = served_dir(&cert)?;
        let mut issuer = FakeIssuer::answering([Ok(first.issued()), Ok(second.issued())]);
        let mut installer = FakeInstaller {
            requests: VecDeque::from([Ok(()), Ok(())]),
            ..FakeInstaller::default()
        };
        let min_interval = i64::try_from(MIN_FORCED_INTERVAL.as_secs())?;
        // t0: the initial, unforced check. t1: the first forced round (no
        // earlier order, so it goes ahead). t2: the second forced round,
        // past the interval since t1, so it goes ahead too.
        let t2 = cert.at(1).saturating_add(min_interval);
        let mut times = VecDeque::from([cert.at(1), cert.at(1), t2]);
        let ended = block_on(run_loop(
            &mut issuer,
            &mut installer,
            dir.path(),
            || times.pop_front().unwrap_or(t2),
            |_delay| std::future::ready(ControlFlow::Break(())),
        ));
        ended?;
        assert_eq!(issuer.calls, 2);
        assert_eq!(installer.installed, vec![first.chain_pem, second.chain_pem]);
        Ok(())
    }

    /// A `RenewNow` that arrives while the loop waits out a backoff after a
    /// failure does not shorten that wait: the sleep seam still sees the
    /// full backoff delay, and only the round after it is forced.
    #[test]
    fn a_renew_now_during_backoff_does_not_shorten_the_wait() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let mut issuer =
            FakeIssuer::answering([Err(AcmeError::NoDns01Challenge), Ok(cert.issued())]);
        let mut installer = FakeInstaller {
            // Readable once during the backoff wait, then quiet.
            requests: VecDeque::from([Ok(())]),
            results: VecDeque::from([Err(closed())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || cert.at(1),
                |delay| {
                    delays.push(delay);
                    let ready = delays.len() != 1;
                    std::future::ready(if ready {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    })
                },
            ))
        });
        ended?;
        assert_eq!(delays, vec![FIRST_RETRY, FIRST_RETRY]);
        assert_eq!(issuer.calls, 2);
        assert!(logs.contains("renewal requested during backoff"), "{logs}");
        assert!(logs.contains("the next attempt is at"), "{logs}");
        Ok(())
    }

    /// Three `RenewNow` messages during one 60 s backoff, arriving (by the
    /// clock seam) at +10 s, +20 s and +50 s: each re-wait is only the time
    /// left to the deadline set when the backoff began, not the full delay
    /// again, so the wait never grows past that deadline. The round after
    /// the backoff is then forced.
    #[test]
    fn repeated_renew_now_during_backoff_only_wait_out_the_remaining_time() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let mut issuer =
            FakeIssuer::answering([Err(AcmeError::NoDns01Challenge), Ok(cert.issued())]);
        let mut installer = FakeInstaller {
            requests: VecDeque::from([Ok(()), Ok(()), Ok(())]),
            results: VecDeque::from([Err(closed())]),
            ..FakeInstaller::default()
        };
        // The round starts at 0; the three requests arrive at 10, 20 and 50.
        let mut clock = VecDeque::from([0, 10, 20, 50]);
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || clock.pop_front().unwrap_or(50),
                |delay| {
                    delays.push(delay);
                    let ready = delays.len() == 4;
                    std::future::ready(if ready {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    })
                },
            ))
        });
        ended?;
        assert_eq!(
            delays,
            vec![
                FIRST_RETRY,
                Duration::from_secs(50),
                Duration::from_secs(40),
                Duration::from_secs(10),
            ]
        );
        assert_eq!(issuer.calls, 2);
        assert_eq!(installer.installed, vec![cert.issued().chain_pem]);
        assert!(logs.contains("renewal requested during backoff"), "{logs}");
        Ok(())
    }

    /// A `RenewNow` recorded during the round that then fails is logged at
    /// once (not only when it arrives later, mid-wait): the backoff that
    /// follows is not shortened either.
    #[test]
    fn a_renew_now_recorded_before_a_failed_round_does_not_shorten_its_backoff() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = tempfile::TempDir::new()?;
        let mut issuer =
            FakeIssuer::answering([Err(AcmeError::NoDns01Challenge), Ok(cert.issued())]);
        let mut installer = FakeInstaller {
            // None before the first round; one recorded during it.
            pending: VecDeque::from([false, true]),
            results: VecDeque::from([Err(closed())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || cert.at(1),
                |delay| {
                    delays.push(delay);
                    std::future::ready(ControlFlow::Continue(()))
                },
            ))
        });
        ended?;
        assert_eq!(delays, vec![FIRST_RETRY]);
        assert_eq!(issuer.calls, 2);
        assert!(logs.contains("renewal requested during backoff"), "{logs}");
        Ok(())
    }

    /// A message other than `RenewNow` during a backoff wait ends the loop,
    /// and the log says why, as it does outside a backoff.
    #[test]
    fn an_unexpected_message_during_a_backoff_wait_ends_the_loop_and_is_logged() -> R {
        let dir = tempfile::TempDir::new()?;
        let mut issuer = FakeIssuer::answering([Err(AcmeError::NoDns01Challenge)]);
        let mut installer = FakeInstaller {
            requests: VecDeque::from([Err(AcmeChannelError::Protocol("expected RenewNow"))]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || 0,
                |delay| {
                    delays.push(delay);
                    std::future::ready(ControlFlow::Break(()))
                },
            ))
        });
        ended?;
        assert_eq!(delays, vec![FIRST_RETRY]);
        assert_eq!(issuer.calls, 1);
        assert!(logs.contains("WARN"), "{logs}");
        assert!(logs.contains("renewals stop"), "{logs}");
        Ok(())
    }

    /// Each wake reads one request: `RenewNow` starts a forced round (the
    /// served certificate is not due), and a closed channel ends the loop.
    #[test]
    fn a_wake_reads_one_request_and_renew_now_forces_a_round() -> R {
        let cert = Cert::new(&["a.example"])?;
        let next = Cert::valid(&["a.example"], (2026, 1, 2), (2026, 1, 12))?;
        let dir = served_dir(&cert)?;
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let mut installer = FakeInstaller {
            requests: VecDeque::from([Ok(())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || cert.at(1),
                |delay| {
                    delays.push(delay);
                    std::future::ready(ControlFlow::Break(()))
                },
            ))
        });
        ended?;
        assert_eq!(issuer.calls, 1);
        assert_eq!(installer.installed, vec![next.chain_pem]);
        assert_eq!(delays, vec![CHECK_INTERVAL, CHECK_INTERVAL]);
        assert!(installer.requests.is_empty());
        assert!(logs.contains("renewal requested by the worker"), "{logs}");
        assert!(
            logs.contains("the worker closed the acme channel"),
            "{logs}"
        );
        Ok(())
    }

    /// A `RenewNow` recorded while `hello` or an install waited for its
    /// answer forces the next round, and that round starts without a wait.
    /// The clock advances past `MIN_FORCED_INTERVAL` between the two, so the
    /// second forced order is not itself throttled.
    #[test]
    fn a_renew_now_recorded_during_hello_or_an_install_forces_the_next_round() -> R {
        let cert = Cert::new(&["a.example"])?;
        let first = Cert::valid(&["a.example"], (2026, 1, 2), (2026, 1, 12))?;
        let second = Cert::valid(&["a.example"], (2026, 1, 3), (2026, 1, 13))?;
        let dir = served_dir(&cert)?;
        let mut issuer = FakeIssuer::answering([Ok(first.issued()), Ok(second.issued())]);
        let mut installer = FakeInstaller {
            // During hello, then during the first install.
            pending: VecDeque::from([true, true]),
            results: VecDeque::from([Ok(()), Err(closed())]),
            ..FakeInstaller::default()
        };
        let mut delays = Vec::new();
        let mut times = VecDeque::from([cert.at(1), cert.at(1).saturating_add(3601)]);
        let (ended, logs) = capture(|| {
            block_on(run_loop(
                &mut issuer,
                &mut installer,
                dir.path(),
                || times.pop_front().unwrap_or_else(|| cert.at(1)),
                |delay| {
                    delays.push(delay);
                    std::future::ready(ControlFlow::Continue(()))
                },
            ))
        });
        ended?;
        assert_eq!(issuer.calls, 2);
        assert_eq!(installer.installed, vec![first.chain_pem, second.chain_pem]);
        assert!(delays.is_empty(), "{delays:?}");
        assert!(logs.contains("renewal requested by the worker"), "{logs}");
        Ok(())
    }

    /// Runs the loop over `dir` with a real client on `acme_end`, the real
    /// wait, and the clock at `now`. Returns the delays, and the logs.
    fn drive_channel(
        acme_end: Channel,
        issuer: &mut FakeIssuer,
        dir: &std::path::Path,
        now: i64,
    ) -> Result<(Vec<Duration>, String), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd as _;
        let peer = acme_end.as_fd().try_clone_to_owned()?;
        let mut client = AcmeClient::new(acme_end);
        let mut delays = Vec::new();
        let (ended, logs) = capture(|| {
            block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    run_loop(
                        issuer,
                        &mut client,
                        dir,
                        || now,
                        |delay| {
                            delays.push(delay);
                            wait_or_peer(peer.as_fd(), delay)
                        },
                    ),
                )
                .await
            })
        });
        ended?.map_err(|_| format!("the loop did not end; slept {delays:?}"))?;
        Ok((delays, logs))
    }

    /// The worker asks for a renewal while the loop waits an hour: the wait
    /// ends at once, and the certificate that is not due is renewed.
    #[test]
    fn a_renew_now_during_a_long_wait_starts_a_forced_round_at_once() -> R {
        let cert = Cert::new(&["a.example"])?;
        let next = Cert::valid(&["a.example"], (2026, 1, 2), (2026, 1, 12))?;
        let dir = served_dir(&cert)?;
        let (acme_end, mut worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || -> Result<AcmeMessage, ChannelError> {
            worker_end.send(&WorkerMessage::RenewNow)?;
            let install = worker_end.recv::<AcmeMessage>()?;
            worker_end.send(&WorkerMessage::Installed)?;
            // The channel closes here: the loop ends in its next wait.
            Ok(install)
        });
        let mut issuer = FakeIssuer::answering([Ok(next.issued())]);
        let started = std::time::Instant::now();
        let (delays, logs) = drive_channel(acme_end, &mut issuer, dir.path(), cert.at(1))?;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(delays, vec![CHECK_INTERVAL, CHECK_INTERVAL]);
        assert_eq!(issuer.calls, 1);
        let install = worker.join().map_err(|_| "worker thread panicked")??;
        assert!(
            matches!(install, AcmeMessage::Install { ref chain_pem, .. } if *chain_pem == next.chain_pem),
            "{install:?}"
        );
        assert!(logs.contains("renewal requested by the worker"), "{logs}");
        assert!(
            logs.contains("the worker closed the acme channel"),
            "{logs}"
        );
        assert!(!logs.contains("BEGIN"), "{logs}");
        Ok(())
    }

    /// A message other than `RenewNow` during a wait ends the loop, and the
    /// log says why.
    #[test]
    fn an_unexpected_message_during_a_wait_ends_the_loop_and_is_logged() -> R {
        let cert = Cert::new(&["a.example"])?;
        let dir = served_dir(&cert)?;
        let (acme_end, mut worker_end) = Channel::pair()?;
        worker_end.send(&WorkerMessage::Installed)?;
        let mut issuer = FakeIssuer::default();
        let (delays, logs) = drive_channel(acme_end, &mut issuer, dir.path(), cert.at(1))?;
        assert_eq!(delays, vec![CHECK_INTERVAL]);
        assert_eq!(issuer.calls, 0);
        assert!(logs.contains("WARN"), "{logs}");
        assert!(logs.contains("expected RenewNow"), "{logs}");
        drop(worker_end);
        Ok(())
    }

    /// The runtime cannot watch a regular file: the wait still runs, to its
    /// end, and says so in the log. Linux only: epoll refuses a regular file,
    /// but kqueue (macOS) accepts one, so there this path cannot be reached
    /// with a file.
    #[cfg(target_os = "linux")]
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
        let (server, _renewer) = acme_link(worker_end)?;
        let ((), logs) = capture(|| {
            serve_installs(
                server,
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

    /// The thread the worker starts and the renewer it gets share one link:
    /// a renewal request reaches the acme end, the acme process installs a
    /// good pair over the channel, and the store then serves it. Once the
    /// thread ends, the renewer fails.
    #[test]
    fn the_install_thread_and_the_renewer_share_one_link() -> R {
        use detent_web::CertRenewer as _;
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
        let (thread, renewer) = thread?;
        assert_eq!(thread.thread().name(), Some("acme-installs"), "{logs}");
        renewer.renew_now()?;
        let mut client = AcmeClient::new(acme_end);
        client.hello()?;
        assert!(client.take_pending_renew());
        client.install(good.chain_pem.clone(), KeyPem::new(good.key_pem.clone()))?;
        renewer.renew_now()?;
        assert_eq!(client.next_request()?, WorkerMessage::RenewNow);
        drop(client);
        thread.join().map_err(|_| "install thread panicked")?;
        assert_ne!(served_leaf(&store), bootstrap);
        assert_eq!(served_leaf(&store), good.pair()?.cert_der());
        let late = renewer
            .renew_now()
            .err()
            .ok_or("the renewer outlived the link")?;
        assert!(!late.is_empty());
        assert!(format!("{renewer:?}").contains("Renewer"));
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
        let (server, _renewer) = acme_link(worker_end)?;
        let ((), logs) = capture(|| {
            serve_installs(
                server,
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
