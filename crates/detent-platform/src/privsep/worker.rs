//! The unprivileged side of the privsep pair (PLAN §2.4; ADR-001).
//!
//! [`Client`] is a thin, **blocking** typed wrapper over [`Channel`]. It is
//! deliberately not `async`: the monitor is synchronous by design, and the web
//! layer will call these methods from `tokio::task::spawn_blocking` rather than
//! dragging an async runtime into the privileged protocol.
//!
//! The client holds the [`HelloAck`] tables it received at handshake time, so
//! the rest of the worker can resolve "the `hosts` module's `/etc/hosts`
//! target" to a [`TargetId`] without ever putting a path on the wire.

use crate::fs::atomic::Sha256Digest;

use super::proto::{
    BackupId, BackupInfo, BindingId, BindingInfo, CheckId, CheckOutcome, CommitId, HelloAck,
    ModuleId, PROTO_VERSION, PathKind, PendingService, ProtoError, Request, Response,
    ServiceAction, ServiceOutcome, TargetContents, TargetId, TargetInfo, WriteReceipt,
};
use super::transport::{Channel, ChannelError};

/// A call to the monitor failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The socket failed.
    #[error("privsep channel failed")]
    Channel(#[source] ChannelError),
    /// The monitor refused the request.
    #[error("monitor refused the request: {0}")]
    Remote(#[source] ProtoError),
    /// The monitor answered a different request than the one that was sent.
    /// This is a bug on one side or the other, never normal operation.
    #[error("monitor answered {got} where {want} was expected")]
    Unexpected {
        /// What was expected.
        want: &'static str,
        /// What arrived.
        got: &'static str,
    },
    /// A method was called before [`Client::hello`].
    #[error("privsep handshake has not happened yet")]
    NotGreeted,
}

impl From<ChannelError> for ClientError {
    fn from(err: ChannelError) -> Self {
        Self::Channel(err)
    }
}

/// The worker's handle on the monitor.
#[derive(Debug)]
pub struct Client {
    channel: Channel,
    tables: Option<HelloAck>,
}

impl Client {
    /// Wrap a connected channel. No traffic happens until [`Client::hello`].
    #[must_use]
    pub const fn new(channel: Channel) -> Self {
        Self {
            channel,
            tables: None,
        }
    }

    /// Borrow the channel, e.g. to change its timeouts.
    #[must_use]
    pub const fn channel_mut(&mut self) -> &mut Channel {
        &mut self.channel
    }

    /// The tables learned at handshake time, if the handshake has happened.
    #[must_use]
    pub const fn tables(&self) -> Option<&HelloAck> {
        self.tables.as_ref()
    }

    /// Perform the handshake and cache the allow-list tables.
    ///
    /// # Errors
    ///
    /// [`ClientError::Remote`] when the monitor rejects the version,
    /// [`ClientError::Unexpected`] for a mismatched reply, and
    /// [`ClientError::Channel`] for socket failures.
    pub fn hello(&mut self) -> Result<&HelloAck, ClientError> {
        let response = self.call(&Request::Hello {
            proto: PROTO_VERSION,
        })?;
        match response {
            Response::HelloAck(ack) => {
                self.tables = Some(ack);
                self.tables.as_ref().ok_or(ClientError::NotGreeted)
            }
            other => Err(unexpected("HelloAck", &other)),
        }
    }

    // -- table lookups ------------------------------------------------------

    /// Every target the monitor advertised.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotGreeted`] before the handshake.
    pub fn targets(&self) -> Result<&[TargetInfo], ClientError> {
        Ok(&self.ack()?.targets)
    }

    /// Every service binding the monitor advertised.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotGreeted`] before the handshake.
    pub fn bindings(&self) -> Result<&[BindingInfo], ClientError> {
        Ok(&self.ack()?.bindings)
    }

    /// The id of the module called `name`.
    #[must_use]
    pub fn module_id(&self, name: &str) -> Option<ModuleId> {
        self.tables
            .as_ref()?
            .modules
            .iter()
            .find(|module| module.name == name)
            .map(|module| module.id)
    }

    /// The id of `module`'s target at `path` with kind `kind`.
    ///
    /// The path is matched against what the *monitor* advertised; it is never
    /// sent back. `None` means the worker asked for something outside the
    /// allow-list, which is a bug in the worker, not a permission failure.
    #[must_use]
    pub fn target_id(&self, module: &str, path: &str, kind: PathKind) -> Option<TargetId> {
        let module = self.module_id(module)?;
        self.tables
            .as_ref()?
            .targets
            .iter()
            .find(|target| target.module == module && target.path == path && target.kind == kind)
            .map(|target| target.id)
    }

    /// The id of `module`'s first service binding.
    #[must_use]
    pub fn binding_id(&self, module: &str) -> Option<BindingId> {
        let module = self.module_id(module)?;
        self.tables
            .as_ref()?
            .bindings
            .iter()
            .find(|binding| binding.module == module)
            .map(|binding| binding.id)
    }

    /// The id of `module`'s first external check.
    #[must_use]
    pub fn check_id(&self, module: &str) -> Option<CheckId> {
        let module = self.module_id(module)?;
        self.tables
            .as_ref()?
            .checks
            .iter()
            .find(|check| check.module == module)
            .map(|check| check.id)
    }

    // -- operations ---------------------------------------------------------

    /// Read a target's current contents and digest.
    ///
    /// # Errors
    ///
    /// As [`Client::hello`], plus [`ClientError::Remote`] when the target
    /// cannot be read.
    pub fn read_target(&mut self, target: TargetId) -> Result<TargetContents, ClientError> {
        match self.checked_call(&Request::ReadTarget { target })? {
            Response::Target(contents) => Ok(contents),
            other => Err(unexpected("Target", &other)),
        }
    }

    /// Replace a target's contents atomically.
    ///
    /// `expected_prev` is the digest from the read that produced the edit;
    /// passing it turns a lost update into [`ProtoError::Conflict`].
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`].
    pub fn write_target(
        &mut self,
        target: TargetId,
        expected_prev: Option<Sha256Digest>,
        bytes: Vec<u8>,
    ) -> Result<WriteReceipt, ClientError> {
        match self.checked_call(&Request::WriteTarget {
            target,
            expected_prev,
            bytes,
        })? {
            Response::Written(receipt) => Ok(receipt),
            other => Err(unexpected("Written", &other)),
        }
    }

    /// Run a module's upstream validator against candidate bytes.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]; [`ProtoError::Unavailable`] when no check
    /// runner is wired up.
    pub fn run_check(
        &mut self,
        check: CheckId,
        bytes: Vec<u8>,
    ) -> Result<CheckOutcome, ClientError> {
        match self.checked_call(&Request::RunCheck { check, bytes })? {
            Response::Checked(outcome) => Ok(outcome),
            other => Err(unexpected("Checked", &other)),
        }
    }

    /// Act on a service binding.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]; [`ProtoError::ActionNotAllowed`] when the
    /// module did not declare the action.
    pub fn service(
        &mut self,
        binding: BindingId,
        action: ServiceAction,
    ) -> Result<ServiceOutcome, ClientError> {
        match self.checked_call(&Request::Service { binding, action })? {
            Response::Serviced(outcome) => Ok(outcome),
            other => Err(unexpected("Serviced", &other)),
        }
    }

    /// List a module's retained backups, newest first.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`].
    pub fn list_backups(&mut self, module: ModuleId) -> Result<Vec<BackupInfo>, ClientError> {
        match self.checked_call(&Request::ListBackups { module })? {
            Response::Backups(entries) => Ok(entries),
            other => Err(unexpected("Backups", &other)),
        }
    }

    /// Restore one entry of the listing from [`Client::list_backups`].
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`].
    pub fn restore(
        &mut self,
        module: ModuleId,
        backup: BackupId,
    ) -> Result<(TargetId, Sha256Digest), ClientError> {
        match self.checked_call(&Request::Restore { module, backup })? {
            Response::Restored { target, new_digest } => Ok((target, new_digest)),
            other => Err(unexpected("Restored", &other)),
        }
    }

    /// Arm the commit-confirm timer over every write since the last commit.
    ///
    /// Returns the timeout the monitor actually applied, which may be clamped,
    /// and how many targets it will roll back.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]; [`ProtoError::CommitPending`] when another
    /// commit is already armed.
    pub fn start_confirm_timer(
        &mut self,
        commit: CommitId,
        timeout_s: u16,
        service: Option<PendingService>,
    ) -> Result<(u16, u16), ClientError> {
        match self.checked_call(&Request::StartConfirmTimer {
            commit,
            timeout_s,
            service,
        })? {
            Response::ConfirmTimerStarted {
                timeout_s,
                rollback_targets,
                ..
            } => Ok((timeout_s, rollback_targets)),
            other => Err(unexpected("ConfirmTimerStarted", &other)),
        }
    }

    /// Report whether a commit-confirm window is currently pending.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`].
    pub fn pending_commit(&mut self) -> Result<Option<CommitId>, ClientError> {
        match self.checked_call(&Request::PendingCommit)? {
            Response::Pending(commit) => Ok(commit),
            other => Err(unexpected("Pending", &other)),
        }
    }

    /// Confirm an armed commit, discarding its rollback.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]; [`ProtoError::CommitExpired`] when the
    /// deadline passed, in which case the monitor rolls the commit back before
    /// replying, or [`ProtoError::UnknownId`] when nothing is armed under that
    /// id.
    pub fn confirm_commit(&mut self, commit: CommitId) -> Result<CommitId, ClientError> {
        match self.checked_call(&Request::ConfirmCommit { commit })? {
            Response::Committed { commit } => Ok(commit),
            other => Err(unexpected("Committed", &other)),
        }
    }

    /// Roll a pending commit back immediately, instead of waiting for its
    /// deadline. Returns the commit and how many targets were restored.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]; [`ProtoError::UnknownId`] when nothing is
    /// armed under that id — the same answer a second call for the same
    /// commit gets, or a call after the deadline already rolled it back on
    /// its own.
    pub fn rollback_commit(&mut self, commit: CommitId) -> Result<(CommitId, u16), ClientError> {
        match self.checked_call(&Request::RollbackCommit { commit })? {
            Response::RolledBack { commit, restored } => Ok((commit, restored)),
            other => Err(unexpected("RolledBack", &other)),
        }
    }

    /// Ask the monitor to authenticate and atomically install a staged release.
    ///
    /// `tag` names both worker-staged inputs under `<state_root>/update/staged`:
    /// the binary itself and `<tag>.sigstore.json`. `len` and `sha256` bind
    /// the binary; the monitor still hashes the same bytes it opens and verifies
    /// their Sigstore bundle before swapping.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`]. Authenticity failures are reported coarsely
    /// as [`ProtoError::VerificationFailed`].
    pub fn replace_binary(
        &mut self,
        tag: &str,
        len: u64,
        sha256: Sha256Digest,
    ) -> Result<String, ClientError> {
        match self.checked_call(&Request::ReplaceBinary {
            tag: tag.to_owned(),
            len,
            sha256,
        })? {
            Response::Replaced { version } => Ok(version),
            other => Err(unexpected("Replaced", &other)),
        }
    }

    /// Ask the monitor to exit.
    ///
    /// # Errors
    ///
    /// As [`Client::read_target`].
    pub fn shutdown(&mut self) -> Result<(), ClientError> {
        match self.checked_call(&Request::Shutdown)? {
            Response::ShuttingDown => Ok(()),
            other => Err(unexpected("ShuttingDown", &other)),
        }
    }

    // -- plumbing -----------------------------------------------------------

    fn ack(&self) -> Result<&HelloAck, ClientError> {
        self.tables.as_ref().ok_or(ClientError::NotGreeted)
    }

    /// Send a request and read exactly one response.
    fn call(&mut self, request: &Request) -> Result<Response, ClientError> {
        self.channel.send(request)?;
        Ok(self.channel.recv::<Response>()?)
    }

    /// As [`Client::call`], but requires the handshake to have happened and
    /// turns [`Response::Error`] into [`ClientError::Remote`].
    fn checked_call(&mut self, request: &Request) -> Result<Response, ClientError> {
        if self.tables.is_none() {
            return Err(ClientError::NotGreeted);
        }
        match self.call(request)? {
            Response::Error(err) => Err(ClientError::Remote(err)),
            other => Ok(other),
        }
    }
}

fn unexpected(want: &'static str, got: &Response) -> ClientError {
    if let Response::Error(err) = got {
        return ClientError::Remote(err.clone());
    }
    ClientError::Unexpected {
        want,
        got: variant_name(got),
    }
}

const fn variant_name(response: &Response) -> &'static str {
    match response {
        Response::HelloAck(_) => "HelloAck",
        Response::Target(_) => "Target",
        Response::Written(_) => "Written",
        Response::Checked(_) => "Checked",
        Response::Serviced(_) => "Serviced",
        Response::Backups(_) => "Backups",
        Response::Restored { .. } => "Restored",
        Response::ConfirmTimerStarted { .. } => "ConfirmTimerStarted",
        Response::Committed { .. } => "Committed",
        Response::ShuttingDown => "ShuttingDown",
        Response::Error(_) => "Error",
        Response::RolledBack { .. } => "RolledBack",
        Response::Replaced { .. } => "Replaced",
        Response::Pending(_) => "Pending",
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, ClientError};
    use crate::fs::atomic::Sha256Digest;
    use crate::privsep::proto::{
        BackupId, BindingId, CheckId, CheckOutcome, CommitId, HelloAck, ModuleId, PROTO_VERSION,
        PathKind, ProtoError, Request, Response, ServiceAction, ServiceOutcome, TargetContents,
        TargetId, WriteReceipt,
    };
    use crate::privsep::transport::Channel;
    use std::thread;

    fn hello_ack() -> HelloAck {
        HelloAck {
            proto: PROTO_VERSION,
            modules: Vec::new(),
            targets: Vec::new(),
            checks: Vec::new(),
            bindings: Vec::new(),
        }
    }

    /// A fake monitor that answers `Request::Hello` with `Response::HelloAck`
    /// and every later request with `wrong`, regardless of what was asked —
    /// enough to exercise `Client`'s "the monitor answered the wrong thing"
    /// paths (`unexpected`/`variant_name`) without teaching a fake peer the
    /// whole protocol.
    fn client_with_scripted_reply(
        wrong: Response,
    ) -> Result<(Client, thread::JoinHandle<()>), Box<dyn std::error::Error>> {
        let (mut monitor_end, worker_end) = Channel::pair()?;
        let handle = thread::spawn(move || {
            if monitor_end.recv::<Request>().is_err() {
                return;
            }
            if monitor_end.send(&Response::HelloAck(hello_ack())).is_err() {
                return;
            }
            loop {
                let Ok(_request) = monitor_end.recv::<Request>() else {
                    return;
                };
                if monitor_end.send(&wrong).is_err() {
                    return;
                }
            }
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        Ok((client, handle))
    }

    #[test]
    fn methods_reject_use_before_hello() -> Result<(), Box<dyn std::error::Error>> {
        let (_monitor_end, worker_end) = Channel::pair()?;
        let mut client = Client::new(worker_end);
        assert!(client.targets().is_err());
        assert!(client.bindings().is_err());
        assert!(matches!(
            client.read_target(TargetId(0)),
            Err(ClientError::NotGreeted)
        ));
        assert_eq!(client.module_id("fake"), None);
        assert_eq!(client.target_id("fake", "/etc/hosts", PathKind::File), None);
        assert_eq!(client.binding_id("fake"), None);
        assert_eq!(client.check_id("fake"), None);
        Ok(())
    }

    #[test]
    fn a_dead_channel_surfaces_as_a_client_channel_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let (monitor_end, worker_end) = Channel::pair()?;
        // No peer left to answer: `Client::call`'s `channel.send(request)?`
        // (or the `recv` right after it) must propagate a `ChannelError`
        // through `From<ChannelError> for ClientError`.
        drop(monitor_end);
        let mut client = Client::new(worker_end);
        assert!(matches!(client.hello(), Err(ClientError::Channel(_))));
        Ok(())
    }

    #[test]
    fn targets_and_bindings_read_through_the_cached_tables()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut monitor_end, worker_end) = Channel::pair()?;
        let handle = thread::spawn(move || {
            let Ok(_hello) = monitor_end.recv::<Request>() else {
                return;
            };
            let _ = monitor_end.send(&Response::HelloAck(hello_ack()));
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        assert_eq!(client.targets().ok(), Some([].as_slice()));
        assert_eq!(client.bindings().ok(), Some([].as_slice()));
        // The scripted peer thread panicking (rather than returning early)
        // would be a bug in the test double; a plain `join` assertion
        // surfaces that without requiring `Box<dyn Any + Send>` (the thread
        // panic payload type) to implement `std::error::Error`, which it
        // does not.
        assert!(handle.join().is_ok());
        Ok(())
    }

    #[test]
    fn hello_reports_a_remote_error_when_the_monitor_sends_one()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut monitor_end, worker_end) = Channel::pair()?;
        let handle = thread::spawn(move || {
            let Ok(_hello) = monitor_end.recv::<Request>() else {
                return;
            };
            let _ = monitor_end.send(&Response::Error(ProtoError::Unavailable(
                "not ready".to_owned(),
            )));
        });
        let mut client = Client::new(worker_end);
        let err = client.hello().err();
        assert!(matches!(
            err,
            Some(ClientError::Remote(ProtoError::Unavailable(_)))
        ));
        assert!(handle.join().is_ok());
        Ok(())
    }

    #[test]
    fn hello_reports_unexpected_for_a_wrong_response_type() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut monitor_end, worker_end) = Channel::pair()?;
        let handle = thread::spawn(move || {
            let Ok(_hello) = monitor_end.recv::<Request>() else {
                return;
            };
            let _ = monitor_end.send(&Response::ShuttingDown);
        });
        let mut client = Client::new(worker_end);
        let err = client.hello().err();
        assert!(matches!(
            err,
            Some(ClientError::Unexpected {
                want: "HelloAck",
                got: "ShuttingDown"
            })
        ));
        assert!(handle.join().is_ok());
        Ok(())
    }

    // Every non-`hello` method's "the monitor answered something else" arm,
    // each exercised with a different wrong `Response` variant so that,
    // together, they also cover every arm of `variant_name`. Split into one
    // test per method to stay under `clippy::too_many_lines`.

    #[test]
    fn read_target_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::HelloAck(hello_ack()))?;
        assert!(matches!(
            client.read_target(TargetId(0)),
            Err(ClientError::Unexpected {
                want: "Target",
                got: "HelloAck"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn write_target_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::Target(TargetContents {
            target: TargetId(0),
            bytes: Vec::new(),
            digest: Sha256Digest::of(b"x"),
        }))?;
        assert!(matches!(
            client.write_target(TargetId(0), None, Vec::new()),
            Err(ClientError::Unexpected {
                want: "Written",
                got: "Target"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn run_check_reports_unexpected_for_a_wrong_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut client, handle) = client_with_scripted_reply(Response::Written(WriteReceipt {
            target: TargetId(0),
            prev_digest: None,
            new_digest: Sha256Digest::of(b"x"),
            created: false,
            backed_up: false,
            owner_preserved: true,
        }))?;
        assert!(matches!(
            client.run_check(CheckId(0), Vec::new()),
            Err(ClientError::Unexpected {
                want: "Checked",
                got: "Written"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn service_reports_unexpected_for_a_wrong_response() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::Checked(CheckOutcome {
            check: CheckId(0),
            passed: true,
            exit_code: Some(0),
            detail: String::new(),
        }))?;
        assert!(matches!(
            client.service(BindingId(0), ServiceAction::Restart),
            Err(ClientError::Unexpected {
                want: "Serviced",
                got: "Checked"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn list_backups_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) =
            client_with_scripted_reply(Response::Serviced(ServiceOutcome {
                binding: BindingId(0),
                active: true,
                detail: String::new(),
            }))?;
        assert!(matches!(
            client.list_backups(ModuleId(0)),
            Err(ClientError::Unexpected {
                want: "Backups",
                got: "Serviced"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn restore_reports_unexpected_for_a_wrong_response() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::Backups(Vec::new()))?;
        assert!(matches!(
            client.restore(ModuleId(0), BackupId(0)),
            Err(ClientError::Unexpected {
                want: "Restored",
                got: "Backups"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn start_confirm_timer_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::Restored {
            target: TargetId(0),
            new_digest: Sha256Digest::of(b"x"),
        })?;
        assert!(matches!(
            client.start_confirm_timer(CommitId(0), 1, None),
            Err(ClientError::Unexpected {
                want: "ConfirmTimerStarted",
                got: "Restored"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn confirm_commit_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::ConfirmTimerStarted {
            commit: CommitId(0),
            timeout_s: 1,
            rollback_targets: 0,
        })?;
        assert!(matches!(
            client.confirm_commit(CommitId(0)),
            Err(ClientError::Unexpected {
                want: "Committed",
                got: "ConfirmTimerStarted"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn shutdown_reports_unexpected_for_a_wrong_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut client, handle) = client_with_scripted_reply(Response::RolledBack {
            commit: CommitId(0),
            restored: 0,
        })?;
        assert!(matches!(
            client.shutdown(),
            Err(ClientError::Unexpected {
                want: "ShuttingDown",
                got: "RolledBack"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn rollback_commit_reports_unexpected_for_a_wrong_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, handle) = client_with_scripted_reply(Response::Committed {
            commit: CommitId(0),
        })?;
        assert!(matches!(
            client.rollback_commit(CommitId(0)),
            Err(ClientError::Unexpected {
                want: "RolledBack",
                got: "Committed"
            })
        ));
        drop(client);
        let _ = handle.join();
        Ok(())
    }
}
