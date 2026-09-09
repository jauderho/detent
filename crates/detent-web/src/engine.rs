//! The bridge between async handlers and the synchronous [`OpsEngine`].
//!
//! ```text
//!   handler ─┐                                     ┌── privsep Client
//!   handler ─┼─▶ EngineHandle ─▶ mpsc ─▶ ops thread┤
//!   handler ─┘        ▲                            └── OpsEngine (&mut self)
//!                     │ oneshot reply
//!                     └────────────────────────────────────┘
//! ```
//!
//! [`OpsEngine::execute`] takes `&mut self` and owns the single privsep socket
//! that every privileged action travels over. Handlers are `async` and run on
//! a multi-threaded runtime. Rather than wrap the engine in a mutex — which
//! would block runtime worker threads on a socket round-trip, and needs an
//! async mutex to be safe across an `.await` anyway — the engine lives on one
//! dedicated OS thread and is spoken to over a channel.
//!
//! # Guarantees
//!
//! * **Operations are serialized, deliberately.** There is exactly one privsep
//!   channel and the engine is not reentrant, so a queue of one is the correct
//!   shape, not a bottleneck to be optimized away.
//! * **No runtime worker ever blocks.** The only synchronous call an
//!   [`EngineHandle`] makes is a non-blocking `mpsc::Sender::send`; the wait is
//!   a `tokio::sync::oneshot` receive.
//! * **A stopped engine is a typed error, never a hang.** A closed channel and
//!   a dropped reply both surface as [`EngineError::Stopped`].
//! * **A cancelled request does not cancel the work.** Dropping the future
//!   drops the reply channel; the operation still completes and is still
//!   audited, because a half-applied configuration is worse than an unread
//!   answer.

use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

use detent_core::diag::MessageId;
use detent_ops::{Identity, OpOutcome, Operation, OpsEngine, OpsError};
use tokio::sync::oneshot;

/// One unit of work for the engine thread.
#[derive(Debug)]
struct Job {
    /// What to do.
    op: Operation,
    /// On whose behalf.
    who: Identity,
    /// Where the answer goes. Dropped when the caller gave up.
    reply: oneshot::Sender<Result<OpOutcome, OpsError>>,
}

/// Why an operation submitted through an [`EngineHandle`] did not produce an
/// outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The engine ran the operation and it failed.
    #[error(transparent)]
    Ops(#[from] OpsError),
    /// The engine thread is gone: it was joined, or it panicked. Nothing was
    /// run.
    #[error("the operations engine is no longer running")]
    Stopped,
}

impl EngineError {
    /// The Fluent id describing this failure.
    ///
    /// An [`Ops`](Self::Ops) failure keeps the operation layer's own id, so
    /// the web API renders the same sentence the CLI does for the same cause.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        match *self {
            Self::Ops(ref err) => err.message_id(),
            Self::Stopped => MessageId::new("web-engine-stopped"),
        }
    }
}

/// A cloneable, `Send + Sync` ticket to the one engine thread.
///
/// Every handler that needs privileged work holds one, usually inside the
/// axum application state.
#[derive(Debug, Clone)]
pub struct EngineHandle {
    /// The engine thread's inbox.
    jobs: Sender<Job>,
}

impl EngineHandle {
    /// A handle over an arbitrary sender, so a test can build one whose
    /// receiver is already gone — a state [`spawn`] cannot produce.
    #[cfg(test)]
    const fn from_sender(jobs: Sender<Job>) -> Self {
        Self { jobs }
    }

    /// A handle with no engine behind it: every
    /// [`execute`](Self::execute) answers [`EngineError::Stopped`].
    ///
    /// The layers above the engine — state, extractors, the auth routes — do
    /// no privileged work, so their tests want an [`AppState`] without the
    /// thread, the privsep socket and the temporary state root a real engine
    /// needs.
    ///
    /// [`AppState`]: crate::state::AppState
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        let (jobs, inbox) = mpsc::channel();
        drop(inbox);
        Self::from_sender(jobs)
    }

    /// Run `op` on behalf of `who`, waiting for the engine thread.
    ///
    /// # Errors
    ///
    /// [`EngineError::Ops`] when the engine ran the operation and it failed,
    /// [`EngineError::Stopped`] when the engine thread is gone.
    pub async fn execute(&self, op: Operation, who: Identity) -> Result<OpOutcome, EngineError> {
        let (reply, answer) = oneshot::channel();
        self.jobs
            .send(Job { op, who, reply })
            .map_err(|_closed| EngineError::Stopped)?;
        answer
            .await
            .map_err(|_dropped| EngineError::Stopped)?
            .map_err(EngineError::Ops)
    }
}

/// The engine's dedicated OS thread, and the switch that stops it.
///
/// Held by whatever owns the server's lifetime. Dropping it without calling
/// [`join`](Self::join) detaches the thread: the loop still ends once every
/// [`EngineHandle`] is dropped, but nobody observes the engine's shutdown
/// result.
#[derive(Debug)]
pub struct EngineThread {
    /// This end keeps the loop alive; [`join`](Self::join) drops it.
    keepalive: Option<Sender<Job>>,
    /// The running thread; `None` only after [`join`](Self::join).
    thread: Option<JoinHandle<Result<(), OpsError>>>,
}

impl EngineThread {
    /// Stop the engine and wait for it.
    ///
    /// Drops this end of the channel and joins the thread. **Every
    /// [`EngineHandle`] must be dropped first** — the loop runs until the last
    /// sender is gone, so a surviving handle makes this block. In the server
    /// that is automatic: the handles live in the router state, which is
    /// dropped when serving ends.
    ///
    /// # Errors
    ///
    /// The engine's own [`OpsEngine::shutdown`] result, or
    /// [`EngineError::Stopped`] when the thread panicked.
    pub fn join(mut self) -> Result<(), EngineError> {
        drop(self.keepalive.take());
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_panicked| EngineError::Stopped)?
                .map_err(EngineError::Ops),
            None => Err(EngineError::Stopped),
        }
    }
}

/// Move `engine` onto its own thread and return the way to talk to it.
///
/// The thread runs until every [`EngineHandle`] *and* the returned
/// [`EngineThread`] have been dropped, then asks the monitor to exit through
/// [`OpsEngine::shutdown`].
#[must_use]
pub fn spawn(engine: OpsEngine) -> (EngineHandle, EngineThread) {
    let (jobs, inbox) = mpsc::channel::<Job>();
    let thread = thread::spawn(move || {
        let mut engine = engine;
        while let Ok(job) = inbox.recv() {
            let outcome = engine.execute(job.op, &job.who);
            // The caller may have gone away mid-operation. The work is done
            // and audited either way, so an unsendable answer is dropped.
            let _ = job.reply.send(outcome);
        }
        engine.shutdown()
    });
    (
        EngineHandle { jobs: jobs.clone() },
        EngineThread {
            keepalive: Some(jobs),
            thread: Some(thread),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{EngineError, EngineHandle, EngineThread, spawn};

    use std::collections::BTreeMap;
    use std::thread;

    use detent_core::descriptor::{HostProfile, InitSystem, Os};
    use detent_ops::{AllowAll, Identity, NullAudit, OpOutcome, Operation, OpsEngine, OpsError};
    use detent_platform::host::{Detected, HostFacts};
    use detent_platform::privsep::allowlist::{Allowlist, Config};
    use detent_platform::privsep::monitor::{Hooks, Monitor};
    use detent_platform::privsep::transport::Channel;
    use detent_platform::privsep::worker::Client;
    use detent_platform::service;
    use tempfile::TempDir;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../locales/en-US/core.ftl");

    /// A live engine, the temporary state root it must outlive, and the
    /// monitor thread behind its privsep socket.
    struct Fixture {
        engine: Option<OpsEngine>,
        monitor: Option<thread::JoinHandle<()>>,
        _dir: TempDir,
    }

    impl Fixture {
        /// An engine with **no** modules registered: enough to exercise the
        /// bridge (`ListModules`, `HostProfile`, and an unknown module) without
        /// depending on any module's behaviour, and without writing a file.
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let dir = TempDir::new()?;
            let config = Config::with_state_root(dir.path().join("state"));
            let allow = Allowlist::from_modules(&[], &config)?;
            let (monitor_end, worker_end) = Channel::pair()?;
            let monitor = thread::spawn(move || {
                let mut channel = monitor_end;
                let _ = Monitor::new(allow, Hooks::default()).serve(&mut channel);
            });
            let mut client = Client::new(worker_end);
            client.hello()?;
            let host = Detected {
                profile: HostProfile {
                    os: Os::Linux,
                    init: InitSystem::Systemd,
                    hostname: "detent-test".to_owned(),
                    service_versions: BTreeMap::new(),
                    ram_mib: 1024,
                },
                facts: HostFacts::default(),
            };
            let engine = OpsEngine::new(
                Vec::new(),
                client,
                host,
                Box::new(NullAudit),
                Box::new(AllowAll),
                service::for_host(InitSystem::Systemd),
            );
            Ok(Self {
                engine: Some(engine),
                monitor: Some(monitor),
                _dir: dir,
            })
        }

        /// Put the engine on its own thread.
        fn spawn(&mut self) -> Result<(EngineHandle, EngineThread), Box<dyn std::error::Error>> {
            let engine = self.engine.take().ok_or("the engine was already spawned")?;
            Ok(spawn(engine))
        }

        /// Wait for the monitor to exit, after the engine has shut it down.
        fn finish(&mut self) -> R {
            match self.monitor.take() {
                Some(monitor) => monitor
                    .join()
                    .map_err(|_| "the monitor thread panicked".into()),
                None => Ok(()),
            }
        }
    }

    fn who() -> Identity {
        Identity::local("tester")
    }

    #[tokio::test]
    async fn an_operation_crosses_the_thread_and_comes_back() -> R {
        let mut fixture = Fixture::new()?;
        let (handle, thread) = fixture.spawn()?;

        match handle.execute(Operation::ListModules, who()).await? {
            OpOutcome::Modules(modules) => assert!(modules.is_empty()),
            other => return Err(format!("unexpected outcome {other:?}").into()),
        }
        match handle.execute(Operation::HostProfile, who()).await? {
            OpOutcome::Host(report) => assert_eq!(report.profile.hostname, "detent-test"),
            other => return Err(format!("unexpected outcome {other:?}").into()),
        }

        drop(handle);
        thread.join()?;
        fixture.finish()
    }

    #[tokio::test]
    async fn a_failing_operation_keeps_the_operation_layers_message_id() -> R {
        let mut fixture = Fixture::new()?;
        let (handle, thread) = fixture.spawn()?;

        let err = handle
            .execute(
                Operation::GetModule {
                    id: "no-such-module".to_owned(),
                },
                who(),
            )
            .await
            .err()
            .ok_or("expected the unknown module to be refused")?;
        assert!(matches!(
            err,
            EngineError::Ops(OpsError::UnknownModule { .. })
        ));
        assert_eq!(err.message_id().as_str(), "ops-unknown-module");
        assert!(!err.to_string().is_empty());
        assert!(!format!("{err:?}").is_empty());

        drop(handle);
        thread.join()?;
        fixture.finish()
    }

    #[tokio::test]
    async fn concurrent_callers_are_served_one_at_a_time() -> R {
        let mut fixture = Fixture::new()?;
        let (handle, thread) = fixture.spawn()?;

        let mut tasks = Vec::new();
        for _ in 0_u8..8 {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                handle.execute(Operation::ListModules, who()).await
            }));
        }
        for task in tasks {
            let outcome = task.await??;
            assert!(matches!(outcome, OpOutcome::Modules(_)));
        }

        drop(handle);
        thread.join()?;
        fixture.finish()
    }

    #[tokio::test]
    async fn join_stops_the_loop_and_returns_the_engines_shutdown_result() -> R {
        let mut fixture = Fixture::new()?;
        let (handle, thread) = fixture.spawn()?;
        assert!(handle.execute(Operation::ListModules, who()).await.is_ok());
        drop(handle);
        thread.join()?;
        fixture.finish()
    }

    #[test]
    fn dropping_the_thread_handle_without_joining_still_ends_the_loop() -> R {
        let mut fixture = Fixture::new()?;
        let (handle, thread) = fixture.spawn()?;
        drop(thread);
        drop(handle);
        fixture.finish()
    }

    #[tokio::test]
    async fn a_handle_whose_engine_is_gone_reports_stopped() -> R {
        let (jobs, inbox) = std::sync::mpsc::channel();
        drop(inbox);
        let dead = EngineHandle::from_sender(jobs);
        let err = dead
            .execute(Operation::ListModules, who())
            .await
            .err()
            .ok_or("expected a stopped engine")?;
        assert!(matches!(err, EngineError::Stopped));
        assert_eq!(err.message_id().as_str(), "web-engine-stopped");
        assert!(!err.to_string().is_empty());
        assert!(
            CATALOGUE.lines().any(|line| line
                .split('=')
                .next()
                .is_some_and(|k| k.trim() == "web-engine-stopped")),
            "`web-engine-stopped` is missing from core.ftl"
        );
        Ok(())
    }

    #[test]
    fn an_already_joined_thread_reports_stopped() {
        // Reachable only by hand: `join` consumes `self`, so the empty slot
        // cannot occur through the public API. It exists so `join` has no
        // `unwrap` in it.
        let empty = EngineThread {
            keepalive: None,
            thread: None,
        };
        assert!(matches!(empty.join(), Err(EngineError::Stopped)));
    }

    #[test]
    fn a_panicking_engine_thread_reports_stopped_on_join() {
        let thread = thread::spawn(|| -> Result<(), OpsError> {
            Err(OpsError::Unsupported { what: "nothing" })
        });
        let engine_thread = EngineThread {
            keepalive: None,
            thread: Some(thread),
        };
        assert!(matches!(
            engine_thread.join(),
            Err(EngineError::Ops(OpsError::Unsupported { .. }))
        ));
    }
}
