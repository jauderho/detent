//! The channel between the acme process and the worker (ADR-015).
//!
//! ```text
//!   serve ──fork──▶ acme (uid `detent`, confined, outbound only)
//!     │                │ AcmeMessage { Hello | Install { chain, key } }
//!     └──fork──▶ worker◀┘ WorkerMessage { Hello | Installed | Refused
//!                                          | RenewNow }
//! ```
//!
//! [`spawn_acme`](super::spawn::spawn_acme) creates the socket pair. The
//! acme process speaks first: [`AcmeMessage::Hello`], then one
//! [`AcmeMessage::Install`] for each issued certificate. The worker checks the
//! pair, stores it and answers [`WorkerMessage::Installed`] or
//! [`WorkerMessage::Refused`]. The acme process never writes the served
//! certificate itself. The worker may also send [`WorkerMessage::RenewNow`]
//! on its own at any time; the acme process reads it with
//! [`AcmeClient::next_request`], or records it when it arrives before an
//! answer.
//!
//! # Versions
//!
//! Both sides ship in the same binary, so there is no negotiation: the
//! versions in the two `Hello`s must be equal, or the worker refuses and
//! stops. The enums are `#[non_exhaustive]` for Rust callers, so a later
//! slice can add `Status`; on the wire they stay closed, as in
//! [`proto`](super::proto): `postcard` does not decode an unknown
//! discriminant, and the receiver stops.
//!
//! # The key
//!
//! [`KeyPem`] is a `String` whose `Debug` prints `[redacted]`, so a logged
//! message never shows the private key. The memory is not wiped: the frame
//! buffers in [`transport`](super::transport) hold the same bytes and are not
//! wiped either, and this crate links no `zeroize`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::transport::{Channel, ChannelError};

/// Version of this protocol. Both sides must send the same value in
/// `Hello`.
///
/// Version 2 added [`WorkerMessage::RenewNow`]. A version 1 acme process
/// would not decode it, so the version changed with the message.
pub const ACME_PROTO_VERSION: u16 = 2;

/// Read and write timeout on both ends of the acme channel.
///
/// The acme process waits this long for the worker's answer to an
/// `Install`: parsing a chain and writing two small files take well under a
/// second, so 60 s is ample, and a worker that does not answer in that time
/// is reported within the same renewal attempt instead of blocking the
/// loop. The worker treats a read timeout as idle time and keeps waiting
/// ([`AcmeServer::serve`]), so the timeout does not limit the hour between
/// checks.
pub const ACME_TIMEOUT: Duration = Duration::from_secs(60);

/// A PEM private key. `Debug` prints `[redacted]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPem(String);

impl KeyPem {
    /// Wrap `pem`.
    #[must_use]
    pub const fn new(pem: String) -> Self {
        Self(pem)
    }

    /// The PEM text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for KeyPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// What the acme process sends to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AcmeMessage {
    /// First message: the sender's [`ACME_PROTO_VERSION`].
    Hello {
        /// The sender's protocol version.
        version: u16,
    },
    /// Serve this certificate from now on.
    Install {
        /// The issued chain, leaf first, PEM.
        chain_pem: String,
        /// The leaf's private key, PEM.
        key_pem: KeyPem,
    },
}

/// What the worker answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerMessage {
    /// Answer to [`AcmeMessage::Hello`]: the worker's
    /// [`ACME_PROTO_VERSION`].
    Hello {
        /// The worker's protocol version.
        version: u16,
    },
    /// The pair is stored and served.
    Installed,
    /// The worker did not install the pair, or refused the message.
    Refused {
        /// Why.
        reason: String,
    },
    /// Not an answer: the worker asks the acme process to renew now. It can
    /// arrive at any time, also while the acme process waits for an answer
    /// ([`AcmeClient::take_pending_renew`]).
    RenewNow,
}

/// A failure on the acme channel, seen from either side.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcmeChannelError {
    /// The channel failed: closed, timed out, or a frame did not decode.
    #[error("acme channel failed")]
    Channel(#[source] ChannelError),
    /// The peer speaks another protocol version.
    #[error("acme protocol version {theirs} does not match {ours}")]
    Version {
        /// This side's version.
        ours: u16,
        /// The peer's version.
        theirs: u16,
    },
    /// The worker refused the message.
    #[error("the worker refused: {0}")]
    Refused(String),
    /// A message arrived that is not valid at this point.
    #[error("acme protocol violation: {0}")]
    Protocol(&'static str),
}

impl From<ChannelError> for AcmeChannelError {
    fn from(err: ChannelError) -> Self {
        Self::Channel(err)
    }
}

/// The acme process's side of the channel.
#[derive(Debug)]
pub struct AcmeClient {
    channel: Channel,
    /// A `RenewNow` arrived during [`AcmeClient::call`].
    pending_renew: bool,
}

impl AcmeClient {
    /// A client on `channel`.
    #[must_use]
    pub const fn new(channel: Channel) -> Self {
        Self {
            channel,
            pending_renew: false,
        }
    }

    /// True once when a `RenewNow` arrived while [`AcmeClient::hello`] or
    /// [`AcmeClient::install`] waited for an answer; the flag is then
    /// cleared.
    pub const fn take_pending_renew(&mut self) -> bool {
        std::mem::replace(&mut self.pending_renew, false)
    }

    /// Read one message the worker sent on its own, after the channel was
    /// seen readable. Only [`WorkerMessage::RenewNow`] is valid.
    ///
    /// # Errors
    ///
    /// [`AcmeChannelError::Protocol`] for any other message, and
    /// [`AcmeChannelError::Channel`] when the channel fails: `Closed` when
    /// the worker closed it, `Timeout` when nothing arrived.
    pub fn next_request(&mut self) -> Result<WorkerMessage, AcmeChannelError> {
        match self.channel.recv::<WorkerMessage>()? {
            WorkerMessage::RenewNow => Ok(WorkerMessage::RenewNow),
            _ => Err(AcmeChannelError::Protocol("expected RenewNow")),
        }
    }

    /// Send `Hello` and check the worker's answer.
    ///
    /// # Errors
    ///
    /// [`AcmeChannelError::Version`] when the worker speaks another version,
    /// [`AcmeChannelError::Refused`] when it refused ours,
    /// [`AcmeChannelError::Protocol`] for any other answer, and
    /// [`AcmeChannelError::Channel`] when the channel fails.
    pub fn hello(&mut self) -> Result<(), AcmeChannelError> {
        match self.call(&AcmeMessage::Hello {
            version: ACME_PROTO_VERSION,
        })? {
            WorkerMessage::Hello { version } if version == ACME_PROTO_VERSION => Ok(()),
            WorkerMessage::Hello { version } => Err(AcmeChannelError::Version {
                ours: ACME_PROTO_VERSION,
                theirs: version,
            }),
            _ => Err(AcmeChannelError::Protocol("expected Hello")),
        }
    }

    /// Ask the worker to install `chain_pem` and `key_pem`.
    ///
    /// # Errors
    ///
    /// [`AcmeChannelError::Refused`] with the worker's reason,
    /// [`AcmeChannelError::Protocol`] for an answer other than `Installed`,
    /// and [`AcmeChannelError::Channel`] when the channel fails.
    pub fn install(&mut self, chain_pem: String, key_pem: KeyPem) -> Result<(), AcmeChannelError> {
        match self.call(&AcmeMessage::Install { chain_pem, key_pem })? {
            WorkerMessage::Installed => Ok(()),
            _ => Err(AcmeChannelError::Protocol("expected Installed")),
        }
    }

    /// Send `message` and read one answer; a `Refused` answer is an error.
    /// A `RenewNow` read before the answer is recorded, not returned.
    fn call(&mut self, message: &AcmeMessage) -> Result<WorkerMessage, AcmeChannelError> {
        self.channel.send(message)?;
        loop {
            match self.channel.recv::<WorkerMessage>()? {
                WorkerMessage::RenewNow => self.pending_renew = true,
                WorkerMessage::Refused { reason } => {
                    return Err(AcmeChannelError::Refused(reason));
                }
                answer => return Ok(answer),
            }
        }
    }
}

/// Split the worker's end of the acme channel into the [`AcmeServer`], which
/// reads and answers, and an [`AcmeRenewer`], which another thread uses to
/// send [`WorkerMessage::RenewNow`].
///
/// # Errors
///
/// [`AcmeChannelError::Channel`] when the socket cannot be duplicated
/// ([`Channel::try_clone`]).
pub fn acme_link(channel: Channel) -> Result<(AcmeServer, AcmeRenewer), AcmeChannelError> {
    let writer = Arc::new(Mutex::new(channel.try_clone()?));
    Ok((
        AcmeServer {
            reader: channel,
            writer: Arc::clone(&writer),
        },
        AcmeRenewer { writer },
    ))
}

/// The worker's side of the acme channel: it reads every message and
/// answers through the writer it shares with the [`AcmeRenewer`]s.
#[derive(Debug)]
pub struct AcmeServer {
    /// The only handle that reads.
    reader: Channel,
    /// Every write goes through this lock, so frames never interleave.
    writer: Arc<Mutex<Channel>>,
}

/// Sends [`WorkerMessage::RenewNow`] from any thread. Clones share one
/// writer with the [`AcmeServer`].
#[derive(Debug, Clone)]
pub struct AcmeRenewer {
    writer: Arc<Mutex<Channel>>,
}

impl AcmeRenewer {
    /// Ask the acme process to renew now. The acme process may be in the
    /// middle of an exchange; it records the request then.
    ///
    /// # Errors
    ///
    /// [`AcmeChannelError::Channel`] when the channel fails: `Closed` once
    /// the acme process or the [`AcmeServer`] has stopped.
    pub fn renew_now(&self) -> Result<(), AcmeChannelError> {
        Ok(send(&self.writer, &WorkerMessage::RenewNow)?)
    }
}

/// Write `message` under the lock. A poisoned lock is still used: no code
/// that can panic runs while it is held, so the stream is not torn.
fn send(writer: &Mutex<Channel>, message: &WorkerMessage) -> Result<(), ChannelError> {
    writer
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .send(message)
}

impl AcmeServer {
    /// Answer the acme process until it closes the channel.
    ///
    /// `install` receives each chain and key after a matching `Hello`, and
    /// returns `Err(reason)` to refuse the pair. A read timeout is idle
    /// time, not an end: the acme process is quiet for an hour between
    /// checks. When this returns, the write side of the socket is shut
    /// down, so the acme process sees the channel close even while an
    /// [`AcmeRenewer`] is alive, and later `renew_now` calls fail.
    ///
    /// # Errors
    ///
    /// `Ok(())` when the acme process closed the channel. Otherwise
    /// [`AcmeChannelError::Protocol`] after the worker refused a `Hello`
    /// with another version or an `Install` before `Hello`, and
    /// [`AcmeChannelError::Channel`] when the channel fails or a frame does
    /// not decode. The worker then keeps serving its last certificate
    /// (ADR-015).
    pub fn serve(
        mut self,
        install: impl FnMut(&str, &KeyPem) -> Result<(), String>,
    ) -> Result<(), AcmeChannelError> {
        let served = serve_on(&mut self.reader, &self.writer, install);
        // The peer may be gone already; the session's outcome is `served`.
        let _shut = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .shutdown_write();
        served
    }
}

/// The body of [`AcmeServer::serve`].
fn serve_on(
    reader: &mut Channel,
    writer: &Mutex<Channel>,
    mut install: impl FnMut(&str, &KeyPem) -> Result<(), String>,
) -> Result<(), AcmeChannelError> {
    let mut greeted = false;
    loop {
        let message = match reader.recv::<AcmeMessage>() {
            Ok(message) => message,
            Err(ChannelError::Timeout) => continue,
            Err(ChannelError::Closed) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let (answer, stop) = match message {
            AcmeMessage::Hello { version } if version == ACME_PROTO_VERSION => {
                greeted = true;
                (
                    WorkerMessage::Hello {
                        version: ACME_PROTO_VERSION,
                    },
                    None,
                )
            }
            AcmeMessage::Hello { version } => (
                WorkerMessage::Refused {
                    reason: format!(
                        "acme protocol version {version} does not match {ACME_PROTO_VERSION}"
                    ),
                },
                Some("version mismatch"),
            ),
            AcmeMessage::Install { .. } if !greeted => (
                WorkerMessage::Refused {
                    reason: "Install before Hello".to_owned(),
                },
                Some("Install before Hello"),
            ),
            AcmeMessage::Install { chain_pem, key_pem } => {
                let answer = match install(&chain_pem, &key_pem) {
                    Ok(()) => WorkerMessage::Installed,
                    Err(reason) => WorkerMessage::Refused { reason },
                };
                (answer, None)
            }
        };
        send(writer, &answer)?;
        if let Some(violation) = stop {
            return Err(AcmeChannelError::Protocol(violation));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACME_PROTO_VERSION, AcmeChannelError, AcmeClient, AcmeMessage, KeyPem, WorkerMessage,
        acme_link,
    };
    use crate::privsep::proto::MAX_FRAME;
    use crate::privsep::transport::{Channel, ChannelError};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Stand-in PEM text: low entropy on purpose (CI runs gitleaks).
    const CHAIN: &str = "chain line one\nchain line two\n";
    const KEY: &str = "not a real pem";

    /// Serves `channel` with `install` and no renewer.
    fn serve_without_renewer(
        channel: Channel,
        install: impl FnMut(&str, &KeyPem) -> Result<(), String>,
    ) -> Result<(), AcmeChannelError> {
        let (server, _renewer) = acme_link(channel)?;
        server.serve(install)
    }

    #[test]
    fn debug_never_prints_the_key() {
        let message = AcmeMessage::Install {
            chain_pem: CHAIN.to_owned(),
            key_pem: KeyPem::new(KEY.to_owned()),
        };
        let shown = format!("{message:?}");
        assert!(shown.contains("[redacted]"), "{shown}");
        assert!(!shown.contains(KEY), "{shown}");
        assert!(shown.contains("chain line one"), "{shown}");
        assert_eq!(format!("{:?}", KeyPem::new(KEY.to_owned())), "[redacted]");
        assert_eq!(KeyPem::new(KEY.to_owned()).expose(), KEY);
    }

    #[test]
    fn every_message_round_trips_over_a_channel() -> R {
        let (mut acme, mut worker) = Channel::pair()?;
        for message in [
            AcmeMessage::Hello {
                version: ACME_PROTO_VERSION,
            },
            AcmeMessage::Install {
                chain_pem: CHAIN.to_owned(),
                key_pem: KeyPem::new(KEY.to_owned()),
            },
        ] {
            acme.send(&message)?;
            assert_eq!(worker.recv::<AcmeMessage>()?, message);
        }
        for message in [
            WorkerMessage::Hello {
                version: ACME_PROTO_VERSION,
            },
            WorkerMessage::Installed,
            WorkerMessage::Refused {
                reason: "wrong domains".to_owned(),
            },
            WorkerMessage::RenewNow,
        ] {
            worker.send(&message)?;
            assert_eq!(acme.recv::<WorkerMessage>()?, message);
        }
        Ok(())
    }

    /// A real chain plus key is a few KiB; a chain of 32 KiB certificates
    /// with a 16 KiB key is far past anything a CA issues and still fits.
    #[test]
    fn a_long_chain_and_key_fit_one_frame_and_an_oversize_one_is_refused() -> R {
        let (mut acme, mut worker) = Channel::pair()?;
        let chain_pem = "c".repeat(8 * 32 * 1024);
        let key_pem = KeyPem::new("k".repeat(16 * 1024));
        let large = AcmeMessage::Install { chain_pem, key_pem };
        let expected = large.clone();
        // Larger than the socket buffer: read concurrently.
        let reader = std::thread::spawn(move || worker.recv::<AcmeMessage>().ok());
        acme.send(&large)?;
        assert_eq!(reader.join().ok().flatten(), Some(expected));

        let oversize = AcmeMessage::Install {
            chain_pem: "c".repeat(MAX_FRAME),
            key_pem: KeyPem::new(String::new()),
        };
        assert!(matches!(
            acme.send(&oversize),
            Err(ChannelError::Oversize { .. })
        ));
        Ok(())
    }

    /// Runs [`AcmeServer::serve`](super::AcmeServer::serve) on a thread
    /// with an installer that accepts a chain equal to [`CHAIN`] and refuses
    /// anything else.
    fn with_worker(
        test: impl FnOnce(&mut AcmeClient) -> R,
    ) -> Result<Result<(), AcmeChannelError>, Box<dyn std::error::Error>> {
        let (acme_end, worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || {
            serve_without_renewer(worker_end, |chain, key| {
                if chain == CHAIN && key.expose() == KEY {
                    Ok(())
                } else {
                    Err("chain does not cover the configured domains".to_owned())
                }
            })
        });
        let mut client = AcmeClient::new(acme_end);
        let result = test(&mut client);
        drop(client);
        let served = worker.join().map_err(|_| "worker thread panicked")?;
        result?;
        Ok(served)
    }

    #[test]
    fn the_worker_installs_after_hello_and_reports_a_refusal() -> R {
        let served = with_worker(|client| {
            client.hello()?;
            client.install(CHAIN.to_owned(), KeyPem::new(KEY.to_owned()))?;
            let refused = client.install("other".to_owned(), KeyPem::new(KEY.to_owned()));
            assert!(
                matches!(refused, Err(AcmeChannelError::Refused(ref reason)) if reason.contains("domains")),
                "{refused:?}"
            );
            Ok(())
        })?;
        // The acme end closed cleanly: the worker stops without an error.
        assert!(served.is_ok(), "{served:?}");
        Ok(())
    }

    #[test]
    fn install_before_hello_is_refused_and_ends_the_session() -> R {
        let served = with_worker(|client| {
            let refused = client.install(CHAIN.to_owned(), KeyPem::new(KEY.to_owned()));
            assert!(
                matches!(refused, Err(AcmeChannelError::Refused(_))),
                "{refused:?}"
            );
            Ok(())
        })?;
        assert!(
            matches!(served, Err(AcmeChannelError::Protocol(_))),
            "{served:?}"
        );
        Ok(())
    }

    #[test]
    fn a_version_mismatch_is_refused_on_both_sides() -> R {
        // The worker refuses a Hello with another version and stops.
        let (mut acme, worker) = Channel::pair()?;
        let thread = std::thread::spawn(move || serve_without_renewer(worker, |_, _| Ok(())));
        acme.send(&AcmeMessage::Hello {
            version: ACME_PROTO_VERSION.wrapping_add(1),
        })?;
        assert!(matches!(
            acme.recv::<WorkerMessage>()?,
            WorkerMessage::Refused { .. }
        ));
        let served = thread.join().map_err(|_| "worker thread panicked")?;
        assert!(
            matches!(served, Err(AcmeChannelError::Protocol(_))),
            "{served:?}"
        );

        // The acme side refuses a worker that answers with another version.
        let (acme, mut worker) = Channel::pair()?;
        let peer = std::thread::spawn(move || -> Result<(), ChannelError> {
            let _hello = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::Hello {
                version: ACME_PROTO_VERSION.wrapping_add(1),
            })
        });
        let mut client = AcmeClient::new(acme);
        let answer = client.hello();
        assert!(
            matches!(answer, Err(AcmeChannelError::Version { theirs, .. }) if theirs == ACME_PROTO_VERSION.wrapping_add(1)),
            "{answer:?}"
        );
        peer.join().map_err(|_| "peer thread panicked")??;
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_kind_is_a_protocol_error() -> R {
        let (acme, mut worker) = Channel::pair()?;
        let peer = std::thread::spawn(move || -> Result<(), ChannelError> {
            let _hello = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::Installed)?;
            let _install = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::Hello {
                version: ACME_PROTO_VERSION,
            })
        });
        let mut client = AcmeClient::new(acme);
        assert!(matches!(client.hello(), Err(AcmeChannelError::Protocol(_))));
        assert!(matches!(
            client.install(CHAIN.to_owned(), KeyPem::new(KEY.to_owned())),
            Err(AcmeChannelError::Protocol(_))
        ));
        peer.join().map_err(|_| "peer thread panicked")??;
        Ok(())
    }

    #[test]
    fn the_worker_stops_on_a_frame_it_cannot_decode_and_waits_through_idle_time() -> R {
        let (mut acme, worker) = Channel::pair_with(
            std::time::Duration::from_millis(20),
            std::time::Duration::from_secs(5),
        )?;
        let thread = std::thread::spawn(move || serve_without_renewer(worker, |_, _| Ok(())));
        // Longer than the worker's read timeout: an idle channel is not an end.
        std::thread::sleep(std::time::Duration::from_millis(60));
        // A `String` is not an `AcmeMessage`.
        acme.send(&"not a message".to_owned())?;
        let served = thread.join().map_err(|_| "worker thread panicked")?;
        assert!(
            matches!(
                served,
                Err(AcmeChannelError::Channel(ChannelError::Decode(_)))
            ),
            "{served:?}"
        );
        Ok(())
    }

    /// Version 2 added `RenewNow`; both `Hello`s carry it.
    #[test]
    fn both_hellos_carry_version_2() -> R {
        assert_eq!(ACME_PROTO_VERSION, 2);
        let (acme, mut worker) = Channel::pair()?;
        let peer = std::thread::spawn(move || -> Result<AcmeMessage, ChannelError> {
            let hello = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::Hello { version: 2 })?;
            Ok(hello)
        });
        let mut client = AcmeClient::new(acme);
        client.hello()?;
        let sent = peer.join().map_err(|_| "peer thread panicked")??;
        assert_eq!(sent, AcmeMessage::Hello { version: 2 });

        let (mut acme, worker) = Channel::pair()?;
        let thread = std::thread::spawn(move || serve_without_renewer(worker, |_, _| Ok(())));
        acme.send(&AcmeMessage::Hello { version: 2 })?;
        assert_eq!(
            acme.recv::<WorkerMessage>()?,
            WorkerMessage::Hello { version: 2 }
        );
        drop(acme);
        let served = thread.join().map_err(|_| "worker thread panicked")?;
        assert!(served.is_ok(), "{served:?}");
        Ok(())
    }

    #[test]
    fn next_request_returns_renew_now_refuses_an_answer_and_reports_eof() -> R {
        let (acme, mut worker) = Channel::pair()?;
        let mut client = AcmeClient::new(acme);
        worker.send(&WorkerMessage::RenewNow)?;
        assert_eq!(client.next_request()?, WorkerMessage::RenewNow);
        // A message sent out of turn is not a request.
        worker.send(&WorkerMessage::Installed)?;
        let answer = client.next_request();
        assert!(
            matches!(answer, Err(AcmeChannelError::Protocol(_))),
            "{answer:?}"
        );
        drop(worker);
        let closed = client.next_request();
        assert!(
            matches!(closed, Err(AcmeChannelError::Channel(ChannelError::Closed))),
            "{closed:?}"
        );
        Ok(())
    }

    /// A `RenewNow` that arrives while the client waits for an answer is
    /// recorded, and the exchange goes on.
    #[test]
    fn a_renew_now_before_an_answer_is_recorded_and_the_exchange_goes_on() -> R {
        let (acme, mut worker) = Channel::pair()?;
        let peer = std::thread::spawn(move || -> Result<(), ChannelError> {
            let _hello = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::RenewNow)?;
            worker.send(&WorkerMessage::Hello {
                version: ACME_PROTO_VERSION,
            })?;
            let _install = worker.recv::<AcmeMessage>()?;
            worker.send(&WorkerMessage::RenewNow)?;
            worker.send(&WorkerMessage::RenewNow)?;
            worker.send(&WorkerMessage::Installed)
        });
        let mut client = AcmeClient::new(acme);
        assert!(!client.take_pending_renew());
        client.hello()?;
        assert!(client.take_pending_renew());
        assert!(!client.take_pending_renew());
        client.install(CHAIN.to_owned(), KeyPem::new(KEY.to_owned()))?;
        assert!(client.take_pending_renew());
        assert!(!client.take_pending_renew());
        peer.join().map_err(|_| "peer thread panicked")??;
        Ok(())
    }

    /// A `RenewNow` sent before the acme process greets the worker is
    /// recorded by the client, and the greeting goes on.
    #[test]
    fn a_renew_now_before_hello_is_recorded_by_the_client() -> R {
        let (acme, worker) = Channel::pair()?;
        let (worker_side, renewer) = acme_link(worker)?;
        renewer.renew_now()?;
        let thread = std::thread::spawn(move || worker_side.serve(|_, _| Ok(())));
        let mut client = AcmeClient::new(acme);
        client.hello()?;
        assert!(client.take_pending_renew());
        drop(client);
        let served = thread.join().map_err(|_| "worker thread panicked")?;
        assert!(served.is_ok(), "{served:?}");
        Ok(())
    }

    /// Reads from `acme` until `answer`, and counts the `RenewNow`s read
    /// before it.
    fn read_until(acme: &mut Channel, answer: &WorkerMessage) -> Result<usize, ChannelError> {
        let mut renews = 0_usize;
        loop {
            let message = acme.recv::<WorkerMessage>()?;
            if message == *answer {
                return Ok(renews);
            }
            assert_eq!(message, WorkerMessage::RenewNow);
            renews = renews.saturating_add(1);
        }
    }

    /// `renew_now` on another thread while the server answers `Install`s:
    /// every frame on the channel stays whole, and every request arrives.
    #[test]
    fn renew_now_from_another_thread_does_not_tear_the_answers() -> R {
        const ROUNDS: usize = 300;
        let (mut acme, worker) = Channel::pair()?;
        let (worker_side, renewer) = acme_link(worker)?;
        let serving = std::thread::spawn(move || worker_side.serve(|_, _| Ok(())));
        let asking = renewer.clone();
        let renewing = std::thread::spawn(move || -> Result<(), AcmeChannelError> {
            for _ in 0..ROUNDS {
                asking.renew_now()?;
            }
            Ok(())
        });
        acme.send(&AcmeMessage::Hello {
            version: ACME_PROTO_VERSION,
        })?;
        let mut renews = read_until(
            &mut acme,
            &WorkerMessage::Hello {
                version: ACME_PROTO_VERSION,
            },
        )?;
        for _ in 0..ROUNDS {
            acme.send(&AcmeMessage::Install {
                chain_pem: CHAIN.to_owned(),
                key_pem: KeyPem::new(KEY.to_owned()),
            })?;
            renews = renews.saturating_add(read_until(&mut acme, &WorkerMessage::Installed)?);
        }
        renewing.join().map_err(|_| "renewer thread panicked")??;
        // Every `RenewNow` is written now, so all of them come before the
        // answer to one more `Install`.
        acme.send(&AcmeMessage::Install {
            chain_pem: CHAIN.to_owned(),
            key_pem: KeyPem::new(KEY.to_owned()),
        })?;
        renews = renews.saturating_add(read_until(&mut acme, &WorkerMessage::Installed)?);
        assert_eq!(renews, ROUNDS);
        drop(acme);
        let served = serving.join().map_err(|_| "worker thread panicked")?;
        assert!(served.is_ok(), "{served:?}");
        drop(renewer);
        Ok(())
    }

    /// When the server stops, the acme process sees the channel close even
    /// while a renewer is still alive, and the renewer then fails.
    #[test]
    fn the_channel_closes_when_the_server_stops_while_a_renewer_lives() -> R {
        let (mut acme, worker) = Channel::pair()?;
        let (worker_side, renewer) = acme_link(worker)?;
        let thread = std::thread::spawn(move || worker_side.serve(|_, _| Ok(())));
        acme.send(&AcmeMessage::Hello {
            version: ACME_PROTO_VERSION.wrapping_add(1),
        })?;
        assert!(matches!(
            acme.recv::<WorkerMessage>()?,
            WorkerMessage::Refused { .. }
        ));
        let served = thread.join().map_err(|_| "worker thread panicked")?;
        assert!(
            matches!(served, Err(AcmeChannelError::Protocol(_))),
            "{served:?}"
        );
        assert!(matches!(
            acme.recv::<WorkerMessage>(),
            Err(ChannelError::Closed)
        ));
        let late = renewer.renew_now();
        assert!(
            matches!(late, Err(AcmeChannelError::Channel(ChannelError::Closed))),
            "{late:?}"
        );
        Ok(())
    }

    #[test]
    fn errors_carry_their_detail_in_display() {
        assert!(
            AcmeChannelError::Refused("wrong domains".to_owned())
                .to_string()
                .contains("wrong domains")
        );
        assert!(
            AcmeChannelError::Version { ours: 1, theirs: 9 }
                .to_string()
                .contains('9')
        );
        assert!(
            AcmeChannelError::Protocol("hello first")
                .to_string()
                .contains("hello first")
        );
        assert!(
            !AcmeChannelError::Channel(ChannelError::Closed)
                .to_string()
                .is_empty()
        );
    }
}
