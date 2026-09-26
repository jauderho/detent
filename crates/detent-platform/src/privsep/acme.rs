//! The channel between the acme process and the worker (ADR-015).
//!
//! ```text
//!   serve ──fork──▶ acme (uid `detent`, confined, outbound only)
//!     │                │ AcmeMessage { Hello | Install { chain, key } }
//!     └──fork──▶ worker◀┘ WorkerMessage { Hello | Installed | Refused }
//! ```
//!
//! [`spawn_acme`](super::spawn::spawn_acme) creates the socket pair. The
//! acme process speaks first: [`AcmeMessage::Hello`], then one
//! [`AcmeMessage::Install`] for each issued certificate. The worker checks the
//! pair, stores it and answers [`WorkerMessage::Installed`] or
//! [`WorkerMessage::Refused`]. The acme process never writes the served
//! certificate itself.
//!
//! # Versions
//!
//! Both sides ship in the same binary, so there is no negotiation: the
//! versions in the two `Hello`s must be equal, or the worker refuses and
//! stops. The enums are `#[non_exhaustive]` for Rust callers, so a later
//! slice can add `RenewNow` and `Status`; on the wire they stay closed, as in
//! [`proto`](super::proto): `postcard` does not decode an unknown
//! discriminant, and the receiver stops.
//!
//! # The key
//!
//! [`KeyPem`] is a `String` whose `Debug` prints `[redacted]`, so a logged
//! message never shows the private key. The memory is not wiped: the frame
//! buffers in [`transport`](super::transport) hold the same bytes and are not
//! wiped either, and this crate links no `zeroize`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::transport::{Channel, ChannelError};

/// Version of this protocol. Both sides must send the same value in
/// `Hello`.
pub const ACME_PROTO_VERSION: u16 = 1;

/// Read and write timeout on both ends of the acme channel.
///
/// The acme process waits this long for the worker's answer to an
/// `Install`: parsing a chain and writing two small files take well under a
/// second, so 60 s is ample, and a worker that does not answer in that time
/// is reported within the same renewal attempt instead of blocking the
/// loop. The worker treats a read timeout as idle time and keeps waiting
/// ([`serve_acme`]), so the timeout does not limit the hour between checks.
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
}

impl AcmeClient {
    /// A client on `channel`.
    #[must_use]
    pub const fn new(channel: Channel) -> Self {
        Self { channel }
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
    fn call(&mut self, message: &AcmeMessage) -> Result<WorkerMessage, AcmeChannelError> {
        self.channel.send(message)?;
        match self.channel.recv::<WorkerMessage>()? {
            WorkerMessage::Refused { reason } => Err(AcmeChannelError::Refused(reason)),
            answer => Ok(answer),
        }
    }
}

/// The worker's side: answer the acme process on `channel` until it closes.
///
/// `install` receives each chain and key after a matching `Hello`, and
/// returns `Err(reason)` to refuse the pair. A read timeout is idle time, not
/// an end: the acme process is quiet for an hour between checks.
///
/// # Errors
///
/// `Ok(())` when the acme process closed the channel. Otherwise
/// [`AcmeChannelError::Protocol`] after the worker refused a `Hello` with
/// another version or an `Install` before `Hello`, and
/// [`AcmeChannelError::Channel`] when the channel fails or a frame does not
/// decode. The worker then keeps serving its last certificate (ADR-015).
pub fn serve_acme(
    channel: &mut Channel,
    mut install: impl FnMut(&str, &KeyPem) -> Result<(), String>,
) -> Result<(), AcmeChannelError> {
    let mut greeted = false;
    loop {
        let message = match channel.recv::<AcmeMessage>() {
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
        channel.send(&answer)?;
        if let Some(violation) = stop {
            return Err(AcmeChannelError::Protocol(violation));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACME_PROTO_VERSION, AcmeChannelError, AcmeClient, AcmeMessage, KeyPem, WorkerMessage,
        serve_acme,
    };
    use crate::privsep::proto::MAX_FRAME;
    use crate::privsep::transport::{Channel, ChannelError};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Stand-in PEM text: low entropy on purpose (CI runs gitleaks).
    const CHAIN: &str = "chain line one\nchain line two\n";
    const KEY: &str = "not a real pem";

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

    /// Runs `serve_acme` on a thread with an installer that accepts a chain
    /// equal to [`CHAIN`] and refuses anything else.
    fn with_worker(
        test: impl FnOnce(&mut AcmeClient) -> R,
    ) -> Result<Result<(), AcmeChannelError>, Box<dyn std::error::Error>> {
        let (acme_end, mut worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || {
            serve_acme(&mut worker_end, |chain, key| {
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
        let (mut acme, mut worker) = Channel::pair()?;
        let thread = std::thread::spawn(move || serve_acme(&mut worker, |_, _| Ok(())));
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
        let mut worker = worker;
        let thread = std::thread::spawn(move || serve_acme(&mut worker, |_, _| Ok(())));
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
