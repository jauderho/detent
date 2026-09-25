//! Framing for the privsep socket.
//!
//! # Why `SOCK_STREAM` and not `SOCK_SEQPACKET`
//!
//! PLAN §2.4 and ADR-001 describe the channel as
//! `socketpair(AF_UNIX, SOCK_SEQPACKET)`, whose datagram boundaries would make
//! explicit framing unnecessary. macOS does not implement `SOCK_SEQPACKET`
//! (`socketpair` returns `EPROTONOSUPPORT`), and macOS is a tier-1 host/dev
//! platform in PLAN §1.6, so the protocol would then be untestable on the
//! machine it is developed on.
//!
//! This module therefore uses `SOCK_STREAM` — exactly what
//! [`UnixStream::pair`] gives on both platforms — plus a 4-byte big-endian
//! length prefix. That restores message boundaries portably, and it makes the
//! 1 MiB cap explicit in the header rather than implicit in a kernel buffer
//! size: [`Channel::recv`] rejects an over-large length **before** allocating
//! anything for the body.
//!
//! # Timeouts
//!
//! Both directions carry a timeout (30 s by default). A header that never
//! arrives is a normal idle condition and is reported as
//! [`ChannelError::Timeout`] — [`Channel::poll_recv`] turns it into `Ok(None)`
//! so the monitor can check its commit-confirm deadline between messages. A
//! timeout or EOF *in the middle* of a frame is not recoverable: the stream is
//! desynchronized, and the caller must close it.

use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::proto::{CodecError, MAX_FRAME, decode, encode};

/// Bytes of length prefix in front of every frame.
const HEADER_LEN: usize = 4;

/// Default read and write timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything that can go wrong on the channel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelError {
    /// The peer closed the socket cleanly, or died mid-frame.
    #[error("privsep channel closed by peer")]
    Closed,
    /// A length header advertised more than [`MAX_FRAME`] bytes, or the
    /// message to send exceeds it. Nothing was allocated for the body.
    #[error("frame of {len} bytes exceeds the {MAX_FRAME} byte limit")]
    Oversize {
        /// The advertised or attempted length.
        len: usize,
    },
    /// A complete frame arrived but is not a valid message.
    #[error("cannot decode privsep frame: {0}")]
    Decode(#[from] CodecError),
    /// The configured timeout elapsed.
    #[error("privsep channel timed out")]
    Timeout,
    /// Any other syscall failure.
    #[error("privsep channel i/o error")]
    Io(#[source] std::io::Error),
}

impl ChannelError {
    /// True for the two conditions that mean "the peer is speaking nonsense":
    /// the monitor answers these by closing the connection and exiting, so
    /// that its supervisor restarts the pair (PLAN §2.4).
    #[must_use]
    pub const fn is_protocol_violation(&self) -> bool {
        matches!(self, Self::Oversize { .. } | Self::Decode(_))
    }
}

/// A length-prefixed message channel over one end of a Unix socket pair.
#[derive(Debug)]
pub struct Channel {
    stream: UnixStream,
    read_timeout: Duration,
}

impl Channel {
    /// Wrap a connected socket with [`DEFAULT_TIMEOUT`] in both directions.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when the timeouts cannot be applied to the socket.
    pub fn new(stream: UnixStream) -> Result<Self, ChannelError> {
        Self::with_timeouts(stream, DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
    }

    /// Wrap a connected socket with explicit timeouts.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when the timeouts cannot be applied to the socket.
    pub fn with_timeouts(
        stream: UnixStream,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, ChannelError> {
        stream
            .set_write_timeout(Some(write_timeout))
            .map_err(ChannelError::Io)?;
        let channel = Self {
            stream,
            read_timeout,
        };
        channel.apply_read_timeout(read_timeout)?;
        Ok(channel)
    }

    /// A connected pair of channels, for tests and for
    /// [`spawn_pair`](super::spawn::spawn_pair).
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when `socketpair(2)` fails or the timeouts cannot
    /// be applied.
    pub fn pair() -> Result<(Self, Self), ChannelError> {
        Self::pair_with(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
    }

    /// As [`Channel::pair`], with explicit timeouts on both ends.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when `socketpair(2)` fails or the timeouts cannot
    /// be applied.
    pub fn pair_with(
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(Self, Self), ChannelError> {
        let (left, right) = UnixStream::pair().map_err(ChannelError::Io)?;
        Ok((
            Self::with_timeouts(left, read_timeout, write_timeout)?,
            Self::with_timeouts(right, read_timeout, write_timeout)?,
        ))
    }

    /// The read timeout currently configured.
    #[must_use]
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Borrow the underlying socket, e.g. to read its peer credentials.
    #[must_use]
    pub const fn socket(&self) -> &UnixStream {
        &self.stream
    }

    /// Replace the read timeout used for subsequent receives.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when the socket option cannot be set.
    pub fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), ChannelError> {
        self.apply_read_timeout(timeout)?;
        self.read_timeout = timeout;
        Ok(())
    }

    fn apply_read_timeout(&self, timeout: Duration) -> Result<(), ChannelError> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(ChannelError::Io)
    }

    /// Encode and send one message.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Oversize`] when the encoding exceeds [`MAX_FRAME`],
    /// [`ChannelError::Closed`] when the peer is gone, [`ChannelError::Timeout`]
    /// when the write timeout elapses, and [`ChannelError::Io`] otherwise.
    pub fn send<T: Serialize>(&mut self, message: &T) -> Result<(), ChannelError> {
        let body = match encode(message) {
            Ok(body) => body,
            Err(CodecError::Oversize { len }) => return Err(ChannelError::Oversize { len }),
            Err(other) => return Err(ChannelError::Decode(other)),
        };
        // `body.len() <= MAX_FRAME`, which is far below `u32::MAX`, so the
        // conversion cannot truncate.
        let len =
            u32::try_from(body.len()).map_err(|_| ChannelError::Oversize { len: body.len() })?;
        let mut frame = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream.write_all(&frame).map_err(map_write_error)?;
        self.stream.flush().map_err(map_write_error)
    }

    /// Receive one message, waiting up to the configured read timeout for it.
    ///
    /// # Errors
    ///
    /// As [`Channel::poll_recv`], plus [`ChannelError::Timeout`] when no frame
    /// starts within the timeout.
    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T, ChannelError> {
        self.poll_recv()?.ok_or(ChannelError::Timeout)
    }

    /// Receive one message, or `Ok(None)` if the read timeout elapsed before
    /// any byte of a frame arrived.
    ///
    /// A timeout *after* the first byte is fatal, because the stream is then
    /// desynchronized; it is reported as [`ChannelError::Timeout`] and the
    /// caller must not reuse the channel.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Closed`] on EOF, [`ChannelError::Oversize`] for a
    /// length header above [`MAX_FRAME`] (checked before allocating the body),
    /// [`ChannelError::Decode`] for a frame that is not a valid message, and
    /// [`ChannelError::Io`] for any other syscall failure.
    pub fn poll_recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, ChannelError> {
        let mut header = [0_u8; HEADER_LEN];
        match self.read_exact_or_idle(&mut header)? {
            Filled::Idle => return Ok(None),
            Filled::Full => {}
        }
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME {
            return Err(ChannelError::Oversize { len });
        }
        let mut body = vec![0_u8; len];
        match self.read_exact_or_idle(&mut body)? {
            // Zero bytes read at the start of the *body* still counts as
            // mid-frame: the header is already consumed.
            Filled::Idle => return Err(ChannelError::Timeout),
            Filled::Full => {}
        }
        Ok(Some(decode(&body)?))
    }

    /// Fill `buf` completely, or report that nothing at all arrived in time.
    fn read_exact_or_idle(&mut self, buf: &mut [u8]) -> Result<Filled, ChannelError> {
        let mut filled = 0_usize;
        while filled < buf.len() {
            let Some(slot) = buf.get_mut(filled..) else {
                return Err(ChannelError::Closed);
            };
            match self.stream.read(slot) {
                // EOF, whether at a frame boundary or halfway through one.
                Ok(0) => return Err(ChannelError::Closed),
                Ok(read) => filled = filled.saturating_add(read),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) if is_timeout(&err) => {
                    return if filled == 0 {
                        Ok(Filled::Idle)
                    } else {
                        Err(ChannelError::Timeout)
                    };
                }
                Err(err) => return Err(ChannelError::Io(err)),
            }
        }
        Ok(Filled::Full)
    }

    /// Close the write half so the peer observes EOF.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Io`] when `shutdown(2)` fails.
    pub fn shutdown_write(&self) -> Result<(), ChannelError> {
        self.stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(ChannelError::Io)
    }
}

/// Outcome of a best-effort fill of a buffer.
enum Filled {
    /// The buffer is full.
    Full,
    /// The timeout elapsed and not a single byte had been read.
    Idle,
}

/// `SO_RCVTIMEO`/`SO_SNDTIMEO` surface as `WouldBlock` on Linux and
/// `TimedOut` on macOS, so both are treated as a timeout.
fn is_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn map_write_error(err: std::io::Error) -> ChannelError {
    match err.kind() {
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => {
            ChannelError::Closed
        }
        ErrorKind::WouldBlock | ErrorKind::TimedOut => ChannelError::Timeout,
        _ => ChannelError::Io(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, ChannelError, DEFAULT_TIMEOUT, HEADER_LEN, is_timeout, map_write_error};
    use crate::privsep::proto::{MAX_FRAME, PROTO_VERSION, Request, Response, TargetId};
    use serde::Serialize;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn messages_round_trip_over_a_socket_pair() -> Result<(), Box<dyn std::error::Error>> {
        let (mut a, mut b) = Channel::pair()?;
        assert_eq!(a.read_timeout(), DEFAULT_TIMEOUT);
        assert!(a.socket().peer_addr().is_ok());
        assert!(
            a.send(&Request::Hello {
                proto: PROTO_VERSION
            })
            .is_ok()
        );
        assert_eq!(
            b.recv::<Request>().ok(),
            Some(Request::Hello {
                proto: PROTO_VERSION
            })
        );
        assert!(b.send(&Response::ShuttingDown).is_ok());
        assert_eq!(a.recv::<Response>().ok(), Some(Response::ShuttingDown));
        Ok(())
    }

    #[test]
    fn a_large_but_legal_frame_survives() -> Result<(), Box<dyn std::error::Error>> {
        let (mut a, mut b) = Channel::pair()?;
        let bytes = vec![0x41_u8; 512 * 1024];
        let request = Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: bytes.clone(),
            journal: false,
        };
        // A 512 KiB frame exceeds the socket buffer, so the write must be
        // drained concurrently or `write_all` blocks forever.
        let reader = std::thread::spawn(move || b.recv::<Request>().ok());
        assert!(a.send(&request).is_ok());
        assert_eq!(reader.join().ok().flatten(), Some(request));
        Ok(())
    }

    #[test]
    fn an_oversize_length_header_is_rejected_before_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        let header = u32::try_from(MAX_FRAME + 1).unwrap_or(u32::MAX);
        assert!(left.write_all(&header.to_be_bytes()).is_ok());
        let mut channel = Channel::new(right)?;
        let err = channel.poll_recv::<Request>().err();
        assert!(matches!(
            err,
            Some(ChannelError::Oversize { len }) if len == MAX_FRAME + 1
        ));
        assert!(ChannelError::Oversize { len: MAX_FRAME + 1 }.is_protocol_violation());
        Ok(())
    }

    #[test]
    fn a_frame_that_is_not_a_message_is_a_protocol_violation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        // Length 4, body = an out-of-range discriminant.
        assert!(left.write_all(&4_u32.to_be_bytes()).is_ok());
        assert!(left.write_all(&[250, 0, 0, 0]).is_ok());
        let mut channel = Channel::new(right)?;
        let err = channel.poll_recv::<Request>().err();
        assert!(matches!(err, Some(ChannelError::Decode(_))));
        assert!(err.is_some_and(|e| e.is_protocol_violation()));
        Ok(())
    }

    #[test]
    fn a_truncated_frame_reports_closure_not_a_bad_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        // `Channel::new` sets a write timeout on `right`, which fails with
        // `EINVAL` on macOS once its peer has already been dropped
        // (verified: `UnixStream::pair()`, `drop(left)`, then
        // `right.set_write_timeout(...)` -> `Err(InvalidInput)`). The channel
        // must therefore be constructed while `left` is still alive; only the
        // write that follows should happen after the drop.
        let mut channel = Channel::new(right)?;
        assert!(left.write_all(&16_u32.to_be_bytes()).is_ok());
        assert!(left.write_all(&[0, 1, 2]).is_ok());
        drop(left);
        assert!(matches!(
            channel.poll_recv::<Request>().err(),
            Some(ChannelError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn a_truncated_header_reports_closure() -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        // See the comment in `a_truncated_frame_reports_closure_not_a_bad_message`:
        // the channel must wrap `right` before `left` is dropped.
        let mut channel = Channel::new(right)?;
        assert!(left.write_all(&[0, 0]).is_ok());
        drop(left);
        assert!(matches!(
            channel.poll_recv::<Request>().err(),
            Some(ChannelError::Closed)
        ));
        assert_eq!(HEADER_LEN, 4);
        Ok(())
    }

    #[test]
    fn an_idle_channel_polls_to_none_and_recv_times_out() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_keep, right) = UnixStream::pair()?;
        let mut channel =
            Channel::with_timeouts(right, Duration::from_millis(30), Duration::from_millis(30))?;
        assert!(matches!(channel.poll_recv::<Request>(), Ok(None)));
        assert!(matches!(
            channel.recv::<Request>().err(),
            Some(ChannelError::Timeout)
        ));
        assert!(channel.set_read_timeout(Duration::from_millis(5)).is_ok());
        assert_eq!(channel.read_timeout(), Duration::from_millis(5));
        assert!(matches!(channel.poll_recv::<Request>(), Ok(None)));
        Ok(())
    }

    #[test]
    fn a_body_that_stops_arriving_is_a_fatal_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        assert!(left.write_all(&8_u32.to_be_bytes()).is_ok());
        let mut channel =
            Channel::with_timeouts(right, Duration::from_millis(30), Duration::from_millis(30))?;
        assert!(matches!(
            channel.poll_recv::<Request>().err(),
            Some(ChannelError::Timeout)
        ));
        drop(left);
        Ok(())
    }

    #[test]
    fn sending_an_oversize_message_fails_without_touching_the_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut a, mut b) = Channel::pair()?;
        let err = a.send(&Request::WriteTarget {
            target: TargetId(0),
            expected_prev: None,
            bytes: vec![0_u8; MAX_FRAME + 1],
            journal: false,
        });
        assert!(matches!(err, Err(ChannelError::Oversize { .. })));
        // Nothing was written, so the peer is still idle rather than
        // desynchronized.
        assert!(b.set_read_timeout(Duration::from_millis(20)).is_ok());
        assert!(matches!(b.poll_recv::<Request>(), Ok(None)));
        Ok(())
    }

    #[test]
    fn writing_to_a_closed_peer_reports_closure() -> Result<(), Box<dyn std::error::Error>> {
        let (mut a, b) = Channel::pair()?;
        assert!(b.shutdown_write().is_ok());
        drop(b);
        // The first write may land in the socket buffer; the second cannot.
        let _first = a.send(&Request::Shutdown);
        let outcome = a.send(&Request::Shutdown);
        assert!(matches!(
            outcome,
            Err(ChannelError::Closed | ChannelError::Io(_))
        ));
        Ok(())
    }

    #[test]
    fn reading_from_a_closed_peer_reports_closure() -> Result<(), Box<dyn std::error::Error>> {
        let (a, mut b) = Channel::pair()?;
        drop(a);
        assert!(matches!(
            b.recv::<Request>().err(),
            Some(ChannelError::Closed)
        ));
        Ok(())
    }

    /// A `Serialize` impl that always fails, so `Channel::send`'s
    /// non-oversize encode error arm (`CodecError::Malformed` from
    /// `postcard`, not from the size check) is reachable.
    struct Unserializable;

    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("Unserializable always fails"))
        }
    }

    #[test]
    fn sending_a_value_that_fails_to_encode_reports_decode_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut a, _b) = Channel::pair()?;
        assert!(matches!(
            a.send(&Unserializable),
            Err(ChannelError::Decode(_))
        ));
        Ok(())
    }

    #[test]
    fn a_body_that_arrives_partially_then_stalls_is_a_fatal_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut left, right) = UnixStream::pair()?;
        let mut channel =
            Channel::with_timeouts(right, Duration::from_millis(30), Duration::from_millis(30))?;
        // Advertise an 8-byte body but only ever send 3: the header fills
        // (`Filled::Full`), then the body read times out with `filled != 0`,
        // which is the fatal (not idle) timeout branch.
        assert!(left.write_all(&8_u32.to_be_bytes()).is_ok());
        assert!(left.write_all(&[1, 2, 3]).is_ok());
        assert!(matches!(
            channel.poll_recv::<Request>().err(),
            Some(ChannelError::Timeout)
        ));
        drop(left);
        Ok(())
    }

    #[test]
    fn error_classification_is_explicit() {
        assert!(!ChannelError::Closed.is_protocol_violation());
        assert!(!ChannelError::Timeout.is_protocol_violation());
        assert!(!ChannelError::Io(std::io::Error::other("x")).is_protocol_violation());
        assert!(is_timeout(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(is_timeout(&std::io::Error::from(
            std::io::ErrorKind::TimedOut
        )));
        assert!(!is_timeout(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            ChannelError::Closed
        ));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            ChannelError::Closed
        ));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            ChannelError::Closed
        ));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            ChannelError::Timeout
        ));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            ChannelError::Timeout
        ));
        assert!(matches!(
            map_write_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            ChannelError::Io(_)
        ));
        assert!(!ChannelError::Closed.to_string().is_empty());
        assert!(!ChannelError::Timeout.to_string().is_empty());
    }
}
