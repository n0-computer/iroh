//! This module implements the send/recv relaying protocol.
//!
//! Protocol flow:
//!  * server occasionally sends [`FrameType::Ping`]
//!  * client responds to any [`FrameType::Ping`] with a [`FrameType::Pong`]
//!  * clients sends [`FrameType::ClientToRelayDatagram`] or [`FrameType::ClientToRelayDatagramBatch`]
//!  * server then sends [`FrameType::RelayToClientDatagram`] or [`FrameType::RelayToClientDatagramBatch`] to recipient
//!  * server sends [`FrameType::EndpointGone`] when the other client disconnects

use std::num::NonZeroU16;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use iroh_base::{EndpointId, KeyParsingError};
use n0_error::{e, ensure, stack_error};
use n0_future::time::Duration;

use super::common::{FrameType, FrameTypeError};
use crate::KeyCache;

/// The maximum size of a packet sent over relay.
/// (This only includes the data bytes visible to the socket, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

/// The maximum frame size.
///
/// This is also the minimum burst size that a rate-limiter has to accept.
#[cfg(not(wasm_browser))]
pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
#[cfg(feature = "server")]
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(15);

/// The number of packets buffered for sending per client
#[cfg(feature = "server")]
pub(crate) const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512;

/// Protocol send errors.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Error {
    #[error("unexpected frame: got {got:?}, expected {expected:?}")]
    UnexpectedFrame { got: FrameType, expected: FrameType },
    #[error("Frame is too large, has {frame_len} bytes")]
    FrameTooLarge { frame_len: usize },
    #[error(transparent)]
    SerDe {
        #[error(std_err)]
        source: postcard::Error,
    },
    #[error(transparent)]
    FrameTypeError { source: FrameTypeError },
    #[error("Invalid public key")]
    InvalidPublicKey { source: KeyParsingError },
    #[error("Invalid frame encoding")]
    InvalidFrame {},
    #[error("Invalid frame type: {frame_type:?}")]
    InvalidFrameType { frame_type: FrameType },
    #[error("Invalid protocol message encoding")]
    InvalidProtocolMessageEncoding {
        #[error(std_err)]
        source: std::str::Utf8Error,
    },
    #[error("Too few bytes")]
    TooSmall {},
}

/// The messages that a relay sends to clients or the clients receive from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayToClientMsg {
    /// Represents datagrams sent from relays (originally sent to them by another client).
    Datagrams {
        /// The [`EndpointId`] of the original sender.
        remote_endpoint_id: EndpointId,
        /// The datagrams and related metadata.
        datagrams: Datagrams,
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the relay.
    EndpointGone(EndpointId),
    /// A one-way message from relay to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the relay doesn't broadcast a [`RelayToClientMsg::Health`]
        /// until a problem exists.
        problem: String,
    },
    /// A one-way message from relay to client, advertising that the relay is restarting.
    Restarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the relay to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A relay should not send a `try_for` duration more
        /// than a few seconds.
        try_for: Duration,
    },
    /// Request from the relay to reply to the
    /// other side with a [`ClientToRelayMsg::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`ClientToRelayMsg::Ping`] from a client
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
}

/// Messages that clients send to relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientToRelayMsg {
    /// Request from the client to the server to reply to the
    /// other side with a [`RelayToClientMsg::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`RelayToClientMsg::Ping`] from a server
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
    /// Request from the client to relay datagrams to given remote endpoint.
    Datagrams {
        /// The remote endpoint to relay to.
        dst_endpoint_id: EndpointId,
        /// The datagrams and related metadata to relay.
        datagrams: Datagrams,
    },
}

/// One or multiple datagrams being transferred via the relay.
///
/// This type is modeled after [`quinn_proto::Transmit`]
/// (or even more similarly `quinn_udp::Transmit`, but we don't depend on that library here).
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct Datagrams {
    /// Explicit congestion notification bits
    pub ecn: Option<quinn_proto::EcnCodepoint>,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<NonZeroU16>,
    /// The contents of the datagram(s)
    #[debug(skip)]
    pub contents: Bytes,
}

impl<T: AsRef<[u8]>> From<T> for Datagrams {
    fn from(bytes: T) -> Self {
        Self {
            ecn: None,
            segment_size: None,
            contents: Bytes::copy_from_slice(bytes.as_ref()),
        }
    }
}

impl Datagrams {
    /// Splits the current datagram into at maximum `num_segments` segments, returning
    /// the batch with at most `num_segments` and leaving only the rest in `self`.
    ///
    /// Calling this on a datagram batch that only contains a single datagram (`segment_size == None`)
    /// will result in returning essentially a clone of `self`, while making `self` empty afterwards.
    ///
    /// Calling this on a datagram batch with e.g. 15 datagrams with `num_segments == 10` will
    /// result in returning a datagram batch that contains the first 10 datagrams and leave `self`
    /// containing the remaining 5 datagrams.
    ///
    /// Calling this on a datagram batch with less than `num_segments` datagrams will result in
    /// making `self` empty and returning essentially a clone of `self`.
    pub fn take_segments(&mut self, num_segments: usize) -> Datagrams {
        let Some(segment_size) = self.segment_size else {
            let contents = std::mem::take(&mut self.contents);
            return Datagrams {
                ecn: self.ecn,
                segment_size: None,
                contents,
            };
        };

        let usize_segment_size = usize::from(u16::from(segment_size));
        let max_content_len = num_segments * usize_segment_size;
        let contents = self
            .contents
            .split_to(std::cmp::min(max_content_len, self.contents.len()));

        let is_datagram_batch = num_segments > 1 && usize_segment_size < contents.len();

        // If this left our batch with only one more datagram, then remove the segment size
        // to uphold the invariant that single-datagram batches don't have a segment size set.
        if self.contents.len() <= usize_segment_size {
            self.segment_size = None;
        }

        Datagrams {
            ecn: self.ecn,
            segment_size: is_datagram_batch.then_some(segment_size),
            contents,
        }
    }

    fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        let ecn = self.ecn.map_or(0, |ecn| ecn as u8);
        dst.put_u8(ecn);
        if let Some(segment_size) = self.segment_size {
            dst.put_u16(segment_size.into());
        }
        dst.put(self.contents.as_ref());
        dst
    }

    fn encoded_len(&self) -> usize {
        1 // ECN byte
        + self.segment_size.map_or(0, |_| 2) // segment size, when None, then a packed representation is assumed
        + self.contents.len()
    }

    #[allow(clippy::len_zero, clippy::result_large_err)]
    fn from_bytes(mut bytes: Bytes, is_batch: bool) -> Result<Self, Error> {
        if is_batch {
            // 1 bytes ECN, 2 bytes segment size
            ensure!(bytes.len() >= 3, Error::InvalidFrame);
        } else {
            ensure!(bytes.len() >= 1, Error::InvalidFrame);
        }

        let ecn_byte = bytes.get_u8();
        let ecn = quinn_proto::EcnCodepoint::from_bits(ecn_byte);

        let segment_size = if is_batch {
            let segment_size = bytes.get_u16(); // length checked above
            NonZeroU16::new(segment_size)
        } else {
            None
        };

        Ok(Self {
            ecn,
            segment_size,
            contents: bytes,
        })
    }
}

impl RelayToClientMsg {
    /// Returns this frame's corresponding frame type.
    pub fn typ(&self) -> FrameType {
        match self {
            Self::Datagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::RelayToClientDatagramBatch
                } else {
                    FrameType::RelayToClientDatagram
                }
            }
            Self::EndpointGone { .. } => FrameType::EndpointGone,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Health { .. } => FrameType::Health,
            Self::Restarting { .. } => FrameType::Restarting,
        }
    }

    #[cfg(feature = "server")]
    pub(crate) fn to_bytes(&self) -> BytesMut {
        self.write_to(BytesMut::with_capacity(self.encoded_len()))
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    #[cfg(feature = "server")]
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst = self.typ().write_to(dst);
        match self {
            Self::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                dst.put(remote_endpoint_id.as_ref());
                dst = datagrams.write_to(dst);
            }
            Self::EndpointGone(endpoint_id) => {
                dst.put(endpoint_id.as_ref());
            }
            Self::Ping(data) => {
                dst.put(&data[..]);
            }
            Self::Pong(data) => {
                dst.put(&data[..]);
            }
            Self::Health { problem } => {
                dst.put(problem.as_ref());
            }
            Self::Restarting {
                reconnect_in,
                try_for,
            } => {
                dst.put_u32(reconnect_in.as_millis() as u32);
                dst.put_u32(try_for.as_millis() as u32);
            }
        }
        dst
    }

    #[cfg(feature = "server")]
    pub(crate) fn encoded_len(&self) -> usize {
        let payload_len = match self {
            Self::Datagrams { datagrams, .. } => {
                32 // endpointid
                + datagrams.encoded_len()
            }
            Self::EndpointGone(_) => 32,
            Self::Ping(_) | Self::Pong(_) => 8,
            Self::Health { problem } => problem.len(),
            Self::Restarting { .. } => {
                4 // u32
                + 4 // u32
            }
        };
        self.typ().encoded_len() + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_bytes(mut content: Bytes, cache: &KeyCache) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        ensure!(
            frame_len <= MAX_PACKET_SIZE,
            Error::FrameTooLarge { frame_len }
        );

        let res = match frame_type {
            FrameType::RelayToClientDatagram | FrameType::RelayToClientDatagramBatch => {
                ensure!(content.len() >= EndpointId::LENGTH, Error::InvalidFrame);

                let remote_endpoint_id = cache.key_from_slice(&content[..EndpointId::LENGTH])?;
                let datagrams = Datagrams::from_bytes(
                    content.slice(EndpointId::LENGTH..),
                    frame_type == FrameType::RelayToClientDatagramBatch,
                )?;
                Self::Datagrams {
                    remote_endpoint_id,
                    datagrams,
                }
            }
            FrameType::EndpointGone => {
                ensure!(content.len() == EndpointId::LENGTH, Error::InvalidFrame);
                let endpoint_id = cache.key_from_slice(content.as_ref())?;
                Self::EndpointGone(endpoint_id)
            }
            FrameType::Ping => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            FrameType::Health => {
                let problem = std::str::from_utf8(&content)?.to_owned();
                Self::Health { problem }
            }
            FrameType::Restarting => {
                ensure!(content.len() == 4 + 4, Error::InvalidFrame);
                let reconnect_in = u32::from_be_bytes(
                    content[..4]
                        .try_into()
                        .map_err(|_| e!(Error::InvalidFrame))?,
                );
                let try_for = u32::from_be_bytes(
                    content[4..]
                        .try_into()
                        .map_err(|_| e!(Error::InvalidFrame))?,
                );
                let reconnect_in = Duration::from_millis(reconnect_in as u64);
                let try_for = Duration::from_millis(try_for as u64);
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            _ => {
                return Err(e!(Error::InvalidFrameType { frame_type }));
            }
        };
        Ok(res)
    }
}

impl ClientToRelayMsg {
    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Self::Datagrams { datagrams, .. } => {
                if datagrams.segment_size.is_some() {
                    FrameType::ClientToRelayDatagramBatch
                } else {
                    FrameType::ClientToRelayDatagram
                }
            }
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
        }
    }

    pub(crate) fn to_bytes(&self) -> BytesMut {
        self.write_to(BytesMut::with_capacity(self.encoded_len()))
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst = self.typ().write_to(dst);
        match self {
            Self::Datagrams {
                dst_endpoint_id,
                datagrams,
            } => {
                dst.put(dst_endpoint_id.as_ref());
                dst = datagrams.write_to(dst);
            }
            Self::Ping(data) => {
                dst.put(&data[..]);
            }
            Self::Pong(data) => {
                dst.put(&data[..]);
            }
        }
        dst
    }

    pub(crate) fn encoded_len(&self) -> usize {
        let payload_len = match self {
            Self::Ping(_) | Self::Pong(_) => 8,
            Self::Datagrams { datagrams, .. } => {
                32 // endpoint id
                + datagrams.encoded_len()
            }
        };
        self.typ().encoded_len() + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    #[cfg(feature = "server")]
    pub(crate) fn from_bytes(mut content: Bytes, cache: &KeyCache) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        ensure!(
            frame_len <= MAX_PACKET_SIZE,
            Error::FrameTooLarge { frame_len }
        );

        let res = match frame_type {
            FrameType::ClientToRelayDatagram | FrameType::ClientToRelayDatagramBatch => {
                let dst_endpoint_id = cache.key_from_slice(&content[..EndpointId::LENGTH])?;
                let datagrams = Datagrams::from_bytes(
                    content.slice(EndpointId::LENGTH..),
                    frame_type == FrameType::ClientToRelayDatagramBatch,
                )?;
                Self::Datagrams {
                    dst_endpoint_id,
                    datagrams,
                }
            }
            FrameType::Ping => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                ensure!(content.len() == 8, Error::InvalidFrame);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            _ => {
                return Err(e!(Error::InvalidFrameType { frame_type }));
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
#[cfg(feature = "server")]
mod tests {
    use data_encoding::HEXLOWER;
    use iroh_base::SecretKey;
    use n0_error::Result;

    use super::*;

    fn check_expected_bytes(frames: Vec<(Vec<u8>, &str)>) {
        for (bytes, expected_hex) in frames {
            let stripped: Vec<u8> = expected_hex
                .chars()
                .filter_map(|s| {
                    if s.is_ascii_whitespace() {
                        None
                    } else {
                        Some(s as u8)
                    }
                })
                .collect();
            let expected_bytes = HEXLOWER.decode(&stripped).unwrap();
            assert_eq!(HEXLOWER.encode(&bytes), HEXLOWER.encode(&expected_bytes));
        }
    }

    #[test]
    fn test_server_client_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                RelayToClientMsg::Health {
                    problem: "Hello? Yes this is dog.".into(),
                }
                .write_to(Vec::new()),
                "0b 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (
                RelayToClientMsg::EndpointGone(client_key.public()).write_to(Vec::new()),
                "08 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61",
            ),
            (
                RelayToClientMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0a 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(quinn::EcnCodepoint::Ce),
                        segment_size: NonZeroU16::new(6),
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // segment size
                // hello world contents bytes
                "07
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(quinn::EcnCodepoint::Ce),
                        segment_size: None,
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // hello world contents bytes
                "06
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                RelayToClientMsg::Restarting {
                    reconnect_in: Duration::from_millis(10),
                    try_for: Duration::from_millis(20),
                }
                .write_to(Vec::new()),
                "0c 00 00 00 0a 00 00 00 14",
            ),
        ]);

        Ok(())
    }

    #[test]
    fn test_client_server_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                ClientToRelayMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0a 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(quinn::EcnCodepoint::Ce),
                        segment_size: NonZeroU16::new(6),
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // Segment size
                // hello world contents
                "05
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: client_key.public(),
                    datagrams: Datagrams {
                        ecn: Some(quinn::EcnCodepoint::Ce),
                        segment_size: None,
                        contents: "Hello World!".into(),
                    },
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // hello world contents
                "04
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
        ]);

        Ok(())
    }
}

#[cfg(all(test, feature = "server"))]
mod proptests {
    use iroh_base::SecretKey;
    use proptest::prelude::*;

    use super::*;

    fn secret_key() -> impl Strategy<Value = SecretKey> {
        prop::array::uniform32(any::<u8>()).prop_map(SecretKey::from)
    }

    fn key() -> impl Strategy<Value = EndpointId> {
        secret_key().prop_map(|key| key.public())
    }

    fn ecn() -> impl Strategy<Value = Option<quinn_proto::EcnCodepoint>> {
        (0..=3).prop_map(|n| match n {
            1 => Some(quinn_proto::EcnCodepoint::Ce),
            2 => Some(quinn_proto::EcnCodepoint::Ect0),
            3 => Some(quinn_proto::EcnCodepoint::Ect1),
            _ => None,
        })
    }

    fn datagrams() -> impl Strategy<Value = Datagrams> {
        // The max payload size (conservatively, since with segment_size = 0 we'd have slightly more space)
        const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - EndpointId::LENGTH - 1 /* ECN bytes */ - 2 /* segment size */;
        (
            ecn(),
            prop::option::of(MAX_PAYLOAD_SIZE / 20..MAX_PAYLOAD_SIZE),
            prop::collection::vec(any::<u8>(), 0..MAX_PAYLOAD_SIZE),
        )
            .prop_map(|(ecn, segment_size, data)| Datagrams {
                ecn,
                segment_size: segment_size
                    .map(|ss| std::cmp::min(data.len(), ss) as u16)
                    .and_then(NonZeroU16::new),
                contents: Bytes::from(data),
            })
    }

    /// Generates a random valid frame
    fn server_client_frame() -> impl Strategy<Value = RelayToClientMsg> {
        let recv_packet = (key(), datagrams()).prop_map(|(remote_endpoint_id, datagrams)| {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            }
        });
        let endpoint_gone = key().prop_map(RelayToClientMsg::EndpointGone);
        let ping = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Pong);
        let health = ".{0,65536}"
            .prop_filter("exceeds MAX_PACKET_SIZE", |s| {
                s.len() < MAX_PACKET_SIZE // a single unicode character can match a regex "." but take up multiple bytes
            })
            .prop_map(|problem| RelayToClientMsg::Health { problem });
        let restarting = (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| {
            RelayToClientMsg::Restarting {
                reconnect_in: Duration::from_millis(reconnect_in.into()),
                try_for: Duration::from_millis(try_for.into()),
            }
        });
        prop_oneof![recv_packet, endpoint_gone, ping, pong, health, restarting]
    }

    fn client_server_frame() -> impl Strategy<Value = ClientToRelayMsg> {
        let send_packet = (key(), datagrams()).prop_map(|(dst_endpoint_id, datagrams)| {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id,
                datagrams,
            }
        });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(ClientToRelayMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(ClientToRelayMsg::Pong);
        prop_oneof![send_packet, ping, pong]
    }

    proptest! {
        #[test]
        fn server_client_frame_roundtrip(frame in server_client_frame()) {
            let encoded = frame.to_bytes().freeze();
            let decoded = RelayToClientMsg::from_bytes(encoded, &KeyCache::test()).unwrap();
            prop_assert_eq!(frame, decoded);
        }

        #[test]
        fn client_server_frame_roundtrip(frame in client_server_frame()) {
            let encoded = frame.to_bytes().freeze();
            let decoded = ClientToRelayMsg::from_bytes(encoded, &KeyCache::test()).unwrap();
            prop_assert_eq!(frame, decoded);
        }

        #[test]
        fn server_client_frame_encoded_len(frame in server_client_frame()) {
            let claimed_encoded_len = frame.encoded_len();
            let actual_encoded_len = frame.to_bytes().len();
            prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
        }

        #[test]
        fn client_server_frame_encoded_len(frame in client_server_frame()) {
            let claimed_encoded_len = frame.encoded_len();
            let actual_encoded_len = frame.to_bytes().len();
            prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
        }

        #[test]
        fn datagrams_encoded_len(datagrams in datagrams()) {
            let claimed_encoded_len = datagrams.encoded_len();
            let actual_encoded_len = datagrams.write_to(Vec::new()).len();
            prop_assert_eq!(claimed_encoded_len, actual_encoded_len);
        }
    }
}
