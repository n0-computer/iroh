//! This module implements the send/recv relaying protocol.
//!
//! Protocol flow:
//!  * server occasionally sends [`FrameType::Ping`]
//!  * client responds to any [`FrameType::Ping`] with a [`FrameType::Pong`]
//!  * clients sends [`FrameType::ClientToRelayDatagrams`]
//!  * server then sends [`FrameType::RelayToClientDatagrams`] to recipient
//!  * server sends [`FrameType::NodeGone`] when the other client disconnects

use bytes::{BufMut, Bytes, BytesMut};
use iroh_base::{NodeId, SignatureError};
use n0_future::time::{self, Duration};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, ResultExt, Snafu};

use super::common::{FrameType, FrameTypeError};
use crate::KeyCache;

/// The maximum size of a packet sent over relay.
/// (This only includes the data bytes visible to magicsock, not
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
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("unexpected frame: got {got}, expected {expected}"))]
    UnexpectedFrame { got: FrameType, expected: FrameType },
    #[snafu(display("Frame is too large, has {frame_len} bytes"))]
    FrameTooLarge { frame_len: usize },
    #[snafu(transparent)]
    Timeout { source: time::Elapsed },
    #[snafu(transparent)]
    SerDe { source: postcard::Error },
    #[snafu(transparent)]
    FrameTypeError { source: FrameTypeError },
    #[snafu(display("Invalid public key"))]
    InvalidPublicKey { source: SignatureError },
    #[snafu(display("Invalid frame encoding"))]
    InvalidFrame {},
    #[snafu(display("Invalid frame type: {frame_type}"))]
    InvalidFrameType { frame_type: FrameType },
    #[snafu(display("Invalid protocol message encoding"))]
    InvalidProtocolMessageEncoding { source: std::str::Utf8Error },
    #[snafu(display("Too few bytes"))]
    TooSmall {},
}

/// The messages that a relay sends to clients or the clients receive from the relay.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum RelayToClientMsg {
    /// Represents datagrams sent from relays (originally sent to them by another client).
    ReceivedPacket {
        /// The [`NodeId`] of the original sender.
        src_key: NodeId,
        /// The received packet bytes.
        #[debug(skip)]
        content: Bytes,
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the relay.
    NodeGone(NodeId),
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
    /// Request from the client to relay datagrams to given remote node.
    SendPacket {
        /// The remote node to relay to.
        dst_key: NodeId,
        /// The datagrams and related metadata to relay.
        packet: Bytes,
    },
}

impl RelayToClientMsg {
    /// Returns this frame's corresponding frame type.
    pub fn typ(&self) -> FrameType {
        match self {
            Self::ReceivedPacket { .. } => FrameType::RecvPacket,
            Self::NodeGone { .. } => FrameType::NodeGone,
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
            Self::ReceivedPacket {
                src_key: remote_node_id,
                content,
            } => {
                dst.put(remote_node_id.as_ref());
                dst.put(content.as_ref());
            }
            Self::NodeGone(node_id) => {
                dst.put(node_id.as_ref());
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
            Self::ReceivedPacket { content, .. } => {
                32 // nodeid
                + content.len()
            }
            Self::NodeGone(_) => 32,
            Self::Ping(_) | Self::Pong(_) => 8,
            Self::Health { problem } => problem.len(),
            Self::Restarting { .. } => {
                4 // u32
                + 4 // u32
            }
        };
        1 // frame type
        + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_bytes(mut content: Bytes, cache: &KeyCache) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        snafu::ensure!(
            frame_len <= MAX_PACKET_SIZE,
            FrameTooLargeSnafu { frame_len }
        );

        let res = match frame_type {
            FrameType::RecvPacket => {
                snafu::ensure!(content.len() >= NodeId::LENGTH, InvalidFrameSnafu);

                let src_key = cache
                    .key_from_slice(&content[..NodeId::LENGTH])
                    .context(InvalidPublicKeySnafu)?;
                let content = content.slice(NodeId::LENGTH..);
                Self::ReceivedPacket { src_key, content }
            }
            FrameType::NodeGone => {
                snafu::ensure!(content.len() == NodeId::LENGTH, InvalidFrameSnafu);
                let node_id = cache
                    .key_from_slice(content.as_ref())
                    .context(InvalidPublicKeySnafu)?;
                Self::NodeGone(node_id)
            }
            FrameType::Ping => {
                snafu::ensure!(content.len() == 8, InvalidFrameSnafu);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                snafu::ensure!(content.len() == 8, InvalidFrameSnafu);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            FrameType::Health => {
                let problem = std::str::from_utf8(&content)
                    .context(InvalidProtocolMessageEncodingSnafu)?
                    .to_owned();
                Self::Health { problem }
            }
            FrameType::Restarting => {
                snafu::ensure!(content.len() == 4 + 4, InvalidFrameSnafu);
                let reconnect_in = u32::from_be_bytes(
                    content[..4]
                        .try_into()
                        .map_err(|_| InvalidFrameSnafu.build())?,
                );
                let try_for = u32::from_be_bytes(
                    content[4..]
                        .try_into()
                        .map_err(|_| InvalidFrameSnafu.build())?,
                );
                let reconnect_in = Duration::from_millis(reconnect_in as u64);
                let try_for = Duration::from_millis(try_for as u64);
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            _ => {
                return Err(InvalidFrameTypeSnafu { frame_type }.build());
            }
        };
        Ok(res)
    }
}

impl ClientToRelayMsg {
    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Self::SendPacket { .. } => FrameType::SendPacket,
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
            Self::SendPacket { dst_key, packet } => {
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
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
            Self::SendPacket { packet, .. } => {
                32 // node id
                + packet.len()
            }
        };
        1 // frame type (all frame types currently encode as 1 byte varint)
        + payload_len
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    #[cfg(feature = "server")]
    pub(crate) fn from_bytes(mut content: Bytes, cache: &KeyCache) -> Result<Self, Error> {
        let frame_type = FrameType::from_bytes(&mut content)?;
        let frame_len = content.len();
        snafu::ensure!(
            frame_len <= MAX_PACKET_SIZE,
            FrameTooLargeSnafu { frame_len }
        );

        let res = match frame_type {
            FrameType::SendPacket => {
                let dst_key = cache
                    .key_from_slice(&content[..NodeId::LENGTH])
                    .context(InvalidPublicKeySnafu)?;
                let packet = content.slice(NodeId::LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::Ping => {
                snafu::ensure!(content.len() == 8, InvalidFrameSnafu);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                snafu::ensure!(content.len() == 8, InvalidFrameSnafu);
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            _ => {
                return Err(InvalidFrameTypeSnafu { frame_type }.build());
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
    use n0_snafu::Result;

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
                "0a 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (
                RelayToClientMsg::NodeGone(client_key.public()).write_to(Vec::new()),
                "07 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61",
            ),
            (
                RelayToClientMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "08 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                RelayToClientMsg::ReceivedPacket {
                    src_key: client_key.public(),
                    content: "Hello World!".into(),
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // segment size
                // hello world contents bytes
                "06
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
                48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                RelayToClientMsg::Restarting {
                    reconnect_in: Duration::from_millis(10),
                    try_for: Duration::from_millis(20),
                }
                .write_to(Vec::new()),
                "0b 00 00 00 0a 00 00 00 14",
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
                "08 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "09 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToRelayMsg::SendPacket {
                    dst_key: client_key.public(),
                    packet: "Hello World!".into(),
                }
                .write_to(Vec::new()),
                // frame type
                // public key first 16 bytes
                // public key second 16 bytes
                // ECN byte
                // segment size
                // hello world contents
                "05
                19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e a7
                89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d 61
                03
                00 06
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

    fn key() -> impl Strategy<Value = NodeId> {
        secret_key().prop_map(|key| key.public())
    }

    /// Generates random data, up to the maximum packet size minus the given number of bytes
    fn data(consumed: usize) -> impl Strategy<Value = Bytes> {
        let len = MAX_PACKET_SIZE - consumed;
        prop::collection::vec(any::<u8>(), 0..len).prop_map(Bytes::from)
    }

    /// Generates a random valid frame
    fn server_client_frame() -> impl Strategy<Value = RelayToClientMsg> {
        let recv_packet = (key(), data(32))
            .prop_map(|(src_key, content)| RelayToClientMsg::ReceivedPacket { src_key, content });
        let node_gone = key().prop_map(|node_id| RelayToClientMsg::NodeGone(node_id));
        let ping = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(RelayToClientMsg::Pong);
        let health = data(0).prop_map(|_problem| RelayToClientMsg::Health {
            problem: "".to_string(),
        });
        let restarting = (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| {
            RelayToClientMsg::Restarting {
                reconnect_in: Duration::from_millis(reconnect_in.into()),
                try_for: Duration::from_millis(try_for.into()),
            }
        });
        prop_oneof![recv_packet, node_gone, ping, pong, health, restarting]
    }

    fn client_server_frame() -> impl Strategy<Value = ClientToRelayMsg> {
        let send_packet = (key(), data(32))
            .prop_map(|(dst_key, packet)| ClientToRelayMsg::SendPacket { dst_key, packet });
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
    }
}
