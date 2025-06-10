//! This module implements the relaying protocol used by the `server` and `client`.
//!
//! Protocol flow:
//!
//! Login:
//!  * client connects
//!  * -> client sends `FrameType::ClientInfo`
//!
//!  Steady state:
//!  * server occasionally sends `FrameType::KeepAlive` (or `FrameType::Ping`)
//!  * client responds to any `FrameType::Ping` with a `FrameType::Pong`
//!  * clients sends `FrameType::SendPacket`
//!  * server then sends `FrameType::RecvPacket` to recipient

use bytes::{BufMut, Bytes};
use iroh_base::{NodeId, SignatureError};
#[cfg(feature = "server")]
use n0_future::time::Duration;
use n0_future::{time, Sink, SinkExt};
use nested_enum_utils::common_fields;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, ResultExt, Snafu};

use crate::{client::conn::SendError as ConnSendError, KeyCache};

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

/// The one byte frame type at the beginning of the frame
/// header. The second field is a big-endian u32 describing the
/// length of the remaining frame (not including the initial 5 bytes)
#[derive(Debug, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::FromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum FrameType {
    /// magic + 32b pub key + 24B nonce + bytes
    ClientInfo = 2,
    /// 32B dest pub key + packet bytes
    SendPacket = 4,
    /// v0/1 packet bytes, v2: 32B src pub key + packet bytes
    RecvPacket = 5,
    /// Sent from server to client to signal that a previous sender is no longer connected.
    ///
    /// That is, if A sent to B, and then if A disconnects, the server sends `FrameType::PeerGone`
    /// to B so B can forget that a reverse path exists on that connection to get back to A
    ///
    /// 32B pub key of peer that's gone
    NodeGone = 8,
    /// Frames 9-11 concern meshing, which we have eliminated from our version of the protocol.
    /// Messages with these frames will be ignored.
    /// 8 byte ping payload, to be echoed back in FrameType::Pong
    Ping = 12,
    /// 8 byte payload, the contents of ping being replied to
    Pong = 13,
    /// Sent from server to client to tell the client if their connection is
    /// unhealthy somehow.
    ///
    /// Currently this is used to indicate that the connection was closed because of authentication issues.
    Health = 14,

    /// Sent from server to client for the server to declare that it's restarting.
    /// Payload is two big endian u32 durations in milliseconds: when to reconnect,
    /// and how long to try total.
    ///
    /// Handled on the `[relay::Client]`, but currently never sent on the `[relay::Server]`
    Restarting = 15,
    /// Unknown frame type
    #[num_enum(default)]
    Unknown = 255,
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Serialize, Deserialize, MaxSize, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    /// The relay protocol version that the client was built with.
    pub(crate) version: usize,
}

/// Protocol send errors.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SendError {
    #[snafu(transparent)]
    Io { source: std::io::Error },
    #[snafu(transparent)]
    Timeout { source: time::Elapsed },
    #[snafu(transparent)]
    ConnSend { source: ConnSendError },
    #[snafu(transparent)]
    SerDe { source: postcard::Error },
}

/// Protocol send errors.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecvError {
    #[snafu(transparent)]
    Io { source: std::io::Error },
    #[snafu(display("unexpected frame: got {got}, expected {expected}"))]
    UnexpectedFrame { got: FrameType, expected: FrameType },
    #[snafu(display("Frame is too large, has {frame_len} bytes"))]
    FrameTooLarge { frame_len: usize },
    #[snafu(transparent)]
    Timeout { source: time::Elapsed },
    #[snafu(transparent)]
    SerDe { source: postcard::Error },
    #[snafu(transparent)]
    InvalidSignature { source: SignatureError },
    #[snafu(display("Invalid frame encoding"))]
    InvalidFrame {},
    #[snafu(display("Invalid frame type: {frame_type}"))]
    InvalidFrameType { frame_type: FrameType },
    #[snafu(display("invalid protocol message encoding"))]
    InvalidProtocolMessageEncoding { source: std::str::Utf8Error },
    #[snafu(display("Too few bytes"))]
    TooSmall {},
}

/// Writes complete frame, errors if it is unable to write within the given `timeout`.
/// Ignores the timeout if `None`
///
/// Does not flush.
#[cfg(feature = "server")]
pub(crate) async fn write_frame<S: Sink<ServerToClientMsg, Error = std::io::Error> + Unpin>(
    mut writer: S,
    frame: ServerToClientMsg,
    timeout: Option<Duration>,
) -> Result<(), SendError> {
    if let Some(duration) = timeout {
        tokio::time::timeout(duration, writer.send(frame)).await??;
    } else {
        writer.send(frame).await?;
    }

    Ok(())
}

/// TODO(matheus23): Docs
/// The messages received from a framed relay stream.
///
/// This is a type-validated version of the `Frame`s on the `RelayCodec`.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum ServerToClientMsg {
    /// Represents an incoming packet.
    ReceivedPacket {
        /// The [`NodeId`] of the packet sender.
        remote_node_id: NodeId,
        /// The received packet bytes.
        #[debug(skip)]
        data: Bytes,
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the server.
    NodeGone(NodeId),
    /// A one-way message from server to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the server doesn't broadcast a [`ReceivedMessage::Health`]
        /// until a problem exists.
        problem: String,
    },
    /// A one-way message from server to client, advertising that the server is restarting.
    Restarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the server to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A server should not send a TryFor duration more
        /// than a few seconds.
        try_for: Duration,
    },
    /// TODO(matheus23) fix docs
    /// Request from a client or server to reply to the
    /// other side with a [`ReceivedMessage::Pong`] with the given payload.
    Ping([u8; 8]),
    /// TODO(matheus23) fix docs
    /// Reply to a [`ReceivedMessage::Ping`] from a client or server
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
}

/// TODO(matheus23): Docs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientToServerMsg {
    /// TODO
    Ping([u8; 8]),
    /// TODO
    Pong([u8; 8]),
    /// TODO
    SendPacket {
        /// TODO
        dst_key: NodeId,
        /// TODO
        packet: Bytes,
    },
}

impl ServerToClientMsg {
    /// TODO(matheus23): docs
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

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst.put_u8(self.typ().into());
        match self {
            Self::ReceivedPacket {
                remote_node_id: src_key,
                data: content,
            } => {
                dst.put(src_key.as_ref());
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

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_bytes(bytes: Bytes, cache: &KeyCache) -> Result<Self, RecvError> {
        if bytes.is_empty() {
            return Err(TooSmallSnafu.build());
        }
        let frame_type = FrameType::from(bytes[0]);
        let content = bytes.slice(1..);

        let res = match frame_type {
            FrameType::RecvPacket => {
                if content.len() < NodeId::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }

                let frame_len = content.len() - NodeId::LENGTH;
                if frame_len > MAX_PACKET_SIZE {
                    return Err(FrameTooLargeSnafu { frame_len }.build());
                }

                let src_key = cache.key_from_slice(&content[..NodeId::LENGTH])?;
                let content = content.slice(NodeId::LENGTH..);
                Self::ReceivedPacket {
                    remote_node_id: src_key,
                    data: content,
                }
            }
            FrameType::NodeGone => {
                if content.len() != NodeId::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }
                let node_id = cache.key_from_slice(&content[..32])?;
                Self::NodeGone(node_id)
            }
            FrameType::Ping => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong(data)
            }
            FrameType::Health => {
                let problem = std::str::from_utf8(&content)
                    .context(InvalidProtocolMessageEncodingSnafu)?
                    .to_owned();
                // TODO(matheus23): Actually encode/decode the option
                Self::Health { problem }
            }
            FrameType::Restarting => {
                if content.len() != 4 + 4 {
                    return Err(InvalidFrameSnafu.build());
                }
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

impl ClientToServerMsg {
    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Self::SendPacket { .. } => FrameType::SendPacket,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
        }
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst.put_u8(self.typ().into());
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

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_bytes(bytes: Bytes, cache: &KeyCache) -> Result<Self, RecvError> {
        if bytes.is_empty() {
            return Err(TooSmallSnafu.build());
        }
        let frame_type = FrameType::from(bytes[0]);
        let content = bytes.slice(1..);

        let res = match frame_type {
            FrameType::SendPacket => {
                if content.len() < NodeId::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }
                let frame_len = content.len() - NodeId::LENGTH;
                if frame_len > MAX_PACKET_SIZE {
                    return Err(FrameTooLargeSnafu { frame_len }.build());
                }

                let dst_key = cache.key_from_slice(&content[..NodeId::LENGTH])?;
                let packet = content.slice(NodeId::LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::Ping => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping(data)
            }
            FrameType::Pong => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
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
            assert_eq!(bytes, expected_bytes);
        }
    }

    #[test]
    fn test_server_client_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                ServerToClientMsg::Health {
                    problem: "Hello? Yes this is dog.".into(),
                }
                .write_to(Vec::new()),
                "0e 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (
                ServerToClientMsg::NodeGone(client_key.public()).write_to(Vec::new()),
                "08 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61",
            ),
            (
                ServerToClientMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "0c 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ServerToClientMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0d 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ServerToClientMsg::ReceivedPacket {
                    remote_node_id: client_key.public(),
                    data: "Hello World!".into(),
                }
                .write_to(Vec::new()),
                "05 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61 48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                ServerToClientMsg::Restarting {
                    reconnect_in: Duration::from_millis(10),
                    try_for: Duration::from_millis(20),
                }
                .write_to(Vec::new()),
                "0f 00 00 00 0a 00 00 00 14",
            ),
        ]);

        Ok(())
    }

    #[test]
    fn test_client_server_frames_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        check_expected_bytes(vec![
            (
                ClientToServerMsg::Ping([42u8; 8]).write_to(Vec::new()),
                "0c 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToServerMsg::Pong([42u8; 8]).write_to(Vec::new()),
                "0d 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                ClientToServerMsg::SendPacket {
                    dst_key: client_key.public(),
                    packet: "Goodbye!".into(),
                }
                .write_to(Vec::new()),
                "04 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61 47 6f 6f 64 62 79 65 21",
            ),
        ]);

        Ok(())
    }
}

#[cfg(test)]
mod proptests {
    use bytes::BytesMut;
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
    fn server_client_frame() -> impl Strategy<Value = ServerToClientMsg> {
        let recv_packet =
            (key(), data(32)).prop_map(|(src_key, content)| ServerToClientMsg::ReceivedPacket {
                remote_node_id: src_key,
                data: content,
            });
        let node_gone = key().prop_map(|node_id| ServerToClientMsg::NodeGone(node_id));
        let ping = prop::array::uniform8(any::<u8>()).prop_map(ServerToClientMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(ServerToClientMsg::Pong);
        // TODO(matheus23): Actually fix these
        let health = data(0).prop_map(|_problem| ServerToClientMsg::Health {
            problem: "".to_string(),
        });
        let restarting = (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| {
            ServerToClientMsg::Restarting {
                reconnect_in: Duration::from_millis(reconnect_in.into()),
                try_for: Duration::from_millis(try_for.into()),
            }
        });
        prop_oneof![recv_packet, node_gone, ping, pong, health, restarting]
    }

    fn client_server_frame() -> impl Strategy<Value = ClientToServerMsg> {
        let send_packet = (key(), data(32))
            .prop_map(|(dst_key, packet)| ClientToServerMsg::SendPacket { dst_key, packet });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(ClientToServerMsg::Ping);
        let pong = prop::array::uniform8(any::<u8>()).prop_map(ClientToServerMsg::Pong);
        prop_oneof![send_packet, ping, pong]
    }

    proptest! {
        #[test]
        fn server_client_frame_roundtrip(frame in server_client_frame()) {
            let encoded = frame.clone().write_to(BytesMut::new()).freeze();
            let decoded = ServerToClientMsg::from_bytes(encoded, &KeyCache::test()).unwrap();
            prop_assert_eq!(frame, decoded);
        }

        #[test]
        fn client_server_frame_roundtrip(frame in client_server_frame()) {
            let encoded = frame.clone().write_to(BytesMut::new()).freeze();
            let decoded = ClientToServerMsg::from_bytes(encoded, &KeyCache::test()).unwrap();
            prop_assert_eq!(frame, decoded);
        }
    }
}
