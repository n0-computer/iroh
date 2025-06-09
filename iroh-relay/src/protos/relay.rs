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
use iroh_base::{PublicKey, SignatureError};
#[cfg(feature = "server")]
use n0_future::time::Duration;
use n0_future::{time, Sink, SinkExt};
use nested_enum_utils::common_fields;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

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
    PeerGone = 8,
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
    #[snafu(display("Too few bytes"))]
    TooSmall {},
}

/// Writes complete frame, errors if it is unable to write within the given `timeout`.
/// Ignores the timeout if `None`
///
/// Does not flush.
#[cfg(feature = "server")]
pub(crate) async fn write_frame<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    frame: Frame,
    timeout: Option<Duration>,
) -> Result<(), SendError> {
    if let Some(duration) = timeout {
        tokio::time::timeout(duration, writer.send(frame)).await??;
    } else {
        writer.send(frame).await?;
    }

    Ok(())
}

/// The frames in the [`RelayCodec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    SendPacket { dst_key: PublicKey, packet: Bytes },
    RecvPacket { src_key: PublicKey, content: Bytes },
    NodeGone { node_id: PublicKey },
    Ping { data: [u8; 8] },
    Pong { data: [u8; 8] },
    Health { problem: Bytes },
    Restarting { reconnect_in: u32, try_for: u32 },
}

impl Frame {
    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Frame::SendPacket { .. } => FrameType::SendPacket,
            Frame::RecvPacket { .. } => FrameType::RecvPacket,
            Frame::NodeGone { .. } => FrameType::PeerGone,
            Frame::Ping { .. } => FrameType::Ping,
            Frame::Pong { .. } => FrameType::Pong,
            Frame::Health { .. } => FrameType::Health,
            Frame::Restarting { .. } => FrameType::Restarting,
        }
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        dst.put_u8(self.typ().into());
        match self {
            Frame::SendPacket { dst_key, packet } => {
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
            }
            Frame::RecvPacket { src_key, content } => {
                dst.put(src_key.as_ref());
                dst.put(content.as_ref());
            }
            Frame::NodeGone { node_id: peer } => {
                dst.put(peer.as_ref());
            }
            Frame::Ping { data } => {
                dst.put(&data[..]);
            }
            Frame::Pong { data } => {
                dst.put(&data[..]);
            }
            Frame::Health { problem } => {
                dst.put(problem.as_ref());
            }
            Frame::Restarting {
                reconnect_in,
                try_for,
            } => {
                dst.put_u32(*reconnect_in);
                dst.put_u32(*try_for);
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
                if content.len() < PublicKey::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }
                let frame_len = content.len() - PublicKey::LENGTH;
                if frame_len > MAX_PACKET_SIZE {
                    return Err(FrameTooLargeSnafu { frame_len }.build());
                }

                let dst_key = cache.key_from_slice(&content[..PublicKey::LENGTH])?;
                let packet = content.slice(PublicKey::LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::RecvPacket => {
                if content.len() < PublicKey::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }

                let frame_len = content.len() - PublicKey::LENGTH;
                if frame_len > MAX_PACKET_SIZE {
                    return Err(FrameTooLargeSnafu { frame_len }.build());
                }

                let src_key = cache.key_from_slice(&content[..PublicKey::LENGTH])?;
                let content = content.slice(PublicKey::LENGTH..);
                Self::RecvPacket { src_key, content }
            }
            FrameType::PeerGone => {
                if content.len() != PublicKey::LENGTH {
                    return Err(InvalidFrameSnafu.build());
                }
                let peer = cache.key_from_slice(&content[..32])?;
                Self::NodeGone { node_id: peer }
            }
            FrameType::Ping => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping { data }
            }
            FrameType::Pong => {
                if content.len() != 8 {
                    return Err(InvalidFrameSnafu.build());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong { data }
            }
            FrameType::Health => Self::Health { problem: content },
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

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use iroh_base::SecretKey;
    use n0_snafu::Result;

    use super::*;

    #[test]
    fn test_frame_snapshot() -> Result {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);

        let frames = vec![
            (
                Frame::Health {
                    problem: "Hello? Yes this is dog.".into(),
                },
                "0e 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (
                Frame::NodeGone {
                    node_id: client_key.public(),
                },
                "08 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61",
            ),
            (
                Frame::Ping { data: [42u8; 8] },
                "0c 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                Frame::Pong { data: [42u8; 8] },
                "0d 2a 2a 2a 2a 2a 2a 2a 2a",
            ),
            (
                Frame::RecvPacket {
                    src_key: client_key.public(),
                    content: "Hello World!".into(),
                },
                "05 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61 48 65 6c 6c 6f 20 57 6f 72 6c 64 21",
            ),
            (
                Frame::SendPacket {
                    dst_key: client_key.public(),
                    packet: "Goodbye!".into(),
                },
                "04 19 7f 6b 23 e1 6c 85 32 c6 ab c8 38 fa cd 5e
                a7 89 be 0c 76 b2 92 03 34 03 9b fa 8b 3d 36 8d
                61 47 6f 6f 64 62 79 65 21",
            ),
            (
                Frame::Restarting {
                    reconnect_in: 10,
                    try_for: 20,
                },
                "0f 00 00 00 0a 00 00 00 14",
            ),
        ];

        for (frame, expected_hex) in frames {
            let mut bytes = Vec::new();
            frame.write_to(&mut bytes);
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

        Ok(())
    }
}

#[cfg(test)]
mod proptests {
    use iroh_base::SecretKey;
    use proptest::prelude::*;

    use super::*;

    fn secret_key() -> impl Strategy<Value = SecretKey> {
        prop::array::uniform32(any::<u8>()).prop_map(SecretKey::from)
    }

    fn key() -> impl Strategy<Value = PublicKey> {
        secret_key().prop_map(|key| key.public())
    }

    /// Generates random data, up to the maximum packet size minus the given number of bytes
    fn data(consumed: usize) -> impl Strategy<Value = Bytes> {
        let len = MAX_PACKET_SIZE - consumed;
        prop::collection::vec(any::<u8>(), 0..len).prop_map(Bytes::from)
    }

    /// Generates a random valid frame
    fn frame() -> impl Strategy<Value = Frame> {
        let send_packet =
            (key(), data(32)).prop_map(|(dst_key, packet)| Frame::SendPacket { dst_key, packet });
        let recv_packet =
            (key(), data(32)).prop_map(|(src_key, content)| Frame::RecvPacket { src_key, content });
        let peer_gone = key().prop_map(|peer| Frame::NodeGone { node_id: peer });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Ping { data });
        let pong = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Pong { data });
        let health = data(0).prop_map(|problem| Frame::Health { problem });
        let restarting =
            (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| Frame::Restarting {
                reconnect_in,
                try_for,
            });
        prop_oneof![
            send_packet,
            recv_packet,
            peer_gone,
            ping,
            pong,
            health,
            restarting,
        ]
    }

    proptest! {
        #[test]
        fn frame_roundtrip(frame in frame()) {
            let mut encoded = Vec::new();
            frame.clone().write_to(&mut encoded);
            let decoded = Frame::from_bytes(Bytes::from(encoded), &KeyCache::test()).unwrap();
            prop_assert_eq!(frame, decoded);
        }
    }
}
