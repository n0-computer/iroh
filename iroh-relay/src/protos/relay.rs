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

use std::time::Duration;

use anyhow::{bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
#[cfg(any(test, feature = "server"))]
use futures_lite::{Stream, StreamExt};
use futures_sink::Sink;
use futures_util::SinkExt;
use iroh_base::{PublicKey, SecretKey, Signature};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// The maximum size of a packet sent over relay.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

/// The maximum frame size.
///
/// This is also the minimum burst size that a rate-limiter has to accept.
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// The Relay magic number, sent in the FrameType::ClientInfo frame upon initial connection.
const MAGIC: &str = "RELAY🔑";

#[cfg(feature = "server")]
pub(crate) const KEEP_ALIVE: Duration = Duration::from_secs(60);
// TODO: what should this be?
#[cfg(feature = "server")]
pub(crate) const SERVER_CHANNEL_SIZE: usize = 1024 * 100;
/// The number of packets buffered for sending per client
pub(crate) const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512; //32;
pub(crate) const PER_CLIENT_READ_QUEUE_DEPTH: usize = 512;

/// ProtocolVersion is bumped whenever there's a wire-incompatible change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FrameType::RecvPacket at beginning.
///
/// NOTE: we are technically running a modified version of the protocol.
/// `FrameType::PeerPresent`, `FrameType::WatchConn`, `FrameType::ClosePeer`, have been removed.
/// The server will error on that connection if a client sends one of these frames.
/// We have split with the DERP protocol significantly starting with our relay protocol 3
/// `FrameType::PeerPresent`, `FrameType::WatchConn`, `FrameType::ClosePeer`, `FrameType::ServerKey`, and `FrameType::ServerInfo` have been removed.
/// The server will error on that connection if a client sends one of these frames.
/// This materially affects the handshake protocol, and so relay nodes on version 3 will be unable to communicate
/// with nodes running earlier protocol versions.
pub(crate) const PROTOCOL_VERSION: usize = 3;

/// Indicates this IS the client's home node
const PREFERRED: u8 = 1u8;
/// Indicates this IS NOT the client's home node
const NOT_PREFERRED: u8 = 0u8;

/// The one byte frame type at the beginning of the frame
/// header. The second field is a big-endian u32 describing the
/// length of the remaining frame (not including the initial 5 bytes)
#[derive(Debug, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::FromPrimitive, Clone, Copy)]
#[repr(u8)]
pub(crate) enum FrameType {
    /// magic + 32b pub key + 24B nonce + bytes
    ClientInfo = 2,
    /// 32B dest pub key + packet bytes
    SendPacket = 4,
    /// v0/1 packet bytes, v2: 32B src pub key + packet bytes
    RecvPacket = 5,
    /// no payload, no-op (to be replaced with ping/pong)
    KeepAlive = 6,
    /// 1 byte payload: 0x01 or 0x00 for whether this is client's home node
    NotePreferred = 7,
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
    /// unhealthy somehow. Currently the only unhealthy state is whether the
    /// connection is detected as a duplicate.
    /// The entire frame body is the text of the error message. An empty message
    /// clears the error state.
    Health = 14,

    /// Sent from server to client for the server to declare that it's restarting.
    /// Payload is two big endian u32 durations in milliseconds: when to reconnect,
    /// and how long to try total.
    ///
    /// Handled on the `[relay::Client]`, but currently never sent on the `[relay::Server]`
    Restarting = 15,
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

/// Writes complete frame, errors if it is unable to write within the given `timeout`.
/// Ignores the timeout if `None`
///
/// Does not flush.
pub(crate) async fn write_frame<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    frame: Frame,
    timeout: Option<Duration>,
) -> anyhow::Result<()> {
    if let Some(duration) = timeout {
        tokio::time::timeout(duration, writer.send(frame)).await??;
    } else {
        writer.send(frame).await?;
    }

    Ok(())
}

/// Writes a `FrameType::ClientInfo`, including the client's [`PublicKey`],
/// and the client's [`ClientInfo`], sealed using the server's [`PublicKey`].
///
/// Flushes after writing.
pub(crate) async fn send_client_key<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    client_secret_key: &SecretKey,
    client_info: &ClientInfo,
) -> anyhow::Result<()> {
    let msg = postcard::to_stdvec(client_info)?;
    let signature = client_secret_key.sign(&msg);

    writer
        .send(Frame::ClientInfo {
            client_public_key: client_secret_key.public(),
            message: msg.into(),
            signature,
        })
        .await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the `FrameType::ClientInfo` frame from the client (its proof of identity)
/// upon it's initial connection.
#[cfg(any(test, feature = "server"))]
pub(crate) async fn recv_client_key<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
    stream: S,
) -> anyhow::Result<(PublicKey, ClientInfo)> {
    use anyhow::Context;
    // the client is untrusted at this point, limit the input size even smaller than our usual
    // maximum frame size, and give a timeout

    // TODO: variable recv size: 256 * 1024
    let buf = tokio::time::timeout(
        Duration::from_secs(10),
        recv_frame(FrameType::ClientInfo, stream),
    )
    .await
    .context("recv_frame timeout")?
    .context("recv_frame")?;

    if let Frame::ClientInfo {
        client_public_key,
        message,
        signature,
    } = buf
    {
        client_public_key
            .verify(&message, &signature)
            .context("invalid signature")?;
        let info: ClientInfo = postcard::from_bytes(&message).context("deserialization")?;
        Ok((client_public_key, info))
    } else {
        anyhow::bail!("expected FrameType::ClientInfo");
    }
}

/// A cache for public keys.
#[derive(Default, Debug, Clone)]
pub struct KeyCache;

impl KeyCache {
    /// Get a key from key bytes and update the cache.
    pub fn key_from_bytes(
        &self,
        bytes: &[u8; 32],
    ) -> Result<PublicKey, <PublicKey as TryFrom<&[u8; 32]>>::Error> {
        PublicKey::try_from(bytes)
    }

    /// Get a key from a slice of bytes.
    pub fn key_from_slice(
        &self,
        bytes: &[u8],
    ) -> Result<PublicKey, <PublicKey as TryFrom<&[u8]>>::Error> {
        PublicKey::try_from(bytes)
    }
}

/// The protocol for the relay server.
///
/// This is a framed protocol, using [`tokio_util::codec`] to turn the streams of bytes into
/// [`Frame`]s.
#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec {
    cache: KeyCache,
}

impl DerpCodec {
    pub(crate) fn new(cache: KeyCache) -> Self {
        Self { cache }
    }
}

/// The frames in the [`DerpCodec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    ClientInfo {
        client_public_key: PublicKey,
        message: Bytes,
        signature: Signature,
    },
    SendPacket {
        dst_key: PublicKey,
        packet: Bytes,
    },
    RecvPacket {
        src_key: PublicKey,
        content: Bytes,
    },
    KeepAlive,
    NotePreferred {
        preferred: bool,
    },
    NodeGone {
        node_id: PublicKey,
    },
    Ping {
        data: [u8; 8],
    },
    Pong {
        data: [u8; 8],
    },
    Health {
        problem: Bytes,
    },
    Restarting {
        reconnect_in: u32,
        try_for: u32,
    },
}

impl Frame {
    pub(crate) fn typ(&self) -> FrameType {
        match self {
            Frame::ClientInfo { .. } => FrameType::ClientInfo,
            Frame::SendPacket { .. } => FrameType::SendPacket,
            Frame::RecvPacket { .. } => FrameType::RecvPacket,
            Frame::KeepAlive => FrameType::KeepAlive,
            Frame::NotePreferred { .. } => FrameType::NotePreferred,
            Frame::NodeGone { .. } => FrameType::PeerGone,
            Frame::Ping { .. } => FrameType::Ping,
            Frame::Pong { .. } => FrameType::Pong,
            Frame::Health { .. } => FrameType::Health,
            Frame::Restarting { .. } => FrameType::Restarting,
        }
    }

    /// Serialized length (without the frame header)
    pub(crate) fn len(&self) -> usize {
        match self {
            Frame::ClientInfo {
                client_public_key: _,
                message,
                signature: _,
            } => MAGIC.len() + PublicKey::LENGTH + message.len() + Signature::BYTE_SIZE,
            Frame::SendPacket { dst_key: _, packet } => PublicKey::LENGTH + packet.len(),
            Frame::RecvPacket {
                src_key: _,
                content,
            } => PublicKey::LENGTH + content.len(),
            Frame::KeepAlive => 0,
            Frame::NotePreferred { .. } => 1,
            Frame::NodeGone { .. } => PublicKey::LENGTH,
            Frame::Ping { .. } => 8,
            Frame::Pong { .. } => 8,
            Frame::Health { problem } => problem.len(),
            Frame::Restarting { .. } => 4 + 4,
        }
    }

    /// Serialized length with frame header.
    #[cfg(feature = "server")]
    pub(crate) fn len_with_header(&self) -> usize {
        self.len() + HEADER_LEN
    }

    /// Tries to decode a frame received over websockets.
    ///
    /// Specifically, bytes received from a binary websocket message frame.
    pub(crate) fn decode_from_ws_msg(vec: Vec<u8>, cache: &KeyCache) -> anyhow::Result<Self> {
        if vec.is_empty() {
            bail!("error parsing relay::codec::Frame: too few bytes (0)");
        }
        let bytes = Bytes::from(vec);
        let typ = FrameType::from(bytes[0]);
        let frame = Self::from_bytes(typ, bytes.slice(1..), cache)?;
        Ok(frame)
    }

    /// Encodes this frame for sending over websockets.
    ///
    /// Specifically meant for being put into a binary websocket message frame.
    pub(crate) fn encode_for_ws_msg(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.put_u8(self.typ().into());
        self.write_to(&mut bytes);
        bytes
    }

    /// Writes it self to the given buffer.
    fn write_to(&self, dst: &mut impl BufMut) {
        match self {
            Frame::ClientInfo {
                client_public_key,
                message,
                signature,
            } => {
                dst.put(MAGIC.as_bytes());
                dst.put(client_public_key.as_ref());
                dst.put(&signature.to_bytes()[..]);
                dst.put(&message[..]);
            }
            Frame::SendPacket { dst_key, packet } => {
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
            }
            Frame::RecvPacket { src_key, content } => {
                dst.put(src_key.as_ref());
                dst.put(content.as_ref());
            }
            Frame::KeepAlive => {}
            Frame::NotePreferred { preferred } => {
                if *preferred {
                    dst.put_u8(PREFERRED);
                } else {
                    dst.put_u8(NOT_PREFERRED);
                }
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
    }

    fn from_bytes(frame_type: FrameType, content: Bytes, cache: &KeyCache) -> anyhow::Result<Self> {
        let res = match frame_type {
            FrameType::ClientInfo => {
                ensure!(
                    content.len() >= PublicKey::LENGTH + Signature::BYTE_SIZE + MAGIC.len(),
                    "invalid client info frame length: {}",
                    content.len()
                );
                ensure!(
                    &content[..MAGIC.len()] == MAGIC.as_bytes(),
                    "invalid client info frame magic"
                );

                let start = MAGIC.len();
                let client_public_key =
                    cache.key_from_slice(&content[start..start + PublicKey::LENGTH])?;
                let start = start + PublicKey::LENGTH;
                let signature =
                    Signature::from_slice(&content[start..start + Signature::BYTE_SIZE])?;
                let start = start + Signature::BYTE_SIZE;
                let message = content.slice(start..);
                Self::ClientInfo {
                    client_public_key,
                    message,
                    signature,
                }
            }
            FrameType::SendPacket => {
                ensure!(
                    content.len() >= PublicKey::LENGTH,
                    "invalid send packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PublicKey::LENGTH;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE,
                    "data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}"
                );
                let dst_key = cache.key_from_slice(&content[..PublicKey::LENGTH])?;
                let packet = content.slice(PublicKey::LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::RecvPacket => {
                ensure!(
                    content.len() >= PublicKey::LENGTH,
                    "invalid recv packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PublicKey::LENGTH;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE,
                    "data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}"
                );
                let src_key = cache.key_from_slice(&content[..PublicKey::LENGTH])?;
                let content = content.slice(PublicKey::LENGTH..);
                Self::RecvPacket { src_key, content }
            }
            FrameType::KeepAlive => {
                anyhow::ensure!(content.is_empty(), "invalid keep alive frame length");
                Self::KeepAlive
            }
            FrameType::NotePreferred => {
                anyhow::ensure!(content.len() == 1, "invalid note preferred frame length");
                let preferred = match content[0] {
                    PREFERRED => true,
                    NOT_PREFERRED => false,
                    _ => anyhow::bail!("invalid note preferred frame content"),
                };
                Self::NotePreferred { preferred }
            }
            FrameType::PeerGone => {
                anyhow::ensure!(
                    content.len() == PublicKey::LENGTH,
                    "invalid peer gone frame length"
                );
                let peer = cache.key_from_slice(&content[..32])?;
                Self::NodeGone { node_id: peer }
            }
            FrameType::Ping => {
                anyhow::ensure!(content.len() == 8, "invalid ping frame length");
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping { data }
            }
            FrameType::Pong => {
                anyhow::ensure!(content.len() == 8, "invalid pong frame length");
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong { data }
            }
            FrameType::Health => Self::Health { problem: content },
            FrameType::Restarting => {
                ensure!(
                    content.len() == 4 + 4,
                    "invalid restarting frame length: {}",
                    content.len()
                );
                let reconnect_in = u32::from_be_bytes(content[..4].try_into()?);
                let try_for = u32::from_be_bytes(content[4..].try_into()?);
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            _ => {
                anyhow::bail!("invalid frame type: {:?}", frame_type);
            }
        };
        Ok(res)
    }
}

const HEADER_LEN: usize = 5;

impl Decoder for DerpCodec {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 5 bytes
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Can't use the `Buf::get_*` APIs, as that advances the buffer.
        let Some(frame_type) = src.first().map(|b| FrameType::from(*b)) else {
            return Ok(None); // Not enough bytes
        };
        let Some(frame_len) = src
            .get(1..5)
            .and_then(|s| TryInto::<[u8; 4]>::try_into(s).ok())
            .map(u32::from_be_bytes)
            .map(|l| l as usize)
        else {
            return Ok(None); // Not enough bytes
        };

        if frame_len > MAX_FRAME_SIZE {
            anyhow::bail!("Frame of length {} is too large.", frame_len);
        }

        if src.len() < HEADER_LEN + frame_len {
            // Optimization: prereserve the buffer space
            src.reserve(HEADER_LEN + frame_len - src.len());

            return Ok(None);
        }

        // advance the header
        src.advance(HEADER_LEN);

        let content = src.split_to(frame_len).freeze();
        let frame = Frame::from_bytes(frame_type, content, &self.cache)?;

        Ok(Some(frame))
    }
}

impl Encoder<Frame> for DerpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len: usize = frame.len();
        if frame_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", frame_len),
            ));
        }

        let frame_len_u32 = u32::try_from(frame_len).expect("just checked");

        dst.reserve(HEADER_LEN + frame_len);
        dst.put_u8(frame.typ().into());
        dst.put_u32(frame_len_u32);
        frame.write_to(dst);

        Ok(())
    }
}

/// Receives the next frame and matches the frame type. If the correct type is found returns the content,
/// otherwise an error.
#[cfg(any(test, feature = "server"))]
pub(crate) async fn recv_frame<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
    frame_type: FrameType,
    mut stream: S,
) -> anyhow::Result<Frame> {
    match stream.next().await {
        Some(Ok(frame)) => {
            ensure!(
                frame_type == frame.typ(),
                "expected frame {}, found {}",
                frame_type,
                frame.typ()
            );
            Ok(frame)
        }
        Some(Err(err)) => Err(err),
        None => bail!("EOF: unexpected stream end, expected frame {}", frame_type),
    }
}

#[cfg(test)]
mod tests {
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;

    #[tokio::test]
    async fn test_basic_read_write() -> anyhow::Result<()> {
        let (reader, writer) = tokio::io::duplex(1024);
        let mut reader = FramedRead::new(reader, DerpCodec::default());
        let mut writer = FramedWrite::new(writer, DerpCodec::default());

        let expect_buf = b"hello world!";
        let expected_frame = Frame::Health {
            problem: expect_buf.to_vec().into(),
        };
        write_frame(&mut writer, expected_frame.clone(), None).await?;
        writer.flush().await?;
        println!("{:?}", reader);
        let buf = recv_frame(FrameType::Health, &mut reader).await?;
        assert_eq!(expect_buf.len(), buf.len());
        assert_eq!(expected_frame, buf);

        Ok(())
    }

    #[tokio::test]
    async fn test_send_recv_client_key() -> anyhow::Result<()> {
        let (reader, writer) = tokio::io::duplex(1024);
        let mut reader = FramedRead::new(reader, DerpCodec::default());
        let mut writer = FramedWrite::new(writer, DerpCodec::default());

        let client_key = SecretKey::generate(rand::thread_rng());
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
        };
        println!("client_key pub {:?}", client_key.public());
        send_client_key(&mut writer, &client_key, &client_info).await?;
        let (client_pub_key, got_client_info) = recv_client_key(&mut reader).await?;
        assert_eq!(client_key.public(), client_pub_key);
        assert_eq!(client_info, got_client_info);
        Ok(())
    }

    #[test]
    fn test_frame_snapshot() -> anyhow::Result<()> {
        let client_key = SecretKey::from_bytes(&[42u8; 32]);
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
        };
        let message = postcard::to_stdvec(&client_info)?;
        let signature = client_key.sign(&message);

        let frames = vec![
            (
                Frame::ClientInfo {
                    client_public_key: client_key.public(),
                    message: Bytes::from(message),
                    signature,
                },
                "02 52 45 4c 41 59 f0 9f 94 91 19 7f 6b 23 e1 6c
                85 32 c6 ab c8 38 fa cd 5e a7 89 be 0c 76 b2 92
                03 34 03 9b fa 8b 3d 36 8d 61 88 e7 7b 22 f2 92
                ab 37 43 5d a8 de 0b c8 cb 84 e2 88 f4 e7 3b 35
                82 a5 27 31 e9 ff 98 65 46 5c 87 e0 5e 8d 42 7d
                f4 22 bb 6e 85 e1 c0 5f 6f 74 98 37 ba a4 a5 c7
                eb a3 23 0d 77 56 99 10 43 0e 03",
            ),
            (
                Frame::Health {
                    problem: "Hello? Yes this is dog.".into(),
                },
                "0e 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73
                20 69 73 20 64 6f 67 2e",
            ),
            (Frame::KeepAlive, "06"),
            (Frame::NotePreferred { preferred: true }, "07 01"),
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
            let bytes = frame.encode_for_ws_msg();
            // To regenerate the hexdumps:
            // let hexdump = iroh_test::hexdump::print_hexdump(bytes, []);
            // println!("{hexdump}");
            let expected_bytes = iroh_test::hexdump::parse_hexdump(expected_hex)?;
            assert_eq!(bytes, expected_bytes);
        }

        Ok(())
    }
}

#[cfg(test)]
mod proptests {
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
        let client_info = (secret_key()).prop_map(|secret_key| {
            let info = ClientInfo {
                version: PROTOCOL_VERSION,
            };
            let msg = postcard::to_stdvec(&info).expect("using default ClientInfo");
            let signature = secret_key.sign(&msg);
            Frame::ClientInfo {
                client_public_key: secret_key.public(),
                message: msg.into(),
                signature,
            }
        });
        let send_packet =
            (key(), data(32)).prop_map(|(dst_key, packet)| Frame::SendPacket { dst_key, packet });
        let recv_packet =
            (key(), data(32)).prop_map(|(src_key, content)| Frame::RecvPacket { src_key, content });
        let keep_alive = Just(Frame::KeepAlive);
        let note_preferred = any::<bool>().prop_map(|preferred| Frame::NotePreferred { preferred });
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
            client_info,
            send_packet,
            recv_packet,
            keep_alive,
            note_preferred,
            peer_gone,
            ping,
            pong,
            health,
            restarting,
        ]
    }

    fn inject_error(buf: &mut BytesMut) {
        fn is_fixed_size(tpe: FrameType) -> bool {
            match tpe {
                FrameType::KeepAlive
                | FrameType::NotePreferred
                | FrameType::Ping
                | FrameType::Pong
                | FrameType::Restarting
                | FrameType::PeerGone => true,
                FrameType::ClientInfo
                | FrameType::Health
                | FrameType::SendPacket
                | FrameType::RecvPacket
                | FrameType::Unknown => false,
            }
        }
        let tpe: FrameType = buf[0].into();
        let mut len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
        if is_fixed_size(tpe) {
            buf.put_u8(0);
            len += 1;
        } else {
            buf.resize(MAX_FRAME_SIZE + 1, 0);
            len = MAX_FRAME_SIZE + 1;
        }
        buf[1..5].copy_from_slice(&u32::to_be_bytes(len as u32));
    }

    proptest! {

        // Test that we can roundtrip a frame to bytes
        #[test]
        fn frame_roundtrip(frame in frame()) {
            let mut buf = BytesMut::new();
            let mut codec = DerpCodec::default();
            codec.encode(frame.clone(), &mut buf).unwrap();
            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            prop_assert_eq!(frame, decoded);
        }

        #[test]
        fn frame_ws_roundtrip(frame in frame()) {
            let encoded = frame.clone().encode_for_ws_msg();
            let decoded = Frame::decode_from_ws_msg(encoded, &KeyCache::default()).unwrap();
            prop_assert_eq!(frame, decoded);
        }

        // Test that typical invalid frames will result in an error
        #[test]
        fn broken_frame_handling(frame in frame()) {
            let mut buf = BytesMut::new();
            let mut codec = DerpCodec::default();
            codec.encode(frame.clone(), &mut buf).unwrap();
            inject_error(&mut buf);
            let decoded = codec.decode(&mut buf);
            prop_assert!(decoded.is_err());
        }
    }
}
