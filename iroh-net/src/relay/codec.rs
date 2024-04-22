use std::time::Duration;

use anyhow::{bail, ensure, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_lite::{Stream, StreamExt};
use futures_sink::Sink;
use futures_util::SinkExt;
use futures::{Sink, SinkExt, Stream, StreamExt};
use iroh_base::key::{Signature, PUBLIC_KEY_LENGTH};
use tokio_util::codec::{Decoder, Encoder};

use super::types::ClientInfo;
use crate::key::{PublicKey, SecretKey};

/// The maximum size of a packet sent over relay.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// The Relay magic number, sent in the FrameType::ClientInfo frame upon initial connection.
const MAGIC: &str = "RELAY🔑";

pub(super) const KEEP_ALIVE: Duration = Duration::from_secs(60);
// TODO: what should this be?
pub(super) const SERVER_CHANNEL_SIZE: usize = 1024 * 100;
/// The number of packets buffered for sending per client
pub(super) const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512; //32;
pub(super) const PER_CLIENT_READ_QUEUE_DEPTH: usize = 512;

/// ProtocolVersion is bumped whenever there's a wire-incompatible change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FrameType::RecvPacket at beginning
/// NOTE: we are techincally running a modified version of the protocol.
/// `FrameType::PeerPresent`, `FrameType::WatchConn`, `FrameType::ClosePeer`, have been removed.
/// The server will error on that connection if a client sends one of these frames.
/// We have split with the DERP protocol significantly starting with our relay protocol 3
/// `FrameType::PeerPresent`, `FrameType::WatchConn`, `FrameType::ClosePeer`, `FrameType::ServerKey`, and `FrameType::ServerInfo` have been removed.
/// The server will error on that connection if a client sends one of these frames.
/// This materially affects the handshake protocol, and so relay nodes on version 3 will be unable to communicate
/// with nodes running earlier protocol versions.
pub(super) const PROTOCOL_VERSION: usize = 3;

///
/// Protocol flow:
///
/// Login:
///  * client connects
///  * -> client sends FrameType::ClientInfo
///
///  Steady state:
///  * server occasionally sends FrameType::KeepAlive (or FrameType::Ping)
///  * client responds to any FrameType::Ping with a FrameType::Pong
///  * clients sends FrameType::SendPacket
///  * server then sends FrameType::RecvPacket to recipient
///

const PREFERRED: u8 = 1u8;
/// indicates this is NOT the client's home node
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
    /// 32B src pub key + 32B dst pub key + packet bytes
    ForwardPacket = 16,
    #[num_enum(default)]
    Unknown = 255,
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Writes complete frame, errors if it is unable to write within the given `timeout`.
/// Ignores the timeout if `timeout.is_zero()`
///
/// Does not flush.
pub(super) async fn write_frame<S: Sink<Frame, Error = std::io::Error> + Unpin>(
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
pub(super) async fn recv_client_key<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
    stream: S,
) -> anyhow::Result<(PublicKey, ClientInfo)> {
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

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

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
    PeerGone {
        peer: PublicKey,
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
    pub(super) fn typ(&self) -> FrameType {
        match self {
            Frame::ClientInfo { .. } => FrameType::ClientInfo,
            Frame::SendPacket { .. } => FrameType::SendPacket,
            Frame::RecvPacket { .. } => FrameType::RecvPacket,
            Frame::KeepAlive => FrameType::KeepAlive,
            Frame::NotePreferred { .. } => FrameType::NotePreferred,
            Frame::PeerGone { .. } => FrameType::PeerGone,
            Frame::Ping { .. } => FrameType::Ping,
            Frame::Pong { .. } => FrameType::Pong,
            Frame::Health { .. } => FrameType::Health,
            Frame::Restarting { .. } => FrameType::Restarting,
        }
    }

    /// Serialized length (without the frame header)
    pub(super) fn len(&self) -> usize {
        match self {
            Frame::ClientInfo {
                client_public_key: _,
                message,
                signature: _,
            } => MAGIC.as_bytes().len() + PUBLIC_KEY_LENGTH + message.len() + Signature::BYTE_SIZE,
            Frame::SendPacket { dst_key: _, packet } => PUBLIC_KEY_LENGTH + packet.len(),
            Frame::RecvPacket {
                src_key: _,
                content,
            } => PUBLIC_KEY_LENGTH + content.len(),
            Frame::KeepAlive => 0,
            Frame::NotePreferred { .. } => 1,
            Frame::PeerGone { .. } => PUBLIC_KEY_LENGTH,
            Frame::Ping { .. } => 8,
            Frame::Pong { .. } => 8,
            Frame::Health { problem } => problem.len(),
            Frame::Restarting { .. } => 4 + 4,
        }
    }

    /// Writes it self to the given buffer.
    fn write_to(&self, dst: &mut BytesMut) {
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
            Frame::PeerGone { peer } => {
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

    fn from_bytes(frame_type: FrameType, content: Bytes) -> anyhow::Result<Self> {
        let res = match frame_type {
            FrameType::ClientInfo => {
                ensure!(
                    content.len()
                        >= PUBLIC_KEY_LENGTH + Signature::BYTE_SIZE + MAGIC.as_bytes().len(),
                    "invalid client info frame length: {}",
                    content.len()
                );
                ensure!(
                    &content[..MAGIC.as_bytes().len()] == MAGIC.as_bytes(),
                    "invalid client info frame magic"
                );

                let start = MAGIC.as_bytes().len();
                let client_public_key =
                    PublicKey::try_from(&content[start..start + PUBLIC_KEY_LENGTH])?;
                let start = start + PUBLIC_KEY_LENGTH;
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
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid send packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PUBLIC_KEY_LENGTH;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE,
                    "data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}"
                );
                let dst_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let packet = content.slice(PUBLIC_KEY_LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::RecvPacket => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid recv packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PUBLIC_KEY_LENGTH;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE,
                    "data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}"
                );
                let src_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let content = content.slice(PUBLIC_KEY_LENGTH..);
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
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid peer gone frame length"
                );
                let peer = PublicKey::try_from(&content[..32])?;
                Self::PeerGone { peer }
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
        let frame = Frame::from_bytes(frame_type, content)?;

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
pub(super) async fn recv_frame<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
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
        let mut reader = FramedRead::new(reader, DerpCodec);
        let mut writer = FramedWrite::new(writer, DerpCodec);

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
        let mut reader = FramedRead::new(reader, DerpCodec);
        let mut writer = FramedWrite::new(writer, DerpCodec);

        let client_key = SecretKey::generate();
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
}

/// these test are slow in debug mode, so only run them in release mode
#[cfg(test)]
#[cfg(not(debug_assertions))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

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
        let server_key = key().prop_map(|key| Frame::ServerKey { key });
        let client_info = (key(), data(32)).prop_map(|(client_public_key, encrypted_message)| {
            Frame::ClientInfo {
                client_public_key,
                encrypted_message,
            }
        });
        let send_packet =
            (key(), data(32)).prop_map(|(dst_key, packet)| Frame::SendPacket { dst_key, packet });
        let recv_packet =
            (key(), data(32)).prop_map(|(src_key, content)| Frame::RecvPacket { src_key, content });
        let keep_alive = Just(Frame::KeepAlive);
        let note_preferred = any::<bool>().prop_map(|preferred| Frame::NotePreferred { preferred });
        let peer_gone = key().prop_map(|peer| Frame::PeerGone { peer });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Ping { data });
        let pong = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Pong { data });
        let health = data(0).prop_map(|problem| Frame::Health { problem });
        let restarting =
            (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| Frame::Restarting {
                reconnect_in,
                try_for,
            });
        prop_oneof![
            server_key,
            client_info,
            server_info,
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
                FrameType::ServerKey
                | FrameType::KeepAlive
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
            DerpCodec.encode(frame.clone(), &mut buf).unwrap();
            let decoded = DerpCodec.decode(&mut buf).unwrap().unwrap();
            prop_assert_eq!(frame, decoded);
        }

        // Test that typical invalid frames will result in an error
        #[test]
        fn broken_frame_handling(frame in frame()) {
            let mut buf = BytesMut::new();
            DerpCodec.encode(frame.clone(), &mut buf).unwrap();
            inject_error(&mut buf);
            let decoded = DerpCodec.decode(&mut buf);
            prop_assert!(decoded.is_err());
        }
    }
}
