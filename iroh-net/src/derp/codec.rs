use std::time::Duration;

use anyhow::{bail, ensure, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio_util::codec::{Decoder, Encoder};

use super::types::ClientInfo;
use crate::key::{PublicKey, SecretKey, SharedSecret};

/// The maximum size of a packet sent over DERP.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// The DERP magic number, sent in the FrameType::ServerKey frame
/// upon initial connection
///
/// 8 bytes: 0x44 45 52 50 f0 9f 94 91
const MAGIC: &str = "DERP🔑";

pub(super) const KEEP_ALIVE: Duration = Duration::from_secs(60);
// TODO: what should this be?
pub(super) const SERVER_CHANNEL_SIZE: usize = 1024 * 100;
/// The number of packets buffered for sending per client
pub(super) const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512; //32;

/// ProtocolVersion is bumped whenever there's a wire-incompatiable change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FrameType::RecvPacket at beginning
pub(super) const PROTOCOL_VERSION: usize = 2;

///
/// Protocol flow:
///
/// Login:
///  * client connects
///  * server sends FrameType::ServerKey
///  * client sends FrameType::ClientInfo
///  * server sends FrameType::ServerInfo
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
    /// 8B magic + 32B public key + (0+ bytes future use)
    ServerKey = 1,
    /// 32b pub key + 24B nonce + chachabox(bytes)
    ClientInfo = 2,
    /// 24B nonce + chachabox(bytes)
    ServerInfo = 3,
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
    /// Like [`FrameType::PeerGone`], but for other members of the DERP region
    /// when they're meshed up together
    ///
    /// 32B pub key of peer that's connected
    PeerPresent = 9,
    /// How one DERP node in a regional mesh subscribes to the others in the region.
    ///
    /// There's no payload. If the sender doesn't have permission, the connection
    /// is closed. Otherwise, the client is initially flooded with
    /// [`FrameType::PeerPresent`] for all connected nodes, and then a stream of
    /// [`FrameType::PeerPresent`] & [`FrameType::PeerGone`] has peers connect and disconnect.
    WatchConns = 10,
    /// A priviledged frame type (requires the mesh key for now) that closes
    /// the provided peer's connection. (To be used for cluster load balancing
    /// purposes, when clients end up on a non-ideal node)
    ///
    /// 32B pub key of peer close.
    ClosePeer = 11,
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
    /// Handled on the `[derp::Client]`, but currently never sent on the `[derp::Server]`
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
    shared_secret: &SharedSecret,
    client_public_key: &PublicKey,
    client_info: &ClientInfo,
) -> anyhow::Result<()> {
    let mut msg = postcard::to_stdvec(client_info)?;
    shared_secret.seal(&mut msg);
    writer
        .send(Frame::ClientInfo {
            client_public_key: *client_public_key,
            encrypted_message: msg.into(),
        })
        .await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the `FrameType::ClientInfo` frame from the client (its proof of identity)
/// upon it's initial connection.
pub(super) async fn recv_client_key<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
    secret_key: SecretKey,
    stream: S,
) -> anyhow::Result<(PublicKey, ClientInfo, SharedSecret)> {
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
        encrypted_message,
    } = buf
    {
        let mut encrypted_message = encrypted_message.to_vec();
        let shared_secret = secret_key.shared(&client_public_key);
        shared_secret
            .open(&mut encrypted_message)
            .context("shared secret")?;
        let info: ClientInfo =
            postcard::from_bytes(&encrypted_message).context("deserialization")?;
        Ok((client_public_key, info, shared_secret))
    } else {
        anyhow::bail!("expected FrameType::ClientInfo");
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // TODO: reevaluate
pub(crate) enum Frame {
    ServerKey {
        key: PublicKey,
    },
    ClientInfo {
        client_public_key: PublicKey,
        encrypted_message: Bytes,
    },
    ServerInfo {
        encrypted_message: Bytes,
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
    PeerPresent {
        peer: PublicKey,
    },
    WatchConns,
    ClosePeer {
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
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: Bytes,
    },
}

impl Frame {
    pub(super) fn typ(&self) -> FrameType {
        match self {
            Frame::ServerKey { .. } => FrameType::ServerKey,
            Frame::ClientInfo { .. } => FrameType::ClientInfo,
            Frame::ServerInfo { .. } => FrameType::ServerInfo,
            Frame::SendPacket { .. } => FrameType::SendPacket,
            Frame::RecvPacket { .. } => FrameType::RecvPacket,
            Frame::KeepAlive => FrameType::KeepAlive,
            Frame::NotePreferred { .. } => FrameType::NotePreferred,
            Frame::PeerGone { .. } => FrameType::PeerGone,
            Frame::PeerPresent { .. } => FrameType::PeerPresent,
            Frame::WatchConns => FrameType::WatchConns,
            Frame::ClosePeer { .. } => FrameType::ClosePeer,
            Frame::Ping { .. } => FrameType::Ping,
            Frame::Pong { .. } => FrameType::Pong,
            Frame::Health { .. } => FrameType::Health,
            Frame::Restarting { .. } => FrameType::Restarting,
            Frame::ForwardPacket { .. } => FrameType::ForwardPacket,
        }
    }

    /// Serialized length (without the frame header)
    pub(super) fn len(&self) -> usize {
        match self {
            Frame::ServerKey { .. } => MAGIC.as_bytes().len() + PUBLIC_KEY_LENGTH,
            Frame::ClientInfo {
                client_public_key: _,
                encrypted_message,
            } => PUBLIC_KEY_LENGTH + encrypted_message.len(),
            Frame::ServerInfo { encrypted_message } => encrypted_message.len(),
            Frame::SendPacket { dst_key: _, packet } => PUBLIC_KEY_LENGTH + packet.len(),
            Frame::RecvPacket {
                src_key: _,
                content,
            } => PUBLIC_KEY_LENGTH + content.len(),
            Frame::KeepAlive => 0,
            Frame::NotePreferred { .. } => 1,
            Frame::PeerGone { .. } => PUBLIC_KEY_LENGTH,
            Frame::PeerPresent { .. } => PUBLIC_KEY_LENGTH,
            Frame::WatchConns => 0,
            Frame::ClosePeer { .. } => PUBLIC_KEY_LENGTH,
            Frame::Ping { .. } => 8,
            Frame::Pong { .. } => 8,
            Frame::Health { problem } => problem.len(),
            Frame::Restarting { .. } => 4 + 4,
            Frame::ForwardPacket {
                src_key: _,
                dst_key: _,
                packet,
            } => PUBLIC_KEY_LENGTH * 2 + packet.len(),
        }
    }

    /// Writes it self to the given buffer.
    fn write_to(&self, dst: &mut BytesMut) {
        match self {
            Frame::ServerKey { key } => {
                dst.put(MAGIC.as_bytes());
                dst.put(key.as_ref());
            }
            Frame::ClientInfo {
                client_public_key,
                encrypted_message,
            } => {
                dst.put(client_public_key.as_ref());
                dst.put(&encrypted_message[..]);
            }
            Frame::ServerInfo { encrypted_message } => {
                dst.put(&encrypted_message[..]);
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
            Frame::PeerPresent { peer } => {
                dst.put(peer.as_ref());
            }
            Frame::WatchConns => {}
            Frame::ClosePeer { peer } => {
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
            Frame::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                dst.put(src_key.as_ref());
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
            }
        }
    }

    fn from_bytes(frame_type: FrameType, content: Bytes) -> anyhow::Result<Self> {
        let res = match frame_type {
            FrameType::ServerKey => {
                ensure!(
                    content.len() == 32 + MAGIC.as_bytes().len(),
                    "invalid server key frame length"
                );
                ensure!(
                    &content[..MAGIC.as_bytes().len()] == MAGIC.as_bytes(),
                    "invalid server key frame magic"
                );
                let key = PublicKey::try_from(&content[MAGIC.as_bytes().len()..])?;
                Self::ServerKey { key }
            }
            FrameType::ClientInfo => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid client info frame length: {}",
                    content.len()
                );
                let client_public_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let encrypted_message = content.slice(PUBLIC_KEY_LENGTH..);
                Self::ClientInfo {
                    client_public_key,
                    encrypted_message,
                }
            }
            FrameType::ServerInfo => Self::ServerInfo {
                encrypted_message: content,
            },
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
            FrameType::PeerPresent => {
                anyhow::ensure!(
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid peer present frame length"
                );
                let peer = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                Self::PeerPresent { peer }
            }
            FrameType::WatchConns => {
                anyhow::ensure!(content.is_empty(), "invalid watch conns frame length");
                Self::WatchConns
            }
            FrameType::ClosePeer => {
                anyhow::ensure!(
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid close peer frame length"
                );
                let peer = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                Self::ClosePeer { peer }
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
                let reconnect_in = u32::from_be_bytes(content[..4].try_into().unwrap());
                let try_for = u32::from_be_bytes(content[4..].try_into().unwrap());
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            FrameType::ForwardPacket => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH * 2,
                    "invalid forward packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PUBLIC_KEY_LENGTH * 2;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE - PUBLIC_KEY_LENGTH * 2,
                    "data packet longer ({packet_len}) than {MAX_PACKET_SIZE}"
                );

                let src_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let dst_key =
                    PublicKey::try_from(&content[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2])?;
                let packet = content.slice(64..);
                Self::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
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

        // Can't use the `get_` Buf api, as that advances the buffer
        let frame_type: FrameType = src[0].into();
        let frame_len = u32::from_be_bytes(src[1..5].try_into().unwrap()) as usize;

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

    use crate::derp::codec::DerpCodec;

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

        let server_key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
            mesh_key: Some([1u8; 32]),
            can_ack_pings: true,
            is_prober: true,
        };
        println!("client_key pub {:?}", client_key.public());
        let shared_secret = client_key.shared(&server_key.public());
        send_client_key(
            &mut writer,
            &shared_secret,
            &client_key.public(),
            &client_info,
        )
        .await?;
        let (client_pub_key, got_client_info, _) = recv_client_key(server_key, &mut reader).await?;
        assert_eq!(client_key.public(), client_pub_key);
        assert_eq!(client_info, got_client_info);
        Ok(())
    }
}

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
        let server_info =
            data(0).prop_map(|encrypted_message| Frame::ServerInfo { encrypted_message });
        let send_packet =
            (key(), data(32)).prop_map(|(dst_key, packet)| Frame::SendPacket { dst_key, packet });
        let recv_packet =
            (key(), data(32)).prop_map(|(src_key, content)| Frame::RecvPacket { src_key, content });
        let keep_alive = Just(Frame::KeepAlive);
        let note_preferred = any::<bool>().prop_map(|preferred| Frame::NotePreferred { preferred });
        let peer_gone = key().prop_map(|peer| Frame::PeerGone { peer });
        let peer_present = key().prop_map(|peer| Frame::PeerPresent { peer });
        let watch_conns = Just(Frame::WatchConns);
        let close_peer = key().prop_map(|peer| Frame::ClosePeer { peer });
        let ping = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Ping { data });
        let pong = prop::array::uniform8(any::<u8>()).prop_map(|data| Frame::Pong { data });
        let health = data(0).prop_map(|problem| Frame::Health { problem });
        let restarting =
            (any::<u32>(), any::<u32>()).prop_map(|(reconnect_in, try_for)| Frame::Restarting {
                reconnect_in,
                try_for,
            });
        let forward_packet =
            (key(), key(), data(64)).prop_map(|(src_key, dst_key, packet)| Frame::ForwardPacket {
                src_key,
                dst_key,
                packet,
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
            peer_present,
            watch_conns,
            close_peer,
            ping,
            pong,
            health,
            restarting,
            forward_packet,
        ]
    }

    proptest! {

        /// this test is slow in debug mode, so only run it in release mode
        #[test]
        fn frame_roundtrip(frame in frame()) {
            let mut buf = BytesMut::new();
            DerpCodec.encode(frame.clone(), &mut buf).unwrap();
            let decoded = DerpCodec.decode(&mut buf).unwrap().unwrap();
            prop_assert_eq!(frame, decoded);
        }
    }
}
