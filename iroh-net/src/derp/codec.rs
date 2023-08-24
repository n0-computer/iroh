use std::time::Duration;

use anyhow::{bail, ensure, Context};
use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

use super::types::ClientInfo;
use crate::key::{PublicKey, SecretKey, SharedSecret};

/// The maximum size of a packet sent over DERP.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

const MAX_FRAME_SIZE: usize = 1024 * 1024;

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

/// The one byte frame type at the beginning of the frame
/// header. The second field is a big-endian u32 describing the
/// length of the remaining frame (not including the initial 5 bytes)
#[derive(Debug, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
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
pub(super) async fn write_frame<S: Sink<Frame, Error = anyhow::Error> + Unpin>(
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
pub(crate) async fn send_client_key<S: Sink<Frame, Error = anyhow::Error> + Unpin>(
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

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Serialized length
    pub(super) fn len(&self) -> usize {
        postcard::serialize_with_flavor(self, postcard::ser_flavors::Size::default())
            .expect("should serialize")
    }
}

impl Decoder for DerpCodec {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // ensure we never attempt to read more than MAX_FRAME_SIZE
        let max_len = std::cmp::min(src.len(), MAX_FRAME_SIZE);

        match postcard::take_from_bytes(&src[..max_len]) {
            Ok((frame, rest)) => {
                // how many bytes we consumed
                let consumed = max_len - rest.len();
                src.advance(consumed);
                Ok(Some(frame))
            }
            Err(err) => match err {
                postcard::Error::DeserializeUnexpectedEnd => {
                    // Frame too large
                    if max_len == MAX_FRAME_SIZE {
                        bail!("attempted to read frame larger than MAX_FRAME_SIZE");
                    }
                    // We haven't read enough yet
                    Ok(None)
                }
                _ => Err(err.into()),
            },
        }
    }
}

impl Encoder<Frame> for DerpCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len: usize = frame.len();
        ensure!(
            frame_len < MAX_FRAME_SIZE,
            "frame of length {} is too large.",
            frame_len
        );

        // Need to actually resize, as otherwise the slice is too short
        dst.resize(frame_len, 0u8);
        let written = postcard::to_slice(&frame, dst)?;
        debug_assert_eq!(written.len(), frame_len);

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
