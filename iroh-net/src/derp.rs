//! Package derp implements the Designated Encrypted Relay for Packets (DERP)
//! protocol written by Tailscale.
//
//! DERP routes packets to clients using curve25519 keys as addresses.
//
//! DERP is used by proxy encrypted QUIC packets through the DERP servers when
//! a direct path cannot be found or opened. DERP is a last resort. Both side
//! between very aggressive NATs, firewalls, no IPv6, etc? Well, DERP.
//! Based on tailscale/derp/derp.go

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub(crate) mod client;
pub(crate) mod client_conn;
pub(crate) mod clients;
pub mod http;
mod map;
mod metrics;
pub(crate) mod server;
pub(crate) mod types;

pub use self::client::{Client as DerpClient, ReceivedMessage};
pub use self::http::Client as HttpClient;
pub use self::map::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
pub use self::metrics::Metrics;
pub use self::server::{
    ClientConnHandler, MaybeTlsStream as MaybeTlsStreamServer, PacketForwarderHandler, Server,
};
pub use self::types::{MeshKey, PacketForwarder};

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::key::{Keypair, PublicKey, SharedSecret, PUBLIC_KEY_LENGTH};
use types::ClientInfo;

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

const KEEP_ALIVE: Duration = Duration::from_secs(60);
// TODO: what should this be?
const SERVER_CHANNEL_SIZE: usize = 1024 * 100;
/// The number of packets buffered for sending per client
const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 512; //32;

/// ProtocolVersion is bumped whenever there's a wire-incompatiable change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FrameType::RecvPacket at beginning
const PROTOCOL_VERSION: usize = 2;

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
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameType {
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
    Unknown = 255,
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<u8> for FrameType {
    fn from(value: u8) -> Self {
        match value {
            1 => FrameType::ServerKey,
            2 => FrameType::ClientInfo,
            3 => FrameType::ServerInfo,
            4 => FrameType::SendPacket,
            5 => FrameType::RecvPacket,
            6 => FrameType::KeepAlive,
            7 => FrameType::NotePreferred,
            8 => FrameType::PeerGone,
            9 => FrameType::PeerPresent,
            10 => FrameType::WatchConns,
            11 => FrameType::ClosePeer,
            12 => FrameType::Ping,
            13 => FrameType::Pong,
            14 => FrameType::Health,
            15 => FrameType::Restarting,
            16 => FrameType::ForwardPacket,
            _ => FrameType::Unknown,
        }
    }
}

impl From<FrameType> for u8 {
    fn from(value: FrameType) -> Self {
        value as u8
    }
}

async fn read_frame_header(mut reader: impl AsyncRead + Unpin) -> Result<(FrameType, usize)> {
    let frame_type = reader.read_u8().await?;
    let frame_len = reader.read_u32().await?;
    Ok((frame_type.into(), frame_len.try_into()?))
}

/// AsyncReads a frame header and then reads a `frame_len` of bytes into `buf`.
/// It resizes the `buf` to the expected `frame_len`.
///
/// If the frame header length is greater than `max_size`, `read_frame` returns
/// an error after reading the frame header.
///
/// Also errors if we receive EOF before the end of the expected length of the frame.
async fn read_frame(
    mut reader: impl AsyncRead + Unpin,
    max_size: usize,
    buf: &mut BytesMut,
) -> Result<(FrameType, usize)> {
    let (frame_type, frame_len) = read_frame_header(&mut reader)
        .await
        .context("frame header")?;
    debug!("read frame header: {:?} - {:?}", frame_type, frame_len);
    ensure!(
        frame_len < max_size,
        "frame header size {frame_len} exceeds reader limit of {max_size}"
    );
    buf.resize(frame_len, 0u8);
    reader.read_exact(buf).await.context("read exact")?;
    Ok((frame_type, frame_len))
}

async fn read_frame_timeout(
    mut reader: impl AsyncRead + Unpin,
    max_size: usize,
    buf: &mut BytesMut,
    timeout: Option<Duration>,
) -> Result<(FrameType, usize)> {
    if let Some(duration) = timeout {
        let (frame_type, frame_len) =
            tokio::time::timeout(duration, read_frame(&mut reader, max_size, buf))
                .await
                .context("timeout")??;
        Ok((frame_type, frame_len))
    } else {
        read_frame(&mut reader, max_size, buf).await
    }
}

async fn write_frame_header(
    mut writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    frame_len: usize,
) -> Result<()> {
    let frame_len = u32::try_from(frame_len)?;
    writer.write_u8(frame_type.into()).await?;
    writer.write_u32(frame_len).await?;
    Ok(())
}

/// AsyncWrites a complete frame. Does not flush.
async fn write_frame<'a>(
    mut writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    bytes: &[&[u8]],
) -> Result<()> {
    let bytes_len: usize = bytes.iter().map(|b| b.len()).sum();
    ensure!(
        bytes_len <= MAX_FRAME_SIZE,
        "unreasonably large frame write"
    );
    write_frame_header(&mut writer, frame_type, bytes_len).await?;
    for b in bytes {
        writer.write_all(b).await?;
    }
    Ok(())
}

/// AsyncWrites a complete frame, errors if it is unable to write within the given `timeout`.
/// Ignores the timeout if `timeout.is_zero()`
///
/// Does not flush.
async fn write_frame_timeout(
    writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    bytes: &[&[u8]],
    timeout: Option<Duration>,
) -> Result<()> {
    if let Some(duration) = timeout {
        tokio::time::timeout(duration, write_frame(writer, frame_type, bytes)).await??;
        Ok(())
    } else {
        write_frame(writer, frame_type, bytes).await
    }
}

/// Writes a `FrameType::ClientInfo`, including the client's [`PublicKey`],
/// and the client's [`ClientInfo`], sealed using the server's [`PublicKey`].
///
/// Flushes after writing.
pub(crate) async fn send_client_key<W: AsyncWrite + Unpin>(
    mut writer: W,
    shared_secret: &SharedSecret,
    client_public_key: &PublicKey,
    client_info: &ClientInfo,
) -> Result<()> {
    let mut msg = postcard::to_stdvec(client_info)?;
    shared_secret.seal(&mut msg);
    write_frame(
        &mut writer,
        FrameType::ClientInfo,
        &[client_public_key.as_bytes(), &msg],
    )
    .await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the `FrameType::ClientInfo` frame from the client (its proof of identity)
/// upon it's initial connection.
async fn recv_client_key<R: AsyncRead + Unpin>(
    secret_key: Keypair,
    mut reader: R,
) -> Result<(PublicKey, ClientInfo, SharedSecret)> {
    let mut buf = BytesMut::new();
    // the client is untrusted at this point, limit the input size even smaller than our usual
    // maximum frame size, and give a timeout
    let (frame_type, _) = read_frame_timeout(
        &mut reader,
        256 * 1024,
        &mut buf,
        Some(Duration::from_secs(10)),
    )
    .await
    .context("read frame")?;
    ensure!(
        frame_type == FrameType::ClientInfo,
        "expected FrameType::ClientInfo frame got {frame_type}"
    );
    let key = PublicKey::try_from(&buf[..PUBLIC_KEY_LENGTH]).context("public key")?;
    let mut msg = buf[PUBLIC_KEY_LENGTH..].to_vec();
    let shared_secret = secret_key.shared(&key);
    shared_secret.open(&mut msg).context("shared secret")?;
    let info: ClientInfo = postcard::from_bytes(&msg).context("deserialization")?;
    Ok((key, info, shared_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_read_write() -> Result<()> {
        let (mut reader, mut writer) = tokio::io::duplex(1024);

        write_frame_header(&mut writer, FrameType::PeerGone, 301).await?;
        let (frame_type, frame_len) = read_frame_header(&mut reader).await?;
        assert_eq!(frame_type, FrameType::PeerGone);
        assert_eq!(frame_len, 301);

        let expect_buf = b"hello world!";
        write_frame(&mut writer, FrameType::Health, &[expect_buf]).await?;
        writer.flush().await?;
        println!("{:?}", reader);
        let mut got_buf = BytesMut::new();
        let (frame_type, frame_len) = read_frame(&mut reader, 1024, &mut got_buf).await?;
        assert_eq!(FrameType::Health, frame_type);
        assert_eq!(expect_buf.len(), frame_len);
        assert_eq!(expect_buf.as_slice(), &got_buf);
        Ok(())
    }

    #[tokio::test]
    async fn test_send_recv_client_key() -> Result<()> {
        let (mut reader, mut writer) = tokio::io::duplex(1024);
        let server_key = Keypair::generate();
        let client_key = Keypair::generate();
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
