//! Package derp implements the Designated Encrypted Relay for Packets (DERP)
//! protocol.
//
//! DERP routes packets to clients using curve25519 keys as addresses.
//
//! DERP is used by Tailscale nodes to proxy encrypted WireGuard
//! packets through the Tailscale cloud servers when a direct path
//! cannot be found or opened. DERP is a last resort. Both side
//! between very aggressive NATs, firewalls, no IPv6, etc? Well, DERP.
//! Based on tailscale/derp/derp.go

pub(crate) mod client;
pub(crate) mod client_conn;
pub(crate) mod clients;
pub mod http;
mod map;
mod server;
pub(crate) mod types;

pub use self::client::ReceivedMessage;
pub use self::map::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
pub use self::server::Server;

use std::time::Duration;

use anyhow::{ensure, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The maximum size of a packet sent over DERP.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
const MAX_PACKET_SIZE: usize = 64 * 1024;

const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// The DERP magic number, sent in the FRAME_SERVER_KEY frame
/// upon initial connection
///
/// 8 bytes: 0x44 45 52 50 f0 9f 94 91
const MAGIC: &str = "DERP🔑";

const NONCE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 1 + 4; // FrameType byte + 4 byte length
const KEY_LEN: usize = 32;
const MAX_INFO_LEN: usize = 1024 * 1024;
const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// ProtocolVersion is bumped whenever there's a wire-incompatiable change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FRAME_RECV_PACKET at beginning
const PROTOCOL_VERSION: usize = 2;

/// The one byte frame type at the beginning of the frame
/// header. The second field is a big-endian u32 describing the
/// length of the remaining frame (not including the initial 5 bytes)
/// TODO: this should probably be an enum
type FrameType = u8;

///
/// Protocol flow:
///
/// Login:
///  * client connects
///  * server sends FRAME_SERVER_KEY
///  * client sends FRAME_CLIENT_INFO
///  * server sends FRAME_SERVER_INFO
///
///  Steady state:
///  * server occasionally sends FRAME_KEEP_ALIVE (or FRAME_PING)
///  * client responds to any FRAME_PING with a FRAME_PONG
///  * clients sends FRAME_SEND_PACKET
///  * server then sends FRAME_RECV_PACKET to recipient
///

/// 8B magic + 32B public key + (0+ bytes future use)
const FRAME_SERVER_KEY: FrameType = 0x01;
/// 32b pub key + 24B nonce + naclbox(json)
const FRAME_CLIENT_INFO: FrameType = 0x02;
/// 24B nonce + naclbox(json)
const FRAME_SERVER_INFO: FrameType = 0x03;
/// 32B dest pub key + packet bytes
const FRAME_SEND_PACKET: FrameType = 0x04;
/// 32B src pub key + 32B dst pub key + packet bytes
const FRAME_FORWARD_PACKET: FrameType = 0x0a;
/// v0/1 packet bytes, v2: 32B src pub key + packet bytes
const FRAME_RECV_PACKET: FrameType = 0x05;
/// no payload, no-op (to be replaced with ping/pong)
const FRAME_KEEP_ALIVE: FrameType = 0x06;
/// 1 byte payload: 0x01 or 0x00 for whether this is client's home node
const FRAME_NOTE_PREFERRED: FrameType = 0x07;
/// indicates this is the client's home node
const PREFERRED: u8 = 1u8;
/// indicates this is NOT the client's home node
const NOT_PREFERRED: u8 = 0u8;

/// Sent from server to client to signal that a previous sender is no longer connected.
///
/// That is, if A sent to B, and then if A disconnects, the server sends `FRAME_PEER_GONE`
/// to B so B can forget that a reverse path exists on that connection to get back to A
///
/// 32B pub key of peer that's gone
const FRAME_PEER_GONE: FrameType = 0x08;

/// Like [`FRAME_PEER_GONE`], but for other members of the DERP region
/// when they're meshed up together
///
/// 32B pub key of peer that's connected
const FRAME_PEER_PRESENT: FrameType = 0x09;

/// How one DERP node in a regional mesh subscribes to the others in the region.
///
/// There's no payload. If the sender doesn't have permission, the connection
/// is closed. Otherwise, the client is initially flooded with
/// [`FRAME_PEER_PRESENT`] for all connected nodes, and then a stream of
/// [`FRAME_PEER_PRESENT`] & [`FRAME_PEER_GONE`] has peers connect and disconnect.
const FRAME_WATCH_CONNS: FrameType = 0x10;

/// A priviledged frame type (requires the mesh key for now) that closes
/// the provided peer's connection. (To be used for cluster load balancing
/// purposes, when clients end up on a non-ideal node)
///
/// 32B pub key of peer close.
const FRAME_CLOSE_PEER: FrameType = 0x11;

/// 8 byte ping payload, to be echoed back in FRAME_PONG
const FRAME_PING: FrameType = 0x12;
/// 8 byte payload, the contents of ping being replied to
const FRAME_PONG: FrameType = 0x13;

/// Sent from server to client to tell the client if their connection is
/// unhealthy somehow. Currently the only unhealthy state is whether the
/// connection is detected as a duplicate.
/// The entire frame body is the text of the error message. An empty message
/// clears the error state.
const FRAME_HEALTH: FrameType = 0x14;

/// Sent from server to client for the server to declare that it's restarting.
/// Payload is two big endian u32 durations in milliseconds: when to reconnect,
/// and how long to try total. See [`SERVER_RESTARTING_MESSAGE`] for
/// more details on how the client should interpret them.
const FRAME_RESTARTING: FrameType = 0x15;

async fn read_frame_header(mut reader: impl AsyncRead + Unpin) -> Result<(FrameType, usize)> {
    let frame_type = reader.read_u8().await?;
    let frame_len = reader.read_u32().await?;
    Ok((frame_type, frame_len.try_into()?))
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
    mut buf: &mut BytesMut,
) -> Result<(FrameType, usize)> {
    let (frame_type, frame_len) = read_frame_header(&mut reader).await?;
    ensure!(
        frame_len < max_size,
        "frame header size {frame_len} exceeds reader limit of {max_size}"
    );
    buf.resize(frame_len, 0u8);
    reader.read_exact(&mut buf).await?;
    Ok((frame_type, frame_len))
}

async fn write_frame_header(
    mut writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    frame_len: usize,
) -> Result<()> {
    let frame_len = u32::try_from(frame_len)?;
    writer.write_u8(frame_type).await?;
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
        write_frame(writer, frame_type, &bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_read_write() -> Result<()> {
        let (mut reader, mut writer) = tokio::io::duplex(1024);

        write_frame_header(&mut writer, FRAME_PEER_GONE, 301).await?;
        let (frame_type, frame_len) = read_frame_header(&mut reader).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);
        assert_eq!(frame_len, 301);

        let expect_buf = b"hello world!";
        write_frame(&mut writer, FRAME_HEALTH, &[expect_buf]).await?;
        writer.flush().await;
        println!("{:?}", reader);
        let mut got_buf = BytesMut::new();
        let (frame_type, frame_len) = read_frame(&mut reader, 1024, &mut got_buf).await?;
        assert_eq!(FRAME_HEALTH, frame_type);
        assert_eq!(expect_buf.len(), frame_len);
        assert_eq!(expect_buf.as_slice(), &got_buf);
        Ok(())
    }
}
