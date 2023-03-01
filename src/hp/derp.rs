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

mod client;
pub mod http;
mod map;

pub use client::ReceivedMessage;
pub use map::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

use std::time::Duration;

use anyhow::{bail, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The maximum size of a packet sent over DERP.
/// (This only includes the data bytes visible to magicsock, not
/// including its on-wire framing overhead)
const MAX_PACKET_SIZE: usize = 64 * 1024;

const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

/// The DERP magic number, sent in the FRAME_SERVER_KEY frame
/// upon initial connection
const MAGIC: &str = "DERP🔑";

const NONCE_LEN: u8 = 24;
const FRAME_HEADER_LEN: u8 = 1 + 4; // FrameType byte + 4 byte length
const KEY_LEN: u8 = 32;
const MAX_INFO_LEN: usize = 1024 * 1024;
const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// ProtocolVersion is bumped whenever there's a wire-incompatiable change.
///  - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
///  - version 2: received packets have src addrs in FRAME_RECV_PACKET at beginning
const PROTOCOL_VERSION: u8 = 2;

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

const FRAME_SERVER_KEY: FrameType = 0x01;
/// 8B magic + 32B public key + (0+ bytes future use)
const FRAME_CLIENT_INFO: FrameType = 0x02;
/// 32b pub key + 24B nonce + naclbox(json)
const FRAME_SERVER_INFO: FrameType = 0x03;
/// 24B nonce + naclbox(json)
const FRAME_SEND_PACKET: FrameType = 0x04;
/// 32B dest pub key + packet bytes
const FRAME_FORWARD_PACKET: FrameType = 0x0a;
/// 32B src pub key + 32B dst pub key + packet bytes
const FRAME_RECV_PACKET: FrameType = 0x05;
/// v0/1 packet bytes, v2: 32B src pub key + packet
/// bytes
const FRAME_KEEP_ALIVE: FrameType = 0x06;
/// no payload, no-op (to be replaced with ping/pong)
const FRAME_NOTE_PREFERRED: FrameType = 0x07;
/// 1 byte paylouad: 0x01 or 0x00 for whether this is
/// client's home node

/// Sent from server to client to signal that a previous sender
/// is no longer connected. That is, if A sent to B, and then if
/// A disconnects, the server sends `FRAME_PEER_GONE` to B so B can
/// forget that a reverse path exists on that connection to get back
/// to A
const FRAME_PEER_GONE: FrameType = 0x08; // 32B pub key of peer that's gone

/// Like [`FRAME_PEER_GONE`], but for other members of the DERP region
/// when they're meshed up together
const FRAME_PEER_PRESENT: FrameType = 0x09; // 32B pub key of peer that's connected

/// How one DERP node in a regional mesh subscribes to the others in the region.
/// There's no payload. If the sender doesn't have permission, the connection
/// is closed. Otherwise, the client is initially flooded with
/// [`FRAME_PEER_PRESENT`] for all connected nodes, and then a stream of
/// [`FRAME_PEER_PRESENT`] & [`FRAME_PEER_GONE`] has peers connect and disconnect.
const FRAME_WATCH_CONNS: FrameType = 0x10;

/// A priviledged frame type (requires the mesh key for now) that closes
/// the provided peer's connection. (To be used for cluster load balancing
/// purposes, when clients end up on a non-ideal node)
const FRAME_CLOSE_PEER: FrameType = 0x11;
/// 32B pub key of peer close.

const FRAME_PING: FrameType = 0x12;
/// 8 byte ping payload, to be echoed back in FRAME_PONG
const FRAME_PONG: FrameType = 0x13;
/// 8 byte payload, the contents of ping being replied to

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

async fn read_frame_type_header(
    reader: impl AsyncRead + Unpin,
    want_type: FrameType,
) -> Result<u32> {
    let (got_type, frame_len) = read_frame_header(reader).await?;
    if want_type != got_type {
        bail!("bad frame type {got_type:#04x}, want {want_type:#04x}");
    }
    Ok(frame_len)
}

async fn read_frame_header(mut reader: impl AsyncRead + Unpin) -> Result<(FrameType, u32)> {
    let frame_type = reader.read_u8().await?;
    let frame_len = reader.read_u32().await?;
    Ok((frame_type, frame_len))
}

/// AsyncReads a frame header and then reads its payload into `bytes` of
/// `frame_len`.
///
/// If the frame header length is greater than `max_size`, `read_frame` returns
/// an error after reading the frame header.
///
/// If the frame is less than `max_size` but greater than the `bytes.len()`,
/// `bytes.len()` bytes are read, and there is no error. The `frame_type` and `frame_len`
/// are returned as a tuple `(FrameType, u32)`. If the number of bytes read are less than
/// `frame_len`, we DO NOT ERROR.
async fn read_frame(
    mut reader: impl AsyncRead + Unpin,
    max_size: u32,
    mut bytes: BytesMut,
) -> Result<(FrameType, u32)> {
    let (frame_type, frame_len) = read_frame_header(&mut reader).await?;
    if frame_len > max_size {
        bail!("frame header size {frame_len} exceeds reader limit of {max_size}");
    }

    reader.read_exact(&mut bytes).await?;
    Ok((frame_type, frame_len))
}

async fn write_frame_header(
    mut writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    frame_len: u32,
) -> Result<()> {
    writer.write_u8(frame_type).await?;
    writer.write_u32(frame_len).await?;
    Ok(())
}

/// AsyncWrites a complete frame & flushes it.
async fn write_frame(
    mut writer: impl AsyncWrite + Unpin,
    frame_type: FrameType,
    bytes: BytesMut,
) -> Result<()> {
    if bytes.len() > MAX_FRAME_SIZE {
        bail!("unreasonably large frame write");
    }
    let frame_len = u32::try_from(bytes.len())?;
    write_frame_header(&mut writer, frame_type, frame_len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
