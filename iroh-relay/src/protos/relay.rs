//! TODO(matheus23) docs

use bytes::{BufMut, Bytes};
use quinn_proto::{coding::Codec, VarInt};

/// Possible frame types during handshaking
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
// needs to be pub due to being exposed in error types
pub enum FrameType {
    /// The client frame type for the client challenge request
    ClientRequestChallenge = 1,
    /// The server frame type for the challenge response
    ServerChallenge = 2,
    /// The client frame type for the authentication frame
    ClientAuth = 3,
    /// The server frame type for authentication confirmation
    ServerConfirmsAuth = 4,
    /// The server frame type for authentication denial
    ServerDeniesAuth = 5,
    /// 32B dest pub key + packet bytes TODO(matheus23): Fix docs
    SendPacket = 10,
    /// v0/1 packet bytes, v2: 32B src pub key + packet bytes TODO(matheus23): Fix docs
    RecvPacket = 11,
    /// no payload, no-op (to be replaced with ping/pong)
    KeepAlive = 12,
    /// Sent from server to client to signal that a previous sender is no longer connected.
    ///
    /// That is, if A sent to B, and then if A disconnects, the server sends `FrameType::PeerGone`
    /// to B so B can forget that a reverse path exists on that connection to get back to A
    ///
    /// 32B pub key of peer that's gone
    NodeGone = 14,
    /// Frames 9-11 concern meshing, which we have eliminated from our version of the protocol.
    /// Messages with these frames will be ignored.
    /// 8 byte ping payload, to be echoed back in FrameType::Pong
    Ping = 15,
    /// 8 byte payload, the contents of ping being replied to
    Pong = 16,
    /// Sent from server to client to tell the client if their connection is
    /// unhealthy somehow.
    Health = 17,

    /// Sent from server to client for the server to declare that it's restarting.
    /// Payload is two big endian u32 durations in milliseconds: when to reconnect,
    /// and how long to try total.
    ///
    /// Handled on the `[relay::Client]`, but currently never sent on the `[relay::Server]`
    Restarting = 18,
    /// The frame type was unknown.
    ///
    /// This frame is the result of parsing any future frame types that this implementation
    /// does not yet understand.
    #[num_enum(default)]
    Unknown,
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FrameType {
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        VarInt::from(*self).encode(&mut dst);
        dst
    }

    // TODO(matheus23): Consolidate errors between handshake.rs and relay.rs
    // Perhaps a shared error type `FramingError`?
    pub(crate) fn from_bytes(bytes: Bytes) -> Option<(Self, Bytes)> {
        let mut cursor = std::io::Cursor::new(&bytes);
        let tag = VarInt::decode(&mut cursor).ok()?;
        let tag_u32 = u32::try_from(u64::from(tag)).ok()?;
        let frame_type = FrameType::from(tag_u32);
        let content = bytes.slice(cursor.position() as usize..);
        Some((frame_type, content))
    }
}

impl From<FrameType> for VarInt {
    fn from(value: FrameType) -> Self {
        (value as u32).into()
    }
}
