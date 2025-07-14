//! Common types between the [`super::handshake`] and [`super::relay`] protocols.
//!
//! Hosts the [`FrameType`] enum to make sure we're not accidentally reusing frame type
//! integers for different frames.

use bytes::{Buf, BufMut};
use nested_enum_utils::common_fields;
use quinn_proto::{coding::Codec, VarInt};
use snafu::{Backtrace, OptionExt, Snafu};

/// Possible frame types during handshaking
#[repr(u32)]
#[derive(
    Copy, Clone, PartialEq, Eq, Debug, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
// needs to be pub due to being exposed in error types
pub enum FrameType {
    /// The server frame type for the challenge response
    ServerChallenge = 0,
    /// The client frame type for the authentication frame
    ClientAuth = 1,
    /// The server frame type for authentication confirmation
    ServerConfirmsAuth = 2,
    /// The server frame type for authentication denial
    ServerDeniesAuth = 3,
    /// 32B dest pub key + ECN byte + segment size u16 + datagrams contents
    SendPacket = 4,
    /// 32B src pub key + ECN byte + segment size u16 + datagrams contents
    RecvPacket = 6,
    /// Sent from server to client to signal that a previous sender is no longer connected.
    ///
    /// That is, if A sent to B, and then if A disconnects, the server sends `FrameType::PeerGone`
    /// to B so B can forget that a reverse path exists on that connection to get back to A
    ///
    /// 32B pub key of peer that's gone
    NodeGone = 8,
    /// Messages with these frames will be ignored.
    /// 8 byte ping payload, to be echoed back in FrameType::Pong
    Ping = 9,
    /// 8 byte payload, the contents of ping being replied to
    Pong = 10,
    /// Sent from server to client to tell the client if their connection is unhealthy somehow.
    /// Contains only UTF-8 bytes.
    Health = 11,

    /// Sent from server to client for the server to declare that it's restarting.
    /// Payload is two big endian u32 durations in milliseconds: when to reconnect,
    /// and how long to try total.
    Restarting = 12,
}

#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum FrameTypeError {
    #[snafu(display("not enough bytes to parse frame type"))]
    UnexpectedEnd {},
    #[snafu(display("frame type unknown"))]
    UnknownFrameType { tag: VarInt },
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FrameType {
    /// Writes the frame type to the buffer (as a QUIC-encoded varint).
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        VarInt::from(*self).encode(&mut dst);
        dst
    }

    /// Parses the frame type (as a QUIC-encoded varint) from the first couple of bytes given
    /// and returns the frame type and the rest.
    pub(crate) fn from_bytes(buf: &mut impl Buf) -> Result<Self, FrameTypeError> {
        let tag = VarInt::decode(buf).ok().context(UnexpectedEndSnafu)?;
        let tag_u32 = u32::try_from(u64::from(tag))
            .ok()
            .context(UnknownFrameTypeSnafu { tag })?;
        let frame_type = FrameType::try_from(tag_u32)
            .ok()
            .context(UnknownFrameTypeSnafu { tag })?;
        Ok(frame_type)
    }
}

impl From<FrameType> for VarInt {
    fn from(value: FrameType) -> Self {
        (value as u32).into()
    }
}
