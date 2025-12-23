//! Common types between the [`super::handshake`] and [`super::relay`] protocols.
//!
//! Hosts the [`FrameType`] enum to make sure we're not accidentally reusing frame type
//! integers for different frames.

use bytes::{Buf, BufMut};
use n0_error::{e, stack_error};
use quinn_proto::{
    VarInt,
    coding::{Decodable, Encodable, UnexpectedEnd},
};

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
    /// 32B dest pub key + ECN bytes + one datagram's content
    ClientToRelayDatagram = 4,
    /// 32B dest pub key + ECN byte + segment size u16 + datagrams contents
    ClientToRelayDatagramBatch = 5,
    /// 32B src pub key + ECN bytes + one datagram's content
    RelayToClientDatagram = 6,
    /// 32B src pub key + ECN byte + segment size u16 + datagrams contents
    RelayToClientDatagramBatch = 7,
    /// Sent from server to client to signal that a previous sender is no longer connected.
    ///
    /// That is, if A sent to B, and then if A disconnects, the server sends `FrameType::PeerGone`
    /// to B so B can forget that a reverse path exists on that connection to get back to A
    ///
    /// 32B pub key of peer that's gone
    EndpointGone = 8,
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

#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum FrameTypeError {
    #[error("not enough bytes to parse frame type")]
    UnexpectedEnd {
        #[error(std_err)]
        source: UnexpectedEnd,
    },
    #[error("frame type unknown")]
    UnknownFrameType { tag: VarInt },
}

impl FrameType {
    /// Writes the frame type to the buffer (as a QUIC-encoded varint).
    pub(crate) fn write_to<O: BufMut>(&self, mut dst: O) -> O {
        VarInt::from(*self).encode(&mut dst);
        dst
    }

    /// Returns the amount of bytes that [`Self::write_to`] would write.
    pub(crate) fn encoded_len(&self) -> usize {
        // Copied implementation from `VarInt::size`
        let x: u32 = (*self).into();
        if x < 2u32.pow(6) {
            1 // this will pretty much always be the case
        } else if x < 2u32.pow(14) {
            2
        } else if x < 2u32.pow(30) {
            4
        } else {
            unreachable!("Impossible FrameType primitive representation")
        }
    }

    /// Parses the frame type (as a QUIC-encoded varint) from the first couple of bytes given
    /// and returns the frame type and the rest.
    pub(crate) fn from_bytes(buf: &mut impl Buf) -> Result<Self, FrameTypeError> {
        let tag = VarInt::decode(buf).map_err(|err| e!(FrameTypeError::UnexpectedEnd, err))?;
        let tag_u32 = u32::try_from(u64::from(tag))
            .map_err(|_| e!(FrameTypeError::UnknownFrameType { tag }))?;
        let frame_type = FrameType::try_from(tag_u32)
            .map_err(|_| e!(FrameTypeError::UnknownFrameType { tag }))?;
        Ok(frame_type)
    }
}

impl From<FrameType> for VarInt {
    fn from(value: FrameType) -> Self {
        (value as u32).into()
    }
}
