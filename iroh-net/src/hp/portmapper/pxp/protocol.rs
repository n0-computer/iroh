//! Definitions and utilities to interact with a NAT-PMP/PCP server.

use std::net::{Ipv4Addr, Ipv6Addr};

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6887#section-19>

/// Port to use when acting as a client. This is the one we bind to.
pub const CLIENT_PORT: u16 = 5350;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Size of a [`Request`] sent by this client, in bytes.
// NOTE: 1byte for the version +
//       1byte for the opcode +
//       2bytes reserved +
//       4bytes for the lifetime +
//       16bytes for the client's ip
const REQ_SIZE: usize = 1 + 1 + 2 + 4 + 16;

/// Minimum size of an encoded [`Response`] sent by a server to this client.
// NOTE: 1byte for the version +
//       1byte for the opcode ORd with [`RESPONSE_INDICATOR`] +
//       1byte reserved +
//       1byte for the result code +
//       4bytes for the lifetime +
//       4bytes for the epoch time +
//       12bytes reserved
const MIN_RESP_SIZE: usize = 1 + 1 + 1 + 1 + 4 + 4 + 12;

/// Indicator ORd into the [`Opcode`] to indicate a response packet.
const RESPONSE_INDICATOR: u8 = 1u8 << 7;

/// NAT-PMP/PCP Version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum Version {
    /// NAT-PMP Version according to [RFC 6886 Transition to Port Control Protocol](https://datatracker.ietf.org/doc/html/rfc6886#section-1.1)
    // Version 0
    NatPmp = 0,
    /// PCP Version according to [RFC 6887 Version Negotiation](https://datatracker.ietf.org/doc/html/rfc6887#section-9)
    // Version 2
    Pcp = 2,
}

/// Opcode as defined in [RFC 6887 IANA Considerations](https://datatracker.ietf.org/doc/html/rfc6887#section-19)
// NOTE: PEER is not used, therefor not implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum Opcode {
    /// Annouce Opcode.
    ///
    /// Used by the server to annouce changes to clients. These include restarts
    /// (indicating loss of state) and changes to mappings and external ip addresses.
    ///
    /// See [RFC 6887 ANNOUNCE Opcode](https://datatracker.ietf.org/doc/html/rfc6887#section-14.1)
    Announce = 0,
    /// Map Opcode,
    ///
    /// Used to deal with endpoint-idependent mappings.
    ///
    /// See [RFC 6887 MAP Opcode](https://datatracker.ietf.org/doc/html/rfc6887#section-11)
    Map = 1,
}

/// ResultCode in a [`Response`].
///
/// Refer to [RFC 6887 Result Codes](https://datatracker.ietf.org/doc/html/rfc6887#section-7.4)
// NOTE: docs for each variant are largely adapted from the RFC's description of each code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum ResultCode {
    /// Success.
    Success = 0,
    /// The version number at the start of the PCP Request header is not recognized by the PCP
    /// server.
    UnsuppVersion = 1,
    /// The requested operation is disabled for this PCP client, or the PCP client requested an
    /// operation that cannot be fulfilled by the PCP server's security policy.
    NotAuthorized = 2,
    /// The request could not be successfully parsed.
    MalformedRequest = 3,
    /// Unsupported Opcode.
    UnsuppOpcode = 4,
    /// Unsupported option. This error only occurs if the option is in the mandatory-to-process
    /// range.
    UnsuppOption = 5,
    /// Malformed option (e.g., appears too many times, invalid length).
    MalformedOption = 6,
    /// The PCP server or the device it controls is experiencing a network failure of some sort
    /// (e.g., has not yet obtained an external IP address). This is a short lifetime error.
    NetworkFailure = 7,
    /// Request is well-formed and valid, but the server has insufficient resources to complete the
    /// requested operation at this time. This is a short lifetime error.
    NoResources = 8,
    /// Unsupported transport protocol, e.g., SCTP in a NAT that handles only UDP and TCP. This is
    /// a long lifetime error.
    UnsuppProtocol = 9,
    /// This attempt to create a new mapping would exceed this subscriber's port quota. This is a
    /// short lifetime error.
    UserExQuota = 10,
    /// The suggested external port and/or external address cannot be provided.
    CannotProvideExternal = 11,
    /// The source IP address of the request packet does not match the contents of the PCP Client's
    /// IP Address field.
    AddressMismatch = 12,
    /// The PCP server was not able to create the filters in this request.
    ExcessiveRemotePeers = 13,
}

/// A PCP Request.
///
/// See [RFC 6887 Request Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.1)
///
// NOTE: Opcode information and PCP Options are both optional, and currently not used in this
// code, thus not implemented.
pub struct Request {
    /// [`Version`] to use in this request.
    version: Version,
    /// [`Opcode`] of this request.
    opcode: Opcode,
    /// Requested lifetime in seconds used by the [`Request::opcode`].
    lifetime_seconds: u32,
    /// IP Address of the client.
    ///
    /// If the IP is an IpV4 address, is represented as a IpV4-mapped IpV6 address.
    client_addr: Ipv6Addr,
}

/// A PCP Response/Notification.
///
/// See [RFC 6887 Response Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.2)
///
// NOTE: Opcode response data and PCP Options are both optional, and currently not used in this
// code, thus not implemented.
#[derive(Debug)]
pub struct Response {
    /// [`Version`] of the response.
    version: Version,
    /// [`Opcode`] of the [`Request`] that related to this response.
    opcode: Opcode,
    /// [`ResultCode`] of the response.
    result_code: ResultCode,
    /// Lifetime in seconds that can be assumed by this response.
    ///
    /// For sucessful requests, this lifetime is how long to assume a mapping will last. For error
    /// responses, the lifetime indicates how long will the server return the same response for
    /// this response.
    lifetime_seconds: u32,
    /// Epoch time of the server.
    epoch_time: u32,
}

impl Request {
    // TODO(@divma): to_bytes? as_bytes?
    pub fn encode(&self) -> [u8; REQ_SIZE] {
        let mut buf = [0; REQ_SIZE];
        buf[0] = self.version as u8;
        buf[1] = self.opcode as u8;
        // buf[2] reserved
        // buf[3] reserved
        buf[4..8].copy_from_slice(&self.lifetime_seconds.to_be_bytes());
        buf[8..].copy_from_slice(&self.client_addr.octets());
        buf
    }
}

/// Errors that can occur when decoding a [`Response`] from a server.
// TODO(@divma): copy docs instead of refer?
#[derive(Debug)]
pub enum DecodeError {
    /// Request is too short or is otherwise malformed.
    Malformed,
    /// The [`RESPONSE_INDICATOR`] is not present.
    NotAResponse,
    /// See [`InvalidOpcode`].
    InvalidOpcode,
    /// See [`InvalidVersion`].
    InvalidVersion,
    /// See [`InvalidResultCode`].
    InvalidResultCode,
}

impl From<InvalidOpcode> for DecodeError {
    fn from(value: InvalidOpcode) -> Self {
        DecodeError::InvalidOpcode
    }
}

impl From<InvalidVersion> for DecodeError {
    fn from(value: InvalidVersion) -> Self {
        DecodeError::InvalidVersion
    }
}

impl From<InvalidResultCode> for DecodeError {
    fn from(value: InvalidResultCode) -> Self {
        DecodeError::InvalidResultCode
    }
}

impl Response {
    // TODO(@divma): from_bytes?
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < MIN_RESP_SIZE {
            return Err(DecodeError::Malformed);
        }
        let version: Version = buf[0].try_into()?;
        let opcode = buf[1];
        // buf[2] reserved
        if !(opcode & RESPONSE_INDICATOR == RESPONSE_INDICATOR) {
            return Err(DecodeError::NotAResponse);
        }
        let opcode = (opcode & !RESPONSE_INDICATOR).try_into()?;
        let result_code = buf[3].try_into()?;
        let lifetime_bytes = buf[4..8].try_into().expect("slice has the right len");
        let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);
        let epoch_bytes = buf[8..12].try_into().expect("slice has the right len");
        let epoch_time = u32::from_be_bytes(epoch_bytes);

        Ok(Response {
            version,
            opcode,
            result_code,
            lifetime_seconds,
            epoch_time,
        })
    }
}

/// Error ocurring when attempting to identify the [`Version`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidVersion;

impl TryFrom<u8> for Version {
    type Error = InvalidVersion;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::NatPmp),
            2 => Ok(Version::Pcp),
            _ => Err(InvalidVersion),
        }
    }
}

/// Error ocurring when attempting to identity the [`Opcode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidOpcode;

impl TryFrom<u8> for Opcode {
    type Error = InvalidOpcode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::Announce),
            1 => Ok(Opcode::Map),
            _ => Err(InvalidOpcode),
        }
    }
}

/// Error ocurring when attempting to decode the [`ResultCode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidResultCode;

impl TryFrom<u8> for ResultCode {
    type Error = InvalidResultCode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ResultCode::Success),
            1 => Ok(ResultCode::UnsuppVersion),
            2 => Ok(ResultCode::NotAuthorized),
            3 => Ok(ResultCode::MalformedRequest),
            4 => Ok(ResultCode::UnsuppOpcode),
            5 => Ok(ResultCode::UnsuppOption),
            6 => Ok(ResultCode::MalformedOption),
            7 => Ok(ResultCode::NetworkFailure),
            8 => Ok(ResultCode::NoResources),
            9 => Ok(ResultCode::UnsuppProtocol),
            10 => Ok(ResultCode::UserExQuota),
            11 => Ok(ResultCode::CannotProvideExternal),
            12 => Ok(ResultCode::AddressMismatch),
            13 => Ok(ResultCode::ExcessiveRemotePeers),
            _ => Err(InvalidResultCode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn version_repr_identity() {
        for v in Version::iter() {
            assert_eq!((v as u8).try_into(), Ok(v));
        }
    }

    #[test]
    fn opcode_repr_identity() {
        for o in Opcode::iter() {
            assert_eq!((o as u8).try_into(), Ok(o));
        }
    }

    #[test]
    fn response_code_repr_identity() {
        for rc in ResultCode::iter() {
            assert_eq!((rc as u8).try_into(), Ok(rc));
        }
    }
}
