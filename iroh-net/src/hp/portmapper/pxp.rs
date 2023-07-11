//! Utilities for probing [NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) and
//! [PCP](https://datatracker.ietf.org/doc/html/rfc6887).

#![allow(unused)]

// NOTES
// TODO(@divma): move to pr desc
// PCP has multicast announcements from the server to the clients, this means binding to
// 224.0.0.1:CLIENT_PORT. to implement or not to implement.

use std::{
    fmt::Result,
    net::{Ipv4Addr, Ipv6Addr},
};

/// NAT-PMP/PCP Version
#[derive(Debug)]
#[repr(u8)]
pub enum Version {
    /// NAT-PMP Version according to [RFC 6886 Transition to Port Control Protocol](https://datatracker.ietf.org/doc/html/rfc6886#section-1.1)
    // Version 0
    NatPmp = 0,
    /// PCP Version according to [RFC 6887 Version Negotiation](https://datatracker.ietf.org/doc/html/rfc6887#section-9)
    // Version 2
    Pcp = 2,
}

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6887#section-19>

/// Port to use when acting as a client. This is the one we bind to.
pub const CLIENT_PORT: u16 = 5350;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Opcode as defined in [RFC 6887 IANA Considerations](https://datatracker.ietf.org/doc/html/rfc6887#section-19)
// NOTE: PEER is not used, therefor not implemented.
#[derive(Debug)]
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
#[derive(Debug)]
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

pub fn build_announce_request(ip: Ipv4Addr) -> Vec<u8> {
    let capacity = (8 / 8) + (8 / 8) + (16 / 8) + (32 / 8) + (128 / 8);
    let mut buf = Vec::with_capacity(capacity);
    // let req = Request {
    //     version: Version::Pcp,
    //     opcode: Opcode::Announce,
    //     lifetime_seconds: 0,
    //     client_addr: ip.to_ipv6_mapped(),
    // };
    buf.push(Version::Pcp as u8);
    buf.push(Opcode::Announce as u8);
    // 16bits reserved
    buf.push(0);
    buf.push(0);
    // the lifetime
    buf.extend_from_slice(&0u32.to_be_bytes());
    let ip = ip.to_ipv6_mapped();
    buf.extend_from_slice(&ip.octets());
    assert_eq!(buf.len(), capacity, "malformed?");

    buf
}

/// Error ocurring when attempting to identify the [`Version`] in a server response.
#[derive(Debug)]
pub struct InvalidVersion(u8);

impl TryFrom<u8> for Version {
    type Error = InvalidVersion;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::NatPmp),
            2 => Ok(Version::Pcp),
            other => Err(InvalidVersion(other)),
        }
    }
}

/// Error ocurring when attempting to identity the [`Opcode`] in a server response.
#[derive(Debug)]
pub struct InvalidOpcode(u8);

impl TryFrom<u8> for Opcode {
    type Error = InvalidOpcode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::Announce),
            1 => Ok(Opcode::Map),
            other => Err(InvalidOpcode(other)),
        }
    }
}

/// Error ocurring when attempting to decode the [`ResultCode`] in a server response.
#[derive(Debug)]
pub struct InvalidResultCode(u8);

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
            other => Err(InvalidResultCode(other)),
        }
    }
}

pub fn parse_response(buf: Vec<u8>) -> Response {
    let version: Version = buf[0].try_into().unwrap();
    let opcode = buf[1];
    assert!((opcode & 0x80) == 0x80);
    let opcode = (opcode & 0x7F).try_into().unwrap();
    let result_code = buf[3].try_into().unwrap();
    let lifetime_bytes = buf[4..8].try_into().unwrap();
    let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);
    let epoch_bytes = buf[8..12].try_into().unwrap();
    let epoch_time = u32::from_be_bytes(epoch_bytes);

    Response {
        version,
        opcode,
        result_code,
        lifetime_seconds,
        epoch_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_repr_identity() {
        // TODO(@divma): check that tryfrom impls are correct.
    }
}
