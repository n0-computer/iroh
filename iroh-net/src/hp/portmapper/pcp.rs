//! Utilities for probing [NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) and
//! [PCP](https://datatracker.ietf.org/doc/html/rfc6887).

#![allow(unused)]

use std::net::Ipv6Addr;

/// NAT-PMP/PCP Version
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
// TODO(@divma): remember
// > Clients should therefore bind specifically to 224.0.0.1:5350, not to 0.0.0.0:5350.
pub const CLIENT_PORT: u16 = 5350;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Opcode as defined in [RFC 6887 IANA Considerations](https://datatracker.ietf.org/doc/html/rfc6887#section-19)
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
    /// See [RFC 6887 MAP Ocode](https://datatracker.ietf.org/doc/html/rfc6887#section-11)
    Map = 1,
}

// TODO(@divma): adjust docs
pub enum ResultCode {
    /// Success.
    Success = 0,
    /// The version number at the start of the PCP Request header is not recognized by this PCP
    /// server.  This is a long lifetime error.  This document describes PCP version 2.
    UnsuppVersion = 1,
    /// The requested operation is disabled for this PCP client, or the PCP client requested an
    /// operation that cannot be fulfilled by the PCP server's security policy.  This is a long
    /// lifetime error.
    NotAuthorized = 2,
    /// The request could not be successfully parsed. This is a long lifetime error.
    MalformedRequest = 3,
    /// Unsupported Opcode.  This is a long lifetime error.
    UnsuppOpcode = 4,
    /// Unsupported option.  This error only occurs if the option is in the mandatory-to-process
    /// range.  This is a long lifetime error.
    UnsuppOption = 5,
    /// Malformed option (e.g., appears too many times, invalid length).  This is a long lifetime
    /// error.
    MalformedOption = 6,
    /// The PCP server or the device it controls is experiencing a network failure of some sort
    /// (e.g., has not yet obtained an external IP address).  This is a short lifetime error.
    NetworkFailure = 7,
    /// Request is well-formed and valid, but the server has insufficient resources to complete the
    /// requested operation at this time.  For example, the NAT device cannot create more mappings
    /// at this time, is short of CPU cycles or memory, or is unable to handle the request due to
    /// some other temporary condition.  The same request may succeed in the future.  This is a
    /// system-wide error, different from USEREXQUOTA.  This can be used as a catch- all error,
    /// should no other error message be suitable.  This is a short lifetime error.
    NoResources = 8,
    /// Unsupported transport protocol, e.g., SCTP in a NAT that handles only UDP and TCP.  This is
    /// a long lifetime error.
    UnsuppProtocol = 9,
    /// This attempt to create a new mapping would exceed this subscriber's port quota.  This is a
    /// short lifetime error.
    UserExQuota = 10,
    /// The suggested external port and/or external address cannot be provided.  This error MUST
    /// only be returned for: *  MAP requests that included the PREFERFAILURE option (normal MAP
    /// requests will return an available external port) *  MAP requests for the SCTP protocol
    /// (PREFERFAILURE is implied) *  PEER requests See Section 13.2 for details of the
    /// PREFERFAILURE Option.  The error lifetime depends on the reason for the failure.
    CannotProvideExternal = 11,
    /// The source IP address of the request packet does not match the contents of the PCP Client's
    /// IP Address field, due to an unexpected NAT on the path between the PCP client and the
    /// PCP-controlled NAT or firewall.  This is a long lifetime error.
    AddressMismatch = 12,
    /// The PCP server was not able to create the filters in this request.  This result code MUST
    /// only be returned if the MAP request contained the FILTER option.  See Section 13.3 for
    /// details of the FILTER Option.  This is a long lifetime error.
    ExcessiveRemotePeers = 13,
}

/// A PCP Request.
///
/// See [RFC 6887 Request Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.1)
///
/// NOTE: Opcode information and PCP Options are both optional, and currently not used in this
/// code, thus not implemented.
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
/// NOTE: Opcode response data and PCP Options are both optional, and currently not used in this
/// code, thus not implemented.
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

impl TryFrom<u8> for Version {
    type Error = ResultCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::NatPmp),
            2 => Ok(Version::Pcp),
            _ => Err(ResultCode::UnsuppVersion),
        }
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
