//! Definitions and utilities to interact with a NAT-PMP server.

mod request;
mod response;

use num_enum::{IntoPrimitive, TryFromPrimitive};

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6887#section-19>

pub use request::*;
pub use response::*;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Nat Version according to [RFC 6886 Transition to Port Control Protocol](https://datatracker.ietf.org/doc/html/rfc6886#section-1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    /// NAT-PMP version
    NatPmp = 0,
}

/// Opcode accepted by a NAT-PMP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Opcode {
    /// Determine the external address of the gateway.
    ///
    /// See [RFC 6886 Determining the External Address](https://datatracker.ietf.org/doc/html/rfc6886#section-3.2).
    DetermineExternalAddress = 0,
    /// Get a UDP Mapping.
    ///
    /// See [RFC 6886 Requesting a Mapping](https://datatracker.ietf.org/doc/html/rfc6886#section-3.3).
    MapUdp = 1,
}
