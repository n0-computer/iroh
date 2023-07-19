//! Definitions and utilities to interact with a NAT-PMP server.

mod request;
mod response;

use num_enum::{IntoPrimitive, TryFromPrimitive};

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6887#section-19>

pub use request::*;
pub use response::*;

/// Nat Version according to [RFC 6887 Version Negotiation](https://datatracker.ietf.org/doc/html/rfc6887#section-9).
/// TODO(@divma): real link
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    NatPmp = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Opcode {
    // 3.2.  Determining the External Address
    DetermineExternalAddress = 0,
    // 3.3.  Requesting a Mapping
    MapUdp = 1,
    // 3.3.  Requesting a Mapping
    MapTcp = 2,
}
