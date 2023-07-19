use std::net::Ipv4Addr;

use num_enum::TryFromPrimitive;

use super::{MapProtocol, Opcode, Version};

#[derive(Debug)]
pub enum Response {
    PublicAddress {
        epoch_time: u32,
        public_ip: Ipv4Addr,
    },
    PortMap {
        proto: MapProtocol,
        epoch_time: u32,
        private_port: u16,
        external_port: u16,
        lifetime_seconds: u32,
    },
}

// 3.5.  Result Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum ResultCode {
    Success = 0,
    // TODO(@divma): responses having this error have a different packet format. annoying
    UnsupportedVersion = 1,
    /// Functionality is suported but not allowerd: e.g. box supports mapping, but user has turned
    /// feature off.
    NotAuthorizedOrRefused = 2,
    /// Netfork failures, e.g. NAT box itself has not obtained a DHCP lease.
    NetworkFailure = 3,
    /// NAT box cannot create any more mappings at this time.
    OutOfResources = 4,
    UnsupportedOpcode = 5,
}

/// Errors that can occur when decoding a [`Response`] from a server.
// TODO(@divma): copy docs instead of refer?
#[derive(Debug, derive_more::Display, thiserror::Error)]
pub enum Error {
    /// Request is too short or is otherwise malformed.
    #[display("Response is malformed")]
    Malformed,
    /// The [`RESPONSE_INDICATOR`] is not present.
    #[display("Packet does not appear to be a response")]
    NotAResponse,
    /// See [`InvalidOpcode`].
    #[display("Invalid Opcode received")]
    InvalidOpcode,
    /// See [`InvalidVersion`].
    #[display("Invalid version received")]
    InvalidVersion,
    /// See [`InvalidResultCode`].
    #[display("Invalid result code received")]
    InvalidResultCode,
    UnsupportedVersion,
    NotAuthorizedOrRefused,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
}

impl Response {
    /// Minimum size of an encoded [`Response`] sent by a server to this client.
    pub const MIN_SIZE: usize = // parts of a public ip response
        1 + // version
        1 + // opcode
        2 + // result code
        4 + // epoch time
        4; // lifetime

    /// Minimum size of an encoded [`Response`] sent by a server to this client.
    pub const MAX_SIZE: usize = // parts of mapping response
        1 + // version
        1 + // opcode
        2 + // result code
        4 + // epoch time
        2 + // private port
        2 + // public port
        4; // lifetime

    /// Indicator ORd into the [`Opcode`] to indicate a response packet.
    pub const INDICATOR: u8 = 1u8 << 7;

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_SIZE || buf.len() > Self::MAX_SIZE {
            return Err(Error::Malformed);
        }
        let _: Version = buf[0].try_into().map_err(|_| Error::InvalidVersion)?;
        let opcode = buf[1];
        if opcode & Self::INDICATOR != Self::INDICATOR {
            return Err(Error::NotAResponse);
        }
        let opcode: Opcode = (opcode & !Self::INDICATOR)
            .try_into()
            .map_err(|_| Error::InvalidOpcode)?;

        let result_bytes =
            u16::from_be_bytes(buf[2..4].try_into().expect("slice has the right len"));
        let result_code = result_bytes
            .try_into()
            .map_err(|_| Error::InvalidResultCode)?;

        match result_code {
            ResultCode::Success => Ok(()),
            ResultCode::UnsupportedVersion => Err(Error::UnsupportedVersion),
            ResultCode::NotAuthorizedOrRefused => Err(Error::NotAuthorizedOrRefused),
            ResultCode::NetworkFailure => Err(Error::NetworkFailure),
            ResultCode::OutOfResources => Err(Error::OutOfResources),
            ResultCode::UnsupportedOpcode => Err(Error::UnsupportedOpcode),
        }?;

        let response = match opcode {
            Opcode::DetermineExternalAddress => {
                let epoch_bytes = buf[4..8].try_into().expect("slice has the right len");
                let epoch_time = u32::from_be_bytes(epoch_bytes);
                let ip_bytes: [u8; 4] = buf[8..12].try_into().expect("slice has the right len");
                Response::PublicAddress {
                    epoch_time,
                    public_ip: ip_bytes.into(),
                }
            }
            Opcode::MapUdp => {
                let proto = MapProtocol::UDP;

                let epoch_bytes = buf[4..8].try_into().expect("slice has the right len");
                let epoch_time = u32::from_be_bytes(epoch_bytes);

                let private_port_bytes = buf[8..10].try_into().expect("slice has the right len");
                let private_port = u16::from_be_bytes(private_port_bytes);

                let external_port_bytes = buf[10..12].try_into().expect("slice has the right len");
                let external_port = u16::from_be_bytes(external_port_bytes);

                let lifetime_bytes = buf[12..16].try_into().expect("slice has the right len");
                let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);

                Response::PortMap {
                    proto,
                    epoch_time,
                    private_port,
                    external_port,
                    lifetime_seconds,
                }
            }
        };

        Ok(response)
    }
}
