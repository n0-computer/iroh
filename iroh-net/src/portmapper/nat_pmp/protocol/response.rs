//! A NAT-PMP response encoding and decoding.

use std::net::Ipv4Addr;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{MapProtocol, Opcode, Version};

/// A NAT-PMP successful Response/Notification.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// Response to a [`Opcode::DetermineExternalAddress`] request.
    PublicAddress {
        epoch_time: u32,
        public_ip: Ipv4Addr,
    },
    /// Response to a [`Opcode::MapUdp`] request.
    PortMap {
        /// Protocol for which the mapping was requested.
        proto: MapProtocol,
        /// Epoch time of the server.
        epoch_time: u32,
        /// Local port for which the mapping was created.
        private_port: u16,
        /// External port registered for this mapping.
        external_port: u16,
        /// Lifetime in seconds that can be assumed by this mapping.
        lifetime_seconds: u32,
    },
}

/// Result code obtained in a NAT-PMP response.
///
/// See [RFC 6886 Result Codes](https://datatracker.ietf.org/doc/html/rfc6886#section-3.5)
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum ResultCode {
    /// A successful response.
    Success = 0,
    /// The sent version is not supported by the NAT-PMP server.
    UnsupportedVersion = 1,
    /// Functionality is suported but not allowerd: e.g. box supports mapping, but user has turned
    /// feature off.
    NotAuthorizedOrRefused = 2,
    /// Netfork failures, e.g. NAT device itself has not obtained a DHCP lease.
    NetworkFailure = 3,
    /// NAT-PMP server cannot create any more mappings at this time.
    OutOfResources = 4,
    /// Opcode is not supported by the server.
    UnsupportedOpcode = 5,
}

/// Errors that can occur when decoding a [`Response`] from a server.
#[derive(Debug, derive_more::Display, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Request is too short or is otherwise malformed.
    #[display("Response is malformed")]
    Malformed,
    /// The [`RESPONSE_INDICATOR`] is not present.
    #[display("Packet does not appear to be a response")]
    NotAResponse,
    /// The received opcode is not recognized.
    #[display("Invalid Opcode received")]
    InvalidOpcode,
    /// The received version is not recognized.
    #[display("Invalid version received")]
    InvalidVersion,
    /// The received result code is not recognized.
    #[display("Invalid result code received")]
    InvalidResultCode,
    /// Received an error code indicating the server does not support the sent version.
    #[display("Server does not support the version")]
    UnsupportedVersion,
    /// Received an error code indicating the operation is supported but not authorized.
    #[display("Operation is supported but not authorized")]
    NotAuthorizedOrRefused,
    /// Received an error code indicating the server experienced a network failure
    #[display("Server experienced a network failure")]
    NetworkFailure,
    /// Received an error code indicating the server cannot create more mappings at this time.
    #[display("Server is out of resources")]
    OutOfResources,
    /// Received an error code indicating the Opcode is not supported by the server.
    #[display("Server does not suport this opcode")]
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
    pub const RESPONSE_INDICATOR: u8 = 1u8 << 7;

    /// Decode a response.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_SIZE || buf.len() > Self::MAX_SIZE {
            return Err(Error::Malformed);
        }
        let _: Version = buf[0].try_into().map_err(|_| Error::InvalidVersion)?;
        let opcode = buf[1];
        if opcode & Self::RESPONSE_INDICATOR != Self::RESPONSE_INDICATOR {
            return Err(Error::NotAResponse);
        }
        let opcode: Opcode = (opcode & !Self::RESPONSE_INDICATOR)
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

    #[cfg(test)]
    fn random<R: rand::Rng>(opcode: Opcode, rng: &mut R) -> Self {
        match opcode {
            Opcode::DetermineExternalAddress => {
                let octects: [u8; 4] = rng.gen();
                Response::PublicAddress {
                    epoch_time: rng.gen(),
                    public_ip: octects.into(),
                }
            }
            Opcode::MapUdp => Response::PortMap {
                proto: MapProtocol::UDP,
                epoch_time: rng.gen(),
                private_port: rng.gen(),
                external_port: rng.gen(),
                lifetime_seconds: rng.gen(),
            },
        }
    }

    #[cfg(test)]
    fn encode(&self) -> Vec<u8> {
        match self {
            Response::PublicAddress {
                epoch_time,
                public_ip,
            } => {
                let mut buf = Vec::with_capacity(Self::MIN_SIZE);
                // version
                buf.push(Version::NatPmp.into());
                // response indicator and opcode
                let opcode: u8 = Opcode::DetermineExternalAddress.into();
                buf.push(Response::RESPONSE_INDICATOR | opcode);
                // result code
                let result_code: u16 = ResultCode::Success.into();
                for b in result_code.to_be_bytes() {
                    buf.push(b);
                }
                // epoch
                for b in epoch_time.to_be_bytes() {
                    buf.push(b);
                }
                // public ip
                for b in public_ip.octets() {
                    buf.push(b)
                }
                buf
            }
            Response::PortMap {
                proto: _,
                epoch_time,
                private_port,
                external_port,
                lifetime_seconds,
            } => {
                let mut buf = Vec::with_capacity(Self::MAX_SIZE);
                // version
                buf.push(Version::NatPmp.into());
                // response indicator and opcode
                let opcode: u8 = Opcode::MapUdp.into();
                buf.push(Response::RESPONSE_INDICATOR | opcode);
                // result code
                let result_code: u16 = ResultCode::Success.into();
                for b in result_code.to_be_bytes() {
                    buf.push(b);
                }
                // epoch
                for b in epoch_time.to_be_bytes() {
                    buf.push(b);
                }
                // internal port
                for b in private_port.to_be_bytes() {
                    buf.push(b)
                }
                // external port
                for b in external_port.to_be_bytes() {
                    buf.push(b)
                }
                for b in lifetime_seconds.to_be_bytes() {
                    buf.push(b)
                }
                buf
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;

    #[test]
    fn test_decode_external_addr_response() {
        let mut gen = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let response = Response::random(Opcode::DetermineExternalAddress, &mut gen);
        let encoded = response.encode();
        assert_eq!(Ok(response), Response::decode(&encoded));
    }

    #[test]
    fn test_encode_decode_map_response() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let response = Response::random(Opcode::MapUdp, &mut rng);
        let encoded = response.encode();
        assert_eq!(Ok(response), Response::decode(&encoded));
    }
}
