//! A NAT-PCP request encoding and decoding.

use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{Opcode, Version};

/// A NAT-PCP Request.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// Request to determine the gateway's external address.
    ExternalAddress,
    /// Request to register a mapping with the NAT-PCP server.
    Mapping {
        /// Protocol to use for this mapping.
        proto: MapProtocol,
        /// Local port to map.
        local_port: u16,
        /// Preferred external port.
        external_port: u16,
        /// Requested lifetime in seconds for the mapping.
        lifetime_seconds: u32,
    },
}

/// Protocol for which a port mapping is requested.
// NOTE: spec defines TCP as well, which we don't need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum MapProtocol {
    /// UDP mapping.
    UDP = 1,
}

impl Request {
    /// Encode this [`Request`].
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::ExternalAddress => vec![
                Version::NatPmp.into(),
                Opcode::DetermineExternalAddress.into(),
            ],
            Request::Mapping {
                proto,
                local_port,
                external_port,
                lifetime_seconds,
            } => {
                let opcode = match proto {
                    MapProtocol::UDP => Opcode::MapUdp,
                };
                let mut buf = vec![Version::NatPmp.into(), opcode.into()];
                buf.push(0); // reserved
                buf.push(0); // reserved
                buf.extend_from_slice(&local_port.to_be_bytes());
                buf.extend_from_slice(&external_port.to_be_bytes());
                buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
                buf
            }
        }
    }

    #[cfg(test)]
    fn random<R: rand::Rng>(opcode: super::Opcode, rng: &mut R) -> Self {
        match opcode {
            Opcode::DetermineExternalAddress => Request::ExternalAddress,
            Opcode::MapUdp => Request::Mapping {
                proto: MapProtocol::UDP,
                local_port: rng.gen(),
                external_port: rng.gen(),
                lifetime_seconds: rng.gen(),
            },
        }
    }

    #[cfg(test)]
    #[track_caller]
    fn decode(buf: &[u8]) -> Self {
        let _version: Version = buf[0].try_into().unwrap();
        let opcode: super::Opcode = buf[1].try_into().unwrap();
        // check if this is a mapping request, or an external address request
        match opcode {
            Opcode::DetermineExternalAddress => Request::ExternalAddress,
            Opcode::MapUdp => {
                // buf[2] reserved
                // buf[3] reserved

                let local_port_bytes = buf[4..6].try_into().expect("slice has the right size");
                let local_port = u16::from_be_bytes(local_port_bytes);

                let external_port_bytes = buf[6..8].try_into().expect("slice has the right size");
                let external_port = u16::from_be_bytes(external_port_bytes);

                let lifetime_bytes: [u8; 4] = buf[8..12].try_into().unwrap();
                let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);
                Request::Mapping {
                    proto: MapProtocol::UDP,
                    local_port,
                    external_port,
                    lifetime_seconds,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;

    #[test]
    fn test_encode_decode_addr_request() {
        let mut gen = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let request = Request::random(super::Opcode::DetermineExternalAddress, &mut gen);
        let encoded = request.encode();
        assert_eq!(request, Request::decode(&encoded));
    }

    #[test]
    fn test_encode_decode_map_request() {
        let mut gen = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let request = Request::random(super::Opcode::MapUdp, &mut gen);
        let encoded = request.encode();
        assert_eq!(request, Request::decode(&encoded));
    }
}
