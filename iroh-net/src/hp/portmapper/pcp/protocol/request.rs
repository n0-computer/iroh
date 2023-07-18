use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    opcode_data::{MapData, MapProtocol, OpcodeData},
    Version,
};

/// A PCP Request.
///
/// See [RFC 6887 Request Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.1)
///
// NOTE: PCP Options are optional, and currently not used in this code, thus not implemented
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// [`Version`] to use in this request.
    pub(super) version: Version,
    /// Requested lifetime in seconds.
    pub(super) lifetime_seconds: u32,
    /// IP Address of the client.
    ///
    /// If the IP is an IpV4 address, is represented as a IpV4-mapped IpV6 address.
    pub(super) client_addr: Ipv6Addr,
    /// Data associated to the [`super::Opcode`] in this request.
    pub(super) opcode_data: OpcodeData,
}

impl Request {
    /// Size of a [`Request`] sent by this client, in bytes.
    pub const MIN_SIZE: usize = // parts:
        1 + // version
        1 + // opcode
        2 + // reserved
        4 + // lifetime
        16; // local ip

    /// Encode this [`Request`].
    pub fn encode(&self) -> Vec<u8> {
        let Request {
            version,
            lifetime_seconds,
            client_addr,
            opcode_data,
        } = self;
        let mut buf = Vec::with_capacity(Self::MIN_SIZE + opcode_data.encoded_size());
        // buf[0]
        buf.push((*version).into());
        // buf[1]
        buf.push(opcode_data.opcode().into());
        // buf[2] reserved
        buf.push(0);
        // buf[3] reserved
        buf.push(0);
        // buf[4..8]
        buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
        // buf[8..24]
        buf.extend_from_slice(&client_addr.octets());
        // buf[24..]
        opcode_data.encode_into(&mut buf);

        buf
    }

    /// Create an announce request.
    pub fn annouce(client_addr: Ipv6Addr) -> Request {
        Request {
            version: Version::Pcp,
            // opcode announce requires a lifetime of 0 and to ignore the lifetime on response
            lifetime_seconds: 0,
            client_addr,
            // the pcp announce opcode requests and responses have no opcode-specific payload
            opcode_data: OpcodeData::Announce,
        }
    }

    pub fn mapping(
        nonce: [u8; 12],
        local_port: u16,
        local_ip: Ipv4Addr,
        preferred_external_port: Option<u16>,
        preferred_external_address: Option<Ipv4Addr>,
        lifetime_seconds: u32,
    ) -> Request {
        Request {
            version: Version::Pcp,
            lifetime_seconds,
            client_addr: local_ip.to_ipv6_mapped(),
            opcode_data: OpcodeData::MapData(MapData {
                nonce,
                protocol: MapProtocol::Udp,
                local_port,
                // if the pcp client does not know the external port, or does not have a
                // preference, it must use 0.
                external_port: preferred_external_port.unwrap_or_default(),
                external_address: preferred_external_address
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
                    .to_ipv6_mapped(),
            }),
        }
    }

    #[cfg(test)]
    fn random<R: rand::Rng>(opcode: super::Opcode, rng: &mut R) -> Self {
        let opcode_data = OpcodeData::random(opcode, rng);
        let addr_octects: [u8; 16] = rng.gen();
        Request {
            version: Version::Pcp,
            lifetime_seconds: rng.gen(),
            client_addr: Ipv6Addr::from(addr_octects),
            opcode_data,
        }
    }

    #[cfg(test)]
    #[track_caller]
    fn decode(buf: &[u8]) -> Self {
        let version: Version = buf[0].try_into().unwrap();
        let opcode: super::Opcode = buf[1].try_into().unwrap();
        // buf[2] reserved
        // buf[3] reserved
        let lifetime_bytes: [u8; 4] = buf[4..8].try_into().unwrap();
        let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);

        let local_ip_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
        let client_addr: Ipv6Addr = local_ip_bytes.into();

        let opcode_data = OpcodeData::decode(opcode, &buf[24..]).unwrap();
        Self {
            version,
            lifetime_seconds,
            client_addr,
            opcode_data,
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

        let request = Request::random(super::super::Opcode::Announce, &mut gen);
        let encoded = request.encode();
        assert_eq!(request, Request::decode(&encoded));
    }

    #[test]
    fn test_encode_decode_map_request() {
        let mut gen = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let request = Request::random(super::super::Opcode::Map, &mut gen);
        let encoded = request.encode();
        assert_eq!(request, Request::decode(&encoded));
    }
}
