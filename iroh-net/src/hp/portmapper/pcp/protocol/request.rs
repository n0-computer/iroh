use std::net::Ipv6Addr;

use super::{opcode_data::OpcodeData, Version};

/// A PCP Request.
///
/// See [RFC 6887 Request Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.1)
///
// NOTE: PCP Options are optional, and currently not used in this code, thus not implemented
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
    pub const SIZE: usize = // parts:
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
        let mut buf = Vec::with_capacity(Self::SIZE + opcode_data.encoded_size());
        // buf[0]
        buf.push(*version as u8);
        // buf[1]
        buf.push(opcode_data.opcode() as u8);
        // buf[2] reserved
        buf.push(0);
        // buf[3] reserved
        buf.push(0);
        // buf[4..8]
        buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
        // buf[8..12]
        buf.extend_from_slice(&client_addr.octets());
        // buf[12..]
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
}
