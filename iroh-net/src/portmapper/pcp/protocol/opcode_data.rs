//! Encoding and decoding of the data associated with an [`Opcode`].

use std::net::Ipv6Addr;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::Opcode;

/// Data associated to an [`Opcode`]
#[derive(Debug, PartialEq, Eq)]
pub enum OpcodeData {
    /// Data for an [`Opcode::Announce`] request.
    Announce,
    /// Data for an [`Opcode::Map`] request.
    MapData(MapData),
}

/// [`OpcodeData`] associated to a [`Opcode::Map`].
#[derive(Debug, PartialEq, Eq)]
pub struct MapData {
    /// Nonce of the request. Used to verify responses in the client side, and modifications in the
    /// server side.
    pub nonce: [u8; 12],
    /// Protocol for which the mapping is being requested.
    pub protocol: MapProtocol,
    /// Local port for the mapping.
    pub local_port: u16,
    /// External port of the mapping.
    pub external_port: u16,
    /// External ip of the mapping.
    pub external_address: Ipv6Addr,
}

/// Protocol for which a port mapping is requested.
// NOTE: technically any IANA protocol is allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum MapProtocol {
    Udp = 17,
}

/// Generic error returned when decoding [`OpcodeData`] fails.
#[derive(Debug)]
pub struct InvalidOpcodeData;

impl MapData {
    /// Size of the opcode-specific data of a [`Opcode::Map`] request.
    pub const ENCODED_SIZE: usize = // parts
        12 + // nonce
        1 + // protocol
        3 + // reserved
        2 + // local port
        2 + // external port
        16; // external address

    /// Encode this [`MapData`].
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let MapData {
            nonce,
            protocol,
            local_port,
            external_port,
            external_address,
        } = self;
        let mut buf = [0; Self::ENCODED_SIZE];
        buf[0..12].copy_from_slice(nonce);
        buf[12] = (*protocol).into();
        // buf[13..16] reserved
        buf[16..18].copy_from_slice(&local_port.to_be_bytes());
        buf[18..20].copy_from_slice(&external_port.to_be_bytes());
        buf[20..].copy_from_slice(&external_address.octets());

        buf
    }

    /// Decode a [`MapData`].
    pub fn decode(buf: &[u8]) -> Result<Self, InvalidOpcodeData> {
        if buf.len() < Self::ENCODED_SIZE {
            return Err(InvalidOpcodeData);
        }

        let nonce = buf[..12].try_into().expect("slice has the right size");

        let protocol = buf[12].try_into().map_err(|_| InvalidOpcodeData)?;

        // buf[13..16] reserved

        let local_port_bytes = buf[16..18].try_into().expect("slice has the right size");
        let local_port = u16::from_be_bytes(local_port_bytes);

        let external_port_bytes = buf[18..20].try_into().expect("slice has the right size");
        let external_port = u16::from_be_bytes(external_port_bytes);

        let external_addr_bytes: [u8; 16] = buf[20..].try_into().expect("buffer size was verified");
        let external_address = Ipv6Addr::from(external_addr_bytes);

        Ok(MapData {
            nonce,
            protocol,
            local_port,
            external_port,
            external_address,
        })
    }

    #[cfg(test)]
    fn random<R: rand::Rng>(rng: &mut R) -> MapData {
        let octects: [u8; 16] = rng.gen();
        MapData {
            nonce: rng.gen(),
            protocol: MapProtocol::Udp,
            local_port: rng.gen(),
            external_port: rng.gen(),
            external_address: octects.into(),
        }
    }
}

impl OpcodeData {
    /// Get the associated [`Opcode`].
    pub fn opcode(&self) -> Opcode {
        match self {
            OpcodeData::Announce => Opcode::Announce,
            OpcodeData::MapData(_) => Opcode::Map,
        }
    }

    /// Encode this [`OpcodeData`] into the buffer.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            OpcodeData::Announce => {}
            OpcodeData::MapData(map_data) => buf.extend_from_slice(&map_data.encode()),
        }
    }

    /// Exact size an encoded [`OpcodeData`] will have.
    pub const fn encoded_size(&self) -> usize {
        match self {
            OpcodeData::Announce => 0,
            OpcodeData::MapData(_) => MapData::ENCODED_SIZE,
        }
    }

    /// Decode the [`OpcodeData`] expected for a given [`Opcode`].
    pub fn decode(opcode: Opcode, buf: &[u8]) -> Result<Self, InvalidOpcodeData> {
        match opcode {
            Opcode::Announce => Ok(OpcodeData::Announce),
            Opcode::Map => {
                let map_data = MapData::decode(buf)?;
                Ok(OpcodeData::MapData(map_data))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn random<R: rand::Rng>(opcode: Opcode, rng: &mut R) -> OpcodeData {
        match opcode {
            Opcode::Announce => OpcodeData::Announce,
            Opcode::Map => OpcodeData::MapData(MapData::random(rng)),
        }
    }
}
