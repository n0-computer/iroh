use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{Opcode, Version};

/// A NAT-PCP Request.
#[derive(Debug)]
pub enum Request {
    ExternalAddress,
    Mapping {
        proto: MapProtocol,
        local_port: u16,
        external_port: u16,
        lifetime_seconds: u32,
    },
}

/// Protocol for which a port mapping is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum MapProtocol {
    UDP = 1,
    TCP = 2,
}

impl Request {
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
                    MapProtocol::TCP => Opcode::MapTcp,
                };
                let mut buf = vec![Version::NatPmp.into(), opcode.into()];
                // reserved
                buf.push(0);
                buf.push(0);
                buf.extend_from_slice(&local_port.to_be_bytes());
                buf.extend_from_slice(&external_port.to_be_bytes());
                buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
                buf
            }
        }
    }
}
