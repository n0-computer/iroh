use super::{Opcode, Version};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapProtocol {
    UDP,
    TCP,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::ExternalAddress => vec![
                Version::NatPmp as u8,
                Opcode::DetermineExternalAddress as u8,
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
                let mut buf = vec![Version::NatPmp as u8, opcode as u8];
                buf.extend_from_slice(&local_port.to_be_bytes());
                buf.extend_from_slice(&external_port.to_be_bytes());
                buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
                buf
            }
        }
    }
}
