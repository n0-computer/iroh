mod request;
mod response;

pub use request::*;
pub use response::*;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Version {
    NatPmp = 0,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // 3.2.  Determining the External Address
    DetermineExternalAddress = 0,
    // 3.3.  Requesting a Mapping
    MapUdp = 1,
    // 3.3.  Requesting a Mapping
    MapTcp = 2,
}

