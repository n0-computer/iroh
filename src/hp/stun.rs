use std::net::IpAddr;

pub use stun_rs::TransactionId;

#[derive(Debug, thiserror::Error)]
pub enum Error {}

/// Parses a STUN binding request.
pub fn parse_binding_request(b: &[u8]) -> Result<TransactionId, Error> {
    todo!()
}

/// Parses a successful binding response STUN packet.
/// The IP address is extracted from the XOR-MAPPED-ADDRESS attribute.
pub fn parse_response(b: &[u8]) -> Result<(TransactionId, IpAddr), Error> {
    todo!()
}
