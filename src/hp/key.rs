// TODO: constant time things

use std::ops::Deref;

/// Public Key for a regular peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePublic([u8; 32]);

impl From<[u8; 32]> for NodePublic {
    fn from(value: [u8; 32]) -> Self {
        NodePublic(value)
    }
}

impl Deref for NodePublic {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Private Key for a regular peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePrivate {}

/// Public Key for a discovery Node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoPublic {}

/// Private Key for a discovery Node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoPrivate {}

impl DiscoPrivate {
    pub fn new() -> Self {
        todo!()
    }

    pub fn public(&self) -> DiscoPublic {
        todo!()
    }
}

/// Shared Secret for a discovery Node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoShared {}

pub const NODE_PUBLIC_RAW_LEN: usize = 32;
pub const DISCO_PUBLIC_RAW_LEN: usize = 32;
