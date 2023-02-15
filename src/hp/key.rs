/// Public Key for a regular peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePublic {}

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
