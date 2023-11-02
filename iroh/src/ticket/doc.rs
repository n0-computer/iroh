//! Tickets for [`iroh-sync`] documents.

use iroh_net::PeerAddr;
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::KeyBytes;

use super::*;

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", IrohTicket::serialize(self))]
pub struct Ticket {
    /// either a public or private key
    pub capability: KeyBytes,
    /// A list of nodes to contact.
    pub nodes: Vec<PeerAddr>,
}

impl IrohTicket for Ticket {
    const KIND: Kind = Kind::Doc;
}

impl Ticket {
    /// Create a new doc ticket
    pub fn new(key: KeyBytes, peers: Vec<PeerAddr>) -> Self {
        Self {
            capability: key,
            nodes: peers,
        }
    }
}

impl std::str::FromStr for Ticket {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IrohTicket::deserialize(s)
    }
}
