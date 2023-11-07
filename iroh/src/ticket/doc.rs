//! Tickets for [`iroh-sync`] documents.

use iroh_net::NodeAddr;
use iroh_sync::Capability;
use serde::{Deserialize, Serialize};

use super::*;

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", IrohTicket::serialize(self))]
pub struct Ticket {
    /// either a public or private key
    pub capability: Capability,
    /// A list of nodes to contact.
    pub nodes: Vec<NodeAddr>,
}

impl IrohTicket for Ticket {
    const KIND: Kind = Kind::Doc;
}

impl Ticket {
    /// Create a new doc ticket
    pub fn new(capability: Capability, peers: Vec<NodeAddr>) -> Self {
        Self {
            capability,
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
