//! Tickets for [`iroh-sync`] documents.

use iroh_base::ticket;
use iroh_net::NodeAddr;
use iroh_sync::Capability;
use serde::{Deserialize, Serialize};

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", ticket::Ticket::serialize(self))]
pub struct Ticket {
    /// either a public or private key
    pub capability: Capability,
    /// A list of nodes to contact.
    pub nodes: Vec<NodeAddr>,
}

#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Ticket),
}

impl ticket::Ticket for Ticket {
    fn kind() -> &'static str {
        "doc"
    }

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(self.clone());
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ticket::Error> {
        let res: TicketWireFormat = postcard::from_bytes(bytes).map_err(ticket::Error::Postcard)?;
        let res = match res {
            TicketWireFormat::Variant0(ticket) => ticket,
        };
        if res.nodes.is_empty() {
            return Err(ticket::Error::Verify("addressing info cannot be empty"));
        }
        Ok(res)
    }
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
    type Err = ticket::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}
