//! Tickets for nodes.

use std::str::FromStr;

use anyhow::{ensure, Result};
use iroh_base::ticket::{Error as TicketError, Ticket as IrohTicket};
use serde::{Deserialize, Serialize};

use crate::NodeAddr;

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", IrohTicket::serialize(self))]
pub struct Ticket {
    node: NodeAddr,
}

impl IrohTicket for Ticket {
    fn kind() -> &'static str {
        "node"
    }

    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, TicketError> {
        let res: Self = postcard::from_bytes(bytes).map_err(TicketError::Postcard)?;
        if res.node.info.is_empty() {
            return Err(TicketError::Verify("addressing info cannot be empty"));
        }
        Ok(res)
    }
}

impl FromStr for Ticket {
    type Err = TicketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IrohTicket::deserialize(s)
    }
}

impl Ticket {
    /// Creates a new ticket.
    pub fn new(node: NodeAddr) -> Result<Self> {
        ensure!(!node.info.is_empty(), "addressing info cannot be empty");
        Ok(Self { node })
    }

    /// The [`NodeAddr`] of the provider for this ticket.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node
    }
}

impl Serialize for Ticket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let Ticket { node } = self;
            (node).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Ticket {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let peer = Deserialize::deserialize(deserializer)?;
            Self::new(peer).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::key::SecretKey;
    use std::net::SocketAddr;

    use super::*;

    fn make_ticket() -> Ticket {
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let derp_url = None;
        Ticket {
            node: NodeAddr::from_parts(peer, derp_url, vec![addr]),
        }
    }

    #[test]
    fn test_ticket_postcard() {
        let ticket = make_ticket();
        let bytes = postcard::to_stdvec(&ticket).unwrap();
        let ticket2: Ticket = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_json() {
        let ticket = make_ticket();
        let json = serde_json::to_string(&ticket).unwrap();
        let ticket2: Ticket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_base32_roundtrip() {
        let ticket = make_ticket();
        let base32 = ticket.to_string();
        println!("Ticket: {base32}");
        println!("{} bytes", base32.len());

        let ticket2: Ticket = base32.parse().unwrap();
        assert_eq!(ticket2, ticket);
    }
}
