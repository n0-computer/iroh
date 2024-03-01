//! Tickets for nodes.

use std::str::FromStr;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{
    node_addr::NodeAddr,
    ticket::{self, Ticket},
};

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", Ticket::serialize(self))]
pub struct NodeTicket {
    node: NodeAddr,
}

/// Wire format for [`NodeTicket`].
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(NodeTicket),
}

impl Ticket for NodeTicket {
    const KIND: &'static str = "node";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(self.clone());
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, ticket::Error> {
        let res: TicketWireFormat = postcard::from_bytes(bytes).map_err(ticket::Error::Postcard)?;
        let TicketWireFormat::Variant0(res) = res;
        if res.node.info.is_empty() {
            return Err(ticket::Error::Verify("addressing info cannot be empty"));
        }
        Ok(res)
    }
}

impl FromStr for NodeTicket {
    type Err = ticket::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}

impl NodeTicket {
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

impl Serialize for NodeTicket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let NodeTicket { node } = self;
            (node).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for NodeTicket {
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
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    use crate::base32;
    use crate::key::{PublicKey, SecretKey};

    use super::*;

    fn make_ticket() -> NodeTicket {
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let derp_url = None;
        NodeTicket {
            node: NodeAddr::from_parts(peer, derp_url, vec![addr]),
        }
    }

    #[test]
    fn test_ticket_postcard() {
        let ticket = make_ticket();
        let bytes = postcard::to_stdvec(&ticket).unwrap();
        let ticket2: NodeTicket = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_json() {
        let ticket = make_ticket();
        let json = serde_json::to_string(&ticket).unwrap();
        let ticket2: NodeTicket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_base32() {
        let node_id =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();

        let ticket = NodeTicket {
            node: NodeAddr::from_parts(
                node_id,
                Some("http://derp.me./".parse().unwrap()),
                vec!["127.0.0.1:1024".parse().unwrap()],
            ),
        };
        let base32 = base32::parse_vec(ticket.to_string().strip_prefix("node").unwrap()).unwrap();
        let expected = parse_hexdump("
            00 # variant
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # node id, 32 bytes, see above
            01 # derp url present
            10 687474703a2f2f646572702e6d652e2f # derp url, 16 bytes, see above
            01 # one direct address
            00 # ipv4
            7f000001 8008 # address, see above
        ").unwrap();
        assert_eq_hex!(base32, expected);
    }
}
