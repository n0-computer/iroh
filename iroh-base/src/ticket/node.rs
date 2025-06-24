//! Tickets for nodes.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{Variant0AddrInfo, Variant0NodeAddr};
use crate::{
    node_addr::NodeAddr,
    ticket::{self, ParseError, Ticket},
};

/// A token containing information for establishing a connection to a node.
///
/// Contains
/// - The [`NodeId`] of the node to connect to (a 32-byte ed25519 public key).
/// - If used, the ['RelayUrl`] of on which the node can be reached.
/// - Any *direct addresses* on which the node might be reachable.
///
/// This allows establishing a connection to the node in most circumstances where it is
/// possible to do so.
///
/// This [`NodeTicket`] is a single item which can be easily serialized and deserialized and
/// implements the [`Ticket`] trait.  The [`Display`] and [`FromStr`] traits can also be
/// used to round-trip the ticket to string.
///
/// [`NodeId`]: crate::key::NodeId
/// [`Display`]: std::fmt::Display
/// [`FromStr`]: std::str::FromStr
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", Ticket::serialize(self))]
pub struct NodeTicket {
    node: NodeAddr,
}

/// Wire format for [`NodeTicket`].
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Variant0NodeTicket),
}

// Legacy
#[derive(Serialize, Deserialize)]
struct Variant0NodeTicket {
    node: Variant0NodeAddr,
}

impl Ticket for NodeTicket {
    const KIND: &'static str = "node";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(Variant0NodeTicket {
            node: Variant0NodeAddr {
                node_id: self.node.node_id,
                info: Variant0AddrInfo {
                    relay_url: self.node.relay_url.clone(),
                    direct_addresses: self.node.direct_addresses.clone(),
                },
            },
        });
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let res: TicketWireFormat = postcard::from_bytes(bytes)?;
        let TicketWireFormat::Variant0(Variant0NodeTicket { node }) = res;
        Ok(Self {
            node: NodeAddr {
                node_id: node.node_id,
                relay_url: node.info.relay_url,
                direct_addresses: node.info.direct_addresses,
            },
        })
    }
}

impl FromStr for NodeTicket {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}

impl NodeTicket {
    /// Creates a new ticket.
    pub fn new(node: NodeAddr) -> Self {
        Self { node }
    }

    /// The [`NodeAddr`] of the provider for this ticket.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node
    }
}

impl From<NodeAddr> for NodeTicket {
    /// Creates a ticket from given addressing info.
    fn from(addr: NodeAddr) -> Self {
        Self { node: addr }
    }
}

impl From<NodeTicket> for NodeAddr {
    /// Returns the addressing info from given ticket.
    fn from(ticket: NodeTicket) -> Self {
        ticket.node
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
            Ok(Self::new(peer))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use data_encoding::HEXLOWER;

    use super::*;
    use crate::key::{PublicKey, SecretKey};

    fn make_ticket() -> NodeTicket {
        let peer = SecretKey::generate(&mut rand::thread_rng()).public();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let relay_url = None;
        NodeTicket {
            node: NodeAddr::from_parts(peer, relay_url, [addr]),
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
                ["127.0.0.1:1024".parse().unwrap()],
            ),
        };
        let base32 = data_encoding::BASE32_NOPAD
            .decode(
                ticket
                    .to_string()
                    .strip_prefix("node")
                    .unwrap()
                    .to_ascii_uppercase()
                    .as_bytes(),
            )
            .unwrap();
        let expected = [
            // variant
            "00",
            // node id, 32 bytes, see above
            "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6",
            // relay url present
            "01",
            // relay url, 16 bytes, see above
            "10",
            "687474703a2f2f646572702e6d652e2f",
            // one direct address
            "01",
            // ipv4
            "00",
            // address, see above
            "7f0000018008",
        ];
        let expected = HEXLOWER.decode(expected.concat().as_bytes()).unwrap();
        assert_eq!(base32, expected);
    }
}
