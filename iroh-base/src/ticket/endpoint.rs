//! Tickets for endpoints.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{Variant0AddrInfo, Variant0NodeAddr};
use crate::{
    endpoint_addr::EndpointAddr,
    ticket::{self, ParseError, Ticket},
};

/// A token containing information for establishing a connection to an endpoint.
///
/// Contains
/// - The [`EndpointId`] of the endpoint to connect to (a 32-byte ed25519 public key).
/// - If used, the ['RelayUrl`] of on which the endpoint can be reached.
/// - Any *direct addresses* on which the endpoint might be reachable.
///
/// This allows establishing a connection to the endpoint in most circumstances where it is
/// possible to do so.
///
/// This [`EndpointTicket`] is a single item which can be easily serialized and deserialized and
/// implements the [`Ticket`] trait.  The [`Display`] and [`FromStr`] traits can also be
/// used to round-trip the ticket to string.
///
/// [`EndpointId`]: crate::key::EndpointId
/// [`Display`]: std::fmt::Display
/// [`FromStr`]: std::str::FromStr
/// ['RelayUrl`]: crate::relay_url::RelayUrl
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", Ticket::serialize(self))]
pub struct EndpointTicket {
    node: EndpointAddr,
}

/// Wire format for [`EndpointTicket`].
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Variant0NodeTicket),
}

// Legacy
#[derive(Serialize, Deserialize)]
struct Variant0NodeTicket {
    node: Variant0NodeAddr,
}

impl Ticket for EndpointTicket {
    const KIND: &'static str = "node";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(Variant0NodeTicket {
            node: Variant0NodeAddr {
                node_id: self.node.id,
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
            node: EndpointAddr {
                endpoint_id: node.node_id,
                relay_url: node.info.relay_url,
                direct_addresses: node.info.direct_addresses,
            },
        })
    }
}

impl FromStr for EndpointTicket {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}

impl EndpointTicket {
    /// Creates a new ticket.
    pub fn new(node: EndpointAddr) -> Self {
        Self { node }
    }

    /// The [`EndpointAddr`] of the provider for this ticket.
    pub fn endpoint_addr(&self) -> &EndpointAddr {
        &self.node
    }
}

impl From<EndpointAddr> for EndpointTicket {
    /// Creates a ticket from given addressing info.
    fn from(addr: EndpointAddr) -> Self {
        Self { node: addr }
    }
}

impl From<EndpointTicket> for EndpointAddr {
    /// Returns the addressing info from given ticket.
    fn from(ticket: EndpointTicket) -> Self {
        ticket.node
    }
}

impl Serialize for EndpointTicket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let EndpointTicket { node } = self;
            (node).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for EndpointTicket {
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
    use rand::SeedableRng;

    use super::*;
    use crate::key::{PublicKey, SecretKey};

    fn make_ticket() -> EndpointTicket {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let peer = SecretKey::generate(&mut rng).public();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let relay_url = None;
        EndpointTicket {
            node: EndpointAddr::from_parts(peer, relay_url, [addr]),
        }
    }

    #[test]
    fn test_ticket_postcard() {
        let ticket = make_ticket();
        let bytes = postcard::to_stdvec(&ticket).unwrap();
        let ticket2: EndpointTicket = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_json() {
        let ticket = make_ticket();
        let json = serde_json::to_string(&ticket).unwrap();
        let ticket2: EndpointTicket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_base32() {
        let endpoint_id =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();

        let ticket = EndpointTicket {
            node: EndpointAddr::from_parts(
                endpoint_id,
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
