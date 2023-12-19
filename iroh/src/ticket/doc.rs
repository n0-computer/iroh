//! Tickets for [`iroh-sync`] documents.

use iroh_base::ticket;
use iroh_net::NodeAddr;
use iroh_sync::Capability;
use serde::{Deserialize, Serialize};

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", ticket::Ticket::serialize(self))]
pub struct DocTicket {
    /// either a public or private key
    pub capability: Capability,
    /// A list of nodes to contact.
    pub nodes: Vec<NodeAddr>,
}

/// Wire format for [`Ticket`].
///
/// In the future we might have multiple variants (not versions, since they
/// might be both equally valid), so this is a single variant enum to force
/// postcard to add a discriminator.
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(DocTicket),
}

impl ticket::Ticket for DocTicket {
    const KIND: &'static str = "doc";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(self.clone());
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ticket::Error> {
        let res: TicketWireFormat = postcard::from_bytes(bytes).map_err(ticket::Error::Postcard)?;
        let TicketWireFormat::Variant0(res) = res;
        if res.nodes.is_empty() {
            return Err(ticket::Error::Verify("addressing info cannot be empty"));
        }
        Ok(res)
    }
}

impl DocTicket {
    /// Create a new doc ticket
    pub fn new(capability: Capability, peers: Vec<NodeAddr>) -> Self {
        Self {
            capability,
            nodes: peers,
        }
    }
}

impl std::str::FromStr for DocTicket {
    type Err = ticket::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::base32;
    use iroh_net::key::PublicKey;
    use iroh_sync::{Capability, NamespaceId};
    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    #[test]
    fn test_ticket_base32() {
        let node_id = PublicKey::from_bytes(
            &<[u8; 32]>::try_from(
                hex::decode("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let namespace_id = NamespaceId::from(
            &<[u8; 32]>::try_from(
                hex::decode("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                    .unwrap(),
            )
            .unwrap(),
        );

        let ticket = DocTicket {
            capability: Capability::Read(namespace_id),
            nodes: vec![NodeAddr::from_parts(node_id, None, vec![])],
        };
        let base32 = base32::parse_vec(ticket.to_string().strip_prefix("doc").unwrap()).unwrap();
        let expected = parse_hexdump("
            00 # variant
            01 # capability discriminator, 1 = read
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # namespace id, 32 bytes, see above
            01 # one node
            20 # length prefix (this needs to go away)
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # node id, 32 bytes, see above
            00 # no derp url
            00 # no direct addresses
        ").unwrap();
        assert_eq_hex!(base32, expected);
    }
}
