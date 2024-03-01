//! Tickets for blobs.
use std::str::FromStr;

use anyhow::{ensure, Result};
use crate::{
    hash::{BlobFormat, Hash},
    ticket::{self, Ticket},
};
use serde::{Deserialize, Serialize};

use crate::node_addr::NodeAddr;

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", Ticket::serialize(self))]
pub struct BlobTicket {
    /// The provider to get a file from.
    node: NodeAddr,
    /// The format of the blob.
    format: BlobFormat,
    /// The hash to retrieve.
    hash: Hash,
}

/// Wire format for [`BlobTicket`].
///
/// In the future we might have multiple variants (not versions, since they
/// might be both equally valid), so this is a single variant enum to force
/// postcard to add a discriminator.
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(BlobTicket),
}

impl Ticket for BlobTicket {
    const KIND: &'static str = "blob";

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

impl FromStr for BlobTicket {
    type Err = ticket::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ticket::deserialize(s)
    }
}

impl BlobTicket {
    /// Creates a new ticket.
    pub fn new(node: NodeAddr, hash: Hash, format: BlobFormat) -> Result<Self> {
        ensure!(!node.info.is_empty(), "addressing info cannot be empty");
        Ok(Self { hash, format, node })
    }

    /// The hash of the item this ticket can retrieve.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// The [`NodeAddr`] of the provider for this ticket.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node
    }

    /// The [`BlobFormat`] for this ticket.
    pub fn format(&self) -> BlobFormat {
        self.format
    }

    /// True if the ticket is for a collection and should retrieve all blobs in it.
    pub fn recursive(&self) -> bool {
        self.format.is_hash_seq()
    }

    /// Get the contents of the ticket, consuming it.
    pub fn into_parts(self) -> (NodeAddr, Hash, BlobFormat) {
        let BlobTicket { node, hash, format } = self;
        (node, hash, format)
    }
}

impl Serialize for BlobTicket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let BlobTicket { node, format, hash } = self;
            (node, format, hash).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BlobTicket {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let (peer, format, hash) = Deserialize::deserialize(deserializer)?;
            Self::new(peer, hash, format).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::base32;
    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    use crate::key::{PublicKey, SecretKey};
    use std::net::SocketAddr;

    use super::*;

    fn make_ticket() -> BlobTicket {
        let hash = Hash::new(b"hi there");
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let derp_url = None;
        BlobTicket {
            hash,
            node: NodeAddr::from_parts(peer, derp_url, vec![addr]),
            format: BlobFormat::HashSeq,
        }
    }

    #[test]
    fn test_ticket_postcard() {
        let ticket = make_ticket();
        let bytes = postcard::to_stdvec(&ticket).unwrap();
        let ticket2: BlobTicket = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_json() {
        let ticket = make_ticket();
        let json = serde_json::to_string(&ticket).unwrap();
        let ticket2: BlobTicket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_base32() {
        let hash =
            Hash::from_str("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
                .unwrap();
        let node_id =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();

        let ticket = BlobTicket {
            node: NodeAddr::from_parts(node_id, None, vec![]),
            format: BlobFormat::Raw,
            hash,
        };
        let base32 = base32::parse_vec(ticket.to_string().strip_prefix("blob").unwrap()).unwrap();
        let expected = parse_hexdump("
            00 # discriminator for variant 0
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # node id, 32 bytes, see above
            00 # derp url
            00 # number of addresses (0)
            00 # format (raw)
            0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072 # hash, 32 bytes, see above
        ").unwrap();
        assert_eq_hex!(base32, expected);
    }
}
