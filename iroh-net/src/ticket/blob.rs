//! Tickets for blobs.
use std::str::FromStr;

use anyhow::{ensure, Result};
use iroh_base::{
    hash::{BlobFormat, Hash},
    ticket::{Error as TicketError, Ticket as IrohTicket},
};
use serde::{Deserialize, Serialize};

use crate::NodeAddr;

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", IrohTicket::serialize(self))]
pub struct Ticket {
    /// The provider to get a file from.
    node: NodeAddr,
    /// The format of the blob.
    format: BlobFormat,
    /// The hash to retrieve.
    hash: Hash,
}

#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Ticket),
}

impl IrohTicket for Ticket {
    fn kind() -> &'static str {
        "blob"
    }

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(self.clone());
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, TicketError> {
        let res: TicketWireFormat = postcard::from_bytes(bytes).map_err(TicketError::Postcard)?;
        let res = match res {
            TicketWireFormat::Variant0(ticket) => ticket,
        };
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
        let Ticket { node, hash, format } = self;
        (node, hash, format)
    }
}

impl Serialize for Ticket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let Ticket { node, format, hash } = self;
            (node, format, hash).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Ticket {
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

    fn make_ticket() -> Ticket {
        let hash = Hash::new(b"hi there");
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let derp_url = None;
        Ticket {
            hash,
            node: NodeAddr::from_parts(peer, derp_url, vec![addr]),
            format: BlobFormat::HashSeq,
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

    #[test]
    fn test_ticket_base32() {
        let hash = Hash::from_bytes(
            <[u8; 32]>::try_from(
                hex::decode("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
                    .unwrap(),
            )
            .unwrap(),
        );
        let node_id = PublicKey::from_bytes(
            &<[u8; 32]>::try_from(
                hex::decode("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let ticket = Ticket {
            hash,
            format: BlobFormat::Raw,
            node: NodeAddr::from_parts(node_id, None, vec![]),
        };
        let base32 = base32::parse_vec(ticket.to_string().strip_prefix("blob").unwrap()).unwrap();
        let expected = parse_hexdump("
            00 # discriminator for variant 0
            ae 58 ff 88 33 24 1a c8 2d 6f f7 61 10 46 ed 67 b5 07 2d 14 2c 58 8d 00 63 e9 42 d9 a7 55 02 b6 # node id
            00 # derp url
            00 # number of addresses (0)
            00 # what even is this?
            0b 84 d3 58 e4 c8 be 6c 38 62 6b 21 82 ff 57 58 18 ba 6b d3 f4 b9 04 64 99 4b e1 4c b3 54 a0 72 # hash        
        ").unwrap();
        assert_eq_hex!(base32, expected);
    }
}
