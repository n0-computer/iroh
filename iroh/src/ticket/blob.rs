//! Tickets for blobs.

use std::str::FromStr;

use anyhow::{ensure, Result};
use iroh_bytes::{protocol::RequestToken, BlobFormat, Hash};
use iroh_net::{derp::DerpMap, key::SecretKey, NodeAddr};
use serde::{Deserialize, Serialize};

use crate::dial::Options;

use super::*;

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
    /// Optional Request token.
    token: Option<RequestToken>,
}

impl IrohTicket for Ticket {
    const KIND: Kind = Kind::Blob;

    fn verify(&self) -> std::result::Result<(), &'static str> {
        if self.node.info.is_empty() {
            return Err("addressing info cannot be empty");
        }
        Ok(())
    }
}

impl FromStr for Ticket {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IrohTicket::deserialize(s)
    }
}

impl Ticket {
    /// Creates a new ticket.
    pub fn new(
        peer: NodeAddr,
        hash: Hash,
        format: BlobFormat,
        token: Option<RequestToken>,
    ) -> Result<Self> {
        ensure!(!peer.info.is_empty(), "addressing info cannot be empty");
        Ok(Self {
            hash,
            format,
            node: peer,
            token,
        })
    }

    /// The hash of the item this ticket can retrieve.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// The [`NodeAddr`] of the provider for this ticket.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node
    }

    /// The [`RequestToken`] for this ticket.
    pub fn token(&self) -> Option<&RequestToken> {
        self.token.as_ref()
    }

    /// The [`BlobFormat`] for this ticket.
    pub fn format(&self) -> BlobFormat {
        self.format
    }

    /// Set the [`RequestToken`] for this ticket.
    pub fn with_token(self, token: Option<RequestToken>) -> Self {
        Self { token, ..self }
    }

    /// True if the ticket is for a collection and should retrieve all blobs in it.
    pub fn recursive(&self) -> bool {
        self.format.is_hash_seq()
    }

    /// Get the contents of the ticket, consuming it.
    pub fn into_parts(self) -> (NodeAddr, Hash, BlobFormat, Option<RequestToken>) {
        let Ticket {
            node: peer,
            hash,
            format,
            token,
        } = self;
        (peer, hash, format, token)
    }

    /// Convert this ticket into a [`Options`], adding the given secret key.
    pub fn as_get_options(&self, secret_key: SecretKey, derp_map: Option<DerpMap>) -> Options {
        Options {
            peer: self.node.clone(),
            secret_key,
            keylog: true,
            derp_map,
        }
    }
}

impl Serialize for Ticket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let Ticket {
                node,
                format,
                hash,
                token,
            } = self;
            (node, format, hash, token).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Ticket {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let (peer, format, hash, token) = Deserialize::deserialize(deserializer)?;
            Self::new(peer, hash, format, token).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bao_tree::blake3;

    use super::*;

    fn make_ticket() -> Ticket {
        let hash = blake3::hash(b"hi there");
        let hash = Hash::from(hash);
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let token = RequestToken::new(vec![1, 2, 3, 4, 5, 6]).unwrap();
        let derp_region = Some(0);
        Ticket {
            hash,
            node: NodeAddr::from_parts(peer, derp_region, vec![addr]),
            token: Some(token),
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
}
