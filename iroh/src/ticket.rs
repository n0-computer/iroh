//! This module manages the different tickets Iroh has.

use anyhow::{ensure, Result};
use iroh_bytes::{protocol::RequestToken, BlobFormat, Hash};
use iroh_net::PeerAddr;
use serde::{Deserialize, Serialize};

/// Kind of ticket
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum TicketKind {
    Blob,
    Doc,
    Peer,
}

trait IrohTicket<'de>: Serialize + Deserialize<'de> {
    const KIND: TicketKind;
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard::to_stdvec is infallible")
    }
}

fn serialize<'de, T: IrohTicket<'de>>(ticket: &T) -> String {
    let mut out = IrohTicket::KIND.to_string();
    let bytes = ticket.to_bytes();
    ticket.encode_append(&bytes, &mut out);
    out
}


/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.  The [`Display`]
/// and [`FromStr`] implementations serialize to base32.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobTicket {
    /// The provider to get a file from.
    peer: PeerAddr,
    /// The format of the blob.
    format: BlobFormat,
    /// The hash to retrieve.
    hash: Hash,
    /// Optional Request token.
    token: Option<RequestToken>,
}

impl BlobTicket {
    const OPT_PREFIX: &'static str = "blob:";
    /// Creates a new ticket.
    pub fn new(
        peer: PeerAddr,
        hash: Hash,
        format: BlobFormat,
        token: Option<RequestToken>,
    ) -> Result<Self> {
        ensure!(!peer.is_empty(), "addressing information cannot be empty");
        Ok(Self {
            hash,
            format,
            peer,
            token,
        })
    }

    /// Deserializes from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let slf: BlobTicket = postcard::from_bytes(bytes)?;
        ensure!(!slf.is_empty(), "Invalid addressing info in ticket");
        Ok(slf)
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }

    /// The hash of the item this ticket can retrieve.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// The [`PeerAddr`] of the provider for this ticket.
    pub fn node_addr(&self) -> &PeerAddr {
        &self.peer
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
    pub fn into_parts(self) -> (PeerAddr, Hash, BlobFormat, Option<RequestToken>) {
        let Self {
            peer,
            hash,
            format,
            token,
        } = self;
        (peer, hash, format, token)
    }
}

/*
/// Serializes to base32.
impl Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.to_bytes();
        let mut out = Self::OPT_PREFIX.to_string();
        data_encoding::BASE32_NOPAD.encode_append(&bytes, &mut out);
        out.make_ascii_lowercase();
        write!(f, "{out}",)
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(Self::OPT_PREFIX)
            .unwrap_or(s)
            .to_ascii_uppercase();
        let bytes = data_encoding::BASE32_NOPAD.decode(s.as_bytes())?;
        Self::from_bytes(&bytes)
    }
}
*/
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bao_tree::blake3;

    use super::*;

    #[test]
    fn test_ticket_base32_roundtrip() {
        let hash = blake3::hash(b"hi there");
        let hash = Hash::from(hash);
        let peer = SecretKey::generate().public();
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let token = RequestToken::new(vec![1, 2, 3, 4, 5, 6]).unwrap();
        let derp_region = Some(0);
        let ticket = Ticket {
            hash,
            peer: PeerAddr::from_parts(peer, derp_region, vec![addr]),
            token: Some(token),
            format: BlobFormat::HashSeq,
        };
        let base32 = ticket.to_string();
        println!("Ticket: {base32}");
        println!("{} bytes", base32.len());

        let ticket2: Ticket = base32.parse().unwrap();
        assert_eq!(ticket2, ticket);
    }
}
