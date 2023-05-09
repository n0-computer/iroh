//! The ticket type for the provider.
//!
//! This is in it's own module to enforce the invariant that you can not construct a ticket
//! with an empty address list.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::util;
use crate::{Hash, PeerId};

/// A token containing everything to get a file from the provider.

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.  The [`Display`]
/// and [`FromStr`] implementations serialize to base64.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    /// The hash to retrieve.
    hash: Hash,
    /// The peer ID identifying the provider.
    peer: PeerId,
    /// The socket addresses the provider is listening on.
    ///
    /// This will never be empty.
    addrs: Vec<SocketAddr>,
}

impl Ticket {
    pub(super) fn new(hash: Hash, peer: PeerId, addrs: Vec<SocketAddr>) -> Result<Self> {
        ensure!(!addrs.is_empty(), "addrs list can not be empty");
        Ok(Self { hash, peer, addrs })
    }

    /// Deserializes from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let slf: Ticket = postcard::from_bytes(bytes)?;
        ensure!(!slf.addrs.is_empty(), "Invalid address list in ticket");
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

    /// The [`PeerId`] of the provider for this ticket.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// The addresses on which the provider can be reached.
    ///
    /// This is guaranteed to be non-empty.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

/// Serializes to base64.
impl Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = self.to_bytes();
        write!(f, "{}", util::encode(encoded))
    }
}

/// Deserializes from base64.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = util::decode(s)?;
        let slf = Self::from_bytes(&bytes)?;
        Ok(slf)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::Keypair;

    use super::*;

    #[test]
    fn test_ticket_base64_roundtrip() {
        let hash = blake3::hash(b"hi there");
        let hash = Hash::from(hash);
        let peer = PeerId::from(Keypair::generate().public());
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let ticket = Ticket {
            hash,
            peer,
            addrs: vec![addr],
        };
        let base64 = ticket.to_string();
        println!("Ticket: {base64}");
        println!("{} bytes", base64.len());

        let ticket2: Ticket = base64.parse().unwrap();
        assert_eq!(ticket2, ticket);
    }
}
