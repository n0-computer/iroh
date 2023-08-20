//! The ticket type for the provider.
//!
//! This is in it's own module to enforce the invariant that you can not construct a ticket
//! with an empty address list.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{ensure, Context, Result};
use iroh_bytes::protocol::RequestToken;
use iroh_bytes::Hash;
use iroh_net::derp::DerpMap;
use iroh_net::key::{PeerId, SecretKey};
use serde::{Deserialize, Serialize};

/// Options for the client
#[derive(Clone, Debug)]
pub struct Options {
    /// The secret key of the node
    pub secret_key: SecretKey,
    /// The addresses to connect to
    pub addrs: Vec<SocketAddr>,
    /// The peer id to dial
    pub peer_id: PeerId,
    /// Whether to log the SSL keys when `SSLKEYLOGFILE` environment variable is set
    pub keylog: bool,
    /// The configuration of the derp services
    pub derp_map: Option<DerpMap>,
    /// The DERP region of the node
    pub derp_region: Option<u16>,
}

/// Create a new endpoint and dial a peer, returning the connection
///
/// Note that this will create an entirely new endpoint, so it should be only
/// used for short lived connections. If you want to connect to multiple peers,
/// it is preferable to create an endpoint and use `connect` on the endpoint.
pub async fn dial(opts: Options) -> anyhow::Result<quinn::Connection> {
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(opts.secret_key)
        .derp_map(opts.derp_map)
        .keylog(opts.keylog)
        .bind(0)
        .await?;
    endpoint
        .connect(
            opts.peer_id,
            &iroh_bytes::protocol::ALPN,
            opts.derp_region,
            &opts.addrs,
        )
        .await
        .context("failed to connect to provider")
}

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.  The [`Display`]
/// and [`FromStr`] implementations serialize to base32.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    /// The hash to retrieve.
    hash: Hash,
    /// The peer ID identifying the provider.
    peer: PeerId,
    /// Optional Request token.
    token: Option<RequestToken>,
    /// The socket addresses the provider is listening on.
    ///
    /// This will never be empty.
    addrs: Vec<SocketAddr>,
    /// True to treat the hash as a collection and retrieve all blobs in it.
    recursive: bool,
    /// DERP region of the provider
    derp_region: Option<u16>,
}

impl Ticket {
    /// Creates a new ticket.
    pub fn new(
        hash: Hash,
        peer: PeerId,
        addrs: Vec<SocketAddr>,
        token: Option<RequestToken>,
        recursive: bool,
        derp_region: Option<u16>,
    ) -> Result<Self> {
        ensure!(!addrs.is_empty(), "addrs list can not be empty");
        Ok(Self {
            hash,
            peer,
            addrs,
            token,
            recursive,
            derp_region,
        })
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

    /// The [`RequestToken`] for this ticket.
    pub fn token(&self) -> Option<&RequestToken> {
        self.token.as_ref()
    }

    /// Set the [`RequestToken`] for this ticket.
    pub fn with_token(self, token: Option<RequestToken>) -> Self {
        Self { token, ..self }
    }

    /// True if the ticket is for a collection and should retrieve all blobs in it.
    pub fn recursive(&self) -> bool {
        self.recursive
    }

    /// Set recursive to for this ticket
    pub fn with_recursive(self, recursive: bool) -> Self {
        Self { recursive, ..self }
    }

    /// The addresses on which the provider can be reached.
    ///
    /// This is guaranteed to be non-empty.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// DERP region of the provider
    pub fn derp_region(&self) -> Option<u16> {
        self.derp_region
    }

    /// Get the contents of the ticket, consuming it.
    pub fn into_parts(
        self,
    ) -> (
        Hash,
        PeerId,
        Vec<SocketAddr>,
        Option<RequestToken>,
        bool,
        Option<u16>,
    ) {
        let Ticket {
            hash,
            peer,
            token,
            addrs,
            recursive,
            derp_region,
        } = self;
        (hash, peer, addrs, token, recursive, derp_region)
    }

    /// Convert this ticket into a [`Options`], adding the given secret key.
    pub fn as_get_options(&self, secret_key: SecretKey, derp_map: Option<DerpMap>) -> Options {
        Options {
            peer_id: self.peer,
            addrs: self.addrs.clone(),
            secret_key,
            keylog: true,
            derp_region: self.derp_region,
            derp_map,
        }
    }
}

/// Serializes to base32.
impl Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = self.to_bytes();
        let mut text = data_encoding::BASE32_NOPAD.encode(&encoded);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let slf = Self::from_bytes(&bytes)?;
        Ok(slf)
    }
}

#[cfg(test)]
mod tests {
    use bao_tree::blake3;

    use super::*;

    #[test]
    fn test_ticket_base32_roundtrip() {
        let hash = blake3::hash(b"hi there");
        let hash = Hash::from(hash);
        let peer = PeerId::from(SecretKey::generate().public());
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let token = RequestToken::new(vec![1, 2, 3, 4, 5, 6]).unwrap();
        let derp_region = Some(0);
        let ticket = Ticket {
            hash,
            peer,
            addrs: vec![addr],
            token: Some(token),
            recursive: true,
            derp_region,
        };
        let base32 = ticket.to_string();
        println!("Ticket: {base32}");
        println!("{} bytes", base32.len());

        let ticket2: Ticket = base32.parse().unwrap();
        assert_eq!(ticket2, ticket);
    }
}
