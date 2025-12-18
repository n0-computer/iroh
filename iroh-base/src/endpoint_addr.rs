//! Addressing for iroh endpoints.
//!
//! This module contains some common addressing types for iroh.  An endpoint is uniquely
//! identified by the [`EndpointId`] but that does not make it addressable on the network layer.
//! For this the addition of a [`RelayUrl`] and/or direct addresses are required.
//!
//! The primary way of addressing an endpoint is by using the [`EndpointAddr`].

use std::{collections::BTreeSet, net::SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{EndpointId, PublicKey, RelayUrl};

/// Network-level addressing information for an iroh endpoint.
///
/// This combines an endpoint's identifier with network-level addressing information of how to
/// contact the endpoint.
///
/// To establish a network connection to an endpoint both the [`EndpointId`] and one or more network
/// paths are needed.  The network paths can come from various sources, current sources can come from
///
/// - A [discovery] service which can provide routing information for a given [`EndpointId`].
///
/// - A [`RelayUrl`] of the endpoint's [home relay], this allows establishing the connection via
///   the Relay server and is very reliable.
///
/// - One or more *IP based addresses* on which the endpoint might be reachable.  Depending on the
///   network location of both endpoints it might not be possible to establish a direct
///   connection without the help of a [Relay server].
///
/// This structure will always contain the required [`EndpointId`] and will contain an optional
/// number of other addressing information.  It is a generic addressing type used whenever a connection
/// to other endpoints needs to be established.
///
/// [discovery]: https://docs.rs/iroh/*/iroh/index.html#endpoint-discovery
/// [home relay]: https://docs.rs/iroh/*/iroh/relay/index.html
/// [Relay server]: https://docs.rs/iroh/*/iroh/index.html#relay-servers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointAddr {
    /// The endpoint's identifier.
    pub id: EndpointId,
    /// The endpoint's addresses
    pub addrs: BTreeSet<TransportAddr>,
}

/// Available address types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TransportAddr {
    /// Relays
    Relay(RelayUrl),
    /// IP based addresses
    Ip(SocketAddr),
}

impl TransportAddr {
    /// Whether this is a transport address via a relay server.
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(_))
    }

    /// Whether this is an IP transport address.
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }
}

impl EndpointAddr {
    /// Creates a new [`EndpointAddr`] with no network level addresses.
    ///
    /// This still is usable with e.g. a discovery service to establish a connection,
    /// depending on the situation.
    pub fn new(id: PublicKey) -> Self {
        EndpointAddr {
            id,
            addrs: Default::default(),
        }
    }

    /// Creates a new [`EndpointAddr`] from its parts.
    pub fn from_parts(id: PublicKey, addrs: impl IntoIterator<Item = TransportAddr>) -> Self {
        Self {
            id,
            addrs: addrs.into_iter().collect(),
        }
    }

    /// Adds a [`RelayUrl`] address.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.addrs.insert(TransportAddr::Relay(relay_url));
        self
    }

    /// Adds an IP based address.
    pub fn with_ip_addr(mut self, addr: SocketAddr) -> Self {
        self.addrs.insert(TransportAddr::Ip(addr));
        self
    }

    /// Adds a list of addresses.
    pub fn with_addrs(mut self, addrs: impl IntoIterator<Item = TransportAddr>) -> Self {
        for addr in addrs.into_iter() {
            self.addrs.insert(addr);
        }
        self
    }

    /// Returns true, if only a [`EndpointId`] is present.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Returns a list of IP addresses of this peer.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Ip(addr) => Some(addr),
            _ => None,
        })
    }

    /// Returns a list of relay urls of this peer.
    ///
    ///  In practice this is expected to be zero or one home relay for all known cases currently.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(url) => Some(url),
            _ => None,
        })
    }
}

impl From<EndpointId> for EndpointAddr {
    fn from(endpoint_id: EndpointId) -> Self {
        EndpointAddr::new(endpoint_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    enum NewAddrType {
        /// Relays
        Relay(RelayUrl),
        /// IP based addresses
        Ip(SocketAddr),
        /// New addr type for testing
        Cool(u16),
    }

    #[test]
    fn test_roundtrip_new_addr_type() {
        let old = vec![
            TransportAddr::Ip("127.0.0.1:9".parse().unwrap()),
            TransportAddr::Relay("https://example.com".parse().unwrap()),
        ];
        let old_ser = postcard::to_stdvec(&old).unwrap();
        let old_back: Vec<TransportAddr> = postcard::from_bytes(&old_ser).unwrap();
        assert_eq!(old, old_back);

        let new = vec![
            NewAddrType::Ip("127.0.0.1:9".parse().unwrap()),
            NewAddrType::Relay("https://example.com".parse().unwrap()),
            NewAddrType::Cool(4),
        ];
        let new_ser = postcard::to_stdvec(&new).unwrap();
        let new_back: Vec<NewAddrType> = postcard::from_bytes(&new_ser).unwrap();

        assert_eq!(new, new_back);

        // serialize old into new
        let old_new_back: Vec<NewAddrType> = postcard::from_bytes(&old_ser).unwrap();

        assert_eq!(
            old_new_back,
            vec![
                NewAddrType::Ip("127.0.0.1:9".parse().unwrap()),
                NewAddrType::Relay("https://example.com".parse().unwrap()),
            ]
        );
    }
}
