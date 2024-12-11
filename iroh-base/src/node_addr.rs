//! Addressing for iroh nodes.
//!
//! This module contains some common addressing types for iroh.  A node is uniquely
//! identified by the [`NodeId`] but that does not make it addressable on the network layer.
//! For this the addition of a [`RelayUrl`] and/or direct addresses are required.
//!
//! The primary way of addressing a node is by using the [`NodeAddr`].

use std::{collections::BTreeSet, net::SocketAddr};

use serde::{Deserialize, Serialize};

use crate::key::{NodeId, PublicKey};
pub use crate::relay_url::RelayUrl;

/// Network-level addressing information for an iroh node.
///
/// This combines a node's identifier with network-level addressing information of how to
/// contact the node.
///
/// To establish a network connection to a node both the [`NodeId`] and one or more network
/// paths are needed.  The network paths can come from various sources:
///
/// - A [discovery] service which can provide routing information for a given [`NodeId`].
///
/// - A [`RelayUrl`] of the node's [home relay], this allows establishing the connection via
///   the Relay server and is very reliable.
///
/// - One or more *direct addresses* on which the node might be reachable.  Depending on the
///   network location of both nodes it might not be possible to establish a direct
///   connection without the help of a [Relay server].
///
/// This structure will always contain the required [`NodeId`] and will contain an optional
/// number of network-level addressing information.  It is a generic addressing type used
/// whenever a connection to other nodes needs to be established.
///
/// [discovery]: https://docs.rs/iroh/*/iroh/index.html#node-discovery
/// [home relay]: https://docs.rs/iroh/*/iroh/relay/index.html
/// [Relay server]: https://docs.rs/iroh/*/iroh/index.html#relay-servers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeAddr {
    /// The node's identifier.
    pub node_id: NodeId,
    /// The node's home relay url.
    pub relay_url: Option<RelayUrl>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl NodeAddr {
    /// Creates a new [`NodeAddr`] with no `relay_url` and no `direct_addresses`.
    pub fn new(node_id: PublicKey) -> Self {
        NodeAddr {
            node_id,
            relay_url: None,
            direct_addresses: Default::default(),
        }
    }

    /// Adds a relay url.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.relay_url = Some(relay_url);
        self
    }

    /// Adds the given direct addresses.
    pub fn with_direct_addresses(
        mut self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        self.direct_addresses = addresses.into_iter().collect();
        self
    }

    /// Creates a new [`NodeAddr`] from its parts.
    pub fn from_parts(
        node_id: PublicKey,
        relay_url: Option<RelayUrl>,
        direct_addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            relay_url,
            direct_addresses: direct_addresses.into_iter().collect(),
        }
    }

    /// Returns true, if only a [`NodeId`] is present.
    pub fn is_empty(&self) -> bool {
        self.relay_url.is_none() && self.direct_addresses.is_empty()
    }

    /// Returns the direct addresses of this peer.
    pub fn direct_addresses(&self) -> impl Iterator<Item = &SocketAddr> {
        self.direct_addresses.iter()
    }

    /// Returns the relay url of this peer.
    pub fn relay_url(&self) -> Option<&RelayUrl> {
        self.relay_url.as_ref()
    }
}

impl From<(PublicKey, Option<RelayUrl>, &[SocketAddr])> for NodeAddr {
    fn from(value: (PublicKey, Option<RelayUrl>, &[SocketAddr])) -> Self {
        let (node_id, relay_url, direct_addresses_iter) = value;
        NodeAddr {
            node_id,
            relay_url,
            direct_addresses: direct_addresses_iter.iter().copied().collect(),
        }
    }
}

impl From<NodeId> for NodeAddr {
    fn from(node_id: NodeId) -> Self {
        NodeAddr::new(node_id)
    }
}
