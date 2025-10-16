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
/// paths are needed.  The network paths can come from various sources:
///
/// - A [discovery] service which can provide routing information for a given [`EndpointId`].
///
/// - A [`RelayUrl`] of the endpoint's [home relay], this allows establishing the connection via
///   the Relay server and is very reliable.
///
/// - One or more *direct addresses* on which the endpoint might be reachable.  Depending on the
///   network location of both endpoints it might not be possible to establish a direct
///   connection without the help of a [Relay server].
///
/// This structure will always contain the required [`EndpointId`] and will contain an optional
/// number of network-level addressing information.  It is a generic addressing type used
/// whenever a connection to other endpoints needs to be established.
///
/// [discovery]: https://docs.rs/iroh/*/iroh/index.html#endpoint-discovery
/// [home relay]: https://docs.rs/iroh/*/iroh/relay/index.html
/// [Relay server]: https://docs.rs/iroh/*/iroh/index.html#relay-servers
#[derive(
    derive_more::Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct EndpointAddr {
    /// The endpoint's identifier.
    #[debug("{}", endpoint_id.fmt_short())]
    pub endpoint_id: EndpointId,
    /// The endpoint's home relay url.
    pub relay_url: Option<RelayUrl>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl EndpointAddr {
    /// Creates a new [`EndpointAddr`] with no `relay_url` and no `direct_addresses`.
    pub fn new(endpoint_id: EndpointId) -> Self {
        EndpointAddr {
            endpoint_id,
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

    /// Creates a new [`EndpointAddr`] from its parts.
    pub fn from_parts(
        endpoint_id: EndpointId,
        relay_url: Option<RelayUrl>,
        direct_addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        Self {
            endpoint_id,
            relay_url,
            direct_addresses: direct_addresses.into_iter().collect(),
        }
    }

    /// Returns true, if only a [`EndpointId`] is present.
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

impl From<(PublicKey, Option<RelayUrl>, &[SocketAddr])> for EndpointAddr {
    fn from(value: (PublicKey, Option<RelayUrl>, &[SocketAddr])) -> Self {
        let (endpoint_id, relay_url, direct_addresses_iter) = value;
        EndpointAddr {
            endpoint_id,
            relay_url,
            direct_addresses: direct_addresses_iter.iter().copied().collect(),
        }
    }
}

impl From<EndpointId> for EndpointAddr {
    fn from(endpoint_id: EndpointId) -> Self {
        EndpointAddr::new(endpoint_id)
    }
}
