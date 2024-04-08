//! DNS node discovery for iroh-net

use crate::{
    discovery::{Discovery, DiscoveryItem},
    MagicEndpoint, NodeId,
};
use anyhow::Result;
use futures::{future::FutureExt, stream::BoxStream, StreamExt};

use crate::dns;

/// The n0 testing DNS node origin
pub const N0_TESTDNS_NODE_ORIGIN: &str = "testdns.iroh.link";

/// DNS node discovery
///
/// When asked to resolve a [`NodeId`], this service performs a lookup in the Domain Name System (DNS).
///
/// It uses the [`MagicEndpoint`]'s DNS resolver to query for `TXT` records under the domain
/// `_iroh.<z32-node-id>.<origin-domain>`:
///
/// * `_iroh`: is the record name
/// * `<z32-node-id>` is the [`NodeId`] encoded in [`z-base-32`] format
/// * `<origin-domain>` is the node origin domain as set in [`DnsDiscovery::new`].
///
/// Each TXT record returned from the query is expected to contain a string in the format `<name>=<value>`.
/// If a TXT record contains multiple character strings, they are concatenated first.
/// The supported attributes are:
/// * `relay=<url>`: The URL of the home relay server of the node
///
/// The DNS resolver defaults to using the nameservers configured on the host system, but can be changed
/// with [`crate::magic_endpoint::MagicEndpointBuilder::dns_resolver`].
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
#[derive(Debug)]
pub struct DnsDiscovery {
    origin_domain: String,
}

impl DnsDiscovery {
    /// Create a new DNS discovery.
    pub fn new(origin_domain: String) -> Self {
        Self { origin_domain }
    }

    /// Create a new DNS discovery which uses the [`N0_TESTDNS_NODE_ORIGIN`] origin domain.
    pub fn n0_testdns() -> Self {
        Self::new(N0_TESTDNS_NODE_ORIGIN.to_string())
    }
}

impl Discovery for DnsDiscovery {
    fn resolve(
        &self,
        ep: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'_, Result<DiscoveryItem>>> {
        let resolver = ep.dns_resolver().clone();
        let fut = async move {
            let node_addr =
                dns::node_info::lookup_by_id(&resolver, &node_id, &self.origin_domain).await?;
            Ok(DiscoveryItem {
                provenance: "dns",
                last_updated: None,
                addr_info: node_addr.info,
            })
        };
        Some(fut.into_stream().boxed())
    }
}
