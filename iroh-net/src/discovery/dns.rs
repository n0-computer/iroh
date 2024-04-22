//! DNS node discovery for iroh-net

use anyhow::Result;
use futures_lite::stream::Boxed as BoxStream;

use crate::{
    discovery::{Discovery, DiscoveryItem},
    dns, MagicEndpoint, NodeId,
};

/// The n0 testing DNS node origin
pub const N0_DNS_NODE_ORIGIN: &str = "dns.iroh.link";

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

    /// Create a new DNS discovery which uses the [`N0_DNS_NODE_ORIGIN`] origin domain.
    pub fn n0_dns() -> Self {
        Self::new(N0_DNS_NODE_ORIGIN.to_string())
    }
}

impl Discovery for DnsDiscovery {
    fn resolve(
        &self,
        ep: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let resolver = ep.dns_resolver().clone();
        let origin_domain = self.origin_domain.clone();
        let fut = async move {
            let node_addr =
                dns::node_info::lookup_by_id(&resolver, &node_id, &origin_domain).await?;
            Ok(DiscoveryItem {
                provenance: "dns",
                last_updated: None,
                addr_info: node_addr.info,
            })
        };
        let stream = futures_lite::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}
