//! DNS node discovery for iroh

use anyhow::Result;
use iroh_base::NodeId;
use iroh_relay::dns::DnsResolver;
pub use iroh_relay::dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING};
use n0_future::boxed::BoxStream;

use super::IntoDiscovery;
use crate::{
    discovery::{Discovery, DiscoveryItem},
    endpoint::force_staging_infra,
    Endpoint,
};

const DNS_STAGGERING_MS: &[u64] = &[200, 300];

/// DNS node discovery
///
/// When asked to resolve a [`NodeId`], this service performs a lookup in the Domain Name System (DNS).
///
/// It uses the [`Endpoint`]'s DNS resolver to query for `TXT` records under the domain
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
/// with [`crate::endpoint::Builder::dns_resolver`].
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
#[derive(Debug)]
pub struct DnsDiscovery {
    origin_domain: String,
    dns_resolver: DnsResolver,
}

/// Builder for [`DnsDiscovery`].
#[derive(Debug)]
pub struct DnsDiscoveryBuilder {
    origin_domain: String,
}

impl DnsDiscoveryBuilder {
    /// Builds a [`DnsDiscovery`] with the passed [`DnsResolver`].
    pub fn build(self, dns_resolver: DnsResolver) -> DnsDiscovery {
        DnsDiscovery::new(dns_resolver, self.origin_domain)
    }
}

impl DnsDiscovery {
    /// Creates a [`DnsDiscoveryBuilder`] that implements [`IntoDiscovery`].
    pub fn builder(origin_domain: String) -> DnsDiscoveryBuilder {
        DnsDiscoveryBuilder { origin_domain }
    }

    /// Creates a new DNS discovery using the `iroh.link` domain.
    ///
    /// This uses the [`N0_DNS_NODE_ORIGIN_PROD`] domain.
    ///
    /// # Usage during tests
    ///
    /// For testing it is possible to use the [`N0_DNS_NODE_ORIGIN_STAGING`] domain
    /// with [`DnsDiscovery::new`].  This would then use a hosted staging discovery
    /// service for testing purposes.
    pub fn n0_dns() -> DnsDiscoveryBuilder {
        if force_staging_infra() {
            Self::builder(N0_DNS_NODE_ORIGIN_STAGING.to_string())
        } else {
            Self::builder(N0_DNS_NODE_ORIGIN_PROD.to_string())
        }
    }

    /// Creates a new DNS discovery.
    fn new(dns_resolver: DnsResolver, origin_domain: String) -> Self {
        Self {
            dns_resolver,
            origin_domain,
        }
    }
}

impl IntoDiscovery for DnsDiscoveryBuilder {
    fn into_discovery(self: Box<Self>, endpoint: &Endpoint) -> Result<Box<dyn Discovery>> {
        Ok(Box::new(DnsDiscovery::new(
            endpoint.dns_resolver().clone(),
            self.origin_domain,
        )))
    }
}

impl Discovery for DnsDiscovery {
    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let resolver = self.dns_resolver.clone();
        let origin_domain = self.origin_domain.clone();
        let fut = async move {
            let node_info = resolver
                .lookup_node_by_id_staggered(&node_id, &origin_domain, DNS_STAGGERING_MS)
                .await?;
            Ok(DiscoveryItem::new(node_info, "dns", None))
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}
