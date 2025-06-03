//! DNS node discovery for iroh

use iroh_base::NodeId;
use iroh_relay::dns::DnsResolver;
pub use iroh_relay::dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING};
use n0_future::boxed::BoxStream;

use super::{DiscoveryError, IntoDiscovery, IntoDiscoveryError};
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
/// * `<origin-domain>` is the node origin domain as set in [`DnsDiscovery::builder`].
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
///
/// See [`DnsDiscovery::builder`].
#[derive(Debug)]
pub struct DnsDiscoveryBuilder {
    origin_domain: String,
    dns_resolver: Option<DnsResolver>,
}

impl DnsDiscoveryBuilder {
    /// Sets the DNS resolver to use.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Builds a [`DnsDiscovery`] with the passed [`DnsResolver`].
    pub fn build(self) -> DnsDiscovery {
        DnsDiscovery {
            dns_resolver: self.dns_resolver.unwrap_or_default(),
            origin_domain: self.origin_domain,
        }
    }
}

impl DnsDiscovery {
    /// Creates a [`DnsDiscoveryBuilder`] that implements [`IntoDiscovery`].
    pub fn builder(origin_domain: String) -> DnsDiscoveryBuilder {
        DnsDiscoveryBuilder {
            origin_domain,
            dns_resolver: None,
        }
    }

    /// Creates a new DNS discovery using the `iroh.link` domain.
    ///
    /// This uses the [`N0_DNS_NODE_ORIGIN_PROD`] domain.
    ///
    /// # Usage during tests
    ///
    /// For testing it is possible to use the [`N0_DNS_NODE_ORIGIN_STAGING`] domain
    /// with [`DnsDiscovery::builder`].  This would then use a hosted staging discovery
    /// service for testing purposes.
    pub fn n0_dns() -> DnsDiscoveryBuilder {
        if force_staging_infra() {
            Self::builder(N0_DNS_NODE_ORIGIN_STAGING.to_string())
        } else {
            Self::builder(N0_DNS_NODE_ORIGIN_PROD.to_string())
        }
    }
}

impl IntoDiscovery for DnsDiscoveryBuilder {
    fn into_discovery(mut self, endpoint: &Endpoint) -> Result<impl Discovery, IntoDiscoveryError> {
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver().clone());
        }
        Ok(self.build())
    }
}

impl Discovery for DnsDiscovery {
    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        let resolver = self.dns_resolver.clone();
        let origin_domain = self.origin_domain.clone();
        let fut = async move {
            let node_info = resolver
                .lookup_node_by_id_staggered(&node_id, &origin_domain, DNS_STAGGERING_MS)
                .await
                .map_err(|e| DiscoveryError::from_err("dns", e))?;
            Ok(DiscoveryItem::new(node_info, "dns", None))
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}
