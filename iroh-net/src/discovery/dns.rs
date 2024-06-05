//! DNS node discovery for iroh-net

use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Result};
use futures_lite::stream::Boxed as BoxStream;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig},
    AsyncResolver,
};

use crate::{
    discovery::{Discovery, DiscoveryItem},
    dns::{DnsResolver, ResolverExt},
    Endpoint, NodeId,
};

/// The n0 testing DNS node origin
pub const N0_DNS_NODE_ORIGIN: &str = "dns.iroh.link";
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
    port: Option<u16>,
    use_ipv6: bool,
}

impl DnsDiscovery {
    /// Create a new DNS discovery.
    pub fn new(origin_domain: String) -> Self {
        Self {
            origin_domain,
            port: None,
            use_ipv6: false,
        }
    }

    /// Create a new DNS discovery with a custom port and IP protocol version.
    ///
    /// This method configures the DNS query to communicate with the specified DNS server,
    /// using either IPv4 or IPv6 as determined by the `use_ipv6` flag.
    ///
    /// # Arguments
    ///
    /// * `origin_domain` - The domain name of the DNS server.
    /// * `port` - The port number the DNS server is listening on.
    /// * `use_ipv6` - If true, the query will use IPv6 to connect to the DNS server;
    ///   if false, it will use IPv4.
    ///
    /// Note: To handle both IPv4 and IPv6 connections simultaneously, consider using
    /// [`ConcurrentDiscovery`](crate::discovery::ConcurrentDiscovery) to combine the queries
    /// from both versions.
    pub fn with_port(origin_domain: String, port: u16, use_ipv6: bool) -> Self {
        Self {
            origin_domain,
            port: Some(port),
            use_ipv6,
        }
    }

    /// Create a new DNS discovery which uses the [`N0_DNS_NODE_ORIGIN`] origin domain.
    pub fn n0_dns() -> Self {
        Self::new(N0_DNS_NODE_ORIGIN.to_string())
    }
}

const DNS_TIMEOUT: Duration = Duration::from_secs(1);

impl Discovery for DnsDiscovery {
    fn resolve(&self, ep: Endpoint, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let resolver = ep.dns_resolver().clone();
        let origin_domain = self.origin_domain.clone();
        let port = self.port;
        let use_ipv6 = self.use_ipv6;
        let fut = async move {
            // Use custom port if specified, otherwise use existing resolver.
            let resolver = if let Some(port) = port {
                resolve_with_domain(&resolver, &origin_domain, port, use_ipv6).await?
            } else {
                resolver
            };

            let node_addr = resolver
                .lookup_by_id_staggered(&node_id, &origin_domain, DNS_STAGGERING_MS)
                .await?;

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

async fn resolve_with_domain(
    resolver: &DnsResolver,
    domain: &str,
    port: u16,
    use_ipv6: bool,
) -> Result<DnsResolver> {
    let dst_ip = if use_ipv6 {
        resolver.lookup_ipv6(domain, DNS_TIMEOUT).await?.next()
    } else {
        resolver.lookup_ipv4(domain, DNS_TIMEOUT).await?.next()
    };

    let dst_ip = dst_ip.ok_or(anyhow!("dns:{domain} No Ip"))?;

    Ok(resolver_with_nameserver(SocketAddr::new(dst_ip, port)))
}

fn resolver_with_nameserver(nameserver: SocketAddr) -> DnsResolver {
    let mut config = ResolverConfig::new();
    let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
    config.add_name_server(nameserver_config);
    AsyncResolver::tokio(config, Default::default())
}
