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

/// DNS node discovery.
///
/// The DNS discovery looks up node addressing information over the Domain Name System.
/// Node information is resolved via an _iroh_node.z32encodednodeid TXT record.
///
/// The content of this record is expected to be a DNS attribute string, with a required
/// `node=` attribute containing the base32 encoded node id and a derp_url attribute containing the
/// node's home Derp server.
///
/// The discovery has to be configured with a `node_origin`, which is the domain name under which
/// lookups for nodes will be made.
/// With a origin of mydns.example, a node info record would be searched at
/// _iroh_node.z32encodednodeid.mydns.example TXT
#[derive(Debug)]
pub struct DnsDiscovery {
    node_origin: String,
}

impl DnsDiscovery {
    /// Create a new DNS discovery with `node_origin` appended to all lookups.
    pub fn new(node_origin: String) -> Self {
        Self { node_origin }
    }

    /// Create a new DNS discovery which uses the n0 testdns origin.
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
                dns::node_info::lookup_by_id(&resolver, &node_id, &self.node_origin).await?;
            Ok(DiscoveryItem {
                provenance: "iroh-dns",
                last_updated: None,
                addr_info: node_addr.info,
            })
        };
        Some(fut.into_stream().boxed())
    }
}
