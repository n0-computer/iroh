use std::sync::Arc;

use anyhow::Result;
use futures::{future::FutureExt, stream::BoxStream, StreamExt};
use iroh_net::{
    discovery::{Discovery, DiscoveryItem},
    key::SecretKey,
    AddrInfo, MagicEndpoint, NodeId,
};
use tracing::warn;

use crate::publish::{self, Publisher};
use crate::resolve::{self, Resolver};

#[derive(Debug)]
pub struct DnsDiscovery {
    publisher: Option<Arc<Publisher>>,
    resolver: Resolver,
}

impl DnsDiscovery {
    pub fn new(resolver: Resolver, publisher: Option<Arc<Publisher>>) -> Self {
        Self {
            resolver,
            publisher,
        }
    }
    pub fn with_iroh_test(secret_key: Option<SecretKey>) -> Result<Self> {
        let publisher =
            secret_key.map(|k| Arc::new(Publisher::new(publish::Config::with_iroh_test(k))));
        let resolver = Resolver::new(resolve::Config::with_cloudflare_and_iroh_test())?;
        Ok(Self::new(resolver, publisher))
    }
    pub fn localhost_dev(secret_key: Option<SecretKey>) -> Result<Self> {
        let publisher =
            secret_key.map(|k| Arc::new(Publisher::new(publish::Config::localhost_dev(k))));
        let resolver = Resolver::new(resolve::Config::localhost_dev())?;
        Ok(Self::new(resolver, publisher))
    }
}

impl Discovery for DnsDiscovery {
    fn publish(&self, info: &AddrInfo) {
        if let Some(publisher) = self.publisher.clone() {
            let info = info.clone();
            tokio::task::spawn(async move {
                if let Err(err) = publisher.publish_addr_info(&info).await {
                    warn!("failed to publish address update: {err:?}");
                }
            });
        }
    }

    fn resolve<'a>(
        &'a self,
        _ep: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'a, Result<DiscoveryItem>>> {
        let fut = async move {
            let addr_info = self.resolver.resolve_node_by_id(node_id).await?;
            Ok(DiscoveryItem {
                provenance: "iroh-dns",
                last_updated: None,
                addr_info,
            })
        };
        Some(fut.into_stream().boxed())
    }
}
