//! Trait and utils for the node discovery mechanism.

use anyhow::Result;
use futures::stream::BoxStream;

use crate::{AddrInfo, MagicEndpoint, NodeId};

/// Node discovery for [`super::MagicEndpoint`].
///
/// The purpose of this trait is to hoop up a node discovery mechanism that
/// allows finding information such as the derp url and current addresses
/// of a node given the id.
///
/// To allow for discovery, the [`super::MagicEndpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start it's own task.
pub trait Discovery: std::fmt::Debug + Send + Sync {
    /// Publish the given [`AddrInfo`] to the discovery mechanisms.
    ///
    /// This is fire and forget, since the magicsock can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's
    /// own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::MagicEndpoint`].
    fn publish(&self, _info: &AddrInfo) {}

    /// Resolve the [`AddrInfo`] for the given [`PublicKey`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(
        &self,
        _endpoint: MagicEndpoint,
        _node_id: NodeId,
    ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
        None
    }
}

/// The results returned from [`Discovery::resolve`].
#[derive(Debug, Clone)]
pub struct DiscoveryItem {
    /// A static string to identify the discovery source.
    ///
    /// Should be uniform per discovery service.
    pub provenance: &'static str,
    /// Optional timestamp when this node address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    pub last_updated: Option<u64>,
    /// The adress info for the node being resolved.
    pub addr_info: AddrInfo,
}

/// A discovery service that combines multiple discovery sources.
#[derive(Debug, Default)]
pub struct CombinedDiscovery {
    services: Vec<Box<dyn Discovery>>,
}

impl CombinedDiscovery {
    /// Create a new [`CombinedDiscovery`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a [`Discovery`] service.
    pub fn add(&mut self, service: impl Discovery + 'static) {
        self.services.push(Box::new(service));
    }
}

impl<T> From<T> for CombinedDiscovery
where
    T: Iterator<Item = Box<dyn Discovery>>,
{
    fn from(iter: T) -> Self {
        let services = iter.collect::<Vec<_>>();
        Self { services }
    }
}

impl Discovery for CombinedDiscovery {
    fn publish(&self, info: &AddrInfo) {
        for service in &self.services {
            service.publish(info);
        }
    }

    fn resolve(
        &self,
        endpoint: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
        let streams = self
            .services
            .iter()
            .filter_map(|service| service.resolve(endpoint.clone(), node_id));
        let streams = futures::stream::select_all(streams);
        Some(Box::pin(streams))
    }
}
