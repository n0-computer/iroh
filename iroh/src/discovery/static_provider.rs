//! A static discovery implementation that allows adding info for nodes manually.
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use futures_lite::stream::{self, StreamExt};
use iroh_base::{NodeAddr, NodeId, RelayUrl};

use super::{Discovery, DiscoveryItem};

/// A static discovery implementation that allows providing info for nodes manually.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct StaticProvider {
    nodes: Arc<RwLock<BTreeMap<NodeId, NodeInfo>>>,
}

#[derive(Debug)]
struct NodeInfo {
    relay_url: Option<RelayUrl>,
    direct_addresses: BTreeSet<SocketAddr>,
    last_updated: SystemTime,
}

impl StaticProvider {
    /// The provenance string for this discovery implementation.
    pub const PROVENANCE: &'static str = "static_discovery";

    /// Create a new static discovery instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a static discovery instance from something that can be converted into node addresses.
    ///
    /// Example:
    /// ```rust
    /// use std::{net::SocketAddr, str::FromStr};
    ///
    /// use iroh::{discovery::static_provider::StaticProvider, Endpoint, NodeAddr};
    ///
    /// # fn get_addrs() -> Vec<NodeAddr> {
    /// #     Vec::new()
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// // get addrs from somewhere
    /// let addrs = get_addrs();
    ///
    /// // create a StaticProvider from the list of addrs.
    /// let discovery = StaticProvider::from_node_addrs(addrs);
    /// // create an endpoint with the discovery
    /// let endpoint = Endpoint::builder()
    ///     .add_discovery(|_| Some(discovery))
    ///     .bind()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_node_addrs(infos: impl IntoIterator<Item = impl Into<NodeAddr>>) -> Self {
        let res = Self::default();
        for info in infos {
            res.add_node_addr(info);
        }
        res
    }

    /// Add node info for the given node id.
    ///
    /// This will completely overwrite any existing info for the node.
    pub fn set_node_addr(&self, info: impl Into<NodeAddr>) -> Option<NodeAddr> {
        let last_updated = SystemTime::now();
        let info: NodeAddr = info.into();
        let mut guard = self.nodes.write().unwrap();
        let previous = guard.insert(
            info.node_id,
            NodeInfo {
                relay_url: info.relay_url,
                direct_addresses: info.direct_addresses,
                last_updated,
            },
        );
        previous.map(|x| NodeAddr {
            node_id: info.node_id,
            relay_url: x.relay_url,
            direct_addresses: x.direct_addresses,
        })
    }

    /// Add node info for the given node id, combining it with any existing info.
    ///
    /// This will add any new direct addresses and overwrite the relay url.
    pub fn add_node_addr(&self, info: impl Into<NodeAddr>) {
        let info: NodeAddr = info.into();
        let last_updated = SystemTime::now();
        let mut guard = self.nodes.write().unwrap();
        match guard.entry(info.node_id) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing.direct_addresses.extend(info.direct_addresses);
                existing.relay_url = info.relay_url;
                existing.last_updated = last_updated;
            }
            Entry::Vacant(entry) => {
                entry.insert(NodeInfo {
                    relay_url: info.relay_url,
                    direct_addresses: info.direct_addresses,
                    last_updated,
                });
            }
        }
    }

    /// Get node info for the given node id.
    pub fn get_node_addr(&self, node_id: NodeId) -> Option<NodeAddr> {
        let guard = self.nodes.read().unwrap();
        let info = guard.get(&node_id)?;
        Some(NodeAddr {
            node_id,
            relay_url: info.relay_url.clone(),
            direct_addresses: info.direct_addresses.clone(),
        })
    }

    /// Remove node info for the given node id.
    pub fn remove_node_addr(&self, node_id: NodeId) -> Option<NodeAddr> {
        let mut guard = self.nodes.write().unwrap();
        let info = guard.remove(&node_id)?;
        Some(NodeAddr {
            node_id,
            relay_url: info.relay_url,
            direct_addresses: info.direct_addresses,
        })
    }
}

impl Discovery for StaticProvider {
    fn publish(&self, _url: Option<&RelayUrl>, _addrs: &BTreeSet<SocketAddr>) {}

    fn resolve(
        &self,
        _endpoint: crate::Endpoint,
        node_id: NodeId,
    ) -> Option<futures_lite::stream::Boxed<anyhow::Result<super::DiscoveryItem>>> {
        let guard = self.nodes.read().unwrap();
        let info = guard.get(&node_id);
        match info {
            Some(addr_info) => {
                let item = DiscoveryItem {
                    node_addr: NodeAddr {
                        node_id,
                        relay_url: addr_info.relay_url.clone(),
                        direct_addresses: addr_info.direct_addresses.clone(),
                    },
                    provenance: Self::PROVENANCE,
                    last_updated: Some(
                        addr_info
                            .last_updated
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .expect("time drift")
                            .as_micros() as u64,
                    ),
                };
                Some(stream::iter(Some(Ok(item))).boxed())
            }
            None => None,
        }
    }
}
