//! A static discovery implementation that allows adding info for nodes manually.
use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::{Arc, RwLock},
};

use futures_lite::stream::{self, StreamExt};
use iroh_base::{
    key::NodeId,
    node_addr::{AddrInfo, NodeAddr},
};

use super::{Discovery, DiscoveryItem};

/// A static discovery implementation that allows adding info for nodes manually.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct StaticDiscovery {
    nodes: Arc<RwLock<BTreeMap<NodeId, AddrInfo>>>,
}

impl StaticDiscovery {
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
    /// use std::str::FromStr;
    ///
    /// use iroh_base::ticket::NodeTicket;
    /// use iroh_net::{Endpoint, discovery::static_discovery::StaticDiscovery};
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// # #[derive(Default)] struct Args { tickets: Vec<NodeTicket> }
    /// # let args = Args::default();
    /// let tickets: Vec<NodeTicket> = args.tickets;
    /// let discovery = StaticDiscovery::from_node_addrs(tickets);
    /// let endpoint = Endpoint::builder()
    ///     .add_discovery(|_| Some(discovery))
    ///     .bind().await?;
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
    pub fn set_node_addr(&self, info: impl Into<NodeAddr>) {
        let info: NodeAddr = info.into();
        let mut guard = self.nodes.write().unwrap();
        guard.insert(info.node_id, info.info);
    }

    /// Add node info for the given node id, combining it with any existing info.
    ///
    /// This will add any new direct addresses and overwrite the relay url.
    pub fn add_node_addr(&self, info: impl Into<NodeAddr>) {
        let info: NodeAddr = info.into();
        let mut guard = self.nodes.write().unwrap();
        match guard.entry(info.node_id) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing.direct_addresses.extend(info.info.direct_addresses);
                existing.relay_url = info.info.relay_url;
            }
            Entry::Vacant(entry) => {
                entry.insert(info.info);
            }
        }
    }

    /// Get node info for the given node id.
    pub fn get_node_addr(&self, node_id: NodeId) -> Option<NodeAddr> {
        let guard = self.nodes.read().unwrap();
        let info = guard.get(&node_id).cloned()?;
        Some(NodeAddr { node_id, info })
    }

    /// Remove node info for the given node id.
    pub fn remove_node_addr(&self, node_id: NodeId) {
        let mut guard = self.nodes.write().unwrap();
        guard.remove(&node_id);
    }
}

impl Discovery for StaticDiscovery {
    fn publish(&self, _info: &AddrInfo) {}

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
                    node_id,
                    provenance: Self::PROVENANCE,
                    last_updated: None,
                    addr_info: addr_info.clone(),
                };
                Some(stream::iter(Some(Ok(item))).boxed())
            }
            None => None,
        }
    }
}
