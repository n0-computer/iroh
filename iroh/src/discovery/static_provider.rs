//! A static node discovery to manually add node addressing information.
//!
//! Often an application might get node addressing information out-of-band in an
//! application-specific way.  [`NodeTicket`]'s are one common way used to achieve this.
//! This "static" addressing information is often only usable for a limited time so needs to
//! be able to be removed again once know it is no longer useful.
//!
//! This is where the [`StaticProvider`] is useful: it allows applications to add and
//! retract node addressing information that is otherwise out-of-band to iroh.
//!
//! [`NodeTicket`]: https://docs.rs/iroh-base/latest/iroh_base/ticket/struct.NodeTicket

use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::{Arc, RwLock},
};

use iroh_base::NodeId;
use n0_future::{
    boxed::BoxStream,
    stream::{self, StreamExt},
    time::SystemTime,
};

use super::{Discovery, DiscoveryItem, NodeData, NodeInfo};

/// A static node discovery to manually add node addressing information.
///
/// Often an application might get node addressing information out-of-band in an
/// application-specific way.  [`NodeTicket`]'s are one common way used to achieve this.
/// This "static" addressing information is often only usable for a limited time so needs to
/// be able to be removed again once know it is no longer useful.
///
/// This is where the [`StaticProvider`] is useful: it allows applications to add and
/// retract node addressing information that is otherwise out-of-band to iroh.
///
/// # Examples
///
/// ```rust
/// use iroh::{discovery::static_provider::StaticProvider, Endpoint, NodeAddr};
/// use iroh_base::SecretKey;
///
/// # #[tokio::main]
/// # async fn main() -> n0_snafu::TestResult<()> {
/// // Create the discovery service and endpoint.
/// let discovery = StaticProvider::new();
///
/// let _ep = Endpoint::builder()
///     .add_discovery({
///         let discovery = discovery.clone();
///         move |_| Some(discovery)
///     })
///     .bind()
///     .await?;
///
/// // Sometime later add a RelayUrl for a fake NodeId.
/// let node_id = SecretKey::from_bytes(&[0u8; 32]).public(); // Do not use fake secret keys!
/// // You can pass either `NodeInfo` or `NodeAddr` to `add_node_info`.
/// discovery.add_node_info(
///     NodeAddr {
///         node_id,
///         relay_url: Some("https://example.com".parse()?),
///         direct_addresses: Default::default(),
///     },
/// );
///
/// # Ok(())
/// # }
/// ```
///
/// [`NodeTicket`]: https://docs.rs/iroh-base/latest/iroh_base/ticket/struct.NodeTicket
#[derive(Debug, Default, Clone)]
#[repr(transparent)]
pub struct StaticProvider {
    nodes: Arc<RwLock<BTreeMap<NodeId, StoredNodeInfo>>>,
}

#[derive(Debug)]
struct StoredNodeInfo {
    data: NodeData,
    last_updated: SystemTime,
}

impl StaticProvider {
    /// The provenance string for this discovery implementation.
    ///
    /// This is mostly used for debugging information and allows understanding the origin of
    /// addressing information used by an iroh [`Endpoint`].
    ///
    /// [`Endpoint`]: crate::Endpoint
    pub const PROVENANCE: &'static str = "static_discovery";

    /// Creates a new static discovery instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a static discovery instance from node addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::{net::SocketAddr, str::FromStr};
    ///
    /// use iroh::{discovery::static_provider::StaticProvider, Endpoint, NodeAddr};
    ///
    /// # fn get_addrs() -> Vec<NodeAddr> {
    /// #     Vec::new()
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> n0_snafu::TestResult<()> {
    /// // get addrs from somewhere
    /// let addrs = get_addrs();
    ///
    /// // create a StaticProvider from the list of addrs.
    /// let discovery = StaticProvider::from_node_info(addrs);
    /// // create an endpoint with the discovery
    /// let endpoint = Endpoint::builder()
    ///     .add_discovery(|_| Some(discovery))
    ///     .bind()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_node_info(infos: impl IntoIterator<Item = impl Into<NodeInfo>>) -> Self {
        let res = Self::default();
        for info in infos {
            res.add_node_info(info);
        }
        res
    }

    /// Sets node addressing information for the given node ID.
    ///
    /// This will completely overwrite any existing info for the node.
    ///
    /// Returns the [`NodeData`] of the previous entry, or `None` if there was no previous
    /// entry for this node ID.
    pub fn set_node_info(&self, node_info: impl Into<NodeInfo>) -> Option<NodeData> {
        let last_updated = SystemTime::now();
        let NodeInfo { node_id, data } = node_info.into();
        let mut guard = self.nodes.write().expect("poisoned");
        let previous = guard.insert(node_id, StoredNodeInfo { data, last_updated });
        previous.map(|x| x.data)
    }

    /// Augments node addressing information for the given node ID.
    ///
    /// The provided addressing information is combined with the existing info in the static
    /// provider.  Any new direct addresses are added to those already present while the
    /// relay URL is overwritten.
    pub fn add_node_info(&self, node_info: impl Into<NodeInfo>) {
        let last_updated = SystemTime::now();
        let NodeInfo { node_id, data } = node_info.into();
        let mut guard = self.nodes.write().expect("poisoned");
        match guard.entry(node_id) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing
                    .data
                    .add_direct_addresses(data.direct_addresses().iter().copied());
                existing.data.set_relay_url(data.relay_url().cloned());
                existing.data.set_user_data(data.user_data().cloned());
                existing.last_updated = last_updated;
            }
            Entry::Vacant(entry) => {
                entry.insert(StoredNodeInfo { data, last_updated });
            }
        }
    }

    /// Returns node addressing information for the given node ID.
    pub fn get_node_info(&self, node_id: NodeId) -> Option<NodeInfo> {
        let guard = self.nodes.read().expect("poisoned");
        let info = guard.get(&node_id)?;
        Some(NodeInfo::from_parts(node_id, info.data.clone()))
    }

    /// Removes all node addressing information for the given node ID.
    ///
    /// Any removed information is returned.
    pub fn remove_node_info(&self, node_id: NodeId) -> Option<NodeInfo> {
        let mut guard = self.nodes.write().expect("poisoned");
        let info = guard.remove(&node_id)?;
        Some(NodeInfo::from_parts(node_id, info.data))
    }
}

impl Discovery for StaticProvider {
    fn publish(&self, _data: &NodeData) {}

    fn resolve(
        &self,
        _endpoint: crate::Endpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<Result<super::DiscoveryItem, super::DiscoveryError>>> {
        let guard = self.nodes.read().expect("poisoned");
        let info = guard.get(&node_id);
        match info {
            Some(node_info) => {
                let last_updated = node_info
                    .last_updated
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("time drift")
                    .as_micros() as u64;
                let item = DiscoveryItem::new(
                    NodeInfo::from_parts(node_id, node_info.data.clone()),
                    Self::PROVENANCE,
                    Some(last_updated),
                );
                Some(stream::iter(Some(Ok(item))).boxed())
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::{NodeAddr, SecretKey};
    use n0_snafu::{TestResult, TestResultExt};

    use super::*;
    use crate::Endpoint;

    #[tokio::test]
    async fn test_basic() -> TestResult {
        let discovery = StaticProvider::new();

        let _ep = Endpoint::builder()
            .add_discovery({
                let discovery = discovery.clone();
                move |_| Some(discovery)
            })
            .bind()
            .await?;

        let key = SecretKey::from_bytes(&[0u8; 32]);
        let addr = NodeAddr {
            node_id: key.public(),
            relay_url: Some("https://example.com".parse()?),
            direct_addresses: Default::default(),
        };
        let user_data = Some("foobar".parse().unwrap());
        let node_info = NodeInfo::from(addr.clone()).with_user_data(user_data.clone());
        discovery.add_node_info(node_info.clone());

        let back = discovery.get_node_info(key.public()).context("no addr")?;

        assert_eq!(back, node_info);
        assert_eq!(back.user_data(), user_data.as_ref());
        assert_eq!(back.into_node_addr(), addr);

        let removed = discovery
            .remove_node_info(key.public())
            .context("nothing removed")?;
        assert_eq!(removed, node_info);
        let res = discovery.get_node_info(key.public());
        assert!(res.is_none());

        Ok(())
    }
}
