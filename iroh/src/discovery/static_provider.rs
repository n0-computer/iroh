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
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use iroh_base::{NodeAddr, NodeId, RelayUrl};
use n0_future::{
    boxed::BoxStream,
    stream::{self, StreamExt},
    time::SystemTime,
};

use super::{Discovery, DiscoveryItem};

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
/// # async fn main() -> anyhow::Result<()> {
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
/// /// Sometime later add a RelayUrl for a fake NodeId.
/// let key = SecretKey::from_bytes(&[0u8; 32]); // Do not use fake secret keys!
/// discovery.add_node_addr(NodeAddr {
///     node_id: key.public(),
///     relay_url: Some("https://example.com".parse()?),
///     direct_addresses: Default::default(),
/// });
///
/// # Ok(())
/// # }
/// ```
///
/// [`NodeTicket`]: https://docs.rs/iroh-base/latest/iroh_base/ticket/struct.NodeTicket
#[derive(Debug, Default, Clone)]
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

    /// Sets node addressing information for the given node ID.
    ///
    /// This will completely overwrite any existing info for the node.
    pub fn set_node_addr(&self, info: impl Into<NodeAddr>) -> Option<NodeAddr> {
        let last_updated = SystemTime::now();
        let info: NodeAddr = info.into();
        let mut guard = self.nodes.write().expect("poisoned");
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

    /// Augments node addressing information for the given node ID.
    ///
    /// The provided addressing information is combined with the existing info in the static
    /// provider.  Any new direct addresses are added to those already present while the
    /// relay URL is overwritten.
    pub fn add_node_addr(&self, info: impl Into<NodeAddr>) {
        let info: NodeAddr = info.into();
        let last_updated = SystemTime::now();
        let mut guard = self.nodes.write().expect("poisoned");
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

    /// Returns node addressing information for the given node ID.
    pub fn get_node_addr(&self, node_id: NodeId) -> Option<NodeAddr> {
        let guard = self.nodes.read().expect("poisoned");
        let info = guard.get(&node_id)?;
        Some(NodeAddr {
            node_id,
            relay_url: info.relay_url.clone(),
            direct_addresses: info.direct_addresses.clone(),
        })
    }

    /// Removes all node addressing information for the given node ID.
    ///
    /// Any removed information is returned.
    pub fn remove_node_addr(&self, node_id: NodeId) -> Option<NodeAddr> {
        let mut guard = self.nodes.write().expect("poisoned");
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
    ) -> Option<BoxStream<anyhow::Result<super::DiscoveryItem>>> {
        let guard = self.nodes.read().expect("poisoned");
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

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use iroh_base::SecretKey;
    use testresult::TestResult;

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
        discovery.add_node_addr(addr.clone());

        let back = discovery.get_node_addr(key.public()).context("no addr")?;

        assert_eq!(back, addr);

        let removed = discovery
            .remove_node_addr(key.public())
            .context("nothing removed")?;
        assert_eq!(removed, addr);
        let res = discovery.get_node_addr(key.public());
        assert!(res.is_none());

        Ok(())
    }
}
