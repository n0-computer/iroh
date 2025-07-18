use std::{collections::BTreeMap, sync::Arc};

use iroh_base::{NodeId, RelayUrl};
use snafu::Snafu;

use crate::net_report::IpMappedAddr;

/// Can occur when converting a [`SocketAddr`] to an [`RelayMappedAddr`]
#[derive(Debug, Snafu)]
#[snafu(display("Failed to convert"))]
pub struct RelayMappedAddrError;

/// A Map of [`RelayMappedAddresses`] to [`SocketAddr`].
#[derive(Debug, Clone, Default)]
pub(crate) struct RelayMappedAddresses(Arc<std::sync::Mutex<Inner>>);

#[derive(Debug, Default)]
pub(super) struct Inner {
    by_mapped_addr: BTreeMap<IpMappedAddr, (RelayUrl, NodeId)>,
    by_url: BTreeMap<(RelayUrl, NodeId), IpMappedAddr>,
}

impl RelayMappedAddresses {
    /// Adds a [`RelayUrl`] to the map and returns the generated [`IpMappedAddr`].
    ///
    /// If this [`RelayUrl`] already exists in the map, it returns its
    /// associated [`IpMappedAddr`].
    ///
    /// Otherwise a new [`IpMappedAddr`] is generated for it and returned.
    pub(super) fn get_or_register(&self, relay: RelayUrl, node: NodeId) -> IpMappedAddr {
        let mut inner = self.0.lock().expect("poisoned");
        if let Some(mapped_addr) = inner.by_url.get(&(relay.clone(), node)) {
            return *mapped_addr;
        }
        let ip_mapped_addr = IpMappedAddr::generate();
        inner
            .by_mapped_addr
            .insert(ip_mapped_addr, (relay.clone(), node));
        inner.by_url.insert((relay, node), ip_mapped_addr);
        ip_mapped_addr
    }

    /// Returns the [`IpMappedAddr`] for the given [`RelayUrl`].
    pub(crate) fn get_mapped_addr(&self, relay: RelayUrl, node: NodeId) -> Option<IpMappedAddr> {
        let inner = self.0.lock().expect("poisoned");
        inner.by_url.get(&(relay, node)).copied()
    }

    /// Returns the [`RelayUrl`] for the given [`IpMappedAddr`].
    pub(crate) fn get_url(&self, mapped_addr: &IpMappedAddr) -> Option<(RelayUrl, NodeId)> {
        let inner = self.0.lock().expect("poisoned");
        inner.by_mapped_addr.get(mapped_addr).cloned()
    }
}
