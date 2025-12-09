use std::collections::BTreeSet;

use iroh_base::{EndpointAddr, EndpointId, TransportAddr};
use n0_future::time::Instant;

use crate::endpoint::Source;

/// Information about a remote endpoint.
#[derive(Debug, Clone)]
pub struct RemoteInfo {
    pub(super) endpoint_id: EndpointId,
    pub(super) addrs: Vec<TransportAddrInfo>,
}

impl RemoteInfo {
    /// Returns the remote's endpoint id.
    pub fn id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns an iterator over known all addresses for this remote.
    ///
    /// Note that this may include outdated or unusable addresses.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddrInfo> {
        self.addrs.iter()
    }

    /// Converts into an iterator over known all addresses for this remote.
    ///
    /// Note that this may include outdated or unusable addresses.
    pub fn into_addrs(self) -> impl Iterator<Item = TransportAddrInfo> {
        self.addrs.into_iter()
    }

    /// Returns a [`EndpointAddr`] that includes all addresses that are not [`AddrUsage::Unusable`].
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        let addrs = self
            .addrs
            .into_iter()
            .filter(|a| !matches!(a.usage(), TransportAddrUsage::Unusable))
            .map(|a| a.addr);

        EndpointAddr {
            id: self.endpoint_id,
            addrs: BTreeSet::from_iter(addrs),
        }
    }
}

/// Address of a remote with some metadata
#[derive(Debug, Clone)]
pub struct TransportAddrInfo {
    pub(super) addr: TransportAddr,
    pub(super) usage: TransportAddrUsage,
    pub(super) most_recent_source: Source,
}

impl TransportAddrInfo {
    /// Returns the [`TransportAddr`].
    pub fn addr(&self) -> &TransportAddr {
        &self.addr
    }

    /// Converts into [`TransportAddr`].
    pub fn into_addr(self) -> TransportAddr {
        self.addr
    }

    /// Returns information how this address is used.
    pub fn usage(&self) -> TransportAddrUsage {
        self.usage
    }

    /// Returns the most recent source of this address.
    ///
    /// We may learn about new addresses from multiple sources. This returns the most recent source
    /// that told us about this address.
    pub fn most_recent_source(&self) -> &Source {
        &self.most_recent_source
    }
}

/// Information how a transport address is used.
#[derive(Debug, Copy, Clone)]
pub enum TransportAddrUsage {
    /// The address is in active use.
    Active,
    /// The address was used, but is not currently.
    Inactive {
        /// Time when this address was last used.
        last_used: Instant,
    },
    /// We tried to use this address, but failed.
    Unusable,
    /// We have not tried to use this address.
    Unknown,
}
