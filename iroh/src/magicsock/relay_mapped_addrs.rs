use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use iroh_base::{NodeId, RelayUrl};
use snafu::Snafu;

/// Can occur when converting a [`SocketAddr`] to an [`IpMappedAddr`]
#[derive(Debug, Snafu)]
#[snafu(display("Failed to convert"))]
pub struct IpMappedAddrError;

/// A map fake Ipv6 address with an actual IP address.
///
/// It is essentially a lookup key for an IP that iroh's magicsocket knows about.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct IpMappedAddr(Ipv6Addr);

/// Counter to always generate unique addresses for [`IpMappedAddr`].
static IP_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

impl IpMappedAddr {
    /// The Prefix/L of our Unique Local Addresses.
    const ADDR_PREFIXL: u8 = 0xfd;
    /// The Global ID used in our Unique Local Addresses.
    const ADDR_GLOBAL_ID: [u8; 5] = [21, 7, 10, 81, 11];
    /// The Subnet ID used in our Unique Local Addresses.
    const ADDR_SUBNET: [u8; 2] = [0, 1];

    /// The dummy port used for all mapped addresses.
    const MAPPED_ADDR_PORT: u16 = 12345;

    /// Generates a globally unique fake UDP address.
    ///
    /// This generates a new IPv6 address in the Unique Local Address range (RFC 4193)
    /// which is recognised by iroh as an IP mapped address.
    pub(crate) fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = Self::ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&Self::ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&Self::ADDR_SUBNET);

        let counter = IP_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`IpMappedAddr`].
    ///
    /// This does not have a routable IP address.
    ///
    /// This uses a made-up, but fixed port number.  The [IpMappedAddresses`] map this is
    /// made for creates a unique [`IpMappedAddr`] for each IP+port and thus does not use
    /// the port to map back to the original [`SocketAddr`].
    pub(crate) fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), Self::MAPPED_ADDR_PORT)
    }
}

impl TryFrom<Ipv6Addr> for IpMappedAddr {
    type Error = IpMappedAddrError;

    fn try_from(value: Ipv6Addr) -> std::result::Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == Self::ADDR_PREFIXL
            && octets[1..6] == Self::ADDR_GLOBAL_ID
            && octets[6..8] == Self::ADDR_SUBNET
        {
            return Ok(Self(value));
        }
        Err(IpMappedAddrError)
    }
}

impl std::fmt::Display for IpMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IpMappedAddr({})", self.0)
    }
}

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
