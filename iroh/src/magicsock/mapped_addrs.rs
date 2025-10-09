//! The various mapped addresses we use.
//!

//! We use non-IP transports to carry datagrams.  Yet Quinn needs to address those
//! transports using IPv6 addresses.  These defines mappings of several IPv6 Unique Local
//! Address ranges we use to keep track of the various "fake" address types we use.

use std::{
    fmt,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustc_hash::FxHashMap;
use snafu::Snafu;
use tracing::trace;

/// The Prefix/L of all Unique Local Addresses.
const ADDR_PREFIXL: u8 = 0xfd;

/// The Global ID used in n0's Unique Local Addresses.
const ADDR_GLOBAL_ID: [u8; 5] = [21, 7, 10, 81, 11];

/// The Subnet ID for [`RelayMappedAddr].
const RELAY_MAPPED_SUBNET: [u8; 2] = [0, 1];

/// The Subnet ID for [`NodeIdMappedAddr`].
const NODE_ID_SUBNET: [u8; 2] = [0; 2];

/// The dummy port used for all mapped addresses.
///
/// We map each entity, usually a [`NodeId`], to an IPv6 address.  But socket addresses
/// involve ports, so we use a dummy fixed port when creating socket addresses.
const MAPPED_PORT: u16 = 12345;

/// Counter to always generate unique addresses for [`RelayMappedAddr`].
static RELAY_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Counter to always generate unique addresses for [`NodeIdMappedAddr`].
static NODE_ID_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generic mapped address.
///
/// Allows implementing [`AddrMap`].
pub(crate) trait MappedAddr {
    /// Generates a new mapped address in the IPv6 Unique Local Address space.
    fn generate() -> Self;

    /// Returns a consistent [`SocketAddr`] for the mapped addr.
    ///
    /// This socket address does not have a routable IP address.  It uses a fake but
    /// consistent port number, since the port does not play a role in the addressing.  This
    /// socket address is only to be used to pass into Quinn.
    fn private_socket_addr(&self) -> SocketAddr;
}

/// An enum encompassing all the mapped and unmapped addresses.
///
/// This can consistently convert a socket address as we use them in Quinn and return a real
/// socket address or a mapped address.  Note that this does not mean that the mapped
/// address exists, only that it is semantically a valid mapped address.
#[derive(Clone, Debug)]
pub(crate) enum MultipathMappedAddr {
    /// An address for a [`NodeId`], via one or more paths.
    Mixed(NodeIdMappedAddr),
    /// An address for a particular [`NodeId`] via a particular relay.
    Relay(RelayMappedAddr),
    /// An IP based transport address.
    #[cfg(not(wasm_browser))]
    Ip(SocketAddr),
}

impl From<SocketAddr> for MultipathMappedAddr {
    fn from(value: SocketAddr) -> Self {
        match value.ip() {
            IpAddr::V4(_) => Self::Ip(value),
            IpAddr::V6(addr) => {
                if let Ok(addr) = NodeIdMappedAddr::try_from(addr) {
                    return Self::Mixed(addr);
                }
                if let Ok(addr) = RelayMappedAddr::try_from(addr) {
                    return Self::Relay(addr);
                }
                #[cfg(not(wasm_browser))]
                Self::Ip(value)
            }
        }
    }
}

/// An address used to address a node on any or all paths.
///
/// This is only used for initially connecting to a remote node.  We instruct Quinn to send
/// to this address, and duplicate all packets for this address to send on all paths we
/// might want to send the initial on:
///
/// - If this the first connection to the remote node we don't know which path will work and
///   send to all of them.
///
/// - If there already is an active connection to this node we now which path to use.
///
/// It is but a newtype around an IPv6 Unique Local Addr.  And in our QUIC-facing socket
/// APIs like [`quinn::AsyncUdpSocket`] it comes in as the inner [`Ipv6Addr`], in those
/// interfaces we have to be careful to do the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NodeIdMappedAddr(Ipv6Addr);

impl MappedAddr for NodeIdMappedAddr {
    /// Generates a globally unique fake UDP address.
    ///
    /// This generates and IPv6 Unique Local Address according to RFC 4193.
    fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&NODE_ID_SUBNET);

        let counter = NODE_ID_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`NodeIdMappedAddr`].
    ///
    /// This socket address does not have a routable IP address.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Quinn.
    fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), MAPPED_PORT)
    }
}

impl std::fmt::Display for NodeIdMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NodeIdMappedAddr({})", self.0)
    }
}

impl TryFrom<Ipv6Addr> for NodeIdMappedAddr {
    type Error = NodeIdMappedAddrError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == ADDR_PREFIXL
            && octets[1..6] == ADDR_GLOBAL_ID
            && octets[6..8] == NODE_ID_SUBNET
        {
            return Ok(Self(value));
        }
        Err(NodeIdMappedAddrError)
    }
}

/// Can occur when converting a [`SocketAddr`] to an [`NodeIdMappedAddr`]
#[derive(Debug, Snafu)]
#[snafu(display("Failed to convert"))]
pub(crate) struct NodeIdMappedAddrError;

/// An Ipv6 ULA address, identifying a relay path for a [`NodeId`].
///
/// Since iroh nodes are reachable via a relay server we have a network path indicated by
/// the `(NodeId, RelayUrl)`.  However Quinn can only handle socket addresses, so we use
/// IPv6 addresses in a private IPv6 Unique Local Address range, which map to a unique
/// `(NodeId, RelayUrl)` pair.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct RelayMappedAddr(Ipv6Addr);

impl MappedAddr for RelayMappedAddr {
    /// Generates a globally unique fake UDP address.
    ///
    /// This generates a new IPv6 address in the Unique Local Address range (RFC 4193)
    /// which is recognised by iroh as an IP mapped address.
    fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&RELAY_MAPPED_SUBNET);

        let counter = RELAY_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`RelayMappedAddr`].
    ///
    /// This does not have a routable IP address.
    ///
    /// This uses a made-up, but fixed port number.  The [`RelayAddrMap`] creates a unique
    /// [`RelayMappedAddr`] for each `(NodeId, RelayUrl)` pair and thus does not use the
    /// port to map back to the original [`SocketAddr`].
    fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), MAPPED_PORT)
    }
}

impl TryFrom<Ipv6Addr> for RelayMappedAddr {
    type Error = RelayMappedAddrError;

    fn try_from(value: Ipv6Addr) -> std::result::Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == ADDR_PREFIXL
            && octets[1..6] == ADDR_GLOBAL_ID
            && octets[6..8] == RELAY_MAPPED_SUBNET
        {
            return Ok(Self(value));
        }
        Err(RelayMappedAddrError)
    }
}

/// Can occur when converting a [`SocketAddr`] to an [`RelayMappedAddr`]
#[derive(Debug, Snafu)]
#[snafu(display("Failed to convert"))]
pub(crate) struct RelayMappedAddrError;

impl std::fmt::Display for RelayMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RelayMappedAddr({})", self.0)
    }
}

/// A bi-directional map between a key and a [`MappedAddr`].
#[derive(Debug, Clone)]
pub(super) struct AddrMap<K, V> {
    inner: Arc<std::sync::Mutex<AddrMapInner<K, V>>>,
}

// Manual impl because derive ends up requiring T: Default.
impl<K, V> Default for AddrMap<K, V> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<K, V> AddrMap<K, V>
where
    K: Eq + Hash + Clone + fmt::Debug,
    V: MappedAddr + Eq + Hash + Copy + fmt::Debug,
{
    /// Returns the [`MappedAddr`], generating one if needed.
    pub(super) fn get(&self, key: &K) -> V {
        let mut inner = self.inner.lock().expect("poisoned");
        match inner.addrs.get(key) {
            Some(addr) => *addr,
            None => {
                let addr = V::generate();
                inner.addrs.insert(key.clone(), addr);
                inner.lookup.insert(addr, key.clone());
                trace!(?addr, ?key, "generated new addr");
                addr
            }
        }
    }

    /// Performs the reverse lookup.
    pub(super) fn lookup(&self, addr: &V) -> Option<K> {
        let inner = self.inner.lock().expect("poisoned");
        inner.lookup.get(addr).cloned()
    }
}

#[derive(Debug)]
struct AddrMapInner<K, V> {
    addrs: FxHashMap<K, V>,
    lookup: FxHashMap<V, K>,
}

// Manual impl because derive ends up requiring T: Default.
impl<K, V> Default for AddrMapInner<K, V> {
    fn default() -> Self {
        Self {
            addrs: Default::default(),
            lookup: Default::default(),
        }
    }
}
