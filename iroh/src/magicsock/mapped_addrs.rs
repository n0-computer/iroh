//! The various mapped addresses we use.

//! We use non-IP transports to carry datagrams.  Yet Quinn needs to address those
//! transports using IPv6 addresses.  These defines mappings of several IPv6 Unique Local
//! Address ranges we use to keep track of the various "fake" address types we use.

use std::{
    fmt,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use iroh_base::{EndpointId, RelayUrl};
use n0_error::{e, stack_error};
use rustc_hash::FxHashMap;
use tracing::{error, trace};

use super::transports;

/// The Prefix/L of all Unique Local Addresses.
const ADDR_PREFIXL: u8 = 0xfd;

/// The Global ID used in n0's Unique Local Addresses.
const ADDR_GLOBAL_ID: [u8; 5] = [21, 7, 10, 81, 11];

/// The Subnet ID for [`RelayMappedAddr].
const RELAY_MAPPED_SUBNET: [u8; 2] = [0, 1];

/// The Subnet ID for [`EndpointIdMappedAddr`].
const ENDPOINT_ID_SUBNET: [u8; 2] = [0; 2];

/// A default fake addr, using the maximum addr that the internal fake addrs could be using.
pub const DEFAULT_FAKE_ADDR: SocketAddrV6 = SocketAddrV6::new(
    Ipv6Addr::new(
        u16::from_be_bytes([ADDR_PREFIXL, 21]),
        u16::from_be_bytes([7, 10]),
        u16::from_be_bytes([81, 11]),
        u16::from_be_bytes([0, 0]),
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
    ),
    MAPPED_PORT,
    0,
    0,
);

/// The dummy port used for all mapped addresses.
///
/// We map each entity, usually an [`EndpointId`], to an IPv6 address.  But socket addresses
/// involve ports, so we use a dummy fixed port when creating socket addresses.
const MAPPED_PORT: u16 = 12345;

/// Counter to always generate unique addresses for [`RelayMappedAddr`].
static RELAY_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Counter to always generate unique addresses for [`EndpointIdMappedAddr`].
static ENDPOINT_ID_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

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
/// This is essentially a slightly-stronger typed version of the IPv6 mapped addresses that
/// we use on the Quinn side.  It categorises the addressed in what kind of mapped or
/// unmapped addresses they are.
///
/// It does not guarantee that a mapped address exists in the mapping.  Or that a particular
/// address is even supported on this platform.  Hence no wasm exceptions here.
#[derive(Clone, Debug)]
pub(crate) enum MultipathMappedAddr {
    /// An address for a [`EndpointId`], via one or more paths.
    Mixed(EndpointIdMappedAddr),
    /// An address for a particular [`EndpointId`] via a particular relay.
    Relay(RelayMappedAddr),
    /// An IP based transport address.
    Ip(SocketAddr),
}

impl From<SocketAddr> for MultipathMappedAddr {
    fn from(value: SocketAddr) -> Self {
        match value.ip() {
            IpAddr::V4(_) => Self::Ip(value),
            IpAddr::V6(addr) => {
                if let Ok(addr) = EndpointIdMappedAddr::try_from(addr) {
                    return Self::Mixed(addr);
                }
                if let Ok(addr) = RelayMappedAddr::try_from(addr) {
                    return Self::Relay(addr);
                }
                Self::Ip(value)
            }
        }
    }
}

/// An address used to address a endpoint on any or all paths.
///
/// This is only used for initially connecting to a remote endpoint.  We instruct Quinn to
/// send to this address, and duplicate all packets for this address to send on all paths we
/// might want to send the initial on:
///
/// - If this the first connection to the remote endpoint we don't know which path will work
///   and send to all of them.
///
/// - If there already is an active connection to this endpoint we now which path to use.
///
/// It is but a newtype around an IPv6 Unique Local Addr.  And in our QUIC-facing socket
/// APIs like [`quinn::AsyncUdpSocket`] it comes in as the inner [`Ipv6Addr`], in those
/// interfaces we have to be careful to do the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EndpointIdMappedAddr(Ipv6Addr);

impl MappedAddr for EndpointIdMappedAddr {
    /// Generates a globally unique fake UDP address.
    ///
    /// This generates and IPv6 Unique Local Address according to RFC 4193.
    fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&ENDPOINT_ID_SUBNET);

        let counter = ENDPOINT_ID_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`EndpointIdMappedAddr`].
    ///
    /// This socket address does not have a routable IP address and port.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Quinn.
    fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), MAPPED_PORT)
    }
}

impl std::fmt::Display for EndpointIdMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EndpointIdMappedAddr({})", self.0)
    }
}

impl TryFrom<Ipv6Addr> for EndpointIdMappedAddr {
    type Error = EndpointIdMappedAddrError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == ADDR_PREFIXL
            && octets[1..6] == ADDR_GLOBAL_ID
            && octets[6..8] == ENDPOINT_ID_SUBNET
        {
            return Ok(Self(value));
        }
        Err(e!(EndpointIdMappedAddrError))
    }
}

/// Can occur when converting a [`SocketAddr`] to an [`EndpointIdMappedAddr`]
#[stack_error(derive, add_meta)]
#[error("Failed to convert")]
pub(crate) struct EndpointIdMappedAddrError;

/// An Ipv6 ULA address, identifying a relay path for a [`EndpointId`].
///
/// Since iroh endpoint are reachable via a relay server we have a network path indicated by
/// the `(EndpointId, RelayUrl)`.  However Quinn can only handle socket addresses, so we use
/// IPv6 addresses in a private IPv6 Unique Local Address range, which map to a unique
/// `(EndointId, RelayUrl)` pair.
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
    /// This socket address does not have a routable IP address and port.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Quinn.
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
        Err(e!(RelayMappedAddrError))
    }
}

/// Can occur when converting a [`SocketAddr`] to an [`RelayMappedAddr`]
#[stack_error(derive, add_meta)]
#[error("Failed to convert")]
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

/// Functions for the relay mapped address map.
impl AddrMap<(RelayUrl, EndpointId), RelayMappedAddr> {
    /// Converts a mapped socket address to a transport address.
    ///
    /// This takes a socket address, converts it into a [`MultipathMappedAddr`] and then tries
    /// to convert the mapped address into a [`transports::Addr`].
    ///
    /// Returns `Some` with the transport address for IP mapped addresses and for relay mapped
    /// addresses if an entry for the mapped address exists in `self`.
    ///
    /// Returns `None` and emits an error log if the mapped address is a [`MultipathMappedAddr::Mixed`],
    /// or if the mapped address is a [`MultipathMappedAddr::Relay`] and `self` does not contain the
    /// mapped address.
    pub(crate) fn to_transport_addr(
        &self,
        addr: impl Into<MultipathMappedAddr>,
    ) -> Option<transports::Addr> {
        match addr.into() {
            MultipathMappedAddr::Mixed(_) => {
                error!(
                    "Failed to convert addr to transport addr: Mixed mapped addr has no transport address"
                );
                None
            }
            MultipathMappedAddr::Relay(relay_mapped_addr) => {
                match self.lookup(&relay_mapped_addr) {
                    Some(parts) => Some(transports::Addr::from(parts)),
                    None => {
                        error!(
                            "Failed to convert addr to transport addr: Unknown relay mapped addr"
                        );
                        None
                    }
                }
            }
            MultipathMappedAddr::Ip(addr) => Some(transports::Addr::from(addr)),
        }
    }
}
