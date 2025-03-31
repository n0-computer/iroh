use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Can occur when converting a [`SocketAddr`] to an [`IpMappedAddr`]
#[derive(Debug, thiserror::Error)]
#[error("Failed to convert")]
pub struct IpMappedAddrError;

/// A map fake Ipv6 address with an actual IP address.
///
/// It is essentially a lookup key for an IP that iroh's magicsocket knows about.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct IpMappedAddr(Ipv6Addr);

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
    pub fn generate() -> Self {
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
    pub fn private_socket_addr(&self) -> SocketAddr {
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

/// A Map of [`IpMappedAddresses`] to [`SocketAddr`].
// TODO(ramfox): before this is ready to be used beyond QAD, we should add
// mechanisms for keeping track of "aliveness" and pruning address, as we do
// with the `NodeMap`
#[derive(Debug, Clone, Default)]
pub struct IpMappedAddresses(Arc<std::sync::Mutex<Inner>>);

#[derive(Debug, Default)]
pub struct Inner {
    by_mapped_addr: BTreeMap<IpMappedAddr, SocketAddr>,
    /// Because [`std::net::SocketAddrV6`] contains extra fields besides the IP
    /// address and port (ie, flow_info and scope_id), the a [`std::net::SocketAddrV6`]
    /// with the same IP addr and port might Hash to something different.
    /// So to get a hashable key for the map, we are using `(IpAddr, u6)`.
    by_ip_port: BTreeMap<(IpAddr, u16), IpMappedAddr>,
}

impl IpMappedAddresses {
    /// Creates an empty [`IpMappedAddresses`].
    pub fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(Inner::default())))
    }

    /// Adds a [`SocketAddr`] to the map and returns the generated [`IpMappedAddr`].
    ///
    /// If this [`SocketAddr`] already exists in the map, it returns its
    /// associated [`IpMappedAddr`].
    ///
    /// Otherwise a new [`IpMappedAddr`] is generated for it and returned.
    pub fn get_or_register(&self, socket_addr: SocketAddr) -> IpMappedAddr {
        let ip_port = (socket_addr.ip(), socket_addr.port());
        let mut inner = self.0.lock().expect("poisoned");
        if let Some(mapped_addr) = inner.by_ip_port.get(&ip_port) {
            return *mapped_addr;
        }
        let ip_mapped_addr = IpMappedAddr::generate();
        inner.by_mapped_addr.insert(ip_mapped_addr, socket_addr);
        inner.by_ip_port.insert(ip_port, ip_mapped_addr);
        ip_mapped_addr
    }

    /// Returns the [`IpMappedAddr`] for the given [`SocketAddr`].
    pub fn get_mapped_addr(&self, socket_addr: &SocketAddr) -> Option<IpMappedAddr> {
        let ip_port = (socket_addr.ip(), socket_addr.port());
        let inner = self.0.lock().expect("poisoned");
        inner.by_ip_port.get(&ip_port).copied()
    }

    /// Returns the [`SocketAddr`] for the given [`IpMappedAddr`].
    pub fn get_ip_addr(&self, mapped_addr: &IpMappedAddr) -> Option<SocketAddr> {
        let inner = self.0.lock().expect("poisoned");
        inner.by_mapped_addr.get(mapped_addr).copied()
    }
}
