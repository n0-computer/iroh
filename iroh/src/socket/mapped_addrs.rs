//! The various mapped addresses we use.

//! We use non-IP transports to carry datagrams.  Yet Noq needs to address those
//! transports using IPv6 addresses.  These defines mappings of several IPv6 Unique Local
//! Address ranges we use to keep track of the various "fake" address types we use.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use iroh_base::{EndpointId, RelayUrl};
use n0_error::{e, stack_error};
use rand::Rng;
use rustc_hash::FxHashMap;
use tracing::trace;

/// The Prefix/L of all Unique Local Addresses.
const ADDR_PREFIXL: u8 = 0xfd;

/// The Global ID used in n0's Unique Local Addresses.
const ADDR_GLOBAL_ID: [u8; 5] = [0x15, 0x07, 0x0a, 0x51, 0x0b];

/// The Subnet ID for [`RelayMappedAddr]: fd15:70a:510b:1::/64.
const RELAY_MAPPED_SUBNET: [u8; 2] = [0x00, 0x01];

/// The Subnet ID for [`CustomMappedAddr`]: fd15:70a:510b:3::/64.
const CUSTOM_MAPPED_SUBNET: [u8; 2] = [0x00, 0x03];

/// The Subnet ID for [`EndpointIdMappedAddr`]: fd15:70a:510b::/64.
const ENDPOINT_ID_SUBNET: [u8; 2] = [0x00, 0x00];

/// A default fake addr, using the maximum addr that the internal fake addrs could be using.
pub(crate) const DEFAULT_FAKE_ADDR: SocketAddrV6 = SocketAddrV6::new(
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
/// We map each entity, usually an [`crate::EndpointId`], to an IPv6 address.  But socket addresses
/// involve ports, so we use a dummy fixed port when creating socket addresses.
const MAPPED_PORT: u16 = 12345;

/// Generic mapped address.
///
/// Allows implementing [`AddrMap`].
pub(crate) trait MappedAddr {
    /// Generates a new mapped address in the IPv6 Unique Local Address space.
    ///
    /// The host bits are random so a remote peer cannot guess one of our live mapped
    /// addresses (uniqueness is ensured by [`AddrMap::get`]).
    fn generate() -> Self;

    /// Returns a consistent [`SocketAddr`] for the mapped addr.
    ///
    /// This socket address does not have a routable IP address.  It uses a fake but
    /// consistent port number, since the port does not play a role in the addressing.  This
    /// socket address is only to be used to pass into Noq.
    fn private_socket_addr(&self) -> SocketAddr;
}

/// An enum encompassing all the mapped and unmapped addresses.
///
/// This is essentially a slightly-stronger typed version of the IPv6 mapped addresses that
/// we use on the Noq side.  It categorises the addressed in what kind of mapped or
/// unmapped addresses they are.
///
/// It does not guarantee that a mapped address exists in the mapping.  Or that a particular
/// address is even supported on this platform.  Hence no wasm exceptions here.
#[derive(Clone, Debug)]
pub(crate) enum MultipathMappedAddr {
    /// An address for a [`crate::EndpointId`], via one or more paths.
    Mixed(EndpointIdMappedAddr),
    /// An address for a particular [`crate::EndpointId`] via a particular relay.
    Relay(RelayMappedAddr),
    /// An IP based transport address.
    Ip(SocketAddr),
    /// Custom transport address.
    Custom(CustomMappedAddr),
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
                if let Ok(addr) = CustomMappedAddr::try_from(addr) {
                    return Self::Custom(addr);
                }
                Self::Ip(value)
            }
        }
    }
}

/// An address used to address a endpoint on any or all paths.
///
/// This is only used for initially connecting to a remote endpoint.  We instruct Noq to
/// send to this address, and duplicate all packets for this address to send on all paths we
/// might want to send the initial on:
///
/// - If this the first connection to the remote endpoint we don't know which path will work
///   and send to all of them.
///
/// - If there already is an active connection to this endpoint we now which path to use.
///
/// It is but a newtype around an IPv6 Unique Local Addr.  And in our QUIC-facing socket
/// APIs like [`noq::AsyncUdpSocket`] it comes in as the inner [`Ipv6Addr`], in those
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
        rand::rng().fill_bytes(&mut addr[8..16]);

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`EndpointIdMappedAddr`].
    ///
    /// This socket address does not have a routable IP address and port.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Noq.
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

/// An Ipv6 ULA address, identifying a relay path for a [`crate::EndpointId`].
///
/// Since iroh endpoint are reachable via a relay server we have a network path indicated by
/// the `(EndpointId, RelayUrl)`.  However Noq can only handle socket addresses, so we use
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
        rand::rng().fill_bytes(&mut addr[8..16]);

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`RelayMappedAddr`].
    ///
    /// This socket address does not have a routable IP address and port.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Noq.
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

/// An Ipv6 ULA address, identifying a custom transport path.
///
/// Custom transports allow user-defined transport mechanisms. However Noq can only handle
/// socket addresses, so we use IPv6 addresses in a private IPv6 Unique Local Address range,
/// which map to a unique [`iroh_base::CustomAddr`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct CustomMappedAddr(Ipv6Addr);

impl MappedAddr for CustomMappedAddr {
    /// Generates a globally unique fake UDP address.
    ///
    /// This generates a new IPv6 address in the Unique Local Address range (RFC 4193)
    /// which is recognised by iroh as an IP mapped address.
    fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&CUSTOM_MAPPED_SUBNET);
        rand::rng().fill_bytes(&mut addr[8..16]);

        Self(Ipv6Addr::from(addr))
    }

    /// Returns a consistent [`SocketAddr`] for the [`CustomMappedAddr`].
    ///
    /// This socket address does not have a routable IP address and port.
    ///
    /// This uses a made-up port number, since the port does not play a role in the
    /// addressing.  This socket address is only to be used to pass into Noq.
    fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), MAPPED_PORT)
    }
}

impl TryFrom<IpAddr> for CustomMappedAddr {
    type Error = CustomMappedAddrError;

    fn try_from(value: IpAddr) -> std::result::Result<Self, Self::Error> {
        match value {
            IpAddr::V4(_) => Err(e!(CustomMappedAddrError)),
            IpAddr::V6(addr) => addr.try_into(),
        }
    }
}

impl TryFrom<Ipv6Addr> for CustomMappedAddr {
    type Error = CustomMappedAddrError;

    fn try_from(value: Ipv6Addr) -> std::result::Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == ADDR_PREFIXL
            && octets[1..6] == ADDR_GLOBAL_ID
            && octets[6..8] == CUSTOM_MAPPED_SUBNET
        {
            return Ok(Self(value));
        }
        Err(e!(CustomMappedAddrError))
    }
}

/// Can occur when converting a [`SocketAddr`] to a [`CustomMappedAddr`]
#[stack_error(derive, add_meta)]
#[error("Failed to convert")]
pub(crate) struct CustomMappedAddrError;

impl std::fmt::Display for CustomMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "CustomMappedAddr({})", self.0)
    }
}

/// A bi-directional map between a key and a [`MappedAddr`].
///
/// Entries are only removed explicitly with [`AddrMap::remove`]. Keys come from trusted
/// sources or are removed by their owner, see [`RelayAddrMap`] for relay-chosen keys.
///
/// The forward map uses the standard library's randomly seeded hasher because keys may be
/// chosen by remotes whereas the reverse map uses `FxHashMap` because mapped addresses are
/// generated locally at random.
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
                let addr = generate_unique(&inner.lookup);
                inner.addrs.insert(key.clone(), addr);
                inner.lookup.insert(addr, key.clone());
                trace!(?addr, ?key, "generated new addr");
                addr
            }
        }
    }

    /// Removes the entry for `key`, if any.
    pub(super) fn remove(&self, key: &K) {
        let mut inner = self.inner.lock().expect("poisoned");
        if let Some(addr) = inner.addrs.remove(key) {
            inner.lookup.remove(&addr);
            trace!(?addr, ?key, "removed addr");
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
    addrs: HashMap<K, V>,
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

/// Generates a mapped address not yet present in `lookup`.
///
/// It's important these are generated randomly and not a counter in order to be
/// unpredictable from the outside.
fn generate_unique<V: MappedAddr + Eq + Hash, K>(lookup: &FxHashMap<V, K>) -> V {
    loop {
        let candidate = V::generate();
        if !lookup.contains_key(&candidate) {
            break candidate;
        }
    }
}

/// Maximum number of unpinned entries per relay in a [`RelayAddrMap`].
///
/// Bounding per relay ensures a relay forging source IDs can only evict unpinned entries
/// from its own traffic.
const MAX_UNPINNED_PER_RELAY: usize = 1024;

/// Maximum number of relays with unpinned entries in a [`RelayAddrMap`].
///
/// Adding a relay beyond this limit evicts all unpinned entries of the least recently used
/// relay, bounding entries left behind by relays we are no longer connected to.
const MAX_UNPINNED_RELAYS: usize = 64;

/// A bi-directional map between `(RelayUrl, EndpointId)` and [`RelayMappedAddr`].
///
/// Every datagram received over a relay needs a mapped address, and the relay chooses the
/// source [`EndpointId`]. Noq may keep using a mapped address for as long as a connection
/// or handshake refers to it, so entries are either pinned or unpinned:
///
/// - [`RelayAddrMap::get_unpinned`] looks up or inserts an entry for a received datagram.
///   New entries are unpinned.
///
/// - The `RemoteStateActor` of an endpoint pins the entries of that endpoint which its
///   connections use as paths, with [`RelayAddrMap::get_pinned`] or
///   [`RelayAddrMap::pin_addr`]. Pinned entries are never evicted.
///   [`RelayAddrMap::unpin_endpoint`] unpins them again once the actor stops.
///
/// - Unpinned entries are bounded per relay and in the number of relays. When a bound is
///   exceeded, the oldest unpinned entries are removed.
#[derive(Debug, Clone, Default)]
pub(super) struct RelayAddrMap {
    inner: Arc<std::sync::Mutex<RelayAddrMapInner>>,
}

impl RelayAddrMap {
    /// Returns the [`RelayMappedAddr`] for `key`, pinning it for the endpoint it names.
    pub(super) fn get_pinned(&self, key: &(RelayUrl, EndpointId)) -> RelayMappedAddr {
        let mut inner = self.inner.lock().expect("poisoned");
        inner.entries.pin(key)
    }

    /// Pins the entry for `addr` and returns its key, if the entry exists and names
    /// `endpoint_id`.
    ///
    /// Looking up and pinning under one lock ensures the entry cannot be evicted in between.
    /// Entries naming another endpoint are not pinned and `None` is returned: they would
    /// otherwise stay pinned for an endpoint whose actor may never run, and so never be
    /// unpinned.
    pub(super) fn pin_addr(
        &self,
        addr: &RelayMappedAddr,
        endpoint_id: &EndpointId,
    ) -> Option<(RelayUrl, EndpointId)> {
        let mut inner = self.inner.lock().expect("poisoned");
        let key = inner
            .entries
            .lookup
            .get(addr)
            .filter(|key| key.1 == *endpoint_id)
            .cloned()?;
        inner.entries.pin(&key);
        Some(key)
    }

    /// Returns the [`RelayMappedAddr`] for `key`, inserting an unpinned entry if needed.
    pub(super) fn get_unpinned(&self, key: &(RelayUrl, EndpointId)) -> RelayMappedAddr {
        let mut guard = self.inner.lock().expect("poisoned");
        let inner = &mut *guard;
        // Only receive traffic refreshes a relay, so silent relays are evicted first.
        let pushed = inner.touch_relay(&key.0);
        match inner.entries.addrs.get(key) {
            Some(RelayEntry {
                addr,
                queued: Some(seq),
            }) => {
                let (addr, seq) = (*addr, *seq);
                if pushed - seq > MAX_UNPINNED_PER_RELAY as u64 / 2 {
                    // Refresh active unpinned entries once they are past the midpoint of the
                    // queue, avoiding a new queue record on every packet.
                    inner.enqueue(key);
                }
                addr
            }
            Some(RelayEntry { addr, queued: None }) => *addr,
            None => {
                let addr = inner.entries.get_or_insert(key).addr;
                inner.enqueue(key);
                addr
            }
        }
    }

    /// Unpins all entries of `endpoint_id` after its `RemoteStateActor` has stopped.
    ///
    /// The entries are queued rather than removed, so Noq can finish handshakes that are
    /// still in flight and a reconnecting peer keeps its mapped address unless evicted in
    /// the meantime.
    pub(super) fn unpin_endpoint(&self, endpoint_id: &EndpointId) {
        let mut inner = self.inner.lock().expect("poisoned");
        let relays = inner.entries.pinned.remove(endpoint_id).unwrap_or_default();
        for relay in relays {
            inner.enqueue(&(relay, *endpoint_id));
        }
    }

    /// Performs the reverse lookup.
    pub(super) fn lookup(&self, addr: &RelayMappedAddr) -> Option<(RelayUrl, EndpointId)> {
        let inner = self.inner.lock().expect("poisoned");
        inner.entries.lookup.get(addr).cloned()
    }

    /// Returns the number of entries.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner.lock().expect("poisoned").entries.addrs.len()
    }

    /// Returns whether an entry for `addr` exists and is pinned.
    #[cfg(test)]
    pub(super) fn is_pinned(&self, addr: &RelayMappedAddr) -> bool {
        let inner = self.inner.lock().expect("poisoned");
        inner
            .entries
            .lookup
            .get(addr)
            .and_then(|key| inner.entries.addrs.get(key))
            .is_some_and(|entry| entry.queued.is_none())
    }
}

#[derive(Debug, Default)]
struct RelayAddrMapInner {
    entries: RelayEntries,
    /// Per-relay FIFO queues of unpinned entries.
    queues: HashMap<RelayUrl, UnpinnedQueue>,
    /// Monotonic counter incremented on [`RelayAddrMap::get_unpinned`], used for
    /// [`UnpinnedQueue::last_used`].
    tick: u64,
}

/// Forward, reverse, and pin tables for a [`RelayAddrMap`].
#[derive(Debug, Default)]
struct RelayEntries {
    addrs: HashMap<(RelayUrl, EndpointId), RelayEntry>,
    lookup: FxHashMap<RelayMappedAddr, (RelayUrl, EndpointId)>,
    /// Relays on which each endpoint currently has pinned entries.
    pinned: HashMap<EndpointId, HashSet<RelayUrl>>,
}

#[derive(Debug)]
struct RelayEntry {
    addr: RelayMappedAddr,
    /// Sequence number of this entry's live record in its relay's [`UnpinnedQueue`], or
    /// `None` if the entry is pinned.
    ///
    /// Queue records with any other sequence number are stale (left behind when the entry
    /// was pinned or requeued) and are ignored on pop.
    queued: Option<u64>,
}

#[derive(Debug, Default)]
struct UnpinnedQueue {
    /// Queued `(key, seq)` records from oldest to newest.
    ///
    /// May contain stale records; see [`RelayEntry::queued`].
    records: VecDeque<((RelayUrl, EndpointId), u64)>,
    /// Sequence number of the most recently pushed record.
    pushed: u64,
    /// Value of [`RelayAddrMapInner::tick`] when this relay last delivered a datagram.
    last_used: u64,
}

impl RelayAddrMapInner {
    /// Marks `relay` as recently used, first evicting the unpinned entries of the least
    /// recently used relay if adding `relay` would exceed [`MAX_UNPINNED_RELAYS`].
    ///
    /// Returns [`UnpinnedQueue::pushed`] of `relay`'s queue.
    fn touch_relay(&mut self, relay: &RelayUrl) -> u64 {
        self.tick += 1;
        // Runs on every received relay datagram, so the common case is a single lookup.
        if let Some(queue) = self.queues.get_mut(relay) {
            queue.last_used = self.tick;
            return queue.pushed;
        }
        if self.queues.len() >= MAX_UNPINNED_RELAYS {
            let least_recent = self
                .queues
                .iter()
                .min_by_key(|(_, queue)| queue.last_used)
                .map(|(relay, _)| relay.clone());
            if let Some(queue) = least_recent.and_then(|relay| self.queues.remove(&relay)) {
                for (key, seq) in queue.records {
                    self.entries.evict_record(&key, seq);
                }
            }
        }
        let queue = UnpinnedQueue {
            last_used: self.tick,
            ..Default::default()
        };
        self.queues.insert(relay.clone(), queue);
        0
    }

    /// Pushes `key` onto its relay's queue and evicts the oldest records past
    /// [`MAX_UNPINNED_PER_RELAY`].
    ///
    /// Does not update `last_used`: if the relay has no queue yet, it is created with
    /// `last_used = 0`, so unpinning entries of silent relays cannot displace active ones.
    /// If [`MAX_UNPINNED_RELAYS`] queues already exist, the entry is evicted immediately.
    fn enqueue(&mut self, key: &(RelayUrl, EndpointId)) {
        let Self {
            entries, queues, ..
        } = self;
        let Some(entry) = entries.addrs.get_mut(key) else {
            return;
        };
        if !queues.contains_key(&key.0) && queues.len() >= MAX_UNPINNED_RELAYS {
            entries.remove(key);
            return;
        }

        let queue = queues.entry(key.0.clone()).or_default();
        queue.pushed += 1;
        queue.records.push_back((key.clone(), queue.pushed));
        entry.queued = Some(queue.pushed);
        while queue.records.len() > MAX_UNPINNED_PER_RELAY {
            if let Some((key, seq)) = queue.records.pop_front() {
                entries.evict_record(&key, seq);
            }
        }
    }
}

impl RelayEntries {
    /// Returns the entry for `key`, inserting one with a fresh address if needed.
    ///
    /// The caller must immediately either pin or enqueue a new entry.
    fn get_or_insert(&mut self, key: &(RelayUrl, EndpointId)) -> &mut RelayEntry {
        self.addrs.entry(key.clone()).or_insert_with(|| {
            let addr = generate_unique(&self.lookup);
            self.lookup.insert(addr, key.clone());
            trace!(?addr, ?key, "generated new addr");
            RelayEntry { addr, queued: None }
        })
    }

    /// Marks the entry for `key` as pinned by the endpoint it names, inserting it if needed.
    fn pin(&mut self, key: &(RelayUrl, EndpointId)) -> RelayMappedAddr {
        self.pinned.entry(key.1).or_default().insert(key.0.clone());
        let entry = self.get_or_insert(key);
        entry.queued = None;
        entry.addr
    }

    /// Removes the entry for `key` if `seq` is still its current queue record.
    fn evict_record(&mut self, key: &(RelayUrl, EndpointId), seq: u64) {
        if self
            .addrs
            .get(key)
            .is_some_and(|entry| entry.queued == Some(seq))
        {
            self.remove(key);
        }
    }

    /// Removes the entry for `key`.
    fn remove(&mut self, key: &(RelayUrl, EndpointId)) {
        if let Some(entry) = self.addrs.remove(key) {
            self.lookup.remove(&entry.addr);
            trace!(addr = ?entry.addr, ?key, "evicted unpinned addr");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use iroh_base::SecretKey;

    use super::*;

    const MAX: u64 = MAX_UNPINNED_PER_RELAY as u64;
    const RELAYS: u8 = MAX_UNPINNED_RELAYS as u8;

    fn id(i: u64) -> EndpointId {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::from_bytes(&bytes).public()
    }

    fn url(relay: u8) -> RelayUrl {
        format!("https://relay{relay}.example")
            .parse()
            .expect("valid url")
    }

    fn key(relay: u8, i: u64) -> (RelayUrl, EndpointId) {
        (url(relay), id(i))
    }

    /// Inserts `n` unpinned entries for distinct endpoints on `relay`.
    fn flood(map: &RelayAddrMap, relay: u8, n: u64) -> Vec<RelayMappedAddr> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1_000_000);
        (0..n)
            .map(|_| {
                let i = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                map.get_unpinned(&key(relay, i))
            })
            .collect()
    }

    #[test]
    fn test_addr_map_remove() {
        let map = AddrMap::<EndpointId, RelayMappedAddr>::default();
        let addr = map.get(&id(1));
        assert_eq!(map.get(&id(1)), addr);
        assert_eq!(map.lookup(&addr), Some(id(1)));

        map.remove(&id(1));
        assert_eq!(map.lookup(&addr), None);
        assert!(map.inner.lock().unwrap().addrs.is_empty());
    }

    #[test]
    fn test_get_is_stable_and_reversible() {
        let map = RelayAddrMap::default();
        let addr = map.get_pinned(&key(0, 1));
        assert_eq!(map.get_pinned(&key(0, 1)), addr);
        assert_eq!(map.get_unpinned(&key(0, 1)), addr);
        assert_eq!(map.lookup(&addr), Some(key(0, 1)));
    }

    /// Flooding a relay with unpinned entries stays within the per-relay cap and preserves
    /// pinned entries and other relays.
    #[test]
    fn test_unpinned_entries_are_bounded_per_relay() {
        let map = RelayAddrMap::default();
        let pinned = map.get_pinned(&key(0, 0));
        // Created on receive, then registered as a path by the actor of id(1).
        let received = map.get_unpinned(&key(0, 1));
        map.pin_addr(&received, &id(1));
        let other_relay = map.get_unpinned(&key(1, 2));

        let flood = flood(&map, 0, 3 * MAX);

        assert_eq!(map.lookup(&pinned), Some(key(0, 0)));
        assert_eq!(map.lookup(&received), Some(key(0, 1)));
        assert_eq!(map.lookup(&other_relay), Some(key(1, 2)));
        assert!(map.lookup(flood.last().unwrap()).is_some());
        assert!(map.lookup(&flood[0]).is_none());
        // Two pinned entries, the other relay's entry, plus the capped relay.
        assert_eq!(map.len(), 3 + MAX_UNPINNED_PER_RELAY);
    }

    /// Pinning an unpinned entry protects it from eviction.
    #[test]
    fn test_get_pinned_pins_unpinned_entry() {
        let map = RelayAddrMap::default();
        let addr = map.get_unpinned(&key(0, 1));
        assert_eq!(map.get_pinned(&key(0, 1)), addr);
        flood(&map, 0, 2 * MAX);
        assert_eq!(map.lookup(&addr), Some(key(0, 1)));
    }

    /// `pin_addr` only pins entries naming the given endpoint.
    #[test]
    fn test_pin_addr_ignores_other_endpoints() {
        let map = RelayAddrMap::default();
        let addr = map.get_unpinned(&key(0, 1));
        // A relay labelled id(2)'s path as id(1).
        assert_eq!(map.pin_addr(&addr, &id(2)), None);
        assert!(map.inner.lock().unwrap().entries.pinned.is_empty());
        flood(&map, 0, MAX);
        assert_eq!(map.lookup(&addr), None);
        assert_eq!(map.pin_addr(&addr, &id(1)), None, "evicted");
    }

    /// `pin_addr` pins entries naming the given endpoint and returns their key.
    #[test]
    fn test_pin_addr_returns_key() {
        let map = RelayAddrMap::default();
        let addr = map.get_unpinned(&key(0, 1));
        assert_eq!(map.pin_addr(&addr, &id(1)), Some(key(0, 1)));
        assert!(map.is_pinned(&addr));
    }

    /// Unpinning an endpoint keeps its entries until they are evicted and places them at the
    /// back of the queue even if they were previously near the front.
    #[test]
    fn test_unpin_endpoint() {
        let map = RelayAddrMap::default();
        // Created on receive, then registered as a path by the actor of id(1).
        let received = map.get_unpinned(&key(0, 1));
        map.pin_addr(&received, &id(1));
        flood(&map, 0, MAX - 1);
        let pinned = map.get_pinned(&key(1, 1));
        let other = map.get_pinned(&key(0, 2));

        // The actor of id(1) stops.
        map.unpin_endpoint(&id(1));
        assert_eq!(map.lookup(&received), Some(key(0, 1)));
        assert_eq!(map.lookup(&pinned), Some(key(1, 1)));

        flood(&map, 0, MAX - 1);
        assert_eq!(map.lookup(&received), Some(key(0, 1)));
        flood(&map, 0, 1);
        assert_eq!(map.lookup(&received), None);
        assert_eq!(map.lookup(&pinned), Some(key(1, 1)), "other relay");
        assert_eq!(map.lookup(&other), Some(key(0, 2)), "still pinned");
        assert!(
            !map.inner
                .lock()
                .unwrap()
                .entries
                .pinned
                .contains_key(&id(1))
        );
    }

    /// Unpinning entries of relays without a queue once at [`MAX_UNPINNED_RELAYS`] evicts
    /// those entries instead of displacing active relays.
    #[test]
    fn test_unpin_does_not_add_relays() {
        let map = RelayAddrMap::default();
        let addrs: Vec<_> = (0..RELAYS)
            .map(|relay| map.get_unpinned(&key(relay, relay as u64)))
            .collect();
        // Pinned entries on relays that have no unpinned queue yet.
        let candidates: Vec<_> = (0..10)
            .map(|i| map.get_pinned(&key(RELAYS + i, 500)))
            .collect();

        map.unpin_endpoint(&id(500));
        assert!(addrs.iter().all(|addr| map.lookup(addr).is_some()));
        assert!(candidates.iter().all(|addr| map.lookup(addr).is_none()));
        assert_eq!(map.inner.lock().unwrap().queues.len(), MAX_UNPINNED_RELAYS);
    }

    /// A hit on a pinned entry marks its relay as used.
    #[test]
    fn test_pinned_hit_marks_relay_used() {
        let map = RelayAddrMap::default();
        let unpinned = map.get_unpinned(&key(0, 0));
        map.get_pinned(&key(0, 1));
        for relay in 1..RELAYS {
            map.get_unpinned(&key(relay, relay as u64 + 100));
        }
        // Receive traffic on the pinned entry refreshes relay 0.
        map.get_unpinned(&key(0, 1));

        map.get_unpinned(&key(RELAYS, 1000));
        assert_eq!(map.lookup(&unpinned), Some(key(0, 0)));
    }

    /// An unpinned entry that keeps receiving traffic is refreshed before it reaches the
    /// front of the queue.
    #[test]
    fn test_used_unpinned_entry_is_requeued() {
        let map = RelayAddrMap::default();
        let addr = map.get_unpinned(&key(0, 1));
        for i in 0..3 * MAX {
            map.get_unpinned(&key(0, 100 + i));
            assert_eq!(map.get_unpinned(&key(0, 1)), addr);
        }
    }

    /// Unpinning into a new relay queue leaves `last_used` at 0 so that silent relays are
    /// evicted before relays with receive traffic.
    #[test]
    fn test_unpin_does_not_refresh_relays() {
        let map = RelayAddrMap::default();
        // A relay with a handshake in flight.
        let handshake = map.get_unpinned(&key(0, 0));
        // An actor that pinned entries on relays without receive traffic stops.
        for relay in 1..RELAYS {
            map.get_pinned(&key(relay, 500));
        }
        map.unpin_endpoint(&id(500));
        {
            let inner = map.inner.lock().unwrap();
            assert_eq!(inner.queues.len(), MAX_UNPINNED_RELAYS);
            for relay in 1..RELAYS {
                assert_eq!(inner.queues[&url(relay)].last_used, 0);
            }
        }

        // Traffic from a new relay evicts one of the silent relays, not the active one.
        map.get_unpinned(&key(RELAYS, 1000));
        assert_eq!(map.lookup(&handshake), Some(key(0, 0)));
    }

    /// Popping an older stale queue record does not evict an entry that was pinned and later
    /// requeued with a newer sequence number.
    #[test]
    fn test_stale_record_does_not_evict_requeued_entry() {
        let map = RelayAddrMap::default();
        let addr = map.get_unpinned(&key(0, 1));
        // Pin and later unpin: the first record becomes stale once the second is pushed.
        map.get_pinned(&key(0, 1));
        flood(&map, 0, MAX - 1);
        // Requeueing overflows the queue and pops the stale record.
        map.unpin_endpoint(&id(1));
        assert_eq!(map.lookup(&addr), Some(key(0, 1)));
        assert_eq!(map.len(), MAX_UNPINNED_PER_RELAY);
    }

    /// The number of relays with unpinned entries is capped at [`MAX_UNPINNED_RELAYS`],
    /// evicting the least recently used relay.
    #[test]
    fn test_unpinned_relays_are_bounded() {
        let map = RelayAddrMap::default();
        let first = map.get_unpinned(&key(0, 0));
        let second = map.get_unpinned(&key(1, 1));
        let rest: Vec<_> = (2..RELAYS)
            .map(|relay| map.get_unpinned(&key(relay, relay as u64)))
            .collect();
        // Refresh relay 0 so relay 1 becomes the least recently used.
        map.get_unpinned(&key(0, 0));

        let new = map.get_unpinned(&key(RELAYS, 1000));
        assert_eq!(map.lookup(&first), Some(key(0, 0)));
        assert_eq!(
            map.lookup(&second),
            None,
            "least recently used relay evicted"
        );
        assert!(rest.iter().all(|addr| map.lookup(addr).is_some()));
        assert!(map.lookup(&new).is_some());
        assert_eq!(map.len(), MAX_UNPINNED_RELAYS);
        assert_eq!(map.inner.lock().unwrap().queues.len(), MAX_UNPINNED_RELAYS);
    }
}
