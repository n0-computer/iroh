use std::{
    collections::{hash_map::Entry, BTreeSet, HashMap},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl};
use iroh_metrics::inc;
use n0_future::time::Instant;
use serde::{Deserialize, Serialize};
use stun_rs::TransactionId;
use tracing::{debug, info, instrument, trace, warn};

use self::{
    best_addr::ClearReason,
    node_state::{NodeState, Options, PingHandled},
};
use super::{
    metrics::Metrics as MagicsockMetrics, ActorMessage, DiscoMessageSource, QuicMappedAddr,
};
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;
use crate::{
    disco::{CallMeMaybe, Pong, SendAddr},
    watchable::Watcher,
};

mod best_addr;
mod node_state;
mod path_state;
mod udp_paths;

pub use node_state::{ConnectionType, ControlMsg, DirectAddrInfo, RemoteInfo};
pub(super) use node_state::{DiscoPingPurpose, PingAction, PingRole, SendPing};

/// Number of nodes that are inactive for which we keep info about. This limit is enforced
/// periodically via [`NodeMap::prune_inactive`].
const MAX_INACTIVE_NODES: usize = 30;

/// Map of the [`NodeState`] information for all the known nodes.
///
/// The nodes can be looked up by:
///
/// - The node's ID in this map, only useful if you know the ID from an insert or lookup.
///   This is static and never changes.
///
/// - The [`QuicMappedAddr`] which internally identifies the node to the QUIC stack.  This
///   is static and never changes.
///
/// - The nodes's public key, aka `PublicKey` or "node_key".  This is static and never changes,
///   however a node could be added when this is not yet known.
///
/// - A public socket address on which they are reachable on the internet, known as ip-port.
///   These come and go as the node moves around on the internet
///
/// An index of nodeInfos by node key, QuicMappedAddr, and discovered ip:port endpoints.
#[derive(Default, Debug)]
pub(super) struct NodeMap {
    inner: Mutex<NodeMapInner>,
}

#[derive(Default, Debug)]
pub(super) struct NodeMapInner {
    by_node_key: HashMap<NodeId, usize>,
    by_ip_port: HashMap<IpPort, usize>,
    by_quic_mapped_addr: HashMap<QuicMappedAddr, usize>,
    by_id: HashMap<usize, NodeState>,
    next_id: usize,
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
}

/// Identifier to look up a [`NodeState`] in the [`NodeMap`].
///
/// You can look up entries in [`NodeMap`] with various keys, depending on the context you
/// have for the node.  These are all the keys the [`NodeMap`] can use.
#[derive(Debug, Clone)]
enum NodeStateKey {
    Idx(usize),
    NodeId(NodeId),
    QuicMappedAddr(QuicMappedAddr),
    IpPort(IpPort),
}

/// The origin or *source* through which an address associated with a remote node
/// was discovered.
///
/// An aggregate of the [`Source`]s of all the addresses of a node describe the
/// [`Source`]s of the node itself.
///
/// A [`Source`] helps track how and where an address was learned. Multiple
/// sources can be associated with a single address, if we have discovered this
/// address through multiple means.
///
/// Each time a [`NodeAddr`] is added to the node map, usually through
/// [`crate::endpoint::Endpoint::add_node_addr_with_source`], a [`Source`] must be supplied to indicate
/// how the address was obtained.
///
/// A [`Source`] can describe a variety of places that an address or node was
/// discovered, such as a configured discovery service, the network itself
/// (if another node has reached out to us), or as a user supplied [`NodeAddr`].

#[derive(Serialize, Deserialize, strum::Display, Debug, Clone, Eq, PartialEq, Hash)]
#[strum(serialize_all = "kebab-case")]
pub enum Source {
    /// Address was loaded from the fs.
    Saved,
    /// A node communicated with us first via UDP.
    Udp,
    /// A node communicated with us first via relay.
    Relay,
    /// Application layer added the address directly.
    App,
    /// The address was discovered by a discovery service.
    #[strum(serialize = "{name}")]
    Discovery {
        /// The name of the discovery service that discovered the address.
        name: String,
    },
    /// Application layer with a specific name added the node directly.
    #[strum(serialize = "{name}")]
    NamedApp {
        /// The name of the application that added the node
        name: String,
    },
}

impl NodeMap {
    #[cfg(not(any(test, feature = "test-utils")))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    pub(super) fn load_from_vec(nodes: Vec<NodeAddr>) -> Self {
        Self::from_inner(NodeMapInner::load_from_vec(nodes))
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    pub(super) fn load_from_vec(nodes: Vec<NodeAddr>, path_selection: PathSelection) -> Self {
        Self::from_inner(NodeMapInner::load_from_vec(nodes, path_selection))
    }

    fn from_inner(inner: NodeMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Add the contact information for a node.
    pub(super) fn add_node_addr(&self, node_addr: NodeAddr, source: Source) {
        self.inner
            .lock()
            .expect("poisoned")
            .add_node_addr(node_addr, source)
    }

    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.inner.lock().expect("poisoned").node_count()
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn receive_udp(&self, udp_addr: SocketAddr) -> Option<(PublicKey, QuicMappedAddr)> {
        self.inner.lock().expect("poisoned").receive_udp(udp_addr)
    }

    pub(super) fn receive_relay(&self, relay_url: &RelayUrl, src: NodeId) -> QuicMappedAddr {
        self.inner
            .lock()
            .expect("poisoned")
            .receive_relay(relay_url, src)
    }

    pub(super) fn notify_ping_sent(
        &self,
        id: usize,
        dst: SendAddr,
        tx_id: stun_rs::TransactionId,
        purpose: DiscoPingPurpose,
        msg_sender: tokio::sync::mpsc::Sender<ActorMessage>,
    ) {
        if let Some(ep) = self
            .inner
            .lock()
            .expect("poisoned")
            .get_mut(NodeStateKey::Idx(id))
        {
            ep.ping_sent(dst, tx_id, purpose, msg_sender);
        }
    }

    pub(super) fn notify_ping_timeout(&self, id: usize, tx_id: stun_rs::TransactionId) {
        if let Some(ep) = self
            .inner
            .lock()
            .expect("poisoned")
            .get_mut(NodeStateKey::Idx(id))
        {
            ep.ping_timeout(tx_id);
        }
    }

    pub(super) fn get_quic_mapped_addr_for_node_key(
        &self,
        node_key: NodeId,
    ) -> Option<QuicMappedAddr> {
        self.inner
            .lock()
            .expect("poisoned")
            .get(NodeStateKey::NodeId(node_key))
            .map(|ep| *ep.quic_mapped_addr())
    }

    /// Insert a received ping into the node map, and return whether a ping with this tx_id was already
    /// received.
    pub(super) fn handle_ping(
        &self,
        sender: PublicKey,
        src: SendAddr,
        tx_id: TransactionId,
    ) -> PingHandled {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_ping(sender, src, tx_id)
    }

    pub(super) fn handle_pong(&self, sender: PublicKey, src: &DiscoMessageSource, pong: Pong) {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_pong(sender, src, pong)
    }

    #[must_use = "actions must be handled"]
    pub(super) fn handle_call_me_maybe(
        &self,
        sender: PublicKey,
        cm: CallMeMaybe,
    ) -> Vec<PingAction> {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_call_me_maybe(sender, cm)
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn get_send_addrs(
        &self,
        addr: QuicMappedAddr,
        have_ipv6: bool,
    ) -> Option<(
        PublicKey,
        Option<SocketAddr>,
        Option<RelayUrl>,
        Vec<PingAction>,
    )> {
        let mut inner = self.inner.lock().expect("poisoned");
        let ep = inner.get_mut(NodeStateKey::QuicMappedAddr(addr))?;
        let public_key = *ep.public_key();
        trace!(dest = %addr, node_id = %public_key.fmt_short(), "dst mapped to NodeId");
        let (udp_addr, relay_url, msgs) = ep.get_send_addrs(have_ipv6);
        Some((public_key, udp_addr, relay_url, msgs))
    }

    pub(super) fn notify_shutdown(&self) {
        let mut inner = self.inner.lock().expect("poisoned");
        for (_, ep) in inner.node_states_mut() {
            ep.reset();
        }
    }

    pub(super) fn reset_node_states(&self) {
        let mut inner = self.inner.lock().expect("poisoned");
        for (_, ep) in inner.node_states_mut() {
            ep.note_connectivity_change();
        }
    }

    pub(super) fn nodes_stayin_alive(&self) -> Vec<PingAction> {
        let mut inner = self.inner.lock().expect("poisoned");
        inner
            .node_states_mut()
            .flat_map(|(_idx, node_state)| node_state.stayin_alive())
            .collect()
    }

    /// Returns the [`RemoteInfo`]s for each node in the node map.
    pub(super) fn list_remote_infos(&self, now: Instant) -> Vec<RemoteInfo> {
        // NOTE: calls to this method will often call `into_iter` (or similar methods). Note that
        // we can't avoid `collect` here since it would hold a lock for an indefinite time. Even if
        // we were to find this acceptable, dealing with the lifetimes of the mutex's guard and the
        // internal iterator will be a hassle, if possible at all.
        self.inner
            .lock()
            .expect("poisoned")
            .remote_infos_iter(now)
            .collect()
    }

    /// Returns a [`Watcher`] for given node's [`ConnectionType`].
    ///
    /// # Errors
    ///
    /// Will return an error if there is not an entry in the [`NodeMap`] for
    /// the `node_id`
    pub(super) fn conn_type(&self, node_id: NodeId) -> anyhow::Result<Watcher<ConnectionType>> {
        self.inner.lock().expect("poisoned").conn_type(node_id)
    }

    /// Get the [`RemoteInfo`]s for the node identified by [`NodeId`].
    pub(super) fn remote_info(&self, node_id: NodeId) -> Option<RemoteInfo> {
        self.inner.lock().expect("poisoned").remote_info(node_id)
    }

    /// Prunes nodes without recent activity so that at most [`MAX_INACTIVE_NODES`] are kept.
    pub(super) fn prune_inactive(&self) {
        self.inner.lock().expect("poisoned").prune_inactive();
    }

    pub(crate) fn on_direct_addr_discovered(&self, discovered: BTreeSet<SocketAddr>) {
        self.inner
            .lock()
            .expect("poisoned")
            .on_direct_addr_discovered(discovered);
    }
}

impl NodeMapInner {
    #[cfg(not(any(test, feature = "test-utils")))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    fn load_from_vec(nodes: Vec<NodeAddr>) -> Self {
        let mut me = Self::default();
        for node_addr in nodes {
            me.add_node_addr(node_addr, Source::Saved);
        }
        me
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    fn load_from_vec(nodes: Vec<NodeAddr>, path_selection: PathSelection) -> Self {
        let mut me = Self {
            path_selection,
            ..Default::default()
        };
        for node_addr in nodes {
            me.add_node_addr(node_addr, Source::Saved);
        }
        me
    }

    /// Add the contact information for a node.
    #[instrument(skip_all, fields(node = %node_addr.node_id.fmt_short()))]
    fn add_node_addr(&mut self, node_addr: NodeAddr, source: Source) {
        let source0 = source.clone();
        let node_id = node_addr.node_id;
        let relay_url = node_addr.relay_url.clone();
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(node_id), || Options {
            node_id,
            relay_url,
            active: false,
            source,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection,
        });
        node_state.update_from_node_addr(
            node_addr.relay_url.as_ref(),
            &node_addr.direct_addresses,
            source0,
        );
        let id = node_state.id();
        for addr in node_addr.direct_addresses() {
            self.set_node_state_for_ip_port(*addr, id);
        }
    }

    /// Prunes direct addresses from nodes that claim to share an address we know points to us.
    pub(super) fn on_direct_addr_discovered(&mut self, discovered: BTreeSet<SocketAddr>) {
        for addr in discovered {
            self.remove_by_ipp(addr.into(), ClearReason::MatchesOurLocalAddr)
        }
    }

    /// Removes a direct address from a node.
    fn remove_by_ipp(&mut self, ipp: IpPort, reason: ClearReason) {
        if let Some(id) = self.by_ip_port.remove(&ipp) {
            if let Entry::Occupied(mut entry) = self.by_id.entry(id) {
                let node = entry.get_mut();
                node.remove_direct_addr(&ipp, reason);
                if node.direct_addresses().count() == 0 {
                    let node_id = node.public_key();
                    let mapped_addr = node.quic_mapped_addr();
                    self.by_node_key.remove(node_id);
                    self.by_quic_mapped_addr.remove(mapped_addr);
                    debug!(node_id=%node_id.fmt_short(), ?reason, "removing node");
                    entry.remove();
                }
            }
        }
    }

    fn get_id(&self, id: NodeStateKey) -> Option<usize> {
        match id {
            NodeStateKey::Idx(id) => Some(id),
            NodeStateKey::NodeId(node_key) => self.by_node_key.get(&node_key).copied(),
            NodeStateKey::QuicMappedAddr(addr) => self.by_quic_mapped_addr.get(&addr).copied(),
            NodeStateKey::IpPort(ipp) => self.by_ip_port.get(&ipp).copied(),
        }
    }

    fn get_mut(&mut self, id: NodeStateKey) -> Option<&mut NodeState> {
        self.get_id(id).and_then(|id| self.by_id.get_mut(&id))
    }

    fn get(&self, id: NodeStateKey) -> Option<&NodeState> {
        self.get_id(id).and_then(|id| self.by_id.get(&id))
    }

    fn get_or_insert_with(
        &mut self,
        id: NodeStateKey,
        f: impl FnOnce() -> Options,
    ) -> &mut NodeState {
        let id = self.get_id(id);
        match id {
            None => self.insert_node(f()),
            Some(id) => self.by_id.get_mut(&id).expect("is not empty"),
        }
    }

    /// Number of nodes currently listed.
    fn node_count(&self) -> usize {
        self.by_id.len()
    }

    /// Marks the node we believe to be at `ipp` as recently used.
    #[cfg(not(wasm_browser))]
    fn receive_udp(&mut self, udp_addr: SocketAddr) -> Option<(NodeId, QuicMappedAddr)> {
        let ip_port: IpPort = udp_addr.into();
        let Some(node_state) = self.get_mut(NodeStateKey::IpPort(ip_port)) else {
            info!(src=%udp_addr, "receive_udp: no node_state found for addr, ignore");
            return None;
        };
        node_state.receive_udp(ip_port, Instant::now());
        Some((*node_state.public_key(), *node_state.quic_mapped_addr()))
    }

    #[instrument(skip_all, fields(src = %src.fmt_short()))]
    fn receive_relay(&mut self, relay_url: &RelayUrl, src: NodeId) -> QuicMappedAddr {
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(src), || {
            trace!("packets from unknown node, insert into node map");
            Options {
                node_id: src,
                relay_url: Some(relay_url.clone()),
                active: true,
                source: Source::Relay,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection,
            }
        });
        node_state.receive_relay(relay_url, src, Instant::now());
        *node_state.quic_mapped_addr()
    }

    fn node_states(&self) -> impl Iterator<Item = (&usize, &NodeState)> {
        self.by_id.iter()
    }

    fn node_states_mut(&mut self) -> impl Iterator<Item = (&usize, &mut NodeState)> {
        self.by_id.iter_mut()
    }

    /// Get the [`RemoteInfo`]s for all nodes.
    fn remote_infos_iter(&self, now: Instant) -> impl Iterator<Item = RemoteInfo> + '_ {
        self.node_states().map(move |(_, ep)| ep.info(now))
    }

    /// Get the [`RemoteInfo`]s for each node.
    fn remote_info(&self, node_id: NodeId) -> Option<RemoteInfo> {
        self.get(NodeStateKey::NodeId(node_id))
            .map(|ep| ep.info(Instant::now()))
    }

    /// Returns a stream of [`ConnectionType`].
    ///
    /// Sends the current [`ConnectionType`] whenever any changes to the
    /// connection type for `public_key` has occurred.
    ///
    /// # Errors
    ///
    /// Will return an error if there is not an entry in the [`NodeMap`] for
    /// the `public_key`
    fn conn_type(&self, node_id: NodeId) -> anyhow::Result<Watcher<ConnectionType>> {
        match self.get(NodeStateKey::NodeId(node_id)) {
            Some(ep) => Ok(ep.conn_type()),
            None => anyhow::bail!("No endpoint for {node_id:?} found"),
        }
    }

    fn handle_pong(&mut self, sender: NodeId, src: &DiscoMessageSource, pong: Pong) {
        if let Some(ns) = self.get_mut(NodeStateKey::NodeId(sender)).as_mut() {
            let insert = ns.handle_pong(&pong, src.into());
            if let Some((src, key)) = insert {
                self.set_node_key_for_ip_port(src, &key);
            }
            trace!(?insert, "received pong")
        } else {
            warn!("received pong: node unknown, ignore")
        }
    }

    #[must_use = "actions must be handled"]
    fn handle_call_me_maybe(&mut self, sender: NodeId, cm: CallMeMaybe) -> Vec<PingAction> {
        let ns_id = NodeStateKey::NodeId(sender);
        if let Some(id) = self.get_id(ns_id.clone()) {
            for number in &cm.my_numbers {
                // ensure the new addrs are known
                self.set_node_state_for_ip_port(*number, id);
            }
        }
        match self.get_mut(ns_id) {
            None => {
                inc!(MagicsockMetrics, recv_disco_call_me_maybe_bad_disco);
                debug!("received call-me-maybe: ignore, node is unknown");
                vec![]
            }
            Some(ns) => {
                debug!(endpoints = ?cm.my_numbers, "received call-me-maybe");

                ns.handle_call_me_maybe(cm)
            }
        }
    }

    fn handle_ping(&mut self, sender: NodeId, src: SendAddr, tx_id: TransactionId) -> PingHandled {
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(sender), || {
            debug!("received ping: node unknown, add to node map");
            let source = if src.is_relay() {
                Source::Relay
            } else {
                Source::Udp
            };
            Options {
                node_id: sender,
                relay_url: src.relay_url(),
                active: true,
                source,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection,
            }
        });

        let handled = node_state.handle_ping(src.clone(), tx_id);
        if let SendAddr::Udp(ref addr) = src {
            if matches!(handled.role, PingRole::NewPath) {
                self.set_node_key_for_ip_port(*addr, &sender);
            }
        }
        handled
    }

    /// Inserts a new node into the [`NodeMap`].
    fn insert_node(&mut self, options: Options) -> &mut NodeState {
        info!(
            node = %options.node_id.fmt_short(),
            relay_url = ?options.relay_url,
            source = %options.source,
            "inserting new node in NodeMap",
        );
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let node_state = NodeState::new(id, options);

        // update indices
        self.by_quic_mapped_addr
            .insert(*node_state.quic_mapped_addr(), id);
        self.by_node_key.insert(*node_state.public_key(), id);

        self.by_id.insert(id, node_state);
        self.by_id.get_mut(&id).expect("just inserted")
    }

    /// Makes future node lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    fn set_node_key_for_ip_port(&mut self, ipp: impl Into<IpPort>, nk: &PublicKey) {
        let ipp = ipp.into();
        if let Some(id) = self.by_ip_port.get(&ipp) {
            if !self.by_node_key.contains_key(nk) {
                self.by_node_key.insert(*nk, *id);
            }
            self.by_ip_port.remove(&ipp);
        }
        if let Some(id) = self.by_node_key.get(nk) {
            trace!("insert ip -> id: {:?} -> {}", ipp, id);
            self.by_ip_port.insert(ipp, *id);
        }
    }

    fn set_node_state_for_ip_port(&mut self, ipp: impl Into<IpPort>, id: usize) {
        let ipp = ipp.into();
        trace!(?ipp, ?id, "set endpoint for ip:port");
        self.by_ip_port.insert(ipp, id);
    }

    /// Prunes nodes without recent activity so that at most [`MAX_INACTIVE_NODES`] are kept.
    fn prune_inactive(&mut self) {
        let now = Instant::now();
        let mut prune_candidates: Vec<_> = self
            .by_id
            .values()
            .filter(|node| !node.is_active(&now))
            .map(|node| (*node.public_key(), node.last_used()))
            .collect();

        let prune_count = prune_candidates.len().saturating_sub(MAX_INACTIVE_NODES);
        if prune_count == 0 {
            // within limits
            return;
        }

        prune_candidates.sort_unstable_by_key(|(_pk, last_used)| *last_used);
        prune_candidates.truncate(prune_count);
        for (public_key, last_used) in prune_candidates.into_iter() {
            let node = public_key.fmt_short();
            match last_used.map(|instant| instant.elapsed()) {
                Some(last_used) => trace!(%node, ?last_used, "pruning inactive"),
                None => trace!(%node, last_used=%"never", "pruning inactive"),
            }

            let Some(id) = self.by_node_key.remove(&public_key) else {
                debug_assert!(false, "missing by_node_key entry for pk in by_id");
                continue;
            };

            let Some(ep) = self.by_id.remove(&id) else {
                debug_assert!(false, "missing by_id entry for id in by_node_key");
                continue;
            };

            for ip_port in ep.direct_addresses() {
                self.by_ip_port.remove(&ip_port);
            }

            self.by_quic_mapped_addr.remove(ep.quic_mapped_addr());
        }
    }
}

/// An (Ip, Port) pair.
///
/// NOTE: storing an [`IpPort`] is safer than storing a [`SocketAddr`] because for IPv6 socket
/// addresses include fields that can't be assumed consistent even within a single connection.
#[derive(Debug, derive_more::Display, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[display("{}", SocketAddr::from(*self))]
pub struct IpPort {
    ip: IpAddr,
    port: u16,
}

impl From<SocketAddr> for IpPort {
    fn from(socket_addr: SocketAddr) -> Self {
        Self {
            ip: socket_addr.ip(),
            port: socket_addr.port(),
        }
    }
}

impl From<IpPort> for SocketAddr {
    fn from(ip_port: IpPort) -> Self {
        let IpPort { ip, port } = ip_port;
        (ip, port).into()
    }
}

impl IpPort {
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh_base::SecretKey;

    use super::{node_state::MAX_INACTIVE_DIRECT_ADDRESSES, *};

    impl NodeMap {
        #[track_caller]
        fn add_test_addr(&self, node_addr: NodeAddr) {
            self.add_node_addr(
                node_addr,
                Source::NamedApp {
                    name: "test".into(),
                },
            )
        }
    }

    /// Test persisting and loading of known nodes.
    #[tokio::test]
    async fn restore_from_vec() {
        let _guard = iroh_test::logging::setup();

        let node_map = NodeMap::default();

        let mut rng = rand::thread_rng();
        let node_a = SecretKey::generate(&mut rng).public();
        let node_b = SecretKey::generate(&mut rng).public();
        let node_c = SecretKey::generate(&mut rng).public();
        let node_d = SecretKey::generate(&mut rng).public();

        let relay_x: RelayUrl = "https://my-relay-1.com".parse().unwrap();
        let relay_y: RelayUrl = "https://my-relay-2.com".parse().unwrap();

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let node_addr_a = NodeAddr::new(node_a)
            .with_relay_url(relay_x)
            .with_direct_addresses(direct_addresses_a);
        let node_addr_b = NodeAddr::new(node_b).with_relay_url(relay_y);
        let node_addr_c = NodeAddr::new(node_c).with_direct_addresses(direct_addresses_c);
        let node_addr_d = NodeAddr::new(node_d);

        node_map.add_test_addr(node_addr_a);
        node_map.add_test_addr(node_addr_b);
        node_map.add_test_addr(node_addr_c);
        node_map.add_test_addr(node_addr_d);

        let mut addrs: Vec<NodeAddr> = node_map
            .list_remote_infos(Instant::now())
            .into_iter()
            .filter_map(|info| {
                let addr: NodeAddr = info.into();
                if addr.is_empty() {
                    return None;
                }
                Some(addr)
            })
            .collect();
        let loaded_node_map = NodeMap::load_from_vec(addrs.clone(), PathSelection::default());

        let mut loaded: Vec<NodeAddr> = loaded_node_map
            .list_remote_infos(Instant::now())
            .into_iter()
            .filter_map(|info| {
                let addr: NodeAddr = info.into();
                if addr.is_empty() {
                    return None;
                }
                Some(addr)
            })
            .collect();

        loaded.sort_unstable();
        addrs.sort_unstable();

        // compare the node maps via their known nodes
        assert_eq!(addrs, loaded);
    }

    fn addr(port: u16) -> SocketAddr {
        (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
    }

    #[test]
    fn test_prune_direct_addresses() {
        let _guard = iroh_test::logging::setup();

        let node_map = NodeMap::default();
        let public_key = SecretKey::generate(rand::thread_rng()).public();
        let id = node_map
            .inner
            .lock()
            .unwrap()
            .insert_node(Options {
                node_id: public_key,
                relay_url: None,
                active: false,
                source: Source::NamedApp {
                    name: "test".into(),
                },
                path_selection: PathSelection::default(),
            })
            .id();

        const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // add [`MAX_INACTIVE_DIRECT_ADDRESSES`] active direct addresses and double
        // [`MAX_INACTIVE_DIRECT_ADDRESSES`] that are inactive

        info!("Adding active addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 5000 + i as u16);
            let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
            // add address
            node_map.add_test_addr(node_addr);
            // make it active
            node_map.inner.lock().unwrap().receive_udp(addr);
        }

        info!("Adding offline/inactive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES * 2 {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
            node_map.add_test_addr(node_addr);
        }

        let mut node_map_inner = node_map.inner.lock().unwrap();
        let endpoint = node_map_inner.by_id.get_mut(&id).unwrap();

        info!("Adding alive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = stun_rs::TransactionId::from([i as u8; 12]);
            // Note that this already invokes .prune_direct_addresses() because these are
            // new UDP paths.
            endpoint.handle_ping(addr, txid);
        }

        info!("Pruning addresses");
        endpoint.prune_direct_addresses();

        // Half the offline addresses should have been pruned.  All the active and alive
        // addresses should have been kept.
        assert_eq!(
            endpoint.direct_addresses().count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 3
        );

        // We should have both offline and alive addresses which are not active.
        assert_eq!(
            endpoint
                .direct_address_states()
                .filter(|(_addr, state)| !state.is_active())
                .count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 2
        )
    }

    #[test]
    fn test_prune_inactive() {
        let node_map = NodeMap::default();
        // add one active node and more than MAX_INACTIVE_NODES inactive nodes
        let active_node = SecretKey::generate(rand::thread_rng()).public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        node_map.add_test_addr(NodeAddr::new(active_node).with_direct_addresses([addr]));
        node_map
            .inner
            .lock()
            .unwrap()
            .receive_udp(addr)
            .expect("registered");

        for _ in 0..MAX_INACTIVE_NODES + 1 {
            let node = SecretKey::generate(rand::thread_rng()).public();
            node_map.add_test_addr(NodeAddr::new(node));
        }

        assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 2);
        node_map.prune_inactive();
        assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 1);
        node_map
            .inner
            .lock()
            .unwrap()
            .get(NodeStateKey::NodeId(active_node))
            .expect("should not be pruned");
    }
}
