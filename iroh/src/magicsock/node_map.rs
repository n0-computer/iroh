use std::sync::Arc;
use std::{
    collections::{BTreeSet, HashMap, hash_map::Entry},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl};
use n0_future::{task::AbortOnDropHandle, time::Instant};
use node_state::{NodeStateActor, NodeStateHandle};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, instrument, trace, warn};

use self::node_state::{NodeState, Options};
use super::mapped_addrs::{AddrMap, RelayMappedAddr};
#[cfg(any(test, feature = "test-utils"))]
use super::transports::TransportsSender;
#[cfg(not(any(test, feature = "test-utils")))]
use super::transports::TransportsSender;
use super::{DirectAddr, DiscoState};
use super::{
    MagicsockMetrics,
    mapped_addrs::NodeIdMappedAddr,
    transports::{self, OwnedTransmit},
};
use crate::disco::{self, CallMeMaybe};
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;

mod node_state;
mod path_state;
mod path_validity;
mod udp_paths;

pub(super) use node_state::{NodeStateMessage, PingAction};

pub use node_state::{ConnectionType, ControlMsg, DirectAddrInfo, RemoteInfo};

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
/// - The [`NodeIdMappedAddr`] which internally identifies the node to the QUIC stack.  This
///   is static and never changes.
///
/// - The nodes's public key, aka `PublicKey` or "node_key".  This is static and never changes,
///   however a node could be added when this is not yet known.
///
/// - A public socket address on which they are reachable on the internet, known as ip-port.
///   These come and go as the node moves around on the internet
///
/// An index of nodeInfos by node key, NodeIdMappedAddr, and discovered ip:port endpoints.
#[derive(Debug)]
pub(super) struct NodeMap {
    inner: Mutex<NodeMapInner>,
    /// The mapping between [`NodeId`]s and [`NodeIdMappedAddr`]s.
    pub(super) node_mapped_addrs: AddrMap<NodeId, NodeIdMappedAddr>,
    /// The mapping between nodes via a relay and their [`RelayMappedAddr`]s.
    pub(super) relay_mapped_addrs: AddrMap<(RelayUrl, NodeId), RelayMappedAddr>,
}

#[derive(Debug)]
pub(super) struct NodeMapInner {
    metrics: Arc<MagicsockMetrics>,
    /// Handle to an actor that can send over the transports.
    transports_handle: TransportsSenderHandle,
    local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
    disco: DiscoState,
    by_node_key: HashMap<NodeId, usize>,
    by_ip_port: HashMap<IpPort, usize>,
    by_quic_mapped_addr: HashMap<NodeIdMappedAddr, usize>,
    by_id: HashMap<usize, NodeState>,
    next_id: usize,
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
    /// The [`NodeStateActor`] for each remote node.
    ///
    /// [`NodeStateActor`]: node_state::NodeStateActor
    node_states: HashMap<NodeId, NodeStateHandle>,
}

/// Identifier to look up a [`NodeState`] in the [`NodeMap`].
///
/// You can look up entries in [`NodeMap`] with various keys, depending on the context you
/// have for the node.  These are all the keys the [`NodeMap`] can use.
#[derive(Debug, Clone)]
enum NodeStateKey {
    NodeId(NodeId),
    NodeIdMappedAddr(NodeIdMappedAddr),
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
    /// The address was advertised by a call-me-maybe DISCO message.
    CallMeMaybe,
    /// We received a ping on the path.
    Ping,
}

impl NodeMap {
    #[cfg(any(test, feature = "test-utils"))]
    pub(super) fn new(
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
        local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
        disco: DiscoState,
    ) -> Self {
        Self::from_inner(NodeMapInner::new(metrics, sender, local_addrs, disco))
    }

    #[cfg(not(any(test, feature = "test-utils")))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    pub(super) async fn load_from_vec(
        nodes: Vec<NodeAddr>,
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
        local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
        disco: DiscoState,
    ) -> Self {
        let me = Self::from_inner(NodeMapInner::new(metrics, sender, local_addrs, disco));
        for addr in nodes {
            me.add_node_addr(addr, Source::Saved).await;
        }
        me
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Create a new [`NodeMap`] from a list of [`NodeAddr`]s.
    pub(super) async fn load_from_vec(
        nodes: Vec<NodeAddr>,
        path_selection: PathSelection,
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
        local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
        disco: DiscoState,
    ) -> Self {
        let mut inner = NodeMapInner::new(metrics, sender, local_addrs, disco);
        inner.path_selection = path_selection;
        let me = Self::from_inner(inner);
        for addr in nodes {
            me.add_node_addr(addr, Source::Saved).await;
        }
        me
    }

    fn from_inner(inner: NodeMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
            node_mapped_addrs: Default::default(),
            relay_mapped_addrs: Default::default(),
        }
    }

    /// Adds addresses where a node might be contactable.
    pub(super) async fn add_node_addr(&self, node_addr: NodeAddr, source: Source) {
        if let Some(ref relay_url) = node_addr.relay_url {
            // Ensure we have a RelayMappedAddress for this.
            self.relay_mapped_addrs
                .get(&(relay_url.clone(), node_addr.node_id));
        }
        let node_state = self.node_state_actor(node_addr.node_id);

        // This only fails if the sender is closed.  That means the NodeStateActor has
        // stopped, which only happens during shutdown.
        node_state
            .send(NodeStateMessage::AddNodeAddr(node_addr, source))
            .await
            .ok();
    }

    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.inner.lock().expect("poisoned").node_count()
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn receive_udp(
        &self,
        udp_addr: SocketAddr,
    ) -> Option<(PublicKey, NodeIdMappedAddr)> {
        self.inner.lock().expect("poisoned").receive_udp(udp_addr)
    }

    pub(super) fn receive_relay(&self, relay_url: &RelayUrl, src: NodeId) -> NodeIdMappedAddr {
        self.inner
            .lock()
            .expect("poisoned")
            .receive_relay(relay_url, src)
    }

    pub(super) fn get_all_paths_addr_for_node(&self, node_id: NodeId) -> Option<NodeIdMappedAddr> {
        self.inner
            .lock()
            .expect("poisoned")
            .get(NodeStateKey::NodeId(node_id))
            .map(|ep| *ep.all_paths_mapped_addr())
    }

    pub(super) fn get_direct_addrs(&self, node_key: NodeId) -> Vec<SocketAddr> {
        self.inner
            .lock()
            .expect("poisoned")
            .get(NodeStateKey::NodeId(node_key))
            .map(|ep| ep.direct_addresses().map(Into::into).collect())
            .unwrap_or_default()
    }

    /// Returns a [`NodeAddr`] with all the currently known direct addresses and the relay URL.
    pub(super) fn get_current_addr(&self, node_key: NodeId) -> Option<NodeAddr> {
        self.inner
            .lock()
            .expect("poisoned")
            .get(NodeStateKey::NodeId(node_key))
            .map(|ep| ep.get_current_addr())
    }

    pub(super) fn handle_call_me_maybe(
        &self,
        sender: PublicKey,
        cm: CallMeMaybe,
        metrics: &MagicsockMetrics,
    ) {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_call_me_maybe(sender, cm, metrics);
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn get_send_addrs(
        &self,
        addr: NodeIdMappedAddr,
        have_ipv6: bool,
        metrics: &MagicsockMetrics,
    ) -> Option<(
        PublicKey,
        Option<SocketAddr>,
        Option<RelayUrl>,
        Vec<PingAction>,
    )> {
        let mut inner = self.inner.lock().expect("poisoned");
        let ep = inner.get_mut(NodeStateKey::NodeIdMappedAddr(addr))?;
        let public_key = *ep.public_key();
        trace!(dest = %addr, node_id = %public_key.fmt_short(), "dst mapped to NodeId");
        let (udp_addr, relay_url, ping_actions) = ep.get_send_addrs(have_ipv6, metrics);
        Some((public_key, udp_addr, relay_url, ping_actions))
    }

    pub(super) fn reset_node_states(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("poisoned");
        for (_, ep) in inner.node_states_mut() {
            ep.note_connectivity_change(now);
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

    /// Returns a [`n0_watcher::Direct`] for given node's [`ConnectionType`].
    ///
    /// # Errors
    ///
    /// Will return `None` if there is not an entry in the [`NodeMap`] for
    /// the `node_id`
    pub(super) fn conn_type(&self, node_id: NodeId) -> Option<n0_watcher::Direct<ConnectionType>> {
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
            .on_direct_addr_discovered(discovered, Instant::now());
    }

    /// Returns the sender for the [`NodeStateActor`].
    ///
    /// If needed a new actor is started on demand.
    ///
    /// [`NodeStateActor`]: node_state::NodeStateActor
    pub(super) fn node_state_actor(&self, node_id: NodeId) -> mpsc::Sender<NodeStateMessage> {
        let mut inner = self.inner.lock().expect("poisoned");
        match inner.node_states.get(&node_id) {
            Some(handle) => handle.sender.clone(),
            None => {
                // Create a new NodeStateActor and insert it into the node map.
                let sender = inner.transports_handle.inbox.clone();
                let local_addrs = inner.local_addrs.clone();
                let disco = inner.disco.clone();
                let metrics = inner.metrics.clone();
                let actor = NodeStateActor::new(node_id, sender, local_addrs, disco, metrics);
                let handle = actor.start();
                let sender = handle.sender.clone();
                inner.node_states.insert(node_id, handle);

                // Ensure there is a NodeMappedAddr for this NodeId.
                self.node_mapped_addrs.get(&node_id);
                sender
            }
        }
    }

    pub(super) fn handle_ping(&self, msg: disco::Ping, sender: NodeId, src: transports::Addr) {
        if msg.node_key != sender {
            warn!("DISCO Ping NodeId mismatch, ignoring ping");
            return;
        }
        let node_state = self.node_state_actor(sender);
        if let Err(err) = node_state.try_send(NodeStateMessage::PingReceived(msg, src)) {
            // TODO: This is really, really bad and will drop pings under load.  But
            //    DISCO pings are going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO Ping dropped: {err:#}");
        }
    }

    pub(super) fn handle_pong(&self, msg: disco::Pong, sender: NodeId, src: transports::Addr) {
        let node_state = self.node_state_actor(sender);
        if let Err(err) = node_state.try_send(NodeStateMessage::PongReceived(msg, src)) {
            // TODO: This is really, really bad and will drop pings under load.  But
            //    DISCO pings are going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO Pong dropped: {err:#}");
        }
    }
}

impl NodeMapInner {
    fn new(
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
        local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
        disco: DiscoState,
    ) -> Self {
        let transports_handle = Self::start_transports_sender(sender);
        Self {
            metrics,
            transports_handle,
            local_addrs,
            disco,
            by_node_key: Default::default(),
            by_ip_port: Default::default(),
            by_quic_mapped_addr: Default::default(),
            by_id: Default::default(),
            next_id: 0,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: Default::default(),
            node_states: Default::default(),
        }
    }

    fn start_transports_sender(sender: TransportsSender) -> TransportsSenderHandle {
        let actor = TransportsSenderActor::new(sender);
        actor.start()
    }

    /// Prunes direct addresses from nodes that claim to share an address we know points to us.
    pub(super) fn on_direct_addr_discovered(
        &mut self,
        discovered: BTreeSet<SocketAddr>,
        now: Instant,
    ) {
        for addr in discovered {
            self.remove_by_ipp(addr.into(), now, "matches our local addr")
        }
    }

    /// Removes a direct address from a node.
    fn remove_by_ipp(&mut self, ipp: IpPort, now: Instant, why: &'static str) {
        if let Some(id) = self.by_ip_port.remove(&ipp) {
            if let Entry::Occupied(mut entry) = self.by_id.entry(id) {
                let node = entry.get_mut();
                node.remove_direct_addr(&ipp, now, why);
                if node.direct_addresses().count() == 0 {
                    let node_id = node.public_key();
                    let mapped_addr = node.all_paths_mapped_addr();
                    self.by_node_key.remove(node_id);
                    self.by_quic_mapped_addr.remove(mapped_addr);
                    debug!(node_id=%node_id.fmt_short(), why, "removing node");
                    entry.remove();
                }
            }
        }
    }

    fn get_id(&self, id: NodeStateKey) -> Option<usize> {
        match id {
            NodeStateKey::NodeId(node_key) => self.by_node_key.get(&node_key).copied(),
            NodeStateKey::NodeIdMappedAddr(addr) => self.by_quic_mapped_addr.get(&addr).copied(),
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
    fn receive_udp(&mut self, udp_addr: SocketAddr) -> Option<(NodeId, NodeIdMappedAddr)> {
        let ip_port: IpPort = udp_addr.into();
        let Some(node_state) = self.get_mut(NodeStateKey::IpPort(ip_port)) else {
            trace!(src=%udp_addr, "receive_udp: no node_state found for addr, ignore");
            return None;
        };
        node_state.receive_udp(ip_port, Instant::now());
        Some((
            *node_state.public_key(),
            *node_state.all_paths_mapped_addr(),
        ))
    }

    #[instrument(skip_all, fields(src = %src.fmt_short()))]
    fn receive_relay(&mut self, relay_url: &RelayUrl, src: NodeId) -> NodeIdMappedAddr {
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
        *node_state.all_paths_mapped_addr()
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
    /// Will return `None` if there is not an entry in the [`NodeMap`] for
    /// the `public_key`
    fn conn_type(&self, node_id: NodeId) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.get(NodeStateKey::NodeId(node_id))
            .map(|ep| ep.conn_type())
    }

    fn handle_call_me_maybe(
        &mut self,
        sender: NodeId,
        cm: CallMeMaybe,
        metrics: &MagicsockMetrics,
    ) {
        let ns_id = NodeStateKey::NodeId(sender);
        if let Some(id) = self.get_id(ns_id.clone()) {
            for number in &cm.my_numbers {
                // ensure the new addrs are known
                self.set_node_state_for_ip_port(*number, id);
            }
        }
        match self.get_mut(ns_id) {
            None => {
                debug!("received call-me-maybe: ignore, node is unknown");
                metrics.recv_disco_call_me_maybe_bad_disco.inc();
            }
            Some(ns) => {
                debug!(endpoints = ?cm.my_numbers, "received call-me-maybe");

                ns.handle_call_me_maybe(cm);
            }
        }
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
            .insert(*node_state.all_paths_mapped_addr(), id);
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

            self.by_quic_mapped_addr.remove(ep.all_paths_mapped_addr());
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

/// An actor that can send datagrams onto iroh transports.
///
/// The [`NodeStateActor`]s want to be able to send datagrams.  Because we can not create
/// [`TransportsSender`]s on demand we must share one for the entire [`NodeMap`], which
/// lives in this actor.
///
/// [`NodeStateActor`]: node_state::NodeStateActor
#[derive(Debug)]
struct TransportsSenderActor {
    sender: TransportsSender,
}

impl TransportsSenderActor {
    fn new(sender: TransportsSender) -> Self {
        Self { sender }
    }

    fn start(self) -> TransportsSenderHandle {
        // This actor gets an inbox size of exactly 1.  This is the same as if they had the
        // underlying sender directly: either you can send or not, or you await until you
        // can.  No need to introduce extra buffering.
        let (tx, rx) = mpsc::channel(1);

        // No .instrument() on task, run method has an #[instrument] attribute.
        let task = tokio::spawn(async move {
            self.run(rx).await;
        });
        TransportsSenderHandle {
            inbox: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

    #[instrument(name = "TransportsSenderActor", skip_all)]
    async fn run(self, mut inbox: mpsc::Receiver<TransportsSenderMessage>) {
        use TransportsSenderMessage::SendDatagram;

        loop {
            if let Some(SendDatagram(dst, owned_transmit)) = inbox.recv().await {
                let transmit = transports::Transmit {
                    ecn: owned_transmit.ecn,
                    contents: owned_transmit.contents.as_ref(),
                    segment_size: owned_transmit.segment_size,
                };
                let len = transmit.contents.len();
                match self.sender.send(&dst, None, &transmit).await {
                    Ok(()) => {
                        trace!(?dst, %len, "sent transmit");
                    }
                    Err(err) => {
                        trace!(?dst, %len, "transmit failed to send: {err:#}");
                    }
                };
            } else {
                break;
            }
        }
        trace!("actor terminating");
    }
}

#[derive(Debug)]
struct TransportsSenderHandle {
    inbox: mpsc::Sender<TransportsSenderMessage>,
    _task: AbortOnDropHandle<()>,
}

#[derive(Debug)]
enum TransportsSenderMessage {
    SendDatagram(transports::Addr, OwnedTransmit),
}

impl From<(transports::Addr, OwnedTransmit)> for TransportsSenderMessage {
    fn from(source: (transports::Addr, OwnedTransmit)) -> Self {
        Self::SendDatagram(source.0, source.1)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use iroh_base::SecretKey;
    use tracing_test::traced_test;

    use super::{node_state::MAX_INACTIVE_DIRECT_ADDRESSES, *};
    use crate::disco::SendAddr;
    use crate::magicsock::DiscoveredDirectAddrs;
    use crate::magicsock::transports::Transports;

    impl NodeMap {
        async fn add_test_addr(&self, node_addr: NodeAddr) {
            self.add_node_addr(
                node_addr,
                Source::NamedApp {
                    name: "test".into(),
                },
            )
            .await;
        }
    }

    /// Test persisting and loading of known nodes.
    #[tokio::test]
    #[traced_test]
    async fn restore_from_vec() {
        let transports = Transports::new(Vec::new(), Vec::new(), Arc::new(1200.into()));
        let direct_addrs = DiscoveredDirectAddrs::default();
        let (disco, _) = DiscoState::new(&SecretKey::generate(&mut rand::rngs::OsRng));
        let node_map = NodeMap::new(
            Default::default(),
            transports.create_sender(),
            direct_addrs.addrs.watch(),
            disco.clone(),
        );

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

        node_map.add_test_addr(node_addr_a).await;
        node_map.add_test_addr(node_addr_b).await;
        node_map.add_test_addr(node_addr_c).await;
        node_map.add_test_addr(node_addr_d).await;

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
        let loaded_node_map = NodeMap::load_from_vec(
            addrs.clone(),
            PathSelection::default(),
            Default::default(),
            transports.create_sender(),
            direct_addrs.addrs.watch(),
            disco,
        )
        .await;

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

    #[tokio::test]
    #[traced_test]
    async fn test_prune_direct_addresses() {
        let transports = Transports::new(Vec::new(), Vec::new(), Arc::new(1200.into()));
        let direct_addrs = DiscoveredDirectAddrs::default();
        let (disco, _) = DiscoState::new(&SecretKey::generate(&mut rand::rngs::OsRng));
        let node_map = NodeMap::new(
            Default::default(),
            transports.create_sender(),
            direct_addrs.addrs.watch(),
            disco,
        );
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
            node_map.add_test_addr(node_addr).await;
            // make it active
            node_map.inner.lock().unwrap().receive_udp(addr);
        }

        info!("Adding offline/inactive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES * 2 {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
            node_map.add_test_addr(node_addr).await;
        }

        let mut node_map_inner = node_map.inner.lock().unwrap();
        let endpoint = node_map_inner.by_id.get_mut(&id).unwrap();

        info!("Adding alive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = stun_rs::TransactionId::from([i as u8; 12]);
            // Note that this already invokes .prune_direct_addresses() because these are
            // new UDP paths.
            // endpoint.handle_ping(addr, txid);
        }

        info!("Pruning addresses");
        endpoint.prune_direct_addresses(Instant::now());

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

    #[tokio::test]
    async fn test_prune_inactive() {
        let transports = Transports::new(Vec::new(), Vec::new(), Arc::new(1200.into()));
        let direct_addrs = DiscoveredDirectAddrs::default();
        let (disco, _) = DiscoState::new(&SecretKey::generate(&mut rand::rngs::OsRng));
        let node_map = NodeMap::new(
            Default::default(),
            transports.create_sender(),
            direct_addrs.addrs.watch(),
            disco,
        );
        // add one active node and more than MAX_INACTIVE_NODES inactive nodes
        let active_node = SecretKey::generate(rand::thread_rng()).public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        node_map
            .add_test_addr(NodeAddr::new(active_node).with_direct_addresses([addr]))
            .await;
        node_map
            .inner
            .lock()
            .unwrap()
            .receive_udp(addr)
            .expect("registered");

        for _ in 0..MAX_INACTIVE_NODES + 1 {
            let node = SecretKey::generate(rand::thread_rng()).public();
            node_map.add_test_addr(NodeAddr::new(node)).await;
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
