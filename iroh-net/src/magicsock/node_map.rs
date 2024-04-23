use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use anyhow::{ensure, Context as _};
use futures::Stream;
use iroh_base::key::NodeId;
use iroh_metrics::inc;
use parking_lot::Mutex;
use stun_rs::TransactionId;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, instrument, trace, warn};

use self::node_state::{NodeState, Options, PingHandled};
use super::{
    metrics::Metrics as MagicsockMetrics, ActorMessage, DiscoMessageSource, QuicMappedAddr,
};
use crate::{
    disco::{CallMeMaybe, Pong, SendAddr},
    key::PublicKey,
    relay::RelayUrl,
    stun, NodeAddr,
};

mod best_addr;
mod node_state;

pub use node_state::{ConnectionType, ControlMsg, DirectAddrInfo, NodeInfo};
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
}

/// Identifier to look up a [`NodeState`] in the [`NodeMap`].
///
/// You can look up entries in [`NodeMap`] with various keys, depending on the context you
/// have for the node.  These are all the keys the [`NodeMap`] can use.
#[derive(Clone)]
enum NodeStateKey<'a> {
    Idx(&'a usize),
    NodeId(&'a NodeId),
    QuicMappedAddr(&'a QuicMappedAddr),
    IpPort(&'a IpPort),
}

impl NodeMap {
    /// Create a new [`NodeMap`] from data stored in `path`.
    pub(super) fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self::from_inner(NodeMapInner::load_from_file(path)?))
    }

    fn from_inner(inner: NodeMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Get the known node addresses stored in the map. Nodes with empty addressing information are
    /// filtered out.
    #[cfg(test)]
    pub(super) fn known_node_addresses(&self) -> Vec<NodeAddr> {
        self.inner.lock().known_node_addresses().collect()
    }

    /// Add the contact information for a node.
    pub(super) fn add_node_addr(&self, node_addr: NodeAddr) {
        self.inner.lock().add_node_addr(node_addr)
    }

    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.inner.lock().node_count()
    }

    pub(super) fn receive_udp(&self, udp_addr: SocketAddr) -> Option<(PublicKey, QuicMappedAddr)> {
        self.inner.lock().receive_udp(udp_addr)
    }

    pub(super) fn receive_relay(&self, relay_url: &RelayUrl, src: PublicKey) -> QuicMappedAddr {
        self.inner.lock().receive_relay(relay_url, &src)
    }

    pub(super) fn notify_ping_sent(
        &self,
        id: usize,
        dst: SendAddr,
        tx_id: stun::TransactionId,
        purpose: DiscoPingPurpose,
        msg_sender: tokio::sync::mpsc::Sender<ActorMessage>,
    ) {
        if let Some(ep) = self.inner.lock().get_mut(NodeStateKey::Idx(&id)) {
            ep.ping_sent(dst, tx_id, purpose, msg_sender);
        }
    }

    pub(super) fn notify_ping_timeout(&self, id: usize, tx_id: stun::TransactionId) {
        if let Some(ep) = self.inner.lock().get_mut(NodeStateKey::Idx(&id)) {
            ep.ping_timeout(tx_id);
        }
    }

    pub(super) fn get_quic_mapped_addr_for_node_key(
        &self,
        node_key: &PublicKey,
    ) -> Option<QuicMappedAddr> {
        self.inner
            .lock()
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
        self.inner.lock().handle_ping(sender, src, tx_id)
    }

    pub(super) fn handle_pong(&self, sender: PublicKey, src: &DiscoMessageSource, pong: Pong) {
        self.inner.lock().handle_pong(sender, src, pong)
    }

    #[must_use = "actions must be handled"]
    pub(super) fn handle_call_me_maybe(
        &self,
        sender: PublicKey,
        cm: CallMeMaybe,
    ) -> Vec<PingAction> {
        self.inner.lock().handle_call_me_maybe(sender, cm)
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn get_send_addrs(
        &self,
        addr: &QuicMappedAddr,
        have_ipv6: bool,
    ) -> Option<(
        PublicKey,
        Option<SocketAddr>,
        Option<RelayUrl>,
        Vec<PingAction>,
    )> {
        let mut inner = self.inner.lock();
        let ep = inner.get_mut(NodeStateKey::QuicMappedAddr(addr))?;
        let public_key = *ep.public_key();
        let (udp_addr, relay_url, msgs) = ep.get_send_addrs(have_ipv6);
        Some((public_key, udp_addr, relay_url, msgs))
    }

    pub(super) fn notify_shutdown(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.node_states_mut() {
            ep.reset();
        }
    }

    pub(super) fn reset_node_states(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.node_states_mut() {
            ep.note_connectivity_change();
        }
    }

    pub(super) fn nodes_stayin_alive(&self) -> Vec<PingAction> {
        let mut inner = self.inner.lock();
        inner
            .node_states_mut()
            .flat_map(|(_idx, node_state)| node_state.stayin_alive())
            .collect()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn node_infos(&self, now: Instant) -> Vec<NodeInfo> {
        self.inner.lock().node_infos(now)
    }

    /// Returns a stream of [`ConnectionType`].
    ///
    /// Sends the current [`ConnectionType`] whenever any changes to the
    /// connection type for `public_key` has occured.
    ///
    /// # Errors
    ///
    /// Will return an error if there is not an entry in the [`NodeMap`] for
    /// the `public_key`
    pub(super) fn conn_type_stream(
        &self,
        public_key: &PublicKey,
    ) -> anyhow::Result<ConnectionTypeStream> {
        self.inner.lock().conn_type_stream(public_key)
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn node_info(&self, public_key: &PublicKey) -> Option<NodeInfo> {
        self.inner.lock().node_info(public_key)
    }

    /// Saves the known node info to the given path, returning the number of nodes persisted.
    pub(super) async fn save_to_file(&self, path: &Path) -> anyhow::Result<usize> {
        ensure!(!path.is_dir(), "{} must be a file", path.display());

        // So, not sure what to do here.
        let mut known_nodes = self
            .inner
            .lock()
            .known_node_addresses()
            .collect::<Vec<_>>()
            .into_iter()
            .peekable();
        if known_nodes.peek().is_none() {
            // prevent file handling if unnecessary
            return Ok(0);
        }

        let mut ext = path.extension().map(|s| s.to_owned()).unwrap_or_default();
        ext.push(".tmp");
        let tmp_path = path.with_extension(ext);

        if tokio::fs::try_exists(&tmp_path).await.unwrap_or(false) {
            tokio::fs::remove_file(&tmp_path)
                .await
                .context("failed deleting existing tmp file")?;
        }
        if let Some(parent) = tmp_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut tmp = tokio::fs::File::create(&tmp_path)
            .await
            .context("failed creating tmp file")?;

        let mut count = 0;
        for node_addr in known_nodes {
            let ser = postcard::to_stdvec(&node_addr).context("failed to serialize node data")?;
            tmp.write_all(&ser)
                .await
                .context("failed to persist node data")?;
            count += 1;
        }
        tmp.flush().await.context("failed to flush node data")?;
        drop(tmp);

        // move the file
        tokio::fs::rename(tmp_path, path)
            .await
            .context("failed renaming node data file")?;
        Ok(count)
    }

    /// Prunes nodes without recent activity so that at most [`MAX_INACTIVE_NODES`] are kept.
    pub(super) fn prune_inactive(&self) {
        self.inner.lock().prune_inactive();
    }
}

impl NodeMapInner {
    /// Get the known node addresses stored in the map. Nodes with empty addressing information are
    /// filtered out.
    fn known_node_addresses(&self) -> impl Iterator<Item = NodeAddr> + '_ {
        self.by_id.values().filter_map(|endpoint| {
            let node_addr = endpoint.node_addr();
            (!node_addr.info.is_empty()).then_some(node_addr)
        })
    }

    /// Create a new [`NodeMap`] from data stored in `path`.
    fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        ensure!(path.is_file(), "{} is not a file", path.display());
        let mut me = NodeMapInner::default();
        let contents = std::fs::read(path)?;
        let mut slice: &[u8] = &contents;
        while !slice.is_empty() {
            let (node_addr, next_contents) =
                postcard::take_from_bytes(slice).context("failed to load node data")?;
            me.add_node_addr(node_addr);
            slice = next_contents;
        }
        Ok(me)
    }

    /// Add the contact information for a node.
    #[instrument(skip_all, fields(node = %node_addr.node_id.fmt_short()))]
    fn add_node_addr(&mut self, node_addr: NodeAddr) {
        let NodeAddr { node_id, info } = node_addr;

        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(&node_id), || Options {
            node_id,
            relay_url: info.relay_url.clone(),
            active: false,
        });

        node_state.update_from_node_addr(&info);
        let id = node_state.id();
        for addr in &info.direct_addresses {
            self.set_node_state_for_ip_port(*addr, id);
        }
    }

    fn get_id(&self, id: NodeStateKey) -> Option<usize> {
        match id {
            NodeStateKey::Idx(id) => Some(*id),
            NodeStateKey::NodeId(node_key) => self.by_node_key.get(node_key).copied(),
            NodeStateKey::QuicMappedAddr(addr) => self.by_quic_mapped_addr.get(addr).copied(),
            NodeStateKey::IpPort(ipp) => self.by_ip_port.get(ipp).copied(),
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
    fn receive_udp(&mut self, udp_addr: SocketAddr) -> Option<(NodeId, QuicMappedAddr)> {
        let ip_port: IpPort = udp_addr.into();
        let Some(node_state) = self.get_mut(NodeStateKey::IpPort(&ip_port)) else {
            info!(src=%udp_addr, "receive_udp: no node_state found for addr, ignore");
            return None;
        };
        node_state.receive_udp(ip_port, Instant::now());
        Some((*node_state.public_key(), *node_state.quic_mapped_addr()))
    }

    #[instrument(skip_all, fields(src = %src.fmt_short()))]
    fn receive_relay(&mut self, relay_url: &RelayUrl, src: &PublicKey) -> QuicMappedAddr {
        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(src), || {
            trace!("packets from unknown node, insert into node map");
            Options {
                node_id: *src,
                relay_url: Some(relay_url.clone()),
                active: true,
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

    /// Get the [`EndpointInfo`]s for each endpoint
    fn node_infos(&self, now: Instant) -> Vec<NodeInfo> {
        self.node_states().map(|(_, ep)| ep.info(now)).collect()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    fn node_info(&self, public_key: &PublicKey) -> Option<NodeInfo> {
        self.get(NodeStateKey::NodeId(public_key))
            .map(|ep| ep.info(Instant::now()))
    }

    /// Returns a stream of [`ConnectionType`].
    ///
    /// Sends the current [`ConnectionType`] whenever any changes to the
    /// connection type for `public_key` has occured.
    ///
    /// # Errors
    ///
    /// Will return an error if there is not an entry in the [`NodeMap`] for
    /// the `public_key`
    fn conn_type_stream(&self, public_key: &PublicKey) -> anyhow::Result<ConnectionTypeStream> {
        match self.get(NodeStateKey::NodeId(public_key)) {
            Some(ep) => Ok(ConnectionTypeStream {
                initial: Some(ep.conn_type()),
                inner: ep.conn_type_stream(),
            }),
            None => anyhow::bail!("No endpoint for {public_key:?} found"),
        }
    }

    fn handle_pong(&mut self, sender: PublicKey, src: &DiscoMessageSource, pong: Pong) {
        if let Some(ns) = self.get_mut(NodeStateKey::NodeId(&sender)).as_mut() {
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
    fn handle_call_me_maybe(&mut self, sender: PublicKey, cm: CallMeMaybe) -> Vec<PingAction> {
        let ns_id = NodeStateKey::NodeId(&sender);
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

    fn handle_ping(
        &mut self,
        sender: PublicKey,
        src: SendAddr,
        tx_id: TransactionId,
    ) -> PingHandled {
        let node_state = self.get_or_insert_with(NodeStateKey::NodeId(&sender), || {
            debug!("received ping: node unknown, add to node map");
            Options {
                node_id: sender,
                relay_url: src.relay_url(),
                active: true,
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

/// Stream returning `ConnectionTypes`
#[derive(Debug)]
pub struct ConnectionTypeStream {
    initial: Option<ConnectionType>,
    inner: watchable::WatcherStream<ConnectionType>,
}

impl Stream for ConnectionTypeStream {
    type Item = ConnectionType;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(initial_conn_type) = this.initial.take() {
            return Poll::Ready(Some(initial_conn_type));
        }
        Pin::new(&mut this.inner).poll_next(cx)
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
    use super::node_state::MAX_INACTIVE_DIRECT_ADDRESSES;
    use super::*;
    use crate::{key::SecretKey, magic_endpoint::AddrInfo};
    use std::net::Ipv4Addr;

    /// Test persisting and loading of known nodes.
    #[tokio::test]
    async fn load_save_node_data() {
        let _guard = iroh_test::logging::setup();

        let node_map = NodeMap::default();

        let node_a = SecretKey::generate().public();
        let node_b = SecretKey::generate().public();
        let node_c = SecretKey::generate().public();
        let node_d = SecretKey::generate().public();

        let relay_x: RelayUrl = "https://my-relay-1.com".parse().unwrap();
        let relay_y: RelayUrl = "https://my-relay-2.com".parse().unwrap();

        fn addr(port: u16) -> SocketAddr {
            (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
        }

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let node_addr_a = NodeAddr::new(node_a)
            .with_relay_url(relay_x)
            .with_direct_addresses(direct_addresses_a);
        let node_addr_b = NodeAddr::new(node_b).with_relay_url(relay_y);
        let node_addr_c = NodeAddr::new(node_c).with_direct_addresses(direct_addresses_c);
        let node_addr_d = NodeAddr::new(node_d);

        node_map.add_node_addr(node_addr_a);
        node_map.add_node_addr(node_addr_b);
        node_map.add_node_addr(node_addr_c);
        node_map.add_node_addr(node_addr_d);

        let root = testdir::testdir!();
        let path = root.join("nodes.postcard");
        node_map.save_to_file(&path).await.unwrap();

        let loaded_node_map = NodeMap::load_from_file(&path).unwrap();
        let loaded: HashMap<PublicKey, AddrInfo> = loaded_node_map
            .known_node_addresses()
            .into_iter()
            .map(|NodeAddr { node_id, info }| (node_id, info))
            .collect();

        let og: HashMap<PublicKey, AddrInfo> = node_map
            .known_node_addresses()
            .into_iter()
            .map(|NodeAddr { node_id, info }| (node_id, info))
            .collect();
        // compare the node maps via their known nodes
        assert_eq!(og, loaded);
    }

    #[test]
    fn test_prune_direct_addresses() {
        let _guard = iroh_test::logging::setup();

        let node_map = NodeMap::default();
        let public_key = SecretKey::generate().public();
        let id = node_map
            .inner
            .lock()
            .insert_node(Options {
                node_id: public_key,
                relay_url: None,
                active: false,
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
            node_map.add_node_addr(node_addr);
            // make it active
            node_map.inner.lock().receive_udp(addr);
        }

        info!("Adding offline/inactive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES * 2 {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
            node_map.add_node_addr(node_addr);
        }

        let mut node_map_inner = node_map.inner.lock();
        let endpoint = node_map_inner.by_id.get_mut(&id).unwrap();

        info!("Adding alive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = stun::TransactionId::from([i as u8; 12]);
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
        let active_node = SecretKey::generate().public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        node_map.add_node_addr(NodeAddr::new(active_node).with_direct_addresses([addr]));
        node_map.inner.lock().receive_udp(addr).expect("registered");

        for _ in 0..MAX_INACTIVE_NODES + 1 {
            let node = SecretKey::generate().public();
            node_map.add_node_addr(NodeAddr::new(node));
        }

        assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 2);
        node_map.prune_inactive();
        assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 1);
        node_map
            .inner
            .lock()
            .get(NodeStateKey::NodeId(&active_node))
            .expect("should not be pruned");
    }
}
