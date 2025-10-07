use std::sync::Arc;
use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

use iroh_base::{NodeAddr, NodeId, RelayUrl};
use n0_future::task::AbortOnDropHandle;
use node_state::{NodeStateActor, NodeStateHandle};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{Instrument, info_span, trace, warn};

use crate::disco::{self};
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;

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

mod node_state;
mod path_state;

pub(super) use node_state::NodeStateMessage;

pub use node_state::{ConnectionType, ControlMsg, DirectAddrInfo};

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
    /// The node ID of the local node.
    local_node_id: NodeId,
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
    /// We established a connection on this address.
    ///
    /// Currently this means the path was in uses as [`PathId::ZERO`] when the a connection
    /// was added to the [`NodeStateActor`].
    ///
    /// [`PathId::ZERO`]: quinn_proto::PathId::ZERO
    /// [`NodeStateActor`]: self::node_state::NodeStateActor
    Connection,
}

impl NodeMap {
    /// Creates a new [`NodeMap`].
    pub(super) fn new(
        local_node_id: NodeId,
        #[cfg(any(test, feature = "test-utils"))] path_selection: PathSelection,
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
        local_addrs: n0_watcher::Direct<Option<BTreeSet<DirectAddr>>>,
        disco: DiscoState,
    ) -> Self {
        let mut inner = NodeMapInner::new(metrics, sender, local_addrs, disco);

        #[cfg(any(test, feature = "test-utils"))]
        {
            inner.path_selection = path_selection;
        }

        Self {
            local_node_id,
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

    pub(super) fn node_mapped_addr(&self, node_id: NodeId) -> NodeIdMappedAddr {
        self.node_mapped_addrs.get(&node_id)
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
                let actor = NodeStateActor::new(
                    node_id,
                    self.local_node_id,
                    sender,
                    local_addrs,
                    disco,
                    self.relay_mapped_addrs.clone(),
                    metrics,
                );
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
            // TODO: This is really, really bad and will drop pongs under load.  But
            //    DISCO pongs are going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO Pong dropped: {err:#}");
        }
    }

    pub(super) fn handle_call_me_maybe(
        &self,
        msg: disco::CallMeMaybe,
        sender: NodeId,
        src: transports::Addr,
    ) {
        if !src.is_relay() {
            warn!("DISCO CallMeMaybe packets should only come via relay");
            return;
        }
        let node_state = self.node_state_actor(sender);
        if let Err(err) = node_state.try_send(NodeStateMessage::CallMeMaybeReceived(msg)) {
            // TODO: This is bad and will drop call-me-maybe's under load.  But
            //    DISCO CallMeMaybe going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO CallMeMaybe dropped: {err:#}");
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
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: Default::default(),
            node_states: Default::default(),
        }
    }

    fn start_transports_sender(sender: TransportsSender) -> TransportsSenderHandle {
        let actor = TransportsSenderActor::new(sender);
        actor.start()
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
    fn conn_type(&self, _node_id: NodeId) -> Option<n0_watcher::Direct<ConnectionType>> {
        todo!();
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

        let task = tokio::spawn(
            async move {
                self.run(rx).await;
            }
            .instrument(info_span!("TransportsSenderActor")),
        );
        TransportsSenderHandle {
            inbox: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

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
                    Ok(()) => {}
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

    use tracing_test::traced_test;

    // use super::*;

    // impl NodeMap {
    //     async fn add_test_addr(&self, node_addr: NodeAddr) {
    //         self.add_node_addr(
    //             node_addr,
    //             Source::NamedApp {
    //                 name: "test".into(),
    //             },
    //         )
    //         .await;
    //     }
    // }

    // fn addr(port: u16) -> SocketAddr {
    //     (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
    // }

    #[tokio::test]
    #[traced_test]
    async fn test_prune_direct_addresses() {
        panic!("support this again");
        // let transports = Transports::new(Vec::new(), Vec::new(), Arc::new(1200.into()));
        // let direct_addrs = DiscoveredDirectAddrs::default();
        // let secret_key = SecretKey::generate(&mut rand::rngs::OsRng);
        // let (disco, _) = DiscoState::new(&secret_key);
        // let node_map = NodeMap::new(
        //     secret_key.public(),
        //     Default::default(),
        //     transports.create_sender(),
        //     direct_addrs.addrs.watch(),
        //     disco,
        // );
        // let public_key = SecretKey::generate(rand::thread_rng()).public();
        // let id = node_map
        //     .inner
        //     .lock()
        //     .unwrap()
        //     .insert_node(Options {
        //         node_id: public_key,
        //         relay_url: None,
        //         active: false,
        //         source: Source::NamedApp {
        //             name: "test".into(),
        //         },
        //         path_selection: PathSelection::default(),
        //     })
        //     .id();

        // const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // // add [`MAX_INACTIVE_DIRECT_ADDRESSES`] active direct addresses and double
        // // [`MAX_INACTIVE_DIRECT_ADDRESSES`] that are inactive

        // info!("Adding active addresses");
        // for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
        //     let addr = SocketAddr::new(LOCALHOST, 5000 + i as u16);
        //     let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
        //     // add address
        //     node_map.add_test_addr(node_addr).await;
        //     // make it active
        //     node_map.inner.lock().unwrap().receive_udp(addr);
        // }

        // info!("Adding offline/inactive addresses");
        // for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES * 2 {
        //     let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
        //     let node_addr = NodeAddr::new(public_key).with_direct_addresses([addr]);
        //     node_map.add_test_addr(node_addr).await;
        // }

        // let mut node_map_inner = node_map.inner.lock().unwrap();
        // let endpoint = node_map_inner.by_id.get_mut(&id).unwrap();

        // info!("Adding alive addresses");
        // for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
        //     let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
        //     let txid = stun_rs::TransactionId::from([i as u8; 12]);
        //     // Note that this already invokes .prune_direct_addresses() because these are
        //     // new UDP paths.
        //     // endpoint.handle_ping(addr, txid);
        // }

        // info!("Pruning addresses");
        // endpoint.prune_direct_addresses(Instant::now());

        // // Half the offline addresses should have been pruned.  All the active and alive
        // // addresses should have been kept.
        // assert_eq!(
        //     endpoint.direct_addresses().count(),
        //     MAX_INACTIVE_DIRECT_ADDRESSES * 3
        // );

        // // We should have both offline and alive addresses which are not active.
        // assert_eq!(
        //     endpoint
        //         .direct_address_states()
        //         .filter(|(_addr, state)| !state.is_active())
        //         .count(),
        //     MAX_INACTIVE_DIRECT_ADDRESSES * 2
        // )
    }

    #[tokio::test]
    async fn test_prune_inactive() {
        panic!("support this again");
        // let transports = Transports::new(Vec::new(), Vec::new(), Arc::new(1200.into()));
        // let direct_addrs = DiscoveredDirectAddrs::default();
        // let secret_key = SecretKey::generate(&mut rand::rngs::OsRng);
        // let (disco, _) = DiscoState::new(&secret_key);
        // let node_map = NodeMap::new(
        //     secret_key.public(),
        //     Default::default(),
        //     transports.create_sender(),
        //     direct_addrs.addrs.watch(),
        //     disco,
        // );
        // // add one active node and more than MAX_INACTIVE_NODES inactive nodes
        // let active_node = SecretKey::generate(rand::thread_rng()).public();
        // let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        // node_map
        //     .add_test_addr(NodeAddr::new(active_node).with_direct_addresses([addr]))
        //     .await;
        // node_map
        //     .inner
        //     .lock()
        //     .unwrap()
        //     .receive_udp(addr)
        //     .expect("registered");

        // for _ in 0..MAX_INACTIVE_NODES + 1 {
        //     let node = SecretKey::generate(rand::thread_rng()).public();
        //     node_map.add_test_addr(NodeAddr::new(node)).await;
        // }

        // assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 2);
        // node_map.prune_inactive();
        // assert_eq!(node_map.node_count(), MAX_INACTIVE_NODES + 1);
        // node_map
        //     .inner
        //     .lock()
        //     .unwrap()
        //     .get(NodeStateKey::NodeId(active_node))
        //     .expect("should not be pruned");
    }
}
