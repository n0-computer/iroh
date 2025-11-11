use std::{
    collections::{BTreeSet, hash_map},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::warn;

use super::{
    DirectAddr, DiscoState, MagicsockMetrics,
    mapped_addrs::{AddrMap, EndpointIdMappedAddr, RelayMappedAddr},
    transports::{self, TransportsSender},
};
use crate::disco::{self};
// #[cfg(any(test, feature = "test-utils"))]
// use crate::endpoint::PathSelection;

mod endpoint_state;
mod path_state;

pub(super) use endpoint_state::EndpointStateMessage;
pub(crate) use endpoint_state::PathsWatchable;
pub use endpoint_state::{ConnectionType, PathInfo, PathInfoList};
use endpoint_state::{EndpointStateActor, EndpointStateHandle};

/// Interval in which handles to closed [`EndpointStateActor`]s should be removed.
pub(super) const ENDPOINT_MAP_GC_INTERVAL: Duration = Duration::from_secs(60);

// TODO: use this
// /// Number of endpoints that are inactive for which we keep info about. This limit is enforced
// /// periodically via [`NodeMap::prune_inactive`].
// const MAX_INACTIVE_NODES: usize = 30;

/// Map containing all the state for endpoints.
///
/// - Has actors which each manage all the connection state for a remote endpoint.
///
/// - Has the mapped addresses we use to refer to non-IP transports destinations into IPv6
///   addressing space that is used by Quinn.
#[derive(Debug)]
pub(crate) struct EndpointMap {
    //
    // State we keep about remote endpoints.
    //
    /// The actors tracking each remote endpoint.
    actor_handles: Mutex<FxHashMap<EndpointId, EndpointStateHandle>>,
    /// The mapping between [`EndpointId`]s and [`EndpointIdMappedAddr`]s.
    pub(super) endpoint_mapped_addrs: AddrMap<EndpointId, EndpointIdMappedAddr>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    pub(super) relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,

    //
    // State needed to start a new EndpointStateHandle.
    //
    /// The endpoint ID of the local endpoint.
    local_endpoint_id: EndpointId,
    metrics: Arc<MagicsockMetrics>,
    local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    disco: DiscoState,
    sender: TransportsSender,
}

impl EndpointMap {
    /// Creates a new [`EndpointMap`].
    pub(super) fn new(
        local_endpoint_id: EndpointId,
        // TODO:
        // #[cfg(any(test, feature = "test-utils"))] path_selection: PathSelection,
        metrics: Arc<MagicsockMetrics>,

        local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        disco: DiscoState,
        sender: TransportsSender,
    ) -> Self {
        Self {
            actor_handles: Mutex::new(FxHashMap::default()),
            endpoint_mapped_addrs: Default::default(),
            relay_mapped_addrs: Default::default(),
            local_endpoint_id,
            metrics,
            local_addrs,
            disco,
            sender,
        }
    }

    /// Adds addresses where an endpoint might be contactable.
    pub(super) async fn add_endpoint_addr(&self, endpoint_addr: EndpointAddr, source: Source) {
        for url in endpoint_addr.relay_urls() {
            // Ensure we have a RelayMappedAddress.
            self.relay_mapped_addrs
                .get(&(url.clone(), endpoint_addr.id));
        }
        let actor = self.endpoint_state_actor(endpoint_addr.id);

        // This only fails if the sender is closed.  That means the EndpointStateActor has
        // stopped, which only happens during shutdown.
        actor
            .send(EndpointStateMessage::AddEndpointAddr(endpoint_addr, source))
            .await
            .ok();
    }

    pub(super) fn endpoint_mapped_addr(&self, eid: EndpointId) -> EndpointIdMappedAddr {
        self.endpoint_mapped_addrs.get(&eid)
    }

    /// Returns a [`n0_watcher::Direct`] for given endpoint's [`ConnectionType`].
    ///
    /// # Errors
    ///
    /// Will return `None` if there is not an entry in the [`EndpointMap`] for
    /// the `endpoint_id`
    pub(super) fn conn_type(
        &self,
        _endpoint_id: EndpointId,
    ) -> Option<n0_watcher::Direct<ConnectionType>> {
        todo!();
    }

    /// Removes the handles for terminated [`EndpointStateActor`]s from the endpoint map.
    ///
    /// This should be called periodically to remove handles to endpoint state actors
    /// that have shutdown after their idle timeout expired.
    pub(super) fn remove_closed_endpoint_state_actors(&self) {
        let mut handles = self.actor_handles.lock().expect("poisoned");
        handles.retain(|_eid, handle| !handle.sender.is_closed())
    }

    /// Returns the sender for the [`EndpointStateActor`].
    ///
    /// If needed a new actor is started on demand.
    ///
    /// [`EndpointStateActor`]: endpoint_state::EndpointStateActor
    pub(super) fn endpoint_state_actor(
        &self,
        eid: EndpointId,
    ) -> mpsc::Sender<EndpointStateMessage> {
        let mut handles = self.actor_handles.lock().expect("poisoned");
        match handles.entry(eid) {
            hash_map::Entry::Occupied(mut entry) => {
                if let Some(sender) = entry.get().sender.get() {
                    sender
                } else {
                    // The actor is dead: Start a new actor.
                    let (handle, sender) = self.start_endpoint_state_actor(eid);
                    entry.insert(handle);
                    sender
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let (handle, sender) = self.start_endpoint_state_actor(eid);
                entry.insert(handle);
                sender
            }
        }
    }

    /// Starts a new endpoint state actor and returns a handle and a sender.
    ///
    /// The handle is not inserted into the endpoint map, this must be done by the caller of this function.
    fn start_endpoint_state_actor(
        &self,
        eid: EndpointId,
    ) -> (EndpointStateHandle, mpsc::Sender<EndpointStateMessage>) {
        // Ensure there is a EndpointMappedAddr for this EndpointId.
        self.endpoint_mapped_addrs.get(&eid);
        let handle = EndpointStateActor::new(
            eid,
            self.local_endpoint_id,
            self.local_addrs.clone(),
            self.disco.clone(),
            self.relay_mapped_addrs.clone(),
            self.metrics.clone(),
            self.sender.clone(),
        )
        .start();
        let sender = handle.sender.get().expect("just created");
        (handle, sender)
    }

    pub(super) fn handle_ping(&self, msg: disco::Ping, sender: EndpointId, src: transports::Addr) {
        if msg.endpoint_key != sender {
            warn!("DISCO Ping EndpointId mismatch, ignoring ping");
            return;
        }
        let endpoint_state = self.endpoint_state_actor(sender);
        if let Err(err) = endpoint_state.try_send(EndpointStateMessage::PingReceived(msg, src)) {
            // TODO: This is really, really bad and will drop pings under load.  But
            //    DISCO pings are going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO Ping dropped: {err:#}");
        }
    }

    pub(super) fn handle_pong(&self, msg: disco::Pong, sender: EndpointId, src: transports::Addr) {
        let actor = self.endpoint_state_actor(sender);
        if let Err(err) = actor.try_send(EndpointStateMessage::PongReceived(msg, src)) {
            // TODO: This is really, really bad and will drop pongs under load.  But
            //    DISCO pongs are going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO Pong dropped: {err:#}");
        }
    }

    pub(super) fn handle_call_me_maybe(
        &self,
        msg: disco::CallMeMaybe,
        sender: EndpointId,
        src: transports::Addr,
    ) {
        if !src.is_relay() {
            warn!("DISCO CallMeMaybe packets should only come via relay");
            return;
        }
        let actor = self.endpoint_state_actor(sender);
        if let Err(err) = actor.try_send(EndpointStateMessage::CallMeMaybeReceived(msg)) {
            // TODO: This is bad and will drop call-me-maybe's under load.  But
            //    DISCO CallMeMaybe going away with QUIC-NAT-TRAVERSAL so I don't care.
            warn!("DISCO CallMeMaybe dropped: {err:#}");
        }
    }
}

/// The origin or *source* through which an address associated with a remote endpoint
/// was discovered.
///
/// An aggregate of the [`Source`]s of all the addresses of an endpoint describe the
/// [`Source`]s of the endpoint itself.
///
/// A [`Source`] helps track how and where an address was learned. Multiple
/// sources can be associated with a single address, if we have discovered this
/// address through multiple means.
#[derive(Serialize, Deserialize, strum::Display, Debug, Clone, Eq, PartialEq, Hash)]
#[strum(serialize_all = "kebab-case")]
pub enum Source {
    /// Address was loaded from the fs.
    Saved,
    /// An endpoint communicated with us first via UDP.
    Udp,
    /// An endpoint communicated with us first via relay.
    Relay,
    /// Application layer added the address directly.
    App,
    /// The address was discovered by a discovery service.
    #[strum(serialize = "{name}")]
    Discovery {
        /// The name of the discovery service that discovered the address.
        name: String,
    },
    /// Application layer with a specific name added the endpoint directly.
    #[strum(serialize = "{name}")]
    NamedApp {
        /// The name of the application that added the endpoint
        name: String,
    },
    /// The address was advertised by a call-me-maybe DISCO message.
    CallMeMaybe,
    /// We received a ping on the path.
    Ping,
    /// We established a connection on this address.
    ///
    /// Currently this means the path was in uses as [`PathId::ZERO`] when the a connection
    /// was added to the `EndpointStateActor`.
    ///
    /// [`PathId::ZERO`]: quinn_proto::PathId::ZERO
    Connection,
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
