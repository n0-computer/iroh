use std::{
    collections::{BTreeSet, hash_map},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_base::{EndpointId, RelayUrl};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub(crate) use self::remote_state::PathsWatcher;
pub(super) use self::remote_state::RemoteStateMessage;
pub use self::remote_state::{PathInfo, PathInfoList};
use self::remote_state::{RemoteStateActor, RemoteStateHandle};
use super::{
    DirectAddr, MagicsockMetrics,
    mapped_addrs::{AddrMap, EndpointIdMappedAddr, RelayMappedAddr},
    transports::TransportsSender,
};
use crate::discovery::ConcurrentDiscovery;

mod remote_state;

/// Interval in which handles to closed [`RemoteStateActor`]s should be removed.
pub(super) const REMOTE_MAP_GC_INTERVAL: Duration = Duration::from_secs(60);

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
pub(crate) struct RemoteMap {
    //
    // State we keep about remote endpoints.
    //
    /// The actors tracking each remote endpoint.
    actor_handles: Mutex<FxHashMap<EndpointId, RemoteStateHandle>>,
    /// The mapping between [`EndpointId`]s and [`EndpointIdMappedAddr`]s.
    pub(super) endpoint_mapped_addrs: AddrMap<EndpointId, EndpointIdMappedAddr>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    pub(super) relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,

    //
    // State needed to start a new RemoteStateHandle.
    //
    /// The endpoint ID of the local endpoint.
    local_endpoint_id: EndpointId,
    metrics: Arc<MagicsockMetrics>,
    local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    sender: TransportsSender,
    discovery: ConcurrentDiscovery,
}

impl RemoteMap {
    /// Creates a new [`RemoteMap`].
    pub(super) fn new(
        local_endpoint_id: EndpointId,
        metrics: Arc<MagicsockMetrics>,
        local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        sender: TransportsSender,
        discovery: ConcurrentDiscovery,
    ) -> Self {
        Self {
            actor_handles: Mutex::new(FxHashMap::default()),
            endpoint_mapped_addrs: Default::default(),
            relay_mapped_addrs: Default::default(),
            local_endpoint_id,
            metrics,
            local_addrs,
            sender,
            discovery,
        }
    }

    pub(super) fn endpoint_mapped_addr(&self, eid: EndpointId) -> EndpointIdMappedAddr {
        self.endpoint_mapped_addrs.get(&eid)
    }

    /// Removes the handles for terminated [`RemoteStateActor`]s from the endpoint map.
    ///
    /// This should be called periodically to remove handles to endpoint state actors
    /// that have shutdown after their idle timeout expired.
    pub(super) fn remove_closed_remote_state_actors(&self) {
        let mut handles = self.actor_handles.lock().expect("poisoned");
        handles.retain(|_eid, handle| !handle.sender.is_closed())
    }

    /// Returns the sender for the [`RemoteStateActor`].
    ///
    /// If needed a new actor is started on demand.
    ///
    /// [`RemoteStateActor`]: remote_state::RemoteStateActor
    pub(super) fn remote_state_actor(&self, eid: EndpointId) -> mpsc::Sender<RemoteStateMessage> {
        let mut handles = self.actor_handles.lock().expect("poisoned");
        match handles.entry(eid) {
            hash_map::Entry::Occupied(mut entry) => {
                if let Some(sender) = entry.get().sender.get() {
                    sender
                } else {
                    // The actor is dead: Start a new actor.
                    let (handle, sender) = self.start_remote_state_actor(eid);
                    entry.insert(handle);
                    sender
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let (handle, sender) = self.start_remote_state_actor(eid);
                entry.insert(handle);
                sender
            }
        }
    }

    /// Starts a new remote state actor and returns a handle and a sender.
    ///
    /// The handle is not inserted into the endpoint map, this must be done by the caller of this function.
    fn start_remote_state_actor(
        &self,
        eid: EndpointId,
    ) -> (RemoteStateHandle, mpsc::Sender<RemoteStateMessage>) {
        // Ensure there is a RemoteMappedAddr for this EndpointId.
        self.endpoint_mapped_addrs.get(&eid);
        let handle = RemoteStateActor::new(
            eid,
            self.local_endpoint_id,
            self.local_addrs.clone(),
            self.relay_mapped_addrs.clone(),
            self.metrics.clone(),
            self.sender.clone(),
            self.discovery.clone(),
        )
        .start();
        let sender = handle.sender.get().expect("just created");
        (handle, sender)
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
#[allow(private_interfaces)]
pub enum Source {
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
    #[strum(serialize = "CallMeMaybe")]
    CallMeMaybe {
        /// private marker
        _0: Private,
    },
    /// We received a ping on the path.
    #[strum(serialize = "Ping")]
    Ping {
        /// private marker
        _0: Private,
    },
    /// We established a connection on this address.
    ///
    /// Currently this means the path was in uses as [`PathId::ZERO`] when the a connection
    /// was added to the `RemoteStateActor`.
    ///
    /// [`PathId::ZERO`]: quinn_proto::PathId::ZERO
    #[strum(serialize = "Connection")]
    Connection {
        /// private marker
        _0: Private,
    },
}

/// Helper to ensure certain `Source` variants can not be constructed externally.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct Private;

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
