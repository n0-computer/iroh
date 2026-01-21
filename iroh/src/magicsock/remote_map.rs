use std::{
    collections::{BTreeSet, hash_map},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker, ready},
};

use iroh_base::{EndpointId, RelayUrl};
use n0_future::task::JoinSet;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

pub(crate) use self::remote_state::PathsWatcher;
use self::remote_state::RemoteStateActor;
pub(super) use self::remote_state::RemoteStateMessage;
pub use self::remote_state::{
    PathInfo, PathInfoList, RemoteInfo, TransportAddrInfo, TransportAddrUsage,
};
use super::{
    DirectAddr, MagicsockMetrics,
    mapped_addrs::{AddrMap, EndpointIdMappedAddr, RelayMappedAddr},
};
use crate::address_lookup;

mod remote_state;

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
    /// The "direct" addresses known for our local endpoint
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    address_lookup: address_lookup::ConcurrentAddressLookup,
    shutdown_token: CancellationToken,

    /// The state kept for spawning new tasks for remote state actors and cleaning them up.
    state: Mutex<ActorState>,
}

/// Stores the state required for managing the `RemoteStateActor`s.
///
/// All of these are stored in the same mutex, as we have invariants about e.g. the
/// `senders` getting an entry for each task that's spawned, or the waker being woken each time
/// we add a task.
#[derive(Debug, Default)]
struct ActorState {
    /// All the `RemoteStateActor` tasks, stored inside a `JoinSet`.
    ///
    /// These tasks return their endpoint ID and the list of messages they didn't get to handle
    /// when they shut down.
    tasks: JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
    /// The waker that notifies `poll_cleanup` when the join set is populated with another task.
    poll_cleanup_waker: Option<Waker>,
    /// The senders for the inbox of each `RemoteStateActor` that runs.
    senders: FxHashMap<EndpointId, mpsc::Sender<RemoteStateMessage>>,
}

impl RemoteMap {
    /// Creates a new [`RemoteMap`].
    pub(super) fn new(
        local_endpoint_id: EndpointId,
        metrics: Arc<MagicsockMetrics>,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        address_lookup: address_lookup::ConcurrentAddressLookup,
        shutdown_token: CancellationToken,
    ) -> Self {
        Self {
            endpoint_mapped_addrs: Default::default(),
            relay_mapped_addrs: Default::default(),
            local_endpoint_id,
            metrics,
            local_direct_addrs,
            address_lookup,
            shutdown_token,
            state: Default::default(),
        }
    }

    pub(super) fn endpoint_mapped_addr(&self, eid: EndpointId) -> EndpointIdMappedAddr {
        self.endpoint_mapped_addrs.get(&eid)
    }

    /// Potentially removes terminated [`RemoteStateActor`]s from the remote map.
    ///
    /// Resolves to the endpoint ID that of the remote state actor that got cleaned up.
    ///
    /// Returns pending if there was no actor to be cleaned up right now, and registers
    /// for moments where this could become the case.
    ///
    /// Only one task is allowed to poll this function concurrently.
    pub(super) fn poll_cleanup(&self, cx: &mut Context<'_>) -> Poll<EndpointId> {
        let mut guard = self.state.lock().expect("poisoned");
        let ActorState {
            ref mut tasks,
            ref mut poll_cleanup_waker,
            ref mut senders,
        } = *guard;
        while let Some(result) = ready!(tasks.poll_join_next(cx)) {
            match result {
                Ok((eid, leftover_msgs)) => {
                    let entry = senders.entry(eid);
                    if leftover_msgs.is_empty() {
                        // the actor shut down cleanly
                        match entry {
                            hash_map::Entry::Occupied(occupied_entry) => occupied_entry.remove(),
                            hash_map::Entry::Vacant(_) => {
                                panic!("this should be impossible TODO(matheus23)");
                            }
                        };
                        return Poll::Ready(eid);
                    }

                    // The remote actor got messages while it was closing, so we're restarting
                    debug!(%eid, "restarting terminated remote state actor: messages received during shutdown");
                    let sender = self.start_remote_state_actor(
                        eid,
                        leftover_msgs,
                        tasks,
                        poll_cleanup_waker,
                    );
                    entry.insert_entry(sender);
                }
                Err(err) => {
                    if let Ok(panic) = err.try_into_panic() {
                        error!("RemoteStateActor panicked.");
                        std::panic::resume_unwind(panic);
                    }
                }
            }
        }
        // There's nothing to clean up.
        // Let's get woken when there's another task.
        // If we're called after that, then we'll fall into `poll_join_next` and
        // properly wait for a task to finish.
        guard.poll_cleanup_waker.replace(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn on_network_change(&self, is_major: bool) {
        let guard = self.state.lock().expect("poisoned");
        for sender in guard.senders.values() {
            sender
                .try_send(RemoteStateMessage::NetworkChange { is_major })
                .ok();
        }
    }

    /// Returns the sender for the [`RemoteStateActor`].
    ///
    /// If needed a new actor is started on demand.
    ///
    /// [`RemoteStateActor`]: remote_state::RemoteStateActor
    pub(super) fn remote_state_actor(&self, eid: EndpointId) -> mpsc::Sender<RemoteStateMessage> {
        let mut guard = self.state.lock().expect("poisoned");
        let ActorState {
            ref mut tasks,
            ref mut poll_cleanup_waker,
            ref mut senders,
        } = *guard;
        match senders.entry(eid) {
            hash_map::Entry::Occupied(mut entry) => {
                let sender = entry.get();
                if sender.is_closed() {
                    // The actor is dead: Start a new actor.
                    let sender =
                        self.start_remote_state_actor(eid, vec![], tasks, poll_cleanup_waker);
                    entry.insert(sender.clone());
                    sender
                } else {
                    sender.clone()
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let sender = self.start_remote_state_actor(eid, vec![], tasks, poll_cleanup_waker);
                entry.insert(sender.clone());
                sender
            }
        }
    }

    pub(super) fn remote_state_actor_if_exists(
        &self,
        eid: EndpointId,
    ) -> Option<mpsc::Sender<RemoteStateMessage>> {
        self.state
            .lock()
            .expect("poisoned")
            .senders
            .get(&eid)
            .cloned()
    }

    /// Starts a new remote state actor and returns a handle and a sender.
    ///
    /// The handle is not inserted into the endpoint map, this must be done by the caller of this function.
    fn start_remote_state_actor(
        &self,
        eid: EndpointId,
        initial_msgs: Vec<RemoteStateMessage>,
        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
        poll_cleanup_waker: &mut Option<Waker>,
    ) -> mpsc::Sender<RemoteStateMessage> {
        // Ensure there is a RemoteMappedAddr for this EndpointId.
        self.endpoint_mapped_addrs.get(&eid);
        let sender = RemoteStateActor::new(
            eid,
            self.local_endpoint_id,
            self.local_direct_addrs.clone(),
            self.relay_mapped_addrs.clone(),
            self.metrics.clone(),
            self.address_lookup.clone(),
        )
        .start(initial_msgs, tasks, self.shutdown_token.clone());
        if let Some(waker) = poll_cleanup_waker.take() {
            // Notify something waiting for changes to tasks when there's a new task.
            waker.wake();
        }
        sender
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
    /// The address was discovered by an Address Lookup system
    #[strum(serialize = "{name}")]
    AddressLookup {
        /// The name of the Address Lookup that discovered the address.
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
