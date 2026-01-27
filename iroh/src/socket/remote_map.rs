use std::{
    collections::BTreeSet,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl};
use n0_future::task::JoinSet;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

pub(crate) use self::remote_state::PathsWatcher;
use self::remote_state::RemoteStateActor;
pub(super) use self::remote_state::RemoteStateMessage;
pub use self::remote_state::{
    PathInfo, PathInfoList, RemoteInfo, TransportAddrInfo, TransportAddrUsage,
};
use super::{
    DirectAddr, Metrics as SocketMetrics,
    mapped_addrs::{AddrMap, EndpointIdMappedAddr, RelayMappedAddr},
};
use crate::{
    address_lookup,
    socket::{
        RemoteStateActorStoppedError,
        concurrent_read_map::{ConcurrentReadMap, ReadOnlyMap},
    },
};

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
    /// Maps for converting between mapped and IP/relay addrs.
    pub(crate) mapped_addrs: MappedAddrs,

    /// The senders for the inbox of each `RemoteStateActor` that runs.
    ///
    /// This is separated out of `Tasks` to make keeping a mutable borrow of the senders possible
    /// while we're spawning a task using another mutable borrow of `Tasks`.
    senders: ConcurrentReadMap<EndpointId, mpsc::Sender<RemoteStateMessage>>,

    /// The state kept for spawning new actors and cleaning them up.
    tasks: Tasks,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MappedAddrs {
    /// The mapping between [`EndpointId`]s and [`EndpointIdMappedAddr`]s.
    pub(super) endpoint_addrs: AddrMap<EndpointId, EndpointIdMappedAddr>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    pub(super) relay_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
}

/// Stores the state required for starting and cleaning up the `RemoteStateActor`s.
///
/// When this is dropped, this will abort all tasks.
#[derive(Debug)]
struct Tasks {
    //
    // State required for spawning new actors.
    //
    /// The endpoint ID of the local endpoint.
    local_endpoint_id: EndpointId,
    metrics: Arc<SocketMetrics>,
    /// The "direct" addresses known for our local endpoint
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    address_lookup: address_lookup::ConcurrentAddressLookup,
    shutdown_token: CancellationToken,

    //
    // State for task-tracking spawned actors.
    //
    /// All the `RemoteStateActor` tasks, stored inside a `JoinSet`.
    ///
    /// These tasks return their endpoint ID and the list of messages they didn't get to handle
    /// when they shut down.
    tasks: JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
    /// The waker that notifies `poll_cleanup` when the join set is populated with another task.
    poll_cleanup_waker: Option<Waker>,
}

impl RemoteMap {
    /// Creates a new [`RemoteMap`].
    pub(super) fn new(
        local_endpoint_id: EndpointId,
        metrics: Arc<SocketMetrics>,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        address_lookup: address_lookup::ConcurrentAddressLookup,
        shutdown_token: CancellationToken,
    ) -> Self {
        Self {
            mapped_addrs: Default::default(),
            senders: Default::default(),
            tasks: Tasks {
                local_endpoint_id,
                metrics,
                local_direct_addrs,
                address_lookup,
                shutdown_token,
                tasks: Default::default(),
                poll_cleanup_waker: None,
            },
        }
    }

    /// Potentially removes terminated [`RemoteStateActor`]s from the remote map.
    ///
    /// Resolves to the endpoint ID that of the remote state actor that got cleaned up.
    ///
    /// Returns pending if there was no actor to be cleaned up right now, and registers
    /// for moments where this could become the case.
    ///
    /// Only one task is allowed to poll this function concurrently.
    pub(super) fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<EndpointId> {
        while let Some(result) = ready!(self.tasks.tasks.poll_join_next(cx)) {
            match result {
                Ok((eid, leftover_msgs)) => {
                    if leftover_msgs.is_empty() {
                        // the actor shut down cleanly
                        self.senders.remove(&eid);
                        return Poll::Ready(eid);
                    }

                    // The remote actor got messages while it was closing, so we're restarting
                    debug!(%eid, "restarting terminated remote state actor: messages received during shutdown");
                    let sender =
                        self.tasks
                            .start_remote_state_actor(eid, leftover_msgs, &self.mapped_addrs);
                    // We don't have to be careful about guards - only one thread is modifying this hashmap at a time.
                    self.senders.insert(eid, sender);
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
        self.tasks.poll_cleanup_waker.replace(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn on_network_change(&mut self, is_major: bool) {
        let read = self.senders.read_only();
        let guard = read.guard();
        for sender in read.values(&guard) {
            sender
                .try_send(RemoteStateMessage::NetworkChange { is_major })
                .ok();
        }
    }

    pub(super) async fn resolve_remote(
        &mut self,
        addr: EndpointAddr,
    ) -> Result<Result<EndpointIdMappedAddr, address_lookup::Error>, RemoteStateActorStoppedError>
    {
        let EndpointAddr { id, addrs } = addr;
        let actor = self.remote_state_actor(id);
        let (tx, rx) = oneshot::channel();
        actor
            .send(RemoteStateMessage::ResolveRemote(addrs, tx))
            .await?;

        match rx.await {
            Ok(Ok(())) => Ok(Ok(self.mapped_addrs.endpoint_addrs.get(&id))),
            Ok(Err(err)) => Ok(Err(err)),
            Err(_) => Err(RemoteStateActorStoppedError::new()),
        }
    }

    pub(super) async fn remote_info(&mut self, id: EndpointId) -> Option<RemoteInfo> {
        let actor = self.remote_state_actor_if_exists(id)?;
        let (tx, rx) = oneshot::channel();
        actor.send(RemoteStateMessage::RemoteInfo(tx)).await.ok()?;
        rx.await.ok()
    }

    pub(super) async fn add_connection(
        &mut self,
        remote: EndpointId,
        conn: quinn::WeakConnectionHandle,
    ) -> Option<PathsWatcher> {
        let actor = self.remote_state_actor(remote);
        let (tx, rx) = oneshot::channel();
        actor
            .send(RemoteStateMessage::AddConnection(conn, tx))
            .await
            .ok()?;
        rx.await.ok()
    }

    /// Returns the sender for the [`RemoteStateActor`].
    ///
    /// If needed a new actor is started on demand.
    ///
    /// [`RemoteStateActor`]: remote_state::RemoteStateActor
    pub(super) fn remote_state_actor(
        &mut self,
        eid: EndpointId,
    ) -> mpsc::Sender<RemoteStateMessage> {
        let sender = self.senders.get_or_insert_with(eid, || {
            self.tasks
                .start_remote_state_actor(eid, vec![], &self.mapped_addrs)
        });
        if sender.is_closed() {
            // The actor is dead: Start a new actor.
            let sender = self
                .tasks
                .start_remote_state_actor(eid, vec![], &self.mapped_addrs);
            self.senders.insert(eid, sender.clone());
            sender
        } else {
            sender.clone()
        }
    }

    pub(super) fn remote_state_actor_if_exists(
        &self,
        eid: EndpointId,
    ) -> Option<mpsc::Sender<RemoteStateMessage>> {
        self.senders.get(&eid)
    }

    pub(super) fn senders(&self) -> ReadOnlyMap<EndpointId, mpsc::Sender<RemoteStateMessage>> {
        self.senders.read_only()
    }
}

impl Tasks {
    /// Starts a new remote state actor and returns a handle and a sender.
    ///
    /// The handle is not inserted into the endpoint map, this must be done by the caller of this function.
    fn start_remote_state_actor(
        &mut self,
        eid: EndpointId,
        initial_msgs: Vec<RemoteStateMessage>,
        mapped_addrs: &MappedAddrs,
    ) -> mpsc::Sender<RemoteStateMessage> {
        // Ensure there is a RemoteMappedAddr for this EndpointId.
        mapped_addrs.endpoint_addrs.get(&eid);
        let sender = RemoteStateActor::new(
            eid,
            self.local_endpoint_id,
            self.local_direct_addrs.clone(),
            mapped_addrs.relay_addrs.clone(),
            self.metrics.clone(),
            self.address_lookup.clone(),
        )
        .start(initial_msgs, &mut self.tasks, self.shutdown_token.clone());
        if let Some(waker) = self.poll_cleanup_waker.take() {
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
