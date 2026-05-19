use std::{
    collections::BTreeSet,
    hash::Hash,
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};

use iroh_base::{CustomAddr, EndpointAddr, EndpointId, RelayUrl};
use n0_future::task::JoinSet;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Span, debug, error};

pub(crate) use self::remote_state::PathStateReceiver;
use self::remote_state::RemoteStateActor;
pub(super) use self::remote_state::RemoteStateMessage;
pub use self::remote_state::{
    Path, PathEvent, PathEventStream, PathList, PathListIter, PathListStream, RemoteInfo,
    TransportAddrInfo, TransportAddrUsage,
};
use super::{
    DirectAddr, Metrics as SocketMetrics,
    mapped_addrs::{
        AddrMap, CustomMappedAddr, EndpointIdMappedAddr, MultipathMappedAddr, RelayMappedAddr,
    },
    transports,
};
use crate::{
    address_lookup::{self, AddressLookupFailed},
    socket::{
        RemoteStateActorStoppedError,
        concurrent_read_map::{ConcurrentReadMap, ReadOnlyMap},
        transports::TransportBiasMap,
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
///   addressing space that is used by Noq.
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
    /// The mapping between custom transport addresses and their [`CustomMappedAddr`]s.
    pub(super) custom_addrs: AddrMap<CustomAddr, CustomMappedAddr>,
}

/// Converts a mapped socket address to a transport address.
///
/// This takes a socket address, converts it into a [`MultipathMappedAddr`] and then tries
/// to convert the mapped address into a [`transports::Addr`].
///
/// Returns `Some` with the transport address for IP, relay, or custom mapped addresses
/// if an entry exists in the corresponding map.
///
/// Returns `None` for [`MultipathMappedAddr::Mixed`] addresses or unknown mapped addresses.
pub(super) fn to_transport_addr(
    addr: impl Into<MultipathMappedAddr>,
    relay_addrs: &AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
    custom_addrs: &AddrMap<CustomAddr, CustomMappedAddr>,
) -> Option<transports::Addr> {
    match addr.into() {
        MultipathMappedAddr::Mixed(_) => {
            error!(
                "Failed to convert addr to transport addr: Mixed mapped addr has no transport address"
            );
            None
        }
        MultipathMappedAddr::Relay(relay_mapped_addr) => {
            match relay_addrs.lookup(&relay_mapped_addr) {
                Some(parts) => Some(transports::Addr::from(parts)),
                None => {
                    error!("Failed to convert addr to transport addr: Unknown relay mapped addr");
                    None
                }
            }
        }
        MultipathMappedAddr::Custom(custom_mapped_addr) => {
            match custom_addrs.lookup(&custom_mapped_addr) {
                Some(custom_addr) => Some(transports::Addr::Custom(custom_addr)),
                None => {
                    error!("Failed to convert addr to transport addr: Unknown custom mapped addr");
                    None
                }
            }
        }
        MultipathMappedAddr::Ip(addr) => Some(transports::Addr::from(addr)),
    }
}

/// Stores the state required for starting and cleaning up the `RemoteStateActor`s.
///
/// When this is dropped, this will abort all tasks.
#[derive(Debug)]
struct Tasks {
    //
    // State required for spawning new actors.
    //
    metrics: Arc<SocketMetrics>,
    /// The "direct" addresses known for our local endpoint
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    address_lookup: address_lookup::AddressLookupServices,
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
    /// Biases for different transport kinds.
    transport_bias: TransportBiasMap,
    /// The tracing span for this endpoint, to be used as parent span for `RemoteStateActor` tasks.
    span: Span,
}

impl RemoteMap {
    /// Creates a new [`RemoteMap`].
    pub(super) fn new(
        metrics: Arc<SocketMetrics>,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        address_lookup: address_lookup::AddressLookupServices,
        shutdown_token: CancellationToken,
        transport_bias: TransportBiasMap,
        span: Span,
    ) -> Self {
        Self {
            mapped_addrs: Default::default(),
            senders: Default::default(),
            tasks: Tasks {
                metrics,
                local_direct_addrs,
                address_lookup,
                shutdown_token,
                tasks: Default::default(),
                poll_cleanup_waker: None,
                transport_bias,
                span,
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
        tx: oneshot::Sender<Result<(), AddressLookupFailed>>,
    ) -> Result<(), RemoteStateActorStoppedError> {
        let EndpointAddr { id, addrs } = addr;
        let actor = self.remote_state_actor(id);
        actor
            .send(RemoteStateMessage::ResolveRemote(addrs, tx))
            .await?;
        Ok(())
    }

    pub(super) async fn add_connection(
        &mut self,
        remote: EndpointId,
        conn: noq::Connection,
        tx: oneshot::Sender<PathStateReceiver>,
    ) -> Result<(), RemoteStateActorStoppedError> {
        let actor = self.remote_state_actor(remote);
        actor
            .send(RemoteStateMessage::AddConnection(conn, tx))
            .await?;
        Ok(())
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
            self.local_direct_addrs.clone(),
            mapped_addrs.relay_addrs.clone(),
            mapped_addrs.custom_addrs.clone(),
            self.metrics.clone(),
            self.address_lookup.clone(),
            self.transport_bias.clone(),
        )
        .start(
            initial_msgs,
            &mut self.tasks,
            self.shutdown_token.clone(),
            self.span.clone(),
        );
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
#[non_exhaustive]
pub(crate) enum Source {
    /// Application layer added the address directly.
    App,
    /// The address was discovered by an Address Lookup system
    #[strum(serialize = "{name}")]
    AddressLookup {
        /// The name of the Address Lookup that discovered the address.
        name: String,
    },
    /// The address was added as a path within a connection.
    Connection,
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, net::SocketAddr, time::Duration};

    use iroh_base::{SecretKey, TransportAddr};
    use n0_future::future::now_or_never;
    use n0_tracing_test::traced_test;
    use n0_watcher::Watchable;
    use tokio::sync::oneshot;
    use tracing::Span;

    use super::*;

    fn make_remote_map() -> (RemoteMap, CancellationToken, impl Sized) {
        let metrics = Arc::new(SocketMetrics::default());
        let watchable: Watchable<BTreeSet<DirectAddr>> = Watchable::new(BTreeSet::new());
        let local_direct_addrs = watchable.watch();
        let shutdown_token = CancellationToken::new();
        let remote_map = RemoteMap::new(
            metrics,
            local_direct_addrs,
            address_lookup::AddressLookupServices::default(),
            shutdown_token.clone(),
            TransportBiasMap::default(),
            Span::none(),
        );
        let guards = (watchable, shutdown_token.clone().drop_guard());
        (remote_map, shutdown_token, guards)
    }

    /// Regression test: No new RemoteStateActors may be started before
    /// the task for its previous incarnation was processed.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn poll_cleanup_preserves_restarted_sender() {
        let (mut remote_map, _shutdown_token, _guards) = make_remote_map();
        let eid = SecretKey::from_bytes(&[0u8; 32]).public();

        // Non-empty addrs so each `resolve_remote` resolves its tx
        // immediately and does not park in `paths.pending_resolve_requests`;
        // the actor would never idle out otherwise.
        let addr_with_ip = |port: u16| {
            EndpointAddr::from_parts(
                eid,
                [TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port)))],
            )
        };

        // 1. Spawn A1 and let it process a real `ResolveRemote`.
        let (tx1, rx1) = oneshot::channel();
        remote_map
            .resolve_remote(addr_with_ip(1234), tx1)
            .await
            .ok();

        // 2. Advance past idle timeout. The runtime drives A1 to completion
        //    inside the sleep: it drains the message, becomes idle, exits.
        tokio::time::sleep(Duration::from_secs(65)).await;
        assert!(
            matches!(rx1.await, Ok(Ok(()))),
            "First resolve completes Ok"
        );

        // 3. Call `resolve_remote` again. The actor A1 has terminated but its task
        //    has not yet been cleaned up. A1's sender is still in the sender map
        //    but is closed.
        //    Before our fixes, `resolve_remote` would spawn a new actor. When
        //    `poll_cleanup` was then called, the sender to this new actor would be
        //    removed again. We fixed this by first processing the tasks for the
        //    terminated actor.

        //    We resume time so that we don't immediately idle-out again.
        tokio::time::resume();
        let (tx2, rx2) = oneshot::channel();
        remote_map
            .resolve_remote(addr_with_ip(5678), tx2)
            .await
            .ok();

        // 4. Drive `poll_cleanup`, like the socket actor does.
        //    Before our fixes, this would remove the sender to the just-started A2 from the sender map.
        now_or_never(poll_fn(|cx| remote_map.poll_cleanup(cx)));

        // 5. A third `resolve_remote`, this time with no addrs.
        //    With our fix, this reaches the actor spawned above (A2); without
        //    the fix this would start a new actor because A2 was falsely removed from
        //    the senders map.
        let (tx3, rx3) = oneshot::channel();
        remote_map
            .resolve_remote(EndpointAddr::new(eid), tx3)
            .await
            .ok();

        let outcome2 = rx2.await.expect("the resolve tx must be sent");
        let outcome3 = rx3.await.expect("the resolve tx must be sent");
        assert!(outcome2.is_ok(), "expected Ok, but got {outcome2:?}");
        assert!(outcome3.is_ok(), "expected Ok, but got {outcome3:?}");
    }
}
