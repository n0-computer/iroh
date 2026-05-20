use std::{
    collections::BTreeSet,
    future::poll_fn,
    hash::Hash,
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};

use iroh_base::{CustomAddr, EndpointAddr, EndpointId, RelayUrl};
use n0_future::task::JoinSet;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Span, debug, error, trace};

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
    pub(super) mapped_addrs: MappedAddrs,

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

    /// Cleans up terminated `RemoteStateActor` tasks.
    ///
    /// This polls for terminated actor tasks, and removes the corresponding actor sender
    /// from our sender map, or restarts the actor if it has pending messages.
    ///
    /// Resolves to the actor's remote endpoint ID whenever a `RemoteStateActor` task joined,
    /// independent of whether the task was restarted or not.
    ///
    /// Returns pending if there was no actor to be cleaned up right now, and registers
    /// for moments where this could become the case.
    ///
    /// This function should be called in a loop to clean up expired tasks.
    /// Only one task is allowed to poll this function concurrently.
    pub(super) async fn cleanup(&mut self) -> EndpointId {
        poll_fn(|cx| self.poll_cleanup(cx)).await
    }

    /// See [`Self::cleanup`].
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<EndpointId> {
        while let Some(result) = ready!(self.tasks.tasks.poll_join_next(cx)) {
            match result {
                Ok((remote_id, leftover_msgs)) => {
                    if leftover_msgs.is_empty() {
                        // the actor shut down cleanly
                        self.senders.remove(&remote_id);
                        trace!(%remote_id, "cleaned up RemoteStateActor");
                    } else {
                        // The remote actor got messages while it was closing, so we're restarting
                        debug!(%remote_id, "restarting terminated RemoteStateActor: messages received during shutdown");
                        let sender = self.tasks.start_remote_state_actor(
                            remote_id,
                            leftover_msgs,
                            &self.mapped_addrs,
                        );
                        // We don't have to be careful about guards - only one thread is modifying this hashmap at a time.
                        self.senders.insert(remote_id, sender);
                    }
                    return Poll::Ready(remote_id);
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
    ) {
        let EndpointAddr { id, addrs } = addr;
        self.send_to_actor(id, RemoteStateMessage::ResolveRemote(addrs, tx))
            .await
    }

    pub(super) async fn add_connection(
        &mut self,
        remote: EndpointId,
        conn: noq::Connection,
        tx: oneshot::Sender<PathStateReceiver>,
    ) {
        self.send_to_actor(remote, RemoteStateMessage::AddConnection(conn, tx))
            .await
    }

    /// Sends a message to a `RemoteStateActor`, starting it if not running already.
    ///
    /// When sending fails, the actor must be terminating, in which case we wait for its task to
    /// join and then restart the sender.
    async fn send_to_actor(&mut self, remote: EndpointId, message: RemoteStateMessage) {
        let sender = self.senders.get_or_insert_with(remote, || {
            self.tasks
                .start_remote_state_actor(remote, vec![], &self.mapped_addrs)
        });

        if let Err(mpsc::error::SendError(message)) = sender.send(message).await {
            // The send failed, which means the RemoteStateActor is terminating. We call the cleanup
            // function so that its task is processed. This ensures that the leftover messages are
            // properly enqueued into a new actor, and that a later cleanup does not reap a newly
            // created sender again.  We can be sure that the task has not been cleaned up yet
            // because we take a `&mut self` reference.
            while self.cleanup().await != remote {}

            let sender = self.senders.get_or_insert_with(remote, || {
                self.tasks
                    .start_remote_state_actor(remote, vec![], &self.mapped_addrs)
            });
            sender
                .try_send(message)
                .expect("sender just created so it must have capacity")
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
    use std::{net::SocketAddr, time::Duration};

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
    /// the task of its previous incarnation was processed.
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
        remote_map.resolve_remote(addr_with_ip(1234), tx1).await;
        assert!(
            matches!(rx1.await, Ok(Ok(()))),
            "First resolve completes Ok"
        );

        // 2. Advance past idle timeout.
        tokio::time::sleep(Duration::from_secs(65)).await;

        // 3. Call `resolve_remote` again. The actor A1 has terminated but its task
        //    has not yet been cleaned up. A1's sender is still in the sender map
        //    but is closed. This will spawn a new actor A2.
        //    Before our fixes, `resolve_remote` would spawn a new actor, and when
        //    `cleanup` was then called, the sender to this new actor would be
        //    removed again. We fixed this by first processing the joined task for the
        //    terminated actor, so that it is removed from our task list *before*
        //    starting a new actor.
        //    We also resume time here so that we don't immediately idle-out again.
        tokio::time::resume();
        let (tx2, rx2) = oneshot::channel();
        remote_map.resolve_remote(addr_with_ip(5678), tx2).await;

        // 4. Drive `cleanup`, like the socket actor does.
        //    Before our fixes, this would remove the sender to the just-started A2 from the sender map.
        now_or_never(remote_map.cleanup());

        // 5. A third `resolve_remote`, this time with no addrs.
        //    With our fix, this reaches the actor spawned above (A2); without
        //    the fix this would start a new actor because A2 was falsely removed from
        //    the senders map.
        let (tx3, rx3) = oneshot::channel();
        remote_map.resolve_remote(EndpointAddr::new(eid), tx3).await;

        let outcome2 = rx2.await.expect("the resolve tx must be sent");
        let outcome3 = rx3.await.expect("the resolve tx must be sent");
        assert!(outcome2.is_ok(), "expected Ok, but got {outcome2:?}");
        assert!(outcome3.is_ok(), "expected Ok, but got {outcome3:?}");
    }
}
