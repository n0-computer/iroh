use std::{collections::BTreeSet, sync::Arc};

use iroh_base::{CustomAddr, EndpointAddr, EndpointId, RelayUrl};
use n0_future::task::JoinSet;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, error, info_span};

pub(crate) use self::remote_state::PathStateReceiver;
pub(super) use self::remote_state::RemoteStateMessage;
pub use self::remote_state::{
    Path, PathEvent, PathEventStream, PathList, PathListIter, PathListStream, RemoteInfo,
    TransportAddrInfo, TransportAddrUsage,
};
use self::{
    actor_registry::{ActorFactory, ActorRegistry},
    remote_state::RemoteStateActor,
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
    socket::{concurrent_read_map::ReadOnlyMap, transports::TransportBiasMap},
};

mod actor_registry;
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
    /// The supervised [`RemoteStateActor`], one per remote endpoint.
    actors: ActorRegistry<EndpointId, RemoteStateMessage, RemoteStateActorFactory>,
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

/// The [`ActorFactory`] that builds a [`RemoteStateActor`] per remote endpoint.
///
/// Holds the shared state each actor needs.
#[derive(Debug)]
struct RemoteStateActorFactory {
    metrics: Arc<SocketMetrics>,
    /// The "direct" addresses known for our local endpoint.
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    address_lookup: address_lookup::AddressLookupServices,
    shutdown_token: CancellationToken,
    /// Biases for different transport kinds.
    transport_bias: TransportBiasMap,
    /// Parent span for spawned `RemoteStateActor` tasks.
    span: Span,
    /// Maps for converting between mapped and IP/relay addrs.
    mapped_addrs: MappedAddrs,
}

impl ActorFactory<EndpointId, RemoteStateMessage> for RemoteStateActorFactory {
    fn spawn(
        &mut self,
        eid: EndpointId,
        initial_messages: Vec<RemoteStateMessage>,
        tasks: &mut JoinSet<(EndpointId, mpsc::Receiver<RemoteStateMessage>)>,
    ) -> mpsc::Sender<RemoteStateMessage> {
        // Ensure there is a RemoteMappedAddr for this EndpointId.
        self.mapped_addrs.endpoint_addrs.get(&eid);
        let (sender, inbox) = mpsc::channel(16);
        // The span is explicitly parented so the actor's logging does not
        // inherit whichever span happened to first spawn it, which is
        // otherwise very confusing.
        let fut = RemoteStateActor::new(
            eid,
            self.local_direct_addrs.clone(),
            self.mapped_addrs.relay_addrs.clone(),
            self.mapped_addrs.custom_addrs.clone(),
            self.metrics.clone(),
            self.address_lookup.clone(),
            self.transport_bias.clone(),
        )
        .run(initial_messages, inbox, self.shutdown_token.child_token())
        .instrument(info_span!(
            parent: self.span.clone(),
            "RemoteStateActor",
            remote = %eid.fmt_short(),
        ));
        tasks.spawn(fut);
        sender
    }
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
        let mapped_addrs = MappedAddrs::default();
        let factory = RemoteStateActorFactory {
            metrics,
            local_direct_addrs,
            address_lookup,
            shutdown_token,
            transport_bias,
            span,
            mapped_addrs: mapped_addrs.clone(),
        };
        Self {
            mapped_addrs,
            actors: ActorRegistry::new(factory),
        }
    }

    /// Joins a terminated `RemoteStateActor` task, restarting or forgetting it.
    ///
    /// See [`ActorRegistry::cleanup`]. Resolves to the remote endpoint ID of
    /// the actor whose task joined. Should be called in a loop; only one task
    /// may poll it concurrently.
    pub(super) async fn cleanup(&mut self) -> EndpointId {
        self.actors.cleanup().await
    }

    pub(super) fn on_network_change(&self, is_major: bool) {
        let read = self.actors.senders();
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
        self.actors
            .send(id, RemoteStateMessage::ResolveRemote(addrs, tx))
            .await
    }

    pub(super) async fn add_connection(
        &mut self,
        remote: EndpointId,
        conn: noq::Connection,
        tx: oneshot::Sender<PathStateReceiver>,
    ) {
        self.actors
            .send(remote, RemoteStateMessage::AddConnection(conn, tx))
            .await
    }

    pub(super) fn senders(&self) -> ReadOnlyMap<EndpointId, mpsc::Sender<RemoteStateMessage>> {
        self.actors.senders()
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
