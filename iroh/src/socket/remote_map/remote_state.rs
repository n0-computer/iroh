use std::{
    collections::{BTreeSet, VecDeque},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use iroh_base::{EndpointId, RelayUrl, TransportAddr};
use n0_error::StackResultExt;
use n0_future::{
    Either, FuturesUnordered, MergeUnbounded, Stream, StreamExt,
    boxed::BoxStream,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::{Watchable, Watcher};
use quinn::WeakConnectionHandle;
use quinn_proto::{PathError, PathEvent, PathId, PathStatus, iroh_hp};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use sync_wrapper::SyncStream;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, error, event, info_span, instrument, trace, warn};

use self::path_state::RemotePathState;
pub use self::remote_info::{RemoteInfo, TransportAddrInfo, TransportAddrUsage};
use super::Source;
use crate::{
    address_lookup::{
        AddressLookup, ConcurrentAddressLookup, Error as AddressLookupError,
        Item as AddressLookupItem,
    },
    endpoint::{DirectAddr, quic::PathStats},
    socket::{
        Metrics as SocketMetrics,
        mapped_addrs::{AddrMap, MappedAddr, RelayMappedAddr},
        remote_map::Private,
        transports::{self, OwnedTransmit, TransportsSender},
    },
    util::MaybeFuture,
};

mod path_state;
mod remote_info;

/// How often to attempt holepunching.
///
/// If there have been no changes to the NAT address candidates, holepunching will not be
/// attempted more frequently than at this interval.
const HOLEPUNCH_ATTEMPTS_INTERVAL: Duration = Duration::from_secs(5);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(10);

// TODO: use this
// /// How long since the last activity we try to keep an established endpoint peering alive.
// ///
// /// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
// pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better path.
///
/// Even if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// The time after which an idle [`RemoteStateActor`] stops.
///
/// The actor only enters the idle state if no connections are active and no inbox senders exist
/// apart from the one stored in the endpoint map. Stopping and restarting the actor in this state
/// is not an issue; a timeout here serves the purpose of not stopping-and-recreating actors
/// in a high frequency, and to keep data about previous path around for subsequent connections.
const ACTOR_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The minimum RTT difference to make it worth switching IP paths
const RTT_SWITCHING_MIN_IP: Duration = Duration::from_millis(5);

/// How much do we prefer IPv6 over IPv4?
const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// A stream of events from all paths for all connections.
///
/// The connection is identified using [`ConnId`].  The event `Err` variant happens when the
/// actor has lagged processing the events, which is rather critical for us.
type PathEvents = MergeUnbounded<
    Pin<
        Box<dyn Stream<Item = (ConnId, Result<PathEvent, BroadcastStreamRecvError>)> + Send + Sync>,
    >,
>;

/// A stream of events of announced NAT traversal candidate addresses for all connections.
///
/// The connection is identified using [`ConnId`].
type AddrEvents = MergeUnbounded<
    Pin<
        Box<
            dyn Stream<Item = (ConnId, Result<iroh_hp::Event, BroadcastStreamRecvError>)>
                + Send
                + Sync,
        >,
    >,
>;

/// Either a stream of incoming results from [`ConcurrentAddressLookup::resolve`] or infinitely pending.
///
/// Set to [`Either::Left`] with an always-pending stream while address lookup is not running, and to
/// [`Either::Right`] while Address Lookup is running.
///
/// The stream returned from [`ConcurrentAddressLookup::resolve`] is `!Sync`. We use the (safe) [`SyncStream`]
/// wrapper to make it `Sync` so that the [`RemoteStateActor::run`] future stays `Send`.
type AddressLookupStream = Either<
    n0_future::stream::Pending<Result<AddressLookupItem, AddressLookupError>>,
    SyncStream<BoxStream<Result<AddressLookupItem, AddressLookupError>>>,
>;

/// List of addrs and path ids for open paths in a connection.
pub(crate) type PathAddrList = SmallVec<[(TransportAddr, PathId); 4]>;

/// The state we need to know about a single remote endpoint.
///
/// This actor manages all connections to the remote endpoint.  It will trigger holepunching
/// and select the best path etc.
pub(super) struct RemoteStateActor {
    /// The endpoint ID of the remote endpoint.
    endpoint_id: EndpointId,
    /// The endpoint ID of the local endpoint.
    local_endpoint_id: EndpointId,

    // Hooks into the rest of the Socket.
    //
    /// Metrics.
    metrics: Arc<SocketMetrics>,
    /// Our local addresses.
    ///
    /// These are our local addresses and any reflexive transport addresses.
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
    /// Address lookup service, cloned from the socket.
    address_lookup: ConcurrentAddressLookup,

    // Internal state - Quinn Connections we are managing.
    //
    /// All connections we have to this remote endpoint.
    connections: FxHashMap<ConnId, ConnectionState>,
    /// Notifications when connections are closed.
    connections_close: FuturesUnordered<OnClosed>,
    /// Events emitted by Quinn about path changes, for all paths, all connections.
    path_events: PathEvents,
    /// A stream of events of announced NAT traversal candidate addresses for all connections.
    addr_events: AddrEvents,

    // Internal state - Holepunching and path state.
    //
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by Address Lookup
    /// mechanisms.  The are only potentially usable.
    paths: RemotePathState,
    /// Information about the last holepunching attempt.
    last_holepunch: Option<HolepunchAttempt>,

    /// The path we currently consider the preferred path to the remote endpoint.
    ///
    /// **We expect this path to work.** If we become aware this path is broken then it is
    /// set back to `None`.  Having a selected path does not mean we may not be able to get
    /// a better path: e.g. when the selected path is a relay path we still need to trigger
    /// holepunching regularly.
    ///
    /// We only select a path once the path is functional in Quinn.
    selected_path: Watchable<Option<transports::Addr>>,
    /// Time at which we should schedule the next holepunch attempt.
    scheduled_holepunch: Option<Instant>,
    /// When to next attempt opening paths in [`Self::pending_open_paths`].
    scheduled_open_path: Option<Instant>,
    /// Paths which we still need to open.
    ///
    /// They failed to open because we did not have enough CIDs issued by the remote.
    pending_open_paths: VecDeque<transports::Addr>,

    // Internal state - address lookup
    //
    /// Stream of Address Lookup results, or always pending if Address Lookup is not running.
    address_lookup_stream: AddressLookupStream,
}

impl RemoteStateActor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        endpoint_id: EndpointId,
        local_endpoint_id: EndpointId,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
        metrics: Arc<SocketMetrics>,
        address_lookup: ConcurrentAddressLookup,
    ) -> Self {
        Self {
            endpoint_id,
            local_endpoint_id,
            metrics: metrics.clone(),
            local_direct_addrs,
            relay_mapped_addrs,
            address_lookup,
            connections: FxHashMap::default(),
            connections_close: Default::default(),
            path_events: Default::default(),
            addr_events: Default::default(),
            paths: RemotePathState::new(metrics),
            last_holepunch: None,
            selected_path: Default::default(),
            scheduled_holepunch: None,
            scheduled_open_path: None,
            pending_open_paths: VecDeque::new(),
            address_lookup_stream: Either::Left(n0_future::stream::pending()),
        }
    }

    pub(super) fn start(
        self,
        initial_msgs: Vec<RemoteStateMessage>,
        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
        shutdown_token: CancellationToken,
    ) -> mpsc::Sender<RemoteStateMessage> {
        let (tx, rx) = mpsc::channel(16);
        let me = self.local_endpoint_id;
        let endpoint_id = self.endpoint_id;

        // Ideally we'd use the endpoint span as parent.  We'd have to plug that span into
        // here somehow.  Instead we have no parent and explicitly set the me attribute.  If
        // we don't explicitly set a span we get the spans from whatever call happens to
        // first create the actor, which is often very confusing as it then keeps those
        // spans for all logging of the actor.
        tasks.spawn(
            self.run(initial_msgs, rx, shutdown_token)
                .instrument(info_span!(
                    parent: None,
                    "RemoteStateActor",
                    me = %me.fmt_short(),
                    remote = %endpoint_id.fmt_short(),
                )),
        );
        tx
    }

    /// Runs the main loop of the actor.
    ///
    /// Note that the actor uses async handlers for tasks from the main loop.  The actor is
    /// not processing items from the inbox while waiting on any async calls.  So some
    /// discipline is needed to not turn pending for a long time.
    async fn run(
        mut self,
        initial_msgs: Vec<RemoteStateMessage>,
        mut inbox: mpsc::Receiver<RemoteStateMessage>,
        shutdown_token: CancellationToken,
    ) -> (EndpointId, Vec<RemoteStateMessage>) {
        trace!("actor started");
        for msg in initial_msgs {
            self.handle_message(msg).await;
        }
        let idle_timeout = time::sleep(ACTOR_MAX_IDLE_TIMEOUT);
        n0_future::pin!(idle_timeout);

        let check_connections = time::interval(UPGRADE_INTERVAL);
        n0_future::pin!(check_connections);

        loop {
            let scheduled_path_open = match self.scheduled_open_path {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_path_open);
            let scheduled_hp = match self.scheduled_holepunch {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_hp);
            if !inbox.is_empty() || !self.connections.is_empty() {
                idle_timeout
                    .as_mut()
                    .reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
            }

            tokio::select! {
                biased;

                _ = shutdown_token.cancelled() => {
                    trace!("actor cancelled");
                    break;
                }
                msg = inbox.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg).await,
                        None => break,
                    }
                }
                Some((id, evt)) = self.path_events.next() => {
                    self.handle_path_event(id, evt);
                }
                Some((id, evt)) = self.addr_events.next() => {
                    trace!(?id, ?evt, "remote addrs updated, triggering holepunching");
                    self.trigger_holepunching();
                }
                Some(conn_id) = self.connections_close.next(), if !self.connections_close.is_empty() => {
                    self.handle_connection_close(conn_id);
                }
                res = self.local_direct_addrs.updated() => {
                    if let Err(n0_watcher::Disconnected) = res {
                        trace!("direct address watcher disconnected, shutting down");
                        break;
                    }
                    self.local_addrs_updated();
                    trace!("local addrs updated, triggering holepunching");
                    self.trigger_holepunching();
                }
                _ = &mut scheduled_path_open => {
                    trace!("triggering scheduled path_open");
                    self.scheduled_open_path = None;
                    let mut addrs = std::mem::take(&mut self.pending_open_paths);
                    while let Some(addr) = addrs.pop_front() {
                        self.open_path(&addr);
                    }
                }
                _ = &mut scheduled_hp => {
                    trace!("triggering scheduled holepunching");
                    self.scheduled_holepunch = None;
                    self.trigger_holepunching();
                }
                item = self.address_lookup_stream.next() => {
                    self.handle_address_lookup_item(item);
                }
                _ = check_connections.tick() => {
                    self.check_connections();
                }
                _ = &mut idle_timeout => {
                    if self.connections.is_empty() && inbox.is_empty() {
                        trace!("idle timeout expired and still idle: terminate actor");
                        break;
                    } else {
                        // Seems like we weren't really idle, so we reset
                        idle_timeout.as_mut().reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
                    }
                }
            }
        }

        inbox.close();
        // There might be a race between checking `inbox.is_empty()` and `inbox.close()`,
        // so we pull out all messages that are left over.
        let mut leftover_msgs = Vec::with_capacity(inbox.len());
        inbox.recv_many(&mut leftover_msgs, inbox.len()).await;

        trace!("actor terminating");
        (self.endpoint_id, leftover_msgs)
    }

    /// Handles an actor message.
    ///
    /// Error returns are fatal and kill the actor.
    #[instrument(skip(self))]
    async fn handle_message(&mut self, msg: RemoteStateMessage) {
        // trace!("handling message");
        match msg {
            RemoteStateMessage::SendDatagram(sender, transmit) => {
                self.handle_msg_send_datagram(sender, transmit).await;
            }
            RemoteStateMessage::AddConnection(handle, tx) => {
                self.handle_msg_add_connection(handle, tx);
            }
            RemoteStateMessage::ResolveRemote(addrs, tx) => {
                self.handle_msg_resolve_remote(addrs, tx);
            }
            RemoteStateMessage::RemoteInfo(tx) => {
                let addrs = self.paths.to_remote_addrs();
                let info = RemoteInfo {
                    endpoint_id: self.endpoint_id,
                    addrs,
                };
                tx.send(info).ok();
            }
            RemoteStateMessage::NetworkChange { is_major } => {
                self.handle_network_change(is_major);
            }
        }
    }

    fn handle_network_change(&mut self, is_major: bool) {
        for conn in self.connections.values() {
            if let Some(quinn_conn) = conn.handle.upgrade() {
                for (path_id, addr) in &conn.open_paths {
                    if let Some(path) = quinn_conn.path(*path_id) {
                        // Ping the current path
                        if let Err(err) = path.ping() {
                            warn!(%err, %path_id, ?addr, "failed to ping path");
                        }
                    }
                }
            }
        }

        if is_major {
            self.trigger_holepunching();
        }
    }

    /// Handles regularly checking if any paths need hole punching currently
    ///
    /// Currently we need to have 1 IP path, with a good enough latency.
    fn check_connections(&mut self) {
        let mut is_goodenough = true;
        for conn_state in self.connections.values() {
            let mut is_conn_goodenough = false;
            if let Some(conn) = conn_state.handle.upgrade() {
                let min_ip_rtt = conn_state
                    .open_paths
                    .iter()
                    .filter_map(|(path_id, addr)| {
                        if addr.is_ip() {
                            conn.path_stats(*path_id).map(|stats| stats.rtt)
                        } else {
                            None
                        }
                    })
                    .min();

                if let Some(min_ip_rtt) = min_ip_rtt {
                    let is_latency_goodenough = min_ip_rtt <= GOOD_ENOUGH_LATENCY;
                    is_conn_goodenough = is_latency_goodenough;
                } else {
                    // No IP transport found
                    is_conn_goodenough = false;
                }
            }
            is_goodenough &= is_conn_goodenough;
        }

        if !is_goodenough {
            debug!("connections are not good enough, triggering holepunching");
            self.trigger_holepunching();
        }
    }

    /// Handles [`RemoteStateMessage::SendDatagram`].
    async fn handle_msg_send_datagram(
        &mut self,
        mut sender: Box<TransportsSender>,
        transmit: OwnedTransmit,
    ) {
        // Sending datagrams might fail, e.g. because we don't have the right transports set
        // up to handle sending this owned transmit to.
        // After all, we try every single path that we know (relay URL, IP address), even
        // though we might not have a relay transport or ip-capable transport set up.
        // So these errors must not be fatal for this actor (or even this operation).

        if let Some(addr) = self.selected_path.get() {
            trace!(?addr, "sending datagram to selected path");

            if let Err(err) = send_datagram(&mut sender, addr.clone(), transmit).await {
                debug!(?addr, "failed to send datagram on selected_path: {err:#}");
            }
        } else {
            trace!(
                paths = ?self.paths.addrs().collect::<Vec<_>>(),
                "sending datagram to all known paths",
            );
            if self.paths.is_empty() {
                warn!("Cannot send datagrams: No paths to remote endpoint known");
            }

            for addr in self.paths.addrs() {
                // We never want to send to our local addresses.
                // The local address set is updated in the main loop so we can use `peek` here.
                if let transports::Addr::Ip(sockaddr) = addr
                    && self
                        .local_direct_addrs
                        .peek()
                        .iter()
                        .any(|a| a.addr == *sockaddr)
                {
                    trace!(%sockaddr, "not sending datagram to our own address");
                } else if let Err(err) =
                    send_datagram(&mut sender, addr.clone(), transmit.clone()).await
                {
                    debug!(?addr, "failed to send datagram: {err:#}");
                }
            }
            // This message is received *before* a connection is added.  So we do
            // not yet have a connection to holepunch.  Instead we trigger
            // holepunching when AddConnection is received.
        }
    }

    /// Handles [`RemoteStateMessage::AddConnection`].
    ///
    /// Error returns are fatal and kill the actor.
    fn handle_msg_add_connection(
        &mut self,
        handle: WeakConnectionHandle,
        tx: oneshot::Sender<PathsWatcher>,
    ) {
        let pub_open_paths = Watchable::default();
        if let Some(conn) = handle.upgrade() {
            self.metrics.num_conns_opened.inc();
            // Remove any conflicting stable_ids from the local state.
            let conn_id = ConnId(conn.stable_id());
            self.connections.remove(&conn_id);

            // Hook up paths, NAT addresses and connection closed event streams.
            self.path_events.push(Box::pin(
                BroadcastStream::new(conn.path_events()).map(move |evt| (conn_id, evt)),
            ));
            self.addr_events.push(Box::pin(
                BroadcastStream::new(conn.nat_traversal_updates()).map(move |evt| (conn_id, evt)),
            ));
            self.connections_close.push(OnClosed::new(&conn));

            // Add local addrs to the connection
            let local_addrs = self
                .local_direct_addrs
                .get()
                .iter()
                .map(|d| d.addr)
                .collect::<BTreeSet<_>>();
            Self::set_local_addrs(&conn, &local_addrs);

            // Store the connection
            let conn_state = self
                .connections
                .entry(conn_id)
                .insert_entry(ConnectionState {
                    handle: handle.clone(),
                    pub_open_paths: pub_open_paths.clone(),
                    paths: Default::default(),
                    open_paths: Default::default(),
                    path_ids: Default::default(),
                    has_been_direct: false,
                })
                .into_mut();

            // Store PathId(0), set path_status and select best path, check if holepunching
            // is needed.
            if let Some(path) = conn.path(PathId::ZERO)
                && let Ok(socketaddr) = path.remote_address()
                && let Some(path_remote) = self.relay_mapped_addrs.to_transport_addr(socketaddr)
            {
                trace!(?path_remote, "added new connection");
                let path_status = match path_remote {
                    transports::Addr::Ip(_) => PathStatus::Available,
                    transports::Addr::Relay(_, _) => PathStatus::Backup,
                };
                let res = path.set_status(path_status);
                event!(
                    target: "iroh::_events::path::set_status",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    ?path_remote,
                    ?path_status,
                    ?conn_id,
                    path_id = %PathId::ZERO,
                    ?res,
                );
                conn_state.add_open_path(path_remote.clone(), PathId::ZERO, &self.metrics);
                self.paths
                    .insert_open_path(path_remote.clone(), Source::Connection { _0: Private });
                self.select_path();

                if path_remote.is_ip() {
                    // We may have raced this with a relay address.  Try and add any
                    // relay addresses we have back.
                    let relays = self
                        .paths
                        .addrs()
                        .filter(|a| a.is_relay())
                        .cloned()
                        .collect::<Vec<_>>();
                    for remote in relays {
                        self.open_path(&remote);
                    }
                }
            }
            self.trigger_holepunching();
        }
        tx.send(PathsWatcher::new(
            pub_open_paths.watch(),
            self.selected_path.watch(),
            handle,
        ))
        .ok();
    }

    /// Handles [`RemoteStateMessage::ResolveRemote`].
    fn handle_msg_resolve_remote(
        &mut self,
        addrs: BTreeSet<TransportAddr>,
        tx: oneshot::Sender<Result<(), AddressLookupError>>,
    ) {
        let addrs = to_transports_addr(self.endpoint_id, addrs);
        self.paths.insert_multiple(addrs, Source::App);
        self.paths.resolve_remote(tx);
        // Start Address Lookup if we have no selected path.
        self.trigger_address_lookup();
    }

    fn handle_connection_close(&mut self, conn_id: ConnId) {
        if self.connections.remove(&conn_id).is_some() {
            self.metrics.num_conns_closed.inc();
        }
        if self.connections.is_empty() {
            trace!("last connection closed - clearing selected_path");
            self.selected_path.set(None).ok();
        }
    }

    fn handle_address_lookup_item(
        &mut self,
        item: Option<Result<AddressLookupItem, AddressLookupError>>,
    ) {
        match item {
            None => {
                self.address_lookup_stream = Either::Left(n0_future::stream::pending());
                self.paths.address_lookup_finished(Ok(()));
            }
            Some(Err(err)) => {
                warn!("Address Lookup failed: {err:#}");
                self.address_lookup_stream = Either::Left(n0_future::stream::pending());
                self.paths.address_lookup_finished(Err(err));
            }
            Some(Ok(item)) => {
                if item.endpoint_id() != self.endpoint_id {
                    warn!(
                        ?item,
                        "Address Lookup emitted item for wrong remote endpoint"
                    );
                } else {
                    let source = Source::AddressLookup {
                        name: item.provenance().to_string(),
                    };
                    let addrs =
                        to_transports_addr(self.endpoint_id, item.into_endpoint_addr().addrs);
                    self.paths.insert_multiple(addrs, source);
                }
            }
        }
    }

    /// Triggers Address Lookup for the remote endpoint, if needed.
    ///
    /// Does not start Address Lookup if we have a selected path or if Address Lookup is currently running.
    fn trigger_address_lookup(&mut self) {
        if self.selected_path.get().is_some()
            || matches!(self.address_lookup_stream, Either::Right(_))
        {
            return;
        }
        match self.address_lookup.resolve(self.endpoint_id) {
            Some(stream) => self.address_lookup_stream = Either::Right(SyncStream::new(stream)),
            None => self.paths.address_lookup_finished(Ok(())),
        }
    }

    /// Sets the current local addresses to QNT's state to all connections
    fn local_addrs_updated(&mut self) {
        let local_addrs = self
            .local_direct_addrs
            .get()
            .iter()
            .map(|d| d.addr)
            .collect::<BTreeSet<_>>();

        for conn in self.connections.values().filter_map(|s| s.handle.upgrade()) {
            Self::set_local_addrs(&conn, &local_addrs);
        }
        // todo: trace
    }

    /// Sets the current local addresses to QNT's state
    fn set_local_addrs(conn: &quinn::Connection, local_addrs: &BTreeSet<SocketAddr>) {
        let quinn_local_addrs = match conn.get_local_nat_traversal_addresses() {
            Ok(addrs) => BTreeSet::from_iter(addrs),
            Err(err) => {
                warn!("failed to get local nat candidates: {err:#}");
                return;
            }
        };
        for addr in local_addrs.difference(&quinn_local_addrs) {
            if let Err(err) = conn.add_nat_traversal_address(*addr) {
                warn!("failed adding local addr: {err:#}",);
            }
        }
        for addr in quinn_local_addrs.difference(local_addrs) {
            if let Err(err) = conn.remove_nat_traversal_address(*addr) {
                warn!("failed removing local addr: {err:#}");
            }
        }
        trace!(?local_addrs, "updated local QNT addresses");
    }

    /// Triggers holepunching to the remote endpoint.
    ///
    /// This will manage the entire process of holepunching with the remote endpoint.
    ///
    /// - Holepunching happens on the Connection with the lowest [`ConnId`] which is a
    ///   client.
    ///   - Both endpoints may initiate holepunching if both have a client connection.
    ///   - Any opened paths are opened on all other connections without holepunching.
    /// - If there are no changes in local or remote candidate addresses since the
    ///   last attempt **and** there was a recent attempt, a trigger_holepunching call
    ///   will be scheduled instead.
    fn trigger_holepunching(&mut self) {
        if self.connections.is_empty() {
            trace!("not holepunching: no connections");
            return;
        }

        let Some(conn) = self
            .connections
            .iter()
            .filter_map(|(id, state)| state.handle.upgrade().map(|conn| (*id, conn)))
            .filter(|(_, conn)| conn.side().is_client())
            .min_by_key(|(id, _)| *id)
            .map(|(_, conn)| conn)
        else {
            trace!("not holepunching: no client connection");
            return;
        };
        let remote_candidates = match conn.get_remote_nat_traversal_addresses() {
            Ok(addrs) => BTreeSet::from_iter(addrs),
            Err(err) => {
                warn!("failed to get nat candidate addresses: {err:#}");
                return;
            }
        };
        let local_candidates: BTreeSet<SocketAddr> = self
            .local_direct_addrs
            .get()
            .iter()
            .map(|daddr| daddr.addr)
            .collect();
        let new_candidates = self
            .last_holepunch
            .as_ref()
            .map(|last_hp| {
                // Addrs are allowed to disappear, but if there are new ones we need to
                // holepunch again.
                trace!(
                    ?last_hp,
                    ?local_candidates,
                    ?remote_candidates,
                    "candidates to holepunch?"
                );
                !remote_candidates.is_subset(&last_hp.remote_candidates)
                    || !local_candidates.is_subset(&last_hp.local_candidates)
            })
            .unwrap_or(true);
        if !new_candidates && let Some(ref last_hp) = self.last_holepunch {
            let next_hp = last_hp.when + HOLEPUNCH_ATTEMPTS_INTERVAL;
            let now = Instant::now();
            if next_hp > now {
                trace!(scheduled_in = ?(next_hp - now), "not holepunching: no new addresses");
                self.scheduled_holepunch = Some(next_hp);
                return;
            }
        }

        self.do_holepunching(conn);
    }

    /// Unconditionally perform holepunching.
    #[instrument(skip_all)]
    fn do_holepunching(&mut self, conn: quinn::Connection) {
        self.metrics.holepunch_attempts.inc();
        let local_candidates = self
            .local_direct_addrs
            .get()
            .iter()
            .map(|daddr| daddr.addr)
            .collect::<BTreeSet<_>>();

        match conn.initiate_nat_traversal_round() {
            Ok(remote_candidates) => {
                let remote_candidates = remote_candidates
                    .iter()
                    .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
                    .collect();
                event!(
                    target: "iroh::_events::qnt::init",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    ?local_candidates,
                    ?remote_candidates,
                );
                self.last_holepunch = Some(HolepunchAttempt {
                    when: Instant::now(),
                    local_candidates,
                    remote_candidates,
                });
            }
            Err(err) => {
                debug!("failed to initiate NAT traversal: {err:#}");
                use quinn_proto::iroh_hp::Error;
                match err {
                    Error::Closed
                    | Error::TooManyAddresses
                    | Error::WrongConnectionSide
                    | Error::ExtensionNotNegotiated => {
                        // Fatal, no need to retry for now
                    }
                    Error::Multipath(_) | Error::NotEnoughAddresses => {
                        // Retry in a bit
                        let now = Instant::now();
                        let next_hp = now + Duration::from_millis(100);
                        trace!(scheduled_in = ?(next_hp - now), "holepunching retry");
                        self.scheduled_holepunch = Some(next_hp);
                    }
                }
            }
        }
    }

    /// Open the path on all connections.
    ///
    /// This goes through all the connections for which we are the client, and makes sure
    /// the path exists, or opens it.
    #[instrument(level = "warn", skip(self))]
    fn open_path(&mut self, open_addr: &transports::Addr) {
        let path_status = match open_addr {
            transports::Addr::Ip(_) => PathStatus::Available,
            transports::Addr::Relay(_, _) => PathStatus::Backup,
        };
        let quic_addr = match &open_addr {
            transports::Addr::Ip(socket_addr) => *socket_addr,
            transports::Addr::Relay(relay_url, eid) => self
                .relay_mapped_addrs
                .get(&(relay_url.clone(), *eid))
                .private_socket_addr(),
        };

        for (conn_id, conn_state) in self.connections.iter_mut() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            if let Some(&path_id) = conn_state.path_ids.get(open_addr)
                && let Some(path) = conn.path(path_id)
            {
                // We still need to ensure that the path status is set correctly,
                // in case the path was opened by QNT, which opens all IP paths
                // using PATH_STATUS_BACKUP. We need to switch the selected path
                // to use PATH_STATUS_AVAILABLE though!
                let res = path.set_status(path_status);
                event!(
                    target: "iroh::_events::path::set_status",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    ?open_addr,
                    ?path_status,
                    ?conn_id,
                    %path_id,
                    ?res,
                );
                continue;
            }
            if conn.side().is_server() {
                continue;
            }
            let fut = conn.open_path_ensure(quic_addr, path_status);
            match fut.path_id() {
                Some(path_id) => {
                    trace!(?conn_id, %path_id, ?path_status, "opening new path");
                    conn_state.add_path(open_addr.clone(), path_id);
                    // Just like in the PATH_STATUS comment above, we need to make sure that the
                    // path status is set correctly, even if the path already existed.
                    if let Some(path) = conn.path(path_id) {
                        let res = path.set_status(path_status);
                        event!(
                            target: "iroh::_events::path::set_status",
                            Level::DEBUG,
                            remote = %self.endpoint_id.fmt_short(),
                            ?open_addr,
                            ?path_status,
                            ?conn_id,
                            %path_id,
                            ?res,
                        );
                        if let Err(e) = res {
                            warn!(?e, ?open_addr, ?path_status, "Setting path status failed");
                        }
                    }
                }
                None => {
                    let ret = now_or_never(fut);
                    match ret {
                        Some(Err(PathError::RemoteCidsExhausted)) => {
                            self.scheduled_open_path =
                                Some(Instant::now() + Duration::from_millis(333));
                            self.pending_open_paths.push_back(open_addr.clone());
                            trace!(?open_addr, "scheduling open_path");
                        }
                        _ => warn!(?ret, "Opening path failed"),
                    }
                }
            }
        }
    }

    #[instrument(skip(self))]
    fn handle_path_event(
        &mut self,
        conn_id: ConnId,
        event: Result<PathEvent, BroadcastStreamRecvError>,
    ) {
        let Ok(event) = event else {
            warn!("missed a PathEvent, RemoteStateActor lagging");
            // TODO: Is it possible to recover using the sync APIs to figure out what the
            //    state of the connection and it's paths are?
            return;
        };
        let Some(conn_state) = self.connections.get_mut(&conn_id) else {
            trace!("event for removed connection");
            return;
        };
        let Some(conn) = conn_state.handle.upgrade() else {
            trace!("event for closed connection");
            return;
        };
        trace!("path event");
        match event {
            PathEvent::Opened { id: path_id } => {
                let Some(path) = conn.path(path_id) else {
                    trace!("path open event for unknown path");
                    return;
                };

                if let Ok(socketaddr) = path.remote_address()
                    && let Some(path_remote) = self.relay_mapped_addrs.to_transport_addr(socketaddr)
                {
                    event!(
                        target: "iroh::_events::path::open",
                        Level::DEBUG,
                        remote = %self.endpoint_id.fmt_short(),
                        ?path_remote,
                        ?conn_id,
                        %path_id,
                    );
                    conn_state.add_open_path(path_remote.clone(), path_id, &self.metrics);
                    self.paths
                        .insert_open_path(path_remote.clone(), Source::Connection { _0: Private });
                }

                self.select_path();
            }
            PathEvent::Abandoned { id, path_stats } => {
                trace!(?path_stats, "path abandoned");
                // This is the last event for this path.
                if let Some(addr) = conn_state.remove_path(&id) {
                    self.paths.abandoned_path(&addr);
                }
            }
            PathEvent::Closed { id, .. } | PathEvent::LocallyClosed { id, .. } => {
                let Some(path_remote) = conn_state.paths.get(&id).cloned() else {
                    debug!("path not in path_id_map");
                    return;
                };
                event!(
                    target: "iroh::_events::path::closed",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    ?path_remote,
                    ?conn_id,
                    path_id = ?id,
                );
                conn_state.remove_open_path(&id);

                // If one connection closes this path, close it on all connections.
                for (conn_id, conn_state) in self.connections.iter_mut() {
                    let Some(path_id) = conn_state.path_ids.get(&path_remote) else {
                        continue;
                    };
                    let Some(conn) = conn_state.handle.upgrade() else {
                        continue;
                    };
                    if let Some(path) = conn.path(*path_id) {
                        trace!(?path_remote, ?conn_id, %path_id, "closing path");
                        if let Err(err) = path.close() {
                            trace!(
                                ?path_remote,
                                ?conn_id,
                                %path_id,
                                "path close failed: {err:#}"
                            );
                        }
                    }
                }

                // If the remote closed our selected path, select a new one.
                self.select_path();
            }
            PathEvent::RemoteStatus { .. } | PathEvent::ObservedAddr { .. } => {
                // Nothing to do for these events.
            }
        }
    }

    /// Selects the path with the lowest RTT, prefers direct paths.
    ///
    /// If there are direct paths, this selects the direct path with the lowest RTT.  If
    /// there are only relay paths, the relay path with the lowest RTT is chosen.
    ///
    /// The selected path is added to any connections which do not yet have it.  Any unused
    /// direct paths are closed for all connections.
    #[instrument(skip_all)]
    fn select_path(&mut self) {
        // Find the lowest RTT across all connections for each open path.  The long way, so
        // we get to log *all* RTTs.
        let mut all_path_rtts: FxHashMap<transports::Addr, Vec<Duration>> = FxHashMap::default();
        for conn_state in self.connections.values() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            for (path_id, addr) in conn_state.open_paths.iter() {
                if let Some(stats) = conn.path_stats(*path_id) {
                    all_path_rtts
                        .entry(addr.clone())
                        .or_default()
                        .push(stats.rtt);
                }
            }
        }
        trace!(?all_path_rtts, "dumping all path RTTs");
        let path_rtts: FxHashMap<transports::Addr, Duration> = all_path_rtts
            .into_iter()
            .filter_map(|(addr, rtts)| rtts.into_iter().min().map(|rtt| (addr, rtt)))
            .collect();

        // Find the fastest direct IPv4 path.
        let direct_path_ipv4 = path_rtts
            .iter()
            .filter_map(|(addr, rtt)| {
                if let transports::Addr::Ip(SocketAddr::V4(addr)) = *addr {
                    Some((addr, *rtt))
                } else {
                    None
                }
            })
            .min_by_key(|(_addr, rtt)| *rtt);

        // Find the fastest direct IPv6 path.
        let direct_path_ipv6 = path_rtts
            .iter()
            .filter_map(|(addr, rtt)| {
                if let transports::Addr::Ip(SocketAddr::V6(addr)) = *addr {
                    Some((addr, *rtt))
                } else {
                    None
                }
            })
            .min_by_key(|(_addr, rtt)| *rtt);

        // Find the fastest relay path.
        let relay_path = path_rtts
            .iter()
            .filter(|(addr, _rtt)| addr.is_relay())
            .min_by_key(|(_addr, rtt)| *rtt)
            .map(|(addr, rtt)| (addr.clone(), *rtt));

        let current_path = self
            .selected_path
            .get()
            .and_then(|addr| path_rtts.get(&addr).copied().map(|rtt| (addr, rtt)));
        let selected_path = select_best_path(
            current_path.clone(),
            direct_path_ipv4,
            direct_path_ipv6,
            relay_path,
        );

        // Apply our new path
        if let Some((addr, rtt)) = selected_path {
            let prev = self.selected_path.set(Some(addr.clone()));
            if prev.is_ok() {
                event!(
                    target: "iroh::_events::path::selected",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    path_remote = ?addr,
                    ?rtt,
                    prev_remote = ?prev,
                );
            }
            self.open_path(&addr);
            self.close_redundant_paths(&addr);
        } else {
            trace!(?current_path, "keeping current path");
        }
    }

    /// Closes any direct paths not selected if we are the client.
    ///
    /// Makes sure not to close the last direct path.  Relay paths are never closed
    /// currently, because we only have one relay path at this time.
    ///
    /// Only the client closes paths, just like only the client opens paths.  This is to
    /// avoid the client and server selecting different paths and accidentally closing all
    /// paths.
    fn close_redundant_paths(&mut self, selected_path: &transports::Addr) {
        debug_assert_eq!(self.selected_path.get().as_ref(), Some(selected_path),);

        for (conn_id, conn_state) in self.connections.iter() {
            for (path_id, path_remote) in conn_state
                .open_paths
                .iter()
                .filter(|(_, addr)| addr.is_ip())
                .filter(|(_, addr)| *addr != selected_path)
            {
                if conn_state.open_paths.values().filter(|a| a.is_ip()).count() <= 1 {
                    continue; // Do not close the last direct path.
                }
                if let Some(path) = conn_state
                    .handle
                    .upgrade()
                    .filter(|conn| conn.side().is_client())
                    .and_then(|conn| conn.path(*path_id))
                {
                    trace!(?path_remote, ?conn_id, %path_id, "closing direct path");
                    match path.close() {
                        Err(quinn_proto::ClosePathError::LastOpenPath) => {
                            error!("could not close last open path");
                        }
                        Err(quinn_proto::ClosePathError::ClosedPath) => {
                            // We already closed this.
                        }
                        Ok(_fut) => {
                            // We will handle the event in Self::handle_path_events.
                        }
                    }
                }
            }
        }
    }
}

/// Returns `Some` if a new path should be selected, `None` if the `current_path` should
/// continued to be used.
fn select_best_path(
    current_path: Option<(transports::Addr, Duration)>,
    direct_path_ipv4: Option<(SocketAddrV4, Duration)>,
    direct_path_ipv6: Option<(SocketAddrV6, Duration)>,
    new_relay_path: Option<(transports::Addr, Duration)>,
) -> Option<(transports::Addr, Duration)> {
    // Determine the best new IP path.
    let best_ip_path = match (direct_path_ipv4, direct_path_ipv6) {
        (Some((addr_v4, rtt_v4)), Some((addr_v6, rtt_v6))) => {
            Some(select_v4_v6(addr_v4, rtt_v4, addr_v6, rtt_v6))
        }
        (None, Some((addr_v6, rtt_v6))) => Some((addr_v6.into(), rtt_v6)),
        (Some((addr_v4, rtt_v4)), None) => Some((addr_v4.into(), rtt_v4)),
        (None, None) => None,
    };
    let best_ip_path = best_ip_path.map(|(addr, rtt)| (transports::Addr::Ip(addr), rtt));

    match current_path {
        None => {
            // If we currently have no path
            if best_ip_path.is_some() {
                // Use the best IP path
                best_ip_path
            } else {
                // Use the new relay path
                new_relay_path
            }
        }
        Some((transports::Addr::Relay(..), _)) => {
            // If we have a current path, but it is relay
            if best_ip_path.is_some() {
                //  Use the best IP path
                best_ip_path
            } else {
                // Use the new relay path
                new_relay_path
            }
        }
        Some((transports::Addr::Ip(_), current_rtt)) => {
            match &best_ip_path {
                Some((_, new_rtt)) => {
                    // Comparing available IP paths
                    if current_rtt >= *new_rtt + RTT_SWITCHING_MIN_IP {
                        // New IP path is faster
                        best_ip_path
                    } else {
                        // New IP is not faster
                        None
                    }
                }
                None => {
                    // No new IP path, don't switch away
                    None
                }
            }
        }
    }
}

/// Compare two IP addrs v4 & v6 and selects the "best" one.
///
/// This prefers IPv6 paths over IPv4 paths.
fn select_v4_v6(
    addr_v4: SocketAddrV4,
    rtt_v4: Duration,
    addr_v6: SocketAddrV6,
    rtt_v6: Duration,
) -> (SocketAddr, Duration) {
    if rtt_v6 <= rtt_v4 + IPV6_RTT_ADVANTAGE {
        (addr_v6.into(), rtt_v6)
    } else {
        (addr_v4.into(), rtt_v4)
    }
}

fn send_datagram<'a>(
    sender: &'a mut TransportsSender,
    dst: transports::Addr,
    owned_transmit: OwnedTransmit,
) -> impl Future<Output = n0_error::Result<()>> + 'a {
    std::future::poll_fn(move |cx| {
        let transmit = transports::Transmit {
            ecn: owned_transmit.ecn,
            contents: owned_transmit.contents.as_ref(),
            segment_size: owned_transmit.segment_size,
        };

        Pin::new(&mut *sender)
            .poll_send(cx, &dst, None, &transmit)
            .map(|res| res.with_context(|_| format!("failed to send datagram to {dst:?}")))
    })
}

/// Messages to send to the [`RemoteStateActor`].
#[derive(derive_more::Debug)]
pub(crate) enum RemoteStateMessage {
    /// Sends a datagram to all known paths.
    ///
    /// Used to send QUIC Initial packets.  If there is no working direct path this will
    /// trigger holepunching.
    ///
    /// This is not acceptable to use on the normal send path, as it is an async send
    /// operation with a bunch more copying.  So it should only be used for sending QUIC
    /// Initial packets.
    #[debug("SendDatagram(..)")]
    SendDatagram(Box<TransportsSender>, OwnedTransmit),
    /// Adds an active connection to this remote endpoint.
    ///
    /// The connection will now be managed by this actor.  Holepunching will happen when
    /// needed, any new paths discovered via holepunching will be added.  And closed paths
    /// will be removed etc.
    #[debug("AddConnection(..)")]
    AddConnection(WeakConnectionHandle, oneshot::Sender<PathsWatcher>),
    /// Asks if there is any possible path that could be used.
    ///
    /// This adds the provided transport addresses to the list of potential paths for this remote
    /// and starts Address Lookup if needed.
    ///
    /// Returns `Ok` immediately if the provided address list is non-empy or we have are other known paths.
    /// Otherwise returns `Ok` once Address Lookup produces a result, or the Address Lookup error if Address Lookup fails
    /// or produces no results,
    #[debug("ResolveRemote(..)")]
    ResolveRemote(
        BTreeSet<TransportAddr>,
        oneshot::Sender<Result<(), AddressLookupError>>,
    ),
    /// Returns information about the remote.
    ///
    /// This currently only includes a list of all known transport addresses for the remote.
    RemoteInfo(oneshot::Sender<RemoteInfo>),
    /// The network status has changed in some way
    NetworkChange { is_major: bool },
}

/// Information about a holepunch attempt.
///
/// Addresses are always stored in canonical form.
#[derive(Debug)]
struct HolepunchAttempt {
    when: Instant,
    /// The set of local addresses which could take part in holepunching.
    ///
    /// This does not mean every address here participated in the holepunching.  E.g. we
    /// could have tried only a sub-set of the addresses because a previous attempt already
    /// covered part of the range.
    ///
    /// We do not store this as a [`DirectAddr`] because this is checked for equality and we
    /// do not want to compare the sources of these addresses.
    local_candidates: BTreeSet<SocketAddr>,
    /// The set of remote addresses which could take part in holepunching.
    ///
    /// Like [`Self::local_candidates`] we may not have used them.
    remote_candidates: BTreeSet<SocketAddr>,
}

/// Newtype to track Connections.
///
/// The wrapped value is the [`quinn::Connection::stable_id`] value, and is thus only valid
/// for active connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ConnId(usize);

/// State about one connection.
#[derive(Debug)]
struct ConnectionState {
    /// Weak handle to the connection.
    handle: WeakConnectionHandle,
    /// The information we publish to users about the paths used in this connection.
    pub_open_paths: Watchable<PathAddrList>,
    /// The paths that exist on this connection.
    ///
    /// This could be in any state, e.g. while still validating the path or already closed
    /// but not yet fully removed from the connection.  This exists as long as Quinn knows
    /// about the [`PathId`].
    paths: FxHashMap<PathId, transports::Addr>,
    /// The open paths on this connection, a subset of [`Self::paths`].
    open_paths: FxHashMap<PathId, transports::Addr>,
    /// Reverse map of [`Self::paths].
    path_ids: FxHashMap<transports::Addr, PathId>,
    /// Whether this connection has ever had a direct path.
    ///
    /// Used for recording metrics.
    has_been_direct: bool,
}

impl ConnectionState {
    /// Tracks a path for the connection.
    fn add_path(&mut self, remote: transports::Addr, path_id: PathId) {
        self.paths.insert(path_id, remote.clone());
        self.path_ids.insert(remote, path_id);
    }

    /// Tracks an open path for the connection.
    fn add_open_path(
        &mut self,
        remote: transports::Addr,
        path_id: PathId,
        metrics: &Arc<SocketMetrics>,
    ) {
        match remote {
            transports::Addr::Ip(_) => metrics.paths_direct.inc(),
            transports::Addr::Relay(_, _) => metrics.paths_relay.inc(),
        };
        if !self.has_been_direct && remote.is_ip() {
            self.has_been_direct = true;
            metrics.num_conns_direct.inc();
        }
        self.paths.insert(path_id, remote.clone());
        self.open_paths.insert(path_id, remote.clone());
        self.path_ids.insert(remote, path_id);
        self.update_pub_path_info();
    }

    /// Completely removes a path from this connection.
    fn remove_path(&mut self, path_id: &PathId) -> Option<transports::Addr> {
        let addr = self.paths.remove(path_id);
        if let Some(ref addr) = addr {
            self.path_ids.remove(addr);
        }
        self.open_paths.remove(path_id);
        addr
    }

    /// Removes the path from the open paths.
    fn remove_open_path(&mut self, path_id: &PathId) {
        self.open_paths.remove(path_id);

        self.update_pub_path_info();
    }

    /// Sets the new [`PathInfo`] structs for the public [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    fn update_pub_path_info(&self) {
        let new = self
            .open_paths
            .iter()
            .map(|(path_id, remote)| {
                let remote = TransportAddr::from(remote.clone());
                (remote, *path_id)
            })
            .collect::<PathAddrList>();

        self.pub_open_paths.set(new).ok();
    }
}

/// Watcher for the open paths and selected transmission path in a connection.
///
/// This is stored in the [`Connection`], and the watchables are set from within the endpoint state actor.
///
/// Internally, this contains a boxed-mapped-joined watcher over the open paths in the connection and the
/// selected path to the remote endpoint. The watcher is boxed because the mapped-joined watcher with
/// `SmallVec<PathInfoList>` has a size of over 800 bytes, which we don't want to put upon the [`Connection`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Clone, derive_more::Debug)]
#[debug("PathsWatcher")]
#[allow(clippy::type_complexity)]
pub(crate) struct PathsWatcher(
    Box<
        n0_watcher::Map<
            n0_watcher::Tuple<
                n0_watcher::Direct<PathAddrList>,
                n0_watcher::Direct<Option<transports::Addr>>,
            >,
            PathInfoList,
        >,
    >,
);

impl n0_watcher::Watcher for PathsWatcher {
    type Value = PathInfoList;

    fn update(&mut self) -> bool {
        self.0.update()
    }

    fn peek(&self) -> &Self::Value {
        self.0.peek()
    }

    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }

    fn poll_updated(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), n0_watcher::Disconnected>> {
        self.0.poll_updated(cx)
    }
}

impl PathsWatcher {
    fn new(
        open_paths: n0_watcher::Direct<PathAddrList>,
        selected_path: n0_watcher::Direct<Option<transports::Addr>>,
        conn_handle: WeakConnectionHandle,
    ) -> Self {
        Self(Box::new(open_paths.or(selected_path).map(
            move |(open_paths, selected_path)| {
                let selected_path: Option<TransportAddr> = selected_path.map(Into::into);
                let Some(conn) = conn_handle.upgrade() else {
                    return PathInfoList(Default::default());
                };
                let list = open_paths
                    .into_iter()
                    .flat_map(move |(remote, path_id)| {
                        PathInfo::new(path_id, &conn, remote, selected_path.as_ref())
                    })
                    .collect();
                PathInfoList(list)
            },
        )))
    }
}

/// List of [`PathInfo`] for the network paths of a [`Connection`].
///
/// This struct implements [`IntoIterator`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(derive_more::Debug, derive_more::IntoIterator, Eq, PartialEq, Clone)]
#[debug("{_0:?}")]
pub struct PathInfoList(SmallVec<[PathInfo; 4]>);

impl PathInfoList {
    /// Returns an iterator over the path infos.
    pub fn iter(&self) -> impl Iterator<Item = &PathInfo> {
        self.0.iter()
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of paths.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Information about a network path used by a [`Connection`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(derive_more::Debug, Clone)]
pub struct PathInfo {
    path_id: PathId,
    #[debug(skip)]
    handle: WeakConnectionHandle,
    stats: PathStats,
    remote: TransportAddr,
    is_selected: bool,
}

impl PartialEq for PathInfo {
    fn eq(&self, other: &Self) -> bool {
        self.path_id == other.path_id
            && self.remote == other.remote
            && self.is_selected == other.is_selected
    }
}

impl Eq for PathInfo {}

impl PathInfo {
    fn new(
        path_id: PathId,
        conn: &quinn::Connection,
        remote: TransportAddr,
        selected_path: Option<&TransportAddr>,
    ) -> Option<Self> {
        let stats = conn.path_stats(path_id)?;
        Some(Self {
            path_id,
            handle: conn.weak_handle(),
            is_selected: Some(&remote) == selected_path,
            remote,
            stats,
        })
    }

    /// The remote transport address used by this network path.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.remote
    }

    /// Returns `true` if this path is currently the main transmission path for this [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    /// Whether this is an IP transport address.
    pub fn is_ip(&self) -> bool {
        self.remote.is_ip()
    }

    /// Whether this is a transport address via a relay server.
    pub fn is_relay(&self) -> bool {
        self.remote.is_relay()
    }

    /// Returns stats for this transmission path.
    pub fn stats(&self) -> PathStats {
        self.handle
            .upgrade()
            .and_then(|conn| conn.path_stats(self.path_id))
            .unwrap_or(self.stats)
    }

    /// Current best estimate of this paths's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        self.stats().rtt
    }
}

/// Poll a future once, like n0_future::future::poll_once but sync.
fn now_or_never<T, F: Future<Output = T>>(fut: F) -> Option<T> {
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        Poll::Ready(res) => Some(res),
        Poll::Pending => None,
    }
}

/// Future that resolves to the `conn_id` once a connection is closed.
///
/// This uses [`quinn::Connection::on_closed`], which does not keep the connection alive
/// while awaiting the future.
struct OnClosed {
    conn_id: ConnId,
    inner: quinn::OnClosed,
}

impl OnClosed {
    fn new(conn: &quinn::Connection) -> Self {
        Self {
            conn_id: ConnId(conn.stable_id()),
            inner: conn.on_closed(),
        }
    }
}

impl Future for OnClosed {
    type Output = ConnId;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let (_close_reason, _stats) = std::task::ready!(Pin::new(&mut self.inner).poll(cx));
        Poll::Ready(self.conn_id)
    }
}

/// Converts an iterator of [`TransportAddr'] into an iterator of [`transports::Addr`].
fn to_transports_addr(
    endpoint_id: EndpointId,
    addrs: impl IntoIterator<Item = TransportAddr>,
) -> impl Iterator<Item = transports::Addr> {
    addrs.into_iter().filter_map(move |addr| match addr {
        TransportAddr::Relay(relay_url) => Some(transports::Addr::from((relay_url, endpoint_id))),
        TransportAddr::Ip(sockaddr) => Some(transports::Addr::from(sockaddr)),
        _ => {
            warn!(?addr, "Unsupported TransportAddr");
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_select_v4_v6_addr() {
        let v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0);

        // Same RTT, prefer v6
        let (addr, rtt) =
            select_v4_v6(v4, Duration::from_millis(10), v6, Duration::from_millis(10));
        assert_eq!(addr, v6.into());
        assert_eq!(rtt, Duration::from_millis(10));

        // v4 better
        let (addr, rtt) = select_v4_v6(v4, Duration::from_millis(1), v6, Duration::from_millis(10));
        assert_eq!(addr, v4.into());
        assert_eq!(rtt, Duration::from_millis(1));

        // v6 better
        let (addr, rtt) = select_v4_v6(v4, Duration::from_millis(10), v6, Duration::from_millis(1));
        assert_eq!(addr, v6.into());
        assert_eq!(rtt, Duration::from_millis(1));
    }
}
