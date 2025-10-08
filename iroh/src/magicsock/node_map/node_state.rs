use std::{collections::BTreeSet, net::SocketAddr, pin::Pin, sync::Arc};

use iroh_base::{NodeAddr, NodeId, RelayUrl};
use n0_future::{
    MergeUnbounded, Stream, StreamExt,
    task::AbortOnDropHandle,
    time::{Duration, Instant},
};
use n0_watcher::Watcher;
use quinn::WeakConnectionHandle;
use quinn_proto::{PathEvent, PathId, PathStatus};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Whatever};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::{Instrument, Level, debug, error, event, info_span, instrument, trace, warn};

#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;
use crate::{
    disco::{self},
    endpoint::DirectAddr,
    magicsock::{
        DiscoState, HEARTBEAT_INTERVAL, MAX_IDLE_TIMEOUT, MagicsockMetrics,
        mapped_addrs::{AddrMap, MappedAddr, MultipathMappedAddr, RelayMappedAddr},
        transports::{self, OwnedTransmit},
    },
    util::MaybeFuture,
};

use super::{Source, TransportsSenderMessage, path_state::PathState};

/// Number of addresses that are not active that we keep around per node.
///
/// See [`NodeState::prune_direct_addresses`].
pub(super) const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 20;

/// How long since an endpoint path was last alive before it might be pruned.
const LAST_ALIVE_PRUNE_DURATION: Duration = Duration::from_secs(120);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long since the last activity we try to keep an established endpoint peering alive.
///
/// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better path.
///
/// Even if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// The value which we close paths.
// TODO: Quinn should just do this.  Also, I made this value up.
const APPLICATION_ABANDON_PATH: u8 = 30;

/// The state we need to know about a single remote node.
///
/// This actor manages all connections to the remote node.  It will trigger holepunching and
/// select the best path etc.
pub(super) struct NodeStateActor {
    /// The node ID of the remote node.
    node_id: NodeId,
    /// The node ID of the local node.
    local_node_id: NodeId,

    // Hooks into the rest of the MagicSocket.
    //
    /// Metrics.
    metrics: Arc<MagicsockMetrics>,
    /// Allowing us to directly send datagrams.
    ///
    /// Used for handling [`NodeStateMessage::SendDatagram`] messages.
    transports_sender: mpsc::Sender<TransportsSenderMessage>,
    /// Our local addresses.
    ///
    /// These are our local addresses and any reflexive transport addresses.
    local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    /// Shared state to allow to encrypt DISCO messages to peers.
    disco: DiscoState,
    /// The mapping between nodes via a relay and their [`RelayMappedAddr`]s.
    relay_mapped_addrs: AddrMap<(RelayUrl, NodeId), RelayMappedAddr>,

    // Internal state - Quinn Connections we are managing.
    //
    /// All connections we have to this remote node.
    ///
    /// The key is the [`quinn::Connection::stable_id`].
    connections: FxHashMap<usize, WeakConnectionHandle>,
    /// Events emitted by Quinn about path changes.
    // path_events: MergeUnbounded<BroadcastStream<PathEvent>>,
    path_events: MergeUnbounded<
        Pin<
            Box<
                dyn Stream<Item = (usize, Result<PathEvent, BroadcastStreamRecvError>)>
                    + Send
                    + Sync,
            >,
        >,
    >,

    // Internal state - Holepunching and path state.
    //
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by discovery
    /// mechanisms.  The are only potentially usable.
    paths: FxHashMap<transports::Addr, PathState>,
    /// Maps connections and path IDs to the transport addr.
    ///
    /// The [`transports::Addr`] can be looked up in [`Self::paths`].
    ///
    /// The `usize` is the [`Connection::stable_id`] of a connection.  It is important that
    /// this map is cleared of the stable ID of a new connection received from
    /// [`NodeStateMessage::AddConnection`], because this ID is only unique within
    /// *currently active* connections.  So there could be conflicts if we did not yet know
    /// a previous connection no longer exists.
    // TODO: We do exhaustive searches through this map to find items based on
    //    transports::Addr.  Perhaps a bi-directional map could be considered.
    path_id_map: FxHashMap<(usize, PathId), transports::Addr>,
    /// Information about the last holepunching attempt.
    last_holepunch: Option<HolepunchAttempt>,
    /// The path we currently consider the preferred path to the remote node.
    ///
    /// **We expect this path to work.** If we become aware this path is broken then it is
    /// set back to `None`.  Having a selected path does not mean we may not be able to get
    /// a better path: e.g. when the selected path is a relay path we still need to trigger
    /// holepunching regularly.
    ///
    /// We only select a path once the path is functional in Quinn.
    selected_path: Option<transports::Addr>,
    /// Time at which we should schedule the next holepunch attempt.
    scheduled_holepunch: Option<Instant>,
}

impl NodeStateActor {
    pub(super) fn new(
        node_id: NodeId,
        local_node_id: NodeId,
        transports_sender: mpsc::Sender<TransportsSenderMessage>,
        local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        disco: DiscoState,
        relay_mapped_addrs: AddrMap<(RelayUrl, NodeId), RelayMappedAddr>,
        metrics: Arc<MagicsockMetrics>,
    ) -> Self {
        Self {
            node_id,
            local_node_id,
            metrics,
            transports_sender,
            local_addrs,
            relay_mapped_addrs,
            disco,
            connections: FxHashMap::default(),
            path_events: Default::default(),
            paths: FxHashMap::default(),
            path_id_map: FxHashMap::default(),
            last_holepunch: None,
            selected_path: None,
            scheduled_holepunch: None,
        }
    }

    pub(super) fn start(mut self) -> NodeStateHandle {
        let (tx, rx) = mpsc::channel(16);
        let me = self.local_node_id;
        let node_id = self.node_id;

        // Ideally we'd use the endpoint span as parent.  We'd have to plug that span into
        // here somehow.  Instead we have no parent and explicitly set the me attribute.  If
        // we don't explicitly set a span we get the spans from whatever call happens to
        // first create the actor, which is often very confusing as it then keeps those
        // spans for all logging of the actor.
        let task = tokio::spawn(
            async move {
                if let Err(err) = self.run(rx).await {
                    error!("actor failed: {err:#}");
                }
            }
            .instrument(info_span!(
                parent: None,
                "NodeStateActor",
                me = %me.fmt_short(),
                remote_node = %node_id.fmt_short(),
            )),
        );
        NodeStateHandle {
            sender: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

    async fn run(&mut self, mut inbox: mpsc::Receiver<NodeStateMessage>) -> Result<(), Whatever> {
        trace!("actor started");
        loop {
            let scheduled_hp = match self.scheduled_holepunch {
                Some(when) => MaybeFuture::Some(tokio::time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            let mut scheduled_hp = std::pin::pin!(scheduled_hp);
            tokio::select! {
                biased;
                msg = inbox.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg).await?,
                        None => break,
                    }
                }
                Some((id, evt)) = self.path_events.next() => {
                    self.handle_path_event(id, evt).await;
                }
                _ = self.local_addrs.updated() => {
                    trace!("local addrs updated, triggering holepunching");
                    self.trigger_holepunching().await;
                }
                _ = &mut scheduled_hp => {
                    trace!("triggering scheduled holepunching");
                    self.scheduled_holepunch = None;
                    self.trigger_holepunching().await;
                }
            }
        }
        trace!("actor terminating");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn handle_message(&mut self, msg: NodeStateMessage) -> Result<(), Whatever> {
        trace!("handling message");
        match msg {
            NodeStateMessage::SendDatagram(transmit) => {
                if let Some(ref addr) = self.selected_path {
                    self.transports_sender
                        .send((addr.clone(), transmit).into())
                        .await
                        .whatever_context("TransportSenderActor stopped")?;
                } else {
                    for addr in self.paths.keys() {
                        self.transports_sender
                            .send((addr.clone(), transmit.clone()).into())
                            .await
                            .whatever_context("TransportSenerActor stopped")?;
                    }
                    // This message is received *before* a connection is added.  So we do
                    // not yet have a connection to holepunch.  Instead we trigger
                    // holepunching when AddConnection is received.
                }
            }
            NodeStateMessage::AddConnection(handle) => {
                if let Some(conn) = handle.upgrade() {
                    // Remove any conflicting stable_ids from the local state.
                    let stable_id = conn.stable_id();
                    self.connections.remove(&stable_id);
                    self.path_id_map.retain(|(id, _), _| *id != stable_id);

                    // This is a good time to clean up connections.
                    self.cleanup_connections();

                    let stable_id = conn.stable_id();
                    let events = BroadcastStream::new(conn.path_events());
                    let stream = events.map(move |evt| (stable_id, evt));
                    self.path_events.push(Box::pin(stream));
                    self.connections.insert(stable_id, handle.clone());
                    if let Some(conn) = handle.upgrade() {
                        if let Some(addr) = self.path_transports_addr(&conn, PathId::ZERO) {
                            self.paths
                                .entry(addr)
                                .or_default()
                                .sources
                                .insert(Source::Connection, Instant::now());
                            self.select_path();
                        }
                        // TODO: Make sure we are adding the relay path if we're on a direct
                        // path.
                        self.trigger_holepunching().await;
                    }
                }
            }
            NodeStateMessage::AddNodeAddr(node_addr, source) => {
                for sockaddr in node_addr.direct_addresses {
                    let addr = transports::Addr::from(sockaddr);
                    let path = self.paths.entry(addr).or_default();
                    path.sources.insert(source.clone(), Instant::now());
                }
                if let Some(relay_url) = node_addr.relay_url {
                    let addr = transports::Addr::from((relay_url, self.node_id));
                    let path = self.paths.entry(addr).or_default();
                    path.sources.insert(source, Instant::now());
                }
            }
            NodeStateMessage::CallMeMaybeReceived(msg) => {
                event!(
                    target: "iroh::_events::call-me-maybe::recv",
                    Level::DEBUG,
                    remote_node = %self.node_id.fmt_short(),
                    addrs = ?msg.my_numbers,
                );
                let now = Instant::now();
                for addr in msg.my_numbers {
                    let dst = transports::Addr::Ip(addr);
                    let ping = disco::Ping::new(self.local_node_id);

                    let path = self.paths.entry(dst.clone()).or_default();
                    path.sources.insert(Source::CallMeMaybe, now);
                    path.ping_sent = Some(ping.clone());

                    event!(
                        target: "iroh::_events::ping::sent",
                        Level::DEBUG,
                        remote_node = %self.node_id.fmt_short(),
                        ?dst,
                    );
                    self.send_disco_message(dst, disco::Message::Ping(ping))
                        .await;
                }
            }
            NodeStateMessage::PingReceived(ping, src) => {
                let transports::Addr::Ip(addr) = src else {
                    warn!("received ping via relay transport, ignored");
                    return Ok(());
                };
                event!(
                    target: "iroh::_events::ping::recv",
                    Level::DEBUG,
                    remote_node = %self.node_id.fmt_short(),
                    ?src,
                    txn = ?ping.tx_id,
                );
                let pong = disco::Pong {
                    tx_id: ping.tx_id,
                    ping_observed_addr: addr.into(),
                };
                event!(
                    target: "iroh::_events::pong::sent",
                    Level::DEBUG,
                    remote_node = %self.node_id.fmt_short(),
                    dst = ?src,
                    txn = ?pong.tx_id,
                );
                self.send_disco_message(src.clone(), disco::Message::Pong(pong))
                    .await;

                let path = self.paths.entry(src).or_default();
                path.sources.insert(Source::Ping, Instant::now());

                trace!("ping received, triggering holepunching");
                self.trigger_holepunching().await;
            }
            NodeStateMessage::PongReceived(pong, src) => {
                let Some(state) = self.paths.get(&src) else {
                    warn!(path = ?src, "ignoring DISCO Pong for unknown path");
                    return Ok(());
                };
                let ping_tx = state.ping_sent.as_ref().map(|ping| ping.tx_id);
                if ping_tx != Some(pong.tx_id) {
                    debug!(path = ?src, ?ping_tx, pong_tx = ?pong.tx_id,
                        "ignoring unknown DISCO Pong for path");
                    return Ok(());
                }
                event!(
                    target: "iroh::_events::pong::recv",
                    Level::DEBUG,
                    remote_node = %self.node_id.fmt_short(),
                    ?src,
                    txn = ?pong.tx_id,
                );

                self.open_path(&src);
            }
            NodeStateMessage::CanSend(tx) => {
                let can_send = !self.paths.is_empty();
                tx.send(can_send).ok();
            }
            NodeStateMessage::Latency(tx) => {
                let rtt = self.selected_path.as_ref().and_then(|addr| {
                    for (conn_id, path_id) in self
                        .path_id_map
                        .iter()
                        .filter_map(|(key, path)| (path == addr).then_some(key))
                    {
                        if let Some(conn) = self
                            .connections
                            .get(conn_id)
                            .and_then(|handle| handle.upgrade())
                        {
                            if let Some(path_stats) = conn.stats().paths.get(path_id) {
                                return Some(path_stats.rtt);
                            }
                        }
                    }
                    None
                });
                tx.send(rtt).ok();
            }
        }
        Ok(())
    }

    /// Triggers holepunching to the remote node.
    ///
    /// This will manage the entire process of holepunching with the remote node.
    ///
    /// - If there already is a direct connection, nothing happens.
    /// - If there is no relay address known, nothing happens.
    /// - If there was a recent attempt, it will schedule holepunching instead.
    ///   - Unless there are new addresses to try.
    ///   - The scheduled attempt will only run if holepunching has not yet succeeded by
    ///     then.
    /// - DISCO pings will be sent to addresses recently advertised in a call-me-maybe
    ///   message.
    /// - A DISCO call-me-maybe message advertising our own addresses will be sent.
    ///
    /// If a next trigger needs to be scheduled the delay until when to call this again is
    /// returned.
    async fn trigger_holepunching(&mut self) {
        const HOLEPUNCH_ATTEMPTS_INTERVAL: Duration = Duration::from_secs(5);

        if self.connections.is_empty() {
            trace!("not holepunching: no connections");
            return;
        }

        if self
            .selected_path
            .as_ref()
            .map(|addr| addr.is_ip())
            .unwrap_or_default()
        {
            // TODO: We should ping this path to make sure it still works.  Because we now
            // know things could be broken.
            trace!("not holepunching: already have a direct connection");
            // TODO: If the latency is kind of bad we should retry holepunching at times.
            return;
        }

        let remote_addrs: BTreeSet<SocketAddr> = self.remote_hp_addrs();
        let local_addrs: BTreeSet<SocketAddr> = self
            .local_addrs
            .get()
            .iter()
            .map(|daddr| daddr.addr)
            .collect();
        let new_addrs = self
            .last_holepunch
            .as_ref()
            .map(|last_hp| {
                // Addrs are allowed to disappear, but if there are new ones we need to
                // holepunch again.
                !remote_addrs.is_subset(&last_hp.remote_addrs)
                    || !local_addrs.is_subset(&last_hp.local_addrs)
            })
            .unwrap_or(true);
        if !new_addrs {
            if let Some(ref last_hp) = self.last_holepunch {
                let next_hp = last_hp.when + HOLEPUNCH_ATTEMPTS_INTERVAL;
                if next_hp > Instant::now() {
                    trace!(scheduled_in = ?next_hp, "not holepunching: no new addresses");
                    self.scheduled_holepunch = Some(next_hp);
                    return;
                }
            }
        }

        self.do_holepunching().await;
    }

    /// Returns the remote addresses to holepunch against.
    fn remote_hp_addrs(&self) -> BTreeSet<SocketAddr> {
        const CALL_ME_MAYBE_VALIDITY: Duration = Duration::from_secs(30);

        self.paths
            .iter()
            .filter_map(|(addr, state)| match addr {
                transports::Addr::Ip(socket_addr) => Some((socket_addr, state)),
                transports::Addr::Relay(_, _) => None,
            })
            .filter_map(|(addr, state)| {
                if state
                    .sources
                    .get(&Source::CallMeMaybe)
                    .map(|when| when.elapsed() >= CALL_ME_MAYBE_VALIDITY)
                    .unwrap_or_default()
                    || state
                        .sources
                        .get(&Source::Ping)
                        .map(|when| when.elapsed() >= CALL_ME_MAYBE_VALIDITY)
                        .unwrap_or_default()
                {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Unconditionally perform holepunching.
    ///
    /// - DISCO pings will be sent to addresses recently advertised in a call-me-maybe
    ///   message.
    /// - A DISCO call-me-maybe message advertising our own addresses will be sent.
    async fn do_holepunching(&mut self) {
        trace!("holepunching");
        let Some(relay_addr) = self
            .paths
            .iter()
            .filter_map(|(addr, _)| match addr {
                transports::Addr::Ip(_) => None,
                transports::Addr::Relay(_, _) => Some(addr),
            })
            .next()
            .cloned()
        else {
            warn!("holepunching requested but have no relay address");
            return;
        };
        let remote_addrs = self.remote_hp_addrs();

        // Send DISCO Ping messages to all CallMeMaybe-advertised paths.
        for dst in remote_addrs.iter() {
            let msg = disco::Ping::new(self.local_node_id);
            event!(
                target: "iroh::_events::ping::sent",
                Level::DEBUG,
                remote_node = %self.node_id.fmt_short(),
                ?dst,
                txn = ?msg.tx_id,
            );
            let addr = transports::Addr::Ip(*dst);
            self.paths.entry(addr.clone()).or_default().ping_sent = Some(msg.clone());
            self.send_disco_message(addr, disco::Message::Ping(msg))
                .await;
        }

        // Send the DISCO CallMeMaybe message over the relay.
        let my_numbers: Vec<SocketAddr> = self
            .local_addrs
            .get()
            .iter()
            .map(|daddr| daddr.addr)
            .collect();
        let local_addrs: BTreeSet<SocketAddr> = my_numbers.iter().copied().collect();
        let msg = disco::CallMeMaybe { my_numbers };
        event!(
            target: "iroh::_events::call-me-maybe::sent",
            Level::DEBUG,
            remote_node = %self.node_id.fmt_short(),
            dst = ?relay_addr,
            my_numbers = ?msg.my_numbers,
        );
        self.send_disco_message(relay_addr, disco::Message::CallMeMaybe(msg))
            .await;

        self.last_holepunch = Some(HolepunchAttempt {
            when: Instant::now(),
            local_addrs,
            remote_addrs,
        });
    }

    /// Sends a DISCO message to *this* remote node.
    #[instrument(skip(self), fields(dst_node = %self.node_id.fmt_short()))]
    async fn send_disco_message(&self, dst: transports::Addr, msg: disco::Message) {
        let pkt = self.disco.encode_and_seal(self.node_id, &msg);
        let transmit = transports::OwnedTransmit {
            ecn: None,
            contents: pkt,
            segment_size: None,
        };
        let counter = match dst {
            transports::Addr::Ip(_) => &self.metrics.send_disco_udp,
            transports::Addr::Relay(_, _) => &self.metrics.send_disco_relay,
        };
        match self.transports_sender.send((dst, transmit).into()).await {
            Ok(()) => {
                trace!("sent");
                counter.inc();
            }
            Err(err) => {
                warn!("failed to send disco message: {err:#}");
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
            transports::Addr::Relay(relay_url, node_id) => self
                .relay_mapped_addrs
                .get(&(relay_url.clone(), *node_id))
                .private_socket_addr(),
        };

        // The connections that already have this path.
        let mut conns_with_path = BTreeSet::new();
        for ((conn_id, _), addr) in self.path_id_map.iter() {
            if addr == open_addr {
                conns_with_path.insert(*conn_id);
            }
        }

        for conn in self
            .connections
            .iter()
            .filter_map(|(conn_id, handle)| (!conns_with_path.contains(conn_id)).then_some(handle))
            .filter_map(|handle| handle.upgrade())
            .filter(|conn| conn.side().is_client())
        {
            match conn.open_path_ensure(quic_addr, path_status).path_id() {
                Some(path_id) => {
                    self.path_id_map
                        .insert((conn.stable_id(), path_id), open_addr.clone());
                }
                None => {
                    warn!("Opening path failed");
                }
            }
        }
    }

    #[instrument(skip(self))]
    async fn handle_path_event(
        &mut self,
        conn_id: usize,
        event: Result<PathEvent, BroadcastStreamRecvError>,
    ) {
        let Ok(event) = event else {
            warn!("missed a PathEvent, NodeStateActor lagging");
            // TODO: Is it possible to recover using the sync APIs to figure out what the
            //    state of the connection and it's paths are?
            return;
        };
        let Some(handle) = self.connections.get(&conn_id) else {
            trace!("event for removed connection");
            return;
        };
        let Some(conn) = handle.upgrade() else {
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
                path.set_keep_alive_interval(Some(HEARTBEAT_INTERVAL)).ok();
                path.set_max_idle_timeout(Some(MAX_IDLE_TIMEOUT)).ok();

                self.select_path();
            }
            PathEvent::Abandoned { id, path_stats } => {
                trace!(?path_stats, "path abandoned");
                // This is the last event for this path.
                self.path_id_map.remove(&(conn_id, id));
            }
            PathEvent::Closed { id, .. } | PathEvent::LocallyClosed { id, .. } => {
                // If one connection closes this path, close it on all connections.
                let Some(addr) = self.path_id_map.get(&(conn_id, id)) else {
                    debug!("path not in path_id_map");
                    return;
                };
                for (conn_id, path_id) in self
                    .path_id_map
                    .iter()
                    .filter(|(_, path_addr)| *path_addr == addr)
                    .map(|(key, _)| key)
                {
                    if let Some(conn) = self
                        .connections
                        .get(&conn_id)
                        .map(|handle| handle.upgrade())
                        .flatten()
                    {
                        if let Some(path) = conn.path(*path_id) {
                            trace!(?addr, ?conn_id, ?path_id, "closing path");
                            if let Err(err) = path.close(APPLICATION_ABANDON_PATH.into()) {
                                trace!(?addr, ?conn_id, ?path_id, "path close failed: {err:#}");
                            }
                        }
                    }
                }
            }
            PathEvent::RemoteStatus { .. } | PathEvent::ObservedAddr { .. } => {
                // Nothing to do for these events.
            }
        }
    }

    /// Clean up connections which no longer exist.
    // TODO: Call this on a schedule.
    fn cleanup_connections(&mut self) {
        self.connections
            .retain(|_, handle| handle.upgrade().is_some());

        let mut stable_ids = BTreeSet::new();
        for handle in self.connections.values() {
            handle
                .upgrade()
                .map(|conn| stable_ids.insert(conn.stable_id()));
        }

        self.path_id_map
            .retain(|(stable_id, _), _| stable_ids.contains(stable_id));
    }

    /// Selects the path with the lowest RTT, prefers direct paths.
    ///
    /// If there are direct paths, this selects the direct path with the lowest RTT.  If
    /// there are only relay paths, the relay path with the lowest RTT is chosen.
    ///
    /// The selected path is added to any connections which do not yet have it.  Any unused
    /// direct paths are close from all connections.
    fn select_path(&mut self) {
        // Find the lowest RTT across all connections for each open path.  The long way, so
        // we get to trace-log *all* RTTs.
        let mut all_path_rtts: FxHashMap<transports::Addr, Vec<Duration>> = FxHashMap::default();
        for (conn_id, conn) in self
            .connections
            .iter()
            .filter_map(|(id, handle)| handle.upgrade().map(|conn| (*id, conn)))
        {
            let stats = conn.stats();
            for (path_id, stats) in stats.paths {
                if let Some(addr) = self.path_id_map.get(&(conn_id, path_id)) {
                    all_path_rtts
                        .entry(addr.clone())
                        .or_default()
                        .push(stats.rtt);
                } else {
                    trace!(?path_id, "unknown PathId in ConnectionStats");
                }
            }
        }
        trace!(?all_path_rtts, "dumping all path RTTs");
        let path_rtts: FxHashMap<transports::Addr, Duration> = all_path_rtts
            .into_iter()
            .filter_map(|(addr, rtts)| rtts.into_iter().min().map(|rtt| (addr, rtt)))
            .collect();

        // Find the fastest direct path.
        const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);
        let direct_path = path_rtts
            .iter()
            .filter(|(addr, _rtt)| addr.is_ip())
            .map(|(addr, rtt)| {
                if addr.is_ipv4() {
                    (*rtt + IPV6_RTT_ADVANTAGE, addr)
                } else {
                    (*rtt, addr)
                }
            })
            .min()
            .map(|(_rtt, addr)| addr.clone());
        if let Some(addr) = direct_path {
            let prev = self.selected_path.replace(addr.clone());
            if prev.as_ref() != Some(&addr) {
                debug!(?addr, ?prev, "selected new direct path");
            }
            self.open_path(&addr);
            self.close_redundant_paths(&addr);
            return;
        }

        // Still here?  Find the fastest relay path.
        let relay_path = path_rtts
            .iter()
            .filter(|(addr, _rtt)| addr.is_relay())
            .map(|(addr, rtt)| (rtt, addr))
            .min()
            .map(|(_rtt, addr)| addr.clone());
        if let Some(addr) = relay_path {
            let prev = self.selected_path.replace(addr.clone());
            if prev.as_ref() != Some(&addr) {
                debug!(?addr, ?prev, "selected new relay path");
            }
            self.open_path(&addr);
            self.close_redundant_paths(&addr);
            return;
        }
    }

    /// Closes any direct paths not selected.
    ///
    /// Makes sure not to close the last direct path.  Relay paths are never closed
    /// currently, because we only have one relay path at this time.
    fn close_redundant_paths(&mut self, selected_path: &transports::Addr) {
        debug_assert_eq!(self.selected_path.as_ref(), Some(selected_path));

        // We create this to make sure we do not close the last direct path.
        let mut paths_per_conn: FxHashMap<usize, Vec<PathId>> = FxHashMap::default();
        for ((conn_id, path_id), addr) in self.path_id_map.iter() {
            if !addr.is_ip() {
                continue;
            }
            paths_per_conn.entry(*conn_id).or_default().push(*path_id);
        }

        self.path_id_map.retain(|(conn_id, path_id), addr| {
            if !addr.is_ip() || addr == selected_path {
                // This not a direct path or is the selected path.
                return true;
            }
            if paths_per_conn
                .get(conn_id)
                .map(|paths| paths.len() == 1)
                .unwrap_or_default()
            {
                // This is the only direct path on this connection.
                return true;
            }
            if let Some(conn) = self
                .connections
                .get(conn_id)
                .map(|handle| handle.upgrade())
                .flatten()
            {
                trace!(?addr, ?conn_id, ?path_id, "closing direct path");
                if let Some(path) = conn.path(*path_id) {
                    match path.close(APPLICATION_ABANDON_PATH.into()) {
                        Err(quinn_proto::ClosePathError::LastOpenPath) => {
                            error!("could not close last open path");
                        }
                        Err(quinn_proto::ClosePathError::ClosedPath) => (),
                        Ok(_fut) => {
                            // TODO: Should investigate if we care about this future.
                        }
                    }
                }
            }
            false
        });
    }

    /// Returns the remote [`transports::Addr`] for a path.
    fn path_transports_addr(
        &self,
        conn: &quinn::Connection,
        path_id: PathId,
    ) -> Option<transports::Addr> {
        conn.path(path_id)
            .map(|path| {
                path.remote_address().map_or(None, |remote| {
                    match MultipathMappedAddr::from(remote) {
                        MultipathMappedAddr::Mixed(_) => {
                            error!("Mixed addr in use for path");
                            None
                        }
                        MultipathMappedAddr::Relay(mapped) => {
                            match self.relay_mapped_addrs.lookup(&mapped) {
                                Some(parts) => Some(transports::Addr::from(parts)),
                                None => {
                                    error!("Unknown RelayMappedAddr in path");
                                    None
                                }
                            }
                        }
                        MultipathMappedAddr::Ip(addr) => Some(addr.into()),
                    }
                })
            })
            .flatten()
    }
}

/// Messages to send to the [`NodeStateActor`].
#[derive(derive_more::Debug)]
pub(crate) enum NodeStateMessage {
    /// Sends a datagram to all known paths.
    ///
    /// Used to send QUIC Initial packets.  If there is no working direct path this will
    /// trigger holepunching.
    ///
    /// This is not acceptable to use on the normal send path, as it is an async send
    /// operation with a bunch more copying.  So it should only be used for sending QUIC
    /// Initial packets.
    #[debug("SendDatagram(OwnedTransmit)")]
    SendDatagram(OwnedTransmit),
    /// Adds an active connection to this remote node.
    ///
    /// The connection will now be managed by this actor.  Holepunching will happen when
    /// needed, any new paths discovered via holepunching will be added.  And closed paths
    /// will be removed etc.
    #[debug("AddConnection(WeakConnectionHandle)")]
    AddConnection(WeakConnectionHandle),
    /// Adds a [`NodeAddr`] with locations where the node might be reachable.
    AddNodeAddr(NodeAddr, Source),
    /// Process a received DISCO CallMeMaybe message.
    CallMeMaybeReceived(disco::CallMeMaybe),
    /// Process a received DISCO Ping message.
    PingReceived(disco::Ping, transports::Addr),
    /// Process a received DISCO Pong message.
    PongReceived(disco::Pong, transports::Addr),
    /// Asks if there is any possible path that could be used.
    ///
    /// This does not mean there is any guarantee that the remote endpoint is reachable.
    #[debug("CanSend(onseshot::Sender<bool>)")]
    CanSend(oneshot::Sender<bool>),
    /// Returns the current latency to the remote endpoint.
    ///
    /// TODO: This is more of a placeholder message currently.  Check MagicSock::latency.
    Latency(oneshot::Sender<Option<Duration>>),
}

/// A handle to a [`NodeStateActor`].
///
/// Dropping this will stop the actor.
#[derive(Debug)]
pub(super) struct NodeStateHandle {
    pub(super) sender: mpsc::Sender<NodeStateMessage>,
    _task: AbortOnDropHandle<()>,
}

/// Information about a holepunch attempt.
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
    local_addrs: BTreeSet<SocketAddr>,
    /// The set of remote addresses which could take part in holepunching.
    ///
    /// Like `local_addrs` we may not have used them.
    remote_addrs: BTreeSet<SocketAddr>,
}

/// The type of connection we have to the endpoint.
#[derive(derive_more::Display, Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// Direct UDP connection
    #[display("direct({_0})")]
    Direct(SocketAddr),
    /// Relay connection over relay
    #[display("relay({_0})")]
    Relay(RelayUrl),
    /// Both a UDP and a relay connection are used.
    ///
    /// This is the case if we do have a UDP address, but are missing a recent confirmation that
    /// the address works.
    #[display("mixed(udp: {_0}, relay: {_1})")]
    Mixed(SocketAddr, RelayUrl),
    /// We have no verified connection to this PublicKey
    #[default]
    #[display("none")]
    None,
}
