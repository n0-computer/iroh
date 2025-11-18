use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use n0_future::{
    FuturesUnordered, MergeUnbounded, Stream, StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::{Watchable, Watcher};
use quinn::{PathStats, WeakConnectionHandle};
use quinn_proto::{PathError, PathEvent, PathId, PathStatus};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tokio::sync::oneshot;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::{Instrument, Level, debug, error, event, info_span, instrument, trace, warn};

use self::{
    guarded_channel::{GuardedReceiver, GuardedSender, guarded_channel},
    path_state::PathState,
};
use super::Source;
use crate::{
    disco::{self},
    endpoint::DirectAddr,
    magicsock::{
        DiscoState, HEARTBEAT_INTERVAL, MagicsockMetrics, PATH_MAX_IDLE_TIMEOUT,
        mapped_addrs::{AddrMap, MappedAddr, RelayMappedAddr},
        remote_map::Private,
        transports::{self, OwnedTransmit, TransportsSender},
    },
    util::MaybeFuture,
};

mod guarded_channel;
mod path_state;

// TODO: use this
// /// Number of addresses that are not active that we keep around per endpoint.
// ///
// /// See [`RemoteState::prune_direct_addresses`].
// pub(super) const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 20;

// TODO: use this
// /// How long since an endpoint path was last alive before it might be pruned.
// const LAST_ALIVE_PRUNE_DURATION: Duration = Duration::from_secs(120);

// TODO: use this
// /// The latency at or under which we don't try to upgrade to a better path.
// const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

// TODO: use this
// /// How long since the last activity we try to keep an established endpoint peering alive.
// ///
// /// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
// pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

// TODO: use this
// /// How often we try to upgrade to a better path.
// ///
// /// Even if we have some non-relay route that works.
// const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// The value which we close paths.
// TODO: Quinn should just do this.  Also, I made this value up.
const APPLICATION_ABANDON_PATH: u8 = 30;

/// The time after which an idle [`RemoteStateActor`] stops.
///
/// The actor only enters the idle state if no connections are active and no inbox senders exist
/// apart from the one stored in the endpoint map. Stopping and restarting the actor in this state
/// is not an issue; a timeout here serves the purpose of not stopping-and-recreating actors
/// in a high frequency, and to keep data about previous path around for subsequent connections.
const ACTOR_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// A stream of events from all paths for all connections.
///
/// The connection is identified using [`ConnId`].  The event `Err` variant happens when the
/// actor has lagged processing the events, which is rather critical for us.
type PathEvents = MergeUnbounded<
    Pin<
        Box<dyn Stream<Item = (ConnId, Result<PathEvent, BroadcastStreamRecvError>)> + Send + Sync>,
    >,
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

    // Hooks into the rest of the MagicSocket.
    //
    /// Metrics.
    metrics: Arc<MagicsockMetrics>,
    sender: TransportsSender,
    /// Our local addresses.
    ///
    /// These are our local addresses and any reflexive transport addresses.
    local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    /// Shared state to allow to encrypt DISCO messages to peers.
    disco: DiscoState,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,

    // Internal state - Quinn Connections we are managing.
    //
    /// All connections we have to this remote endpoint.
    connections: FxHashMap<ConnId, ConnectionState>,
    /// Notifications when connections are closed.
    connections_close: FuturesUnordered<OnClosed>,
    /// Events emitted by Quinn about path changes, for all paths, all connections.
    path_events: PathEvents,

    // Internal state - Holepunching and path state.
    //
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by discovery
    /// mechanisms.  The are only potentially usable.
    paths: FxHashMap<transports::Addr, PathState>,
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
}

impl RemoteStateActor {
    pub(super) fn new(
        endpoint_id: EndpointId,
        local_endpoint_id: EndpointId,
        local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        disco: DiscoState,
        relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
        metrics: Arc<MagicsockMetrics>,
        sender: TransportsSender,
    ) -> Self {
        Self {
            endpoint_id,
            local_endpoint_id,
            metrics,
            local_addrs,
            relay_mapped_addrs,
            disco,
            connections: FxHashMap::default(),
            connections_close: Default::default(),
            path_events: Default::default(),
            paths: FxHashMap::default(),
            last_holepunch: None,
            selected_path: Default::default(),
            scheduled_holepunch: None,
            scheduled_open_path: None,
            pending_open_paths: VecDeque::new(),
            sender,
        }
    }

    pub(super) fn start(self) -> RemoteStateHandle {
        let (tx, rx) = guarded_channel(16);
        let me = self.local_endpoint_id;
        let endpoint_id = self.endpoint_id;

        // Ideally we'd use the endpoint span as parent.  We'd have to plug that span into
        // here somehow.  Instead we have no parent and explicitly set the me attribute.  If
        // we don't explicitly set a span we get the spans from whatever call happens to
        // first create the actor, which is often very confusing as it then keeps those
        // spans for all logging of the actor.
        let task = task::spawn(self.run(rx).instrument(info_span!(
            parent: None,
            "RemoteStateActor",
            me = %me.fmt_short(),
            remote = %endpoint_id.fmt_short(),
        )));
        RemoteStateHandle {
            sender: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

    /// Runs the main loop of the actor.
    ///
    /// Note that the actor uses async handlers for tasks from the main loop.  The actor is
    /// not processing items from the inbox while waiting on any async calls.  So some
    /// discipline is needed to not turn pending for a long time.
    async fn run(mut self, mut inbox: GuardedReceiver<RemoteStateMessage>) {
        trace!("actor started");
        let idle_timeout = MaybeFuture::None;
        tokio::pin!(idle_timeout);
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
            tokio::select! {
                biased;
                msg = inbox.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg).await,
                        None => break,
                    }
                }
                Some((id, evt)) = self.path_events.next() => {
                    self.handle_path_event(id, evt);
                }
                Some(conn_id) = self.connections_close.next(), if !self.connections_close.is_empty() => {
                    self.connections.remove(&conn_id);
                    if self.connections.is_empty() {
                        trace!("last connection closed - clearing selected_path");
                        self.selected_path.set(None).ok();
                    }
                }
                _ = self.local_addrs.updated(), if self.local_addrs.is_connected() => {
                    trace!("local addrs updated, triggering holepunching");
                    self.trigger_holepunching().await;
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
                    self.trigger_holepunching().await;
                }
                _ = &mut idle_timeout => {
                    if self.connections.is_empty() && inbox.close_if_idle() {
                        trace!("idle timeout expired and still idle: terminate actor");
                        break;
                    }
                }
            }

            let is_idle = self.connections.is_empty() && inbox.is_idle();
            if idle_timeout.is_none() && is_idle {
                trace!("start idle timeout");
                idle_timeout
                    .as_mut()
                    .set_future(time::sleep(ACTOR_MAX_IDLE_TIMEOUT));
            } else if idle_timeout.is_some() && !is_idle {
                trace!("abort idle timeout");
                idle_timeout.as_mut().set_none()
            }
        }
        trace!("actor terminating");
    }

    /// Handles an actor message.
    ///
    /// Error returns are fatal and kill the actor.
    #[instrument(skip(self))]
    async fn handle_message(&mut self, msg: RemoteStateMessage) {
        // trace!("handling message");
        match msg {
            RemoteStateMessage::SendDatagram(transmit) => {
                if let Err(err) = self.handle_msg_send_datagram(transmit).await {
                    warn!("failed to send datagram: {err:#}");
                }
            }
            RemoteStateMessage::AddConnection(handle, tx) => {
                self.handle_msg_add_connection(handle, tx).await;
            }
            RemoteStateMessage::AddEndpointAddr(addr, source) => {
                self.handle_msg_add_endpoint_addr(addr, source);
            }
            RemoteStateMessage::CallMeMaybeReceived(msg) => {
                self.handle_msg_call_me_maybe_received(msg).await;
            }
            RemoteStateMessage::PingReceived(ping, src) => {
                self.handle_msg_ping_received(ping, src).await;
            }
            RemoteStateMessage::PongReceived(pong, src) => {
                self.handle_msg_pong_received(pong, src);
            }
            RemoteStateMessage::CanSend(tx) => {
                self.handle_msg_can_send(tx);
            }
            RemoteStateMessage::Latency(tx) => {
                self.handle_msg_latency(tx);
            }
        }
    }

    async fn send_datagram(
        &self,
        dst: transports::Addr,
        owned_transmit: OwnedTransmit,
    ) -> n0_error::Result<()> {
        // TODO(Frando): Demote to trace or remove.
        debug!(?dst, "send datagram");
        let transmit = transports::Transmit {
            ecn: owned_transmit.ecn,
            contents: owned_transmit.contents.as_ref(),
            segment_size: owned_transmit.segment_size,
        };
        self.sender.send(&dst, None, &transmit).await?;
        Ok(())
    }

    /// Handles [`RemoteStateMessage::SendDatagram`].
    ///
    /// Error returns are fatal and kill the actor.
    async fn handle_msg_send_datagram(&mut self, transmit: OwnedTransmit) -> n0_error::Result<()> {
        if let Some(addr) = self.selected_path.get() {
            trace!(?addr, "sending datagram to selected path");
            self.send_datagram(addr, transmit).await?;
        } else {
            trace!(
                paths = ?self.paths.keys().collect::<Vec<_>>(),
                "sending datagram to all known paths",
            );
            for addr in self.paths.keys() {
                self.send_datagram(addr.clone(), transmit.clone()).await?;
            }
            // This message is received *before* a connection is added.  So we do
            // not yet have a connection to holepunch.  Instead we trigger
            // holepunching when AddConnection is received.
        }
        Ok(())
    }

    /// Handles [`RemoteStateMessage::AddConnection`].
    ///
    /// Error returns are fatal and kill the actor.
    async fn handle_msg_add_connection(
        &mut self,
        handle: WeakConnectionHandle,
        tx: oneshot::Sender<PathsWatcher>,
    ) {
        let pub_open_paths = Watchable::default();
        if let Some(conn) = handle.upgrade() {
            // Remove any conflicting stable_ids from the local state.
            let conn_id = ConnId(conn.stable_id());
            self.connections.remove(&conn_id);

            // Store the connection and hook up paths events stream.
            let events = BroadcastStream::new(conn.path_events());
            let stream = events.map(move |evt| (conn_id, evt));
            self.path_events.push(Box::pin(stream));
            self.connections_close.push(OnClosed::new(&conn));
            let conn_state = self
                .connections
                .entry(conn_id)
                .insert_entry(ConnectionState {
                    handle: handle.clone(),
                    pub_open_paths: pub_open_paths.clone(),
                    paths: Default::default(),
                    open_paths: Default::default(),
                    path_ids: Default::default(),
                })
                .into_mut();

            // Store PathId(0), set path_status and select best path, check if holepunching
            // is needed.
            if let Some(path) = conn.path(PathId::ZERO)
                && let Ok(socketaddr) = path.remote_address()
                && let Some(path_remote) = self.relay_mapped_addrs.to_transport_addr(socketaddr)
            {
                trace!(?path_remote, "added new connection");
                let path_remote_is_ip = path_remote.is_ip();
                let status = match path_remote {
                    transports::Addr::Ip(_) => PathStatus::Available,
                    transports::Addr::Relay(_, _) => PathStatus::Backup,
                };
                path.set_status(status).ok();
                conn_state.add_open_path(path_remote.clone(), PathId::ZERO);
                self.paths
                    .entry(path_remote)
                    .or_default()
                    .sources
                    .insert(Source::Connection { _0: Private }, Instant::now());
                self.select_path();

                if path_remote_is_ip {
                    // We may have raced this with a relay address.  Try and add any
                    // relay addresses we have back.
                    let relays = self
                        .paths
                        .keys()
                        .filter(|a| a.is_relay())
                        .cloned()
                        .collect::<Vec<_>>();
                    for remote in relays {
                        self.open_path(&remote);
                    }
                }
            }
            self.trigger_holepunching().await;
        }
        tx.send(PathsWatcher::new(
            pub_open_paths.watch(),
            self.selected_path.watch(),
            handle,
        ))
        .ok();
    }

    /// Handles [`RemoteStateMessage::AddEndpointAddr`].
    fn handle_msg_add_endpoint_addr(&mut self, addr: EndpointAddr, source: Source) {
        for sockaddr in addr.ip_addrs() {
            let addr = transports::Addr::from(sockaddr);
            self.paths
                .entry(addr)
                .or_default()
                .sources
                .insert(source.clone(), Instant::now());
        }
        for relay_url in addr.relay_urls() {
            let addr = transports::Addr::from((relay_url.clone(), self.endpoint_id));
            self.paths
                .entry(addr)
                .or_default()
                .sources
                .insert(source.clone(), Instant::now());
        }
        trace!("added addressing information");
    }

    /// Handles [`RemoteStateMessage::CallMeMaybeReceived`].
    async fn handle_msg_call_me_maybe_received(&mut self, msg: disco::CallMeMaybe) {
        event!(
            target: "iroh::_events::call_me_maybe::recv",
            Level::DEBUG,
            remote = %self.endpoint_id.fmt_short(),
            addrs = ?msg.my_numbers,
        );
        let now = Instant::now();
        for addr in msg.my_numbers {
            let dst = transports::Addr::Ip(addr);
            let ping = disco::Ping::new(self.local_endpoint_id);

            let path = self.paths.entry(dst.clone()).or_default();
            path.sources
                .insert(Source::CallMeMaybe { _0: Private }, now);
            path.ping_sent = Some(ping.tx_id);

            event!(
                target: "iroh::_events::ping::sent",
                Level::DEBUG,
                remote = %self.endpoint_id.fmt_short(),
                ?dst,
            );
            self.send_disco_message(dst, disco::Message::Ping(ping))
                .await;
        }
    }

    /// Handles [`RemoteStateMessage::PingReceived`].
    async fn handle_msg_ping_received(&mut self, ping: disco::Ping, src: transports::Addr) {
        let transports::Addr::Ip(addr) = src else {
            warn!("received ping via relay transport, ignored");
            return;
        };
        event!(
            target: "iroh::_events::ping::recv",
            Level::DEBUG,
            remote = %self.endpoint_id.fmt_short(),
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
            remote = %self.endpoint_id.fmt_short(),
            dst = ?src,
            txn = ?pong.tx_id,
        );
        self.send_disco_message(src.clone(), disco::Message::Pong(pong))
            .await;

        let path = self.paths.entry(src).or_default();
        path.sources
            .insert(Source::Ping { _0: Private }, Instant::now());

        trace!("ping received, triggering holepunching");
        self.trigger_holepunching().await;
    }

    /// Handles [`RemoteStateMessage::PongReceived`].
    fn handle_msg_pong_received(&mut self, pong: disco::Pong, src: transports::Addr) {
        let Some(state) = self.paths.get(&src) else {
            warn!(path = ?src, ?self.paths, "ignoring DISCO Pong for unknown path");
            return;
        };
        if state.ping_sent != Some(pong.tx_id) {
            debug!(path = ?src, ?state.ping_sent, pong_tx = ?pong.tx_id,
                        "ignoring unknown DISCO Pong for path");
            return;
        }
        event!(
            target: "iroh::_events::pong::recv",
            Level::DEBUG,
            remote_endpoint = %self.endpoint_id.fmt_short(),
            ?src,
            txn = ?pong.tx_id,
        );

        self.open_path(&src);
    }

    /// Handles [`RemoteStateMessage::CanSend`].
    fn handle_msg_can_send(&self, tx: oneshot::Sender<bool>) {
        let can_send = !self.paths.is_empty();
        tx.send(can_send).ok();
    }

    /// Handles [`RemoteStateMessage::Latency`].
    fn handle_msg_latency(&self, tx: oneshot::Sender<Option<Duration>>) {
        let rtt = self.selected_path.get().and_then(|addr| {
            for conn_state in self.connections.values() {
                let Some(path_id) = conn_state.path_ids.get(&addr) else {
                    continue;
                };
                if !conn_state.open_paths.contains_key(path_id) {
                    continue;
                }
                if let Some(rtt) = conn_state
                    .handle
                    .upgrade()
                    .and_then(|conn| conn.path_stats(*path_id).map(|stats| stats.rtt))
                {
                    return Some(rtt);
                }
            }
            None
        });
        tx.send(rtt).ok();
    }

    /// Triggers holepunching to the remote endpoint.
    ///
    /// This will manage the entire process of holepunching with the remote endpoint.
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
            .get()
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
                trace!(?last_hp, ?local_addrs, ?remote_addrs, "addrs to holepunch?");
                !remote_addrs.is_subset(&last_hp.remote_addrs)
                    || !local_addrs.is_subset(&last_hp.local_addrs)
            })
            .unwrap_or(true);
        if !new_addrs {
            if let Some(ref last_hp) = self.last_holepunch {
                let next_hp = last_hp.when + HOLEPUNCH_ATTEMPTS_INTERVAL;
                let now = Instant::now();
                if next_hp > now {
                    trace!(scheduled_in = ?(next_hp - now), "not holepunching: no new addresses");
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
                    .get(&Source::CallMeMaybe { _0: Private })
                    .map(|when| when.elapsed() <= CALL_ME_MAYBE_VALIDITY)
                    .unwrap_or_default()
                    || state
                        .sources
                        .get(&Source::Ping { _0: Private })
                        .map(|when| when.elapsed() <= CALL_ME_MAYBE_VALIDITY)
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
    #[instrument(skip_all)]
    async fn do_holepunching(&mut self) {
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
            let msg = disco::Ping::new(self.local_endpoint_id);
            event!(
                target: "iroh::_events::ping::sent",
                Level::DEBUG,
                remote = %self.endpoint_id.fmt_short(),
                ?dst,
                txn = ?msg.tx_id,
            );
            let addr = transports::Addr::Ip(*dst);
            self.paths.entry(addr.clone()).or_default().ping_sent = Some(msg.tx_id);
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
            target: "iroh::_events::call_me_maybe::sent",
            Level::DEBUG,
            remote = %self.endpoint_id.fmt_short(),
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

    /// Sends a DISCO message to the remote endpoint this actor manages.
    #[instrument(skip(self), fields(remote = %self.endpoint_id.fmt_short()))]
    async fn send_disco_message(&self, dst: transports::Addr, msg: disco::Message) {
        let pkt = self.disco.encode_and_seal(self.endpoint_id, &msg);
        let transmit = transports::OwnedTransmit {
            ecn: None,
            contents: pkt,
            segment_size: None,
        };
        let counter = match dst {
            transports::Addr::Ip(_) => &self.metrics.send_disco_udp,
            transports::Addr::Relay(_, _) => &self.metrics.send_disco_relay,
        };
        match self.send_datagram(dst, transmit).await {
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
            transports::Addr::Relay(relay_url, eid) => self
                .relay_mapped_addrs
                .get(&(relay_url.clone(), *eid))
                .private_socket_addr(),
        };

        for (conn_id, conn_state) in self.connections.iter_mut() {
            if conn_state.path_ids.contains_key(open_addr) {
                continue;
            }
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            if conn.side().is_server() {
                continue;
            }
            let fut = conn.open_path_ensure(quic_addr, path_status);
            match fut.path_id() {
                Some(path_id) => {
                    trace!(?conn_id, ?path_id, "opening new path");
                    conn_state.add_path(open_addr.clone(), path_id);
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
                // TODO: We configure this as defaults when we setup the endpoint, do we
                //    really need to duplicate this?
                path.set_keep_alive_interval(Some(HEARTBEAT_INTERVAL)).ok();
                path.set_max_idle_timeout(Some(PATH_MAX_IDLE_TIMEOUT)).ok();

                if let Ok(socketaddr) = path.remote_address()
                    && let Some(path_remote) = self.relay_mapped_addrs.to_transport_addr(socketaddr)
                {
                    event!(
                        target: "iroh::_events::path::open",
                        Level::DEBUG,
                        remote = %self.endpoint_id.fmt_short(),
                        ?path_remote,
                        ?conn_id,
                        ?path_id,
                    );
                    conn_state.add_open_path(path_remote.clone(), path_id);
                    self.paths
                        .entry(path_remote.clone())
                        .or_default()
                        .sources
                        .insert(Source::Connection { _0: Private }, Instant::now());
                }

                self.select_path();
            }
            PathEvent::Abandoned { id, path_stats } => {
                trace!(?path_stats, "path abandoned");
                // This is the last event for this path.
                conn_state.remove_path(&id);
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
                        trace!(?path_remote, ?conn_id, ?path_id, "closing path");
                        if let Err(err) = path.close(APPLICATION_ABANDON_PATH.into()) {
                            trace!(
                                ?path_remote,
                                ?conn_id,
                                ?path_id,
                                "path close failed: {err:#}"
                            );
                        }
                    }
                }
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

        // Find the fastest direct or relay path.
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
            .min();
        let selected_path = direct_path.or_else(|| {
            // Find the fasted relay path.
            path_rtts
                .iter()
                .filter(|(addr, _rtt)| addr.is_relay())
                .map(|(addr, rtt)| (*rtt, addr))
                .min()
        });
        if let Some((rtt, addr)) = selected_path {
            let prev = self.selected_path.set(Some(addr.clone()));
            if prev.is_ok() {
                debug!(?addr, ?rtt, ?prev, "selected new path");
            }
            self.open_path(addr);
            self.close_redundant_paths(addr);
        }
    }

    /// Closes any direct paths not selected.
    ///
    /// Makes sure not to close the last direct path.  Relay paths are never closed
    /// currently, because we only have one relay path at this time.
    // TODO: Need to handle this on a timer as well probably.  In .select_path() we open new
    //    paths and immediately call this.  But the new paths are probably not yet open on
    //    all connections.
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
                    .and_then(|conn| conn.path(*path_id))
                {
                    trace!(?path_remote, ?conn_id, ?path_id, "closing direct path");
                    match path.close(APPLICATION_ABANDON_PATH.into()) {
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
    SendDatagram(OwnedTransmit),
    /// Adds an active connection to this remote endpoint.
    ///
    /// The connection will now be managed by this actor.  Holepunching will happen when
    /// needed, any new paths discovered via holepunching will be added.  And closed paths
    /// will be removed etc.
    #[debug("AddConnection(..)")]
    AddConnection(WeakConnectionHandle, oneshot::Sender<PathsWatcher>),
    /// Adds a [`EndpointAddr`] with locations where the endpoint might be reachable.
    AddEndpointAddr(EndpointAddr, Source),
    /// Process a received DISCO CallMeMaybe message.
    CallMeMaybeReceived(disco::CallMeMaybe),
    /// Process a received DISCO Ping message.
    #[debug("PingReceived({:?}, src: {_1:?})", _0.tx_id)]
    PingReceived(disco::Ping, transports::Addr),
    /// Process a received DISCO Pong message.
    #[debug("PongReceived({:?}, src: {_1:?})", _0.tx_id)]
    PongReceived(disco::Pong, transports::Addr),
    /// Asks if there is any possible path that could be used.
    ///
    /// This does not mean there is any guarantee that the remote endpoint is reachable.
    #[debug("CanSend(..)")]
    CanSend(oneshot::Sender<bool>),
    /// Returns the current latency to the remote endpoint.
    ///
    /// TODO: This is more of a placeholder message currently.  Check MagicSock::latency.
    #[debug("Latency(..)")]
    Latency(oneshot::Sender<Option<Duration>>),
}

/// A handle to a [`RemoteStateActor`].
///
/// Dropping this will stop the actor. The actor will also stop after an idle timeout
/// if it has no connections, an empty inbox, and no other senders than the one stored
/// in the endpoint map exist.
#[derive(Debug)]
pub(super) struct RemoteStateHandle {
    /// Sender for the channel into the [`RemoteStateActor`].
    ///
    /// This is a [`GuardedSender`], from which we can get a sender but only if the receiver
    /// hasn't been closed.
    pub(super) sender: GuardedSender<RemoteStateMessage>,
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

/// Newtype to track Connections.
///
/// The wrapped value is the [`quinn::Connection::stable_id`] value, and is thus only valid
/// for active connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

impl ConnectionState {
    /// Tracks a path for the connection.
    fn add_path(&mut self, remote: transports::Addr, path_id: PathId) {
        self.paths.insert(path_id, remote.clone());
        self.path_ids.insert(remote, path_id);
    }

    /// Tracks an open path for the connection.
    fn add_open_path(&mut self, remote: transports::Addr, path_id: PathId) {
        self.paths.insert(path_id, remote.clone());
        self.open_paths.insert(path_id, remote.clone());
        self.path_ids.insert(remote, path_id);

        self.update_pub_path_info();
    }

    /// Completely removes a path from this connection.
    fn remove_path(&mut self, path_id: &PathId) {
        if let Some(addr) = self.paths.remove(path_id) {
            self.path_ids.remove(&addr);
        }
        self.open_paths.remove(path_id);
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
