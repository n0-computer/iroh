use std::{collections::BTreeSet, net::SocketAddr, pin::Pin, sync::Arc};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl};
use n0_future::{
    MergeUnbounded, Stream, StreamExt,
    task::AbortOnDropHandle,
    time::{Duration, Instant},
};
use n0_watcher::{Watchable, Watcher};
use quinn::WeakConnectionHandle;
use quinn_proto::{PathEvent, PathId, PathStatus};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Whatever};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::{Instrument, Level, debug, error, event, info_span, instrument, trace, warn};

use super::{Source, TransportsSenderMessage, path_state::PathState};
// TODO: Use this
// #[cfg(any(test, feature = "test-utils"))]
// use crate::endpoint::PathSelection;
use crate::{
    disco::{self},
    endpoint::DirectAddr,
    magicsock::{
        DiscoState, HEARTBEAT_INTERVAL, MagicsockMetrics, PATH_MAX_IDLE_TIMEOUT,
        mapped_addrs::{AddrMap, MappedAddr, MultipathMappedAddr, RelayMappedAddr},
        transports::{self, OwnedTransmit},
    },
    util::MaybeFuture,
};

// TODO: use this
// /// Number of addresses that are not active that we keep around per endpoint.
// ///
// /// See [`EndpointState::prune_direct_addresses`].
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

/// The state we need to know about a single remote endpoint.
///
/// This actor manages all connections to the remote endpoint.  It will trigger holepunching
/// and select the best path etc.
pub(super) struct EndpointStateActor {
    /// The endpoint ID of the remote endpoint.
    endpoint_id: EndpointId,
    /// The endpoint ID of the local endpoint.
    local_endpoint_id: EndpointId,

    // Hooks into the rest of the MagicSocket.
    //
    /// Metrics.
    metrics: Arc<MagicsockMetrics>,
    /// Allowing us to directly send datagrams.
    ///
    /// Used for handling [`EndpointStateMessage::SendDatagram`] messages.
    transports_sender: mpsc::Sender<TransportsSenderMessage>,
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
    /// Events emitted by Quinn about path changes.
    #[allow(clippy::type_complexity)]
    path_events: MergeUnbounded<
        Pin<
            Box<
                dyn Stream<Item = (ConnId, Result<PathEvent, BroadcastStreamRecvError>)>
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
    selected_path: Option<transports::Addr>,
    /// Time at which we should schedule the next holepunch attempt.
    scheduled_holepunch: Option<Instant>,
}

impl EndpointStateActor {
    pub(super) fn new(
        endpoint_id: EndpointId,
        local_endpoint_id: EndpointId,
        transports_sender: mpsc::Sender<TransportsSenderMessage>,
        local_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        disco: DiscoState,
        relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
        metrics: Arc<MagicsockMetrics>,
    ) -> Self {
        Self {
            endpoint_id,
            local_endpoint_id,
            metrics,
            transports_sender,
            local_addrs,
            relay_mapped_addrs,
            disco,
            connections: FxHashMap::default(),
            path_events: Default::default(),
            paths: FxHashMap::default(),
            last_holepunch: None,
            selected_path: None,
            scheduled_holepunch: None,
        }
    }

    pub(super) fn start(mut self) -> EndpointStateHandle {
        let (tx, rx) = mpsc::channel(16);
        let me = self.local_endpoint_id;
        let endpoint_id = self.endpoint_id;

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
                "EndpointStateActor",
                me = %me.fmt_short(),
                remote = %endpoint_id.fmt_short(),
            )),
        );
        EndpointStateHandle {
            sender: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

    /// Runs the main loop of the actor.
    ///
    /// Note that the actor uses async handlers for tasks from the main loop.  The actor is
    /// not processing items from the inbox while waiting on any async calls.  So some
    /// dicipline is needed to not turn pending for a long time.
    async fn run(
        &mut self,
        mut inbox: mpsc::Receiver<EndpointStateMessage>,
    ) -> Result<(), Whatever> {
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
                    self.handle_path_event(id, evt);
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

    /// Handles an actor message.
    ///
    /// Error returns are fatal and kill the actor.
    #[instrument(skip(self))]
    async fn handle_message(&mut self, msg: EndpointStateMessage) -> Result<(), Whatever> {
        // trace!("handling message");
        match msg {
            EndpointStateMessage::SendDatagram(transmit) => {
                self.handle_msg_send_datagram(transmit).await?;
            }
            EndpointStateMessage::AddConnection(handle, paths_info) => {
                self.handle_msg_add_connection(handle, paths_info).await;
            }
            EndpointStateMessage::AddEndpointAddr(addr, source) => {
                self.handle_msg_add_endpoint_addr(addr, source);
            }
            EndpointStateMessage::CallMeMaybeReceived(msg) => {
                self.handle_msg_call_me_maybe_received(msg).await;
            }
            EndpointStateMessage::PingReceived(ping, src) => {
                self.handle_msg_ping_received(ping, src).await;
            }
            EndpointStateMessage::PongReceived(pong, src) => {
                self.handle_msg_pong_received(pong, src);
            }
            EndpointStateMessage::CanSend(tx) => {
                self.handle_msg_can_send(tx);
            }
            EndpointStateMessage::Latency(tx) => {
                self.handle_msg_latency(tx);
            }
        }
        Ok(())
    }

    /// Handles [`EndpointStateMessage::SendDatagram`].
    ///
    /// Error returns are fatal and kill the actor.
    async fn handle_msg_send_datagram(&mut self, transmit: OwnedTransmit) -> Result<(), Whatever> {
        if let Some(ref addr) = self.selected_path {
            trace!(?addr, "sending datagram to selected path");
            self.transports_sender
                .send((addr.clone(), transmit).into())
                .await
                .whatever_context("TransportSenderActor stopped")?;
        } else {
            trace!(
                paths = ?self.paths.keys().collect::<Vec<_>>(),
                "sending datagram to all known paths",
            );
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
        Ok(())
    }

    /// Handles [`EndpointStateMessage::AddConnection`].
    ///
    /// Error returns are fatal and kill the actor.
    async fn handle_msg_add_connection(
        &mut self,
        handle: WeakConnectionHandle,
        paths_info: Watchable<Vec<PathInfo>>,
    ) {
        if let Some(conn) = handle.upgrade() {
            // Remove any conflicting stable_ids from the local state.
            let conn_id = ConnId(conn.stable_id());
            self.connections.remove(&conn_id);

            // This is a good time to clean up connections.
            self.cleanup_connections();

            // Store the connection and hook up paths events stream.
            let events = BroadcastStream::new(conn.path_events());
            let stream = events.map(move |evt| (conn_id, evt));
            self.path_events.push(Box::pin(stream));
            self.connections.insert(
                conn_id,
                ConnectionState {
                    handle: handle.clone(),
                    pub_path_info: paths_info,
                    paths: Default::default(),
                    open_paths: Default::default(),
                    path_ids: Default::default(),
                },
            );

            // Store PathId(0), set path_status and select best path, check if holepunching
            // is needed.
            if let Some(conn) = handle.upgrade() {
                if let Some(path) = conn.path(PathId::ZERO) {
                    if let Some(path_remote) = path
                        .remote_address()
                        .map_or(None, |remote| Some(MultipathMappedAddr::from(remote)))
                        .and_then(|mmaddr| mmaddr.to_transport_addr(&self.relay_mapped_addrs))
                    {
                        trace!(?path_remote, "added new connection");
                        let status = match path_remote {
                            transports::Addr::Ip(_) => PathStatus::Available,
                            transports::Addr::Relay(_, _) => PathStatus::Backup,
                        };
                        path.set_status(status).ok();
                        let conn_state =
                            self.connections.get_mut(&conn_id).expect("inserted above");
                        conn_state.add_open_path(path_remote.clone(), PathId::ZERO);
                        self.paths
                            .entry(path_remote)
                            .or_default()
                            .sources
                            .insert(Source::Connection, Instant::now());
                        self.select_path();
                    }
                }
                // TODO: Make sure we are adding the relay path if we're on a direct
                // path.
                self.trigger_holepunching().await;
            }
        }
    }

    /// Handles [`EndpointStateMessage::AddEndpointAddr`].
    fn handle_msg_add_endpoint_addr(&mut self, addr: EndpointAddr, source: Source) {
        for sockaddr in addr.direct_addresses {
            let addr = transports::Addr::from(sockaddr);
            self.paths
                .entry(addr)
                .or_default()
                .sources
                .insert(source.clone(), Instant::now());
        }
        if let Some(relay_url) = addr.relay_url {
            let addr = transports::Addr::from((relay_url, self.endpoint_id));
            self.paths
                .entry(addr)
                .or_default()
                .sources
                .insert(source, Instant::now());
        }
        trace!("added addressing information");
    }

    /// Handles [`EndpointStateMessage::CallMeMaybeReceived`].
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
            path.sources.insert(Source::CallMeMaybe, now);
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

    /// Handles [`EndpointStateMessage::PingReceived`].
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
        path.sources.insert(Source::Ping, Instant::now());

        trace!("ping received, triggering holepunching");
        self.trigger_holepunching().await;
    }

    /// Handles [`EndpointStateMessage::PongReceived`].
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

    /// Handles [`EndpointStateMessage::CanSend`].
    fn handle_msg_can_send(&self, tx: oneshot::Sender<bool>) {
        let can_send = !self.paths.is_empty();
        tx.send(can_send).ok();
    }

    /// Handles [`EndpointStateMessage::Latency`].
    fn handle_msg_latency(&self, tx: oneshot::Sender<Option<Duration>>) {
        let rtt = self.selected_path.as_ref().and_then(|addr| {
            for conn_state in self.connections.values() {
                let Some(path_id) = conn_state.path_ids.get(addr) else {
                    continue;
                };
                if !conn_state.open_paths.contains_key(path_id) {
                    continue;
                }
                if let Some(stats) = conn_state
                    .handle
                    .upgrade()
                    .and_then(|conn| conn.stats().paths.get(path_id).copied())
                {
                    return Some(stats.rtt);
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
                    .get(&Source::CallMeMaybe)
                    .map(|when| when.elapsed() <= CALL_ME_MAYBE_VALIDITY)
                    .unwrap_or_default()
                    || state
                        .sources
                        .get(&Source::Ping)
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
                    warn!(?ret, "Opening path failed");
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
            warn!("missed a PathEvent, EndpointStateActor lagging");
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

                if let Some(path_remote) = path
                    .remote_address()
                    .map_or(None, |remote| Some(MultipathMappedAddr::from(remote)))
                    .and_then(|mmaddr| mmaddr.to_transport_addr(&self.relay_mapped_addrs))
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
                        .insert(Source::Connection, Instant::now());
                    let mut paths = conn_state.pub_path_info.get();
                    paths.push(PathInfo {
                        transport: path_remote.into(),
                    });
                    conn_state.pub_path_info.set(paths).ok();
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
                // Remove this from the public PathInfo.
                if let Some(state) = self.connections.get(&conn_id) {
                    let mut path_info = state.pub_path_info.get();
                    let transport = TransportType::from(&path_remote);
                    let mut done = false;
                    path_info.retain(|info| {
                        if !done && info.transport == transport {
                            done = true;
                            false
                        } else {
                            true
                        }
                    });
                    state.pub_path_info.set(path_info).ok();
                }

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

    /// Clean up connections which no longer exist.
    // TODO: Call this on a schedule.
    fn cleanup_connections(&mut self) {
        self.connections.retain(|_, c| c.handle.upgrade().is_some());
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
        // TODO: Only consider paths that are actively open: that is we received the open
        // event and have not closed it yet, or have not received a close.  Otherwise we
        // might select from paths that doen't work.  Plus we might not have a
        // representative RTT time yet.

        // Find the lowest RTT across all connections for each open path.  The long way, so
        // we get to log *all* RTTs.
        let mut all_path_rtts: FxHashMap<transports::Addr, Vec<Duration>> = FxHashMap::default();
        for (conn_id, conn_state) in self.connections.iter() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            let stats = conn.stats();
            for (path_id, stats) in stats.paths {
                if let Some(addr) = conn_state.open_paths.get(&path_id) {
                    all_path_rtts
                        .entry(addr.clone())
                        .or_default()
                        .push(stats.rtt);
                } else {
                    trace!(?conn_id, ?path_id, "unknown PathId in ConnectionStats");
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
            .min()
            .map(|(_rtt, addr)| addr.clone());
        let selected_path = direct_path.or_else(|| {
            // Find the fasted relay path.
            path_rtts
                .iter()
                .filter(|(addr, _rtt)| addr.is_relay())
                .map(|(addr, rtt)| (rtt, addr))
                .min()
                .map(|(_rtt, addr)| addr.clone())
        });
        if let Some(addr) = selected_path {
            let prev = self.selected_path.replace(addr.clone());
            if prev.as_ref() != Some(&addr) {
                debug!(?addr, ?prev, "selected new path");
            }
            self.open_path(&addr);
            self.close_redundant_paths(&addr);
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
        debug_assert_eq!(self.selected_path.as_ref(), Some(selected_path));

        for (conn_id, conn_state) in self.connections.iter() {
            for (path_id, path_remote) in conn_state.paths.iter() {
                if path_remote.is_relay() {
                    continue;
                }
                if path_remote == selected_path {
                    continue; // Do not close the selected path.
                }
                if conn_state.open_paths.contains_key(path_id) && conn_state.open_paths.len() <= 1 {
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

/// Messages to send to the [`EndpointStateActor`].
#[derive(derive_more::Debug)]
pub(crate) enum EndpointStateMessage {
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
    AddConnection(WeakConnectionHandle, Watchable<Vec<PathInfo>>),
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

/// A handle to a [`EndpointStateActor`].
///
/// Dropping this will stop the actor.
#[derive(Debug)]
pub(super) struct EndpointStateHandle {
    pub(super) sender: mpsc::Sender<EndpointStateMessage>,
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

/// Newtype to track Connections.
///
/// The wrapped value is the [`Connection::stable_id`] value, and is thus only valid for
/// active connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnId(usize);

/// State about one connection.
#[derive(Debug)]
struct ConnectionState {
    /// Weak handle to the connection.
    handle: WeakConnectionHandle,
    /// The information we publish to users about the paths used in this connection.
    // TODO: Improve this.  Use a map of TransportAddr once that's merged.  Handle the logic
    //    in a method on this struct.
    pub_path_info: Watchable<Vec<PathInfo>>,
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
    }
}

/// Information about a network path used by a [`Connection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    /// The kind of transport this network path is using.
    pub transport: TransportType,
}

/// Different kinds of transports a [`Connection`] can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportType {
    /// A transport via a relay server.
    Relay,
    /// A transport via an IP connection.
    Ip,
}

impl From<MultipathMappedAddr> for TransportType {
    fn from(source: MultipathMappedAddr) -> Self {
        match source {
            MultipathMappedAddr::Mixed(_) => {
                error!("paths should not use mixed addrs");
                TransportType::Relay
            }
            MultipathMappedAddr::Relay(_) => TransportType::Relay,
            MultipathMappedAddr::Ip(_) => TransportType::Ip,
        }
    }
}

impl From<transports::Addr> for TransportType {
    fn from(source: transports::Addr) -> Self {
        match source {
            transports::Addr::Ip(_) => Self::Ip,
            transports::Addr::Relay(_, _) => Self::Relay,
        }
    }
}

impl From<&transports::Addr> for TransportType {
    fn from(source: &transports::Addr) -> Self {
        match source {
            transports::Addr::Ip(_) => Self::Ip,
            transports::Addr::Relay(_, _) => Self::Relay,
        }
    }
}

/// Poll a future once, like n0_future::future::poll_once but sync.
fn now_or_never<T, F: Future<Output = T>>(fut: F) -> Option<T> {
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(res) => Some(res),
        std::task::Poll::Pending => None,
    }
}
