//! The relay actor.
//!
//! The [`RelayActor`] handles all the relay connections.  It is helped by the
//! [`ActiveRelayActor`] which handles a single relay connection.

#[cfg(test)]
use std::net::SocketAddr;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Context;
use backoff::backoff::Backoff;
use bytes::{Bytes, BytesMut};
use futures_buffered::FuturesUnorderedBounded;
use futures_lite::StreamExt;
use iroh_base::{NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_metrics::{inc, inc_by};
use iroh_relay::{
    self as relay,
    client::{ClientError, ReceivedMessage},
    MAX_PACKET_SIZE,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{self, Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use url::Url;

use super::RelayDatagramSendChannelReceiver;
use crate::{
    dns::DnsResolver,
    magicsock::{MagicSock, Metrics as MagicsockMetrics, RelayContents, RelayDatagramRecvQueue},
    util::MaybeFuture,
};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// Maximum size a datagram payload is allowed to be.
const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - PublicKey::LENGTH;

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
#[derive(Debug)]
struct ActiveRelayActor {
    /// Queue to send received relay datagrams on.
    relay_datagrams_recv: Arc<RelayDatagramRecvQueue>,
    /// Channel on which we receive packets to send to the relay.
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    url: RelayUrl,
    /// Whether or not this is the home relay connection.
    is_home_relay: bool,
    /// Configuration to establish connections to a relay server.
    relay_connection_opts: RelayConnectionOptions,
    relay_client: relay::client::Client,
    /// The set of remote nodes we know are present on this relay server.
    ///
    /// If we receive messages from a remote node via, this server it is added to this set.
    /// If the server notifies us this node is gone, it is removed from this set.
    node_present: BTreeSet<NodeId>,
    backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock>,
    last_packet_time: Option<Instant>,
    last_packet_src: Option<NodeId>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ActiveRelayMessage {
    /// Returns whether or not this relay can reach the NodeId.
    HasNodeRoute(NodeId, oneshot::Sender<bool>),
    /// Triggers a connection check to the relay server.
    ///
    /// Sometimes it is known the local network interfaces have changed in which case it
    /// might be prudent to check if the relay connection is still working.  `Vec<IpAddr>`
    /// should contain the current local IP addresses.  If the connection uses a local
    /// socket with an IP address in this list the relay server will be pinged.  If the
    /// connection uses a local socket with an IP address not in this list the server will
    /// always re-connect.
    CheckConnection(Vec<IpAddr>),
    /// Sets this relay as the home relay, or not.
    SetHomeRelay(bool),
    Shutdown,
    #[cfg(test)]
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
struct ActiveRelayActorOptions {
    url: RelayUrl,
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    relay_datagrams_recv: Arc<RelayDatagramRecvQueue>,
    connection_opts: RelayConnectionOptions,
}

/// Configuration needed to create a connection to a relay server.
#[derive(Debug, Clone)]
struct RelayConnectionOptions {
    secret_key: SecretKey,
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_cert_verify: bool,
}

impl ActiveRelayActor {
    fn new(opts: ActiveRelayActorOptions) -> Self {
        let ActiveRelayActorOptions {
            url,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts,
        } = opts;
        let relay_client = Self::create_relay_client(url.clone(), connection_opts.clone());

        ActiveRelayActor {
            relay_datagrams_recv,
            relay_datagrams_send,
            url,
            is_home_relay: false,
            node_present: BTreeSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
            relay_connection_opts: connection_opts,
            relay_client,
        }
    }

    fn create_relay_client(url: RelayUrl, opts: RelayConnectionOptions) -> relay::client::Client {
        let RelayConnectionOptions {
            secret_key,
            dns_resolver,
            proxy_url,
            prefer_ipv6,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify,
        } = opts;
        let mut builder = relay::client::ClientBuilder::new(url)
            .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }
        #[cfg(any(test, feature = "test-utils"))]
        let builder = builder.insecure_skip_cert_verify(insecure_skip_cert_verify);
        builder.build(secret_key, dns_resolver)
    }

    async fn run(mut self, mut inbox: mpsc::Receiver<ActiveRelayMessage>) -> anyhow::Result<()> {
        inc!(MagicsockMetrics, num_relay_conns_added);
        debug!("initial dial {}", self.url);
        self.relay_client
            .connect()
            .await
            .context("initial connection")?;

        let mut ping_future = std::pin::pin!(MaybeFuture::none());

        // If inactive for one tick the actor should exit.  Inactivity is only tracked on
        // the last datagrams sent to the relay, received datagrams will trigger ACKs which
        // is sufficient to keep active connections open.
        let mut inactive_timeout = tokio::time::interval(RELAY_INACTIVE_CLEANUP_TIME);
        inactive_timeout.reset(); // skip immediate tick

        loop {
            // If a read error occurred on the connection it might have been lost.  But we
            // need this connection to stay alive so we can receive more messages sent by
            // peers via the relay even if we don't start sending again first.
            if !self.relay_client.is_connected() {
                debug!("relay re-connecting");
                self.relay_client.connect().await.context("keepalive")?;
            }
            tokio::select! {
                msg = inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("all clients closed");
                        break;
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_preferred) => {
                            self.is_home_relay = is_preferred;
                            self.relay_client.note_preferred(is_preferred).await;
                        }
                        ActiveRelayMessage::HasNodeRoute(peer, r) => {
                            let has_peer = self.node_present.contains(&peer);
                            r.send(has_peer).ok();
                        }
                        ActiveRelayMessage::CheckConnection(local_ips) => {
                            if let Some(fut) = self.handle_check_connection(local_ips).await {
                                if ping_future.is_none() {
                                    ping_future.as_mut().set_future(fut);
                                }
                            }
                        }
                        ActiveRelayMessage::Shutdown => {
                            debug!("shutdown");
                            break;
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            let addr = self.relay_client.local_addr();
                            sender.send(addr).ok();
                        }
                    }
                }
                // Poll for pings
                ping_res = &mut ping_future, if ping_future.is_some() => {
                    ping_future.as_mut().set_none();
                    match ping_res {
                        Ok(latency) => {
                            debug!(?latency, "Still connected.");
                        }
                        Err(err) => {
                            debug!(?err, "Ping failed, reconnecting.");
                            self.reconnect().await;
                        }
                    }
                }
                Some(item) = self.relay_datagrams_send.recv() => {
                    debug_assert_eq!(item.url, self.url);
                    let dur = Duration::from_millis(500); // TODO: constant, and better value
                    match tokio::time::timeout(dur, self.send_relay(item)).await {
                        Ok(_) => {
                            inactive_timeout.reset();
                        }
                        Err(_) => {
                            warn!("relay sending timed out");
                        }
                    }
                }
                msg = self.relay_client.recv() => {
                    trace!("tick: relay_client_receiver");
                    if self.handle_relay_msg(msg).await == ReadResult::Break {
                        // fatal error
                        break;
                    }
                }
                _ = inactive_timeout.tick() => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting");
                    break;
                }
            }
        }
        debug!("exiting");
        self.relay_client.close().await;
        inc!(MagicsockMetrics, num_relay_conns_removed);
        Ok(())
    }

    /// Checks if the current relay connection is fine or needs reconnecting.
    ///
    /// If the local IP address of the current relay connection is in `local_ips` then this
    /// pings the relay, recreating the connection on ping failure.  Otherwise it always
    /// recreates the connection.
    async fn handle_check_connection(
        &mut self,
        local_ips: Vec<IpAddr>,
    ) -> Option<impl Future<Output = std::result::Result<Duration, ClientError>>> {
        match self.relay_client.local_addr() {
            Some(local_addr) if local_ips.contains(&local_addr.ip()) => {
                match self.relay_client.start_ping().await {
                    Ok(fut) => {
                        return Some(fut);
                    }
                    Err(err) => {
                        debug!(?err, "Ping failed, reconnecting.");
                        self.reconnect().await;
                    }
                }
            }
            Some(_local_addr) => {
                debug!("Local IP no longer valid, reconnecting");
                self.reconnect().await;
            }
            None => {
                debug!("No local address for this relay connection, reconnecting.");
                self.reconnect().await;
            }
        }
        None
    }

    async fn reconnect(&mut self) {
        let client =
            Self::create_relay_client(self.url.clone(), self.relay_connection_opts.clone());
        self.relay_client = client;
        if self.is_home_relay {
            self.relay_client.note_preferred(true).await;
        }
    }

    async fn send_relay(&mut self, item: RelaySendItem) {
        // When Quinn sends a GSO Transmit magicsock::split_packets will make us receive
        // more than one packet to send in a single call.  We join all packets back together
        // and prefix them with a u16 packet size.  They then get sent as a single DISCO
        // frame.  However this might still be multiple packets when otherwise the maximum
        // packet size for the relay protocol would be exceeded.
        for packet in PacketizeIter::<_, MAX_PAYLOAD_SIZE>::new(item.remote_node, item.datagrams) {
            let len = packet.len();
            match self.relay_client.send(packet.node_id, packet.payload).await {
                Ok(_) => inc_by!(MagicsockMetrics, send_relay, len as _),
                Err(err) => {
                    warn!("send failed: {err:#}");
                    inc!(MagicsockMetrics, send_relay_error);
                }
            }
        }
    }

    async fn handle_relay_msg(
        &mut self,
        msg: Result<Option<anyhow::Result<ReceivedMessage>>, tokio::time::error::Elapsed>,
    ) -> ReadResult {
        let mut conn_is_closed = false;
        let msg = match msg {
            Ok(Some(Ok(msg))) => Some(msg),
            Ok(Some(Err(err))) => {
                warn!("recv error: {:?}", err);
                self.relay_client.close_for_reconnect().await;
                if !self.relay_client.is_closed() {
                    conn_is_closed = true;
                }
                None
            }
            Ok(None) => {
                warn!("recv error: no connection");
                self.relay_client.close_for_reconnect().await;
                None
            }
            Err(_) => {
                warn!("recv error: timeout");
                self.relay_client.close_for_reconnect().await;
                conn_is_closed = true;
                None
            }
        };

        match msg {
            None => {
                // Forget that all these peers have routes.
                self.node_present.clear();

                if conn_is_closed {
                    // drop client
                    return ReadResult::Break;
                }

                // If our relay connection broke, it might be because our network
                // conditions changed. Start that check.
                // TODO:
                // self.re_stun("relay-recv-error").await;

                // Back off a bit before reconnecting.
                match self.backoff.next_backoff() {
                    Some(t) => {
                        debug!("backoff sleep: {}ms", t.as_millis());
                        time::sleep(t).await;
                        ReadResult::Continue
                    }
                    None => ReadResult::Break,
                }
            }
            Some(msg) => {
                // reset
                self.backoff.reset();
                let now = Instant::now();
                if self
                    .last_packet_time
                    .as_ref()
                    .map(|t| t.elapsed() > Duration::from_secs(5))
                    .unwrap_or(true)
                {
                    self.last_packet_time = Some(now);
                }

                match msg {
                    ReceivedMessage::ReceivedPacket {
                        remote_node_id,
                        data,
                    } => {
                        trace!(len=%data.len(), "received msg");
                        // If this is a new sender we hadn't seen before, remember it and
                        // register a route for this peer.
                        if self
                            .last_packet_src
                            .as_ref()
                            .map(|p| *p != remote_node_id)
                            .unwrap_or(true)
                        {
                            // avoid map lookup w/ high throughput single peer
                            self.last_packet_src = Some(remote_node_id);
                            self.node_present.insert(remote_node_id);
                        }

                        for datagram in PacketSplitIter::new(self.url.clone(), remote_node_id, data)
                        {
                            let Ok(datagram) = datagram else {
                                error!("Invalid packet split");
                                break;
                            };
                            if let Err(err) = self.relay_datagrams_recv.try_send(datagram) {
                                warn!("dropping received relay packet: {err:#}");
                            }
                        }

                        ReadResult::Continue
                    }
                    ReceivedMessage::Ping(data) => {
                        // Best effort reply to the ping.
                        // TODO: use sth like try_send?
                        if let Err(err) = self.relay_client.send_pong(data).await {
                            warn!("pong error: {:?}", err);
                        }
                        ReadResult::Continue
                    }
                    ReceivedMessage::Pong(ping) => {
                        self.relay_client.finish_ping(ping);
                        ReadResult::Continue
                    }
                    ReceivedMessage::Health { .. } => ReadResult::Continue,
                    ReceivedMessage::NodeGone(key) => {
                        self.node_present.remove(&key);
                        ReadResult::Continue
                    }
                    other => {
                        trace!("ignoring: {:?}", other);
                        // Ignore.
                        ReadResult::Continue
                    }
                }
            }
        }
    }
}

pub(super) enum RelayActorMessage {
    MaybeCloseRelaysOnRebind(Vec<IpAddr>),
    SetHome { url: RelayUrl },
}

#[derive(Debug, Clone)]
pub(super) struct RelaySendItem {
    /// The destination for the datagrams.
    pub(super) remote_node: NodeId,
    /// The home relay of the remote node.
    pub(super) url: RelayUrl,
    /// One or more datagrams to send.
    pub(super) datagrams: RelayContents,
}

pub(super) struct RelayActor {
    msock: Arc<MagicSock>,
    /// Queue on which to put received datagrams.
    ///
    /// [`AsyncUdpSocket::poll_recv`] will read from this queue.
    ///
    /// [`AsyncUdpSocket::poll_recv`]: quinn::AsyncUdpSocket::poll_recv
    relay_datagram_recv_queue: Arc<RelayDatagramRecvQueue>,
    /// The actors managing each currently used relay server.
    ///
    /// These actors will exit when they have any inactivity.  Otherwise they will keep
    /// trying to maintain a connection to the relay server as needed.
    active_relays: BTreeMap<RelayUrl, ActiveRelayHandle>,
    /// The tasks for the [`ActiveRelayActor`]s in `active_relays` above.
    active_relay_tasks: JoinSet<()>,
    cancel_token: CancellationToken,
}

impl RelayActor {
    pub(super) fn new(
        msock: Arc<MagicSock>,
        relay_datagram_recv_queue: Arc<RelayDatagramRecvQueue>,
    ) -> Self {
        let cancel_token = CancellationToken::new();
        Self {
            msock,
            relay_datagram_recv_queue,
            active_relays: Default::default(),
            active_relay_tasks: JoinSet::new(),
            cancel_token,
        }
    }

    pub(super) fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub(super) async fn run(
        mut self,
        mut receiver: mpsc::Receiver<RelayActorMessage>,
        mut datagram_send_channel: RelayDatagramSendChannelReceiver,
    ) {
        // When this future is present, it is sending pending datagrams to an
        // ActiveRelayActor.  We can not process further datagrams during this time.
        let mut datagram_send_fut = std::pin::pin!(MaybeFuture::none());

        loop {
            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    trace!("shutting down");
                    break;
                }
                Some(Err(err)) = self.active_relay_tasks.join_next() => {
                    if err.is_panic() {
                        panic!("ActiveRelayActor task panicked: {err:#?}");
                    }
                    if !err.is_cancelled() {
                        error!("ActiveRelayActor failed: {err:?}");
                    }
                    self.reap_active_relays();
                }
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox dropped, shutting down.");
                        break;
                    };
                    let cancel_token = self.cancel_token.child_token();
                    cancel_token.run_until_cancelled(self.handle_msg(msg)).await;
                }
                // Only poll for new datagrams if we are not blocked on sending them.
                item = datagram_send_channel.recv(), if datagram_send_fut.is_none() => {
                    let Some(item) = item else {
                        debug!("Datagram send channel dropped, shutting down.");
                        break;
                    };
                    let token = self.cancel_token.child_token();
                    if let Some(Some(fut)) = token.run_until_cancelled(
                        self.try_send_datagram(item)
                    ).await {
                        datagram_send_fut.as_mut().set_future(fut);
                    }
                }
                // Only poll this future if it is in use.
                _ = &mut datagram_send_fut, if datagram_send_fut.is_some() => {}
            }
        }

        // try shutdown
        if tokio::time::timeout(Duration::from_secs(3), self.close_all_active_relays())
            .await
            .is_err()
        {
            warn!("Failed to shut down all ActiveRelayActors");
        }
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::SetHome { url } => {
                self.set_home_relay(url).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind(ifs) => {
                self.maybe_close_relays_on_rebind(&ifs).await;
            }
        }
    }

    /// Sends datagrams to the correct [`ActiveRelayActor`], or returns a future.
    ///
    /// If the datagram can not be sent immediately, because the destination channel is
    /// full, a future is returned that will complete once the datagrams have been sent to
    /// the [`ActiveRelayActor`].
    async fn try_send_datagram(&mut self, item: RelaySendItem) -> Option<impl Future<Output = ()>> {
        let url = item.url.clone();
        let handle = self
            .active_relay_handle_for_node(&item.url, &item.remote_node)
            .await;
        match handle.datagrams_send_queue.try_send(item) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(?url, "Dropped datagram(s): ActiveRelayActor closed.");
                None
            }
            Err(mpsc::error::TrySendError::Full(item)) => {
                let sender = handle.datagrams_send_queue.clone();
                let fut = async move {
                    if sender.send(item).await.is_err() {
                        warn!(?url, "Dropped datagram(s): ActiveRelayActor closed.");
                    }
                };
                Some(fut)
            }
        }
    }

    async fn set_home_relay(&mut self, home_url: RelayUrl) {
        let home_url_ref = &home_url;
        futures_buffered::join_all(self.active_relays.iter().map(|(url, handle)| async move {
            let is_preferred = url == home_url_ref;
            handle
                .inbox_addr
                .send(ActiveRelayMessage::SetHomeRelay(is_preferred))
                .await
                .ok()
        }))
        .await;

        // Ensure we have an ActiveRelayActor for the current home relay.
        self.active_relay_handle(home_url);
    }

    /// Returns the handle for the [`ActiveRelayActor`] to reach `remote_node`.
    ///
    /// The node is expected to be reachable on `url`, but if no [`ActiveRelayActor`] for
    /// `url` exists but another existing [`ActiveRelayActor`] already knows about the node,
    /// that other node is used.
    async fn active_relay_handle_for_node(
        &mut self,
        url: &RelayUrl,
        remote_node: &NodeId,
    ) -> ActiveRelayHandle {
        if let Some(handle) = self.active_relays.get(url) {
            return handle.clone();
        }

        let mut found_relay: Option<RelayUrl> = None;
        // If we don't have an open connection to the remote node's home relay, see if
        // we have an open connection to a relay node where we'd heard from that peer
        // already.  E.g. maybe they dialed our home relay recently.
        // TODO: LRU cache the NodeId -> relay mapping so this is much faster for repeat
        // senders.

        {
            // Futures which return Some(RelayUrl) if the relay knows about the remote node.
            let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
                let (tx, rx) = oneshot::channel();
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::HasNodeRoute(*remote_node, tx))
                    .await
                    .ok();
                match rx.await {
                    Ok(true) => Some(url.clone()),
                    _ => None,
                }
            });
            let mut futures = FuturesUnorderedBounded::from_iter(check_futs);
            while let Some(maybe_url) = futures.next().await {
                if maybe_url.is_some() {
                    found_relay = maybe_url;
                    break;
                }
            }
        }
        let url = found_relay.unwrap_or(url.clone());
        self.active_relay_handle(url)
    }

    /// Returns the handle of the [`ActiveRelayActor`].
    fn active_relay_handle(&mut self, url: RelayUrl) -> ActiveRelayHandle {
        match self.active_relays.get(&url) {
            Some(e) => e.clone(),
            None => {
                let handle = self.start_active_relay(url.clone());
                if Some(&url) == self.msock.my_relay().as_ref() {
                    if let Err(err) = handle
                        .inbox_addr
                        .try_send(ActiveRelayMessage::SetHomeRelay(true))
                    {
                        error!("Home relay not set, send to new actor failed: {err:#}.");
                    }
                }
                self.active_relays.insert(url, handle.clone());
                handle
            }
        }
    }

    fn start_active_relay(&mut self, url: RelayUrl) -> ActiveRelayHandle {
        info!(?url, "Adding relay connection");

        let connection_opts = RelayConnectionOptions {
            secret_key: self.msock.secret_key.clone(),
            dns_resolver: self.msock.dns_resolver.clone(),
            proxy_url: self.msock.proxy_url().cloned(),
            prefer_ipv6: self.msock.ipv6_reported.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: self.msock.insecure_skip_relay_cert_verify,
        };

        // TODO: Replace 64 with PER_CLIENT_SEND_QUEUE_DEPTH once that's unused
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(64);
        let (inbox_tx, inbox_rx) = mpsc::channel(64);
        let span = info_span!("active-relay", %url);
        let opts = ActiveRelayActorOptions {
            url,
            relay_datagrams_send: send_datagram_rx,
            relay_datagrams_recv: self.relay_datagram_recv_queue.clone(),
            connection_opts,
        };
        let actor = ActiveRelayActor::new(opts);
        self.active_relay_tasks.spawn(
            async move {
                // TODO: Make the actor itself infallible.
                if let Err(err) = actor.run(inbox_rx).await {
                    warn!("actor error: {err:#}");
                }
            }
            .instrument(span),
        );
        let handle = ActiveRelayHandle {
            inbox_addr: inbox_tx,
            datagrams_send_queue: send_datagram_tx,
        };
        self.log_active_relay();
        handle
    }

    /// Closes the relay connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any relay connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// relay connections are pinged.
    async fn maybe_close_relays_on_rebind(&mut self, okay_local_ips: &[IpAddr]) {
        let send_futs = self.active_relays.values().map(|handle| async move {
            handle
                .inbox_addr
                .send(ActiveRelayMessage::CheckConnection(okay_local_ips.to_vec()))
                .await
                .ok();
        });
        futures_buffered::join_all(send_futs).await;
        self.log_active_relay();
    }

    /// Cleans up [`ActiveRelayActor`]s which have stopped running.
    fn reap_active_relays(&mut self) {
        self.active_relays
            .retain(|_url, handle| !handle.inbox_addr.is_closed());

        // Make sure home relay exists
        if let Some(ref url) = self.msock.my_relay() {
            self.active_relay_handle(url.clone());
        }
        self.log_active_relay();
    }

    /// Stops all [`ActiveRelayActor`]s and awaits for them to finish.
    async fn close_all_active_relays(&mut self) {
        let send_futs = self.active_relays.iter().map(|(url, handle)| async move {
            debug!(%url, "Shutting down ActiveRelayActor");
            handle
                .inbox_addr
                .send(ActiveRelayMessage::Shutdown)
                .await
                .ok();
        });
        futures_buffered::join_all(send_futs).await;

        let tasks = std::mem::take(&mut self.active_relay_tasks);
        tasks.join_all().await;

        self.log_active_relay();
    }

    fn log_active_relay(&self) {
        debug!("{} active relay conns{}", self.active_relays.len(), {
            let mut s = String::new();
            if !self.active_relays.is_empty() {
                s += ":";
                for node in self.active_relay_sorted() {
                    s += &format!(" relay-{}", node,);
                }
            }
            s
        });
    }

    fn active_relay_sorted(&self) -> impl Iterator<Item = RelayUrl> {
        let mut ids: Vec<_> = self.active_relays.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

/// Handle to one [`ActiveRelayActor`].
#[derive(Debug, Clone)]
struct ActiveRelayHandle {
    inbox_addr: mpsc::Sender<ActiveRelayMessage>,
    datagrams_send_queue: mpsc::Sender<RelaySendItem>,
}

/// A packet to send over the relay.
///
/// This is nothing but a newtype, it should be constructed using [`PacketizeIter`].  This
/// is a packet of one or more datagrams, each prefixed with a u16-be length.  This is what
/// the `Frame::SendPacket` of the `DerpCodec` transports and is produced by
/// [`PacketizeIter`] and transformed back into datagrams using [`PacketSplitIter`].
#[derive(Debug, PartialEq, Eq)]
struct RelaySendPacket {
    node_id: NodeId,
    payload: Bytes,
}

impl RelaySendPacket {
    fn len(&self) -> usize {
        self.payload.len()
    }
}

/// A single datagram received from a relay server.
///
/// This could be either a QUIC or DISCO packet.
#[derive(Debug)]
pub(super) struct RelayRecvDatagram {
    pub(super) url: RelayUrl,
    pub(super) src: NodeId,
    pub(super) buf: Bytes,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadResult {
    Break,
    Continue,
}

/// Combines datagrams into a single DISCO frame of at most MAX_PACKET_SIZE.
///
/// The disco `iroh_relay::protos::Frame::SendPacket` frame can contain more then a single
/// datagram.  Each datagram in this frame is prefixed with a little-endian 2-byte length
/// prefix.  This occurs when Quinn sends a GSO transmit containing more than one datagram,
/// which are split using [`crate::magicsock::split_packets`].
///
/// The [`PacketSplitIter`] does the inverse and splits such packets back into individual
/// datagrams.
struct PacketizeIter<I: Iterator, const N: usize> {
    node_id: NodeId,
    iter: std::iter::Peekable<I>,
    buffer: BytesMut,
}

impl<I: Iterator, const N: usize> PacketizeIter<I, N> {
    /// Create a new new PacketizeIter from something that can be turned into an
    /// iterator of slices, like a `Vec<Bytes>`.
    fn new(node_id: NodeId, iter: impl IntoIterator<IntoIter = I>) -> Self {
        Self {
            node_id,
            iter: iter.into_iter().peekable(),
            buffer: BytesMut::with_capacity(N),
        }
    }
}

impl<I: Iterator, const N: usize> Iterator for PacketizeIter<I, N>
where
    I::Item: AsRef<[u8]>,
{
    type Item = RelaySendPacket;

    fn next(&mut self) -> Option<Self::Item> {
        use bytes::BufMut;
        while let Some(next_bytes) = self.iter.peek() {
            let next_bytes = next_bytes.as_ref();
            assert!(next_bytes.len() + 2 <= N);
            let next_length: u16 = next_bytes.len().try_into().expect("items < 64k size");
            if self.buffer.len() + next_bytes.len() + 2 > N {
                break;
            }
            self.buffer.put_u16_le(next_length);
            self.buffer.put_slice(next_bytes);
            self.iter.next();
        }
        if !self.buffer.is_empty() {
            Some(RelaySendPacket {
                node_id: self.node_id,
                payload: self.buffer.split().freeze(),
            })
        } else {
            None
        }
    }
}

/// Splits a single [`ReceivedMessage::ReceivedPacket`] frame into datagrams.
///
/// This splits packets joined by [`PacketizeIter`] back into individual datagrams.  See
/// that struct for more details.
#[derive(Debug)]
struct PacketSplitIter {
    url: RelayUrl,
    src: NodeId,
    bytes: Bytes,
}

impl PacketSplitIter {
    /// Create a new PacketSplitIter from a packet.
    fn new(url: RelayUrl, src: NodeId, bytes: Bytes) -> Self {
        Self { url, src, bytes }
    }

    fn fail(&mut self) -> Option<std::io::Result<RelayRecvDatagram>> {
        self.bytes.clear();
        Some(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "",
        )))
    }
}

impl Iterator for PacketSplitIter {
    type Item = std::io::Result<RelayRecvDatagram>;

    fn next(&mut self) -> Option<Self::Item> {
        use bytes::Buf;
        if self.bytes.has_remaining() {
            if self.bytes.remaining() < 2 {
                return self.fail();
            }
            let len = self.bytes.get_u16_le() as usize;
            if self.bytes.remaining() < len {
                return self.fail();
            }
            let buf = self.bytes.split_to(len);
            Some(Ok(RelayRecvDatagram {
                url: self.url.clone(),
                src: self.src,
                buf,
            }))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future;
    use iroh_base::SecretKey;
    use smallvec::smallvec;
    use testresult::TestResult;
    use tokio_util::task::AbortOnDropHandle;

    use super::*;
    use crate::test_utils;

    #[test]
    fn test_packetize_iter() {
        let node_id = SecretKey::generate(rand::thread_rng()).public();
        let empty_vec: Vec<Bytes> = Vec::new();
        let mut iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, empty_vec);
        assert_eq!(None, iter.next());

        let single_vec = vec!["Hello"];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, single_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(1, result.len());
        assert_eq!(
            &[5, 0, b'H', b'e', b'l', b'l', b'o'],
            &result[0].payload[..]
        );

        let spacer = vec![0u8; MAX_PACKET_SIZE - 10];
        let multiple_vec = vec![&b"Hello"[..], &spacer, &b"World"[..]];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, multiple_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(2, result.len());
        assert_eq!(
            &[5, 0, b'H', b'e', b'l', b'l', b'o'],
            &result[0].payload[..7]
        );
        assert_eq!(
            &[5, 0, b'W', b'o', b'r', b'l', b'd'],
            &result[1].payload[..]
        );
    }

    /// Starts a new [`ActiveRelayActor`].
    fn start_active_relay_actor(
        secret_key: SecretKey,
        url: RelayUrl,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
        relay_datagrams_recv: Arc<RelayDatagramRecvQueue>,
    ) -> AbortOnDropHandle<anyhow::Result<()>> {
        let opts = ActiveRelayActorOptions {
            url,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key,
                dns_resolver: crate::dns::default_resolver().clone(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(true)),
                insecure_skip_cert_verify: true,
            },
        };
        let task = tokio::spawn(
            async move {
                let actor = ActiveRelayActor::new(opts);
                actor.run(inbox_rx).await
            }
            .instrument(info_span!("actor-under-test")),
        );
        AbortOnDropHandle::new(task)
    }

    /// Starts an [`ActiveRelayActor`] as an "iroh echo node".
    ///
    /// This actor will connect to the relay server, pretending to be an iroh node, and echo
    /// back any datagram it receives from the relay.  This is used by the
    /// [`ActiveRelayNode`] under test to check connectivity works.
    fn start_echo_node(relay_url: RelayUrl) -> (NodeId, AbortOnDropHandle<()>) {
        let secret_key = SecretKey::from_bytes(&[8u8; 32]);
        let recv_datagram_queue = Arc::new(RelayDatagramRecvQueue::new());
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let actor_task = start_active_relay_actor(
            secret_key.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            recv_datagram_queue.clone(),
        );
        let echo_task = tokio::spawn({
            let relay_url = relay_url.clone();
            async move {
                loop {
                    let datagram = future::poll_fn(|cx| recv_datagram_queue.poll_recv(cx)).await;
                    if let Ok(recv) = datagram {
                        let RelayRecvDatagram { url: _, src, buf } = recv;
                        info!(from = src.fmt_short(), "Received datagram");
                        let send = RelaySendItem {
                            remote_node: src,
                            url: relay_url.clone(),
                            datagrams: smallvec![buf],
                        };
                        send_datagram_tx.send(send).await.ok();
                    }
                }
            }
            .instrument(info_span!("echo-task"))
        });
        let echo_task = AbortOnDropHandle::new(echo_task);
        let supervisor_task = tokio::spawn(async move {
            // move the inbox_tx here so it is not dropped, as this stops the actor.
            let _inbox_tx = inbox_tx;
            tokio::select! {
                biased;
                _ = actor_task => (),
                _ = echo_task => (),
            };
        });
        let supervisor_task = AbortOnDropHandle::new(supervisor_task);
        (secret_key.public(), supervisor_task)
    }

    #[tokio::test]
    async fn test_active_relay_reconnect() -> TestResult {
        let _guard = iroh_test::logging::setup();
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let (peer_node, _echo_node_task) = start_echo_node(relay_url.clone());

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let datagram_recv_queue = Arc::new(RelayDatagramRecvQueue::new());
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let task = start_active_relay_actor(
            secret_key,
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            datagram_recv_queue.clone(),
        );

        // Send a datagram to our echo node.
        info!("first echo");
        let hello_send_item = RelaySendItem {
            remote_node: peer_node,
            url: relay_url.clone(),
            datagrams: smallvec![Bytes::from_static(b"hello")],
        };
        send_datagram_tx.send(hello_send_item.clone()).await?;

        // Check we get it back
        let RelayRecvDatagram {
            url: _,
            src: _,
            buf,
        } = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        assert_eq!(buf.as_ref(), b"hello");

        // Now ask to check the connection, triggering a ping but no reconnect.
        let (tx, rx) = oneshot::channel();
        inbox_tx.send(ActiveRelayMessage::GetLocalAddr(tx)).await?;
        let local_addr = rx.await?.context("no local addr")?;
        info!(?local_addr, "check connection with addr");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection(vec![local_addr.ip()]))
            .await?;

        // Sync the ActiveRelayActor. Ping blocks it and we want to be sure it has handled
        // another inbox message before continuing.
        let (tx, rx) = oneshot::channel();
        inbox_tx.send(ActiveRelayMessage::GetLocalAddr(tx)).await?;
        rx.await?;

        // Echo should still work.
        info!("second echo");
        send_datagram_tx.send(hello_send_item.clone()).await?;
        let recv = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        assert_eq!(recv.buf.as_ref(), b"hello");

        // Now ask to check the connection, this will reconnect without pinging because we
        // do not supply any "valid" local IP addresses.
        info!("check connection");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection(Vec::new()))
            .await?;

        // Give some time to reconnect, mostly to sort logs rather than functional.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Echo should still work.
        info!("third echo");
        send_datagram_tx.send(hello_send_item).await?;
        let recv = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        assert_eq!(recv.buf.as_ref(), b"hello");

        // Shut down the actor.
        inbox_tx.send(ActiveRelayMessage::Shutdown).await?;
        task.await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_active_relay_inactive() -> TestResult {
        let _guard = iroh_test::logging::setup();
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let node_id = secret_key.public();
        let datagram_recv_queue = Arc::new(RelayDatagramRecvQueue::new());
        let (_send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let mut task = start_active_relay_actor(
            secret_key,
            relay_url,
            inbox_rx,
            send_datagram_rx,
            datagram_recv_queue.clone(),
        );

        // Give the task some time to run.  If it responds to HasNodeRoute it is running.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::HasNodeRoute(node_id, tx))
            .await
            .ok();
        rx.await?;

        // We now have an idling ActiveRelayActor.  If we advance time just a little it
        // should stay alive.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME / 2");
        tokio::time::pause();
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME / 2).await;
        tokio::time::resume();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "actor task terminated"
        );

        // If we advance time a lot it should finish.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME");
        tokio::time::pause();
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME).await;
        tokio::time::resume();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), task)
                .await
                .is_ok(),
            "actor task still running"
        );

        Ok(())
    }
}
