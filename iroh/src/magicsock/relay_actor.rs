//! The relay actor.
//!
//! The [`RelayActor`] handles all the relay connections.  It is helped by the
//! [`ActiveRelayActor`] which handles a single relay connection.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use backoff::backoff::Backoff;
use bytes::{Bytes, BytesMut};
use futures_buffered::FuturesUnorderedBounded;
use futures_lite::StreamExt;
use iroh_base::{NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_metrics::{inc, inc_by};
use iroh_relay::{self as relay, client::ClientError, ReceivedMessage, MAX_PACKET_SIZE};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use url::Url;

use crate::{
    dns::DnsResolver,
    magicsock::{MagicSock, Metrics as MagicsockMetrics, RelayContents, RelayDatagramsQueue},
    util::MaybeFuture,
};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// How often `clean_stale_relay` runs when there are potentially-stale relay connections to close.
const RELAY_CLEAN_STALE_INTERVAL: Duration = Duration::from_secs(15);

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
#[derive(Debug)]
struct ActiveRelayActor {
    /// The time of the last request for its write
    /// channel (currently even if there was no write).
    last_write: Instant,
    /// Queue to send received relay datagrams on.
    relay_datagrams_recv: Arc<RelayDatagramsQueue>,
    /// Channel on which we receive packets to send to the relay.
    relay_datagrams_send: mpsc::Receiver<RelaySendPacket>,
    url: RelayUrl,
    relay_client: relay::client::Client,
    relay_client_receiver: relay::client::ClientReceiver,
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
    GetLastWrite(oneshot::Sender<Instant>),
    Ping(oneshot::Sender<Result<Duration, ClientError>>),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    GetNodeRoute(NodeId, oneshot::Sender<bool>),
    NotePreferred(bool),
    Shutdown,
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
struct ActiveRelayActorOptions {
    url: RelayUrl,
    relay_datagrams_send: mpsc::Receiver<RelaySendPacket>,
    relay_datagrams_recv: Arc<RelayDatagramsQueue>,
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
        let (relay_client, relay_client_receiver) =
            Self::create_relay_client(url.clone(), connection_opts);

        ActiveRelayActor {
            last_write: Instant::now(),
            relay_datagrams_recv,
            relay_datagrams_send,
            url,
            node_present: BTreeSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
            relay_client,
            relay_client_receiver,
        }
    }

    fn create_relay_client(
        url: RelayUrl,
        opts: RelayConnectionOptions,
    ) -> (relay::client::Client, relay::client::ClientReceiver) {
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
        let relay_client = self.relay_client.clone();
        relay_client.connect().await.context("initial connection")?;

        // When this future has an inner, it is a future which is currently sending
        // something to the relay server.  Nothing else can be sent to the relay server at
        // the same time.
        let mut relay_send_fut = MaybeFuture::none();

        loop {
            // If a read error occurred on the connection it might have been lost.  But we
            // need this connection to stay alive so we can receive more messages sent by
            // peers via the relay even if we don't start sending again first.
            if !self.relay_client.is_connected().await? {
                debug!("relay re-connecting");
                relay_client.connect().await.context("keepalive")?;
            }
            tokio::select! {
                msg = inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("all clients closed");
                        break;
                    };
                    if self.handle_actor_msg(msg).await {
                        break;
                    }
                }
                // Only poll relay_send_fut if it is sending to the relay.
                _ = &mut relay_send_fut, if relay_send_fut.is_some() => {
                    relay_send_fut = MaybeFuture::none();
                }
                // Only poll for new datagrams if relay_send_fut is not busy.
                Some(msg) = self.relay_datagrams_send.recv(), if relay_send_fut.is_none() => {
                    relay_send_fut = MaybeFuture::with_future(
                        Box::pin(relay_client.send(msg.node_id, msg.packet))
                    );
                    self.last_write = Instant::now();

                }
                msg = self.relay_client_receiver.recv() => {
                    trace!("tick: relay_client_receiver");
                    if let Some(msg) = msg {
                        if self.handle_relay_msg(msg).await == ReadResult::Break {
                            // fatal error
                            break;
                        }
                    }
                }
            }
        }
        debug!("exiting");
        self.relay_client.close().await?;
        inc!(MagicsockMetrics, num_relay_conns_removed);
        Ok(())
    }

    async fn handle_actor_msg(&mut self, msg: ActiveRelayMessage) -> bool {
        trace!("tick: inbox: {:?}", msg);
        match msg {
            ActiveRelayMessage::GetLastWrite(r) => {
                r.send(self.last_write).ok();
            }
            ActiveRelayMessage::Ping(r) => {
                r.send(self.relay_client.ping().await).ok();
            }
            ActiveRelayMessage::GetLocalAddr(r) => {
                r.send(self.relay_client.local_addr().await).ok();
            }
            ActiveRelayMessage::NotePreferred(is_preferred) => {
                self.relay_client.note_preferred(is_preferred).await;
            }
            ActiveRelayMessage::GetNodeRoute(peer, r) => {
                let has_peer = self.node_present.contains(&peer);
                r.send(has_peer).ok();
            }
            ActiveRelayMessage::Shutdown => {
                debug!("shutdown");
                return true;
            }
        }
        false
    }

    async fn handle_relay_msg(&mut self, msg: Result<ReceivedMessage, ClientError>) -> ReadResult {
        match msg {
            Err(err) => {
                warn!("recv error {:?}", err);

                // Forget that all these peers have routes.
                self.node_present.clear();

                if matches!(
                    err,
                    relay::client::ClientError::Closed | relay::client::ClientError::IPDisabled
                ) {
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
            Ok(msg) => {
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
                        let dc = self.relay_client.clone();
                        // TODO: Unbounded tasks/channel
                        tokio::task::spawn(async move {
                            if let Err(err) = dc.send_pong(data).await {
                                warn!("pong error: {:?}", err);
                            }
                        });
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
    Send {
        url: RelayUrl,
        contents: RelayContents,
        remote_node: NodeId,
    },
    MaybeCloseRelaysOnRebind(Vec<IpAddr>),
    SetHome {
        url: RelayUrl,
    },
}

pub(super) struct RelayActor {
    msock: Arc<MagicSock>,
    /// Queue on which to put received datagrams.
    ///
    /// [`AsyncUdpSocket::poll_recv`] will read from this queue.
    ///
    /// [`AsyncUdpSocket::poll_recv`]: quinn::AsyncUdpSocket::poll_recv
    relay_datagram_recv_queue: Arc<RelayDatagramsQueue>,
    /// The actors managing each currently used relay server.
    ///
    /// These actors will exit when they have any inactivity.  Otherwise they will keep
    /// trying to maintain a connection to the relay server as needed.
    active_relays: BTreeMap<RelayUrl, ActiveRelayHandle>,
    /// The tasks for the [`ActiveRelayActor`]s in `active_relays` above.
    active_relay_tasks: JoinSet<()>,
    ping_tasks: JoinSet<(RelayUrl, bool)>,
    cancel_token: CancellationToken,
}

impl RelayActor {
    pub(super) fn new(
        msock: Arc<MagicSock>,
        relay_datagram_recv_queue: Arc<RelayDatagramsQueue>,
    ) -> Self {
        let cancel_token = CancellationToken::new();
        Self {
            msock,
            relay_datagram_recv_queue,
            active_relays: Default::default(),
            active_relay_tasks: JoinSet::new(),
            ping_tasks: Default::default(),
            cancel_token,
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub(super) async fn run(mut self, mut receiver: mpsc::Receiver<RelayActorMessage>) {
        let mut cleanup_timer = time::interval_at(
            time::Instant::now() + RELAY_CLEAN_STALE_INTERVAL,
            RELAY_CLEAN_STALE_INTERVAL,
        );

        loop {
            tokio::select! {
                biased;

                _ = self.cancel_token.cancelled() => {
                    trace!("shutting down");
                    break;
                }
                Some(Err(err)) = self.active_relay_tasks.join_next() => {
                    if !err.is_cancelled() {
                        error!("ActiveRelayActor failed: {err:?}");
                    }
                    self.clean_stale_relay().await;
                }
                // `ping_tasks` being empty is a normal situation - in fact it starts empty
                // until a `MaybeCloseRelaysOnRebind` message is received.
                Some(task_result) = self.ping_tasks.join_next() => {
                    match task_result {
                        Ok((url, ping_success)) => {
                            if !ping_success {
                                let token = self.cancel_token.child_token();
                                token.run_until_cancelled(
                                    self.close_and_reconnect_relay(&url, "rebind-ping-fail")
                                ).await;
                            }
                        }

                        Err(err) => {
                            warn!("ping task error: {:?}", err);
                        }
                    }
                }

                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        trace!("shutting down relay recv loop");
                        break;
                    };
                    let cancel_token = self.cancel_token.child_token();
                    cancel_token.run_until_cancelled(self.handle_msg(msg)).await;
                }
                _ = cleanup_timer.tick() => {
                    trace!("tick: cleanup");
                    let cancel_token = self.cancel_token.child_token();
                    cancel_token.run_until_cancelled(self.clean_stale_relay()).await;
                }
            }
        }

        // try shutdown
        self.close_all_relay("conn-close").await;
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::Send {
                url,
                contents,
                remote_node,
            } => {
                self.send_relay(&url, contents, remote_node).await;
            }
            RelayActorMessage::SetHome { url } => {
                self.set_home_relay(&url).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind(ifs) => {
                self.maybe_close_relays_on_rebind(&ifs).await;
            }
        }
        // Wake up the send waker if one is waiting for space in the channel
        let mut wakers = self.msock.relay_send_waker.lock().expect("poisoned");
        if let Some(waker) = wakers.take() {
            waker.wake();
        }
    }

    async fn set_home_relay(&mut self, home_url: &RelayUrl) {
        futures_buffered::join_all(self.active_relays.iter().map(|(url, handle)| async move {
            let is_preferred = url == home_url;
            handle
                .inbox_addr
                .send(ActiveRelayMessage::NotePreferred(is_preferred))
                .await
                .ok()
        }))
        .await;

        // Ensure we have an ActiveRelayActor for the current home relay.
        self.active_relay_handle(home_url).await;
    }

    async fn send_relay(&mut self, url: &RelayUrl, contents: RelayContents, remote_node: NodeId) {
        const PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - PublicKey::LENGTH;
        let total_bytes = contents.iter().map(|c| c.len() as u64).sum::<u64>();
        trace!(
            %url,
            remote_node = %remote_node.fmt_short(),
            len = total_bytes,
            "sending over relay",
        );
        let handle = self.active_relay_handle_for_node(url, &remote_node).await;

        // When Quinn sends a GSO Transmit magicsock::split_packets will make us receive
        // more than one packet to send in a single call.  We join all packets back together
        // and prefix them with a u16 packet size.  They then get sent as a single DISCO
        // frame.  However this might still be multiple packets when otherwise the maximum
        // packet size for the relay protocol would be exceeded.
        for packet in PacketizeIter::<_, PAYLOAD_SIZE>::new(remote_node, contents) {
            let len = packet.len();
            match handle.datagrams_send_queue.send(packet).await {
                Ok(_) => inc_by!(MagicsockMetrics, send_relay, len as _),
                Err(err) => {
                    warn!(?url, "send failed: {err:#}");
                    inc!(MagicsockMetrics, send_relay_error);
                }
            }
        }
    }

    /// Returns `true`if the message was sent successfully.
    async fn send_to_active_relay(&mut self, url: &RelayUrl, msg: ActiveRelayMessage) -> bool {
        match self.active_relays.get(url) {
            Some(handle) => match handle.inbox_addr.send(msg).await {
                Ok(_) => true,
                Err(mpsc::error::SendError(_)) => {
                    self.close_active_relay(url, "sender-closed").await;
                    false
                }
            },
            None => false,
        }
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
    ) -> &ActiveRelayHandle {
        let mut found_relay: Option<RelayUrl> = None;
        if !self.active_relays.contains_key(url) {
            // If we don't have an open connection to the remote node's home relay, see if
            // we have an open connection to a relay node where we'd heard from that peer
            // already.  E.g. maybe they dialed our home relay recently.
            // TODO: LRU cache the NodeId -> relay mapping so this is much faster for repeat
            // senders.

            // Futures which return Some(RelayUrl) if the relay knows about the remote node.
            let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
                let (tx, rx) = oneshot::channel();
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::GetNodeRoute(*remote_node, tx))
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
        match found_relay {
            Some(url) => self.active_relay_handle(&url).await,
            None => self.active_relay_handle(url).await,
        }
    }

    /// Returns the handle of the [`ActiveRelayActor`].
    async fn active_relay_handle(&mut self, url: &RelayUrl) -> &ActiveRelayHandle {
        if !self.active_relays.contains_key(url) {
            let handle = self.start_active_relay(url.clone());
            self.active_relays.insert(url.clone(), handle);
            if Some(url) == self.msock.my_relay().as_ref() {
                self.send_to_active_relay(url, ActiveRelayMessage::NotePreferred(true))
                    .await;
            }
        }
        self.active_relays.get(url).expect("just inserted")
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
        let mut tasks = Vec::new();
        for url in self.active_relays.keys().cloned().collect::<Vec<_>>() {
            let (os, or) = oneshot::channel();
            let la = if self
                .send_to_active_relay(&url, ActiveRelayMessage::GetLocalAddr(os))
                .await
            {
                match or.await {
                    Ok(None) | Err(_) => {
                        tasks.push((url, "rebind-no-localaddr"));
                        continue;
                    }
                    Ok(Some(la)) => la,
                }
            } else {
                tasks.push((url.clone(), "rebind-no-localaddr"));
                continue;
            };

            if !okay_local_ips.contains(&la.ip()) {
                tasks.push((url, "rebind-default-route-change"));
                continue;
            }

            let (os, or) = oneshot::channel();
            let ping_sent = self
                .send_to_active_relay(&url, ActiveRelayMessage::Ping(os))
                .await;

            self.ping_tasks.spawn(async move {
                let ping_success = time::timeout(Duration::from_secs(3), async {
                    if ping_sent {
                        or.await.is_ok()
                    } else {
                        false
                    }
                })
                .await
                .unwrap_or(false);

                (url, ping_success)
            });
        }

        for (url, why) in tasks {
            self.close_and_reconnect_relay(&url, why).await;
        }

        self.log_active_relay();
    }

    /// Shuts down an active relay actor and restarts it.
    ///
    /// This will force the connection to be re-created.
    async fn close_and_reconnect_relay(&mut self, url: &RelayUrl, why: &'static str) {
        self.close_active_relay(url, why).await;

        // Retrieving the handle starts a new ActiveRelayActor if it did not yet exist.
        self.active_relay_handle(url).await;
    }

    /// Cleans up stale [`ActiveRelayActor`]s.
    ///
    /// This not only checks if the relays have been used recently, but also makes sure that
    /// all relay actors are running.  In particular this is called whenever an
    /// [`ActiveRelayActor`] task finishes.
    async fn clean_stale_relay(&mut self) {
        trace!("checking {} relays for staleness", self.active_relays.len());
        let now = Instant::now();

        // Futures who return Some(RelayUrl) if the relay needs to be cleaned up.
        let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
            let (tx, rx) = oneshot::channel();
            handle
                .inbox_addr
                .send(ActiveRelayMessage::GetLastWrite(tx))
                .await
                .ok();
            match rx.await {
                Ok(last_write) if last_write.duration_since(now) <= RELAY_INACTIVE_CLEANUP_TIME => {
                    None
                }
                _ => Some(url.clone()),
            }
        });
        let futures = FuturesUnorderedBounded::from_iter(check_futs);
        let to_close: Vec<_> = futures.filter_map(|maybe_url| maybe_url).collect().await;

        let dirty = !to_close.is_empty();
        trace!(
            "closing {} of {} relays",
            to_close.len(),
            self.active_relays.len()
        );
        for i in to_close {
            self.close_active_relay(&i, "idle").await;
        }

        // Make sure home relay exists
        if let Some(ref url) = self.msock.my_relay() {
            self.active_relay_handle(url).await;
        }

        if dirty {
            self.log_active_relay();
        }
    }

    async fn close_all_relay(&mut self, why: &'static str) {
        if self.active_relays.is_empty() {
            return;
        }
        // Need to collect to avoid double borrow
        let urls: Vec<_> = self.active_relays.keys().cloned().collect();
        for url in urls {
            self.close_active_relay(&url, why).await;
        }
        self.log_active_relay();
    }

    async fn close_active_relay(&mut self, url: &RelayUrl, why: &'static str) {
        if let Some(handle) = self.active_relays.remove(url) {
            debug!(%url, "closing connection: {}", why);

            handle
                .inbox_addr
                .send(ActiveRelayMessage::Shutdown)
                .await
                .ok();
        }
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
    datagrams_send_queue: mpsc::Sender<RelaySendPacket>,
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
    packet: Bytes,
}

impl RelaySendPacket {
    fn len(&self) -> usize {
        self.packet.len()
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
                packet: self.buffer.split().freeze(),
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
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn test_packetize_iter() {
        let node_id = SecretKey::generate().public();
        let empty_vec: Vec<Bytes> = Vec::new();
        let mut iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, empty_vec);
        assert_eq!(None, iter.next());

        let single_vec = vec!["Hello"];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, single_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(1, result.len());
        assert_eq!(&[5, 0, b'H', b'e', b'l', b'l', b'o'], &result[0].packet[..]);

        let spacer = vec![0u8; MAX_PACKET_SIZE - 10];
        let multiple_vec = vec![&b"Hello"[..], &spacer, &b"World"[..]];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(node_id, multiple_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(2, result.len());
        assert_eq!(
            &[5, 0, b'H', b'e', b'l', b'l', b'o'],
            &result[0].packet[..7]
        );
        assert_eq!(&[5, 0, b'W', b'o', b'r', b'l', b'd'], &result[1].packet[..]);
    }
}
