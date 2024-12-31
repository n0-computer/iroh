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
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{self, Poll},
};

use anyhow::{anyhow, bail, Result};
use backoff::exponential::{ExponentialBackoff, ExponentialBackoffBuilder};
use bytes::{Bytes, BytesMut};
use futures_buffered::FuturesUnorderedBounded;
use futures_lite::StreamExt;
use futures_util::{future, SinkExt};
use iroh_base::{NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_metrics::{inc, inc_by};
use iroh_relay::{
    self as relay,
    client::{Client, ClientSink, ConnSendError, ReceivedMessage, SendMessage},
    MAX_PACKET_SIZE,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{Duration, Instant, MissedTickBehavior},
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

/// Maximum time for a relay server to respond to a relay protocol ping.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for establishing the relay connection.
///
/// This includes DNS, dialing the server, upgrading the connection, and completing the
/// handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time after which the [`ActiveRelayActor`] will drop undeliverable datagrams.
///
/// When the [`ActiveRelayActor`] is not connected it can not deliver datagrams.  However it
/// will still receive datagrams to send from the [`RelayActor`].  If connecting takes
/// longer than this timeout datagrams will be dropped.
const UNDELIVERABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_millis(400);

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
    relay_client_builder: relay::client::ClientBuilder,
    is_home_relay: bool,
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
        let relay_client_builder = Self::create_relay_builder(url.clone(), connection_opts);
        ActiveRelayActor {
            relay_datagrams_recv,
            relay_datagrams_send,
            url,
            last_packet_src: None,
            relay_client_builder,
            is_home_relay: false,
        }
    }

    fn create_relay_builder(
        url: RelayUrl,
        opts: RelayConnectionOptions,
    ) -> relay::client::ClientBuilder {
        let RelayConnectionOptions {
            secret_key,
            dns_resolver,
            proxy_url,
            prefer_ipv6,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify,
        } = opts;
        let mut builder = relay::client::ClientBuilder::new(url, secret_key, dns_resolver)
            .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }
        #[cfg(any(test, feature = "test-utils"))]
        let builder = builder.insecure_skip_cert_verify(insecure_skip_cert_verify);
        builder
    }

    async fn run(
        mut self,
        cancel_token: CancellationToken,
        mut inbox: mpsc::Receiver<ActiveRelayMessage>,
    ) -> anyhow::Result<()> {
        inc!(MagicsockMetrics, num_relay_conns_added);

        // If inactive for one tick the actor should exit.  Inactivity is only tracked on
        // the last datagrams sent to the relay, received datagrams will trigger ACKs which
        // is sufficient to keep active connections open.
        let mut inactive_timeout = tokio::time::interval(RELAY_INACTIVE_CLEANUP_TIME);
        inactive_timeout.reset(); // skip immediate tick

        loop {
            let Some(client) = self
                .run_dialing(&cancel_token, &mut inbox, &mut inactive_timeout)
                .instrument(info_span!("dialing"))
                .await
            else {
                break;
            };
            match self
                .run_connected(&cancel_token, &mut inbox, &mut inactive_timeout, client)
                .instrument(info_span!("connected"))
                .await
            {
                Ok(_) => break,
                Err(err) => {
                    debug!("Connection to relay server lost: {err:#}");
                    continue;
                }
            }
        }
        debug!("exiting");
        inc!(MagicsockMetrics, num_relay_conns_removed);
        Ok(())
    }

    /// Actor loop when connecting to the relay server.
    ///
    /// Returns `None` if the actor needs to shut down.  Returns `Some(client)` when the
    /// connection is established.
    // TODO: consider storing cancel_token and inbox inside the actor.
    async fn run_dialing(
        &mut self,
        cancel_token: &CancellationToken,
        inbox: &mut mpsc::Receiver<ActiveRelayMessage>,
        inactive_timeout: &mut tokio::time::Interval,
    ) -> Option<iroh_relay::client::Client> {
        debug!("Actor loop: connecting to relay.");

        // We regularly flush the relay_datagrams_send queue so it is not full of stale
        // packets while reconnecting.  Those datagrams are dropped and the QUIC congestion
        // controller will have to handle this (DISCO packets do not yet have retry).  This
        // is not an ideal mechanism, an alternative approach would be to use
        // e.g. ConcurrentQueue with force_push, though now you might still send very stale
        // packets when eventually connected.  So perhaps this is a reasonable compromise.
        let mut send_datagram_flush = tokio::time::interval(UNDELIVERABLE_DATAGRAM_TIMEOUT);
        send_datagram_flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
        send_datagram_flush.reset(); // Skip the immediate interval

        let mut connecting_fut = self.connect_relay();
        loop {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    debug!("Shutdown.");
                    break None;
                }
                res = &mut connecting_fut => {
                    match res {
                        Ok(client) => {
                            break Some(client);
                        }
                        Err(err) => {
                            warn!("Client failed to connect: {err:#}");
                            connecting_fut = self.connect_relay();
                        }
                    }
                }
                msg = inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_preferred) => {
                            self.is_home_relay = is_preferred;
                        }
                        ActiveRelayMessage::HasNodeRoute(_peer, sender) => {
                            sender.send(false).ok();
                        }
                        ActiveRelayMessage::CheckConnection(_local_ips) => {}
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(None).ok();
                        }
                    }
                }
                _ = send_datagram_flush.tick() => {
                    let mut logged = false;
                    while self.relay_datagrams_send.try_recv().is_ok() {
                        if !logged {
                            debug!(?UNDELIVERABLE_DATAGRAM_TIMEOUT, "Dropping datagrams to send.");
                            logged = true;
                        }
                    }
                }
                _ = inactive_timeout.tick(), if !self.is_home_relay => {
                    debug!(?RELAY_INACTIVE_CLEANUP_TIME, "Inactive, exiting.");
                    break None;
                }
            }
        }
    }

    /// Returns a future which will repeatedly connect to a relay server.
    ///
    /// The future only completes once the connection is established and retries
    /// connections.  It currently does not ever return `Err` as the retries continue
    /// forever.
    fn connect_relay(&self) -> Pin<Box<dyn Future<Output = Result<Client>> + Send>> {
        let backoff: ExponentialBackoff<backoff::SystemClock> = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(10))
            .with_max_interval(Duration::from_secs(5))
            .build();
        let connect_fn = {
            let client_builder = self.relay_client_builder.clone();
            move || {
                let client_builder = client_builder.clone();
                async move {
                    match tokio::time::timeout(CONNECT_TIMEOUT, client_builder.connect()).await {
                        Ok(Ok(client)) => Ok(client),
                        Ok(Err(err)) => {
                            warn!("Relay connection failed: {err:#}");
                            Err(err.into())
                        }
                        Err(_) => {
                            warn!(?CONNECT_TIMEOUT, "Timeout connecting to relay");
                            Err(anyhow!("Timeout").into())
                        }
                    }
                }
            }
        };
        let retry_fut = backoff::future::retry(backoff, connect_fn);
        Box::pin(retry_fut)
    }

    /// Runs the actor loop when connected to a relay server.
    ///
    /// Returns `Ok` if the actor needs to shut down.  `Err` is returned if the connection
    /// to the relay server is lost.
    async fn run_connected(
        &mut self,
        cancel_token: &CancellationToken,
        inbox: &mut mpsc::Receiver<ActiveRelayMessage>,
        inactive_timeout: &mut tokio::time::Interval,
        client: iroh_relay::client::Client,
    ) -> Result<()> {
        debug!("Actor loop: connected to relay");

        let (mut client_stream, client_sink) = client.split();

        // TODO: an alternative to consider is to create another `run_sending` loop to call
        // when sending.  It would borrow the sink and be awaited in-place.  The benefit is
        // that the send methods wouldn't have to be fallible, as they are bugs really.
        enum SendState {
            Sending(Pin<Box<dyn Future<Output = Result<ClientSink, ConnSendError>> + Send>>),
            Ready(iroh_relay::client::ClientSink),
        }
        impl SendState {
            fn is_sending(&self) -> bool {
                matches!(self, SendState::Sending(_))
            }

            fn is_ready(&self) -> bool {
                matches!(self, SendState::Ready(_))
            }

            fn send(self, msg: SendMessage) -> Result<Self> {
                let SendState::Ready(mut client_sink) = self else {
                    error!("SendState send when not ready!");
                    bail!("SendState not ready");
                };
                let fut = async move {
                    match client_sink.send(msg).await {
                        Ok(_) => Ok(client_sink),
                        Err(err) => {
                            debug!("Send failed: {err:#}");
                            inc!(MagicsockMetrics, send_relay_error);
                            Err(err)
                        }
                    }
                };
                Ok(Self::Sending(Box::pin(fut)))
            }

            fn send_all(
                self,
                msg_iter: impl Iterator<Item = Result<SendMessage, ConnSendError>> + Send + 'static,
            ) -> Result<Self> {
                let SendState::Ready(mut client_sink) = self else {
                    error!("SendState send_all when not ready!");
                    bail!("SendState not ready");
                };
                let fut = async move {
                    let msg_stream = futures_util::stream::iter(msg_iter);
                    let mut stream = pin!(msg_stream);
                    match client_sink.send_all(&mut stream).await {
                        Ok(_) => Ok(client_sink),
                        Err(err) => {
                            debug!("Send all failed: {err:#}");
                            inc!(MagicsockMetrics, send_relay_error);
                            Err(err)
                        }
                    }
                };
                Ok(Self::Sending(Box::pin(fut)))
            }
        }
        impl Future for SendState {
            type Output = Result<ClientSink, ConnSendError>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
                match *self {
                    SendState::Sending(ref mut fut) => fut.as_mut().poll(cx),
                    SendState::Ready(_) => Poll::Pending,
                }
            }
        }

        let mut send_state = SendState::Ready(client_sink);
        if self.is_home_relay {
            send_state = send_state.send(SendMessage::NotePreferred(true))?;
        }

        // A pong message which needs to be sent as soon as possible.
        let mut pending_pong: Option<[u8; 8]> = None;

        // Tracks pings we have sent, awaiting pong replies.
        let mut ping_tracker = PingTracker::new();

        // Tracks the iroh nodes we know are connected to the this relay server.  Used to
        // save on a relay connection in case we want to send to this node but are not yet
        // connected to its home relay.
        let mut nodes_present: BTreeSet<NodeId> = BTreeSet::new();

        loop {
            if pending_pong.is_some() && send_state.is_ready() {
                if let Some(data) = pending_pong.take() {
                    send_state = send_state.send(SendMessage::Pong(data))?;
                    continue;
                }
            }
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    debug!("Shutdown.");
                    break Ok(());
                }
                res = &mut send_state, if send_state.is_sending() => {
                    let client = res?;
                    send_state = SendState::Ready(client);
                }
                _ = ping_tracker.timeout() => {
                    break Err(anyhow!("Ping timeout"));
                }
                msg = inbox.recv(), if send_state.is_ready() => {
                    let Some(msg) = msg else {
                        warn!("Inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_preferred) => {
                            send_state = send_state.send(SendMessage::NotePreferred(is_preferred))?;
                        }
                        ActiveRelayMessage::HasNodeRoute(peer, sender) => {
                            let has_peer = nodes_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                        ActiveRelayMessage::CheckConnection(local_ips) => {
                            match client_stream.local_addr() {
                                Some(addr) if local_ips.contains(&addr.ip()) => {
                                    let data = ping_tracker.new_ping();
                                    send_state = send_state.send(SendMessage::Ping(data))?;
                                }
                                Some(_) => break Err(anyhow!("Local IP no longer valid")),
                                None => break Err(anyhow!("No local addr, reconnecting")),
                            }
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            let addr = client_stream.local_addr();
                            sender.send(addr).ok();
                        }
                    }
                }
                item = self.relay_datagrams_send.recv() => {
                    // TODO: Read in bulk using recv_many, send in bulk.
                    let Some(datagrams) = item else {
                        warn!("Datagram inbox closed, shutdown");
                        break Ok(());
                    };
                    inactive_timeout.reset();
                    let packet_iter = PacketizeIter::<_, MAX_PAYLOAD_SIZE>::new(
                        datagrams.remote_node,
                        datagrams.datagrams,
                    )
                        .map(|p| {
                            inc_by!(MagicsockMetrics, send_relay, p.payload.len() as _);
                            SendMessage::SendPacket(p.node_id, p.payload)
                        })
                        .map(Ok);
                    send_state = send_state.send_all(packet_iter)?;
                }
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(anyhow!("Client stream finished"));
                    };
                    match msg {
                        Ok(msg) => {
                            if let Some(pong_msg) =
                                self.handle_relay_msg(msg, &mut ping_tracker, &mut nodes_present) {
                                pending_pong = Some(pong_msg);
                            }
                        }
                        Err(err) => break Err(anyhow!("Client stream read error: {err:#}")),
                    }
                }
                _ = inactive_timeout.tick(), if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting.");
                    break Ok(());
                }
            }
        }
    }

    fn handle_relay_msg(
        &mut self,
        msg: ReceivedMessage,
        ping_tracker: &mut PingTracker,
        nodes_present: &mut BTreeSet<NodeId>,
    ) -> Option<[u8; 8]> {
        match msg {
            ReceivedMessage::ReceivedPacket {
                remote_node_id,
                data,
            } => {
                trace!(len = %data.len(), "received msg");
                // If this is a new sender, register a route for this peer.
                if self
                    .last_packet_src
                    .as_ref()
                    .map(|p| *p != remote_node_id)
                    .unwrap_or(true)
                {
                    // Avoid map lookup with high throughput single peer.
                    self.last_packet_src = Some(remote_node_id);
                    nodes_present.insert(remote_node_id);
                }
                for datagram in PacketSplitIter::new(self.url.clone(), remote_node_id, data) {
                    let Ok(datagram) = datagram else {
                        warn!("Invalid packet split");
                        break;
                    };
                    if let Err(err) = self.relay_datagrams_recv.try_send(datagram) {
                        warn!("Dropping received relay packet: {err:#}");
                    }
                }
            }
            ReceivedMessage::NodeGone(node_id) => {
                nodes_present.remove(&node_id);
            }
            ReceivedMessage::Ping(data) => return Some(data),
            ReceivedMessage::Pong(data) => {
                ping_tracker.pong_received(data);
            }
            ReceivedMessage::KeepAlive
            | ReceivedMessage::Health { .. }
            | ReceivedMessage::ServerRestarting { .. } => {
                trace!("Ignoring {msg:?}");
            }
        }
        None
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
        let relay_cancel_token = self.cancel_token.child_token();
        self.active_relay_tasks.spawn(
            async move {
                // TODO: Make the actor itself infallible.
                if let Err(err) = actor.run(relay_cancel_token, inbox_rx).await {
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
        self.cancel_token.cancel();
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

/// A single datagram received from a relay server.
///
/// This could be either a QUIC or DISCO packet.
#[derive(Debug)]
pub(super) struct RelayRecvDatagram {
    pub(super) url: RelayUrl,
    pub(super) src: NodeId,
    pub(super) buf: Bytes,
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

/// Tracks pings on a single relay connection.
///
/// Only the last ping needs is useful, any previously sent ping is forgotten and ignored.
#[derive(Debug)]
struct PingTracker {
    inner: Option<PingInner>,
}

#[derive(Debug)]
struct PingInner {
    data: [u8; 8],
    deadline: Instant,
}

impl PingTracker {
    fn new() -> Self {
        Self { inner: None }
    }

    /// Starts a new ping.
    fn new_ping(&mut self) -> [u8; 8] {
        let ping_data = rand::random();
        debug!(data = ?ping_data, "Sending ping to relay server.");
        self.inner = Some(PingInner {
            data: ping_data,
            deadline: Instant::now() + PING_TIMEOUT,
        });
        ping_data
    }

    /// Updates the ping tracker with a received pong.
    ///
    /// Only the pong of the most recent ping will do anything.  There is no harm feeding
    /// any pong however.
    fn pong_received(&mut self, data: [u8; 8]) {
        if self.inner.as_ref().map(|inner| inner.data) == Some(data) {
            debug!(?data, "Pong received from relay server");
            self.inner = None;
        }
    }

    /// Cancel-safe waiting for a ping timeout.
    ///
    /// Unless the most recent sent ping times out, this will never return.
    async fn timeout(&mut self) {
        match self.inner {
            Some(PingInner { deadline, data }) => {
                tokio::time::sleep_until(deadline).await;
                debug!(?data, "Ping timeout.");
                self.inner = None;
            }
            None => future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
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
        cancel_token: CancellationToken,
        url: RelayUrl,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
        relay_datagrams_recv: Arc<RelayDatagramRecvQueue>,
        span: tracing::Span,
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
                actor.run(cancel_token, inbox_rx).await
            }
            .instrument(span),
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
        let cancel_token = CancellationToken::new();
        let actor_task = start_active_relay_actor(
            secret_key.clone(),
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            recv_datagram_queue.clone(),
            info_span!("echo-node"),
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
            let _guard = cancel_token.drop_guard();
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

    /// Sends a message to the echo node, receives the response.
    ///
    /// This takes care of retry and timeout.  Because we don't know when both the
    /// node-under-test and the echo node will be ready and datagrams aren't queued to send
    /// forever, we have to retry a few times.
    async fn send_recv_echo(
        item: RelaySendItem,
        tx: &mpsc::Sender<RelaySendItem>,
        rx: &Arc<RelayDatagramRecvQueue>,
    ) -> Result<()> {
        assert!(item.datagrams.len() == 1);
        // try for 10s in total, 500ms each.
        for _attempt in 0..20 {
            let res = tokio::time::timeout(Duration::from_millis(500), async {
                tx.send(item.clone()).await?;
                let RelayRecvDatagram {
                    url: _,
                    src: _,
                    buf,
                } = future::poll_fn(|cx| rx.poll_recv(cx)).await?;
                assert_eq!(buf.as_ref(), item.datagrams[0]);
                Ok::<_, anyhow::Error>(())
            })
            .await;
            if res.is_ok() {
                break;
            }
        }
        Ok(())
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
        let cancel_token = CancellationToken::new();
        let task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            datagram_recv_queue.clone(),
            info_span!("actor-under-test"),
        );

        // Send a datagram to our echo node.
        info!("first echo");
        let hello_send_item = RelaySendItem {
            remote_node: peer_node,
            url: relay_url.clone(),
            datagrams: smallvec![Bytes::from_static(b"hello")],
        };
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &datagram_recv_queue,
        )
        .await?;
        // send_datagram_tx.send(hello_send_item.clone()).await?;

        // // Check we get it back
        // let RelayRecvDatagram {
        //     url: _,
        //     src: _,
        //     buf,
        // } = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        // assert_eq!(buf.as_ref(), b"hello");

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
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &datagram_recv_queue,
        )
        .await?;
        // send_datagram_tx.send(hello_send_item.clone()).await?;
        // let recv = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        // assert_eq!(recv.buf.as_ref(), b"hello");

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
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &datagram_recv_queue,
        )
        .await?;
        // send_datagram_tx.send(hello_send_item).await?;
        // let recv = future::poll_fn(|cx| datagram_recv_queue.poll_recv(cx)).await?;
        // assert_eq!(recv.buf.as_ref(), b"hello");

        // Shut down the actor.
        cancel_token.cancel();
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
        let cancel_token = CancellationToken::new();
        let mut task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url,
            inbox_rx,
            send_datagram_rx,
            datagram_recv_queue.clone(),
            info_span!("actor-under-test"),
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

        cancel_token.cancel();

        Ok(())
    }

    #[tokio::test]
    async fn test_ping_tracker() {
        tokio::time::pause();
        let mut tracker = PingTracker::new();

        let ping0 = tracker.new_ping();

        let res = tokio::time::timeout(Duration::from_secs(1), tracker.timeout()).await;
        assert!(res.is_err(), "no ping timeout has elapsed yet");

        tracker.pong_received(ping0);
        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_err(), "ping completed before timeout");

        let _ping1 = tracker.new_ping();

        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_ok(), "ping timeout should have happened");

        let _ping2 = tracker.new_ping();

        tokio::time::sleep(Duration::from_secs(10)).await;
        let res = tokio::time::timeout(Duration::from_millis(1), tracker.timeout()).await;
        assert!(res.is_ok(), "ping timeout happened in the past");

        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_err(), "ping timeout should only happen once");
    }
}
