//! The relay actor.
//!
//! The [`RelayActor`] handles all the relay connections.  It is helped by the
//! [`ActiveRelayActor`] which handles a single relay connection.
//!
//! - The [`RelayActor`] manages all connections to relay servers.
//!   - It starts a new [`ActiveRelayActor`] for each relay server needed.
//!   - The [`ActiveRelayActor`] will exit when unused.
//!     - Unless it is for the home relay, this one never exits.
//!   - Each [`ActiveRelayActor`] uses a relay [`Client`].
//!     - The relay [`Client`] is a `Stream` and `Sink` directly connected to the
//!       `TcpStream` connected to the relay server.
//!   - Each [`ActiveRelayActor`] will try and maintain a connection with the relay server.
//!     - If connections fail, exponential backoff is used for reconnections.
//! - When `AsyncUdpSocket` needs to send datagrams:
//!   - It puts them on a queue to the [`RelayActor`].
//!   - The [`RelayActor`] ensures the correct [`ActiveRelayActor`] is running and
//!     forwards datagrams to it.
//!   - The ActiveRelayActor sends datagrams directly to the relay server.
//! - The relay receive path is:
//!   - Whenever [`ActiveRelayActor`] is connected it reads from the underlying `TcpStream`.
//!   - Received datagrams are placed on an mpsc channel that now bypasses the
//!     [`RelayActor`] and goes straight to the `AsyncUpdSocket` interface.
//!
//! [`Client`]: iroh_relay::client::Client

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
};

use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use bytes::{Bytes, BytesMut};
use iroh_base::{NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_relay::{
    self as relay,
    client::{Client, ConnectError, ReceivedMessage, RecvError, SendError, SendMessage},
    PingTracker, MAX_PACKET_SIZE,
};
use n0_future::{
    task::JoinSet,
    time::{self, Duration, Instant, MissedTickBehavior},
    FuturesUnorderedBounded, SinkExt, StreamExt,
};
use n0_watcher::Watchable;
use nested_enum_utils::common_fields;
use netwatch::interfaces;
use snafu::{IntoError, ResultExt, Snafu};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, event, info, info_span, instrument, trace, warn, Instrument, Level};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{
    magicsock::{Metrics as MagicsockMetrics, RelayContents},
    net_report::Report,
    util::MaybeFuture,
};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// Maximum size a datagram payload is allowed to be.
const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - PublicKey::LENGTH;

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Number of datagrams which can be sent to the relay server in one batch.
///
/// This means while this batch is sending to the server no other relay protocol frames can
/// be sent to the server, e.g. no Ping frames or so.  While the maximum packet size is
/// rather large, each item can typically be expected to up to 1500 or the max GSO size.
const SEND_DATAGRAM_BATCH_SIZE: usize = 20;

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
///
/// This value is set to 3 times the QUIC initial Probe Timeout (PTO).
const UNDELIVERABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(3);

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
///
/// The actor shuts down itself on inactivity: inactivity is determined when no more
/// datagrams are being queued to send.
///
/// This actor has 3 main states it can be in, each has it's dedicated run loop:
///
/// - Dialing the relay server.
///
///   This will continuously dial the server until connected, using exponential backoff if
///   it can not connect.  See [`ActiveRelayActor::run_dialing`].
///
/// - Connected to the relay server.
///
///   This state allows receiving from the relay server, though sending is idle in this
///   state.  See [`ActiveRelayActor::run_connected`].
///
/// - Sending to the relay server.
///
///   This is a sub-state of `connected` so the actor can still be receiving from the relay
///   server at this time.  However it is actively sending data to the server so can not
///   consume any further items from inboxes which will result in sending more data to the
///   server until the actor goes back to the `connected` state.
///
/// All these are driven from the top-level [`ActiveRelayActor::run`] loop.
#[derive(Debug)]
struct ActiveRelayActor {
    // The inboxes and channels this actor communicates over.
    /// Inbox for messages which should be handled without any blocking.
    prio_inbox: mpsc::Receiver<ActiveRelayPrioMessage>,
    /// Inbox for messages which involve sending to the relay server.
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    /// Queue for received relay datagrams.
    relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    /// Channel on which we queue packets to send to the relay.
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,

    // Other actor state.
    /// The relay server for this actor.
    url: RelayUrl,
    /// Builder which can repeatedly build a relay client.
    relay_client_builder: relay::client::ClientBuilder,
    /// Whether or not this is the home relay server.
    ///
    /// The home relay server needs to maintain it's connection to the relay server, even if
    /// the relay actor is otherwise idle.
    is_home_relay: bool,
    /// When this expires the actor has been idle and should shut down.
    ///
    /// Unless it is managing the home relay connection.  Inactivity is only tracked on the
    /// last datagram sent to the relay, received datagrams will trigger QUIC ACKs which is
    /// sufficient to keep active connections open.
    inactive_timeout: Pin<Box<time::Sleep>>,
    /// Token indicating the [`ActiveRelayActor`] should stop.
    stop_token: CancellationToken,
    metrics: Arc<MagicsockMetrics>,
}

#[derive(Debug)]
enum ActiveRelayMessage {
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
    #[cfg(test)]
    PingServer(oneshot::Sender<()>),
}

/// Messages for the [`ActiveRelayActor`] which should never block.
///
/// Most messages in the [`ActiveRelayMessage`] enum trigger sending to the relay server,
/// which can be blocking.  So the actor may not always be processing that inbox.  Messages
/// here are processed immediately.
#[derive(Debug)]
enum ActiveRelayPrioMessage {
    /// Returns whether or not this relay can reach the NodeId.
    HasNodeRoute(NodeId, oneshot::Sender<bool>),
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
struct ActiveRelayActorOptions {
    url: RelayUrl,
    prio_inbox_: mpsc::Receiver<ActiveRelayPrioMessage>,
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    connection_opts: RelayConnectionOptions,
    stop_token: CancellationToken,
    metrics: Arc<MagicsockMetrics>,
}

/// Configuration needed to create a connection to a relay server.
#[derive(Debug, Clone)]
struct RelayConnectionOptions {
    secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_cert_verify: bool,
}

/// Possible reasons for a failed relay connection.
#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
enum RelayConnectionError {
    #[snafu(display("Failed to connect to relay server"))]
    Dial { source: DialError },
    #[snafu(display("Failed to handshake with relay server"))]
    Handshake { source: RunError },
    #[snafu(display("Lost connection to relay server"))]
    Established { source: RunError },
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
enum RunError {
    #[snafu(display("Send timeout"))]
    SendTimeout {},
    #[snafu(display("Ping timeout"))]
    PingTimeout {},
    #[snafu(display("Local IP no longer valid"))]
    LocalIpInvalid {},
    #[snafu(display("No local address"))]
    LocalAddrMissing {},
    #[snafu(display("Stream closed by server."))]
    StreamClosedServer {},
    #[snafu(display("Client stream read failed"))]
    ClientStreamRead { source: RecvError },
    #[snafu(display("Client stream write failed"))]
    ClientStreamWrite { source: SendError },
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
enum DialError {
    #[snafu(display("timeout trying to establish a connection"))]
    Timeout {},
    #[snafu(display("unable to connect"))]
    Connect {
        #[snafu(source(from(ConnectError, Box::new)))]
        source: Box<ConnectError>,
    },
}

impl ActiveRelayActor {
    fn new(opts: ActiveRelayActorOptions) -> Self {
        let ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_inbox,
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts,
            stop_token,
            metrics,
        } = opts;
        let relay_client_builder = Self::create_relay_builder(url.clone(), connection_opts);
        ActiveRelayActor {
            prio_inbox,
            inbox,
            relay_datagrams_recv,
            relay_datagrams_send,
            url,
            relay_client_builder,
            is_home_relay: false,
            inactive_timeout: Box::pin(time::sleep(RELAY_INACTIVE_CLEANUP_TIME)),
            stop_token,
            metrics,
        }
    }

    fn create_relay_builder(
        url: RelayUrl,
        opts: RelayConnectionOptions,
    ) -> relay::client::ClientBuilder {
        let RelayConnectionOptions {
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            prefer_ipv6,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify,
        } = opts;

        let mut builder = relay::client::ClientBuilder::new(
            url,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
        )
        .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }
        #[cfg(any(test, feature = "test-utils"))]
        let builder = builder.insecure_skip_cert_verify(insecure_skip_cert_verify);
        builder
    }

    /// The main actor run loop.
    ///
    /// Primarily switches between the dialing and connected states.
    async fn run(mut self) {
        // TODO(frando): decide what this metric means, it's either wrong here or in node_state.rs.
        // From the existing description, it is wrong here.
        // self.metrics.num_relay_conns_added.inc();

        let mut backoff = Self::build_backoff();

        while let Err(err) = self.run_once().await {
            warn!("{err}");
            match err {
                RelayConnectionError::Dial { .. } | RelayConnectionError::Handshake { .. } => {
                    // If dialing failed, or if the relay connection failed before we received a pong,
                    // we wait an exponentially increasing time until we attempt to reconnect again.
                    let Some(delay) = backoff.next() else {
                        warn!("retries exceeded");
                        break;
                    };
                    debug!("retry in {delay:?}");
                    time::sleep(delay).await;
                }
                RelayConnectionError::Established { .. } => {
                    // If the relay connection remained established long enough so that we received a pong
                    // from the relay server, we reset the backoff and attempt to reconnect immediately.
                    backoff = Self::build_backoff();
                }
            }
        }
        debug!("exiting");
        // TODO(frando): decide what this metric means, it's either wrong here or in node_state.rs.
        // From the existing description, it is wrong here.
        // self.metrics.num_relay_conns_removed.inc();
    }

    fn build_backoff() -> impl Backoff {
        ExponentialBuilder::new()
            .with_min_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(16))
            .with_jitter()
            .without_max_times()
            .build()
    }

    /// Attempt to connect to the relay, and run the connected actor loop.
    ///
    /// Returns `Ok(())` if the actor loop should shut down. Returns an error if dialing failed,
    /// or if the relay connection failed while connected. In both cases, the connection should
    /// be retried with a backoff.
    async fn run_once(&mut self) -> Result<(), RelayConnectionError> {
        let client = match self.run_dialing().instrument(info_span!("dialing")).await {
            Some(client_res) => client_res.context(DialSnafu)?,
            None => return Ok(()),
        };
        self.run_connected(client)
            .instrument(info_span!("connected"))
            .await
    }

    fn reset_inactive_timeout(&mut self) {
        self.inactive_timeout
            .as_mut()
            .reset(Instant::now() + RELAY_INACTIVE_CLEANUP_TIME);
    }

    fn set_home_relay(&mut self, is_home: bool) {
        let prev = std::mem::replace(&mut self.is_home_relay, is_home);
        if self.is_home_relay != prev {
            event!(
                target: "iroh::_events::relay::home_changed",
                Level::DEBUG,
                url = %self.url,
                home_relay = self.is_home_relay,
            );
        }
    }

    /// Actor loop when connecting to the relay server.
    ///
    /// Returns `None` if the actor needs to shut down.  Returns `Some(Ok(client))` when the
    /// connection is established, and `Some(Err(err))` if dialing the relay failed.
    async fn run_dialing(&mut self) -> Option<Result<iroh_relay::client::Client, DialError>> {
        debug!("Actor loop: connecting to relay.");

        // We regularly flush the relay_datagrams_send queue so it is not full of stale
        // packets while reconnecting.  Those datagrams are dropped and the QUIC congestion
        // controller will have to handle this (DISCO packets do not yet have retry).  This
        // is not an ideal mechanism, an alternative approach would be to use
        // e.g. ConcurrentQueue with force_push, though now you might still send very stale
        // packets when eventually connected.  So perhaps this is a reasonable compromise.
        let mut send_datagram_flush = time::interval(UNDELIVERABLE_DATAGRAM_TIMEOUT);
        send_datagram_flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
        send_datagram_flush.reset(); // Skip the immediate interval

        let dialing_fut = self.dial_relay();
        tokio::pin!(dialing_fut);
        loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break None;
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasNodeRoute(_peer, sender) => {
                            sender.send(false).ok();
                        }
                    }
                }
                res = &mut dialing_fut => {
                    match res {
                        Ok(client) => {
                            break Some(Ok(client));
                        }
                        Err(err) => {
                            break Some(Err(err));
                        }
                    }
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                        }
                        ActiveRelayMessage::CheckConnection(_local_ips) => {}
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(None).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            drop(sender);
                        }
                    }
                }
                _ = send_datagram_flush.tick() => {
                    self.reset_inactive_timeout();
                    let mut logged = false;
                    while self.relay_datagrams_send.try_recv().is_ok() {
                        if !logged {
                            debug!(?UNDELIVERABLE_DATAGRAM_TIMEOUT, "Dropping datagrams to send.");
                            logged = true;
                        }
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!(?RELAY_INACTIVE_CLEANUP_TIME, "Inactive, exiting.");
                    break None;
                }
            }
        }
    }

    /// Returns a future which will complete once connected to the relay server.
    ///
    /// The future only completes once the connection is established and retries
    /// connections.  It currently does not ever return `Err` as the retries continue
    /// forever.
    // This is using `impl Future` to return a future without a reference to self.
    fn dial_relay(&self) -> impl Future<Output = Result<Client, DialError>> + use<> {
        let client_builder = self.relay_client_builder.clone();
        async move {
            match time::timeout(CONNECT_TIMEOUT, client_builder.connect()).await {
                Ok(Ok(client)) => Ok(client),
                Ok(Err(err)) => Err(ConnectSnafu.into_error(err)),
                Err(_) => Err(TimeoutSnafu.build()),
            }
        }
    }

    /// Runs the actor loop when connected to a relay server.
    ///
    /// Returns `Ok` if the actor needs to shut down.  `Err` is returned if the connection
    /// to the relay server is lost.
    async fn run_connected(
        &mut self,
        client: iroh_relay::client::Client,
    ) -> Result<(), RelayConnectionError> {
        debug!("Actor loop: connected to relay");
        event!(
            target: "iroh::_events::relay::connected",
            Level::DEBUG,
            url = %self.url,
            home_relay = self.is_home_relay,
        );

        let (mut client_stream, client_sink) = client.split();
        let mut client_sink = client_sink.sink_map_err(|e| ClientStreamWriteSnafu.into_error(e));

        let mut state = ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            nodes_present: BTreeSet::new(),
            last_packet_src: None,
            pong_pending: None,
            established: false,
            #[cfg(test)]
            test_pong: None,
        };

        // A buffer to pass through multiple datagrams at once as an optimisation.
        let mut send_datagrams_buf = Vec::with_capacity(SEND_DATAGRAM_BATCH_SIZE);

        // Regularly send pings so we know the connection is healthy.
        // The first ping will be sent immediately.
        let mut ping_interval = time::interval(PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let res = loop {
            if let Some(data) = state.pong_pending.take() {
                let fut = client_sink.send(SendMessage::Pong(data));
                self.run_sending(fut, &mut state, &mut client_stream)
                    .await?;
            }
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break Ok(());
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasNodeRoute(peer, sender) => {
                            let has_peer = state.nodes_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                    }
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(PingTimeoutSnafu.build());
                }
                _ = ping_interval.tick() => {
                    let data = state.ping_tracker.new_ping();
                    let fut = client_sink.send(SendMessage::Ping(data));
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                        }
                        ActiveRelayMessage::CheckConnection(local_ips) => {
                            match client_stream.local_addr() {
                                Some(addr) if local_ips.contains(&addr.ip()) => {
                                    let data = state.ping_tracker.new_ping();
                                    let fut = client_sink.send(SendMessage::Ping(data));
                                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                                }
                                Some(_) => break Err(LocalIpInvalidSnafu.build()),
                                None => break Err(LocalAddrMissingSnafu.build()),
                            }
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            let addr = client_stream.local_addr();
                            sender.send(addr).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            let data = rand::random();
                            state.test_pong = Some((data, sender));
                            let fut = client_sink.send(SendMessage::Ping(data));
                            self.run_sending(fut, &mut state, &mut client_stream).await?;
                        }
                    }
                }
                count = self.relay_datagrams_send.recv_many(
                    &mut send_datagrams_buf,
                    SEND_DATAGRAM_BATCH_SIZE,
                ) => {
                    if count == 0 {
                        warn!("Datagram inbox closed, shutdown");
                        break Ok(());
                    };
                    self.reset_inactive_timeout();
                    // TODO: This allocation is *very* unfortunate.  But so is the
                    // allocation *inside* of PacketizeIter...
                    let dgrams = std::mem::replace(
                        &mut send_datagrams_buf,
                        Vec::with_capacity(SEND_DATAGRAM_BATCH_SIZE),
                    );
                    // TODO(frando): can we avoid the clone here?
                    let metrics = self.metrics.clone();
                    let packet_iter = dgrams.into_iter().flat_map(|datagrams| {
                        PacketizeIter::<_, MAX_PAYLOAD_SIZE>::new(
                            datagrams.remote_node,
                            datagrams.datagrams.clone(),
                        )
                        .map(|p| {
                            Ok(SendMessage::SendPacket(p.node_id, p.payload))
                        })
                    });
                    let mut packet_stream = n0_future::stream::iter(packet_iter).inspect(|m| {
                        if let Ok(SendMessage::SendPacket(_node_id, payload)) = m {
                            metrics.send_relay.inc_by(payload.len() as _);
                        }
                    });
                    let fut = client_sink.send_all(&mut packet_stream);
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(StreamClosedServerSnafu.build());
                    };
                    match msg {
                        Ok(msg) => {
                            self.handle_relay_msg(msg, &mut state);
                            // reset the ping timer, we have just received a message
                            ping_interval.reset();
                        },
                        Err(err) => break Err(ClientStreamReadSnafu.into_error(err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting.");
                    break Ok(());
                }
            }
        };

        if res.is_ok() {
            if let Err(err) = client_sink.close().await {
                debug!("Failed to close client sink gracefully: {err:#}");
            }
        }

        res.map_err(|err| state.map_err(err))
    }

    fn handle_relay_msg(&mut self, msg: ReceivedMessage, state: &mut ConnectedRelayState) {
        match msg {
            ReceivedMessage::ReceivedPacket {
                remote_node_id,
                data,
            } => {
                trace!(len = %data.len(), "received msg");
                // If this is a new sender, register a route for this peer.
                if state
                    .last_packet_src
                    .as_ref()
                    .map(|p| *p != remote_node_id)
                    .unwrap_or(true)
                {
                    // Avoid map lookup with high throughput single peer.
                    state.last_packet_src = Some(remote_node_id);
                    state.nodes_present.insert(remote_node_id);
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
                state.nodes_present.remove(&node_id);
            }
            ReceivedMessage::Ping(data) => state.pong_pending = Some(data),
            ReceivedMessage::Pong(data) => {
                #[cfg(test)]
                {
                    if let Some((expected_data, sender)) = state.test_pong.take() {
                        if data == expected_data {
                            sender.send(()).ok();
                        } else {
                            state.test_pong = Some((expected_data, sender));
                        }
                    }
                }
                state.ping_tracker.pong_received(data);
                state.established = true;
            }
            ReceivedMessage::Health { problem } => {
                let problem = problem.as_deref().unwrap_or("unknown");
                warn!("Relay server reports problem: {problem}");
            }
            ReceivedMessage::KeepAlive | ReceivedMessage::ServerRestarting { .. } => {
                trace!("Ignoring {msg:?}")
            }
        }
    }

    /// Run the actor main loop while sending to the relay server.
    ///
    /// While sending the actor should not read any inboxes which will give it more things
    /// to send to the relay server.
    ///
    /// # Returns
    ///
    /// On `Err` the relay connection should be disconnected.  An `Ok` return means either
    /// the actor should shut down, consult the [`ActiveRelayActor::stop_token`] and
    /// [`ActiveRelayActor::inactive_timeout`] for this, or the send was successful.
    #[instrument(name = "tx", skip_all)]
    async fn run_sending<T>(
        &mut self,
        sending_fut: impl Future<Output = Result<T, RunError>>,
        state: &mut ConnectedRelayState,
        client_stream: &mut iroh_relay::client::ClientStream,
    ) -> Result<(), RelayConnectionError> {
        // we use the same time as for our ping interval
        let send_timeout = PING_INTERVAL;

        let mut timeout = pin!(time::sleep(send_timeout));
        let mut sending_fut = pin!(sending_fut);
        let res = loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    break Ok(());
                }
                _ = &mut timeout => {
                    break Err(SendTimeoutSnafu.build());
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasNodeRoute(peer, sender) => {
                            let has_peer = state.nodes_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                    }
                }
                res = &mut sending_fut => {
                    match res {
                        Ok(_) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(PingTimeoutSnafu.build());
                }
                // No need to read the inbox or datagrams to send.
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(StreamClosedServerSnafu.build());
                    };
                    match msg {
                        Ok(msg) => self.handle_relay_msg(msg, state),
                        Err(err) => break Err(ClientStreamReadSnafu.into_error(err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting.");
                    break Ok(());
                }
            }
        };
        res.map_err(|err| state.map_err(err))
    }
}

/// Shared state when the [`ActiveRelayActor`] is connected to a relay server.
///
/// Common state between [`ActiveRelayActor::run_connected`] and
/// [`ActiveRelayActor::run_sending`].
#[derive(Debug)]
struct ConnectedRelayState {
    /// Tracks pings we have sent, awaits pong replies.
    ping_tracker: PingTracker,
    /// Nodes which are reachable via this relay server.
    nodes_present: BTreeSet<NodeId>,
    /// The [`NodeId`] from whom we received the last packet.
    ///
    /// This is to avoid a slower lookup in the [`ConnectedRelayState::nodes_present`] map
    /// when we are only communicating to a single remote node.
    last_packet_src: Option<NodeId>,
    /// A pong we need to send ASAP.
    pong_pending: Option<[u8; 8]>,
    /// Whether the connection is to be considered established.
    ///
    /// This is set to `true` once a pong was received from the server.
    established: bool,
    #[cfg(test)]
    test_pong: Option<([u8; 8], oneshot::Sender<()>)>,
}

impl ConnectedRelayState {
    fn map_err(&self, error: RunError) -> RelayConnectionError {
        if self.established {
            EstablishedSnafu.into_error(error)
        } else {
            HandshakeSnafu.into_error(error)
        }
    }
}

pub(super) enum RelayActorMessage {
    MaybeCloseRelaysOnRebind,
    NetworkChange { report: Report },
}

#[derive(Debug, Clone)]
pub(crate) struct RelaySendItem {
    /// The destination for the datagrams.
    pub(crate) remote_node: NodeId,
    /// The home relay of the remote node.
    pub(crate) url: RelayUrl,
    /// One or more datagrams to send.
    pub(crate) datagrams: RelayContents,
}

pub(super) struct RelayActor {
    config: Config,
    /// Queue on which to put received datagrams.
    relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
    /// The actors managing each currently used relay server.
    ///
    /// These actors will exit when they have any inactivity.  Otherwise they will keep
    /// trying to maintain a connection to the relay server as needed.
    active_relays: BTreeMap<RelayUrl, ActiveRelayHandle>,
    /// The tasks for the [`ActiveRelayActor`]s in `active_relays` above.
    active_relay_tasks: JoinSet<()>,
    cancel_token: CancellationToken,
}

#[derive(Debug)]
pub struct Config {
    pub my_relay: Watchable<Option<RelayUrl>>,
    pub secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    pub dns_resolver: DnsResolver,
    /// Proxy
    pub proxy_url: Option<Url>,
    /// If the last net_report report, reports IPv6 to be available.
    pub ipv6_reported: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-utils"))]
    pub insecure_skip_relay_cert_verify: bool,
    pub metrics: Arc<MagicsockMetrics>,
}

impl RelayActor {
    pub(super) fn new(
        config: Config,
        relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
    ) -> Self {
        let cancel_token = CancellationToken::new();
        Self {
            config,
            relay_datagram_recv_queue,
            active_relays: Default::default(),
            active_relay_tasks: JoinSet::new(),
            cancel_token,
        }
    }

    pub(super) async fn run(
        mut self,
        mut receiver: mpsc::Receiver<RelayActorMessage>,
        mut datagram_send_channel: mpsc::Receiver<RelaySendItem>,
    ) {
        // When this future is present, it is sending pending datagrams to an
        // ActiveRelayActor.  We can not process further datagrams during this time.
        let mut datagram_send_fut = std::pin::pin!(MaybeFuture::none());

        loop {
            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    debug!("shutting down");
                    break;
                }
                Some(res) = self.active_relay_tasks.join_next() => {
                    match res {
                        Ok(()) => (),
                        Err(err) if err.is_panic() => {
                            error!("ActiveRelayActor task panicked: {err:#?}");
                        }
                        Err(err) if err.is_cancelled() => {
                            error!("ActiveRelayActor cancelled: {err:#?}");
                        }
                        Err(err) => error!("ActiveRelayActor failed: {err:#?}"),
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
                _ = &mut datagram_send_fut, if datagram_send_fut.is_some() => {
                    datagram_send_fut.as_mut().set_none();
                }
            }
        }

        // try shutdown
        if time::timeout(Duration::from_secs(3), self.close_all_active_relays())
            .await
            .is_err()
        {
            warn!("Failed to shut down all ActiveRelayActors");
        }
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::NetworkChange { report } => {
                self.on_network_change(report).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind => {
                self.maybe_close_relays_on_rebind().await;
            }
        }
    }

    /// Sends datagrams to the correct [`ActiveRelayActor`], or returns a future.
    ///
    /// If the datagram can not be sent immediately, because the destination channel is
    /// full, a future is returned that will complete once the datagrams have been sent to
    /// the [`ActiveRelayActor`].
    async fn try_send_datagram(
        &mut self,
        item: RelaySendItem,
    ) -> Option<impl Future<Output = ()> + use<>> {
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

    async fn on_network_change(&mut self, report: Report) {
        let my_relay = self.config.my_relay.get();
        if report.preferred_relay == my_relay {
            // No change.
            return;
        }
        let old_relay = self
            .config
            .my_relay
            .set(report.preferred_relay.clone())
            .unwrap_or_else(|e| e);

        if let Some(relay_url) = report.preferred_relay {
            self.config.metrics.relay_home_change.inc();

            // On change, notify all currently connected relay servers and
            // start connecting to our home relay if we are not already.
            info!("home is now relay {}, was {:?}", relay_url, old_relay);
            self.set_home_relay(relay_url).await;
        }
    }

    async fn set_home_relay(&mut self, home_url: RelayUrl) {
        let home_url_ref = &home_url;
        n0_future::join_all(self.active_relays.iter().map(|(url, handle)| async move {
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
        {
            // Futures which return Some(RelayUrl) if the relay knows about the remote node.
            let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
                let (tx, rx) = oneshot::channel();
                handle
                    .prio_inbox_addr
                    .send(ActiveRelayPrioMessage::HasNodeRoute(*remote_node, tx))
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
                if Some(&url) == self.config.my_relay.get().as_ref() {
                    if let Err(err) = handle
                        .inbox_addr
                        .try_send(ActiveRelayMessage::SetHomeRelay(true))
                    {
                        error!("Home relay not set, send to new actor failed: {err:#}.");
                    }
                }
                self.active_relays.insert(url, handle.clone());
                self.log_active_relay();
                handle
            }
        }
    }

    fn start_active_relay(&mut self, url: RelayUrl) -> ActiveRelayHandle {
        debug!(?url, "Adding relay connection");

        let connection_opts = RelayConnectionOptions {
            secret_key: self.config.secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: self.config.dns_resolver.clone(),
            proxy_url: self.config.proxy_url.clone(),
            prefer_ipv6: self.config.ipv6_reported.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: self.config.insecure_skip_relay_cert_verify,
        };

        // TODO: Replace 64 with PER_CLIENT_SEND_QUEUE_DEPTH once that's unused
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(64);
        let (prio_inbox_tx, prio_inbox_rx) = mpsc::channel(32);
        let (inbox_tx, inbox_rx) = mpsc::channel(64);
        let span = info_span!("active-relay", %url);
        let opts = ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_inbox_rx,
            inbox: inbox_rx,
            relay_datagrams_send: send_datagram_rx,
            relay_datagrams_recv: self.relay_datagram_recv_queue.clone(),
            connection_opts,
            stop_token: self.cancel_token.child_token(),
            metrics: self.config.metrics.clone(),
        };
        let actor = ActiveRelayActor::new(opts);
        self.active_relay_tasks.spawn(
            async move {
                actor.run().await;
            }
            .instrument(span),
        );
        let handle = ActiveRelayHandle {
            prio_inbox_addr: prio_inbox_tx,
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
    async fn maybe_close_relays_on_rebind(&mut self) {
        #[cfg(not(wasm_browser))]
        let ifs = interfaces::State::new().await;
        #[cfg(not(wasm_browser))]
        let local_ips: Vec<_> = ifs
            .interfaces
            .values()
            .flat_map(|netif| netif.addrs())
            .map(|ipnet| ipnet.addr())
            .collect();
        // In browsers, we don't have this information. This will do the right thing in the ActiveRelayActor, though.
        #[cfg(wasm_browser)]
        let local_ips = Vec::new();
        let send_futs = self.active_relays.values().map(|handle| {
            let local_ips = local_ips.clone();
            async move {
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::CheckConnection(local_ips))
                    .await
                    .ok();
            }
        });
        n0_future::join_all(send_futs).await;
        self.log_active_relay();
    }

    /// Cleans up [`ActiveRelayActor`]s which have stopped running.
    fn reap_active_relays(&mut self) {
        self.active_relays
            .retain(|_url, handle| !handle.inbox_addr.is_closed());

        // Make sure home relay exists
        if let Some(url) = self.config.my_relay.get() {
            self.active_relay_handle(url);
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
                    s += &format!(" relay-{node}");
                }
            }
            s
        });
    }

    fn active_relay_sorted(&self) -> impl Iterator<Item = RelayUrl> + use<> {
        let mut ids: Vec<_> = self.active_relays.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

/// Handle to one [`ActiveRelayActor`].
#[derive(Debug, Clone)]
struct ActiveRelayHandle {
    prio_inbox_addr: mpsc::Sender<ActiveRelayPrioMessage>,
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
pub(crate) struct RelayRecvDatagram {
    pub(crate) url: RelayUrl,
    pub(crate) src: NodeId,
    pub(crate) buf: Bytes,
}

/// Combines datagrams into a single DISCO frame of at most MAX_PACKET_SIZE.
///
/// The disco `iroh_relay::protos::Frame::SendPacket` frame can contain more then a single
/// datagram.  Each datagram in this frame is prefixed with a little-endian 2-byte length
/// prefix.  This occurs when Quinn sends a GSO transmit containing more than one datagram,
/// which are split using `split_packets`.
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
    use std::{
        sync::{atomic::AtomicBool, Arc},
        time::Duration,
    };

    use bytes::Bytes;
    use iroh_base::{NodeId, RelayUrl, SecretKey};
    use iroh_relay::PingTracker;
    use n0_snafu::{Error, Result, ResultExt};
    use smallvec::smallvec;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
    use tracing::{info, info_span, Instrument};
    use tracing_test::traced_test;

    use super::{
        ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayMessage, ActiveRelayPrioMessage,
        PacketizeIter, RelayConnectionOptions, RelayRecvDatagram, RelaySendItem, MAX_PACKET_SIZE,
        RELAY_INACTIVE_CLEANUP_TIME, UNDELIVERABLE_DATAGRAM_TIMEOUT,
    };
    use crate::{dns::DnsResolver, test_utils};

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
    #[allow(clippy::too_many_arguments)]
    fn start_active_relay_actor(
        secret_key: SecretKey,
        stop_token: CancellationToken,
        url: RelayUrl,
        prio_inbox_rx: mpsc::Receiver<ActiveRelayPrioMessage>,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
        relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
        span: tracing::Span,
    ) -> AbortOnDropHandle<()> {
        let opts = ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_inbox_rx,
            inbox: inbox_rx,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key,
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(true)),
                insecure_skip_cert_verify: true,
            },
            stop_token,
            metrics: Default::default(),
        };
        let task = tokio::spawn(ActiveRelayActor::new(opts).run().instrument(span));
        AbortOnDropHandle::new(task)
    }

    /// Starts an [`ActiveRelayActor`] as an "iroh echo node".
    ///
    /// This actor will connect to the relay server, pretending to be an iroh node, and echo
    /// back any datagram it receives from the relay.  This is used by the
    /// [`ActiveRelayNode`] under test to check connectivity works.
    fn start_echo_node(relay_url: RelayUrl) -> (NodeId, AbortOnDropHandle<()>) {
        let secret_key = SecretKey::from_bytes(&[8u8; 32]);
        let (recv_datagram_tx, mut recv_datagram_rx) = mpsc::channel(16);
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let actor_task = start_active_relay_actor(
            secret_key.clone(),
            cancel_token.clone(),
            relay_url.clone(),
            prio_inbox_rx,
            inbox_rx,
            send_datagram_rx,
            recv_datagram_tx,
            info_span!("echo-node"),
        );
        let echo_task = tokio::spawn({
            let relay_url = relay_url.clone();
            async move {
                loop {
                    let datagram = recv_datagram_rx.recv().await;
                    if let Some(recv) = datagram {
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
            // move the inboxes here so it is not dropped, as this stops the actor.
            let _prio_inbox_tx = prio_inbox_tx;
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
        rx: &mut mpsc::Receiver<RelayRecvDatagram>,
    ) -> Result<()> {
        assert!(item.datagrams.len() == 1);
        tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                let res = tokio::time::timeout(UNDELIVERABLE_DATAGRAM_TIMEOUT, async {
                    tx.send(item.clone()).await.context("send item")?;
                    let RelayRecvDatagram {
                        url: _,
                        src: _,
                        buf,
                    } = rx.recv().await.unwrap();

                    assert_eq!(buf.as_ref(), item.datagrams[0]);

                    Ok::<_, Error>(())
                })
                .await;
                if res.is_ok() {
                    break;
                }
            }
        })
        .await
        .expect("overall timeout exceeded");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_active_relay_reconnect() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let (peer_node, _echo_node_task) = start_echo_node(relay_url.clone());

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let (datagram_recv_tx, mut datagram_recv_rx) = mpsc::channel(16);
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (_prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url.clone(),
            prio_inbox_rx,
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx.clone(),
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
            &mut datagram_recv_rx,
        )
        .await?;

        // Now ask to check the connection, triggering a ping but no reconnect.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .context("send get local addr msg")?;

        let local_addr = rx
            .await
            .context("wait for local addr msg")?
            .context("no local addr")?;
        info!(?local_addr, "check connection with addr");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection(vec![local_addr.ip()]))
            .await
            .context("send check connection message")?;

        // Sync the ActiveRelayActor. Ping blocks it and we want to be sure it has handled
        // another inbox message before continuing.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .context("send get local addr msg")?;
        rx.await.context("recv send local addr msg")?;

        // Echo should still work.
        info!("second echo");
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &mut datagram_recv_rx,
        )
        .await?;

        // Now ask to check the connection, this will reconnect without pinging because we
        // do not supply any "valid" local IP addresses.
        info!("check connection");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection(Vec::new()))
            .await
            .context("send check connection msg")?;

        // Give some time to reconnect, mostly to sort logs rather than functional.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Echo should still work.
        info!("third echo");
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &mut datagram_recv_rx,
        )
        .await?;

        // Shut down the actor.
        cancel_token.cancel();
        task.await.context("wait for task to finish")?;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_active_relay_inactive() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let (datagram_recv_tx, _datagram_recv_rx) = mpsc::channel(16);
        let (_send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (_prio_inbox_tx, prio_inbox_rx) = mpsc::channel(8);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let mut task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url,
            prio_inbox_rx,
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx,
            info_span!("actor-under-test"),
        );

        // Wait until the actor is connected to the relay server.
        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                let (tx, rx) = oneshot::channel();
                inbox_tx.send(ActiveRelayMessage::PingServer(tx)).await.ok();
                if tokio::time::timeout(Duration::from_millis(100), rx)
                    .await
                    .map(|resp| resp.is_ok())
                    .unwrap_or_default()
                {
                    break;
                }
            }
        })
        .await
        .context("timeout")?;

        // From now on, we pause time
        tokio::time::pause();
        // We now have an idling ActiveRelayActor.  If we advance time just a little it
        // should stay alive.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME / 2");
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME / 2).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "actor task terminated"
        );

        // If we advance time a lot it should finish.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME");
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME).await;
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
        let mut tracker = PingTracker::default();

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
