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
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::{
    self as relay, PingTracker,
    client::{Client, ConnectError, RecvError, SendError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
};
use n0_error::{e, stack_error};
use n0_future::{
    FuturesUnorderedBounded, SinkExt, StreamExt,
    task::JoinSet,
    time::{self, Duration, Instant, MissedTickBehavior},
};
use n0_watcher::Watchable;
use netwatch::interfaces;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, error, event, info, info_span, instrument, trace, warn};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{net_report::Report, socket::Metrics as SocketMetrics, util::MaybeFuture};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

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
    metrics: Arc<SocketMetrics>,
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
    /// Returns whether or not this relay can reach the EndpointId.
    HasEndpointRoute(EndpointId, oneshot::Sender<bool>),
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
    metrics: Arc<SocketMetrics>,
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
#[stack_error(derive, add_meta)]
enum RelayConnectionError {
    #[error("Failed to connect to relay server")]
    Dial { source: DialError },
    #[error("Failed to handshake with relay server")]
    Handshake { source: RunError },
    #[error("Lost connection to relay server")]
    Established { source: RunError },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum RunError {
    #[error("Send timeout")]
    SendTimeout,
    #[error("Ping timeout")]
    PingTimeout,
    #[error("Local IP no longer valid")]
    LocalIpInvalid,
    #[error("No local address")]
    LocalAddrMissing,
    #[error("Stream closed by server.")]
    StreamClosedServer,
    #[error("Client stream read failed")]
    ClientStreamRead {
        #[error(std_err)]
        source: RecvError,
    },
    #[error("Client stream write failed")]
    ClientStreamWrite {
        #[error(std_err)]
        source: SendError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum DialError {
    #[error("timeout (>{timeout:?}) trying to establish a connection")]
    Timeout { timeout: Duration },
    #[error("unable to connect")]
    Connect { source: ConnectError },
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
            Some(client_res) => client_res.map_err(|err| e!(RelayConnectionError::Dial, err))?,
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
        trace!("Actor loop: connecting to relay.");

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
                        ActiveRelayPrioMessage::HasEndpointRoute(_peer, sender) => {
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
                Ok(Err(err)) => Err(e!(DialError::Connect, err)),
                Err(_) => Err(e!(DialError::Timeout {
                    timeout: CONNECT_TIMEOUT
                })),
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
        let mut client_sink = client_sink.sink_map_err(|e| e!(RunError::ClientStreamWrite, e));

        let mut state = ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            endpoints_present: BTreeSet::new(),
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
                let fut = client_sink.send(ClientToRelayMsg::Pong(data));
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
                        ActiveRelayPrioMessage::HasEndpointRoute(peer, sender) => {
                            let has_peer = state.endpoints_present.contains(&peer);
                            sender.send(has_peer).ok();
                        }
                    }
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(e!(RunError::PingTimeout));
                }
                _ = ping_interval.tick() => {
                    let data = state.ping_tracker.new_ping();
                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
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
                                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                                }
                                Some(_) => break Err(e!(RunError::LocalIpInvalid)),
                                None => break Err(e!(RunError::LocalAddrMissing)),
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
                            let fut = client_sink.send(ClientToRelayMsg::Ping(data));
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
                    // TODO(frando): can we avoid the clone here?
                    let metrics = self.metrics.clone();
                    let packet_iter = send_datagrams_buf.drain(..).map(|item| {
                        metrics.send_relay.inc_by(item.datagrams.contents.len() as _);
                        Ok(ClientToRelayMsg::Datagrams {
                            dst_endpoint_id: item.remote_endpoint,
                            datagrams: item.datagrams,
                        })
                    });
                    let mut packet_stream = n0_future::stream::iter(packet_iter);
                    let fut = client_sink.send_all(&mut packet_stream);
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => {
                            self.handle_relay_msg(msg, &mut state);
                            // reset the ping timer, we have just received a message
                            ping_interval.reset();
                        },
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (running).");
                    break Ok(());
                }
            }
        };

        if res.is_ok()
            && let Err(err) = client_sink.close().await
        {
            debug!("Failed to close client sink gracefully: {err:#}");
        }

        res.map_err(|err| state.map_err(err))
    }

    fn handle_relay_msg(&mut self, msg: RelayToClientMsg, state: &mut ConnectedRelayState) {
        match msg {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                trace!(len = datagrams.contents.len(), "received msg");
                // If this is a new sender, register a route for this peer.
                if state
                    .last_packet_src
                    .as_ref()
                    .map(|p| *p != remote_endpoint_id)
                    .unwrap_or(true)
                {
                    // Avoid map lookup with high throughput single peer.
                    state.last_packet_src = Some(remote_endpoint_id);
                    state.endpoints_present.insert(remote_endpoint_id);
                }

                if let Err(err) = self.relay_datagrams_recv.try_send(RelayRecvDatagram {
                    url: self.url.clone(),
                    src: remote_endpoint_id,
                    datagrams,
                }) {
                    warn!("Dropping received relay packet: {err:#}");
                }
            }
            RelayToClientMsg::EndpointGone(endpoint_id) => {
                state.endpoints_present.remove(&endpoint_id);
            }
            RelayToClientMsg::Ping(data) => state.pong_pending = Some(data),
            RelayToClientMsg::Pong(data) => {
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
            RelayToClientMsg::Health { problem } => {
                warn!("Relay server reports problem: {problem}");
            }
            RelayToClientMsg::Restarting { .. } => {
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
                    break Err(e!(RunError::SendTimeout));
                }
                msg = self.prio_inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Priority inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayPrioMessage::HasEndpointRoute(peer, sender) => {
                            let has_peer = state.endpoints_present.contains(&peer);
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
                    break Err(e!(RunError::PingTimeout));
                }
                // No need to read the inbox or datagrams to send.
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => self.handle_relay_msg(msg, state),
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (sending).");
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
    /// Endpoints which are reachable via this relay server.
    endpoints_present: BTreeSet<EndpointId>,
    /// The [`EndpointId`] from whom we received the last packet.
    ///
    /// This is to avoid a slower lookup in the [`ConnectedRelayState::endpoints_present`] map
    /// when we are only communicating to a single remote endpoint.
    last_packet_src: Option<EndpointId>,
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
            e!(RelayConnectionError::Established, error)
        } else {
            e!(RelayConnectionError::Handshake, error)
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
    pub(crate) remote_endpoint: EndpointId,
    /// The home relay of the remote endpoint.
    pub(crate) url: RelayUrl,
    /// One or more datagrams to send.
    pub(crate) datagrams: Datagrams,
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

#[derive(Debug, Clone)]
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
    pub metrics: Arc<SocketMetrics>,
}

impl RelayActor {
    pub(super) fn new(
        config: Config,
        relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
        cancel_token: CancellationToken,
    ) -> Self {
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
            .active_relay_handle_for_endpoint(&item.url, &item.remote_endpoint)
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

    /// Returns the handle for the [`ActiveRelayActor`] to reach `remote_endpoint`.
    ///
    /// The endpoint is expected to be reachable on `url`, but if no [`ActiveRelayActor`] for
    /// `url` exists but another existing [`ActiveRelayActor`] already knows about the endpoint,
    /// that other endpoint is used.
    async fn active_relay_handle_for_endpoint(
        &mut self,
        url: &RelayUrl,
        remote_endpoint: &EndpointId,
    ) -> ActiveRelayHandle {
        if let Some(handle) = self.active_relays.get(url) {
            return handle.clone();
        }

        let mut found_relay: Option<RelayUrl> = None;
        // If we don't have an open connection to the remote endpoint's home relay, see if
        // we have an open connection to a relay endpoint where we'd heard from that peer
        // already.  E.g. maybe they dialed our home relay recently.
        {
            // Futures which return Some(RelayUrl) if the relay knows about the remote endpoint.
            let check_futs = self.active_relays.iter().map(|(url, handle)| async move {
                let (tx, rx) = oneshot::channel();
                handle
                    .prio_inbox_addr
                    .send(ActiveRelayPrioMessage::HasEndpointRoute(
                        *remote_endpoint,
                        tx,
                    ))
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
                if Some(&url) == self.config.my_relay.get().as_ref()
                    && let Err(err) = handle
                        .inbox_addr
                        .try_send(ActiveRelayMessage::SetHomeRelay(true))
                {
                    error!("Home relay not set, send to new actor failed: {err:#}.");
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
                for endpoint in self.active_relay_sorted() {
                    s += &format!(" relay-{endpoint}");
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

/// A single datagram received from a relay server.
///
/// This could be either a QUIC or DISCO packet.
#[derive(Debug)]
pub(crate) struct RelayRecvDatagram {
    pub(crate) url: RelayUrl,
    pub(crate) src: EndpointId,
    pub(crate) datagrams: Datagrams,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use iroh_base::{EndpointId, RelayUrl, SecretKey};
    use iroh_relay::{PingTracker, protos::relay::Datagrams};
    use n0_error::{AnyError as Error, Result, StackResultExt, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
    use tracing::{Instrument, info, info_span};

    use super::{
        ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayMessage, ActiveRelayPrioMessage,
        RELAY_INACTIVE_CLEANUP_TIME, RelayConnectionOptions, RelayRecvDatagram, RelaySendItem,
        UNDELIVERABLE_DATAGRAM_TIMEOUT,
    };
    use crate::{dns::DnsResolver, test_utils};

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

    /// Starts an [`ActiveRelayActor`] as an "iroh echo endpoint".
    ///
    /// This actor will connect to the relay server, pretending to be an iroh endpoint, and echo
    /// back any datagram it receives from the relay.  This is used by the
    /// [`ActiveRelayActor`] under test to check connectivity works.
    fn start_echo_endpoint(relay_url: RelayUrl) -> (EndpointId, AbortOnDropHandle<()>) {
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
            info_span!("echo-endpoint"),
        );
        let echo_task = tokio::spawn({
            let relay_url = relay_url.clone();
            async move {
                loop {
                    let datagram = recv_datagram_rx.recv().await;
                    if let Some(recv) = datagram {
                        let RelayRecvDatagram {
                            url: _,
                            src,
                            datagrams,
                        } = recv;
                        info!(from = %src.fmt_short(), "Received datagram");
                        let send = RelaySendItem {
                            remote_endpoint: src,
                            url: relay_url.clone(),
                            datagrams,
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

    /// Sends a message to the echo endpoint, receives the response.
    ///
    /// This takes care of retry and timeout.  Because we don't know when both the
    /// endpoint-under-test and the echo endpoint will be ready and datagrams aren't queued to send
    /// forever, we have to retry a few times.
    async fn send_recv_echo(
        item: RelaySendItem,
        tx: &mpsc::Sender<RelaySendItem>,
        rx: &mut mpsc::Receiver<RelayRecvDatagram>,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                let res = tokio::time::timeout(UNDELIVERABLE_DATAGRAM_TIMEOUT, async {
                    tx.send(item.clone()).await.std_context("send item")?;
                    let RelayRecvDatagram {
                        url: _,
                        src: _,
                        datagrams,
                    } = rx.recv().await.unwrap();

                    assert_eq!(datagrams, item.datagrams);

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
        let (peer_endpoint, _echo_endpoint_task) = start_echo_endpoint(relay_url.clone());

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

        // Send a datagram to our echo endpoint.
        info!("first echo");
        let hello_send_item = RelaySendItem {
            remote_endpoint: peer_endpoint,
            url: relay_url.clone(),
            datagrams: Datagrams::from(b"hello"),
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
            .std_context("send get local addr msg")?;

        let local_addr = rx
            .await
            .std_context("wait for local addr msg")?
            .context("no local addr")?;
        info!(?local_addr, "check connection with addr");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection(vec![local_addr.ip()]))
            .await
            .std_context("send check connection message")?;

        // Sync the ActiveRelayActor. Ping blocks it and we want to be sure it has handled
        // another inbox message before continuing.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .std_context("send get local addr msg")?;
        rx.await.std_context("recv send local addr msg")?;

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
            .std_context("send check connection msg")?;

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
        task.await.std_context("wait for task to finish")?;

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
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (tx, rx) = oneshot::channel();
                inbox_tx.send(ActiveRelayMessage::PingServer(tx)).await.ok();
                if tokio::time::timeout(Duration::from_millis(200), rx)
                    .await
                    .map(|resp| resp.is_ok())
                    .unwrap_or_default()
                {
                    break;
                }
            }
        })
        .await
        .std_context("timeout")?;

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

        // We resume time for these timeouts, as there's actual I/O happening,
        // for example closing the TCP stream, so we actually need the tokio
        // runtime to idle a bit while the kernel is doing its thing.
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
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
