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
//! - Each relay server has a [`RelayConnection`], and the [`RelayActor`] adds a noq socket
//!   for each one.
//!   - When connected, the [`ActiveRelayActor`] hands the halves of the [`Client`] to it.
//!   - The noq socket receives datagrams straight from the stream half. Other frames come
//!     to the [`ActiveRelayActor`].
//!   - The senders of the noq connections write datagrams straight into the sink half. A
//!     sender that finds the relay disconnected asks the [`RelayActor`] to connect it.
//!
//! [`Client`]: iroh_relay::client::Client

#[cfg(test)]
use std::net::SocketAddr;
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use iroh_base::{RelayUrl, SecretKey};
use iroh_relay::{
    self as relay, PingTracker, RelayMap,
    client::{Client, ConnectError, RecvError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg, Status},
    },
};
use n0_error::{AnyError, e, stack_error};
use n0_future::{
    SinkExt,
    task::{JoinError, JoinSet},
    time::{self, Duration, Instant, MissedTickBehavior},
};
use n0_watcher::Watchable;
use netwatch::interfaces;
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, error, event, info, info_span, trace, warn};
use url::Url;

use super::{RelayConnection, RelayConnections, RelayEvent, RelaySocket, RelayStream, Socket};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{endpoint::RelayStatus, net_report::Report, socket::Metrics as SocketMetrics};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
pub(super) const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout for establishing the relay connection.
///
/// This includes DNS, dialing the server, upgrading the connection, and completing the
/// handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
///
/// The actor shuts down itself on inactivity: inactivity is determined when no sender
/// used the [`RelayConnection`] for a while.
///
/// This actor has 2 main states it can be in, each has it's dedicated run loop:
///
/// - Dialing the relay server.
///
///   This will continuously dial the server until connected, using exponential backoff if
///   it can not connect.  See [`ActiveRelayActor::run_dialing`].
///
/// - Connected to the relay server.
///
///   The noq socket of the [`RelayConnection`] receives the datagrams, and the senders send them.
///   The actor flushes the sink, answers and sends pings, and handles the other frames.
///   See [`ActiveRelayActor::run_connected`].
///
/// All these are driven from the top-level [`ActiveRelayActor::run`] loop.
#[derive(Debug)]
struct ActiveRelayActor {
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    /// The connection this actor connects.
    connection: Arc<RelayConnection>,

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
    /// When this expires the actor may have been idle and should shut down.
    ///
    /// Unless it is managing the home relay connection.  Inactivity is only tracked on the
    /// last datagram sent to the relay, see [`RelayConnection::last_used`]. Received datagrams will
    /// trigger QUIC ACKs which is sufficient to keep active connections open.
    inactive_timeout: Pin<Box<time::Sleep>>,
    /// Token indicating the [`ActiveRelayActor`] should stop.
    stop_token: CancellationToken,
    metrics: Arc<SocketMetrics>,
    my_relay: HomeRelayWatch,
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
    CheckConnection { local_ips: Vec<IpAddr> },
    /// Sets this relay as the home relay, or not.
    SetHomeRelay(bool),
    #[cfg(test)]
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(test)]
    PingServer(oneshot::Sender<()>),
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
struct ActiveRelayActorOptions {
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    connection: Arc<RelayConnection>,
    connection_opts: RelayConnectionOptions,
    stop_token: CancellationToken,
    metrics: Arc<SocketMetrics>,
    my_relay: HomeRelayWatch,
}

/// Configuration needed to create a connection to a relay server.
#[derive(Debug, Clone)]
struct RelayConnectionOptions {
    secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: Arc<AtomicBool>,
    tls_config: rustls::ClientConfig,
    auth_token: Option<String>,
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
        source: io::Error,
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
            inbox,
            connection,
            connection_opts,
            stop_token,
            metrics,
            my_relay,
        } = opts;
        let url = connection.url().clone();
        let relay_client_builder = Self::create_relay_builder(url.clone(), connection_opts);
        ActiveRelayActor {
            inbox,
            connection,
            url,
            relay_client_builder,
            is_home_relay: false,
            inactive_timeout: Box::pin(time::sleep(RELAY_INACTIVE_CLEANUP_TIME)),
            stop_token,
            metrics,
            my_relay,
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
            tls_config,
            auth_token,
        } = opts;

        let mut builder = relay::client::ClientBuilder::new(
            url,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
        )
        .tls_client_config(tls_config)
        .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }

        if let Some(token) = auth_token {
            builder = builder.auth_token(token);
        }
        builder
    }

    /// The main actor run loop.
    ///
    /// Primarily switches between the dialing and connected states.
    async fn run(mut self) {
        let mut backoff = Self::build_backoff();

        while let Err(err) = self.run_once().await {
            debug!("{err:#}");
            let was_established = matches!(err, RelayConnectionError::Established { .. });
            let last_failure = Some(Arc::new(RelayConnectionFailure::new(err)));
            self.my_relay.set_status(
                &self.url,
                RelayConnectionState::Disconnected { last_failure },
            );
            if !was_established {
                // If dialing failed, or if the relay connection failed before we received a pong,
                // we wait an exponentially increasing time until we attempt to reconnect again.
                let Some(delay) = backoff.next() else {
                    debug!("retries exceeded");
                    break;
                };
                debug!("retry in {delay:?}");
                if !self.sleep_backoff(delay).await {
                    break;
                }
            } else {
                // If the relay connection remained established long enough so that we received a pong
                // from the relay server, we reset the backoff and attempt to reconnect immediately.
                backoff = Self::build_backoff();
            }
        }
        debug!("exiting");
    }

    /// Waits out a reconnect backoff delay.
    ///
    /// Returns `false` if the actor should shut down instead of retrying.
    async fn sleep_backoff(&mut self, delay: Duration) -> bool {
        tokio::select! {
            biased;
            _ = self.stop_token.cancelled() => {
                debug!("Shutdown.");
                false
            }
            _ = time::sleep(delay) => true,
        }
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
    #[allow(clippy::result_large_err)]
    async fn run_once(&mut self) -> Result<(), RelayConnectionError> {
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connecting);
        let client = match self.run_dialing().instrument(info_span!("dialing")).await {
            Some(Ok(client)) => client,
            Some(Err(err)) => {
                self.metrics.relay_conns_failed.inc();
                return Err(e!(RelayConnectionError::Dial, err));
            }
            None => return Ok(()),
        };
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connected);
        self.metrics.relay_conns_success.inc();
        let res = self
            .run_connected(client)
            .instrument(info_span!("connected"))
            .await;
        self.metrics.relay_conns_closed.inc();
        res
    }

    /// Returns whether the connection was idle long enough, or else extends the timeout.
    ///
    /// Called when [`Self::inactive_timeout`] expires.
    fn check_inactive(&mut self) -> bool {
        let deadline = self.connection.last_used() + RELAY_INACTIVE_CLEANUP_TIME;
        if deadline <= Instant::now() {
            return true;
        }
        self.inactive_timeout.as_mut().reset(deadline);
        false
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

        let dialing_fut = self.dial_relay();
        tokio::pin!(dialing_fut);
        loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break None;
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
                        ActiveRelayMessage::CheckConnection { .. } => {}
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
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    if self.check_inactive() {
                        debug!(?RELAY_INACTIVE_CLEANUP_TIME, "Inactive, exiting.");
                        break None;
                    }
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
    #[allow(clippy::result_large_err)]
    async fn run_connected(
        &mut self,
        client: iroh_relay::client::Client,
    ) -> Result<(), RelayConnectionError> {
        trace!("Actor loop: connected to relay");
        event!(
            target: "iroh::_events::relay::connected",
            Level::DEBUG,
            url = %self.url,
            home_relay = self.is_home_relay,
        );

        let (client_stream, client_sink) = client.split();
        let local_addr = client_stream.local_addr();
        let (events_tx, mut events) = mpsc::channel(RELAY_EVENTS_CAPACITY);
        let connection = self.connection.clone();
        connection.connect(
            Box::pin(client_sink.sink_map_err(io::Error::other)),
            RelayStream {
                stream: client_stream,
                events: events_tx,
            },
        );

        let mut state = ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            pong_pending: None,
            established: false,
            rate_limited: false,
            #[cfg(test)]
            test_pong: None,
        };

        // Regularly send pings so we know the connection is healthy.
        // The first ping will be sent immediately.
        let mut ping_interval = time::interval(PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let res = loop {
            if let Some(data) = state.pong_pending.take()
                && let Err(err) = send_msg(&connection, ClientToRelayMsg::Pong(data)).await
            {
                break Err(err);
            }
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break Ok(());
                }
                res = poll_fn(|cx| connection.poll_flush(cx)) => {
                    if let Err(err) = res {
                        break Err(e!(RunError::ClientStreamWrite, err));
                    }
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(e!(RunError::PingTimeout));
                }
                _ = ping_interval.tick() => {
                    let data = state.ping_tracker.new_ping();
                    if let Err(err) = send_msg(&connection, ClientToRelayMsg::Ping(data)).await {
                        break Err(err);
                    }
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Inbox closed, shutdown.");
                        break Ok(());
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                            // We are in `run_connected`, so if we just became the home
                            // relay, publish `Connected` (the `RelayActor` only sets
                            // `Connecting` on the URL change since it cannot know our
                            // actual state).
                            if is_home {
                                self.my_relay
                                    .set_status(&self.url, RelayConnectionState::Connected);
                            }
                        }
                        ActiveRelayMessage::CheckConnection { local_ips } => {
                            match local_addr {
                                Some(addr) if local_ips.contains(&addr.ip()) => {
                                    let data = state.ping_tracker.new_ping();
                                    let ping = ClientToRelayMsg::Ping(data);
                                    if let Err(err) = send_msg(&connection, ping).await {
                                        break Err(err);
                                    }
                                }
                                Some(_) => break Err(e!(RunError::LocalIpInvalid)),
                                None => break Err(e!(RunError::LocalAddrMissing)),
                            }
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(local_addr).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            let data = rand::random();
                            state.test_pong = Some((data, sender));
                            if let Err(err) = send_msg(&connection, ClientToRelayMsg::Ping(data)).await {
                                break Err(err);
                            }
                        }
                    }
                }
                event = events.recv() => {
                    match event {
                        Some(RelayEvent::Frame(msg)) => self.handle_relay_msg(msg, &mut state),
                        Some(RelayEvent::Closed(Some(err))) => {
                            break Err(e!(RunError::ClientStreamRead, err));
                        }
                        Some(RelayEvent::Closed(None)) | None => {
                            break Err(e!(RunError::StreamClosedServer));
                        }
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    if self.check_inactive() {
                        debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting.");
                        break Ok(());
                    }
                }
            }
        };

        if let Some(mut sink) = connection.disconnect()
            && res.is_ok()
            && let Err(err) = sink.close().await
        {
            debug!("Failed to close client sink gracefully: {err:#}");
        }

        res.map_err(|err| state.map_err(err))
    }

    fn handle_relay_msg(&mut self, msg: RelayToClientMsg, state: &mut ConnectedRelayState) {
        match msg {
            RelayToClientMsg::Datagrams { .. } => {
                // The noq socket of the relay receives these.
            }
            RelayToClientMsg::EndpointGone(_) => {}
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
            RelayToClientMsg::Status(status) => match status {
                Status::Healthy => info!("Relay server reports: {status}"),
                Status::RateLimited => {
                    warn!("{status}");
                    // The relay sends this at most once per connection, but do not rely
                    // on the remote for the metric to count connections.
                    if !state.rate_limited {
                        state.rate_limited = true;
                        self.metrics.relay_conns_ratelimited.inc();
                    }
                }
                _ => warn!("Relay server reports problem: {status}"),
            },
            RelayToClientMsg::Restarting { .. } => {
                trace!("Ignoring {msg:?}")
            }
            // Deprecated variants, kept for backwards compatibility with older relay protocol versions.
            RelayToClientMsg::Health { problem } => {
                warn!("Relay server reports problem: {problem}");
            }
            _ => unreachable!(
                "got unknown RelayToClientMsg but iroh is released in sync with iroh-relay"
            ),
        }
    }
}

/// How many frames other than datagrams the noq socket may queue for the actor.
const RELAY_EVENTS_CAPACITY: usize = 64;

/// Sends a frame to the relay server, failing if that takes longer than [`PING_INTERVAL`].
async fn send_msg(connection: &RelayConnection, msg: ClientToRelayMsg) -> Result<(), RunError> {
    let mut msg = Some(msg);
    let send = poll_fn(|cx| connection.poll_send(cx, || msg.take().expect("sent once")));
    match time::timeout(PING_INTERVAL, send).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(e!(RunError::ClientStreamWrite, err)),
        Err(_) => Err(e!(RunError::SendTimeout)),
    }
}

/// State of the [`ActiveRelayActor`] while connected to a relay server.
#[derive(Debug)]
struct ConnectedRelayState {
    /// Tracks pings we have sent, awaits pong replies.
    ping_tracker: PingTracker,
    /// A pong we need to send ASAP.
    pong_pending: Option<[u8; 8]>,
    /// Whether the connection is to be considered established.
    ///
    /// This is set to `true` once a pong was received from the server.
    established: bool,
    /// Whether the relay reported that it is rate-limiting this connection.
    ///
    /// Used to count each affected connection only once.
    rate_limited: bool,
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
    /// Adds a noq socket to `endpoint` for each relay server, from now on.
    StartSockets {
        endpoint: noq::Endpoint,
        sock: Arc<Socket>,
    },
    MaybeCloseRelaysOnRebind,
    NetworkChange {
        report: Report,
    },
    /// Trigger an immediate health check on all relay connections.
    ///
    /// Sent after a major network change to detect broken connections faster
    /// using RTT-based timeouts instead of the default 5s ping timeout.
    CheckConnectionAfterNetworkChange,
}

pub(super) struct RelayActor {
    config: Config,
    /// Where to add the noq sockets of the relay servers, once known.
    sockets: Option<(noq::Endpoint, Arc<Socket>)>,
    /// How many of the connections have their noq socket.
    sockets_added: usize,
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
pub(crate) struct Config {
    pub my_relay: HomeRelayWatch,
    pub secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    pub dns_resolver: DnsResolver,
    /// Proxy
    pub proxy_url: Option<Url>,
    /// If the last net_report report, reports IPv6 to be available.
    pub ipv6_reported: Arc<AtomicBool>,
    pub tls_config: rustls::ClientConfig,
    pub metrics: Arc<SocketMetrics>,
    /// Per-relay configuration. Consulted when starting a connection to
    /// look up the auth token and any future per-relay options.
    pub relay_map: RelayMap,
    /// The connections, one per relay server.
    pub connections: RelayConnections,
}

/// Connection state of the home relay.
///
/// Published via [`HomeRelayWatch`] so that [`Endpoint::online`] and the public
/// [`Endpoint::home_relay_status`] watcher can observe the connection state.
/// This type is `pub(crate)`; the public surface lives on
/// [`crate::endpoint::RelayStatus`], and this enum is intentionally free to
/// evolve without affecting the public API.
///
/// [`Endpoint::online`]: crate::Endpoint::online
/// [`Endpoint::home_relay_status`]: crate::Endpoint::home_relay_status
#[derive(Debug, Clone)]
pub(crate) enum RelayConnectionState {
    /// Dialing or performing the relay handshake.
    Connecting,
    /// Connected and handshaked.
    Connected,
    /// Not connected. Either the connection was lost after having been
    /// established, or an attempt to connect failed.
    ///
    /// `last_failure` carries the most recent connection failure, if any. The
    /// initial transition into this state (before any attempt has produced
    /// an error) carries `None`.
    ///
    /// The `Arc` is compared by pointer identity: each new failure produces
    /// a fresh allocation, so the watcher fires on every new error.
    Disconnected {
        last_failure: Option<Arc<RelayConnectionFailure>>,
    },
}

impl RelayConnectionState {
    pub(crate) fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    pub(crate) fn last_failure(&self) -> Option<&RelayConnectionFailure> {
        match self {
            Self::Disconnected { last_failure } => last_failure.as_deref(),
            _ => None,
        }
    }
}

impl PartialEq for RelayConnectionState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Connecting, Self::Connecting) | (Self::Connected, Self::Connected) => true,
            (Self::Disconnected { last_failure: a }, Self::Disconnected { last_failure: b }) => {
                match (a, b) {
                    (None, None) => true,
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

impl Eq for RelayConnectionState {}

/// A failed attempt to connect to a relay server, or a lost connection.
///
/// Contains the type-erased error, together with whatever we could classify from it
/// while the concrete error type was still at hand.
#[derive(Debug)]
pub(crate) struct RelayConnectionFailure {
    error: AnyError,
    auth_denied_reason: Option<String>,
}

impl RelayConnectionFailure {
    fn new(error: RelayConnectionError) -> Self {
        Self {
            auth_denied_reason: auth_denied_reason(&error).map(ToOwned::to_owned),
            error: AnyError::from(error),
        }
    }

    /// Returns the type-erased error.
    pub(crate) fn error(&self) -> &AnyError {
        &self.error
    }

    /// Returns the reason if the relay server denied our authentication.
    pub(crate) fn auth_denied_reason(&self) -> Option<&str> {
        self.auth_denied_reason.as_deref()
    }
}

/// Returns the reason if `error` was caused by the relay server denying our authentication.
fn auth_denied_reason(error: &RelayConnectionError) -> Option<&str> {
    match error {
        RelayConnectionError::Dial {
            source:
                DialError::Connect {
                    source:
                        ConnectError::Handshake {
                            source: handshake::Error::ServerDeniedAuth { reason, .. },
                            ..
                        },
                    ..
                },
            ..
        } => Some(reason),
        _ => None,
    }
}

/// Shared watchable for the home relay URL and connection status.
///
/// Owned by [`RelayActor`] and cloned into each [`ActiveRelayActor`].
///
/// # Write discipline
///
/// The [`RelayActor`] writes the URL (via [`Self::set`] and [`Self::clear`]).
/// Each [`ActiveRelayActor`] updates only the status (via [`Self::set_status`]),
/// which guards against stale writes: if another relay has become home since this actor
/// was designated, the write is silently dropped.
#[derive(Debug, Clone)]
pub(crate) struct HomeRelayWatch {
    inner: Watchable<Option<RelayStatus>>,
}

impl Default for HomeRelayWatch {
    fn default() -> Self {
        Self {
            inner: Watchable::new(None),
        }
    }
}

impl HomeRelayWatch {
    /// Set the home relay URL and status. Used by [`RelayActor`] on relay changes.
    fn set(&self, url: RelayUrl, state: RelayConnectionState) {
        let _ = self.inner.set(Some(RelayStatus::new(url, state)));
    }

    /// Clear the home relay (no preferred relay). Used by [`RelayActor`].
    fn clear(&self) {
        let _ = self.inner.set(None);
    }

    /// Update the status, but only if `url` is still the current home relay.
    ///
    /// This is the only write method [`ActiveRelayActor`] should use. It prevents a
    /// demoted actor from overwriting a newer home relay's status: the [`RelayActor`]
    /// updates the URL in the watchable *before* sending `SetHomeRelay(false)`, so by
    /// the time the old actor tries to write, the URL no longer matches.
    fn set_status(&self, url: &RelayUrl, state: RelayConnectionState) {
        if self.inner.get().as_ref().map(RelayStatus::url) == Some(url) {
            let _ = self.inner.set(Some(RelayStatus::new(url.clone(), state)));
        }
    }

    fn get(&self) -> Option<RelayStatus> {
        self.inner.get()
    }

    pub(crate) fn watch(&self) -> n0_watcher::Direct<Option<RelayStatus>> {
        self.inner.watch()
    }
}

impl RelayActor {
    pub(super) fn new(config: Config, cancel_token: CancellationToken) -> Self {
        Self {
            config,
            sockets: None,
            sockets_added: 0,
            active_relays: Default::default(),
            active_relay_tasks: JoinSet::new(),
            cancel_token,
        }
    }

    pub(super) async fn run(mut self, mut receiver: mpsc::Receiver<RelayActorMessage>) {
        let connections = self.config.connections.clone();
        loop {
            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    debug!("shutting down");
                    break;
                }
                Some(res) = self.active_relay_tasks.join_next() => {
                    log_active_relay_task_result(res);
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
                _ = connections.changed() => self.sync_connections(),
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
            RelayActorMessage::StartSockets { endpoint, sock } => {
                self.sockets = Some((endpoint, sock));
                self.sync_connections();
            }
            RelayActorMessage::NetworkChange { report } => {
                self.on_network_change(report).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind => {
                self.maybe_close_relays_on_rebind().await;
            }
            RelayActorMessage::CheckConnectionAfterNetworkChange => {
                self.check_connection_after_network_change().await;
            }
        }
    }

    /// Adds a noq socket for each new connection, and connects those that asked to.
    fn sync_connections(&mut self) {
        let connections = self.config.connections.all();
        if let Some((endpoint, sock)) = &self.sockets {
            for connection in &connections[self.sockets_added..] {
                let socket = RelaySocket::new(sock.clone(), connection.clone());
                let route = socket.route();
                match endpoint.add_socket(Box::new(socket), vec![route]) {
                    Ok(()) => debug!(url = %connection.url(), "added relay socket"),
                    Err(err) => {
                        warn!(url = %connection.url(), "failed to add relay socket: {err:#}")
                    }
                }
            }
            self.sockets_added = connections.len();
        }
        for connection in connections {
            if connection.take_connect_request() {
                self.active_relay_handle(connection.url().clone());
            }
        }
    }

    async fn on_network_change(&mut self, report: Report) {
        let prev = self.config.my_relay.get();
        let prev_url = prev.as_ref().map(RelayStatus::url);
        if report.preferred_relay.as_ref() == prev_url {
            // No change.
            return;
        }

        if let Some(relay_url) = report.preferred_relay {
            self.config.metrics.relay_home_change.inc();

            // On change, notify all currently connected relay servers and
            // start connecting to our home relay if we are not already.
            info!("home is now relay {}, was {:?}", relay_url, prev_url);
            // Publish `Connecting` initially. If an `ActiveRelayActor` already
            // exists for this URL it will republish its actual status (e.g.
            // `Connected`) when it receives the `SetHomeRelay(true)` message
            // sent below.
            self.config
                .my_relay
                .set(relay_url.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(relay_url).await;
        } else {
            self.config.my_relay.clear();
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

    /// Returns the handle of the [`ActiveRelayActor`].
    fn active_relay_handle(&mut self, url: RelayUrl) -> ActiveRelayHandle {
        match self.active_relays.get(&url) {
            Some(e) => e.clone(),
            None => {
                let handle = self.start_active_relay(url.clone());
                if Some(&url) == self.config.my_relay.get().as_ref().map(RelayStatus::url)
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

        let auth_token = self
            .config
            .relay_map
            .get(&url)
            .and_then(|cfg| cfg.auth_token.clone());
        let connection_opts = RelayConnectionOptions {
            secret_key: self.config.secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: self.config.dns_resolver.clone(),
            proxy_url: self.config.proxy_url.clone(),
            prefer_ipv6: self.config.ipv6_reported.clone(),
            tls_config: self.config.tls_config.clone(),
            auth_token,
        };

        let (inbox_tx, inbox_rx) = mpsc::channel(64);
        let span = info_span!("active-relay", %url);
        let opts = ActiveRelayActorOptions {
            inbox: inbox_rx,
            connection: self.config.connections.get(&url),
            connection_opts,
            stop_token: self.cancel_token.child_token(),
            metrics: self.config.metrics.clone(),
            my_relay: self.config.my_relay.clone(),
        };
        let actor = ActiveRelayActor::new(opts);
        self.active_relay_tasks.spawn(
            async move {
                actor.run().await;
            }
            .instrument(span),
        );
        let handle = ActiveRelayHandle {
            inbox_addr: inbox_tx,
        };
        self.log_active_relay();
        handle
    }

    /// Triggers an immediate health check on all relay connections after a network change.
    async fn check_connection_after_network_change(&mut self) {
        self.send_check_connection().await;
    }

    /// Closes the relay connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any relay connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// relay connections are pinged.
    async fn maybe_close_relays_on_rebind(&mut self) {
        self.send_check_connection().await;
        self.log_active_relay();
    }

    /// Sends a [`ActiveRelayMessage::CheckConnection`] to all active relays with current
    /// local IPs.
    async fn send_check_connection(&self) {
        #[cfg(not(wasm_browser))]
        let ifs = interfaces::State::new().await;
        #[cfg(not(wasm_browser))]
        let local_ips: Vec<_> = ifs
            .interfaces
            .values()
            .flat_map(|netif| netif.addrs())
            .map(|ipnet| ipnet.addr())
            .collect();
        // In browsers, we don't have this information. This will do the right thing
        // in the ActiveRelayActor, though.
        #[cfg(wasm_browser)]
        let local_ips = Vec::new();
        let send_futs = self.active_relays.values().map(|handle| {
            let local_ips = local_ips.clone();
            async move {
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::CheckConnection { local_ips })
                    .await
                    .ok();
            }
        });
        n0_future::join_all(send_futs).await;
    }

    /// Cleans up [`ActiveRelayActor`]s which have stopped running.
    fn reap_active_relays(&mut self) {
        self.active_relays
            .retain(|_url, handle| !handle.inbox_addr.is_closed());

        // Make sure home relay exists
        if let Some(status) = self.config.my_relay.get() {
            self.active_relay_handle(status.url().clone());
        }
        self.log_active_relay();
    }

    /// Stops all [`ActiveRelayActor`]s and awaits for them to finish.
    async fn close_all_active_relays(&mut self) {
        self.cancel_token.cancel();
        let mut tasks = std::mem::take(&mut self.active_relay_tasks);
        // Drain instead of `join_all`, which panics on any `JoinError`.
        while let Some(res) = tasks.join_next().await {
            log_active_relay_task_result(res);
        }

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

/// Reports how one [`ActiveRelayActor`] task ended, in the run loop and on shutdown.
fn log_active_relay_task_result(res: Result<(), JoinError>) {
    match res {
        Ok(()) => (),
        Err(err) if err.is_panic() => error!("ActiveRelayActor task panicked: {err:#?}"),
        Err(err) if err.is_cancelled() => error!("ActiveRelayActor cancelled: {err:#?}"),
        Err(err) => error!("ActiveRelayActor failed: {err:#?}"),
    }
}

/// Handle to one [`ActiveRelayActor`].
#[derive(Debug, Clone)]
struct ActiveRelayHandle {
    inbox_addr: mpsc::Sender<ActiveRelayMessage>,
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use iroh_base::{EndpointId, RelayUrl, SecretKey};
    use iroh_relay::{
        PingTracker,
        tls::{CaTlsConfig, default_provider},
    };
    use n0_error::{Result, StackResultExt, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
    use tracing::{Instrument, info, info_span};

    use super::{
        ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayMessage, Config,
        RELAY_INACTIVE_CLEANUP_TIME, RelayActor, RelayConnection, RelayConnectionOptions,
        RelayConnections, RelayMap,
    };
    use crate::{
        dns::DnsResolver,
        metrics::SocketMetrics,
        socket::transports::{Transmit, relay::RelayDatagramSender},
        test_utils,
    };

    /// Abort stands in for the runtime drop that triggers this in the wild:
    /// `join_next` yields a cancelled `JoinError` either way.
    #[tokio::test]
    #[traced_test]
    async fn close_all_active_relays_survives_a_cancelled_task() {
        let config = Config {
            my_relay: Default::default(),
            secret_key: SecretKey::from_bytes(&[0u8; 32]),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            metrics: Default::default(),
            relay_map: RelayMap::empty(),
            connections: Default::default(),
        };
        let mut actor = RelayActor::new(config, CancellationToken::new());

        let handle = actor.active_relay_tasks.spawn(std::future::pending::<()>());
        handle.abort();

        // Panicked with `join_all`.
        actor.close_all_active_relays().await;

        assert!(actor.active_relay_tasks.is_empty());
        assert!(logs_contain("ActiveRelayActor cancelled"));
    }

    /// Returns a new connection to `url`.
    fn test_connection(url: &RelayUrl) -> Arc<RelayConnection> {
        RelayConnections::default().get(url)
    }

    /// Starts a new [`ActiveRelayActor`] for `connection`.
    fn start_active_relay_actor(
        secret_key: SecretKey,
        stop_token: CancellationToken,
        connection: Arc<RelayConnection>,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        metrics: Arc<SocketMetrics>,
        span: tracing::Span,
    ) -> AbortOnDropHandle<()> {
        let opts = ActiveRelayActorOptions {
            inbox: inbox_rx,
            connection,
            connection_opts: RelayConnectionOptions {
                secret_key,
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(true)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
            },
            stop_token,
            metrics,
            my_relay: Default::default(),
        };
        let task = tokio::spawn(ActiveRelayActor::new(opts).run().instrument(span));
        AbortOnDropHandle::new(task)
    }

    /// Receives one datagram batch, and returns its source and contents.
    async fn recv_datagram(connection: &RelayConnection) -> (EndpointId, Vec<u8>) {
        let (src, datagrams) = poll_fn(|cx| connection.poll_recv(cx)).await;
        (src, datagrams.contents.to_vec())
    }

    /// Receives on `connection` like its noq socket would, which also reads the other frames.
    fn spawn_receiver(connection: Arc<RelayConnection>) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                recv_datagram(&connection).await;
            }
        }))
    }

    /// Sends one datagram, or drops it if the relay does not connect in time.
    async fn send_datagram(sender: &mut RelayDatagramSender, dst: EndpointId, contents: &[u8]) {
        let transmit = Transmit {
            ecn: None,
            contents,
            segment_size: None,
        };
        poll_fn(|cx| sender.poll_send(cx, dst, &transmit))
            .await
            .ok();
    }

    /// Starts an [`ActiveRelayActor`] as an "iroh echo endpoint".
    ///
    /// This actor will connect to the relay server, pretending to be an iroh endpoint, and echo
    /// back any datagram it receives from the relay.  This is used by the
    /// [`ActiveRelayActor`] under test to check connectivity works.
    fn start_echo_endpoint(relay_url: RelayUrl) -> (EndpointId, AbortOnDropHandle<()>) {
        let secret_key = SecretKey::from_bytes(&[8u8; 32]);
        let connection = test_connection(&relay_url);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let actor_task = start_active_relay_actor(
            secret_key.clone(),
            cancel_token.clone(),
            connection.clone(),
            inbox_rx,
            Default::default(),
            info_span!("echo-endpoint"),
        );
        let echo_task = tokio::spawn(
            async move {
                let mut sender = RelayDatagramSender::new(connection.clone());
                loop {
                    let (src, contents) = recv_datagram(&connection).await;
                    info!(from = %src.fmt_short(), "Received datagram");
                    send_datagram(&mut sender, src, &contents).await;
                }
            }
            .instrument(info_span!("echo-task")),
        );
        let echo_task = AbortOnDropHandle::new(echo_task);
        let supervisor_task = tokio::spawn(async move {
            let _guard = cancel_token.drop_guard();
            // move the inbox here so it is not dropped, as this stops the actor.
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
        sender: &mut RelayDatagramSender,
        connection: &RelayConnection,
        dst: EndpointId,
        contents: &[u8],
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                send_datagram(sender, dst, contents).await;
                let res =
                    tokio::time::timeout(Duration::from_secs(1), recv_datagram(connection)).await;
                if let Ok((_, received)) = res {
                    assert_eq!(received, contents);
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
        let connection = test_connection(&relay_url);
        let mut sender = RelayDatagramSender::new(connection.clone());
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let metrics = Arc::new(SocketMetrics::default());
        let task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            connection.clone(),
            inbox_rx,
            metrics.clone(),
            info_span!("actor-under-test"),
        );

        // Send a datagram to our echo endpoint.
        info!("first echo");
        send_recv_echo(&mut sender, &connection, peer_endpoint, b"hello").await?;

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
            .send(ActiveRelayMessage::CheckConnection {
                local_ips: vec![local_addr.ip()],
            })
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
        send_recv_echo(&mut sender, &connection, peer_endpoint, b"hello").await?;

        // Now ask to check the connection, this will reconnect without pinging because we
        // do not supply any "valid" local IP addresses.
        info!("check connection");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection {
                local_ips: Vec::new(),
            })
            .await
            .std_context("send check connection msg")?;

        // Give some time to reconnect, mostly to sort logs rather than functional.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Echo should still work.
        info!("third echo");
        send_recv_echo(&mut sender, &connection, peer_endpoint, b"hello").await?;

        // Shut down the actor.
        cancel_token.cancel();
        task.await.std_context("wait for task to finish")?;

        // The actor connected once at startup and once more after the connection check
        // failed.
        assert_eq!(metrics.relay_conns_success.get(), 2);
        assert_eq!(
            metrics.relay_conns_closed.get(),
            2,
            "the connections are counted as closed once the actor stops"
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_active_relay_inactive() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let metrics = Arc::new(SocketMetrics::default());
        let connection = test_connection(&relay_url);
        let _receiver = spawn_receiver(connection.clone());
        let mut task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            connection,
            inbox_rx,
            metrics.clone(),
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

        assert_eq!(metrics.relay_conns_success.get(), 1);
        assert_eq!(
            metrics.relay_conns_closed.get(),
            0,
            "the connection is only counted as closed once it is gone"
        );

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

        // The actor may have reconnected while we advanced time, because a ping to the relay
        // server can time out while time is frozen, so we do not assert an exact count here.
        assert_eq!(
            metrics.relay_conns_closed.get(),
            metrics.relay_conns_success.get(),
            "all connections are counted as closed once the actor stops"
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

    #[test]
    fn test_home_relay_watch_url_guard() {
        use super::{HomeRelayWatch, RelayConnectionState};
        use crate::endpoint::RelayStatus;

        let watch = HomeRelayWatch::default();
        let a: RelayUrl = "https://a.example.com".parse().unwrap();
        let b: RelayUrl = "https://b.example.com".parse().unwrap();

        // Actor A becomes home and connects
        watch.set(a.clone(), RelayConnectionState::Connecting);
        watch.set_status(&a, RelayConnectionState::Connected);
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(a.clone(), RelayConnectionState::Connected)),
        );

        // RelayActor migrates home to B
        watch.set(b.clone(), RelayConnectionState::Connecting);

        // Old actor A tries to write -- rejected because URL changed
        watch.set_status(
            &a,
            RelayConnectionState::Disconnected { last_failure: None },
        );
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(
                b.clone(),
                RelayConnectionState::Connecting
            )),
        );

        // Actor B writes normally
        watch.set_status(&b, RelayConnectionState::Connected);
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(b, RelayConnectionState::Connected)),
        );
    }
}
