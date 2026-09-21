use std::{
    collections::{BTreeSet, HashMap},
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    endpoint::quic::{self, QuicTransportConfig},
    runtime::Runtime,
    socket::transports::{IpConfig, TransportConfig},
    tls::misc::{Blake3HmacKey, RustlsTokenKey},
};

use super::{Error, LocalIdentity, PeerId, Registry, RemotePolicy, routing, tls};
use crate::{RelayMode, RelayUrl, TransportAddr};

/// Relays joined on demand for outgoing dials. Idle ones are released so
/// remote-supplied hints cannot pin this endpoint to arbitrary hosts forever.
const MAX_DIAL_RELAYS: usize = 16;
/// A dialed relay with no pinned routes for this long is disconnected.
const DIAL_RELAY_IDLE: Duration = Duration::from_secs(60);
/// A freshly joined relay counts as in use until its first route exists.
const DIAL_RELAY_GRACE: Duration = Duration::from_secs(10);
/// Consecutive reconnect failures after which a dialed relay is abandoned.
const DIAL_RELAY_FAILURES: u32 = 24;
/// Handshakes verified concurrently; further incoming attempts are refused.
const MAX_HANDSHAKES: usize = 1024;
/// Authenticated connections waiting for [`IdentityEndpoint::accept`].
const ACCEPT_QUEUE: usize = 256;

/// The exact identity and routing hints used to connect.
///
/// The address is a location hint; TLS authenticates the identity independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointAddr {
    /// The identity that must authenticate the connection.
    pub id: PeerId,
    /// A direct destination, or an unspecified address with port zero for relay routing.
    pub addr: SocketAddr,
    /// Additional direct addresses and versioned relay locations.
    pub addrs: BTreeSet<TransportAddr>,
}

impl EndpointAddr {
    /// Contact an exact identity using only a versioned relay.
    pub fn relay(id: PeerId, url: RelayUrl) -> Self {
        let mut address = Self::new(id, SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0));
        address.addrs.insert(TransportAddr::Relay(url));
        address
    }
    /// Pair an expected identity with a direct address.
    pub fn new(id: PeerId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            addrs: BTreeSet::new(),
        }
    }
}

impl From<PeerId> for EndpointAddr {
    fn from(id: PeerId) -> Self {
        Self::new(id, SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
    }
}

/// Transport and protocol settings inherited from the normal endpoint builder.
#[derive(Debug)]
pub(crate) struct Settings {
    pub transports: Vec<TransportConfig>,
    pub alpns: Vec<Vec<u8>>,
    pub transport: QuicTransportConfig,
    pub provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    pub ca_tls: crate::tls::CaTlsConfig,
    /// Legacy builder options that were set but have no typed equivalent.
    /// Each entry is the bind error reported for that option.
    pub unsupported: Vec<&'static str>,
    pub keylog: bool,
    pub configured_addrs: BTreeSet<SocketAddr>,
}

/// Configures a typed endpoint with pluggable credentials.
#[derive(Debug)]
pub struct Builder {
    identity: LocalIdentity,
    registry: Arc<Registry>,
    settings: Settings,
    policy: Option<RemotePolicy>,
}

impl Builder {
    pub(crate) fn from_settings(
        identity: LocalIdentity,
        registry: Arc<Registry>,
        settings: Settings,
    ) -> Self {
        Self {
            identity,
            registry,
            settings,
            policy: None,
        }
    }

    /// Select a single local binding, replacing prior IP bindings.
    pub fn bind_addr(mut self, address: SocketAddr) -> Self {
        self.settings
            .transports
            .retain(|t| !matches!(t, TransportConfig::Ip { .. }));
        let config = match address {
            SocketAddr::V4(address) => IpConfig::V4 {
                ip_net: ipnet::Ipv4Net::new(*address.ip(), 32).expect("valid prefix"),
                port: address.port(),
                is_required: true,
                is_default: true,
            },
            SocketAddr::V6(address) => IpConfig::V6 {
                ip_net: ipnet::Ipv6Net::new(*address.ip(), 128).expect("valid prefix"),
                port: address.port(),
                scope_id: address.scope_id(),
                is_required: true,
                is_default: true,
            },
        };
        self.settings.transports.push(TransportConfig::Ip {
            config,
            is_user_defined: true,
        });
        self
    }

    /// Disable IP bindings, allowing an explicitly configured relay-only endpoint.
    pub fn clear_ip_transports(mut self) -> Self {
        self.settings
            .transports
            .retain(|t| !matches!(t, TransportConfig::Ip { .. }));
        self
    }

    /// Select relay locations. PQ identities require the versioned identity relay protocol.
    pub fn relay_mode(mut self, mode: RelayMode) -> Self {
        self.settings
            .transports
            .retain(|t| !matches!(t, TransportConfig::Relay { .. }));
        if let Some(config) = Option::<TransportConfig>::from(mode) {
            self.settings.transports.push(config);
        }
        self
    }

    /// Require explicit remote signature suites and, optionally, a peer allowlist.
    pub fn remote_policy(mut self, policy: RemotePolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set accepted application protocols. Empty permits outgoing use only.
    pub fn alpns(mut self, alpns: Vec<Vec<u8>>) -> Self {
        self.settings.alpns = alpns;
        self
    }

    /// Use iroh's QUIC transport configuration for incoming and outgoing connections.
    pub fn transport_config(mut self, config: QuicTransportConfig) -> Self {
        self.settings.transport = config;
        self
    }

    /// Configure TLS trust for relay HTTPS connections.
    pub fn ca_tls_config(mut self, config: crate::tls::CaTlsConfig) -> Self {
        self.settings.ca_tls = config;
        self
    }

    /// Bind the typed transport and start the managed QUIC runtime.
    ///
    /// Binding performs no network I/O. Configured relays are joined in the
    /// background and reconnected with backoff, so an unreachable relay delays
    /// relayed reachability rather than failing the bind.
    pub async fn bind(self) -> Result<IdentityEndpoint, Error> {
        if self
            .settings
            .transports
            .iter()
            .any(|t| matches!(t, TransportConfig::Custom(_)))
        {
            return Err(Error::Protocol(
                "legacy custom transports do not accept typed peer IDs",
            ));
        }
        if let Some(reason) = self.settings.unsupported.first() {
            return Err(Error::Protocol(reason));
        }
        for alpn in &self.settings.alpns {
            check_alpn(alpn)?;
        }
        let registry = match self.policy {
            Some(policy) => Arc::new((*self.registry).clone().with_remote_policy(policy)?),
            None => self.registry,
        };
        if registry.identify_local(self.identity.public_key().as_ref())? != self.identity.id() {
            return Err(Error::IdentityMismatch);
        }
        let provider = self
            .settings
            .provider
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let crypto = tls::server(
            &self.identity,
            registry.clone(),
            self.settings.alpns,
            provider.clone(),
            self.settings.keylog,
        )?;
        let token_key = RustlsTokenKey::new(&mut rand::rng(), &provider).ok_or(Error::Provider)?;
        let mut server_config = noq::ServerConfig::new(Arc::new(crypto), Arc::new(token_key));
        server_config.transport_config(self.settings.transport.to_inner_arc());
        // One HTTPS client configuration, built with the endpoint's provider,
        // serves every relay, QAD and reconnect attempt.
        let https = Arc::new(self.settings.ca_tls.client_config(provider.clone())?);
        let (socket, routing) = routing::Transport::bind(&self.settings.transports)?;
        let relays: BTreeSet<RelayUrl> = self
            .settings
            .transports
            .iter()
            .filter_map(|transport| match transport {
                TransportConfig::Relay { relay_map, .. } => Some(relay_map.urls::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect();
        if routing.local_addrs().is_empty() && relays.is_empty() {
            return Err(Error::BindAddr);
        }
        let qad_targets: Vec<_> = self
            .settings
            .transports
            .iter()
            .filter_map(|t| match t {
                TransportConfig::Relay { relay_map, .. } => Some(relay_map.relays::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .filter_map(|config| config.quic.as_ref().map(|q| (config.url.clone(), q.port)))
            .collect();
        let mut local_candidates: BTreeSet<_> = routing
            .local_addrs()
            .into_iter()
            .filter(|a| !a.ip().is_unspecified())
            .collect();
        if routing
            .local_addrs()
            .iter()
            .any(|a| a.ip().is_unspecified())
        {
            use n0_watcher::Watcher;
            let monitor = netwatch::netmon::Monitor::new()
                .await
                .map_err(|e| Error::Io(std::io::Error::other(e)))?;
            let state = monitor.interface_state().get();
            let ips = if state.local_addresses.regular.is_empty() {
                state.local_addresses.loopback
            } else {
                state.local_addresses.regular
            };
            for local in routing.local_addrs() {
                if local.ip().is_unspecified() {
                    local_candidates.extend(
                        ips.iter()
                            .filter(|ip| ip.is_ipv4() == local.is_ipv4())
                            .map(|ip| SocketAddr::new(*ip, local.port())),
                    );
                }
            }
        }
        local_candidates.extend(self.settings.configured_addrs.iter().copied());
        let (candidates, _) = tokio::sync::watch::channel(local_candidates.clone());
        let mut endpoint_config =
            noq::EndpointConfig::new(Arc::new(Blake3HmacKey::new(&mut rand::rng())));
        endpoint_config.grease_quic_bit(false);
        let runtime = Arc::new(Runtime::with_label(self.identity.id().to_string()));
        let endpoint = match noq::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Box::new(socket),
            runtime.clone(),
        ) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                runtime.abort();
                return Err(error.into());
            }
        };
        let dial_relays: Arc<tokio::sync::Mutex<HashMap<RelayUrl, DialRelay>>> = Default::default();
        for url in &relays {
            spawn_relay(RelaySession {
                runtime: runtime.clone(),
                routing: routing.clone(),
                url: url.clone(),
                client: None,
                identity: self.identity.clone(),
                https: https.clone(),
                cancel: CancellationToken::new(),
                dialed: None,
            });
        }
        if !routing.local_addrs().is_empty() && !qad_targets.is_empty() {
            super::paths::discover(
                &runtime,
                endpoint.clone(),
                https.clone(),
                qad_targets,
                local_candidates,
                candidates.clone(),
            );
        }
        let (accepted_tx, accepted_rx) = mpsc::channel(ACCEPT_QUEUE);
        let inner = Arc::new(Inner {
            endpoint,
            runtime,
            identity: self.identity,
            registry,
            provider,
            transport: self.settings.transport,
            routing,
            relays,
            keylog: self.settings.keylog,
            configured_addrs: self.settings.configured_addrs,
            candidates,
            https,
            dial_relays,
            accepted: tokio::sync::Mutex::new(accepted_rx),
        });
        spawn_acceptor(&inner, accepted_tx);
        Ok(IdentityEndpoint(inner))
    }
}

/// Bookkeeping for a relay joined for an outgoing dial.
#[derive(Debug)]
struct DialRelay {
    cancel: CancellationToken,
    joined: tokio::time::Instant,
}

/// Everything a relay session task needs to register, forward and reconnect.
struct RelaySession {
    runtime: Arc<Runtime>,
    routing: routing::Routing,
    url: RelayUrl,
    client: Option<iroh_relay::identity::Client>,
    identity: LocalIdentity,
    https: Arc<rustls::ClientConfig>,
    cancel: CancellationToken,
    /// Present for dialed relays, which leave the table when they go idle,
    /// are evicted, or fail to reconnect for too long.
    dialed: Option<Arc<tokio::sync::Mutex<HashMap<RelayUrl, DialRelay>>>>,
}

fn spawn_relay(session: RelaySession) {
    use noq::Runtime as _;
    let RelaySession {
        runtime,
        routing,
        url,
        client,
        identity,
        https,
        cancel,
        dialed,
    } = session;
    let mut outgoing = routing.add_relay(url.clone());
    let is_dialed = dialed.is_some();
    let task_routing = routing.clone();
    let task_url = url.clone();
    let task_cancel = cancel.clone();
    let task = async move {
        let routing = task_routing;
        let url = task_url;
        let mut client = client;
        let mut delay = Duration::from_millis(250);
        let mut failures = 0u32;
        loop {
            let active = match client.take() {
                Some(client) => client,
                None => match iroh_relay::identity::Client::connect(&url, &identity, https.clone())
                    .await
                {
                    Ok(client) => client,
                    Err(error) => {
                        failures += 1;
                        if is_dialed && failures >= DIAL_RELAY_FAILURES {
                            tracing::debug!(%error, %url, "abandoning unreachable dialed relay");
                            return;
                        }
                        tracing::debug!(%error, %url, "identity relay reconnect failed");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                        continue;
                    }
                },
            };
            delay = Duration::from_millis(250);
            failures = 0;
            let (send, send_rx) = mpsc::channel(256);
            let (recv_tx, mut recv) = mpsc::channel(256);
            let run = active.run(send_rx, recv_tx);
            tokio::pin!(run);
            let idle_period = DIAL_RELAY_IDLE / 2;
            let mut idle =
                tokio::time::interval_at(tokio::time::Instant::now() + idle_period, idle_period);
            let mut idle_checks = 0u8;
            loop {
                tokio::select! {
                    result = &mut run => {
                        if let Err(error) = result { tracing::debug!(%error, %url, "identity relay disconnected"); }
                        break;
                    }
                    value = outgoing.recv() => {
                        let Some(value) = value else { return; };
                        let _ = send.try_send((value.peer, value.contents));
                    }
                    value = recv.recv() => {
                        let Some((peer, contents)) = value else { break; };
                        if routing.received(url.clone(), routing::RelayDatagram { peer, contents }).is_err() { return; }
                    }
                    _ = idle.tick(), if is_dialed => {
                        if routing.relay_in_use(&url) {
                            idle_checks = 0;
                        } else {
                            idle_checks += 1;
                            if idle_checks >= 2 {
                                tracing::debug!(%url, "leaving idle dialed relay");
                                return;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(delay).await;
        }
    };
    runtime.spawn(Box::pin(async move {
        let _ = task_cancel.run_until_cancelled(task).await;
        // Whether evicted, idle or abandoned, forget the relay and its routes.
        routing.remove_relay(&url);
        // An evicted session was removed from the table before its token was
        // cancelled. A voluntary exit still owns its entry: `ensure_relay`
        // never replaces an entry that is present, so removing by URL is safe.
        if let Some(dialed) = dialed
            && !cancel.is_cancelled()
        {
            dialed.lock().await.remove(&url);
        }
    }));
}

fn check_alpn(alpn: &[u8]) -> Result<(), Error> {
    if alpn.is_empty() || alpn.len() > 255 {
        return Err(Error::Alpn);
    }
    Ok(())
}

/// An authenticated connection before it is handed to the application.
struct Accepted {
    alpn: Vec<u8>,
    direct: tokio::sync::watch::Receiver<bool>,
    inner: noq::Connection,
    remote_id: PeerId,
}

#[derive(Debug)]
struct Inner {
    endpoint: noq::Endpoint,
    runtime: Arc<Runtime>,
    identity: LocalIdentity,
    registry: Arc<Registry>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    transport: QuicTransportConfig,
    routing: routing::Routing,
    relays: BTreeSet<RelayUrl>,
    keylog: bool,
    configured_addrs: BTreeSet<SocketAddr>,
    candidates: tokio::sync::watch::Sender<BTreeSet<SocketAddr>>,
    https: Arc<rustls::ClientConfig>,
    dial_relays: Arc<tokio::sync::Mutex<HashMap<RelayUrl, DialRelay>>>,
    accepted: tokio::sync::Mutex<mpsc::Receiver<Result<Accepted, Error>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"endpoint dropped");
        self.runtime.abort();
    }
}

/// Accept incoming QUIC connections and authenticate each one on its own
/// task, so a stalled handshake never blocks other peers from connecting.
///
/// The task holds a weak endpoint reference; it stops once the endpoint
/// is dropped or closed.
fn spawn_acceptor(inner: &Arc<Inner>, accepted: mpsc::Sender<Result<Accepted, Error>>) {
    use noq::Runtime as _;
    let weak = Arc::downgrade(inner);
    let endpoint = inner.endpoint.clone();
    let runtime = inner.runtime.clone();
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    inner.runtime.spawn(Box::pin(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Some(inner) = weak.upgrade() else { break };
            let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let handshake_lease = inner.routing.pin_route(incoming.remote_address());
            drop(inner);
            let weak = weak.clone();
            let accepted = accepted.clone();
            runtime.spawn(Box::pin(async move {
                let _permit = permit;
                let _handshake_lease = handshake_lease;
                let result = async {
                    let connection = incoming.await?;
                    let inner = weak.upgrade().ok_or(Error::Closed)?;
                    authenticate(&inner, connection)
                }
                .await;
                let _ = accepted.send(result).await;
            }));
        }
    }));
}

/// Verify the peer certificate against the registry and start path management.
fn authenticate(inner: &Arc<Inner>, connection: noq::Connection) -> Result<Accepted, Error> {
    let alpn = connection
        .handshake_data()
        .and_then(|data| data.downcast::<noq::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .ok_or(Error::Alpn)?;
    let certs = connection
        .peer_identity()
        .ok_or(Error::PublicIdentity)?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| Error::PublicIdentity)?;
    if certs.len() != 1 {
        return Err(Error::PublicIdentity);
    }
    let remote_id = inner.registry.identify(certs[0].as_ref())?;
    if let Some(path) = connection.path(noq::PathId::ZERO)
        && let Ok(network) = path.network_path()
        && let Some((routed_peer, _)) = inner.routing.relay_for(network.remote())
        && routed_peer != remote_id
    {
        connection.close(0u32.into(), b"relay identity mismatch");
        return Err(Error::IdentityMismatch);
    }
    let direct = super::paths::start(
        &inner.runtime,
        connection.clone(),
        inner.routing.clone(),
        inner.candidates.subscribe(),
        inner.routing.pin(remote_id),
    );
    Ok(Accepted {
        alpn,
        direct,
        inner: connection,
        remote_id,
    })
}

/// An iroh endpoint with a pluggable identity and typed IP/relay routing.
///
/// Clones share one binding and runtime. Connections keep the runtime alive.
/// Call [`Self::close`] to drain close packets and release all endpoint tasks.
#[derive(Clone, Debug)]
pub struct IdentityEndpoint(Arc<Inner>);

impl IdentityEndpoint {
    /// Configure an endpoint with one local identity and an explicit suite policy.
    ///
    /// The registry must include the local identity's adapter. Its allowlist
    /// applies only to remote peers, independently of the local credential.
    pub fn builder(identity: LocalIdentity, registry: Arc<Registry>) -> Builder {
        crate::Endpoint::builder(crate::endpoint::presets::Empty)
            .clear_ip_transports()
            .credentials(identity, registry)
    }

    /// The identity peers must pin when dialing this endpoint.
    pub fn id(&self) -> PeerId {
        self.0.identity.id()
    }

    /// The bound IP and port, which can be unspecified when listening on all interfaces.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.0
            .routing
            .local_addrs()
            .first()
            .copied()
            .ok_or(Error::BindAddr)
    }

    /// Construct a contact from interface, observed, configured and relay addresses.
    ///
    /// Interfaces are enumerated at bind and QAD periodically refreshes observed
    /// addresses. Each location is a hint; the peer must authenticate this identity.
    pub fn addr(&self) -> Result<EndpointAddr, Error> {
        let local: Vec<_> = self.0.candidates.borrow().iter().copied().collect();
        let mut address = EndpointAddr::new(
            self.id(),
            local
                .first()
                .copied()
                .unwrap_or_else(|| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)),
        );
        address
            .addrs
            .extend(local.into_iter().skip(1).map(TransportAddr::Ip));
        address.addrs.extend(
            self.0
                .configured_addrs
                .iter()
                .copied()
                .map(TransportAddr::Ip),
        );
        address
            .addrs
            .extend(self.0.relays.iter().cloned().map(TransportAddr::Relay));
        Ok(address)
    }

    /// Authenticate exactly the requested identity over IP or a versioned relay.
    ///
    /// Supply direct addresses or a relay location in the destination. Compatible
    /// direct addresses race alongside relay registration and the relayed handshake.
    /// Authenticated NAT traversal can establish a direct path after a relay connects.
    /// Does not retry with a legacy identity. Early data and resumption are disabled.
    pub async fn connect(
        &self,
        address: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection, Error> {
        check_alpn(alpn)?;
        let address = address.into();
        if address.id == self.id() {
            return Err(Error::SelfConnect);
        }
        let local = self.0.routing.local_addrs();
        let direct: BTreeSet<_> = std::iter::once(address.addr)
            .chain(address.addrs.iter().filter_map(|a| match a {
                TransportAddr::Ip(ip) => Some(*ip),
                _ => None,
            }))
            .filter(|addr| {
                !addr.ip().is_unspecified()
                    && addr.port() != 0
                    && local
                        .iter()
                        .any(|bound| bound.is_ipv4() == addr.ip().to_canonical().is_ipv4())
            })
            .map(|addr| match addr {
                SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
                v6 => v6,
            })
            .collect();
        let relay = address.addrs.iter().find_map(|a| match a {
            TransportAddr::Relay(url) => Some(url.clone()),
            _ => None,
        });
        let _dial_lease = self.0.routing.pin(address.id);
        if direct.is_empty() && relay.is_none() {
            return Err(Error::Destination);
        }
        let mut config = tls::client(
            &self.0.identity,
            self.0.registry.clone(),
            address.id,
            alpn,
            self.0.provider.clone(),
            self.0.keylog,
        )?;
        config.transport_config(self.0.transport.to_inner_arc());
        // Each candidate uses the same pinned TLS identity. A failed or silent
        // address must not prevent another advertised location from connecting.
        let mut attempts = FuturesUnordered::new();
        // Include registration in the relay attempt so a stalled relay cannot
        // delay any of the direct candidates.
        let destinations = direct
            .into_iter()
            .map(Some)
            .chain(relay.as_ref().map(|_| None));
        for destination in destinations {
            let config = config.clone();
            let relay = relay.as_ref();
            attempts.push(async move {
                let destination = match destination {
                    Some(destination) => destination,
                    None => {
                        let relay = relay.expect("relay candidate has a relay hint");
                        self.ensure_relay(relay).await?;
                        self.0.routing.dial_address(address.id, relay.clone())?
                    }
                };
                let connection = self
                    .0
                    .endpoint
                    .connect_with(config, destination, "identity.invalid")?
                    .await?;
                let accepted = authenticate(&self.0, connection)?;
                if accepted.remote_id != address.id {
                    return Err(Error::IdentityMismatch);
                }
                Ok(accepted)
            });
        }
        let mut last_error = Error::Destination;
        while let Some(result) = attempts.next().await {
            match result {
                Ok(accepted) => return Ok(self.wrap(accepted)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn wrap(&self, accepted: Accepted) -> Connection {
        Connection {
            alpn: accepted.alpn,
            direct: accepted.direct,
            inner: accepted.inner,
            remote_id: accepted.remote_id,
            _endpoint: self.clone(),
        }
    }

    /// Join a relay named in a dial hint, evicting an idle dialed relay if needed.
    async fn ensure_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        if self.0.relays.contains(url) {
            return Ok(());
        }
        let mut dialed = self.0.dial_relays.lock().await;
        if dialed.contains_key(url) {
            return Ok(());
        }
        if dialed.len() >= MAX_DIAL_RELAYS {
            let now = tokio::time::Instant::now();
            let victim = dialed
                .iter()
                .filter(|(candidate, entry)| {
                    now.duration_since(entry.joined) >= DIAL_RELAY_GRACE
                        && !self.0.routing.relay_in_use(candidate)
                })
                .min_by_key(|(_, entry)| entry.joined)
                .map(|(candidate, _)| candidate.clone());
            let Some(victim) = victim else {
                return Err(Error::Protocol("too many relay connections"));
            };
            if let Some(entry) = dialed.remove(&victim) {
                entry.cancel.cancel();
            }
        }
        let client =
            iroh_relay::identity::Client::connect(url, &self.0.identity, self.0.https.clone())
                .await?;
        let cancel = CancellationToken::new();
        spawn_relay(RelaySession {
            runtime: self.0.runtime.clone(),
            routing: self.0.routing.clone(),
            url: url.clone(),
            client: Some(client),
            identity: self.0.identity.clone(),
            https: self.0.https.clone(),
            cancel: cancel.clone(),
            dialed: Some(self.0.dial_relays.clone()),
        });
        dialed.insert(
            url.clone(),
            DialRelay {
                cancel,
                joined: tokio::time::Instant::now(),
            },
        );
        Ok(())
    }

    /// Accept and authenticate one incoming connection.
    ///
    /// Handshakes run concurrently in the background, so one unresponsive
    /// peer cannot delay others. Authentication failure returns an error; call
    /// again to accept another peer. The application must authorize the
    /// returned [`Connection::remote_id`].
    pub async fn accept(&self) -> Result<Connection, Error> {
        let accepted = self.0.accepted.lock().await.recv().await;
        let accepted = accepted.ok_or(Error::Closed)??;
        Ok(self.wrap(accepted))
    }

    /// Close all connections, drain QUIC close packets, and stop managed tasks.
    /// Closing any clone closes the shared endpoint. Repeated calls are safe.
    pub async fn close(&self) {
        self.0.endpoint.close(0u32.into(), b"endpoint closed");
        self.0.endpoint.wait_all_draining().await;
        self.0.runtime.shutdown().await;
    }
}

/// A completed TLS handshake with an authenticated remote identity.
#[derive(Clone, Debug)]
pub struct Connection {
    alpn: Vec<u8>,
    direct: tokio::sync::watch::Receiver<bool>,
    inner: noq::Connection,
    remote_id: PeerId,
    _endpoint: IdentityEndpoint,
}

impl Connection {
    /// The ALPN protocol negotiated during the authenticated TLS handshake.
    ///
    /// Use this to dispatch accepted connections when listening for multiple protocols.
    pub fn alpn(&self) -> &[u8] {
        &self.alpn
    }

    /// Whether QUIC has validated a direct IP path for this authenticated peer.
    pub fn is_direct(&self) -> bool {
        *self.direct.borrow()
    }

    /// Wait for a validated direct path. NAT traversal preserves the TLS identity.
    pub async fn wait_direct(&self) -> Result<(), Error> {
        let mut direct = self.direct.clone();
        direct.wait_for(|v| *v).await.map_err(|_| Error::Closed)?;
        Ok(())
    }

    /// Return the authenticated remote identity for application authorization.
    pub fn remote_id(&self) -> PeerId {
        self.remote_id
    }
    /// Open a unidirectional stream.
    pub fn open_uni(&self) -> quic::OpenUni<'_> {
        self.inner.open_uni()
    }
    /// Accept a unidirectional stream.
    pub fn accept_uni(&self) -> quic::AcceptUni<'_> {
        self.inner.accept_uni()
    }
    /// Open a bidirectional stream.
    pub fn open_bi(&self) -> quic::OpenBi<'_> {
        self.inner.open_bi()
    }
    /// Accept a bidirectional stream.
    pub fn accept_bi(&self) -> quic::AcceptBi<'_> {
        self.inner.accept_bi()
    }
    /// Close this connection with an application code and reason.
    pub fn close(&self, code: quic::VarInt, reason: &[u8]) {
        self.inner.close(code, reason);
    }
    /// Wait until the connection has closed.
    pub async fn closed(&self) -> quic::ConnectionError {
        self.inner.closed().await
    }
    /// Inspect QUIC connection statistics.
    pub fn stats(&self) -> quic::ConnectionStats {
        self.inner.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_incoming_handshake_does_not_keep_endpoint_alive() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let registry = Arc::new(Registry::builtins(vec![1]).unwrap());
            let bind = || {
                IdentityEndpoint::builder(
                    LocalIdentity::ed25519(crate::SecretKey::generate(), &registry).unwrap(),
                    registry.clone(),
                )
                .bind_addr("127.0.0.1:0".parse().unwrap())
                .alpns(vec![b"lifetime/1".to_vec()])
                .transport_config(
                    QuicTransportConfig::builder()
                        .max_idle_timeout(None)
                        .build(),
                )
                .bind()
            };
            let server = bind().await.unwrap();
            let client = bind().await.unwrap();
            let weak = Arc::downgrade(&server.0);
            let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = EndpointAddr::new(server.id(), proxy.local_addr().unwrap());
            let dial = tokio::spawn({
                let client = client.clone();
                async move { client.connect(address, b"lifetime/1").await }
            });
            let mut packet = [0; 65536];
            let (len, _) = proxy.recv_from(&mut packet).await.unwrap();
            let server_addr = server.local_addr().unwrap();
            proxy.send_to(&packet[..len], server_addr).await.unwrap();
            // A server response proves the acceptor has started the handshake.
            // Withhold that response so the client never completes it.
            loop {
                let (_, source) = proxy.recv_from(&mut packet).await.unwrap();
                if source == server_addr {
                    break;
                }
            }
            drop(server);
            assert!(weak.upgrade().is_none(), "handshake retained the endpoint");
            dial.abort();
            let _ = dial.await;
            client.close().await;
        })
        .await
        .expect("stalled handshake lifetime test timed out");
    }
}
