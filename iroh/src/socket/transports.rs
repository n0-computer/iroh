use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, RelayUrl, TransportAddr};
use iroh_relay::RelayMap;
use n0_future::time::{Duration, Sleep};
use n0_watcher::Watcher;
use relay::{RelayNetworkChangeSender, RelayReceiver, RelaySender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

use super::{Socket, mapped_addrs::MultipathMappedAddr};
use crate::{
    endpoint::RelayStatus,
    metrics::EndpointMetrics,
    net_report::Report,
    socket::mapped_addrs::{
        AddrMap, CustomMappedAddr, DEFAULT_FAKE_ADDR, custom_mapped_net, endpoint_id_mapped_net,
        relay_mapped_net,
    },
};

pub(crate) mod custom;
#[cfg(not(wasm_browser))]
mod ip;
mod relay;

use custom::{CustomEndpoint, CustomSender, CustomTransport};

#[cfg(not(wasm_browser))]
pub(crate) use self::ip::Config as IpConfig;
#[cfg(not(wasm_browser))]
use self::ip::{IpNetworkChangeSender, IpSelection, IpSender, IpTransport, IpTransports};
pub(crate) use self::relay::{
    HomeRelayWatch, RelayActorConfig, RelayConnectionFailure, RelayConnectionState, RelayTransport,
};

/// How many times a transport may error on `poll_recv` in a row before we back off.
///
/// Until then noq polls the transport again right away, so a short glitch costs nothing.
/// After that, each retry waits [`RECV_ERROR_BACKOFF`].
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 8;

/// Delay between `poll_recv` retries of a transport that keeps failing.
///
/// Applies after [`MAX_CONSECUTIVE_RECV_ERRORS`] failures in a row.
const RECV_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// How many consecutive `poll_recv` errors it takes to give up on a transport.
///
/// Then the error is returned to noq, which stops receiving on this transport's socket. With
/// the backoff above this gives a broken transport about half a minute to recover, e.g.
/// through a rebind after a network change.
const MAX_RECV_ERRORS_BEFORE_GIVING_UP: usize = MAX_CONSECUTIVE_RECV_ERRORS + 30;

/// How many datagrams noq may batch into one transmit over a relay.
///
/// The relay actor splits batches into relay frames, so this only bounds the work per
/// `poll_send`. It matches a typical GSO limit.
const RELAY_TRANSMIT_SEGMENTS: NonZeroUsize = NonZeroUsize::new(64).expect("non zero");

/// Manages the different underlying data transports that the socket can support.
///
/// This is the shared half: everything senders and address watchers need. The receive
/// half of each transport lives in a [`TransportReceiver`], driven by its own noq socket.
#[derive(Debug)]
pub(crate) struct Transports {
    #[cfg(not(wasm_browser))]
    ip: IpTransports,
    relay: Vec<RelayTransport>,
    /// Shared with the [`TransportReceiver::Custom`] that polls it.
    ///
    /// `CustomEndpoint::poll_recv` takes `&mut self` while `create_sender` and
    /// `watch_local_addrs` take `&self`, and they run on different tasks, hence the lock.
    /// The receive task takes it once per batch, the others only on connect and setup.
    custom: Vec<Arc<Mutex<Box<dyn CustomEndpoint>>>>,
}

/// The receive half of one transport.
///
/// Each of these becomes one [`NoqSocket`], whose [`NoqReceiver`] noq polls in its own task.
#[derive(Debug)]
pub(crate) enum TransportReceiver {
    #[cfg(not(wasm_browser))]
    Ip(IpTransport),
    Relay(RelayReceiver),
    Custom(Arc<Mutex<Box<dyn CustomEndpoint>>>),
}

impl fmt::Display for TransportReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(not(wasm_browser))]
            Self::Ip(t) => t.fmt(f),
            Self::Relay(t) => t.fmt(f),
            Self::Custom(_) => f.write_str("CustomTransport"),
        }
    }
}

impl TransportReceiver {
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        match self {
            #[cfg(not(wasm_browser))]
            Self::Ip(t) => t.poll_recv(cx, bufs, metas, recv_infos),
            Self::Relay(t) => t.poll_recv(cx, bufs, metas, recv_infos),
            Self::Custom(t) => t
                .lock()
                .expect("poisoned")
                .poll_recv(cx, bufs, metas, recv_infos),
        }
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        match self {
            #[cfg(not(wasm_browser))]
            Self::Ip(t) => t.max_receive_segments(),
            _ => NonZeroUsize::MIN,
        }
    }
}

/// Combined watcher type for all ip transports
type IpTransportsWatcher = n0_watcher::Join<SocketAddr, n0_watcher::Direct<SocketAddr>>;
/// Combined watcher type for all custom transports
type CustomTransportsWatcher =
    n0_watcher::Join<Vec<CustomAddr>, n0_watcher::Direct<Vec<CustomAddr>>>;
/// Combined watcher type for all relay transports
type RelayTransportsWatcher = n0_watcher::Join<
    Option<(RelayUrl, EndpointId)>,
    n0_watcher::Map<n0_watcher::Direct<Option<RelayStatus>>, Option<(RelayUrl, EndpointId)>>,
>;

pub(super) type HomeRelayWatcher = n0_watcher::Map<
    n0_watcher::Join<Option<RelayStatus>, n0_watcher::Direct<Option<RelayStatus>>>,
    Vec<RelayStatus>,
>;

#[cfg(not(wasm_browser))]
/// Combined watcher type for all transports, custom, relay and ip
pub(crate) type LocalAddrsWatch = n0_watcher::Map<
    n0_watcher::Tuple<
        n0_watcher::Tuple<IpTransportsWatcher, CustomTransportsWatcher>,
        RelayTransportsWatcher,
    >,
    Vec<Addr>,
>;

/// Type for watching relay and custom transports only, no ip
#[cfg(wasm_browser)]
pub(crate) type LocalAddrsWatch =
    n0_watcher::Map<n0_watcher::Tuple<CustomTransportsWatcher, RelayTransportsWatcher>, Vec<Addr>>;

/// Available transport configurations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum TransportConfig {
    /// IP based transport
    #[cfg(not(wasm_browser))]
    Ip {
        /// The actual IP Config
        config: ip::Config,
        /// Was this added explicitly by the user.
        is_user_defined: bool,
    },
    /// Relay transport
    Relay {
        /// The [`RelayMap`] used for this relay.
        relay_map: RelayMap,
        /// Was this added explicitly by the user.
        is_user_defined: bool,
    },
    /// Custom transport factory.
    #[cfg_attr(not(feature = "unstable-custom-transports"), allow(dead_code))]
    Custom(Arc<dyn CustomTransport>),
}

impl TransportConfig {
    /// Configures a default IPv4 transport, listening on `0.0.0.0:0`.
    #[cfg(not(wasm_browser))]
    pub(crate) fn default_ipv4() -> Self {
        use std::net::Ipv4Addr;

        use ipnet::Ipv4Net;

        Self::Ip {
            config: ip::Config::V4 {
                ip_net: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("checked"),
                port: 0,
                is_required: true,
                is_default: false,
            },
            is_user_defined: false,
        }
    }

    /// Configures a default IPv6 transport, listening on `[::]:0`.
    #[cfg(not(wasm_browser))]
    pub(crate) fn default_ipv6() -> Self {
        use ipnet::Ipv6Net;

        Self::Ip {
            config: ip::Config::V6 {
                ip_net: Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("checked"),
                scope_id: 0,
                port: 0,
                is_required: false,
                is_default: false,
            },
            is_user_defined: false,
        }
    }

    /// Is this a default IPv4 configuration
    #[cfg(not(wasm_browser))]
    pub(crate) fn is_ipv4_default(&self) -> bool {
        match self {
            Self::Ip { config, .. } => config.is_default() && config.is_ipv4(),
            _ => false,
        }
    }

    /// Is this a default IPv6 configuration
    #[cfg(not(wasm_browser))]
    pub(crate) fn is_ipv6_default(&self) -> bool {
        match self {
            Self::Ip { config, .. } => config.is_default() && config.is_ipv6(),
            _ => false,
        }
    }

    /// Is this configuration set by the user.
    pub(crate) fn is_user_defined(&self) -> bool {
        match self {
            #[cfg(not(wasm_browser))]
            Self::Ip {
                is_user_defined, ..
            } => *is_user_defined,
            Self::Relay {
                is_user_defined, ..
            } => *is_user_defined,
            Self::Custom(_) => true,
        }
    }
}

impl Transports {
    /// Binds the transports.
    ///
    /// Returns the shared half and the receive half of every transport.
    pub(crate) fn bind(
        configs: &[TransportConfig],
        relay_actor_config: RelayActorConfig,
        metrics: &EndpointMetrics,
        shutdown_token: CancellationToken,
    ) -> io::Result<(Self, Vec<TransportReceiver>)> {
        #[cfg(not(wasm_browser))]
        let ip_configs = {
            let mut ip_configs = Vec::new();

            // user defined overrides defaults
            let has_ipv4_default = configs
                .iter()
                .any(|t| t.is_ipv4_default() && t.is_user_defined());
            let has_ipv6_default = configs
                .iter()
                .any(|t| t.is_ipv6_default() && t.is_user_defined());
            for config in configs {
                if let TransportConfig::Ip {
                    config,
                    is_user_defined,
                } = config
                {
                    if !is_user_defined
                        && (config.is_ipv4() && has_ipv4_default
                            || config.is_ipv6() && has_ipv6_default)
                    {
                        continue;
                    }
                    ip_configs.push(*config);
                }
            }
            ip_configs
        };
        let mut recvs = Vec::new();

        #[cfg(not(wasm_browser))]
        let ip = IpTransports::bind(ip_configs.into_iter(), metrics)?;
        #[cfg(not(wasm_browser))]
        recvs.extend(ip.iter().cloned().map(TransportReceiver::Ip));

        let mut relay = Vec::new();
        for _ in configs
            .iter()
            .filter(|t| matches!(t, TransportConfig::Relay { .. }))
        {
            let (transport, recv) =
                RelayTransport::new(relay_actor_config.clone(), shutdown_token.child_token());
            relay.push(transport);
            recvs.push(TransportReceiver::Relay(recv));
        }

        let mut custom = Vec::new();
        for config in configs.iter().filter_map(|t| {
            if let TransportConfig::Custom(config) = t {
                Some(config)
            } else {
                None
            }
        }) {
            let transport = Arc::new(Mutex::new(config.bind()?));
            recvs.push(TransportReceiver::Custom(transport.clone()));
            custom.push(transport);
        }

        let transports = Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            custom,
        };
        Ok((transports, recvs))
    }

    /// Returns a list of all currently known local addresses.
    ///
    /// For IP based transports this is the [`SocketAddr`] of the socket,
    /// for relay transports, this is the home relay.
    pub(crate) fn local_addrs(&self) -> Vec<Addr> {
        self.local_addrs_watch().get()
    }

    pub(super) fn home_relay_watch(&self) -> HomeRelayWatcher {
        n0_watcher::Join::new(self.relay.iter().map(|t| t.my_relay_status()))
            .map(|v| v.into_iter().flatten().collect())
    }

    #[cfg(not(wasm_browser))]
    /// Watch for all currently known local addresses, including IP based transports.
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let ips = n0_watcher::Join::new(self.ip.iter().map(|t| t.local_addr_watch()));
        let relays = n0_watcher::Join::new(self.relay.iter().map(|t| t.local_addr_watch()));
        let custom = n0_watcher::Join::new(
            self.custom
                .iter()
                .map(|t| t.lock().expect("poisoned").watch_local_addrs()),
        );

        ips.or(custom).or(relays).map(|((ips, custom), relays)| {
            let ips = ips.into_iter().map(Addr::from);
            let custom = custom.into_iter().flatten().map(Addr::from);
            let relays = relays
                .into_iter()
                .flatten()
                .map(|(relay_url, endpoint_id)| Addr::Relay(relay_url, endpoint_id));
            ips.chain(custom).chain(relays).collect()
        })
    }

    #[cfg(wasm_browser)]
    /// Watch for all currently known local addresses, excluding IP based transports.
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let relays = n0_watcher::Join::new(self.relay.iter().map(|t| t.local_addr_watch()));
        let custom = n0_watcher::Join::new(
            self.custom
                .iter()
                .map(|t| t.lock().expect("poisoned").watch_local_addrs()),
        );
        custom.or(relays).map(|(custom, relays)| {
            let custom = custom.into_iter().flatten().map(Addr::from);
            let relays = relays
                .into_iter()
                .flatten()
                .map(|(relay_url, endpoint_id)| Addr::Relay(relay_url, endpoint_id));
            custom.chain(relays).collect()
        })
    }

    /// Returns the bound addresses for IP based transports
    #[cfg(not(wasm_browser))]
    pub(crate) fn ip_bind_addrs(&self) -> Vec<SocketAddr> {
        self.ip.iter().map(|t| t.bind_addr()).collect()
    }

    /// Handles potential changes to the underlying network conditions.
    pub(crate) fn create_network_change_sender(&self) -> NetworkChangeSender {
        NetworkChangeSender {
            #[cfg(not(wasm_browser))]
            ip: self
                .ip
                .iter()
                .map(|t| t.create_network_change_sender())
                .collect(),
            relay: self
                .relay
                .iter()
                .map(|t| t.create_network_change_sender())
                .collect(),
        }
    }

    /// Creates the noq sockets for all transports, with their routes.
    ///
    /// Every transport gets a socket that receives on it. IP transports also send on their
    /// own socket, routed by their config. The relay and the custom transports each share
    /// one more socket, which only sends and routes their mapped address range. A last one
    /// routes the [`EndpointIdMappedAddr`] range, so sends to a remote over all its paths
    /// get their own send waker.
    ///
    /// Fails if no transport is bound at all, as the endpoint could not reach anything.
    ///
    /// [`EndpointIdMappedAddr`]: crate::socket::mapped_addrs::EndpointIdMappedAddr
    #[allow(clippy::type_complexity)] // The argument of `noq::Endpoint::new_with_multiple_sockets`.
    pub(crate) fn noq_sockets(
        self,
        sock: Arc<Socket>,
        recvs: Vec<TransportReceiver>,
    ) -> io::Result<Vec<(Box<dyn noq::AsyncUdpSocketNext>, Vec<noq::SocketRoute>)>> {
        if recvs.is_empty() {
            return Err(io::Error::other("no valid address available"));
        }
        let transports = Arc::new(self);
        let live_transports = Arc::new(AtomicUsize::new(recvs.len()));
        let socket =
            |kind, transport: Option<TransportReceiver>| -> Box<dyn noq::AsyncUdpSocketNext> {
                let receiver = transport.map(|transport| NoqReceiver {
                    sock: sock.clone(),
                    live_transports: live_transports.clone(),
                    transport,
                    recv_infos: Default::default(),
                    consecutive_recv_failures: 0,
                    recv_backoff: None,
                });
                Box::new(NoqSocket {
                    sock: sock.clone(),
                    transports: transports.clone(),
                    kind,
                    receiver: Mutex::new(receiver),
                })
            };

        let mut sockets = Vec::new();
        for recv in recvs {
            let (kind, routes) = match &recv {
                #[cfg(not(wasm_browser))]
                TransportReceiver::Ip(t) => {
                    (SocketKind::Ip(t.clone()), vec![t.config().socket_route()])
                }
                TransportReceiver::Relay(_) => (SocketKind::Relay, Vec::new()),
                TransportReceiver::Custom(_) => (SocketKind::Custom, Vec::new()),
            };
            sockets.push((socket(kind, Some(recv)), routes));
        }
        for (kind, net) in [
            (SocketKind::Relay, relay_mapped_net()),
            (SocketKind::Custom, custom_mapped_net()),
            (SocketKind::Mixed, endpoint_id_mapped_net()),
        ] {
            let route = noq::SocketRoute::new(net.into());
            sockets.push((socket(kind, None), vec![route]));
        }
        Ok(sockets)
    }

    /// Creates a sender for the sockets of `kind`, and its segmentation limit
    fn create_sender(&self, kind: &SocketKind) -> (TransportSender, NonZeroUsize) {
        match kind {
            #[cfg(not(wasm_browser))]
            SocketKind::Ip(t) => (
                TransportSender::Ip(t.create_sender()),
                t.max_transmit_segments(),
            ),
            SocketKind::Relay => {
                let senders = self.relay.iter().map(|t| t.create_sender());
                (
                    TransportSender::Relay(senders.collect()),
                    RELAY_TRANSMIT_SEGMENTS,
                )
            }
            SocketKind::Custom => {
                let custom = self.custom.iter().map(|t| t.lock().expect("poisoned"));
                let (senders, segments): (Vec<_>, Vec<_>) = custom
                    .map(|t| (t.create_sender(), t.max_transmit_segments()))
                    .unzip();
                let max = segments.into_iter().min().unwrap_or(NonZeroUsize::MIN);
                (TransportSender::Custom(senders), max)
            }
            SocketKind::Mixed => {
                let sender = Box::new(self.transports_sender());
                (TransportSender::Mixed(sender), NonZeroUsize::MIN)
            }
        }
    }

    /// A sender over all transports, for the remote state actor's Initial packets
    fn transports_sender(&self) -> TransportsSender {
        TransportsSender {
            #[cfg(not(wasm_browser))]
            ip: IpSelection::new(self.ip.iter().map(|t| t.config())),
            #[cfg(not(wasm_browser))]
            ip_senders: self.ip.iter().map(|t| t.create_sender()).collect(),
            relay: self.relay.iter().map(|t| t.create_sender()).collect(),
            custom: self
                .custom
                .iter()
                .map(|t| t.lock().expect("poisoned").create_sender())
                .collect(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct NetworkChangeSender {
    #[cfg(not(wasm_browser))]
    ip: Vec<IpNetworkChangeSender>,
    relay: Vec<RelayNetworkChangeSender>,
}

impl NetworkChangeSender {
    pub(crate) fn on_network_change(&self, report: &Report) {
        #[cfg(not(wasm_browser))]
        for ip in &self.ip {
            ip.on_network_change(report);
        }

        for relay in &self.relay {
            relay.on_network_change(report);
        }
    }

    /// Triggers an immediate relay connection health check after a network change.
    ///
    /// Uses RTT-based timeout for faster detection of broken connections.
    pub(crate) fn check_relay_connection(&self) {
        for relay in &self.relay {
            relay.check_connection_after_network_change();
        }
    }

    /// Rebinds underlying connections, if necessary.
    pub(crate) fn rebind(&self) -> std::io::Result<()> {
        let mut res = Ok(());

        #[cfg(not(wasm_browser))]
        for transport in &self.ip {
            if let Err(err) = transport.rebind() {
                warn!("failed to rebind {:?}", err);
                res = Err(err);
            }
        }

        for transport in &self.relay {
            if let Err(err) = transport.rebind() {
                warn!("failed to rebind {:?}", err);
                res = Err(err);
            }
        }
        res
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub struct Transmit<'a> {
    pub(crate) ecn: Option<noq_udp::EcnCodepoint>,
    /// Packet contents
    pub contents: &'a [u8],
    /// Optional segment size for GSO
    pub segment_size: Option<usize>,
}

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct OwnedTransmit {
    pub(crate) ecn: Option<noq_udp::EcnCodepoint>,
    pub(crate) contents: Bytes,
    pub(crate) segment_size: Option<usize>,
}

impl From<&noq_udp::Transmit<'_>> for OwnedTransmit {
    fn from(source: &noq_udp::Transmit<'_>) -> Self {
        Self {
            ecn: source.ecn,
            contents: Bytes::copy_from_slice(source.contents),
            segment_size: source.segment_size,
        }
    }
}

/// Transports address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Addr {
    /// An IP address, should always be stored in its canonical form.
    Ip(SocketAddr),
    /// A relay address.
    Relay(RelayUrl, EndpointId),
    /// A custom transport address.
    Custom(CustomAddr),
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Addr::Ip(addr) => write!(f, "Ip({addr})"),
            Addr::Relay(url, node_id) => write!(f, "Relay({url}, {})", node_id.fmt_short()),
            Addr::Custom(custom_addr) => write!(f, "Custom({custom_addr:?})"),
        }
    }
}

/// Per-packet recv data filled in by transports during [`poll_recv`][CustomEndpoint::poll_recv].
///
/// This carries the bits of [`noq_udp::RecvMeta`] that custom transports
/// can't express through `RecvMeta` itself: the remote address as a
/// [`CustomAddr`] and, optionally, the local custom address that received
/// the packet. For IP transports the kernel populates `RecvMeta` directly;
/// for relays the local URL is the remote's relay URL — so for them this
/// struct is filled in only with the remote variant.
///
/// Custom transport authors construct values via [`RecvInfo::new`], which
/// only accepts [`CustomAddr`].
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
#[derive(Clone, Debug, Default)]
pub struct RecvInfo {
    remote: Addr,
    local: Option<CustomAddr>,
}

impl RecvInfo {
    /// Creates a [`RecvInfo`] from an internal [`Addr`], with no local custom
    /// address. Used by IP and relay recv paths.
    pub(crate) fn from_addr(remote: Addr) -> Self {
        Self {
            remote,
            local: None,
        }
    }

    pub(crate) fn remote(&self) -> &Addr {
        &self.remote
    }

    pub(crate) fn local(&self) -> Option<&CustomAddr> {
        self.local.as_ref()
    }
}

#[cfg(feature = "unstable-custom-transports")]
impl RecvInfo {
    /// Creates a new [`RecvInfo`] for an incoming packet on a custom transport.
    ///
    /// `remote` is the remote custom address. `local` is the local custom
    /// address that received this packet, if the transport can identify it;
    /// pass `None` otherwise.
    pub fn new(remote: CustomAddr, local: Option<CustomAddr>) -> Self {
        Self {
            remote: Addr::Custom(remote),
            local,
        }
    }
}

impl Default for Addr {
    fn default() -> Self {
        Self::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
    }
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => Self::Ip(value),
            SocketAddr::V6(addr) => {
                Self::Ip(SocketAddr::new(addr.ip().to_canonical(), addr.port()))
            }
        }
    }
}

impl From<&SocketAddr> for Addr {
    fn from(value: &SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => Self::Ip(*value),
            SocketAddr::V6(addr) => {
                Self::Ip(SocketAddr::new(addr.ip().to_canonical(), addr.port()))
            }
        }
    }
}

impl From<CustomAddr> for Addr {
    fn from(value: CustomAddr) -> Self {
        Self::Custom(value)
    }
}

impl From<(RelayUrl, EndpointId)> for Addr {
    fn from(value: (RelayUrl, EndpointId)) -> Self {
        Self::Relay(value.0, value.1)
    }
}

impl From<Addr> for TransportAddr {
    fn from(value: Addr) -> Self {
        match value {
            Addr::Ip(addr) => TransportAddr::Ip(addr),
            Addr::Relay(url, _) => TransportAddr::Relay(url),
            Addr::Custom(addr) => TransportAddr::Custom(addr),
        }
    }
}

impl Addr {
    pub(crate) fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(..))
    }

    /// Returns `None` if not an `Ip`.
    pub(crate) fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Self::Ip(ip) => Some(ip),
            Self::Relay(..) => None,
            Self::Custom(_) => None,
        }
    }
}

/// The local address of a network path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LocalTransportAddr {
    /// The local IP.
    ///
    /// This is almost always present, only some very old operating systems do not support
    /// it.
    Ip(Option<IpAddr>),
    /// The relay over which this network path is connected.
    Relay(RelayUrl),
    /// The local custom address, if the transport reports one.
    Custom(Option<iroh_base::CustomAddr>),
}

impl LocalTransportAddr {
    /// Converts a local address from noq into a [`LocalTransportAddr`].
    ///
    /// This also needs the `remote_addr`, because currently the meaning of the local_ip as returned
    /// from noq depends on the kind of network path, which we can gather from the remote address.
    ///
    /// The meaning of the local IP is a bit particular:
    ///
    /// * For IP transports, it is the address of the local socket.
    /// * For relay transports, we never set the local_ip in the recv meta.
    ///   We take the relay URL of the remote address here instead.
    /// * For custom transports, the custom transport implementation can set a [`CustomAddr`]
    ///   through [`RecvInfo`], which is passed as a mapped address to noq. So we convert it
    ///   back into the [`CustomAddr`] here.
    pub(super) fn from_noq_local_ip(
        noq_local_ip: Option<IpAddr>,
        remote_addr: &Addr,
        custom_mapped_addrs: &AddrMap<CustomAddr, CustomMappedAddr>,
    ) -> Self {
        match &remote_addr {
            // If the remote is a relay, noq_local_ip will be unset because we never set it for relay transports.
            // We return a [`LocalTransportAddr`] with the relay URL.
            Addr::Relay(url, _endpoint_id) => LocalTransportAddr::Relay(url.clone()),
            // For IP transports, the local_ip as reported from noq is the interface IP (umapped), if known.
            Addr::Ip(_) => LocalTransportAddr::Ip(noq_local_ip),
            // For custom transports, the custom transport implementation can set a `CustomAddr` in `RecvInfo`.
            // The custom addr is converted to a mapped address in `super::Socket::process_datagrams`.
            // We convert back to a `CustomAddr` here.
            Addr::Custom(_) => {
                let addr = noq_local_ip
                    .and_then(|ip_addr| CustomMappedAddr::try_from(ip_addr).ok())
                    .and_then(|custom_mapped_addr| custom_mapped_addrs.lookup(&custom_mapped_addr));
                LocalTransportAddr::Custom(addr)
            }
        }
    }
}

/// The kind of a transport address, used for configuring bias.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub enum AddrKind {
    /// An IPv4 address.
    IpV4,
    /// An IPv6 address.
    IpV6,
    /// A relay address.
    Relay,
    /// A custom transport address with the given id.
    Custom(u64),
}

impl PartialEq<TransportAddr> for Addr {
    fn eq(&self, other: &TransportAddr) -> bool {
        match self {
            Addr::Ip(socket_addr) => {
                matches!(other, TransportAddr::Ip(a) if a == socket_addr)
            }
            Addr::Relay(relay_url, _) => {
                matches!(other, TransportAddr::Relay(a) if a == relay_url)
            }
            Addr::Custom(custom_addr) => {
                matches!(other, TransportAddr::Custom(a) if a == custom_addr)
            }
        }
    }
}

/// Identifies a network path by the combination of remote and local addresses.
///
/// The meaning of the local address is a bit particular:
/// * For IP transports it is the interface IP, if known.
/// * For custom transports it is a custom transport address, if the transport implementation reports one.
/// * For relay transports there is no separate local address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub enum FourTuple {
    /// A path over an IP transport.
    Ip {
        /// The remote socket address.
        remote: SocketAddr,
        /// The local interface IP, if the OS reported one.
        local: Option<IpAddr>,
    },
    /// A path over a relay transport.
    Relay {
        /// The URL of the relay server carrying this path.
        url: RelayUrl,
        /// The remote endpoint reached through the relay.
        endpoint_id: EndpointId,
    },
    /// A path over a custom transport.
    Custom {
        /// The remote custom transport address.
        remote: CustomAddr,
        /// The local custom transport address, if the transport reports one.
        local: Option<CustomAddr>,
    },
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl FourTuple {
    /// Creates a four-tuple from a remote address, with no known local address.
    pub fn from_remote(remote: Addr) -> Self {
        match remote {
            Addr::Ip(remote) => Self::Ip {
                remote,
                local: None,
            },
            Addr::Relay(url, endpoint_id) => Self::Relay { url, endpoint_id },
            Addr::Custom(remote) => Self::Custom {
                remote,
                local: None,
            },
        }
    }

    /// Creates a four-tuple from a remote and a local transport address.
    ///
    /// The variant is determined by `remote`. The `local` address is retained only when
    /// it matches that variant. A mismatched `local` is dropped, which cannot happen for
    /// values derived together from the same network path.
    pub fn new(remote: Addr, local: LocalTransportAddr) -> Self {
        match remote {
            Addr::Ip(remote) => Self::Ip {
                remote,
                local: match local {
                    LocalTransportAddr::Ip(local) => local,
                    _ => None,
                },
            },
            Addr::Relay(url, endpoint_id) => Self::Relay { url, endpoint_id },
            Addr::Custom(remote) => Self::Custom {
                remote,
                local: match local {
                    LocalTransportAddr::Custom(local) => local,
                    _ => None,
                },
            },
        }
    }

    /// Returns the remote transport address.
    pub fn remote(&self) -> Addr {
        match self {
            Self::Ip { remote, .. } => Addr::Ip(*remote),
            Self::Relay { url, endpoint_id } => Addr::Relay(url.clone(), *endpoint_id),
            Self::Custom { remote, .. } => Addr::Custom(remote.clone()),
        }
    }

    /// Returns the local transport address.
    pub fn local(&self) -> LocalTransportAddr {
        match self {
            Self::Ip { local, .. } => LocalTransportAddr::Ip(*local),
            Self::Relay { url, .. } => LocalTransportAddr::Relay(url.clone()),
            Self::Custom { local, .. } => LocalTransportAddr::Custom(local.clone()),
        }
    }

    /// Returns `true` if the remote is an IP address.
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip { .. })
    }

    /// Returns `true` if the remote is a relay address.
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::Relay { .. })
    }

    /// Returns the kind of address, for configuring bias.
    pub fn addr_kind(&self) -> AddrKind {
        match self {
            Self::Ip { remote, .. } => match remote {
                SocketAddr::V4(_) => AddrKind::IpV4,
                SocketAddr::V6(_) => AddrKind::IpV6,
            },
            Self::Relay { .. } => AddrKind::Relay,
            Self::Custom { remote, .. } => AddrKind::Custom(remote.id()),
        }
    }
}

impl fmt::Display for FourTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FourTuple::Ip { remote, local } => {
                if let Some(local) = local {
                    write!(f, "Ip({local}->{remote})")
                } else {
                    write!(f, "Ip({remote})")
                }
            }
            FourTuple::Relay { url, endpoint_id } => {
                write!(f, "Relay({url}, {})", endpoint_id.fmt_short())
            }
            FourTuple::Custom { remote, local } => {
                if let Some(local) = local {
                    write!(f, "Custom({local}->{remote})")
                } else {
                    write!(f, "Custom({remote})")
                }
            }
        }
    }
}

/// A sender that sends to all our transports.
///
/// The remote state actor sends QUIC Initial packets with it, to every known path of a
/// remote, as iroh did before multi-socket. Every other send goes through the per-transport
/// noq sockets.
#[derive(Debug, Clone)]
pub(crate) struct TransportsSender {
    /// Picks the IP transport, the same way noq does
    #[cfg(not(wasm_browser))]
    ip: IpSelection,
    /// Indexed by the transport index of [`IpSelection`]
    #[cfg(not(wasm_browser))]
    ip_senders: Vec<IpSender>,
    relay: Vec<RelaySender>,
    custom: Vec<Arc<dyn CustomSender>>,
}

impl TransportsSender {
    pub(crate) fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        network_path: &FourTuple,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        match network_path {
            #[cfg(wasm_browser)]
            FourTuple::Ip { .. } => {
                return Poll::Ready(Err(io::Error::other("IP is unsupported in browser")));
            }
            #[cfg(not(wasm_browser))]
            FourTuple::Ip { remote, local } => {
                let this = &mut *self;
                if let Some(index) = this.ip.select(*remote, *local)
                    && let Some(sender) = this.ip_senders.get_mut(index)
                {
                    return Pin::new(sender).poll_send(cx, *remote, *local, transmit);
                }
            }
            FourTuple::Relay { url, endpoint_id } => {
                let mut has_valid_sender = false;
                for sender in self
                    .relay
                    .iter_mut()
                    .filter(|s| s.is_valid_send_addr(url, endpoint_id))
                {
                    has_valid_sender = true;
                    match sender.poll_send(cx, url.clone(), *endpoint_id, transmit) {
                        Poll::Pending => {}
                        Poll::Ready(res) => return Poll::Ready(res),
                    }
                }
                if has_valid_sender {
                    return Poll::Pending;
                }
            }
            FourTuple::Custom { remote, local } => {
                for sender in &mut self.custom {
                    if sender.is_valid_send_addr(remote) {
                        match sender.poll_send(cx, remote, local.as_ref(), transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
        }

        // We "blackhole" data that we have not found any usable transport for on
        // to make sure the QUIC stack picks up that currently this data does not arrive.
        trace!(%network_path, "no valid transport available");
        Poll::Ready(Ok(()))
    }
}

/// The transport side of a [`NoqSender`]
#[derive(Debug)]
enum TransportSender {
    #[cfg(not(wasm_browser))]
    Ip(IpSender),
    Relay(Vec<RelaySender>),
    Custom(Vec<Arc<dyn CustomSender>>),
    /// Forwards Initial packets to the remote state actor
    ///
    /// The actor sends them on every path, through the [`TransportsSender`] that comes along
    /// with each packet.
    Mixed(Box<TransportsSender>),
}

impl TransportSender {
    /// Sends `transmit` to the destination noq addressed as `mapped_addr`.
    ///
    /// The mapped address is translated back to the transport's own address here, so each
    /// arm reads: look the destination up, hand it to this transport's sender.
    fn poll_send(
        &mut self,
        cx: &mut Context,
        sock: &Socket,
        mapped_addr: MultipathMappedAddr,
        noq_transmit: &noq_udp::Transmit,
    ) -> Poll<io::Result<()>> {
        let transmit = Transmit {
            ecn: noq_transmit.ecn,
            contents: noq_transmit.contents,
            segment_size: noq_transmit.segment_size,
        };
        match (self, mapped_addr) {
            (Self::Mixed(sender), MultipathMappedAddr::Mixed(mapped_addr)) => {
                let Some(endpoint_id) = sock.mapped_addrs.endpoint_addrs.lookup(&mapped_addr)
                else {
                    error!(dst = ?mapped_addr, "unknown NodeIdMappedAddr, dropped transmit");
                    return Poll::Ready(Ok(()));
                };

                // Note we drop the src_ip set in the Noq Transmit.  This is only the
                // Initial packet we are sending, so we do not yet have an src address we
                // need to respond from.
                if let Some(src_ip) = noq_transmit.src_ip {
                    warn!(dst = ?mapped_addr, ?src_ip, dst_endpoint = %endpoint_id.fmt_short(),
                        "oops, flub didn't think this would happen");
                }

                if let Err(msg) = sock.try_send_remote_state_msg(
                    endpoint_id,
                    super::RemoteStateMessage::SendDatagram(
                        sender.clone(),
                        OwnedTransmit::from(noq_transmit),
                    ),
                ) {
                    // We do not want to block the next send which might be on a
                    // different transport.  Instead we let Noq handle this as
                    // a lost datagram.
                    // TODO: Revisit this: we might want to do something better.
                    debug!(
                        dst = ?mapped_addr,
                        dst_endpoint = %endpoint_id.fmt_short(),
                        ?msg,
                        "RemoteStateActor inbox dropped message"
                    );
                }
                return Poll::Ready(Ok(()));
            }
            (Self::Relay(senders), MultipathMappedAddr::Relay(mapped_addr)) => {
                let Some((url, endpoint_id)) = sock.mapped_addrs.relay_addrs.lookup(&mapped_addr)
                else {
                    error!("unknown RelayMappedAddr, dropped transmit");
                    return Poll::Ready(Ok(()));
                };
                let mut has_valid_sender = false;
                for sender in senders
                    .iter_mut()
                    .filter(|s| s.is_valid_send_addr(&url, &endpoint_id))
                {
                    has_valid_sender = true;
                    match sender.poll_send(cx, url.clone(), endpoint_id, &transmit) {
                        Poll::Pending => {}
                        Poll::Ready(res) => return Poll::Ready(res),
                    }
                }
                if has_valid_sender {
                    return Poll::Pending;
                }
            }
            (Self::Custom(senders), MultipathMappedAddr::Custom(mapped_addr)) => {
                let Some(remote) = sock.mapped_addrs.custom_addrs.lookup(&mapped_addr) else {
                    error!("unknown CustomMappedAddr, dropped transmit");
                    return Poll::Ready(Ok(()));
                };
                let local = noq_transmit
                    .src_ip
                    .and_then(|ip_addr| CustomMappedAddr::try_from(ip_addr).ok())
                    .and_then(|addr| sock.mapped_addrs.custom_addrs.lookup(&addr));
                let mut has_valid_sender = false;
                for sender in senders.iter().filter(|s| s.is_valid_send_addr(&remote)) {
                    has_valid_sender = true;
                    match sender.poll_send(cx, &remote, local.as_ref(), &transmit) {
                        Poll::Pending => {}
                        Poll::Ready(res) => return Poll::Ready(res),
                    }
                }
                if has_valid_sender {
                    return Poll::Pending;
                }
            }
            #[cfg(not(wasm_browser))]
            (Self::Ip(sender), MultipathMappedAddr::Ip(remote)) => {
                // Ensure IPv6 mapped addresses are converted back
                let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
                return Pin::new(sender).poll_send(cx, remote, noq_transmit.src_ip, &transmit);
            }
            // noq routed this destination to a socket whose transport cannot reach it, e.g. a
            // relay address while no relay transport is configured.
            (_, mapped_addr) => {
                trace!(dst = ?mapped_addr, "no valid transport available");
            }
        }

        // We "blackhole" data that we have not found any usable transport for on
        // to make sure the QUIC stack picks up that currently this data does not arrive.
        Poll::Ready(Ok(()))
    }
}

/// What a [`NoqSocket`] sends on
#[derive(Debug)]
enum SocketKind {
    #[cfg(not(wasm_browser))]
    Ip(IpTransport),
    /// All relay transports
    Relay,
    /// All custom transports
    Custom,
    /// The remote state actor, for Initial packets to an [`EndpointIdMappedAddr`]
    ///
    /// [`EndpointIdMappedAddr`]: crate::socket::mapped_addrs::EndpointIdMappedAddr
    Mixed,
}

/// A transport, or a group of them, as a noq socket, working with [`MultipathMappedAddr`]s.
///
/// The [`MultipathMappedAddr`]s have an IPv6 representation that noq uses. The senders of
/// this socket map them back to the transport [`Addr`]s of the shared [`Transports`].
#[derive(Debug)]
struct NoqSocket {
    sock: Arc<Socket>,
    transports: Arc<Transports>,
    kind: SocketKind,
    /// Taken by noq when it adds the socket. `None` for the sockets that only send.
    receiver: Mutex<Option<NoqReceiver>>,
}

impl noq::AsyncUdpSocketNext for NoqSocket {
    fn create_sender(&self) -> Pin<Box<dyn noq::UdpSender>> {
        let (transport, max_transmit_segments) = self.transports.create_sender(&self.kind);
        Box::pin(NoqSender {
            sock: self.sock.clone(),
            transport,
            max_transmit_segments,
        })
    }

    fn create_receiver(&self) -> Option<Box<dyn noq::AsyncUdpReceiver>> {
        let receiver = self.receiver.lock().expect("poisoned").take()?;
        Some(Box::new(receiver))
    }

    /// The local address of this socket's transport.
    ///
    /// IP transports report their bound address. The other transports have no IP address
    /// and report a fake IPv6 one.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.kind {
            #[cfg(not(wasm_browser))]
            SocketKind::Ip(t) => Ok(t.local_addr_watch().get()),
            SocketKind::Relay | SocketKind::Custom | SocketKind::Mixed => {
                Ok(DEFAULT_FAKE_ADDR.into())
            }
        }
    }

    fn may_fragment(&self) -> bool {
        match &self.kind {
            #[cfg(not(wasm_browser))]
            SocketKind::Ip(t) => t.may_fragment(),
            _ => false,
        }
    }
}

/// Receives on one transport for noq, which polls it in its own task.
#[derive(Debug)]
struct NoqReceiver {
    sock: Arc<Socket>,
    /// Transports still receiving, shared by all receivers
    live_transports: Arc<AtomicUsize>,
    transport: TransportReceiver,
    /// Cache for per-packet recv info, to speed up access
    recv_infos: Box<[RecvInfo; noq_udp::BATCH_SIZE]>,
    consecutive_recv_failures: usize,
    /// Set while we wait before retrying a failing transport, see [`RECV_ERROR_BACKOFF`].
    recv_backoff: Option<Pin<Box<Sleep>>>,
}

impl noq::AsyncUdpReceiver for NoqReceiver {
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert!(bufs.len() <= noq_udp::BATCH_SIZE, "too many buffers");
        if self.sock.is_closed() {
            return Poll::Pending;
        }
        if let Some(backoff) = &mut self.recv_backoff {
            n0_future::ready!(backoff.as_mut().poll(cx));
            self.recv_backoff = None;
        }

        match self
            .transport
            .poll_recv(cx, bufs, metas, &mut self.recv_infos[..bufs.len()])
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(n)) => {
                self.consecutive_recv_failures = 0;
                self.sock
                    .process_datagrams(&mut bufs[..n], &mut metas[..n], &self.recv_infos[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                // Transports swallow the errors they know to be transient (see e.g.
                // netwatch's read error handling). What reaches us is unclassified, so we
                // retry: first right away, then with a delay, and finally give up.
                self.consecutive_recv_failures += 1;
                if self.consecutive_recv_failures >= MAX_RECV_ERRORS_BEFORE_GIVING_UP {
                    warn!(transport = %self.transport, "transport failed to receive repeatedly, giving up on it: {err:#}");
                    if self.live_transports.fetch_sub(1, Ordering::AcqRel) == 1 {
                        error!("all transports failed to receive, connections will time out");
                    }
                    return Poll::Ready(Err(err));
                }
                debug!(transport = %self.transport, failures = self.consecutive_recv_failures, "recv error: {err:#}");
                if self.consecutive_recv_failures >= MAX_CONSECUTIVE_RECV_ERRORS {
                    let mut backoff = Box::pin(n0_future::time::sleep(RECV_ERROR_BACKOFF));
                    // Register our waker with the timer, so noq polls us again when it fires.
                    if backoff.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(0));
                    }
                    self.recv_backoff = Some(backoff);
                    return Poll::Pending;
                }
                // Let noq poll again right away, like a transient error.
                Poll::Ready(Ok(0))
            }
        }
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.transport.max_receive_segments()
    }
}

/// The sender noq uses for a [`NoqSocket`].
///
/// Translates noq's destination, a possibly mapped address, back to the transport's own
/// address and sends on that transport. A [`MultipathMappedAddr::Mixed`] destination is
/// forwarded to the remote state actor, which sends on all of the remote's paths.
#[derive(Debug)]
pub(crate) struct NoqSender {
    sock: Arc<Socket>,
    transport: TransportSender,
    /// The segmentation limit of the transport this sender belongs to
    max_transmit_segments: NonZeroUsize,
}

impl NoqSender {
    /// Extracts the right [`Addr`] from the [`noq_udp::Transmit`].
    ///
    /// Because Noq does only know about IP transports we map other transports to private
    /// IPv6 Unique Local Address ranges.  This extracts the transport addresses out of the
    /// transmit's destination.
    fn mapped_addr(&self, transmit: &noq_udp::Transmit) -> io::Result<MultipathMappedAddr> {
        if self.sock.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }

        Ok(MultipathMappedAddr::from(transmit.destination))
    }
}

impl noq::UdpSender for NoqSender {
    fn poll_send(
        self: Pin<&mut Self>,
        noq_transmit: &noq_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        // On errors this methods prefers returning Ok(()) to Noq.  Returning an error
        // should only happen if the error is permanent and fatal and it will never be
        // possible to send anything again.  Doing so closes the connection.  Most
        // send errors are intermittent errors, returning Ok(()) in those cases will mean
        // Noq eventually considers the packets that had send errors as lost and will try
        // and re-send them.
        let mapped_addr = self.mapped_addr(noq_transmit)?;
        let this = self.get_mut();

        match this
            .transport
            .poll_send(cx, &this.sock, mapped_addr, noq_transmit)
        {
            Poll::Ready(Ok(())) => {
                trace!(
                    dst = %noq_transmit.destination,
                    len = noq_transmit.contents.len(),
                    "sent transmit"
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(ref err)) => {
                debug!(dst = %noq_transmit.destination, "dropped transmit: {err:#}");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // noq holds this transmit back and keeps sending to other destinations in
                // the meantime, so a full transport only slows down its own paths. Before
                // noq could do that, we had to drop the datagram here.
                trace!(dst = %noq_transmit.destination, "transport pending");
                Poll::Pending
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.max_transmit_segments
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    impl TransportsSender {
        /// A sender whose relay transport is a channel of `capacity` items
        pub(in crate::socket) fn with_bounded_relay(
            capacity: usize,
            #[cfg(not(wasm_browser))] ip_configs: impl Iterator<Item = IpConfig>,
        ) -> (
            TransportsSender,
            impl futures_util::Stream<Item = ()> + Unpin,
        ) {
            let (relay, receiver) = RelaySender::bounded_for_test(capacity);
            #[cfg(not(wasm_browser))]
            let ip = IpTransports::bind(ip_configs, &EndpointMetrics::default())
                .expect("test transports must bind");
            let sender = TransportsSender {
                #[cfg(not(wasm_browser))]
                ip: IpSelection::new(ip.iter().map(|t| t.config())),
                #[cfg(not(wasm_browser))]
                ip_senders: ip.iter().map(|t| t.create_sender()).collect(),
                relay: vec![relay],
                custom: Vec::new(),
            };
            (
                sender,
                tokio_stream::wrappers::ReceiverStream::new(receiver).map(|_| ()),
            )
        }
    }
}
