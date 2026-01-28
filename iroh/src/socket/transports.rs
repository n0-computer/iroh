use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, RelayUrl, TransportAddr};
use iroh_relay::RelayMap;
use n0_watcher::Watcher;
use quinn_proto::PathStatus;
use relay::{RelayNetworkChangeSender, RelaySender};
use rustc_hash::FxHashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, instrument, trace, warn};

use super::{Socket, mapped_addrs::MultipathMappedAddr};
use crate::{metrics::EndpointMetrics, net_report::Report};

pub(crate) mod custom;
#[cfg(not(wasm_browser))]
mod ip;
mod relay;

use custom::{CustomEndpoint, CustomSender, CustomTransport};

#[cfg(not(wasm_browser))]
pub(crate) use self::ip::Config as IpConfig;
#[cfg(not(wasm_browser))]
use self::ip::{IpNetworkChangeSender, IpTransports, IpTransportsSender};
pub(crate) use self::relay::{RelayActorConfig, RelayTransport};

/// Manages the different underlying data transports that the socket can support.
#[derive(Debug)]
pub(crate) struct Transports {
    #[cfg(not(wasm_browser))]
    ip: IpTransports,
    relay: Vec<RelayTransport>,
    custom: Vec<Box<dyn CustomEndpoint>>,

    poll_recv_counter: usize,
    /// Cache for source addrs, to speed up access
    source_addrs: [Addr; quinn_udp::BATCH_SIZE],
}

/// Combined watcher type for all ip transports
type IpTransportsWatcher = n0_watcher::Join<SocketAddr, n0_watcher::Direct<SocketAddr>>;
/// Combined watcher type for all custom transports
type CustomTransportsWatcher =
    n0_watcher::Join<Vec<CustomAddr>, n0_watcher::Direct<Vec<CustomAddr>>>;
/// Combined watcher type for all relay transports
type RelayTransportsWatcher = n0_watcher::Join<
    Option<(RelayUrl, EndpointId)>,
    n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, EndpointId)>>,
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
    Custom(Arc<dyn CustomTransport>),
}

impl TransportConfig {
    /// Configures a default IPv4 transport, listening on `0.0.0.0:0`.
    #[cfg(not(wasm_browser))]
    pub(crate) fn default_ipv4() -> Self {
        use std::net::Ipv4Addr;

        use netdev::ipnet::Ipv4Net;

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
        use netdev::ipnet::Ipv6Net;

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
    /// Binds the  transports.
    pub(crate) fn bind(
        configs: &[TransportConfig],
        relay_actor_config: RelayActorConfig,
        metrics: &EndpointMetrics,
        shutdown_token: CancellationToken,
    ) -> io::Result<Self> {
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
        #[cfg(not(wasm_browser))]
        let ip = IpTransports::bind(ip_configs.into_iter(), metrics)?;

        let relay = configs
            .iter()
            .filter(|t| matches!(t, TransportConfig::Relay { .. }))
            .map(|_c| RelayTransport::new(relay_actor_config.clone(), shutdown_token.child_token()))
            .collect();

        let mut custom = Vec::new();
        for config in configs.iter().filter_map(|t| {
            if let TransportConfig::Custom(config) = t {
                Some(config)
            } else {
                None
            }
        }) {
            let transport = config.bind()?;
            custom.push(transport);
        }

        Ok(Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            custom,
            poll_recv_counter: Default::default(),
            source_addrs: Default::default(),
        })
    }

    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        sock: &Socket,
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        debug_assert!(bufs.len() <= quinn_udp::BATCH_SIZE, "too many buffers");
        if sock.is_closing() {
            return Poll::Pending;
        }

        match self.inner_poll_recv(cx, bufs, metas)? {
            Poll::Pending | Poll::Ready(0) => Poll::Pending,
            Poll::Ready(n) => {
                sock.process_datagrams(&mut bufs[..n], &mut metas[..n], &self.source_addrs[..n]);
                Poll::Ready(Ok(n))
            }
        }
    }

    /// Tries to recv data, on all available transports.
    fn inner_poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");

        macro_rules! poll_transport {
            ($socket:expr) => {
                match $socket.poll_recv(cx, bufs, metas, &mut self.source_addrs)? {
                    Poll::Pending | Poll::Ready(0) => {}
                    Poll::Ready(n) => {
                        return Poll::Ready(Ok(n));
                    }
                }
            };
        }

        // To improve fairness, every other call reverses the ordering of polling.

        let counter = self.poll_recv_counter.wrapping_add(1);

        if counter % 2 == 0 {
            #[cfg(not(wasm_browser))]
            poll_transport!(&mut self.ip);

            for transport in self.relay.iter_mut() {
                poll_transport!(transport);
            }
            for transport in self.custom.iter_mut() {
                poll_transport!(transport);
            }
        } else {
            for transport in self.custom.iter_mut().rev() {
                poll_transport!(transport);
            }
            for transport in self.relay.iter_mut().rev() {
                poll_transport!(transport);
            }
            #[cfg(not(wasm_browser))]
            poll_transport!(&mut self.ip);
        }

        Poll::Pending
    }

    /// Returns a list of all currently known local addresses.
    ///
    /// For IP based transports this is the [`SocketAddr`] of the socket,
    /// for relay transports, this is the home relay.
    pub(crate) fn local_addrs(&self) -> Vec<Addr> {
        self.local_addrs_watch().get()
    }

    #[cfg(not(wasm_browser))]
    /// Watch for all currently known local addresses, including IP based transports.
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let ips = n0_watcher::Join::new(self.ip.iter().map(|t| t.local_addr_watch()));
        let relays = n0_watcher::Join::new(self.relay.iter().map(|t| t.local_addr_watch()));
        let custom = n0_watcher::Join::new(self.custom.iter().map(|t| t.watch_local_addrs()));

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
        let custom = n0_watcher::Join::new(self.custom.iter().map(|t| t.watch_local_addrs()));
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

    #[cfg(not(wasm_browser))]
    pub(crate) fn max_transmit_segments(&self) -> NonZeroUsize {
        let res = self.ip.iter().map(|t| t.max_transmit_segments()).min();
        res.unwrap_or(NonZeroUsize::MIN)
    }

    #[cfg(wasm_browser)]
    pub(crate) fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn max_receive_segments(&self) -> NonZeroUsize {
        // `max_receive_segments` controls the size of the `RecvMeta` buffer
        // that quinn creates. Having buffers slightly bigger than necessary
        // isn't terrible, and makes sure a single socket can read the maximum
        // amount with a single poll. We considered adding these numbers instead,
        // but we never get data from both sockets at the same time in `poll_recv`
        // and it's impossible and unnecessary to be refactored that way.

        let res = self.ip.iter().map(|t| t.max_receive_segments()).max();
        res.unwrap_or(NonZeroUsize::MIN)
    }

    #[cfg(wasm_browser)]
    pub(crate) fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn may_fragment(&self) -> bool {
        self.ip.iter().any(|t| t.may_fragment())
    }

    #[cfg(wasm_browser)]
    pub(crate) fn may_fragment(&self) -> bool {
        false
    }

    pub(crate) fn create_sender(&self) -> TransportsSender {
        #[cfg(not(wasm_browser))]
        let ip = self.ip.create_sender();

        let relay = self.relay.iter().map(|t| t.create_sender()).collect();
        let custom = self.custom.iter().map(|t| t.create_sender()).collect();
        let max_transmit_segments = self.max_transmit_segments();

        TransportsSender {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            custom,
            max_transmit_segments,
        }
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
pub struct Transmit<'a> {
    pub(crate) ecn: Option<quinn_udp::EcnCodepoint>,
    /// Packet contents
    pub contents: &'a [u8],
    /// Optional segment size for GSO
    pub segment_size: Option<usize>,
}

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct OwnedTransmit {
    pub(crate) ecn: Option<quinn_udp::EcnCodepoint>,
    pub(crate) contents: Bytes,
    pub(crate) segment_size: Option<usize>,
}

impl From<&quinn_udp::Transmit<'_>> for OwnedTransmit {
    fn from(source: &quinn_udp::Transmit<'_>) -> Self {
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
            Addr::Custom(custom_addr) => TransportAddr::Custom(custom_addr),
        }
    }
}

impl Addr {
    pub(crate) fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(..))
    }

    pub(crate) fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// Returns `None` if not an `Ip`.
    pub(crate) fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Self::Ip(ip) => Some(ip),
            Self::Relay(..) => None,
            Self::Custom(..) => None,
        }
    }

    /// Returns the kind of address, for configuring bias.
    pub(crate) fn addr_kind(&self) -> AddrKind {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_) => AddrKind::IpV4,
                SocketAddr::V6(_) => AddrKind::IpV6,
            },
            Self::Relay(_, _) => AddrKind::Relay,
            Self::Custom(addr) => AddrKind::Custom(addr.id()),
        }
    }
}

/// The kind of a transport address, used for configuring bias.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// The type of transport, either primary or backup.
///
/// Primary transports compete with each other based on biased RTT measurements.
/// Backup transports are only used when no primary transport is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportType {
    /// A transport that has the potential to be the primary transport.
    ///
    /// It will compete with other Primary transports such as IP based
    /// transports based on biased RTT measurements.
    Primary,
    /// A transport that is only used as a backup transport.
    ///
    /// It will only compete with other backup transports such as the relay
    /// transport based on biased RTT measurements.
    Backup,
}

impl TransportType {
    /// Converts to the corresponding QUIC path status.
    pub fn to_path_status(self) -> PathStatus {
        match self {
            Self::Primary => PathStatus::Available,
            Self::Backup => PathStatus::Backup,
        }
    }
}

/// Bias configuration for a transport type.
///
/// This controls how a transport is prioritized during path selection.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use iroh::endpoint::transports::TransportBias;
///
/// // A primary transport with 100ms RTT advantage (will be preferred)
/// let bias = TransportBias::primary().with_rtt_advantage(Duration::from_millis(100));
///
/// // A backup transport (only used when no primary transport is available)
/// let bias = TransportBias::backup();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransportBias {
    /// Whether this is a primary or backup transport.
    pub(crate) transport_type: TransportType,
    /// RTT bias in nanoseconds. Negative values make this transport more preferred.
    pub(crate) rtt_bias: i128,
}

impl TransportBias {
    /// Creates a primary transport bias with no RTT advantage.
    ///
    /// Primary transports compete with each other based on biased RTT measurements.
    pub fn primary() -> Self {
        Self {
            transport_type: TransportType::Primary,
            rtt_bias: 0,
        }
    }

    /// Creates a backup transport bias with no RTT advantage.
    ///
    /// Backup transports are only used when no primary transport is available.
    pub fn backup() -> Self {
        Self {
            transport_type: TransportType::Backup,
            rtt_bias: 0,
        }
    }

    /// Adds an RTT advantage to this transport, making it more preferred.
    ///
    /// The advantage is subtracted from the measured RTT during path selection,
    /// so a transport with a 100ms advantage will be preferred over one with
    /// the same measured RTT but no advantage.
    pub fn with_rtt_advantage(mut self, advantage: Duration) -> Self {
        self.rtt_bias -= advantage.as_nanos() as i128;
        self
    }

    /// Adds an RTT disadvantage to this transport, making it less preferred.
    ///
    /// The disadvantage is added to the measured RTT during path selection,
    /// so a transport with a 100ms disadvantage will be avoided in favor of
    /// one with the same measured RTT but no disadvantage.
    pub fn with_rtt_disadvantage(mut self, disadvantage: Duration) -> Self {
        self.rtt_bias += disadvantage.as_nanos() as i128;
        self
    }
}

/// A map from address kinds to their transport bias configuration.
///
/// This controls how different transport types are prioritized during path selection.
/// By default:
/// - IPv4 and IPv6 are primary transports (IPv6 has a small RTT advantage)
/// - Relay is a backup transport (only used when no primary transport is available)
#[derive(Debug, Clone)]
pub struct TransportBiasMap {
    map: Arc<FxHashMap<AddrKind, TransportBias>>,
}

/// How much do we prefer IPv6 over IPv4.
pub(super) const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

impl Default for TransportBiasMap {
    fn default() -> Self {
        let mut map = FxHashMap::default();
        map.insert(AddrKind::IpV4, TransportBias::primary());
        map.insert(
            AddrKind::IpV6,
            TransportBias::primary().with_rtt_advantage(IPV6_RTT_ADVANTAGE),
        );
        map.insert(AddrKind::Relay, TransportBias::backup());
        Self { map: Arc::new(map) }
    }
}

impl TransportBiasMap {
    /// Returns a new map with the given bias added or updated.
    pub fn with_bias(self, kind: AddrKind, bias: TransportBias) -> Self {
        let mut map = (*self.map).clone();
        map.insert(kind, bias);
        Self { map: Arc::new(map) }
    }

    /// Gets the bias for the given address.
    ///
    /// Returns a primary transport with no RTT bias if no specific bias is configured.
    pub fn get(&self, addr: &Addr) -> TransportBias {
        self.map
            .get(&addr.addr_kind())
            .cloned()
            .unwrap_or_else(TransportBias::primary)
    }

    /// Computes path selection data for a given address and RTT.
    pub fn path_selection_data(&self, addr: &Addr, rtt: Duration) -> PathSelectionData {
        let bias = self.get(addr);
        let status = bias.transport_type.to_path_status();
        let biased_rtt = rtt.as_nanos() as i128 + bias.rtt_bias;
        PathSelectionData {
            status,
            rtt,
            biased_rtt,
        }
    }
}

/// Data used during path selection.
#[derive(Debug)]
pub struct PathSelectionData {
    /// Status of the path if it would be selected.
    pub status: PathStatus,
    /// Measured RTT for path selection.
    pub rtt: Duration,
    /// Biased RTT for path selection.
    ///
    /// This is an i128 so we can subtract an advantage for e.g. IPv6 without underflowing.
    pub biased_rtt: i128,
}

impl PathSelectionData {
    /// Key for sorting paths. Lower is better.
    ///
    /// First part is the status, 0 for Available, 1 for Backup.
    /// Second part is the biased RTT.
    pub fn sort_key(&self) -> (u8, i128) {
        (self.status as u8, self.biased_rtt)
    }
}

/// A sender that sends to all our transports.
#[derive(Debug, Clone)]
pub(crate) struct TransportsSender {
    #[cfg(not(wasm_browser))]
    ip: IpTransportsSender,
    relay: Vec<RelaySender>,
    custom: Vec<Arc<dyn CustomSender>>,
    max_transmit_segments: NonZeroUsize,
}

impl TransportsSender {
    #[instrument(name = "poll_send", skip(self, cx, transmit), fields(len = transmit.contents.len()))]
    pub(crate) fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        dst: &Addr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        match dst {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => {
                return Poll::Ready(Err(io::Error::other("IP is unsupported in browser")));
            }
            #[cfg(not(wasm_browser))]
            Addr::Ip(dst_addr) => match dst_addr {
                SocketAddr::V4(_) => {
                    if let Some(sender) = self
                        .ip
                        .v4_iter_mut()
                        .find(|s| s.is_valid_send_addr(src, dst_addr))
                    {
                        return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
                    }
                    if let Some(sender) = self.ip.v4_default_mut() {
                        if sender.is_valid_default_addr(src, dst_addr) {
                            return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
                        }
                    }
                }
                SocketAddr::V6(_) => {
                    if let Some(sender) = self
                        .ip
                        .v6_iter_mut()
                        .find(|s| s.is_valid_send_addr(src, dst_addr))
                    {
                        return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
                    }
                    if let Some(sender) = self.ip.v6_default_mut() {
                        if sender.is_valid_default_addr(src, dst_addr) {
                            return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
                        }
                    }
                }
            },
            Addr::Relay(url, endpoint_id) => {
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
            Addr::Custom(addr) => {
                for sender in &mut self.custom {
                    if sender.is_valid_send_addr(addr) {
                        match sender.poll_send(cx, addr, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
        }

        // We "blackhole" data that we have not found any usable transport for on
        // to make sure the QUIC stack picks up that currently this data does not arrive.
        trace!(?src, ?dst, "no valid transport available");
        Poll::Ready(Ok(()))
    }
}

/// A [`Transports`] that works with [`MultipathMappedAddr`]s and their IPv6 representation.
///
/// The [`MultipathMappedAddr`]s have an IPv6 representation that Quinn uses.  This struct
/// knows about these and maps them back to the transport [`Addr`]s used by the wrapped
/// [`Transports`].
#[derive(Debug)]
pub(crate) struct Transport {
    sock: Arc<Socket>,
    transports: Transports,
}

impl Transport {
    pub(crate) fn new(sock: Arc<Socket>, transports: Transports) -> Self {
        Self { sock, transports }
    }
}

impl quinn::AsyncUdpSocket for Transport {
    fn create_sender(&self) -> Pin<Box<dyn quinn::UdpSender>> {
        Box::pin(Sender {
            sock: self.sock.clone(),
            sender: self.transports.create_sender(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.transports.poll_recv(cx, bufs, meta, &self.sock)
    }

    #[cfg(not(wasm_browser))]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let local_addrs = self.transports.local_addrs();
        let addrs: Vec<_> = local_addrs
            .into_iter()
            .map(|addr| {
                use crate::socket::mapped_addrs::DEFAULT_FAKE_ADDR;

                match addr {
                    Addr::Ip(addr) => addr,
                    Addr::Relay(..) => DEFAULT_FAKE_ADDR.into(),
                    Addr::Custom(_) => DEFAULT_FAKE_ADDR.into(),
                }
            })
            .collect();

        if let Some(addr) = addrs.iter().find(|addr| addr.is_ipv6()) {
            return Ok(*addr);
        }
        if let Some(SocketAddr::V4(addr)) = addrs.first() {
            // Pretend to be IPv6, because our `MappedAddr`s need to be IPv6.
            let ip = addr.ip().to_ipv6_mapped().into();
            return Ok(SocketAddr::new(ip, addr.port()));
        }

        if !self.transports.relay.is_empty() {
            // pretend we have an address to make sure things are not too sad during startup
            use crate::socket::mapped_addrs::DEFAULT_FAKE_ADDR;

            return Ok(DEFAULT_FAKE_ADDR.into());
        }
        if !self.transports.custom.is_empty() {
            // pretend we have an address to make sure things are not too sad during startup
            use crate::socket::mapped_addrs::DEFAULT_FAKE_ADDR;

            return Ok(DEFAULT_FAKE_ADDR.into());
        }
        Err(io::Error::other("no valid address available"))
    }

    #[cfg(wasm_browser)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Again, we need to pretend we're IPv6, because of our `MappedAddr`s.
        Ok(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0))
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.transports.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.transports.may_fragment()
    }
}

/// A sender for [`Transport`].
///
/// This is special in that it handles [`MultipathMappedAddr::Mixed`] by delegating to the
/// [`Socket`] which expands it back to one or more [`Addr`]s and sends it
/// using the underlying [`Transports`].
#[derive(Debug)]
#[pin_project::pin_project]
pub(crate) struct Sender {
    sock: Arc<Socket>,
    #[pin]
    sender: TransportsSender,
}

impl Sender {
    /// Extracts the right [`Addr`] from the [`quinn_udp::Transmit`].
    ///
    /// Because Quinn does only know about IP transports we map other transports to private
    /// IPv6 Unique Local Address ranges.  This extracts the transport addresses out of the
    /// transmit's destination.
    fn mapped_addr(&self, transmit: &quinn_udp::Transmit) -> io::Result<MultipathMappedAddr> {
        if self.sock.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }

        Ok(MultipathMappedAddr::from(transmit.destination))
    }
}

impl quinn::UdpSender for Sender {
    fn poll_send(
        self: Pin<&mut Self>,
        quinn_transmit: &quinn_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        // On errors this methods prefers returning Ok(()) to Quinn.  Returning an error
        // should only happen if the error is permanent and fatal and it will never be
        // possible to send anything again.  Doing so kills the Quinn EndpointDriver.  Most
        // send errors are intermittent errors, returning Ok(()) in those cases will mean
        // Quinn eventually considers the packets that had send errors as lost and will try
        // and re-send them.
        let mapped_addr = self.mapped_addr(quinn_transmit)?;

        let transport_addr = match mapped_addr {
            MultipathMappedAddr::Mixed(mapped_addr) => {
                let Some(endpoint_id) = self.sock.mapped_addrs.endpoint_addrs.lookup(&mapped_addr)
                else {
                    error!(dst = ?mapped_addr, "unknown NodeIdMappedAddr, dropped transmit");
                    return Poll::Ready(Ok(()));
                };

                // Note we drop the src_ip set in the Quinn Transmit.  This is only the
                // Initial packet we are sending, so we do not yet have an src address we
                // need to respond from.
                if let Some(src_ip) = quinn_transmit.src_ip {
                    warn!(dst = ?mapped_addr, ?src_ip, dst_endpoint = %endpoint_id.fmt_short(),
                        "oops, flub didn't think this would happen");
                }

                match self.sock.try_send_remote_state_msg(
                    endpoint_id,
                    super::RemoteStateMessage::SendDatagram(
                        Box::new(self.sender.clone()),
                        OwnedTransmit::from(quinn_transmit),
                    ),
                ) {
                    Ok(()) => {
                        trace!(dst = ?mapped_addr, dst_endpoint = %endpoint_id.fmt_short(), "sent transmit");
                        return Poll::Ready(Ok(()));
                    }
                    Err(msg) => {
                        // We do not want to block the next send which might be on a
                        // different transport.  Instead we let Quinn handle this as
                        // a lost datagram.
                        // TODO: Revisit this: we might want to do something better.
                        debug!(
                            dst = ?mapped_addr,
                            dst_endpoint = %endpoint_id.fmt_short(),
                            ?msg,
                            "RemoteStateActor inbox dropped message"
                        );
                        return Poll::Ready(Ok(()));
                    }
                };
            }
            MultipathMappedAddr::Relay(relay_mapped_addr) => {
                match self
                    .sock
                    .mapped_addrs
                    .relay_addrs
                    .lookup(&relay_mapped_addr)
                {
                    Some((relay_url, endpoint_id)) => Addr::Relay(relay_url, endpoint_id),
                    None => {
                        error!("unknown RelayMappedAddr, dropped transmit");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            MultipathMappedAddr::Custom(custom_mapped_addr) => {
                match self
                    .sock
                    .mapped_addrs
                    .custom_addrs
                    .lookup(&custom_mapped_addr)
                {
                    Some(addr) => Addr::Custom(addr),
                    None => {
                        error!("unknown CustomMappedAddr, dropped transmit");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            MultipathMappedAddr::Ip(socket_addr) => {
                // Ensure IPv6 mapped addresses are converted back
                let socket_addr =
                    SocketAddr::new(socket_addr.ip().to_canonical(), socket_addr.port());
                Addr::Ip(socket_addr)
            }
        };

        let transmit = Transmit {
            ecn: quinn_transmit.ecn,
            contents: quinn_transmit.contents,
            segment_size: quinn_transmit.segment_size,
        };
        let this = self.project();

        match this
            .sender
            .poll_send(cx, &transport_addr, quinn_transmit.src_ip, &transmit)
        {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(ref err)) => {
                warn!(?transport_addr, "dropped transmit: {err:#}");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // We do not want to block the next send which might be on a
                // different transport.  Instead we let Quinn handle this as a lost
                // datagram.
                // TODO: Revisit this: we might want to do something better.
                trace!(?transport_addr, "transport pending, dropped transmit");
                Poll::Ready(Ok(()))
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.sender.max_transmit_segments
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use iroh_base::{EndpointId, RelayUrl};

    use super::*;

    fn v4(port: u16) -> Addr {
        Addr::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
    }

    fn v6(port: u16) -> Addr {
        Addr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        )))
    }

    fn relay(port: u16) -> Addr {
        let url = format!("https://relay{port}.iroh.computer")
            .parse::<RelayUrl>()
            .unwrap();
        Addr::Relay(url, EndpointId::from_bytes(&[0u8; 32]).unwrap())
    }

    #[test]
    fn test_transport_bias_map_default() {
        let bias_map = TransportBiasMap::default();

        // IPv4 should be Primary with no bias
        let v4_bias = bias_map.get(&v4(1));
        assert_eq!(v4_bias.transport_type, TransportType::Primary);
        assert_eq!(v4_bias.rtt_bias, 0);

        // IPv6 should be Primary with negative bias (preferred)
        let v6_bias = bias_map.get(&v6(1));
        assert_eq!(v6_bias.transport_type, TransportType::Primary);
        assert_eq!(v6_bias.rtt_bias, -(IPV6_RTT_ADVANTAGE.as_nanos() as i128));

        // Relay should be Backup with no bias
        let relay_bias = bias_map.get(&relay(1));
        assert_eq!(relay_bias.transport_type, TransportType::Backup);
        assert_eq!(relay_bias.rtt_bias, 0);
    }

    #[test]
    fn test_ipv6_bias_gives_advantage() {
        let bias_map = TransportBiasMap::default();

        // With equal RTTs, IPv6 should have a lower biased_rtt
        let rtt = Duration::from_millis(50);
        let v4_bias = bias_map.get(&v4(1));
        let v6_bias = bias_map.get(&v6(1));

        let v4_biased_rtt = rtt.as_nanos() as i128 + v4_bias.rtt_bias;
        let v6_biased_rtt = rtt.as_nanos() as i128 + v6_bias.rtt_bias;

        // IPv6 should have lower biased RTT (more preferred)
        assert!(v6_biased_rtt < v4_biased_rtt);
        assert_eq!(
            v4_biased_rtt - v6_biased_rtt,
            IPV6_RTT_ADVANTAGE.as_nanos() as i128
        );
    }

    #[test]
    fn test_relay_is_backup() {
        let bias_map = TransportBiasMap::default();

        // Relay should be Backup, which means it won't compete with Primary transports
        let relay_bias = bias_map.get(&relay(1));
        assert_eq!(relay_bias.transport_type, TransportType::Backup);

        // Primary transports (IPv4/IPv6) should be preferred over Backup
        let v4_bias = bias_map.get(&v4(1));
        assert!(v4_bias.transport_type < relay_bias.transport_type);
    }
}
