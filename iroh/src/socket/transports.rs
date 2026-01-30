use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{EndpointId, RelayUrl, TransportAddr};
use iroh_relay::RelayMap;
use n0_watcher::Watcher;
use relay::{RelayNetworkChangeSender, RelaySender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, instrument, trace, warn};

use super::{Socket, mapped_addrs::MultipathMappedAddr};
use crate::{metrics::EndpointMetrics, net_report::Report};

#[cfg(not(wasm_browser))]
mod ip;
mod relay;

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

    poll_recv_counter: usize,
    /// Cache for source addrs, to speed up access
    source_addrs: [Addr; quinn_udp::BATCH_SIZE],
}

#[cfg(not(wasm_browser))]
pub(crate) type LocalAddrsWatch = n0_watcher::Map<
    n0_watcher::Tuple<
        n0_watcher::Join<SocketAddr, n0_watcher::Direct<SocketAddr>>,
        n0_watcher::Join<
            Option<(RelayUrl, EndpointId)>,
            n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, EndpointId)>>,
        >,
    >,
    Vec<Addr>,
>;

#[cfg(wasm_browser)]
pub(crate) type LocalAddrsWatch = n0_watcher::Map<
    n0_watcher::Join<
        Option<(RelayUrl, EndpointId)>,
        n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, EndpointId)>>,
    >,
    Vec<Addr>,
>;

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

        Ok(Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
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

        if counter.is_multiple_of(2) {
            #[cfg(not(wasm_browser))]
            poll_transport!(&mut self.ip);

            for transport in &mut self.relay {
                poll_transport!(transport);
            }
        } else {
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

    /// Watch for all currently known local addresses.
    #[cfg(not(wasm_browser))]
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let ips = n0_watcher::Join::new(self.ip.iter().map(|t| t.local_addr_watch()));
        let relays = n0_watcher::Join::new(self.relay.iter().map(|t| t.local_addr_watch()));

        ips.or(relays).map(|(ips, relays)| {
            ips.into_iter()
                .map(Addr::from)
                .chain(
                    relays
                        .into_iter()
                        .flatten()
                        .map(|(relay_url, endpoint_id)| Addr::Relay(relay_url, endpoint_id)),
                )
                .collect()
        })
    }

    #[cfg(wasm_browser)]
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let relays = self.relay.iter().map(|t| t.local_addr_watch());
        n0_watcher::Join::new(relays)
            .map(|relays| relays.into_iter().flatten().map(Addr::from).collect())
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
        let max_transmit_segments = self.max_transmit_segments();

        TransportsSender {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
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
pub(crate) struct Transmit<'a> {
    pub(crate) ecn: Option<quinn_udp::EcnCodepoint>,
    pub(crate) contents: &'a [u8],
    pub(crate) segment_size: Option<usize>,
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
pub(crate) enum Addr {
    /// An IP address, should always be stored in its canonical form.
    Ip(SocketAddr),
    /// A relay address.
    Relay(RelayUrl, EndpointId),
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Addr::Ip(addr) => write!(f, "Ip({addr})"),
            Addr::Relay(url, node_id) => write!(f, "Relay({url}, {})", node_id.fmt_short()),
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
        }
    }
}

/// A sender that sends to all our transports.
#[derive(Debug, Clone)]
pub(crate) struct TransportsSender {
    #[cfg(not(wasm_browser))]
    ip: IpTransportsSender,
    relay: Vec<RelaySender>,
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
                    if let Some(sender) = self.ip.v4_default_mut()
                        && sender.is_valid_default_addr(src, dst_addr)
                    {
                        return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
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
                    if let Some(sender) = self.ip.v6_default_mut()
                        && sender.is_valid_default_addr(src, dst_addr)
                    {
                        return Pin::new(sender).poll_send(cx, *dst_addr, src, transmit);
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
