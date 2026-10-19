use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ipnet::{Ipv4Net, Ipv6Net};
use n0_watcher::Watchable;
use netwatch::{UdpSender, UdpSocket};
use pin_project::pin_project;
use tracing::{debug, info, trace};

use super::{RecvInfo, Transmit};
use crate::metrics::{EndpointMetrics, SocketMetrics};

#[derive(Debug, Clone)]
pub(crate) struct IpTransport {
    config: Config,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<SocketMetrics>,
}

impl std::fmt::Display for IpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let version = if self.config.is_ipv4() { "v4" } else { "v6" };
        write!(f, "IpTransport({version})")
    }
}

/// IP transport configuration
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Config {
    /// General IPv4 binding
    V4 {
        /// The IP address to bind on
        ip_net: Ipv4Net,
        /// The port to bind on
        port: u16,
        /// Is binding mandatory?
        is_required: bool,
        /// Is this a default route?
        is_default: bool,
    },
    /// General IPv6 binding
    V6 {
        /// The IP address to bind on
        ip_net: Ipv6Net,
        /// The scope id.
        scope_id: u32,
        /// The port to bind on
        port: u16,
        /// Is binding mandatory?
        is_required: bool,
        /// Is this a default route?
        is_default: bool,
    },
}

impl Config {
    /// Is this a v4 config.
    pub(crate) fn is_ipv4(&self) -> bool {
        matches!(self,  | Self::V4 { .. })
    }

    /// Is this a v6 config.
    pub(crate) fn is_ipv6(&self) -> bool {
        matches!(self, | Self::V6 { .. })
    }

    /// Is this a default config?
    pub(crate) fn is_default(&self) -> bool {
        match self {
            Self::V4 { is_default, .. } => *is_default,
            Self::V6 { is_default, .. } => *is_default,
        }
    }

    /// Returns the prefix len for the address.
    pub(crate) fn prefix_len(&self) -> u8 {
        match self {
            Self::V4 { ip_net, .. } => ip_net.prefix_len(),
            Self::V6 { ip_net, .. } => ip_net.prefix_len(),
        }
    }

    /// The route for noq to pick this transport's socket
    ///
    /// The network is the destinations, and a bound address is the source. noq's selection
    /// with these routes matches [`IpSelection`].
    pub(super) fn socket_route(&self) -> noq::SocketRoute {
        let (net, addr): (ipnet::IpNet, IpAddr) = match self {
            Self::V4 { ip_net, .. } => ((*ip_net).into(), ip_net.addr().into()),
            Self::V6 { ip_net, .. } => ((*ip_net).into(), ip_net.addr().into()),
        };
        let route = noq::SocketRoute::new(net).with_default(self.is_default());
        if addr.is_unspecified() {
            route
        } else {
            route.with_source(addr)
        }
    }

    /// Is this required to bind.
    pub(crate) fn is_required(&self) -> bool {
        match self {
            Self::V4 { is_required, .. } => *is_required,
            Self::V6 { is_required, .. } => *is_required,
        }
    }

    pub(crate) fn is_valid_default_addr(&self, src: Option<IpAddr>, dst: SocketAddr) -> bool {
        match src {
            Some(src) => match (self, src) {
                (Self::V4 { is_default, .. }, IpAddr::V4(_)) => *is_default,
                (Self::V6 { is_default, .. }, IpAddr::V6(_)) => *is_default,
                _ => false,
            },
            None => match (self, dst) {
                (Self::V4 { is_default, .. }, SocketAddr::V4(_)) => *is_default,
                (Self::V6 { is_default, .. }, SocketAddr::V6(_)) => *is_default,
                _ => false,
            },
        }
    }

    /// Does this configuration match to send to the given `src` and `dst` address.
    pub(crate) fn is_valid_send_addr(&self, src: Option<IpAddr>, dst: SocketAddr) -> bool {
        match src {
            Some(src) => match (self, src) {
                (Self::V4 { ip_net, .. }, IpAddr::V4(src)) => {
                    ip_net.addr().is_unspecified() || ip_net.addr() == src
                }
                (Self::V6 { ip_net, .. }, IpAddr::V6(src)) => {
                    ip_net.addr().is_unspecified() || ip_net.addr() == src
                }
                _ => false,
            },
            None => {
                match (self, dst) {
                    (Self::V4 { ip_net, .. }, SocketAddr::V4(dst_v4)) => {
                        ip_net.contains(dst_v4.ip())
                    }
                    (
                        Self::V6 {
                            ip_net, scope_id, ..
                        },
                        SocketAddr::V6(dst_v6),
                    ) => {
                        if ip_net.contains(dst_v6.ip()) {
                            return true;
                        }
                        if dst_v6.ip().is_unicast_link_local() {
                            // If we have a link local interface, use the scope id
                            if *scope_id == dst_v6.scope_id() {
                                return true;
                            }
                        }
                        false
                    }
                    _ => false,
                }
            }
        }
    }
}

impl From<Config> for SocketAddr {
    fn from(value: Config) -> Self {
        match value {
            Config::V4 { ip_net, port, .. } => {
                SocketAddr::V4(SocketAddrV4::new(ip_net.addr(), port))
            }
            Config::V6 {
                ip_net,
                scope_id,
                port,
                ..
            } => SocketAddr::V6(SocketAddrV6::new(ip_net.addr(), port, 0, scope_id)),
        }
    }
}

impl IpTransport {
    pub(crate) fn bind(config: Config, metrics: Arc<SocketMetrics>) -> io::Result<Self> {
        let addr: SocketAddr = config.into();
        debug!(?addr, "binding");
        let socket = netwatch::UdpSocket::bind_full(addr).inspect_err(|err| {
            debug!(%addr, "failed to bind: {err:#}");
        })?;
        let local_addr = socket.local_addr()?;
        debug!(%addr, %local_addr, "successfully bound");
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(local_addr);

        Ok(Self {
            config,
            socket: Arc::new(socket),
            local_addr,
            metrics,
        })
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert_eq!(
            bufs.len(),
            recv_infos.len(),
            "non matching bufs & recv_infos"
        );
        match self.socket.poll_recv_noq(cx, bufs, metas) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                for i in 0..n {
                    let meta = &mut metas[i];
                    let recv_info = &mut recv_infos[i];
                    if meta.addr.is_ipv4() {
                        // The AsyncUdpSocket is an AF_INET6 socket and needs to show this
                        // as coming from an IPv4-mapped IPv6 addresses, since Noq will
                        // use those when sending on an INET6 socket.
                        let v6_ip = match meta.addr.ip() {
                            IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
                            IpAddr::V6(ipv6_addr) => ipv6_addr,
                        };
                        meta.addr = SocketAddr::new(v6_ip.into(), meta.addr.port());
                    }
                    // The transport addresses are internal to iroh and we always want those
                    // to remain the canonical address.
                    *recv_info = RecvInfo::from_addr(
                        SocketAddr::new(meta.addr.ip().to_canonical(), meta.addr.port()).into(),
                    );
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    pub(super) fn local_addr_watch(&self) -> n0_watcher::Direct<SocketAddr> {
        self.local_addr.watch()
    }

    pub(super) fn max_transmit_segments(&self) -> NonZeroUsize {
        self.socket.max_gso_segments()
    }

    pub(super) fn max_receive_segments(&self) -> NonZeroUsize {
        self.socket.gro_segments()
    }

    pub(super) fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    pub(crate) fn bind_addr(&self) -> SocketAddr {
        self.config.into()
    }

    pub(super) fn config(&self) -> Config {
        self.config
    }

    pub(super) fn create_network_change_sender(&self) -> IpNetworkChangeSender {
        IpNetworkChangeSender {
            socket: self.socket.clone(),
            local_addr: self.local_addr.clone(),
        }
    }

    pub(super) fn create_sender(&self) -> IpSender {
        let sender = self.socket.clone().create_sender();
        IpSender {
            config: self.config,
            sender,
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct IpNetworkChangeSender {
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
}

impl IpNetworkChangeSender {
    pub(super) fn rebind(&self) -> io::Result<()> {
        let old_addr = self.local_addr.get();
        self.socket.rebind()?;
        let addr = self.socket.local_addr()?;
        self.local_addr.set(addr).ok();
        trace!("rebound from {} to {}", old_addr, addr);

        Ok(())
    }

    pub(super) fn on_network_change(&self, _info: &crate::socket::Report) {
        // Nothing to do for now
    }
}

#[derive(Debug, Clone)]
#[pin_project]
pub(super) struct IpSender {
    config: Config,
    #[pin]
    sender: UdpSender,
    metrics: Arc<SocketMetrics>,
}

impl IpSender {
    /// Creates a canonical socket address.
    ///
    /// We may be asked to send IPv4-mapped IPv6 addresses.  But our sockets are configured
    /// to only send their actual family.  So we need to map those back to the canonical
    /// addresses.
    #[inline]
    fn canonical_addr(addr: SocketAddr) -> SocketAddr {
        SocketAddr::new(addr.ip().to_canonical(), addr.port())
    }

    pub(super) fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        dst: SocketAddr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let total_bytes = transmit.contents.len() as u64;
        let res = Pin::new(&mut self.sender).poll_send(
            &noq_udp::Transmit {
                destination: Self::canonical_addr(dst),
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: src,
            },
            cx,
        );

        match res {
            Poll::Ready(Ok(res)) => {
                match dst {
                    SocketAddr::V4(_) => {
                        self.metrics.send_ipv4.inc_by(total_bytes);
                    }
                    SocketAddr::V6(_) => {
                        self.metrics.send_ipv6.inc_by(total_bytes);
                    }
                }
                Poll::Ready(Ok(res))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The bound IP transports.
#[derive(Debug)]
pub(super) struct IpTransports(Vec<IpTransport>);

impl IpTransports {
    pub(super) fn iter(&self) -> impl Iterator<Item = &IpTransport> {
        self.0.iter()
    }

    pub(super) fn bind(
        configs: impl Iterator<Item = Config>,
        metrics: &EndpointMetrics,
    ) -> io::Result<Self> {
        let mut has_v4_default = false;
        let mut has_v6_default = false;
        let mut transports = Vec::new();

        for config in configs {
            match IpTransport::bind(config, metrics.socket.clone()) {
                Ok(transport) => {
                    if config.is_default() {
                        let has_default = if config.is_ipv4() {
                            &mut has_v4_default
                        } else {
                            &mut has_v6_default
                        };
                        if *has_default {
                            return Err(io::Error::other(
                                "can only have a single default transport per address family",
                            ));
                        }
                        *has_default = true;
                    }
                    transports.push(transport);
                }
                Err(err) => {
                    if config.is_required() {
                        return Err(err);
                    }
                    info!("ignoring non required bind failure: {:?}", err);
                }
            }
        }

        Ok(Self(transports))
    }
}

/// Picks the IP transport that sends to a destination
///
/// Per address family, the first transport in prefix order that is valid for the source and
/// destination wins, then the default transport. See [`Config::is_valid_send_addr`] and
/// [`Config::is_valid_default_addr`]. noq picks the socket the same way from
/// [`Config::socket_route`]; this is for the Initial packets iroh sends itself.
#[derive(Debug, Clone, Default)]
pub(super) struct IpSelection {
    /// Configs and their transport index, sorted by prefix length, longest first
    v4: Vec<(Config, usize)>,
    /// Configs and their transport index, sorted by prefix length, longest first
    v6: Vec<(Config, usize)>,
}

impl IpSelection {
    /// Selects among `configs`, by their index
    pub(super) fn new(configs: impl IntoIterator<Item = Config>) -> Self {
        let (mut v4, mut v6): (Vec<_>, Vec<_>) = configs
            .into_iter()
            .enumerate()
            .map(|(index, config)| (config, index))
            .partition(|(config, _)| config.is_ipv4());
        v4.sort_by_key(|(config, _)| std::cmp::Reverse(config.prefix_len()));
        v6.sort_by_key(|(config, _)| std::cmp::Reverse(config.prefix_len()));
        Self { v4, v6 }
    }

    /// Returns the index of the transport for `dst`, sent from `src`
    pub(super) fn select(&self, dst: SocketAddr, src: Option<IpAddr>) -> Option<usize> {
        // noq may hand us IPv4-mapped addresses, our configs use the canonical form.
        let dst = match dst {
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(ip) => SocketAddr::new(ip.into(), v6.port()),
                None => dst,
            },
            SocketAddr::V4(_) => dst,
        };
        let src = src.map(|ip| ip.to_canonical());
        let transports = match dst {
            SocketAddr::V4(_) => &self.v4,
            SocketAddr::V6(_) => &self.v6,
        };
        transports
            .iter()
            .find(|(config, _)| config.is_valid_send_addr(src, dst))
            .or_else(|| {
                transports
                    .iter()
                    .find(|(config, _)| config.is_valid_default_addr(src, dst))
            })
            .map(|(_, index)| *index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind() -> n0_error::Result {
        let has_ipv6 = tokio::net::UdpSocket::bind("[::1]:0").await.is_ok();
        eprintln!("testing with ipv6? {has_ipv6}");

        let metrics = EndpointMetrics::default();
        let config = vec![
            Config::V4 {
                ip_net: Ipv4Net::new("127.0.0.1".parse().unwrap(), 8).unwrap(),
                port: 2222,
                is_required: true,
                is_default: false,
            },
            Config::V4 {
                ip_net: Ipv4Net::new("127.0.0.1".parse().unwrap(), 24).unwrap(),
                port: 1111,
                is_required: true,
                is_default: true,
            },
            Config::V4 {
                ip_net: Ipv4Net::new("127.0.0.1".parse().unwrap(), 0).unwrap(),
                port: 9999,
                is_required: true,
                is_default: false,
            },
            Config::V6 {
                ip_net: Ipv6Net::new("::1".parse().unwrap(), 4).unwrap(),
                port: 2228,
                scope_id: 0,
                is_required: has_ipv6,
                is_default: false,
            },
            Config::V6 {
                ip_net: Ipv6Net::new("::1".parse().unwrap(), 2).unwrap(),
                port: 9998,
                scope_id: 0,
                is_required: has_ipv6,
                is_default: true,
            },
            Config::V6 {
                ip_net: Ipv6Net::new("::1".parse().unwrap(), 32).unwrap(),
                port: 1118,
                scope_id: 0,
                is_required: has_ipv6,
                is_default: false,
            },
        ];

        let transports = IpTransports::bind(config.into_iter(), &metrics)?;
        let expected = if has_ipv6 { 6 } else { 3 };
        assert_eq!(transports.iter().count(), expected);
        Ok(())
    }

    #[test]
    fn ip_selection() {
        let v4 = |net: &str, is_default| Config::V4 {
            ip_net: net.parse().unwrap(),
            port: 0,
            is_required: true,
            is_default,
        };
        let v6 = |net: &str, scope_id, is_default| Config::V6 {
            ip_net: net.parse().unwrap(),
            scope_id,
            port: 0,
            is_required: true,
            is_default,
        };
        let configs = [
            v4("0.0.0.0/0", false),
            v4("10.1.0.5/16", false),
            v4("192.168.0.7/32", true),
            v6("::/0", 0, false),
            v6("fe80::1/128", 7, false),
        ];
        let selection = IpSelection::new(configs);
        let select = |dst: &str, src: Option<&str>| {
            selection.select(dst.parse().unwrap(), src.map(|s| s.parse().unwrap()))
        };
        // Without a source: longest prefix.
        assert_eq!(select("10.1.2.3:1", None), Some(1));
        assert_eq!(select("8.8.8.8:1", None), Some(0));
        // IPv4-mapped destinations select IPv4 transports.
        assert_eq!(select("[::ffff:10.1.2.3]:1", None), Some(1));
        // With a source: a transport bound to it, or a wildcard one.
        assert_eq!(select("10.1.2.3:1", Some("192.168.0.7")), Some(2));
        assert_eq!(select("10.1.2.3:1", Some("172.16.0.1")), Some(0));
        // Link-local destinations select by scope id.
        assert_eq!(select("[fe80::9%7]:1", None), Some(4));
        assert_eq!(select("[2001:db8::1]:1", None), Some(3));
    }
}
