use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use n0_watcher::Watchable;
use netdev::ipnet::{Ipv4Net, Ipv6Net};
use netwatch::{UdpSender, UdpSocket};
use pin_project::pin_project;
use tracing::{debug, info, trace};

use super::{Addr, Transmit};
use crate::metrics::{EndpointMetrics, SocketMetrics};

#[derive(Debug)]
pub(crate) struct IpTransport {
    config: Config,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<SocketMetrics>,
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

    /// Returns the prefix len for the address.
    pub(crate) fn prefix_len(&self) -> u8 {
        match self {
            Self::V4 { ip_net, .. } => ip_net.prefix_len(),
            Self::V6 { ip_net, .. } => ip_net.prefix_len(),
        }
    }

    /// Is this a default config?
    pub(crate) fn is_default(&self) -> bool {
        match self {
            Self::V4 { is_default, .. } => *is_default,
            Self::V6 { is_default, .. } => *is_default,
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
        Ok(Self::new(config, Arc::new(socket), metrics.clone()))
    }

    pub(crate) fn new(config: Config, socket: Arc<UdpSocket>, metrics: Arc<SocketMetrics>) -> Self {
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(socket.local_addr().expect("invalid socket"));

        Self {
            config,
            socket,
            local_addr,
            metrics,
        }
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        match self.socket.poll_recv_quinn(cx, bufs, metas) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                for (source_addr, meta) in source_addrs.iter_mut().zip(metas.iter_mut()).take(n) {
                    if meta.addr.is_ipv4() {
                        // The AsyncUdpSocket is an AF_INET6 socket and needs to show this
                        // as coming from an IPv4-mapped IPv6 addresses, since Quinn will
                        // use those when sending on an INET6 socket.
                        let v6_ip = match meta.addr.ip() {
                            IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
                            IpAddr::V6(ipv6_addr) => ipv6_addr,
                        };
                        meta.addr = SocketAddr::new(v6_ip.into(), meta.addr.port());
                    }
                    // The transport addresses are internal to iroh and we always want those
                    // to remain the canonical address.
                    *source_addr =
                        SocketAddr::new(meta.addr.ip().to_canonical(), meta.addr.port()).into();
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
    pub(super) fn is_valid_send_addr(&self, src: Option<IpAddr>, dst: &SocketAddr) -> bool {
        self.config.is_valid_send_addr(src, *dst)
    }

    pub(super) fn is_valid_default_addr(&self, src: Option<IpAddr>, dst: &SocketAddr) -> bool {
        self.config.is_valid_default_addr(src, *dst)
    }

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
            &quinn_udp::Transmit {
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

#[derive(Debug, Clone)]
pub(super) struct IpTransportsSender {
    /// Stored sorted by prefix len
    v4: Vec<IpSender>,
    default_v4_index: Option<usize>,
    /// Stored sorted by prefix len
    v6: Vec<IpSender>,
    default_v6_index: Option<usize>,
}

impl IpTransportsSender {
    pub(super) fn v4_iter_mut(&mut self) -> impl Iterator<Item = &mut IpSender> {
        self.v4.iter_mut()
    }

    pub(super) fn v4_default_mut(&mut self) -> Option<&mut IpSender> {
        if let Some(i) = self.default_v4_index {
            return Some(&mut self.v4[i]);
        }
        None
    }

    pub(super) fn v6_iter_mut(&mut self) -> impl Iterator<Item = &mut IpSender> {
        self.v6.iter_mut()
    }

    pub(super) fn v6_default_mut(&mut self) -> Option<&mut IpSender> {
        if let Some(i) = self.default_v6_index {
            return Some(&mut self.v6[i]);
        }
        None
    }
}

#[derive(Debug)]
pub(super) struct IpTransports {
    v4: Vec<IpTransport>,
    default_v4_index: Option<usize>,
    v6: Vec<IpTransport>,
    default_v6_index: Option<usize>,
}

impl IpTransports {
    pub(super) fn create_sender(&self) -> IpTransportsSender {
        let ip_v4 = self.v4.iter().map(|t| t.create_sender()).collect();
        let ip_v6 = self.v6.iter().map(|t| t.create_sender()).collect();

        IpTransportsSender {
            v4: ip_v4,
            default_v4_index: self.default_v4_index,
            v6: ip_v6,
            default_v6_index: self.default_v6_index,
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &IpTransport> {
        self.v4.iter().chain(self.v6.iter())
    }

    pub(super) fn bind(
        configs: impl Iterator<Item = Config>,
        metrics: &EndpointMetrics,
    ) -> io::Result<Self> {
        let mut has_v4_default = false;
        let mut ip_v4 = Vec::new();

        let mut has_v6_default = false;
        let mut ip_v6 = Vec::new();

        for config in configs {
            match IpTransport::bind(config, metrics.socket.clone()) {
                Ok(transport) => {
                    if config.is_ipv4() {
                        if config.is_default() {
                            if has_v4_default {
                                return Err(io::Error::other(
                                    "can only have a single IPv4 default transport",
                                ));
                            }
                            has_v4_default = true;
                        }
                        ip_v4.push(transport);
                    } else if config.is_ipv6() {
                        if config.is_default() {
                            if has_v6_default {
                                return Err(io::Error::other(
                                    "can only have a single IPv6 default transport",
                                ));
                            }
                            has_v6_default = true;
                        }
                        ip_v6.push(transport);
                    }
                }
                Err(err) => {
                    if config.is_required() {
                        return Err(err);
                    }
                    info!("ignoring non required bind failure: {:?}", err);
                }
            }
        }

        // Sort in descending order by prefix len
        ip_v4.sort_by_key(|i| std::cmp::Reverse(i.config.prefix_len()));
        ip_v6.sort_by_key(|i| std::cmp::Reverse(i.config.prefix_len()));

        let default_v4_index = ip_v4.iter().position(|i| i.config.is_default());
        let default_v6_index = ip_v6.iter().position(|i| i.config.is_default());

        Ok(Self {
            v4: ip_v4,
            default_v4_index,
            v6: ip_v6,
            default_v6_index,
        })
    }

    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        macro_rules! poll_transport {
            ($socket:expr) => {
                match $socket.poll_recv(cx, bufs, metas, source_addrs)? {
                    Poll::Pending | Poll::Ready(0) => {}
                    Poll::Ready(n) => {
                        return Poll::Ready(Ok(n));
                    }
                }
            };
        }

        for transport in &mut self.v4 {
            poll_transport!(transport);
        }

        for transport in &mut self.v6 {
            poll_transport!(transport);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_sorting() -> n0_error::Result {
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
        assert_eq!(transports.v4[0].config.prefix_len(), 24);
        assert_eq!(transports.v4[1].config.prefix_len(), 8);
        assert_eq!(transports.v4[2].config.prefix_len(), 0);

        assert_eq!(transports.default_v4_index, Some(0));

        if has_ipv6 {
            assert_eq!(transports.v6[0].config.prefix_len(), 32);
            assert_eq!(transports.v6[1].config.prefix_len(), 4);
            assert_eq!(transports.v6[2].config.prefix_len(), 2);

            assert_eq!(transports.default_v6_index, Some(2));
        }
        Ok(())
    }
}
