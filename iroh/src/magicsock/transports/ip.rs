use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use n0_watcher::Watchable;
#[cfg(not(wasm_browser))]
use netdev::ipnet::{Ipv4Net, Ipv6Net};
use netwatch::{UdpSender, UdpSocket};
use pin_project::pin_project;
use tracing::{debug, trace};

use super::{Addr, Transmit};
use crate::metrics::MagicsockMetrics;

#[derive(Debug)]
pub(crate) struct IpTransport {
    config: Config,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<MagicsockMetrics>,
}

/// IP transport configuration
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Config {
    /// Default IPv4 binding
    V4Default {
        /// TODO
        ip_addr: Ipv4Addr,
        /// The port to bind on
        port: u16,
    },
    /// Default IPv6 binding
    V6Default {
        /// TODO
        ip_addr: Ipv6Addr,
        /// The scope_id
        scope_id: u32,
        /// The port to bind on
        port: u16,
    },
    /// IPv4 binding
    V4 {
        /// TODO
        ip_addr: Ipv4Net,
        /// The port to bind on
        port: u16,
    },
    /// IPv6 binding
    V6 {
        /// TODO
        ip_addr: Ipv6Net,
        /// The scope id
        scope_id: u32,
        /// The port to bind on
        port: u16,
    },
}

impl Config {
    /// Is this a v4 config.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::V4Default { .. } | Self::V4 { .. })
    }

    /// Is this a v6 config.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6Default { .. } | Self::V6 { .. })
    }

    /// Is this a default config?
    pub fn is_default(&self) -> bool {
        matches!(self, Self::V4Default { .. } | Self::V6Default { .. })
    }

    /// TODO
    pub fn is_valid_send_addr(&self, dst: SocketAddr) -> bool {
        match self {
            Self::V4Default { .. } => matches!(dst, SocketAddr::V4(_)),
            Self::V6Default { .. } => matches!(dst, SocketAddr::V6(_)),
            Self::V4 { ip_addr, .. } => match dst {
                SocketAddr::V4(dst_v4) => ip_addr.contains(dst_v4.ip()),
                SocketAddr::V6(_) => false,
            },
            Self::V6 {
                ip_addr, scope_id, ..
            } => match dst {
                SocketAddr::V6(dst_v6) => {
                    if ip_addr.contains(dst_v6.ip()) {
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
                SocketAddr::V4(_) => false,
            },
        }
    }
}

impl From<Config> for SocketAddr {
    fn from(value: Config) -> Self {
        match value {
            Config::V4Default { ip_addr, port } => SocketAddr::V4(SocketAddrV4::new(ip_addr, port)),
            Config::V6Default {
                ip_addr,
                scope_id,
                port,
            } => SocketAddr::V6(SocketAddrV6::new(ip_addr, port, 0, scope_id)),
            Config::V4 { ip_addr, port } => SocketAddr::V4(SocketAddrV4::new(ip_addr.addr(), port)),
            Config::V6 {
                ip_addr,
                scope_id,
                port,
            } => SocketAddr::V6(SocketAddrV6::new(ip_addr.addr(), port, 0, scope_id)),
        }
    }
}

fn bind_with_fallback(mut addr: SocketAddr) -> io::Result<netwatch::UdpSocket> {
    debug!(?addr, "binding");
    // First try binding a preferred port, if specified
    match netwatch::UdpSocket::bind_full(addr) {
        Ok(socket) => {
            let local_addr = socket.local_addr()?;
            debug!(%addr, %local_addr, "successfully bound");
            return Ok(socket);
        }
        Err(err) => {
            debug!(%addr, "failed to bind: {err:#}");
            // If that was already the fallback port, then error out
            if addr.port() == 0 {
                return Err(err);
            }
        }
    }

    // Otherwise, try binding with port 0
    addr.set_port(0);
    netwatch::UdpSocket::bind_full(addr)
}

impl IpTransport {
    pub(crate) fn bind(config: Config, metrics: Arc<MagicsockMetrics>) -> io::Result<Self> {
        let socket = bind_with_fallback(config.into())?;
        Ok(Self::new(config, Arc::new(socket), metrics.clone()))
    }

    pub(crate) fn new(
        config: Config,
        socket: Arc<UdpSocket>,
        metrics: Arc<MagicsockMetrics>,
    ) -> Self {
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

    pub(super) fn max_transmit_segments(&self) -> usize {
        self.socket.max_gso_segments()
    }

    pub(super) fn max_receive_segments(&self) -> usize {
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

    pub(super) fn on_network_change(&self, _info: &crate::magicsock::Report) {
        // Nothing to do for now
    }
}

#[derive(Debug, Clone)]
#[pin_project]
pub(super) struct IpSender {
    config: Config,
    #[pin]
    sender: UdpSender,
    metrics: Arc<MagicsockMetrics>,
}

impl IpSender {
    pub(super) fn is_valid_send_addr(&self, dst: &SocketAddr) -> bool {
        // Our net-tools crate binds sockets to their specific family.  This means an IPv6
        // socket can not sent to IPv4, on any platform.  So we need to convert an
        // IPv4-mapped IPv6 address back to it's canonical IPv4 address.
        let mut dst = *dst;
        dst.set_ip(dst.ip().to_canonical());

        self.config.is_valid_send_addr(dst)
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

    pub(super) async fn send(
        &self,
        dst: SocketAddr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let total_bytes = transmit.contents.len() as u64;
        let res = self
            .sender
            .send(&quinn_udp::Transmit {
                destination: Self::canonical_addr(dst),
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: src,
            })
            .await;

        match res {
            Ok(res) => {
                match dst {
                    SocketAddr::V4(_) => {
                        self.metrics.send_ipv4.inc_by(total_bytes);
                    }
                    SocketAddr::V6(_) => {
                        self.metrics.send_ipv6.inc_by(total_bytes);
                    }
                }
                Ok(res)
            }
            Err(err) => Err(err),
        }
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
