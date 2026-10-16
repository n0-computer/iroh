use std::{
    hash::BuildHasher,
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
use noq::SocketId;
use pin_project::pin_project;
use tracing::{debug, info, trace, warn};

use super::{RecvInfo, Transmit};
use crate::metrics::{EndpointMetrics, SocketMetrics};

#[derive(Debug, Clone)]
pub(crate) struct IpTransport {
    config: Config,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<SocketMetrics>,
    /// Whether this is an extra socket, bound with `SO_REUSEPORT` to the address of the
    /// transport before it
    is_copy: bool,
}

impl std::fmt::Display for IpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let version = if self.config.is_ipv4() { "v4" } else { "v6" };
        write!(f, "IpTransport({version})")
    }
}

/// Whether the kernel spreads incoming flows over sockets that share an address with
/// `SO_REUSEPORT`
///
/// Linux does. Other systems either lack `SO_REUSEPORT` or deliver all unicast datagrams of an
/// address to one of the sockets, so extra sockets would never receive.
const REUSE_PORT_BALANCES: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// Returns the options to bind a socket with, setting `SO_REUSEPORT` if `reuse_port` is set
fn bind_options(reuse_port: bool) -> netwatch::BindOptions {
    let opts = netwatch::BindOptions::new();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if reuse_port {
        // The hook reruns on every rebind, so rebound sockets share the address again.
        return opts.configure_socket(|socket, _family| {
            socket2::SockRef::from(&socket).set_reuse_port(true)
        });
    }
    debug_assert!(
        !reuse_port,
        "SO_REUSEPORT requested where it does not balance"
    );
    opts
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
    /// Binds `count` sockets for `config`
    ///
    /// With a `count` above one, all sockets share the address of the first with
    /// `SO_REUSEPORT`, and the kernel spreads incoming flows over them.
    fn bind_all(
        config: Config,
        count: NonZeroUsize,
        metrics: &Arc<SocketMetrics>,
    ) -> io::Result<Vec<Self>> {
        let count = if count.get() > 1 && !REUSE_PORT_BALANCES {
            warn!("binding one socket per IP transport, SO_REUSEPORT does not spread load here");
            1
        } else {
            count.get()
        };
        let reuse_port = count > 1;
        let first = Self::bind(config, config.into(), reuse_port, false, metrics.clone())?;
        // Copies bind the port the first socket got, which matters for port 0.
        let addr = first.local_addr.get();
        let mut transports = vec![first];
        for _ in 1..count {
            transports.push(Self::bind(config, addr, true, true, metrics.clone())?);
        }
        Ok(transports)
    }

    fn bind(
        config: Config,
        addr: SocketAddr,
        reuse_port: bool,
        is_copy: bool,
        metrics: Arc<SocketMetrics>,
    ) -> io::Result<Self> {
        debug!(?addr, reuse_port, "binding");
        let socket = UdpSocket::bind_with(addr, bind_options(reuse_port)).inspect_err(|err| {
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
            is_copy,
        })
    }

    /// Whether `self` and `other` are the same socket
    pub(super) fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.socket, &other.socket)
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
    /// Returns all sockets, including the copies bound with `SO_REUSEPORT`
    pub(super) fn iter(&self) -> impl Iterator<Item = &IpTransport> {
        self.0.iter()
    }

    /// Returns one socket per transport, without the copies
    pub(super) fn primaries(&self) -> impl Iterator<Item = &IpTransport> {
        self.0.iter().filter(|t| !t.is_copy)
    }

    /// Binds the transports, each with `sockets_per_transport` sockets
    pub(super) fn bind(
        configs: impl Iterator<Item = Config>,
        sockets_per_transport: NonZeroUsize,
        metrics: &EndpointMetrics,
    ) -> io::Result<Self> {
        let mut has_v4_default = false;
        let mut has_v6_default = false;
        let mut transports = Vec::new();

        for config in configs {
            match IpTransport::bind_all(config, sockets_per_transport, &metrics.socket) {
                Ok(sockets) => {
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
                    transports.extend(sockets);
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
/// [`Config::is_valid_default_addr`].
///
/// A transport bound several times with `SO_REUSEPORT` has one socket id per socket. Its
/// destinations are spread over them by a hash of the destination, so a destination always
/// uses the same socket.
#[derive(Debug, Clone, Default)]
pub(super) struct IpSelection {
    /// Sorted by prefix length, longest first
    v4: Vec<(Config, Vec<SocketId>)>,
    /// Sorted by prefix length, longest first
    v6: Vec<(Config, Vec<SocketId>)>,
}

impl IpSelection {
    pub(super) fn new(transports: impl IntoIterator<Item = (Config, SocketId)>) -> Self {
        let mut groups: Vec<(Config, Vec<SocketId>)> = Vec::new();
        for (config, id) in transports {
            match groups.iter_mut().find(|(c, _)| *c == config) {
                Some((_, ids)) => ids.push(id),
                None => groups.push((config, vec![id])),
            }
        }
        let (mut v4, mut v6): (Vec<_>, Vec<_>) =
            groups.into_iter().partition(|(config, _)| config.is_ipv4());
        v4.sort_by_key(|(config, _)| std::cmp::Reverse(config.prefix_len()));
        v6.sort_by_key(|(config, _)| std::cmp::Reverse(config.prefix_len()));
        Self { v4, v6 }
    }

    /// Returns the transport for `dst`, sent from `src`
    pub(super) fn select(&self, dst: SocketAddr, src: Option<IpAddr>) -> Option<SocketId> {
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
        let (_, ids) = transports
            .iter()
            .find(|(config, _)| config.is_valid_send_addr(src, dst))
            .or_else(|| {
                transports
                    .iter()
                    .find(|(config, _)| config.is_valid_default_addr(src, dst))
            })?;
        match ids.as_slice() {
            [id] => Some(*id),
            ids => {
                let hash = std::hash::BuildHasherDefault::<std::hash::DefaultHasher>::default()
                    .hash_one(dst);
                Some(ids[hash as usize % ids.len()])
            }
        }
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

        let transports = IpTransports::bind(config.into_iter(), NonZeroUsize::MIN, &metrics)?;
        let expected = if has_ipv6 { 6 } else { 3 };
        assert_eq!(transports.iter().count(), expected);
        Ok(())
    }

    /// Copies bind the address of the first socket, and only the first is a primary
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn bind_copies() -> n0_error::Result {
        let config = Config::V4 {
            ip_net: "127.0.0.1/8".parse().unwrap(),
            port: 0,
            is_required: true,
            is_default: true,
        };
        let metrics = EndpointMetrics::default();
        let transports = IpTransports::bind([config].into_iter(), 3.try_into().unwrap(), &metrics)?;
        let addrs: Vec<_> = transports.iter().map(|t| t.local_addr.get()).collect();
        assert_eq!(addrs.len(), 3);
        assert_ne!(addrs[0].port(), 0);
        assert!(addrs.iter().all(|addr| *addr == addrs[0]));
        assert_eq!(transports.primaries().count(), 1);
        Ok(())
    }

    #[test]
    fn ip_selection_spreads_copies() {
        let config = Config::V4 {
            ip_net: "0.0.0.0/0".parse().unwrap(),
            port: 0,
            is_required: true,
            is_default: true,
        };
        let ids: Vec<SocketId> = (0..3).map(|_| SocketId::new()).collect();
        let selection = IpSelection::new(ids.iter().map(|id| (config, *id)));
        let select = |port: u16| selection.select(SocketAddr::from(([10, 0, 0, 1], port)), None);
        let picked: std::collections::HashSet<_> = (1..100).filter_map(select).collect();
        assert_eq!(picked.len(), ids.len());
        // A destination always gets the same socket.
        assert!((1..100).all(|port| select(port) == select(port)));
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
        let ids: Vec<SocketId> = (0..5).map(|_| SocketId::new()).collect();
        let selection = IpSelection::new([
            (v4("0.0.0.0/0", false), ids[0]),
            (v4("10.1.0.5/16", false), ids[1]),
            (v4("192.168.0.7/32", true), ids[2]),
            (v6("::/0", 0, false), ids[3]),
            (v6("fe80::1/128", 7, false), ids[4]),
        ]);
        let select = |dst: &str, src: Option<&str>| {
            selection.select(dst.parse().unwrap(), src.map(|s| s.parse().unwrap()))
        };
        // Without a source: longest prefix.
        assert_eq!(select("10.1.2.3:1", None), Some(ids[1]));
        assert_eq!(select("8.8.8.8:1", None), Some(ids[0]));
        // IPv4-mapped destinations select IPv4 transports.
        assert_eq!(select("[::ffff:10.1.2.3]:1", None), Some(ids[1]));
        // With a source: a transport bound to it, or a wildcard one.
        assert_eq!(select("10.1.2.3:1", Some("192.168.0.7")), Some(ids[2]));
        assert_eq!(select("10.1.2.3:1", Some("172.16.0.1")), Some(ids[0]));
        // Link-local destinations select by scope id.
        assert_eq!(select("[fe80::9%7]:1", None), Some(ids[4]));
        assert_eq!(select("[2001:db8::1]:1", None), Some(ids[3]));
    }
}
