use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::task::AtomicWaker;
use ipnet::{Ipv4Net, Ipv6Net};
use n0_watcher::Watchable;
use netwatch::{UdpSender, UdpSocket};
use pin_project::pin_project;
use tokio::time::{Instant, Sleep};
use tracing::{debug, info, trace, warn};

use super::{RecvInfo, Transmit};
use crate::metrics::{EndpointMetrics, SocketMetrics};

#[derive(Debug)]
pub(crate) struct IpTransport {
    config: Config,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<SocketMetrics>,
    rebind_waker: Arc<AtomicWaker>,
    rebind_retry: Option<RebindRetry>,
}

// Recovery is driven by receive polling, so dropping the transport also drops
// the retry timer. Persistent failures back off rather than spin or kill Noq.
#[derive(Debug)]
struct RebindRetry {
    delay: Duration,
    sleep: Pin<Box<Sleep>>,
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
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(local_addr);

        Ok(Self {
            config,
            socket: Arc::new(socket),
            local_addr,
            metrics,
            rebind_waker: Default::default(),
            rebind_retry: None,
        })
    }

    /// Closed sockets wait for a backed-off rebind instead of terminating Noq.
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
        self.rebind_waker.register(cx.waker());
        if self.socket.is_closed() {
            let retry = self.rebind_retry.get_or_insert_with(|| {
                let delay = Duration::from_millis(100);
                RebindRetry {
                    delay,
                    sleep: Box::pin(tokio::time::sleep(delay)),
                }
            });
            std::task::ready!(retry.sleep.as_mut().poll(cx));
            if let Err(err) = rebind_socket(&self.socket, &self.local_addr) {
                warn!("failed to rebind IP transport: {err:?}");
                retry.delay = (retry.delay * 2).min(Duration::from_secs(5));
                retry.sleep.as_mut().reset(Instant::now() + retry.delay);
                // Register the timer's wakeup before returning Pending.
                let _ = retry.sleep.as_mut().poll(cx);
                return Poll::Pending;
            }
        }
        self.rebind_retry = None;
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
            Poll::Ready(Err(_)) if self.socket.is_closed() => {
                // A network-change rebind may fail between the check above and
                // the receive poll. Enter recovery on the next poll as well.
                cx.waker().wake_by_ref();
                Poll::Pending
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
            rebind_waker: self.rebind_waker.clone(),
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
    rebind_waker: Arc<AtomicWaker>,
}

impl IpNetworkChangeSender {
    pub(super) fn rebind(&self) -> io::Result<()> {
        let result = rebind_socket(&self.socket, &self.local_addr);
        // netwatch wakes its receivers only on success. A failed rebind must
        // wake the Noq driver too, so it can arm the recovery timer.
        self.rebind_waker.wake();
        result
    }

    pub(super) fn on_network_change(&self, _info: &crate::socket::Report) {
        // Nothing to do for now
    }
}

fn rebind_socket(socket: &UdpSocket, local_addr: &Watchable<SocketAddr>) -> io::Result<()> {
    let old_addr = local_addr.get();
    socket.rebind()?;
    let addr = socket.local_addr()?;
    local_addr.set(addr).ok();
    trace!("rebound from {} to {}", old_addr, addr);
    Ok(())
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

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut IpTransport> {
        self.v4.iter_mut().chain(self.v6.iter_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct WakeCount(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn recovery_transports(count: usize) -> super::super::Transports {
        let config = Config::V4 {
            ip_net: Ipv4Net::new(std::net::Ipv4Addr::LOCALHOST, 32).unwrap(),
            port: 0,
            is_required: true,
            is_default: false,
        };
        super::super::Transports {
            ip: IpTransports::bind(
                std::iter::repeat_n(config, count),
                &EndpointMetrics::default(),
            )
            .unwrap(),
            relay: Vec::new(),
            custom: Vec::new(),
            poll_recv_counter: 0,
            recv_infos: Default::default(),
            consecutive_total_recv_failures: 0,
        }
    }

    #[tokio::test]
    async fn failed_rebind_wakes_receiver_and_recovers_without_relays() {
        let mut transports = recovery_transports(1);
        let socket = transports.ip.v4[0].socket.clone();
        let address = socket.local_addr().unwrap();
        let change = transports.ip.v4[0].create_network_change_sender();
        let wakes = Arc::new(WakeCount::default());
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut storage = [[0u8; 64]; noq_udp::BATCH_SIZE];
        let mut bufs = storage.each_mut().map(|buf| io::IoSliceMut::new(buf));
        let mut metas = [noq_udp::RecvMeta::default(); noq_udp::BATCH_SIZE];
        assert!(
            transports
                .inner_poll_recv(&mut cx, &mut bufs, &mut metas)
                .is_pending()
        );

        // Hold the original port after closing the socket, forcing a real
        // EADDRINUSE. No platform interface changes or injected I/O errors.
        socket.close().await;
        let blocker = std::net::UdpSocket::bind(address).unwrap();
        wakes.0.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            change.rebind().unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
        // Previously these polls exhausted the aggregate receive-error budget
        // and permanently terminated Noq, even before the port became free.
        for _ in 0..32 {
            assert!(
                transports
                    .inner_poll_recv(&mut cx, &mut bufs, &mut metas)
                    .is_pending()
            );
        }
        let peer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            drop(blocker);
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            loop {
                peer.send_to(b"ping", address).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let received = tokio::time::timeout(
            Duration::from_secs(3),
            std::future::poll_fn(|cx| transports.inner_poll_recv(cx, &mut bufs, &mut metas)),
        )
        .await;
        peer.abort();
        assert_eq!(received.unwrap().unwrap(), 1);
        assert_eq!(&storage[0][..4], b"ping");
        assert_eq!(socket.local_addr().unwrap(), address);
        assert_eq!(transports.ip.v4[0].local_addr.get(), address);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_rebind_retries_with_capped_backoff() {
        use std::sync::atomic::Ordering;
        let mut transports = recovery_transports(1);
        let socket = transports.ip.v4[0].socket.clone();
        let address = socket.local_addr().unwrap();
        socket.close().await;
        let _blocker = std::net::UdpSocket::bind(address).unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut storage = [[0u8; 64]; noq_udp::BATCH_SIZE];
        let mut bufs = storage.each_mut().map(|buf| io::IoSliceMut::new(buf));
        let mut metas = [noq_udp::RecvMeta::default(); noq_udp::BATCH_SIZE];
        assert!(
            transports
                .inner_poll_recv(&mut cx, &mut bufs, &mut metas)
                .is_pending()
        );
        for millis in [100, 200, 400, 800, 1600, 3200, 5000, 5000] {
            wakes.0.store(0, Ordering::SeqCst);
            tokio::time::advance(Duration::from_millis(millis - 1)).await;
            tokio::task::yield_now().await;
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            tokio::time::advance(Duration::from_millis(2)).await;
            tokio::task::yield_now().await;
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert!(
                transports
                    .inner_poll_recv(&mut cx, &mut bufs, &mut metas)
                    .is_pending()
            );
        }
    }

    #[tokio::test]
    async fn failed_rebind_does_not_block_healthy_transport() {
        let mut transports = recovery_transports(2);
        let broken = transports.ip.v4[0].socket.clone();
        let broken_address = broken.local_addr().unwrap();
        broken.close().await;
        let _blocker = std::net::UdpSocket::bind(broken_address).unwrap();
        let healthy_address = transports.ip.v4[1].socket.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"healthy", healthy_address).await.unwrap();
        let mut storage = [[0u8; 64]; noq_udp::BATCH_SIZE];
        let mut bufs = storage.each_mut().map(|buf| io::IoSliceMut::new(buf));
        let mut metas = [noq_udp::RecvMeta::default(); noq_udp::BATCH_SIZE];
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| transports.inner_poll_recv(cx, &mut bufs, &mut metas)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&storage[0][..7], b"healthy");
    }

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
