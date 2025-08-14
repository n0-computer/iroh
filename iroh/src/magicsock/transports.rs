use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{Arc, atomic::AtomicUsize},
    task::{Context, Poll},
};

use iroh_base::{NodeId, RelayUrl};
use n0_watcher::Watcher;
use relay::{RelayNetworkChangeSender, RelaySender};
use smallvec::SmallVec;
use tracing::{error, trace, warn};

#[cfg(not(wasm_browser))]
mod ip;
mod relay;

#[cfg(not(wasm_browser))]
pub(crate) use self::ip::IpTransport;
#[cfg(not(wasm_browser))]
use self::ip::{IpNetworkChangeSender, IpSender};
pub(crate) use self::relay::{RelayActorConfig, RelayTransport};
use super::MagicSock;
use crate::net_report::Report;

/// Manages the different underlying data transports that the magicsock
/// can support.
#[derive(Debug)]
pub(crate) struct Transports {
    #[cfg(not(wasm_browser))]
    ip: Vec<IpTransport>,
    relay: Vec<RelayTransport>,

    max_receive_segments: Arc<AtomicUsize>,
    poll_recv_counter: AtomicUsize,
}

#[cfg(not(wasm_browser))]
pub(crate) type LocalAddrsWatch = n0_watcher::Map<
    (
        n0_watcher::Join<SocketAddr, n0_watcher::Direct<SocketAddr>>,
        n0_watcher::Join<
            Option<(RelayUrl, NodeId)>,
            n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, NodeId)>>,
        >,
    ),
    Vec<Addr>,
>;

#[cfg(wasm_browser)]
pub(crate) type LocalAddrsWatch = n0_watcher::Map<
    n0_watcher::Join<
        Option<(RelayUrl, NodeId)>,
        n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, NodeId)>>,
    >,
    Vec<Addr>,
>;

impl Transports {
    /// Creates a new transports structure.
    pub(crate) fn new(
        #[cfg(not(wasm_browser))] ip: Vec<IpTransport>,
        relay: Vec<RelayTransport>,
        max_receive_segments: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            max_receive_segments,
            poll_recv_counter: Default::default(),
        }
    }

    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        msock: &MagicSock,
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        if msock.is_closed() {
            return Poll::Pending;
        }

        let mut source_addrs = vec![Addr::default(); metas.len()];
        match self.inner_poll_recv(cx, bufs, metas, &mut source_addrs)? {
            Poll::Pending | Poll::Ready(0) => Poll::Pending,
            Poll::Ready(n) => {
                msock.process_datagrams(&mut bufs[..n], &mut metas[..n], &source_addrs[..n]);
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
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");

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

        // To improve fairness, every other call reverses the ordering of polling.

        let counter = self
            .poll_recv_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if counter % 2 == 0 {
            #[cfg(not(wasm_browser))]
            for transport in &mut self.ip {
                poll_transport!(transport);
            }
            for transport in &mut self.relay {
                poll_transport!(transport);
            }
        } else {
            for transport in self.relay.iter_mut().rev() {
                poll_transport!(transport);
            }
            #[cfg(not(wasm_browser))]
            for transport in self.ip.iter_mut().rev() {
                poll_transport!(transport);
            }
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

        (ips, relays)
            .map(|(ips, relays)| {
                ips.into_iter()
                    .map(Addr::from)
                    .chain(
                        relays
                            .into_iter()
                            .flatten()
                            .map(|(relay_url, node_id)| Addr::Relay(relay_url, node_id)),
                    )
                    .collect()
            })
            .expect("disconnected")
    }

    #[cfg(wasm_browser)]
    pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
        let relays = self.relay.iter().map(|t| t.local_addr_watch());
        n0_watcher::Join::new(relays)
            .map(|relays| relays.into_iter().flatten().map(Addr::from).collect())
            .expect("disconnected")
    }

    /// Returns the bound addresses for IP based transports
    #[cfg(not(wasm_browser))]
    pub(crate) fn ip_bind_addrs(&self) -> Vec<SocketAddr> {
        self.ip.iter().map(|t| t.bind_addr()).collect()
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn max_transmit_segments(&self) -> usize {
        let res = self.ip.iter().map(|t| t.max_transmit_segments()).min();
        res.unwrap_or(1)
    }

    #[cfg(wasm_browser)]
    pub(crate) fn max_transmit_segments(&self) -> usize {
        1
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn max_receive_segments(&self) -> usize {
        use std::sync::atomic::Ordering::Relaxed;
        // `max_receive_segments` controls the size of the `RecvMeta` buffer
        // that quinn creates. Having buffers slightly bigger than necessary
        // isn't terrible, and makes sure a single socket can read the maximum
        // amount with a single poll. We considered adding these numbers instead,
        // but we never get data from both sockets at the same time in `poll_recv`
        // and it's impossible and unnecessary to be refactored that way.

        let res = self.ip.iter().map(|t| t.max_receive_segments()).max();
        let segments = res.unwrap_or(1);
        self.max_receive_segments.store(segments, Relaxed);
        segments
    }

    #[cfg(wasm_browser)]
    pub(crate) fn max_receive_segments(&self) -> usize {
        1
    }

    #[cfg(not(wasm_browser))]
    pub(crate) fn may_fragment(&self) -> bool {
        self.ip.iter().any(|t| t.may_fragment())
    }

    #[cfg(wasm_browser)]
    pub(crate) fn may_fragment(&self) -> bool {
        false
    }

    pub(crate) fn create_sender(&self, msock: Arc<MagicSock>) -> UdpSender {
        #[cfg(not(wasm_browser))]
        let ip = self.ip.iter().map(|t| t.create_sender()).collect();
        let relay = self.relay.iter().map(|t| t.create_sender()).collect();
        let max_transmit_segments = self.max_transmit_segments();

        UdpSender {
            #[cfg(not(wasm_browser))]
            ip,
            msock,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Addr {
    Ip(SocketAddr),
    Relay(RelayUrl, NodeId),
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
        Self::Ip(value)
    }
}

impl From<(RelayUrl, NodeId)> for Addr {
    fn from(value: (RelayUrl, NodeId)) -> Self {
        Self::Relay(value.0, value.1)
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
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpSender {
    msock: Arc<MagicSock>, // :(
    #[cfg(not(wasm_browser))]
    ip: Vec<IpSender>,
    relay: Vec<RelaySender>,
    max_transmit_segments: usize,
}

impl UdpSender {
    pub(crate) async fn send(
        &self,
        destination: &Addr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        trace!(?destination, "sending");

        let mut any_match = false;
        match destination {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => return Err(io::Error::other("IP is unsupported in browser")),
            #[cfg(not(wasm_browser))]
            Addr::Ip(addr) => {
                for sender in &self.ip {
                    if sender.is_valid_send_addr(addr) {
                        any_match = true;
                        match sender.send(*addr, src, transmit).await {
                            Ok(()) => {
                                return Ok(());
                            }
                            Err(err) => {
                                warn!("ip failed to send: {:?}", err);
                            }
                        }
                    }
                }
            }
            Addr::Relay(url, node_id) => {
                for sender in &self.relay {
                    if sender.is_valid_send_addr(url, node_id) {
                        any_match = true;
                        match sender.send(url.clone(), *node_id, transmit).await {
                            Ok(()) => {
                                return Ok(());
                            }
                            Err(err) => {
                                warn!("relay failed to send: {:?}", err);
                            }
                        }
                    }
                }
            }
        }
        if any_match {
            Err(io::Error::other("all available transports failed"))
        } else {
            Err(io::Error::other("no transport available"))
        }
    }

    pub(crate) fn inner_poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        destination: &Addr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        trace!(?destination, "sending");

        match destination {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => {
                return Poll::Ready(Err(io::Error::other("IP is unsupported in browser")));
            }
            #[cfg(not(wasm_browser))]
            Addr::Ip(addr) => {
                for sender in &mut self.ip {
                    if sender.is_valid_send_addr(addr) {
                        match Pin::new(sender).poll_send(cx, *addr, src, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
            Addr::Relay(url, node_id) => {
                for sender in &mut self.relay {
                    if sender.is_valid_send_addr(url, node_id) {
                        match sender.poll_send(cx, url.clone(), *node_id, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
        }
        Poll::Pending
    }

    /// Best effort sending
    pub(crate) fn inner_try_send(
        &self,
        destination: &Addr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        trace!(?destination, "sending, best effort");

        match destination {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => return Err(io::Error::other("IP is unsupported in browser")),
            #[cfg(not(wasm_browser))]
            Addr::Ip(addr) => {
                for transport in &self.ip {
                    if transport.is_valid_send_addr(addr) {
                        match transport.try_send(*addr, src, transmit) {
                            Ok(()) => return Ok(()),
                            Err(_err) => {
                                continue;
                            }
                        }
                    }
                }
            }
            Addr::Relay(url, node_id) => {
                for transport in &self.relay {
                    if transport.is_valid_send_addr(url, node_id) {
                        match transport.try_send(url.clone(), *node_id, transmit) {
                            Ok(()) => return Ok(()),
                            Err(_err) => {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "no transport ready",
        ))
    }
}

impl quinn::UdpSender for UdpSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &quinn_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let active_paths = self.msock.prepare_send(&self, transmit)?;

        if active_paths.is_empty() {
            // Returning Ok here means we let QUIC timeout.
            // Returning an error would immediately fail a connection.
            // The philosophy of quinn-udp is that a UDP connection could
            // come back at any time or missing should be transient so chooses to let
            // these kind of errors time out.  See test_try_send_no_send_addr to try
            // this out.
            error!("no paths available for node, voiding transmit");
            return Poll::Ready(Ok(()));
        }

        let mut results = SmallVec::<[_; 3]>::new();

        trace!(?active_paths, "attempting to send");

        for destination in active_paths {
            let src = transmit.src_ip;
            let transmit = Transmit {
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
            };

            let res = self
                .as_mut()
                .inner_poll_send(cx, &destination, src, &transmit);
            match res {
                Poll::Ready(Ok(())) => {
                    trace!(dst = ?destination, "sent transmit");
                }
                Poll::Ready(Err(ref err)) => {
                    warn!(dst = ?destination, "failed to send: {err:#}");
                }
                Poll::Pending => {}
            }
            results.push(res);
        }

        if results.iter().all(|p| matches!(p, Poll::Pending)) {
            // Handle backpressure.
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn max_transmit_segments(&self) -> usize {
        self.max_transmit_segments
    }

    fn try_send(self: Pin<&mut Self>, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        let active_paths = self.msock.prepare_send(&self, transmit)?;
        if active_paths.is_empty() {
            // Returning Ok here means we let QUIC timeout.
            // Returning an error would immediately fail a connection.
            // The philosophy of quinn-udp is that a UDP connection could
            // come back at any time or missing should be transient so chooses to let
            // these kind of errors time out.  See test_try_send_no_send_addr to try
            // this out.
            error!("no paths available for node, voiding transmit");
            return Ok(());
        }

        let mut results = SmallVec::<[_; 3]>::new();

        trace!(?active_paths, "attempting to send");

        for destination in active_paths {
            let src = transmit.src_ip;
            let transmit = Transmit {
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
            };

            let res = self.inner_try_send(&destination, src, &transmit);
            match res {
                Ok(()) => {
                    trace!(dst = ?destination, "sent transmit");
                }
                Err(ref err) => {
                    warn!(dst = ?destination, "failed to send: {err:#}");
                }
            }
            results.push(res);
        }

        if results.iter().all(|p| p.is_err()) {
            return Err(io::Error::other("all failed"));
        }
        Ok(())
    }
}
