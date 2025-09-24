use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{Arc, atomic::AtomicUsize},
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{NodeId, RelayUrl};
use n0_watcher::Watcher;
use relay::{RelayNetworkChangeSender, RelaySender};
use tokio::sync::mpsc;
use tracing::{debug, error, instrument, trace, warn};

use crate::net_report::Report;

use super::{MagicSock, mapped_addrs::MultipathMappedAddr, node_map::NodeStateMessage};

#[cfg(not(wasm_browser))]
mod ip;
mod relay;

#[cfg(not(wasm_browser))]
pub(crate) use self::ip::IpTransport;
#[cfg(not(wasm_browser))]
use self::ip::{IpNetworkChangeSender, IpSender};

pub(crate) use self::relay::{RelayActorConfig, RelayTransport};

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

    pub(crate) fn create_sender(&self) -> TransportsSender {
        #[cfg(not(wasm_browser))]
        let ip = self.ip.iter().map(|t| t.create_sender()).collect();
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug)]
pub(crate) struct TransportsSender {
    #[cfg(not(wasm_browser))]
    ip: Vec<IpSender>,
    relay: Vec<RelaySender>,
    max_transmit_segments: usize,
}

impl TransportsSender {
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
    fn inner_try_send(
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

/// A [`Transports`] that works with [`MultipathMappedAddr`]s and their IPv6 representation.
///
/// The [`MultipathMappedAddr`]s have an IPv6 representation that Quinn uses.  This struct
/// knows about these and maps them back to the transport [`Addr`]s used by the wrapped
/// [`Transports`].
#[derive(Debug)]
pub(crate) struct MagicTransport {
    msock: Arc<MagicSock>,
    transports: Transports,
}

impl MagicTransport {
    pub(crate) fn new(msock: Arc<MagicSock>, transports: Transports) -> Self {
        Self { msock, transports }
    }
}

impl quinn::AsyncUdpSocket for MagicTransport {
    fn create_sender(&self) -> Pin<Box<dyn quinn::UdpSender>> {
        Box::pin(MagicSender {
            msock: self.msock.clone(),
            sender: self.transports.create_sender(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.transports.poll_recv(cx, bufs, meta, &self.msock)
    }

    #[cfg(not(wasm_browser))]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let addrs: Vec<_> = self
            .transports
            .local_addrs()
            .into_iter()
            .filter_map(|addr| {
                let addr: SocketAddr = addr.into_socket_addr()?;
                Some(addr)
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

        Err(io::Error::other("no valid address available"))
    }

    #[cfg(wasm_browser)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Again, we need to pretend we're IPv6, because of our `MappedAddr`s.
        Ok(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0))
    }

    fn max_receive_segments(&self) -> usize {
        self.transports.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.transports.may_fragment()
    }
}

/// A sender for [`MagicTransport`].
///
/// This is special in that it handles [`MultipathMappedAddr::Mixed`] by delegating to the
/// [`MagicSock`] which expands it back to one or more [`Addr`]s and sends it
/// using the underlying [`Transports`].
// TODO: Can I just send the TransportsSender along in the NodeStateMessage::SendDatagram
// message??  That way you don't have to hook up the sender into the NodeMap!
#[derive(Debug)]
#[pin_project::pin_project]
pub(crate) struct MagicSender {
    msock: Arc<MagicSock>,
    #[pin]
    sender: TransportsSender,
}

impl MagicSender {
    /// Extracts the right [`Addr`] from the [`quinn_udp::Transmit`].
    ///
    /// Because Quinn does only know about IP transports we map other transports to private
    /// IPv6 Unique Local Address ranges.  This extracts the transport addresses out of the
    /// transmit's destination.
    fn mapped_addr(&self, transmit: &quinn_udp::Transmit) -> io::Result<MultipathMappedAddr> {
        self.msock
            .metrics
            .magicsock
            .send_data
            .inc_by(transmit.contents.len() as _);

        if self.msock.is_closed() {
            self.msock
                .metrics
                .magicsock
                .send_data_network_down
                .inc_by(transmit.contents.len() as _);
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }

        let addr = MultipathMappedAddr::from(transmit.destination);
        trace!(
            dst = ?addr,
            src = ?transmit.src_ip,
            len = %transmit.contents.len(),
            "sending",
        );
        Ok(addr)
    }
}

impl quinn::UdpSender for MagicSender {
    #[instrument(
        skip_all,
        fields(src = ?quinn_transmit.src_ip, len = quinn_transmit.contents.len(), dst, node_id),
    )]
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
                // TODO: Would be nicer to log the NodeId of this, but we only get an actor
                //   sender for it.
                tracing::Span::current().record("dst", tracing::field::debug(&mapped_addr));
                let Some(node_id) = self.msock.node_map.node_mapped_addrs.lookup(&mapped_addr)
                else {
                    error!("unknown NodeIdMappedAddr, dropped transmit");
                    return Poll::Ready(Ok(()));
                };
                tracing::Span::current().record("node_id", node_id.fmt_short());

                // Note we drop the src_ip set in the Quinn Transmit.  This is only the
                // Initial packet we are sending, so we do not yet have an src address we
                // need to respond from.
                if let Some(src_ip) = quinn_transmit.src_ip {
                    warn!(?src_ip, "oops, flub didn't think this would happen");
                }

                let sender = self.msock.node_map.node_state_actor(node_id);
                let transmit = OwnedTransmit::from(quinn_transmit);
                return match sender.try_send(NodeStateMessage::SendDatagram(transmit)) {
                    Ok(()) => {
                        trace!("sent transmit",);
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        // We do not want to block the next send which might be on a
                        // different transport.  Instead we let Quinn handle this as
                        // a lost datagram.
                        // TODO: Revisit this: we might want to do something better.
                        debug!("NodeStateActor inbox full ({err:#}), dropped transmit");
                        Poll::Ready(Ok(()))
                    }
                };
            }
            MultipathMappedAddr::Relay(relay_mapped_addr) => {
                match self
                    .msock
                    .node_map
                    .relay_mapped_addrs
                    .lookup(&relay_mapped_addr)
                {
                    Some((relay_url, node_id)) => Addr::Relay(relay_url, node_id),
                    None => {
                        error!("unknown RelayMappedAddr, dropped transmit");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            MultipathMappedAddr::Ip(socket_addr) => Addr::Ip(socket_addr),
        };
        tracing::Span::current().record("dst", tracing::field::debug(&transport_addr));

        let transmit = Transmit {
            ecn: quinn_transmit.ecn,
            contents: quinn_transmit.contents,
            segment_size: quinn_transmit.segment_size,
        };
        let this = self.project();

        match this
            .sender
            .inner_poll_send(cx, &transport_addr, quinn_transmit.src_ip, &transmit)
        {
            Poll::Ready(Ok(())) => {
                trace!("sent transmit",);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(ref err)) => {
                warn!("dropped transmit: {err:#}");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // We do not want to block the next send which might be on a
                // different transport.  Instead we let Quinn handle this as a lost
                // datagram.
                // TODO: Revisit this: we might want to do something better.
                trace!("transport pending, dropped transmit");
                Poll::Ready(Ok(()))
            }
        }
    }

    fn max_transmit_segments(&self) -> usize {
        self.sender.max_transmit_segments
    }

    #[instrument(
        skip_all,
        fields(src = ?quinn_transmit.src_ip, len = quinn_transmit.contents.len(), dst, node_id),
    )]
    fn try_send(self: Pin<&mut Self>, quinn_transmit: &quinn_udp::Transmit) -> io::Result<()> {
        // As opposed to poll_send this method does return normal IO errors.  Calls to this
        // are one-off fire-and-forget calls with no implications for the EndpointDriver.
        let mapped_addr = self.mapped_addr(quinn_transmit)?;

        let transport_addr = match mapped_addr {
            MultipathMappedAddr::Mixed(mapped_addr) => {
                // TODO: Would be nicer to log the NodeId of this, but we only get an actor
                //   sender for it.
                tracing::Span::current().record("dst", tracing::field::debug(&mapped_addr));
                let Some(node_id) = self.msock.node_map.node_mapped_addrs.lookup(&mapped_addr)
                else {
                    error!("unknown NodeIdMappedAddr, dropped transmit");
                    return Err(io::Error::new(
                        io::ErrorKind::HostUnreachable,
                        "Unknown NodeIdMappedAddr",
                    ));
                };
                tracing::Span::current().record("node_id", node_id.fmt_short());

                // Note we drop the src_ip set in the Quinn Transmit.  This is only the
                // Initial packet we are sending, so we do not yet have an src address we
                // need to respond from.
                if let Some(src_ip) = quinn_transmit.src_ip {
                    warn!(?src_ip, "oops, flub didn't think this would happen");
                }
                let sender = self.msock.node_map.node_state_actor(node_id);
                let transmit = OwnedTransmit::from(quinn_transmit);
                return match sender.try_send(NodeStateMessage::SendDatagram(transmit)) {
                    Ok(()) => {
                        trace!("sent transmit",);
                        Ok(())
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!("NodeStateActor inbox full, dropped transmit");
                        Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "NodeStateActor inbox full",
                        ))
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        debug!("NodeStateActor inbox closed, dropped transmit");
                        Err(io::Error::new(
                            io::ErrorKind::NetworkDown,
                            "NodeStateActor inbox closed",
                        ))
                    }
                };
            }
            MultipathMappedAddr::Relay(relay_mapped_addr) => {
                match self
                    .msock
                    .node_map
                    .relay_mapped_addrs
                    .lookup(&relay_mapped_addr)
                {
                    Some((relay_url, node_id)) => Addr::Relay(relay_url, node_id),
                    None => {
                        error!("unknown RelayMappedAddr, dropped transmit");
                        return Err(io::Error::new(
                            io::ErrorKind::HostUnreachable,
                            "unknown RelayMappedAddr",
                        ));
                    }
                }
            }
            MultipathMappedAddr::Ip(socket_addr) => Addr::Ip(socket_addr),
        };
        tracing::Span::current().record("dst", tracing::field::debug(&transport_addr));

        let transmit = Transmit {
            ecn: quinn_transmit.ecn,
            contents: quinn_transmit.contents,
            segment_size: quinn_transmit.segment_size,
        };
        match self
            .sender
            .inner_try_send(&transport_addr, quinn_transmit.src_ip, &transmit)
        {
            Ok(()) => {
                trace!("sent transmit",);
                Ok(())
            }
            Err(err) => {
                warn!("transmit failed to send: {err:#}");
                Err(err)
            }
        }
    }
}
