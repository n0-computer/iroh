use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{atomic::AtomicUsize, Arc},
    task::{Context, Poll},
};

use iroh_base::{NodeId, RelayUrl};
use n0_watcher::Watcher;
use relay::RelayDatagramSendChannelSender;
use tracing::{trace, warn};

#[cfg(not(wasm_browser))]
mod ip;
mod relay;

#[cfg(not(wasm_browser))]
use self::ip::IpIoPoller;
#[cfg(not(wasm_browser))]
pub(crate) use self::ip::IpTransport;
pub(crate) use self::relay::{RelayActorConfig, RelayTransport};
use super::{MagicSock, MappedAddr, NetInfo};
use crate::net_report::IpMappedAddresses;

/// Manages the different underlying data transports that the magicsock
/// can support.
#[derive(Debug)]
pub(crate) struct Transports {
    #[cfg(not(wasm_browser))]
    ip: Vec<IpTransport>,
    relay: Vec<RelayTransport>,

    poll_recv_counter: AtomicUsize,
}

impl Transports {
    /// Creates a new transports structure.
    pub(crate) fn new(
        #[cfg(not(wasm_browser))] ip: Vec<IpTransport>,
        relay: Vec<RelayTransport>,
    ) -> Self {
        Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            poll_recv_counter: Default::default(),
        }
    }

    /// Send the given [`Transmit`] to the given [`Addr`].
    ///
    /// Sends on the first matching & ready transport.
    pub(crate) fn poll_send(
        &self,
        destination: &Addr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        trace!(?destination, "sending");

        match destination {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => {
                return Poll::Ready(Err(io::Error::other("IP is unsupported in browser")))
            }
            #[cfg(not(wasm_browser))]
            Addr::Ip(addr) => {
                for transport in &self.ip {
                    if transport.is_valid_send_addr(addr) {
                        match transport.poll_send(*addr, src, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
            Addr::Relay(url, node_id) => {
                for transport in &self.relay {
                    if transport.is_valid_send_addr(url, node_id) {
                        match transport.poll_send(url.clone(), *node_id, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
        }
        Poll::Pending
    }

    /// Tries to recv data, on all available transports.
    pub(crate) fn poll_recv(
        &self,
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
            for transport in &self.ip {
                poll_transport!(transport);
            }
            for transport in &self.relay {
                poll_transport!(transport);
            }
        } else {
            for transport in self.relay.iter().rev() {
                poll_transport!(transport);
            }
            #[cfg(not(wasm_browser))]
            for transport in self.ip.iter().rev() {
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
        self.local_addrs_watch().get().expect("not disconnected")
    }

    /// Watch for all currently known local addresses.
    #[cfg(not(wasm_browser))]
    pub(crate) fn local_addrs_watch(&self) -> impl Watcher<Value = Vec<Addr>> + Send + Sync {
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
    pub(crate) fn local_addrs_watch(&self) -> impl Watcher<Value = Vec<Addr>> + Send + Sync {
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

    /// Returns the local addresses for IP based transports
    #[cfg(not(wasm_browser))]
    pub(crate) fn ip_local_addrs(&self) -> Vec<SocketAddr> {
        self.ip.iter().map(|t| t.local_addr()).collect()
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
        // `max_receive_segments` controls the size of the `RecvMeta` buffer
        // that quinn creates. Having buffers slightly bigger than necessary
        // isn't terrible, and makes sure a single socket can read the maximum
        // amount with a single poll. We considered adding these numbers instead,
        // but we never get data from both sockets at the same time in `poll_recv`
        // and it's impossible and unnecessary to be refactored that way.

        let res = self.ip.iter().map(|t| t.max_receive_segments()).max();
        res.unwrap_or(1)
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

    /// Check if a transport is writable, aka sendable on, for the given `addr`.
    pub(crate) fn poll_writable(&self, cx: &mut Context, addr: &Addr) -> Poll<io::Result<()>> {
        // TODO: what about multiple matches?
        match addr {
            #[cfg(wasm_browser)]
            Addr::Ip(..) => Poll::Ready(Err(io::Error::other(
                "IP based addressing is not supported in the browser",
            ))),
            #[cfg(not(wasm_browser))]
            Addr::Ip(addr) => match self.ip.iter().find(|t| t.is_valid_send_addr(addr)) {
                Some(t) => t.poll_writable(cx),
                None => Poll::Pending,
            },
            Addr::Relay(url, node_id) => {
                match self
                    .relay
                    .iter()
                    .find(|t| t.is_valid_send_addr(url, node_id))
                {
                    Some(t) => t.poll_writable(cx),
                    None => Poll::Pending,
                }
            }
        }
    }

    pub(crate) fn create_io_poller(
        &self,
        msock: Arc<MagicSock>,
        ip_mapped_addrs: IpMappedAddresses,
    ) -> Pin<Box<dyn quinn::UdpPoller>> {
        #[cfg(not(wasm_browser))]
        let ip_pollers = self.ip.iter().map(|t| t.create_io_poller()).collect();

        let relay_pollers = self.relay.iter().map(|t| t.create_io_poller()).collect();

        Box::pin(IoPoller {
            #[cfg(not(wasm_browser))]
            ip_pollers,
            relay_pollers,
            ip_mapped_addrs,
            msock,
        })
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

    /// Handles potential changes to the underlying network conditions.
    pub(crate) fn on_network_change(&self, info: &NetInfo) {
        #[cfg(not(wasm_browser))]
        for transport in &self.ip {
            transport.on_network_change(info);
        }

        for transport in &self.relay {
            transport.on_network_change(info);
        }
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

impl TryFrom<Addr> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::Ip(addr) => Ok(addr),
            _ => Err(anyhow::anyhow!("not a valid socket addr")),
        }
    }
}

impl TryFrom<Addr> for IpAddr {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::Ip(addr) => Ok(addr.ip()),
            _ => Err(anyhow::anyhow!("not a valid socket addr")),
        }
    }
}

impl TryFrom<Addr> for (RelayUrl, NodeId) {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::Relay(url, node) => Ok((url, node)),
            _ => Err(anyhow::anyhow!("not a valid relay url")),
        }
    }
}

impl Addr {
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(..))
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(..))
    }
}

#[derive(Debug)]
pub struct IoPoller {
    #[cfg(not(wasm_browser))]
    ip_pollers: Vec<IpIoPoller>,
    relay_pollers: Vec<RelayDatagramSendChannelSender>,
    ip_mapped_addrs: IpMappedAddresses,
    msock: Arc<MagicSock>, // :(
}

impl quinn::UdpPoller for IoPoller {
    fn poll_writable(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        transmit: &quinn_proto::Transmit,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        match MappedAddr::from(transmit.destination) {
            MappedAddr::None(_dest) => {
                // return Poll::Ready(Err(io::Error::other("Cannot convert to a mapped address.")));
            }
            MappedAddr::NodeId(dest) => {
                // Get the node's relay address and best direct address, as well
                // as any pings that need to be sent for hole-punching purposes.
                match this.msock.addr_for_send(dest) {
                    Some((_node_id, udp_addr, relay_url)) => {
                        #[cfg(not(wasm_browser))]
                        if let Some(addr) = udp_addr {
                            for poller in &mut this.ip_pollers {
                                if poller.is_valid_send_addr(&addr) {
                                    match poller.poll_writable(cx) {
                                        Poll::Ready(_) => return Poll::Ready(Ok(())),
                                        Poll::Pending => (),
                                    }
                                }
                            }
                        }
                        if let Some(_url) = relay_url {
                            for poller in &mut this.relay_pollers {
                                match poller.poll_writable(cx) {
                                    Poll::Ready(_) => return Poll::Ready(Ok(())),
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                    None => {
                        // return Poll::Ready(Err(io::Error::other(
                        //     "no NodeState for mapped address",
                        // )));
                    }
                }
            }
            #[cfg(not(wasm_browser))]
            MappedAddr::Ip(addr) => match this.ip_mapped_addrs.get_ip_addr(&addr) {
                Some(addr) => {
                    for poller in &mut this.ip_pollers {
                        if poller.is_valid_send_addr(&addr) {
                            match poller.poll_writable(cx) {
                                Poll::Ready(_) => return Poll::Ready(Ok(())),
                                Poll::Pending => (),
                            }
                        }
                    }
                }
                None => {
                    // return Poll::Ready(Err(io::Error::other("unknown mapped address")));
                }
            },
        }

        Poll::Pending
    }
}
