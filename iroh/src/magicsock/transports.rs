use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    task::{Context, Poll},
};

use iroh_base::{NodeId, RelayUrl};
use tracing::trace;

mod ip;
pub(crate) mod relay;

pub use self::{ip::IpTransport, relay::RelayTransport};
use super::NetInfo;
use crate::watchable::{self, Watcher};

#[derive(Debug)]
pub struct Transports {
    ip: Vec<IpTransport>,
    relay: Vec<RelayTransport>,
}

impl Transports {
    pub fn new(ip: Vec<IpTransport>, relay: Vec<RelayTransport>) -> Self {
        Self { ip, relay }
    }

    pub fn poll_send(&self, destination: &Addr, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        // TODO: should this send on all, or only a single transport?

        trace!(?destination, "sending");

        match destination {
            Addr::Ipv4(addr, port) => {
                let addr = SocketAddr::V4(SocketAddrV4::new(*addr, port.unwrap_or_default()));
                for transport in &self.ip {
                    if transport.is_valid_send_addr(&addr) {
                        match transport.poll_send(addr, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
            Addr::Ipv6(addr, port) => {
                let addr = SocketAddr::V6(SocketAddrV6::new(*addr, port.unwrap_or_default(), 0, 0));
                for transport in &self.ip {
                    if transport.is_valid_send_addr(&addr) {
                        match transport.poll_send(addr, transmit) {
                            Poll::Pending => {}
                            Poll::Ready(res) => return Poll::Ready(res),
                        }
                    }
                }
            }
            Addr::RelayUrl(url, node_id) => {
                for transport in &self.relay {
                    if transport.is_valid_send_addr(&url, &node_id) {
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

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");

        // TODO: randomization
        macro_rules! poll_transport {
            ($socket:expr) => {
                match $socket.poll_recv(cx, bufs, metas)? {
                    Poll::Pending | Poll::Ready(0) => {}
                    Poll::Ready(n) => {
                        return Poll::Ready(Ok(n));
                    }
                }
            };
        }

        for transport in &self.ip {
            poll_transport!(transport);
        }
        for transport in &self.relay {
            poll_transport!(transport);
        }
        Poll::Pending
    }

    pub fn local_addrs(&self) -> Vec<Addr> {
        self.local_addrs_watch().get().expect("not disconnected")
    }

    pub fn local_addrs_watch(&self) -> impl Watcher<Value = Vec<Addr>> + Send + Sync {
        let ips = self.ip.iter().map(|t| {
            t.local_addr_watch()
                .map(move |a| a.map(Addr::from))
                .expect("disconnected")
        });
        let ips = watchable::JoinOpt::new(ips).expect("disconnected");

        let relays = self.relay.iter().map(|t| {
            t.local_addr_watch()
                .map(move |t| t.map(|(url, id)| Addr::RelayUrl(url, id)))
                .expect("disconnected")
        });
        let relays = watchable::JoinOpt::new(relays).expect("disconnected");

        watchable::Merge2::new(ips, relays)
    }

    pub fn max_transmit_segments(&self) -> usize {
        // TODO: does this need to accoutn for the relay transports?

        let res = self.ip.iter().map(|t| t.max_transmit_segments()).min();
        res.unwrap_or(1)
    }

    pub fn max_receive_segments(&self) -> usize {
        // TODO: does this need to accoutn for the relay transports?

        // `max_receive_segments` controls the size of the `RecvMeta` buffer
        // that quinn creates. Having buffers slightly bigger than necessary
        // isn't terrible, and makes sure a single socket can read the maximum
        // amount with a single poll. We considered adding these numbers instead,
        // but we never get data from both sockets at the same time in `poll_recv`
        // and it's impossible and unnecessary to be refactored that way.

        let res = self.ip.iter().map(|t| t.max_receive_segments()).max();
        res.unwrap_or(1)
    }

    pub fn may_fragment(&self) -> bool {
        self.ip.iter().any(|t| t.may_fragment())
    }

    pub fn poll_writable(&self, cx: &mut Context, addr: &Addr) -> Poll<io::Result<()>> {
        // TODO: what about multiple matches?
        match addr {
            Addr::Ipv4(..) | Addr::Ipv6(..) => {
                let addr: SocketAddr = addr.clone().try_into().unwrap();
                match self.ip.iter().find(|t| t.is_valid_send_addr(&addr)) {
                    Some(t) => t.poll_writable(cx),
                    None => Poll::Pending,
                }
            }
            Addr::RelayUrl(url, node_id) => {
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

    pub fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        // To do this properly the MagicSock would need a registry of pollers.  For each
        // node we would look up the poller or create one.  Then on each try_send we can
        // look up the correct poller and configure it to poll the paths it needs.
        //
        // Note however that the current quinn impl calls UdpPoller::poll_writable()
        // **before** it calls try_send(), as opposed to how it is documented.  That is a
        // problem as we would not yet know the path that needs to be polled.  To avoid such
        // ambiguity the API could be changed to a .poll_send(&self, cx: &mut Context,
        // io_poller: Pin<&mut dyn UdpPoller>, transmit: &Transmit) -> Poll<io::Result<()>>
        // instead of the existing .try_send() because then we would have control over this.
        //
        // Right now however we have one single poller behaving the same for each
        // connection.  It checks all paths and returns Poll::Ready as soon as any path is
        // ready.
        let io_pollers: Vec<_> = self
            .ip
            .iter()
            .map(|t| t.create_io_poller())
            .chain(self.relay.iter().map(|t| t.create_io_poller()))
            .collect();

        Box::pin(IoPoller { io_pollers })
    }

    /// Returns a list of a IP based bound addresses
    pub fn bind_addrs(&self) -> Vec<SocketAddr> {
        self.ip.iter().map(|t| t.bind_addr()).collect()
    }

    /// Rebinds underlying connections, if necessary.
    pub fn rebind(&self) -> std::io::Result<()> {
        // TODO: failure in an earlier transport will skip other rebinds, is that ok?

        for transport in &self.ip {
            transport.rebind()?;
        }

        for transport in &self.relay {
            transport.rebind()?;
        }
        Ok(())
    }

    /// Handles potential changes to the underlying network conditions.
    pub fn on_network_change(&self, info: &NetInfo) {
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
pub struct Transmit<'a> {
    pub ecn: Option<quinn_udp::EcnCodepoint>,
    pub contents: &'a [u8],
    pub segment_size: Option<usize>,
    pub src_ip: Option<Addr>,
}

#[derive(Debug, Clone)]
pub struct RecvMeta {
    pub addr: Addr,
    pub len: usize,
    pub stride: usize,
    pub ecn: Option<quinn_udp::EcnCodepoint>,
    pub dst_ip: Option<Addr>,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into(),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Ipv4(Ipv4Addr, Option<u16>),
    Ipv6(Ipv6Addr, Option<u16>),
    RelayUrl(RelayUrl, NodeId),
}

impl From<IpAddr> for Addr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => Self::Ipv4(addr, None),
            IpAddr::V6(addr) => Self::Ipv6(addr, None),
        }
    }
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => Self::Ipv4(*addr.ip(), Some(addr.port())),
            SocketAddr::V6(addr) => Self::Ipv6(*addr.ip(), Some(addr.port())),
        }
    }
}

impl From<(RelayUrl, NodeId)> for Addr {
    fn from(value: (RelayUrl, NodeId)) -> Self {
        Self::RelayUrl(value.0, value.1)
    }
}

impl TryFrom<Addr> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::Ipv4(addr, Some(port)) => Ok(SocketAddr::V4(SocketAddrV4::new(addr, port))),
            Addr::Ipv6(addr, Some(port)) => Ok(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))),
            _ => Err(anyhow::anyhow!("not a valid socket addr")),
        }
    }
}

impl TryFrom<Addr> for IpAddr {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::Ipv4(addr, _) => Ok(IpAddr::V4(addr)),
            Addr::Ipv6(addr, _) => Ok(IpAddr::V6(addr)),
            _ => Err(anyhow::anyhow!("not a valid socket addr")),
        }
    }
}

impl TryFrom<Addr> for (RelayUrl, NodeId) {
    type Error = anyhow::Error;

    fn try_from(value: Addr) -> Result<Self, Self::Error> {
        match value {
            Addr::RelayUrl(url, node) => Ok((url, node)),
            _ => Err(anyhow::anyhow!("not a valid relay url")),
        }
    }
}

impl Addr {
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::RelayUrl(..))
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ipv4(..) | Self::Ipv6(..))
    }
}

#[derive(Debug)]
pub struct IoPoller {
    io_pollers: Vec<Pin<Box<dyn quinn::UdpPoller>>>,
}

impl quinn::UdpPoller for IoPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // This version returns Ready as soon as any of them are ready.
        let this = &mut *self;
        for poller in &mut this.io_pollers {
            match poller.as_mut().poll_writable(cx) {
                Poll::Ready(_) => return Poll::Ready(Ok(())),
                Poll::Pending => (),
            }
        }
        Poll::Pending
    }
}
