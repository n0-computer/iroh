use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    task::{Context, Poll},
};

use enum_dispatch::enum_dispatch;
use iroh_base::{NodeId, RelayUrl};

mod ip;
pub(crate) mod relay;

use crate::watchable::Watcher;

pub use self::{ip::IpTransport, relay::RelayTransport};
use super::NetInfo;

#[derive(Debug)]
pub struct Transports {
    ip: Vec<IpTransport>,
    relay: Vec<RelayTransport>,
}

impl Transports {
    fn poll_send(&self, destination: Addr, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        match destination {
            Addr::Ipv4(addr, port) => {
                let addr = SocketAddr::V4(addr, port.unwrap_or_default());
                for transport in &self.ip {
                    if transport.is_valid_send_addr(&addr) {
                        transport.poll_send(addr, transmit)
                    }
                }
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        todo!()
    }

    fn local_addr(&self) -> Option<Addr> {
        todo!()
    }
    fn local_addr_watch(&self) {
        todo!()
    }

    fn max_transmit_segments(&self) -> usize {
        todo!()
    }
    fn max_receive_segments(&self) -> usize {
        todo!()
    }
    fn may_fragment(&self) -> bool {
        todo!()
    }

    fn is_valid_send_addr(&self, addr: &Addr) -> bool {
        todo!()
    }
    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        todo!()
    }
    fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        todo!()
    }

    /// If this transport is IP based, returns the bound address.
    fn bind_addr(&self) -> Option<SocketAddr> {
        todo!()
    }

    /// Rebinds underlying connections, if necessary.
    fn rebind(&self) -> std::io::Result<()> {
        todo!()
    }

    /// Handles potential changes to the underlying network conditions.
    fn on_network_change(&self, info: &NetInfo) {
        todo!()
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
