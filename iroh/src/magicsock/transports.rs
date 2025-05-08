use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    task::{Context, Poll},
};

use iroh_base::{NodeId, RelayUrl};

mod ip;
pub(crate) mod relay;

pub use self::{ip::IpTransport, relay::RelayTransport};

pub trait Transport: std::fmt::Debug + Send + Sync + 'static {
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()>;
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn max_transmit_segments(&self) -> usize;
    fn max_receive_segments(&self) -> usize;
    fn may_fragment(&self) -> bool;

    fn is_valid_send_addr(&self, addr: &Addr) -> bool;
    fn poll_writable(&self, cx: &mut Context) -> Poll<std::io::Result<()>>;
    fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>>;

    /// If this transport is IP based, returns the bound address.
    fn bind_addr(&self) -> Option<SocketAddr>;
    fn rebind(&self) -> std::io::Result<()>;
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    pub destination: Addr,
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

#[derive(Debug, Clone)]
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
