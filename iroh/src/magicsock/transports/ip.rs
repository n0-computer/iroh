use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use quinn::AsyncUdpSocket;

use super::{Addr, RecvMeta, Transmit, Transport};
use crate::magicsock::UdpConn;

#[derive(Clone, Debug)]
pub struct IpTransport {
    bind_addr: SocketAddr,
    socket: UdpConn,
}

impl IpTransport {
    pub fn new(addr: SocketAddr, socket: UdpConn) -> Self {
        Self {
            bind_addr: addr,
            socket,
        }
    }
}

impl Transport for IpTransport {
    fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.socket.try_send(&quinn_udp::Transmit {
            destination: transmit
                .destination
                .clone()
                .try_into()
                .expect("invalid destination"),
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit
                .src_ip
                .clone()
                .map(|a| a.try_into().expect("invalid src_ip")),
        })
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        todo!()
        // self.socket.poll_recv(cx, bufs, metas)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    fn is_valid_send_addr(&self, addr: &Addr) -> bool {
        match (self.bind_addr, addr) {
            (SocketAddr::V4(_), Addr::Ipv4(..)) => true,
            (SocketAddr::V6(_), Addr::Ipv6(..)) => true,
            _ => false,
        }
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.as_socket_ref().poll_writable(cx)
    }

    fn bind_addr(&self) -> Option<SocketAddr> {
        Some(self.bind_addr)
    }

    fn rebind(&self) -> io::Result<()> {
        self.socket.as_socket_ref().rebind()
    }
}
