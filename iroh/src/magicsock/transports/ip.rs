use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use quinn::AsyncUdpSocket;

use super::Transport;
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

impl AsyncUdpSocket for IpTransport {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.create_io_poller()
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.socket.try_send(transmit)
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_recv(cx, bufs, metas)
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
}

impl Transport for IpTransport {
    fn is_valid_send_addr(&self, addr: SocketAddr) -> bool {
        self.bind_addr.ip() == addr.ip()
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.as_socket_ref().poll_writable(cx)
    }

    fn create_self_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.create_io_poller()
    }

    fn bind_addr(&self) -> Option<SocketAddr> {
        Some(self.bind_addr)
    }

    fn rebind(&self) -> io::Result<()> {
        self.socket.as_socket_ref().rebind()
    }
}
