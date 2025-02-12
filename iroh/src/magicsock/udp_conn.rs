use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use netwatch::UdpSocket;
use quinn::AsyncUdpSocket;
use quinn_udp::Transmit;

/// Wrapper struct to implement Quinn's [`AsyncUdpSocket`] for [`UdpSocket`].
#[derive(Debug, Clone)]
pub(super) struct UdpConn {
    inner: Arc<UdpSocket>,
}

impl UdpConn {
    pub(super) fn wrap(inner: Arc<UdpSocket>) -> Self {
        Self { inner }
    }

    pub(super) fn as_socket_ref(&self) -> &UdpSocket {
        &self.inner
    }

    pub(super) fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(IoPoller {
            io: self.inner.clone(),
        })
    }
}

impl AsyncUdpSocket for UdpConn {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        (*self).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send_quinn(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv_quinn(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

/// Poller for when the socket is writable.
#[derive(Debug)]
struct IoPoller {
    io: Arc<UdpSocket>,
}

impl quinn::UdpPoller for IoPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.io.poll_writable(cx)
    }
}
