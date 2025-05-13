use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use netwatch::UdpSocket;
use quinn::AsyncUdpSocket;
use tracing::trace;

use super::{Addr, Transmit};
use crate::{
    magicsock::UdpConn,
    watchable::{Watchable, Watcher},
};

#[derive(Clone, Debug)]
pub(crate) struct IpTransport {
    bind_addr: SocketAddr,
    socket: UdpConn,
    local_addr: Watchable<SocketAddr>,
}

impl IpTransport {
    pub(crate) fn new(bind_addr: SocketAddr, socket: UdpConn) -> Self {
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(socket.local_addr().expect("invalid socket"));

        Self {
            bind_addr,
            socket,
            local_addr,
        }
    }

    pub(super) fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.create_io_poller()
    }

    pub(super) fn poll_send(
        &self,
        destination: SocketAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        trace!("sending to {}", destination);
        let res = self.socket.try_send(&quinn_udp::Transmit {
            destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit
                .src_ip
                .clone()
                .map(|a| a.try_into().expect("invalid src_ip")),
        });

        match res {
            Ok(res) => Poll::Ready(Ok(res)),
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        }
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    pub(super) fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        match self.socket.poll_recv(cx, bufs, metas) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                for (addr, el) in source_addrs.iter_mut().zip(metas.iter()).take(n) {
                    *addr = el.addr.into();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr.get()
    }

    pub(super) fn local_addr_watch(&self) -> impl Watcher<Value = SocketAddr> + Send {
        self.local_addr.watch()
    }

    pub(super) fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    pub(super) fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }

    pub(super) fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    pub(super) fn is_valid_send_addr(&self, addr: &SocketAddr) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match (self.bind_addr, addr) {
            (SocketAddr::V4(_), SocketAddr::V4(..)) => true,
            (SocketAddr::V6(_), SocketAddr::V6(..)) => true,
            _ => false,
        }
    }

    pub(super) fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.as_socket_ref().poll_writable(cx)
    }

    pub(crate) fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub(super) fn rebind(&self) -> io::Result<()> {
        self.socket.as_socket_ref().rebind()?;
        let addr = self.socket.as_socket_ref().local_addr()?;
        self.local_addr.set(addr).ok();

        Ok(())
    }

    pub(super) fn on_network_change(&self, _info: &crate::magicsock::NetInfo) {
        // Nothing to do for now
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        self.socket.as_socket()
    }
}
