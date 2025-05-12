use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use quinn::AsyncUdpSocket;
use tracing::trace;

use super::{RecvMeta, Transmit};
use crate::{
    magicsock::UdpConn,
    watchable::{Watchable, Watcher},
};

#[derive(Clone, Debug)]
pub struct IpTransport {
    bind_addr: SocketAddr,
    socket: UdpConn,
    local_addr: Watchable<Option<SocketAddr>>,
}

impl IpTransport {
    pub fn new(bind_addr: SocketAddr, socket: UdpConn) -> Self {
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(socket.local_addr().ok());

        Self {
            bind_addr,
            socket,
            local_addr,
        }
    }

    pub fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.create_io_poller()
    }

    pub fn poll_send(
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
    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // TODO: figure out how to optimize this
        let mut quinn_metas = vec![quinn_udp::RecvMeta::default(); metas.len()];
        match self.socket.poll_recv(cx, bufs, &mut quinn_metas) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => {
                for (quinn_meta, meta) in quinn_metas.into_iter().zip(metas.iter_mut()) {
                    meta.addr = quinn_meta.addr.into();
                    meta.len = quinn_meta.len;
                    meta.stride = quinn_meta.stride;
                    meta.ecn = quinn_meta.ecn;
                    meta.dst_ip = quinn_meta.dst_ip.map(Into::into);
                }
                Poll::Ready(res)
            }
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get()
    }

    pub fn local_addr_watch(&self) -> impl Watcher<Value = Option<SocketAddr>> + Send {
        self.local_addr.watch()
    }

    pub fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    pub fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }

    pub fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    pub fn is_valid_send_addr(&self, addr: &SocketAddr) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match (self.bind_addr, addr) {
            (SocketAddr::V4(_), SocketAddr::V4(..)) => true,
            (SocketAddr::V6(_), SocketAddr::V6(..)) => true,
            _ => false,
        }
    }

    pub fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.as_socket_ref().poll_writable(cx)
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn rebind(&self) -> io::Result<()> {
        self.socket.as_socket_ref().rebind()?;
        let addr = self.socket.as_socket_ref().local_addr()?;
        self.local_addr.set(Some(addr.into())).ok();

        Ok(())
    }

    pub fn on_network_change(&self, _info: &crate::magicsock::NetInfo) {
        // Nothing to do for now
    }
}
