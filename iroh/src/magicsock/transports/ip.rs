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

    fn poll_send(&self, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        let res = self.socket.try_send(&quinn_udp::Transmit {
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
    fn poll_recv(
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

    fn on_network_change(&self, _info: &crate::magicsock::NetInfo) {
        // Nothing to do for now
    }
}
