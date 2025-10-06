use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use n0_watcher::Watchable;
use netwatch::{UdpSender, UdpSocket};
use pin_project::pin_project;
use tracing::trace;

use super::{Addr, Transmit};
use crate::metrics::MagicsockMetrics;

#[derive(Debug)]
pub(crate) struct IpTransport {
    bind_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
    metrics: Arc<MagicsockMetrics>,
}

impl IpTransport {
    pub(crate) fn new(
        bind_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        metrics: Arc<MagicsockMetrics>,
    ) -> Self {
        // Currently gets updated on manual rebind
        // TODO: update when UdpSocket under the hood rebinds automatically
        let local_addr = Watchable::new(socket.local_addr().expect("invalid socket"));

        Self {
            bind_addr,
            socket,
            local_addr,
            metrics,
        }
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        match self.socket.poll_recv_quinn(cx, bufs, metas) {
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

    pub(super) fn local_addr_watch(&self) -> n0_watcher::Direct<SocketAddr> {
        self.local_addr.watch()
    }

    pub(super) fn max_transmit_segments(&self) -> usize {
        self.socket.max_gso_segments()
    }

    pub(super) fn max_receive_segments(&self) -> usize {
        self.socket.gro_segments()
    }

    pub(super) fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    pub(crate) fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub(super) fn create_network_change_sender(&self) -> IpNetworkChangeSender {
        IpNetworkChangeSender {
            socket: self.socket.clone(),
            local_addr: self.local_addr.clone(),
        }
    }

    pub(super) fn create_sender(&self) -> IpSender {
        let sender = self.socket.clone().create_sender();
        IpSender {
            bind_addr: self.bind_addr,
            sender,
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct IpNetworkChangeSender {
    socket: Arc<UdpSocket>,
    local_addr: Watchable<SocketAddr>,
}

impl IpNetworkChangeSender {
    pub(super) fn rebind(&self) -> io::Result<()> {
        let old_addr = self.local_addr.get();
        self.socket.rebind()?;
        let addr = self.socket.local_addr()?;
        self.local_addr.set(addr).ok();
        trace!("rebound from {} to {}", old_addr, addr);

        Ok(())
    }

    pub(super) fn on_network_change(&self, _info: &crate::magicsock::Report) {
        // Nothing to do for now
    }
}

#[derive(Debug)]
#[pin_project]
pub(super) struct IpSender {
    bind_addr: SocketAddr,
    #[pin]
    sender: UdpSender,
    metrics: Arc<MagicsockMetrics>,
}

impl IpSender {
    pub(super) fn is_valid_send_addr(&self, addr: &SocketAddr) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match (self.bind_addr, addr) {
            (SocketAddr::V4(_), SocketAddr::V4(..)) => true,
            (SocketAddr::V6(_), SocketAddr::V6(..)) => true,
            _ => false,
        }
    }

    pub(super) async fn send(
        &self,
        dst: SocketAddr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let total_bytes = transmit.contents.len() as u64;
        let res = self
            .sender
            .send(&quinn_udp::Transmit {
                destination: dst,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: src,
            })
            .await;

        match res {
            Ok(res) => {
                match dst {
                    SocketAddr::V4(_) => {
                        self.metrics.send_ipv4.inc_by(total_bytes);
                    }
                    SocketAddr::V6(_) => {
                        self.metrics.send_ipv6.inc_by(total_bytes);
                    }
                }
                Ok(res)
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        dst: SocketAddr,
        src: Option<IpAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let total_bytes = transmit.contents.len() as u64;
        let res = Pin::new(&mut self.sender).poll_send(
            &quinn_udp::Transmit {
                destination: dst,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: src,
            },
            cx,
        );

        match res {
            Poll::Ready(Ok(res)) => {
                match dst {
                    SocketAddr::V4(_) => {
                        self.metrics.send_ipv4.inc_by(total_bytes);
                    }
                    SocketAddr::V6(_) => {
                        self.metrics.send_ipv6.inc_by(total_bytes);
                    }
                }
                Poll::Ready(Ok(res))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}
