use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{bail, Context as _};
use netwatch::UdpSocket;
use quinn::AsyncUdpSocket;
use quinn_udp::Transmit;
use tracing::debug;

/// A UDP socket implementing Quinn's [`AsyncUdpSocket`].
#[derive(Debug, Clone)]
pub struct UdpConn {
    io: Arc<UdpSocket>,
}

impl UdpConn {
    pub(super) fn as_socket(&self) -> Arc<UdpSocket> {
        self.io.clone()
    }

    pub(super) fn as_socket_ref(&self) -> &UdpSocket {
        &self.io
    }

    pub(super) fn bind(addr: SocketAddr) -> anyhow::Result<Self> {
        let sock = bind(addr)?;

        Ok(Self { io: Arc::new(sock) })
    }

    pub fn port(&self) -> u16 {
        self.local_addr().map(|p| p.port()).unwrap_or_default()
    }

    pub(super) fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(IoPoller {
            io: self.io.clone(),
        })
    }
}

impl AsyncUdpSocket for UdpConn {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        (*self).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.io.try_send_quinn(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.io.poll_recv_quinn(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.io.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.io.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.io.gro_segments()
    }
}

fn bind(mut addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    debug!(%addr, "binding");

    // Build a list of preferred ports.
    // - Best is the port that the user requested.
    // - Second best is the port that is currently in use.
    // - If those fail, fall back to 0.

    let mut ports = Vec::new();
    if addr.port() != 0 {
        ports.push(addr.port());
    }
    // Backup port
    ports.push(0);
    // Remove duplicates. (All duplicates are consecutive.)
    ports.dedup();
    debug!(?ports, "candidate ports");

    for port in &ports {
        addr.set_port(*port);
        match UdpSocket::bind_full(addr) {
            Ok(pconn) => {
                let local_addr = pconn.local_addr().context("UDP socket not bound")?;
                debug!(%addr, %local_addr, "successfully bound");
                return Ok(pconn);
            }
            Err(err) => {
                debug!(%addr, "failed to bind: {err:#}");
                continue;
            }
        }
    }

    // Failed to bind, including on port 0 (!).
    bail!("failed to bind any ports on {:?} (tried {:?})", addr, ports);
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
