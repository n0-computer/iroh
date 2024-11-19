use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use anyhow::{bail, Context as _};
use netwatch::UdpSocket;
use quinn::AsyncUdpSocket;
use quinn_udp::{Transmit, UdpSockRef};
use tokio::io::Interest;
use tracing::{debug, trace, warn};

/// A UDP socket implementing Quinn's [`AsyncUdpSocket`].
#[derive(Debug)]
pub struct UdpConn {
    io: Arc<UdpSocket>,
    inner: RwLock<quinn_udp::UdpSocketState>,
}

impl UdpConn {
    pub(super) fn as_socket(&self) -> Arc<UdpSocket> {
        self.io.clone()
    }

    pub(super) fn bind(addr: SocketAddr) -> anyhow::Result<Self> {
        let sock = bind(addr)?;
        let state = sock.with_socket(|socket| {
            quinn_udp::UdpSocketState::new(quinn_udp::UdpSockRef::from(socket))
        })?;

        Ok(Self {
            io: Arc::new(sock),
            inner: RwLock::new(state),
        })
    }

    pub(super) fn rebind(&self) -> anyhow::Result<()> {
        // Rebind underlying socket
        self.io.rebind()?;

        // update socket state
        let new_state = self.io.with_socket(|socket| {
            quinn_udp::UdpSocketState::new(quinn_udp::UdpSockRef::from(socket))
        })?;
        *self.inner.write().unwrap() = new_state;
        Ok(())
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
        (&*self).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        loop {
            if self.io.is_broken() {
                match self.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Err(err);
                    }
                }
            }

            let res = self.io.try_io(Interest::WRITABLE, || {
                self.io.with_socket(|io| {
                    let sock_ref = UdpSockRef::from(io);
                    self.inner.read().unwrap().send(sock_ref, transmit)
                })
            });
            match res {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    match self.io.handle_write_error(err) {
                        Some(err) => return Err(err),
                        None => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            if self.io.is_broken() {
                match self.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::NotConnected, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }

            match self.io.with_socket(|io| io.poll_recv_ready(cx)) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => match self.io.handle_read_error(err) {
                    Some(err) => return Poll::Ready(Err(err)),
                    None => {
                        continue;
                    }
                },
            }

            let res = self.io.try_io(Interest::READABLE, || {
                self.io
                    .with_socket(|io| self.inner.read().unwrap().recv(io.into(), bufs, meta))
            });
            match res {
                Ok(count) => {
                    for meta in meta.iter().take(count) {
                        trace!(
                            src = %meta.addr,
                            len = meta.len,
                            count = meta.len / meta.stride,
                            dst = %meta.dst_ip.map(|x| x.to_string()).unwrap_or_default(),
                            "UDP recv"
                        );
                    }
                    return Poll::Ready(Ok(count));
                }
                Err(err) => {
                    // ignore spurious wakeups
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    match self.io.handle_read_error(err) {
                        Some(err) => return Poll::Ready(Err(err)),
                        None => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.read().unwrap().may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.read().unwrap().max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.read().unwrap().gro_segments()
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use netwatch::IpFamily;
    use tokio::sync::mpsc;
    use tracing::{info_span, Instrument};

    use super::*;
    use crate::{key, tls};

    const ALPN: &[u8] = b"n0/test/1";

    fn wrap_socket(conn: impl AsyncUdpSocket) -> Result<(quinn::Endpoint, key::SecretKey)> {
        let key = key::SecretKey::generate();
        let quic_server_config = tls::make_server_config(&key, vec![ALPN.to_vec()], false)?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(conn),
            Arc::new(quinn::TokioRuntime),
        )?;

        let quic_client_config = tls::make_client_config(&key, None, vec![ALPN.to_vec()], false)?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        quic_ep.set_default_client_config(client_config);
        Ok((quic_ep, key))
    }

    #[tokio::test]
    async fn test_rebinding_conn_send_recv_ipv4() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        rebinding_conn_send_recv(IpFamily::V4).await
    }

    #[tokio::test]
    async fn test_rebinding_conn_send_recv_ipv6() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        if !net_report::os_has_ipv6() {
            return Ok(());
        }
        rebinding_conn_send_recv(IpFamily::V6).await
    }

    async fn rebinding_conn_send_recv(network: IpFamily) -> Result<()> {
        let m1 = UdpConn::bind(SocketAddr::new(network.unspecified_addr(), 0))?;
        let (m1, _m1_key) = wrap_socket(m1)?;

        let m2 = UdpConn::bind(SocketAddr::new(network.unspecified_addr(), 0))?;
        let (m2, _m2_key) = wrap_socket(m2)?;

        let m1_addr = SocketAddr::new(network.local_addr(), m1.local_addr()?.port());
        let (m1_send, mut m1_recv) = mpsc::channel(8);

        let m1_task = tokio::task::spawn(
            async move {
                // we skip accept() errors, they can be caused by retransmits
                if let Some(conn) = m1.accept().await.and_then(|inc| inc.accept().ok()) {
                    let conn = conn.await?;
                    let (mut send_bi, mut recv_bi) = conn.accept_bi().await?;

                    let val = recv_bi.read_to_end(usize::MAX).await?;
                    m1_send.send(val).await?;
                    send_bi.finish()?;
                    send_bi.stopped().await?;
                }

                Ok::<_, anyhow::Error>(())
            }
            .instrument(info_span!("m1_task")),
        );

        let conn = m2.connect(m1_addr, "localhost")?.await?;

        let (mut send_bi, mut recv_bi) = conn.open_bi().await?;
        send_bi.write_all(b"hello").await?;
        send_bi.finish()?;

        let _ = recv_bi.read_to_end(usize::MAX).await?;
        conn.close(0u32.into(), b"done");
        m2.wait_idle().await;

        drop(send_bi);

        // make sure the right values arrived
        let val = m1_recv.recv().await.unwrap();
        assert_eq!(val, b"hello");

        m1_task.await??;

        Ok(())
    }
}
