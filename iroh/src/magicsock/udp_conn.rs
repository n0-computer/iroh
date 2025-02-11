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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use iroh_base::SecretKey;
    use netwatch::IpFamily;
    use tokio::sync::mpsc;
    use tracing::{info_span, Instrument};
    use tracing_test::traced_test;

    use super::*;
    use crate::tls;

    const ALPN: &[u8] = b"n0/test/1";

    fn wrap_socket(conn: impl AsyncUdpSocket) -> Result<(quinn::Endpoint, SecretKey)> {
        let key = SecretKey::generate(rand::thread_rng());
        let quic_server_config = tls::Authentication::RawPublicKey.make_server_config(
            &key,
            vec![ALPN.to_vec()],
            false,
        )?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(conn),
            Arc::new(quinn::TokioRuntime),
        )?;

        let quic_client_config = tls::Authentication::RawPublicKey.make_client_config(
            &key,
            None,
            vec![ALPN.to_vec()],
            None,
            false,
        )?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        quic_ep.set_default_client_config(client_config);
        Ok((quic_ep, key))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rebinding_conn_send_recv_ipv4() -> Result<()> {
        rebinding_conn_send_recv(IpFamily::V4).await
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rebinding_conn_send_recv_ipv6() -> Result<()> {
        if !net_report::os_has_ipv6() {
            return Ok(());
        }
        rebinding_conn_send_recv(IpFamily::V6).await
    }

    async fn rebinding_conn_send_recv(network: IpFamily) -> Result<()> {
        let m1 = UdpConn::wrap(Arc::new(UdpSocket::bind_full(SocketAddr::new(
            network.unspecified_addr(),
            0,
        ))?));
        let (m1, _m1_key) = wrap_socket(m1)?;

        let m2 = UdpConn::wrap(Arc::new(UdpSocket::bind_full(SocketAddr::new(
            network.unspecified_addr(),
            0,
        ))?));
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
