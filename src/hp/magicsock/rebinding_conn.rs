use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::bail;
use futures::ready;
use quinn::AsyncUdpSocket;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::conn::{CurrentPortFate, Network};
use crate::hp::magicsock::SOCKET_BUFFER_SIZE;

/// A UDP socket that can be re-bound. Unix has no notion of re-binding a socket, so we swap it out for a new one.
#[derive(Clone, Debug)]
pub struct RebindingUdpConn {
    io: Arc<tokio::net::UdpSocket>,
    state: Arc<quinn_udp::UdpSocketState>,
}

impl RebindingUdpConn {
    pub(super) fn as_socket(&self) -> Arc<tokio::net::UdpSocket> {
        self.io.clone()
    }

    pub(super) async fn rebind(
        &mut self,
        port: u16,
        network: Network,
        cur_port_fate: CurrentPortFate,
    ) -> anyhow::Result<()> {
        // Do not bother rebinding if we are keeping the port.
        if self.port() == port && cur_port_fate == CurrentPortFate::Keep {
            return Ok(());
        }

        let sock = bind(Some(&self.io), port, network, cur_port_fate).await?;
        self.io = Arc::new(tokio::net::UdpSocket::from_std(sock)?);
        self.state = Default::default();

        Ok(())
    }

    pub(super) async fn bind(port: u16, network: Network) -> anyhow::Result<Self> {
        let sock = bind(None, port, network, CurrentPortFate::Keep).await?;
        Ok(Self {
            io: Arc::new(tokio::net::UdpSocket::from_std(sock)?),
            state: Default::default(),
        })
    }

    pub fn port(&self) -> u16 {
        self.local_addr().map(|p| p.port()).unwrap_or_default()
    }

    pub async fn close(&self) -> Result<(), io::Error> {
        // Nothing to do atm
        Ok(())
    }
}

impl AsyncUdpSocket for RebindingUdpConn {
    fn poll_send(
        &self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        let inner = &self.state;
        let io = &self.io;
        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                inner.send(io.into(), state, transmits)
            }) {
                for t in transmits.iter().take(res) {
                    trace!(
                        "[UDP] -> {} src: {:?} ({}b)",
                        t.destination,
                        t.src_ip,
                        t.contents.len()
                    );
                }

                return Poll::Ready(Ok(res));
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
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                for meta in meta.iter().take(res) {
                    trace!(
                        "[UDP] <- {} dest: {:?} ({}b)",
                        meta.addr,
                        meta.dst_ip,
                        meta.len
                    );
                }

                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

async fn bind(
    inner: Option<&tokio::net::UdpSocket>,
    port: u16,
    network: Network,
    cur_port_fate: CurrentPortFate,
) -> anyhow::Result<std::net::UdpSocket> {
    debug!(
        "bind_socket: network={:?} cur_port_fate={:?}",
        network, cur_port_fate
    );

    // Build a list of preferred ports.
    // - Best is the port that the user requested.
    // - Second best is the port that is currently in use.
    // - If those fail, fall back to 0.

    let mut ports = Vec::new();
    if port != 0 {
        ports.push(port);
    }
    if cur_port_fate == CurrentPortFate::Keep {
        if let Some(cur_addr) = inner.as_ref().and_then(|i| i.local_addr().ok()) {
            ports.push(cur_addr.port());
        }
    }
    // Backup port
    ports.push(0);
    // Remove duplicates. (All duplicates are consecutive.)
    ports.dedup();
    debug!("bind_socket: candidate ports: {:?}", ports);

    for port in &ports {
        // Close the existing conn, in case it is sitting on the port we want.
        if let Some(_inner) = inner {
            // TODO: inner.close()
        }
        // Open a new one with the desired port.
        match listen_packet(network, *port).await {
            Ok(pconn) => {
                debug!(
                    "bind_socket: successfully listened {:?} port {}",
                    network, port
                );
                return Ok(pconn);
            }
            Err(err) => {
                warn!(
                    "bind_socket: unable to bind {:?} port {}: {:?}",
                    network, port, err
                );
                continue;
            }
        }
    }

    // Failed to bind, including on port 0 (!).
    bail!("failed to bind any ports (tried {:?})", ports);
}

/// Opens a packet listener.
async fn listen_packet(network: Network, port: u16) -> std::io::Result<std::net::UdpSocket> {
    let addr = SocketAddr::new(network.default_addr(), port);
    let socket = socket2::Socket::new(
        network.into(),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
        warn!(
            "failed to set recv_buffer_size to {}: {:?}",
            SOCKET_BUFFER_SIZE, err
        );
    }
    if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
        warn!(
            "failed to set send_buffer_size to {}: {:?}",
            SOCKET_BUFFER_SIZE, err
        );
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let socket: std::net::UdpSocket = socket.into();

    quinn_udp::UdpSocketState::configure((&socket).into())?;

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use crate::{hp::key, tls};

    use super::*;
    use anyhow::Result;

    fn wrap_socket(conn: impl AsyncUdpSocket) -> Result<(quinn::Endpoint, key::node::SecretKey)> {
        let key = key::node::SecretKey::generate();
        let tls_server_config =
            tls::make_server_config(&key.clone().into(), vec![tls::P2P_ALPN.to_vec()], false)?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
        let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            conn,
            Arc::new(quinn::TokioRuntime),
        )?;

        let tls_client_config = tls::make_client_config(
            &key.clone().into(),
            None,
            vec![tls::P2P_ALPN.to_vec()],
            false,
        )?;
        let client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
        quic_ep.set_default_client_config(client_config);
        Ok((quic_ep, key))
    }

    #[tokio::test]
    async fn test_rebinding_conn_send_recv() -> Result<()> {
        let m1 = RebindingUdpConn::bind(0, Network::Ipv4).await?;
        let (m1, _m1_key) = wrap_socket(m1)?;

        let m2 = RebindingUdpConn::bind(0, Network::Ipv6).await?;
        let (m2, _m2_key) = wrap_socket(m2)?;

        let m1_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), m1.local_addr()?.port());
        let (m1_send, m1_recv) = flume::bounded(8);

        let m1_task = tokio::task::spawn(async move {
            if let Some(conn) = m1.accept().await {
                let conn = conn.await?;
                let (mut send_bi, mut recv_bi) = conn.accept_bi().await?;

                let val = recv_bi.read_to_end(usize::MAX).await?;
                m1_send.send_async(val).await?;
                send_bi.finish().await?;
            }

            Ok::<_, anyhow::Error>(())
        });

        let conn = m2.connect(m1_addr, "localhost")?.await?;

        let (mut send_bi, mut recv_bi) = conn.open_bi().await?;
        send_bi.write_all(b"hello").await?;
        send_bi.finish().await?;

        let _ = recv_bi.read_to_end(usize::MAX).await?;
        conn.close(0u32.into(), b"done");
        m2.wait_idle().await;

        drop(send_bi);

        // make sure the right values arrived
        let val = m1_recv.recv_async().await?;
        assert_eq!(val, b"hello");

        m1_task.await??;

        Ok(())
    }
}
