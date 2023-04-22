use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::bail;
use futures::{ready, Future, FutureExt};
use quinn::AsyncUdpSocket;
use tokio::{
    io::Interest,
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock},
};
use tracing::{debug, info};

use super::conn::{CurrentPortFate, Network};
use crate::hp::magicsock::SOCKET_BUFFER_SIZE;

/// A UDP socket that can be re-bound. Unix has no notion of re-binding a socket, so we swap it out for a new one.
#[derive(Clone)]
pub struct RebindingUdpConn {
    pub(super) pconn: Arc<RwLock<UdpSocket>>,

    /// Used to aquire a read lock to inner in poll functions.
    /// Sad type
    /// - std::sync::Mutex -> lock in poll methods, as poll_recv does not take &mut self, but rather &self.
    /// - Option -> it needs to be taken out/might not exist.
    /// - Box -> unameable Future
    /// - Send + Sync -> so that this struct is still Send and Sync
    /// - OwnedRwLock{Read|Write}Guard -> need 'static lifetime for the guard
    read_mutex: Arc<
        std::sync::Mutex<
            Option<
                Pin<
                    Box<
                        dyn Future<Output = OwnedRwLockReadGuard<UdpSocket>>
                            + Send
                            + Sync
                            + 'static,
                    >,
                >,
            >,
        >,
    >,
    write_mutex: Arc<
        std::sync::Mutex<
            Option<
                Pin<
                    Box<
                        dyn Future<Output = OwnedRwLockWriteGuard<UdpSocket>>
                            + Send
                            + Sync
                            + 'static,
                    >,
                >,
            >,
        >,
    >,
}

impl Debug for RebindingUdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RebindingUdpConn")
            .field("pconn", &self.pconn)
            .field("read_mutex", &"..")
            .field("write_mutex", &"..")
            .finish()
    }
}

impl RebindingUdpConn {
    pub(super) fn as_socket(&self) -> Arc<tokio::net::UdpSocket> {
        let pconn = tokio::task::block_in_place(|| (self.pconn.blocking_read()));

        pconn.io.clone()
    }

    pub(super) async fn rebind(
        &self,
        port: u16,
        network: Network,
        cur_port_fate: CurrentPortFate,
    ) -> anyhow::Result<()> {
        // Do not bother rebinding if we are keeping the port.
        if self.port().await == port && cur_port_fate == CurrentPortFate::Keep {
            return Ok(());
        }

        // Hold the lock the entire time, so that the close+bind is atomic.
        let mut inner = self.pconn.write().await;
        let pconn = bind(Some(&mut inner), port, network, cur_port_fate).await?;
        *inner = pconn;
        Ok(())
    }

    pub(super) async fn bind(port: u16, network: Network) -> anyhow::Result<Self> {
        let pconn = bind(None, port, network, CurrentPortFate::Keep).await?;

        Ok(Self::from_socket(pconn))
    }

    pub async fn port(&self) -> u16 {
        self.pconn
            .read()
            .await
            .local_addr()
            .map(|p| p.port())
            .unwrap_or_default()
    }

    pub async fn close(&self) -> Result<(), io::Error> {
        // Nothing to do atm
        Ok(())
    }

    pub fn poll_send(
        &self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        let mut writemutex = self.write_mutex.lock().unwrap();

        if writemutex.is_none() {
            // Fast path, see if we can just grab the lock
            if let Ok(ref mut pconn) = self.pconn.try_write() {
                return pconn.poll_send(state, cx, transmits);
            }

            // Otherwise prepare a lock.
            let fut = Box::pin(self.pconn.clone().write_owned());
            writemutex.replace(fut);
        }

        // Waiting on aquiring the lock
        let mut fut = writemutex.take().expect("just set");

        match fut.poll_unpin(cx) {
            Poll::Pending => {
                writemutex.replace(fut);
                Poll::Pending
            }
            Poll::Ready(mut pconn) => pconn.poll_send(state, cx, transmits),
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut read_mutex = self.read_mutex.lock().unwrap();

        if read_mutex.is_none() {
            // Fast path, see if we can just grab the lock
            if let Ok(ref mut pconn) = self.pconn.try_read() {
                return pconn.poll_recv(cx, bufs, meta);
            }

            // Otherwise prepare a lock.
            let fut = Box::pin(self.pconn.clone().read_owned());
            read_mutex.replace(fut);
        }

        // Waiting on aquiring the lock
        let mut fut = read_mutex.take().expect("just set");
        match fut.poll_unpin(cx) {
            Poll::Pending => {
                read_mutex.replace(fut);
                return Poll::Pending;
            }
            Poll::Ready(pconn) => pconn.poll_recv(cx, bufs, meta),
        }
    }

    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        let addr = self.pconn.read().await.local_addr()?;
        Ok(addr)
    }

    pub fn local_addr_blocking(&self) -> io::Result<SocketAddr> {
        let addr = tokio::task::block_in_place(|| self.pconn.blocking_read()).local_addr()?;
        Ok(addr)
    }

    pub(super) fn from_socket(pconn: UdpSocket) -> Self {
        RebindingUdpConn {
            pconn: Arc::new(RwLock::new(pconn)),
            read_mutex: Default::default(),
            write_mutex: Default::default(),
        }
    }
}

#[derive(Debug)]
pub(super) struct UdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: quinn_udp::UdpSocketState,
}

impl UdpSocket {
    pub fn from_std(sock: std::net::UdpSocket) -> io::Result<Self> {
        quinn_udp::UdpSocketState::configure((&sock).into())?;
        Ok(UdpSocket {
            io: Arc::new(tokio::net::UdpSocket::from_std(sock)?),
            inner: quinn_udp::UdpSocketState::new(),
        })
    }
}

impl AsyncUdpSocket for RebindingUdpConn {
    fn poll_send(
        &mut self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        (&*self).poll_send(state, cx, transmits)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr_blocking()
    }
}

impl AsyncUdpSocket for UdpSocket {
    fn poll_send(
        &mut self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        debug!(
            "sending {:?} transmits",
            transmits
                .iter()
                .map(|t| format!("dest: {:?}, bytes: {}", t.destination, t.contents.len()))
                .collect::<Vec<_>>()
        );

        let inner = &mut self.inner;
        let io = &self.io;
        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                inner.send(io.into(), state, transmits)
            }) {
                for t in transmits.iter().take(res) {
                    debug!("[UDP] -> {} ({}b)", t.destination, t.contents.len());
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
        debug!("trying to recv {}: {:?}", bufs.len(), meta.len());

        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                for meta in meta.iter().take(res) {
                    debug!("[UDP] <- {} ({}b)", meta.addr, meta.len);
                }

                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }
}

async fn bind(
    mut inner: Option<&mut UdpSocket>,
    port: u16,
    network: Network,
    cur_port_fate: CurrentPortFate,
) -> anyhow::Result<UdpSocket> {
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
        if let Some(ref mut _inner) = inner {
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
                info!(
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
async fn listen_packet(network: Network, port: u16) -> std::io::Result<UdpSocket> {
    let addr = SocketAddr::new(network.default_addr(), port);
    let socket = socket2::Socket::new(
        network.into(),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
        info!(
            "failed to set recv_buffer_size to {}: {:?}",
            SOCKET_BUFFER_SIZE, err
        );
    }
    if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
        info!(
            "failed to set send_buffer_size to {}: {:?}",
            SOCKET_BUFFER_SIZE, err
        );
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let socket = UdpSocket::from_std(socket.into())?;

    debug!("bound to {}", socket.local_addr()?);

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
            quinn::TokioRuntime,
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rebinding_conn_send_recv() -> Result<()> {
        let m1 = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let m1 = RebindingUdpConn::from_socket(UdpSocket::from_std(m1)?);
        let (m1, _m1_key) = wrap_socket(m1)?;

        let m2 = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let m2 = RebindingUdpConn::from_socket(UdpSocket::from_std(m2)?);
        let (m2, _m2_key) = wrap_socket(m2)?;

        let m1_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), m1.local_addr()?.port());
        let (m1_send, m1_recv) = flume::bounded(8);

        let m1_task = tokio::task::spawn(async move {
            while let Some(conn) = m1.accept().await {
                let conn = conn.await?;
                let (mut send_bi, recv_bi) = conn.accept_bi().await?;

                let val = recv_bi.read_to_end(usize::MAX).await?;
                m1_send.send_async(val).await?;
                send_bi.finish().await?;
                break;
            }

            Ok::<_, anyhow::Error>(())
        });

        let conn = m2.connect(m1_addr, "localhost")?.await?;

        let (mut send_bi, recv_bi) = conn.open_bi().await?;
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
