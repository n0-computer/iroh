use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{future::poll_fn, ready, Future, FutureExt};
use quinn::AsyncUdpSocket;
use tokio::{
    io::Interest,
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock},
};
use tracing::debug;

use super::conn::Network;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no connection set")]
    NoConn,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Reports whether err is an error from a UDP send
    /// operation that should be treated as a UDP packet that just got lost.
    ///
    /// Notably, on Linux this reports true for EPERM errors (from outbound
    /// firewall blocks) which aren't really send errors; they're just
    /// sends that are never going to make it because the local OS blocked it.
    pub fn treat_as_lost_udp(&self) -> bool {
        if let Error::Io(io_err) = self {
            // Linux, while not documented in the man page,
            // returns EPERM when there's an OUTPUT rule with -j
            // DROP or -j REJECT.  We use this very specific
            // Linux+EPERM check rather than something super broad
            // like net.Error.Temporary which could be anything.
            //
            // For now we only do this on Linux, as such outgoing
            // firewall violations mapping to syscall errors
            // hasn't yet been observed on other OSes.
            if let Some(raw_os_err) = io_err.raw_os_error() {
                if raw_os_err == libc::EPERM {
                    return true;
                }
            }
        }
        false
    }
}

/// A UDP socket that can be re-bound. Unix has no notion of re-binding a socket, so we swap it out for a new one.
#[derive(Default)]
pub struct RebindingUdpConn {
    pub(super) inner: Arc<RwLock<Inner>>,
    /// Used to aquire a read lock to inner in poll functions.
    /// Sad type
    /// - std::sync::Mutex -> lock in poll methods, as poll_recv does not take &mut self, but rather &self.
    /// - Option -> it needs to be taken out/might not exist.
    /// - Box -> unameable Future
    /// - Send + Sync -> so that this struct is still Send and Sync
    /// - OwnedRwLock{Read|Write}Guard -> need 'static lifetime for the guard
    read_mutex: std::sync::Mutex<
        Option<Pin<Box<dyn Future<Output = OwnedRwLockReadGuard<Inner>> + Send + Sync + 'static>>>,
    >,
    write_mutex: std::sync::Mutex<
        Option<Pin<Box<dyn Future<Output = OwnedRwLockWriteGuard<Inner>> + Send + Sync + 'static>>>,
    >,
}

impl Debug for RebindingUdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RebindingUdpConn")
            .field("inner", &self.inner)
            .field("read_mutex", &"..")
            .field("write_mutex", &"..")
            .finish()
    }
}

#[derive(Default, Debug)]
pub(super) struct Inner {
    // TODO: evaluate which locking strategy to use
    // pconnAtomic is a pointer to the value stored in pconn, but doesn't
    // require acquiring mu. It's used for reads/writes and only upon failure
    // do the reads/writes then check pconn (after acquiring mu) to see if
    // there's been a rebind meanwhile.
    // pconn isn't really needed, but makes some of the code simpler
    // to keep it distinct.
    // Neither is expected to be nil, sockets are bound on creation.
    // pconn_atomic: atomic.Pointer[nettype.PacketConn],
    pub(super) pconn: Option<UdpSocket>,
    pub(super) port: u16,
}

impl RebindingUdpConn {
    pub async fn port(&self) -> u16 {
        self.inner.read().await.port
    }

    pub async fn close(&self) -> Result<(), Error> {
        let mut state = self.inner.write().await;
        state.close()
    }

    pub async fn send_to(&self, addr: SocketAddr, b: &[u8]) -> io::Result<bool> {
        let mut state = self.inner.write().await;
        if let Some(ref mut conn) = state.pconn {
            conn.send_to(addr, b).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no connection"))
        }
    }

    pub fn poll_send(
        &self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        let mut write_mutex = self.write_mutex.lock().unwrap();

        if write_mutex.is_none() {
            // Fast path, see if we can just grab the lock
            if let Ok(ref mut guard) = self.inner.try_write() {
                return poll_send(&mut guard.pconn, state, cx, transmits);
            }

            // Otherwise prepare a lock.
            let fut = Box::pin(self.inner.clone().write_owned());
            write_mutex.replace(fut);
        }

        // Waiting on aquiring the lock
        let mut fut = write_mutex.take().expect("just set");

        match fut.poll_unpin(cx) {
            Poll::Pending => {
                write_mutex.replace(fut);
                Poll::Pending
            }
            Poll::Ready(mut guard) => poll_send(&mut guard.pconn, state, cx, transmits),
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
            if let Ok(ref mut guard) = self.inner.try_read() {
                return poll_recv(&guard.pconn, cx, bufs, meta);
            }

            // Otherwise prepare a lock.
            let fut = Box::pin(self.inner.clone().read_owned());
            read_mutex.replace(fut);
        }

        // Waiting on aquiring the lock
        let mut fut = read_mutex.take().expect("just set");
        match fut.poll_unpin(cx) {
            Poll::Pending => {
                read_mutex.replace(fut);
                return Poll::Pending;
            }
            Poll::Ready(guard) => poll_recv(&guard.pconn, cx, bufs, meta),
        }
    }

    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        let addr = self.inner.read().await.local_addr()?;
        Ok(addr)
    }

    pub fn local_addr_blocking(&self) -> io::Result<SocketAddr> {
        let addr = tokio::task::block_in_place(|| self.inner.blocking_read()).local_addr()?;
        Ok(addr)
    }

    fn from_socket(p: UdpSocket) -> Self {
        let port = p.local_addr().map(|a| a.port()).unwrap_or_default();
        RebindingUdpConn {
            inner: Arc::new(RwLock::new(Inner {
                pconn: Some(p),
                port,
            })),
            write_mutex: Default::default(),
            read_mutex: Default::default(),
        }
    }
}

impl Inner {
    /// Sets the provided nettype.PacketConn. It should be called only
    /// after acquiring RebindingUDPConn.mu. It upgrades the provided
    /// nettype.PacketConn to a udpConnWithBatchOps when appropriate. This upgrade
    /// is intentionally pushed closest to where read/write ops occur in order to
    /// avoid disrupting surrounding code that assumes nettype.PacketConn is a *net.UDPConn.
    pub fn set_conn(&mut self, p: UdpSocket, _network: Network) {
        // upc := upgradePacketConn(p, network)
        let port = p.local_addr().expect("missing addr").port();
        self.pconn = Some(p);
        self.port = port;
    }

    pub fn close(&mut self) -> Result<(), Error> {
        match self.pconn.take() {
            Some(_pconn) => {
                self.port = 0;
                // pconn.close() is not available, so we just drop for now
                // TODO: make sure the recv loops get shutdown
                Ok(())
            }
            None => Err(Error::NoConn),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let pconn = self
            .pconn
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no connection"))?;
        pconn.local_addr()
    }
}

#[derive(Debug)]
pub(super) struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: quinn_udp::UdpSocketState,
}

impl UdpSocket {
    pub fn from_std(sock: std::net::UdpSocket) -> io::Result<Self> {
        quinn_udp::UdpSocketState::configure((&sock).into())?;
        Ok(UdpSocket {
            io: tokio::net::UdpSocket::from_std(sock)?,
            inner: quinn_udp::UdpSocketState::new(),
        })
    }

    pub async fn send_to(&mut self, addr: SocketAddr, b: &[u8]) -> io::Result<bool> {
        // TODO: store
        let state = quinn_udp::UdpState::new();
        let transmits = [quinn_proto::Transmit {
            destination: addr,
            ecn: None,
            contents: b.to_vec(),
            segment_size: None,
            src_ip: self.local_addr().ok().map(|a| a.ip()),
        }];
        let n = poll_fn(|cx| self.poll_send(&state, cx, &transmits[..])).await?;
        Ok(n > 0)
    }
}

fn poll_send(
    this: &mut Option<UdpSocket>,
    state: &quinn_udp::UdpState,
    cx: &mut Context,
    transmits: &[quinn_proto::Transmit],
) -> Poll<io::Result<usize>> {
    match this {
        Some(ref mut pconn) => pconn.poll_send(state, cx, transmits),
        None => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "no connection"))),
    }
}

fn poll_recv(
    this: &Option<UdpSocket>,
    cx: &mut Context,
    bufs: &mut [io::IoSliceMut<'_>],
    meta: &mut [quinn_udp::RecvMeta],
) -> Poll<io::Result<usize>> {
    match this {
        Some(ref pconn) => pconn.poll_recv(cx, bufs, meta),
        None => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "no connection"))),
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
                debug!("sent {:?}", res);
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
                debug!("received {:?}", res);
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }
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
        let (m1, m1_key) = wrap_socket(m1)?;

        let m2 = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let m2 = RebindingUdpConn::from_socket(UdpSocket::from_std(m2)?);
        let (m2, m2_key) = wrap_socket(m2)?;

        let m1_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), m1.local_addr()?.port());
        let m2_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), m2.local_addr()?.port());
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
