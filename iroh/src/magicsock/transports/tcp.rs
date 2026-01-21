//! TCP transport

#![allow(missing_docs)]

use std::{
    collections::{HashMap, VecDeque, hash_map},
    io::{self},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use iroh_base::UserAddr;
use n0_future::boxed::BoxFuture;
use n0_watcher::Watchable;
use smallvec::SmallVec;
use tokio::net::{TcpSocket, TcpStream};
use tracing::{debug, trace};

use super::{Addr, Transmit};
use crate::{
    endpoint::transports::{UserEndpoint, UserSender, UserTransport},
    magicsock::transports::tcp::addr::{from_user_addr, to_user_addr},
};

/// "tcp"
pub const TCP_TRANSPORT_ID: u64 = 0x746370;

/// Maximum size of the send buffer before backpressure is applied.
const SEND_BUF_SIZE: usize = 64 * 1024;

/// A TCP-based transport for iroh endpoints.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    bind_addr: SocketAddr,
}

impl TcpTransport {
    /// Create a new TCP transport that will bind to the given address.
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }
}

impl UserTransport for TcpTransport {
    fn bind(&self) -> io::Result<Box<dyn UserEndpoint>> {
        let listener = std::net::TcpListener::bind(self.bind_addr)?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let local_addr = listener.local_addr()?;
        debug!(%local_addr, "TCP transport bound");
        let user_addr = to_user_addr(local_addr);
        let addr_watcher = Watchable::new(vec![user_addr]);
        let conns = Default::default();
        Ok(Box::new(TcpEndpoint {
            listener,
            addr_watcher,
            conns,
        }))
    }
}

#[derive(Debug)]
struct TcpEndpoint {
    listener: tokio::net::TcpListener,
    addr_watcher: Watchable<Vec<UserAddr>>,
    conns: Arc<Mutex<Conns>>,
}

impl UserEndpoint for TcpEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<UserAddr>> {
        self.addr_watcher.watch()
    }

    fn create_sender(&self) -> Arc<dyn UserSender> {
        Arc::new(TcpSender {
            conns: self.conns.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        // Poll listener for new connections
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, addr))) => {
                    debug!(%addr, "TCP accepted new connection");
                    let mut conns = self.conns.lock().expect("poisoned");
                    conns.map.insert(addr, TcpConn::from_stream(stream));
                }
                Poll::Ready(Err(e)) => {
                    debug!(?e, "TCP accept error");
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => break,
            }
        }

        // Poll all connections for data and flush send buffers
        let mut num_packets = 0;
        let mut conns = self.conns.lock().expect("poisoned");
        let mut to_remove = SmallVec::<[_; 4]>::new();
        // TODO: Add randomization for more fairness?
        for (addr, conn) in conns.map.iter_mut() {
            // Flush send buffer on every poll_recv to ensure queued data gets sent
            if let Err(e) = conn.poll_flush(cx) {
                debug!(%addr, ?e, "TCP connection flush error, removing");
                to_remove.push(*addr);
                continue;
            }

            if num_packets >= bufs.len() {
                continue;
            }

            match conn.poll_recv_packet(cx) {
                Poll::Ready(Ok((packet, stride))) => {
                    let dst = &mut bufs[num_packets];
                    let len = packet.len().min(dst.len());
                    dst[..len].copy_from_slice(&packet[..len]);
                    trace!(%addr, len, stride, "TCP recv packet");

                    let meta = &mut metas[num_packets];
                    meta.len = len;
                    meta.stride = stride;
                    meta.ecn = None;
                    meta.dst_ip = None;

                    source_addrs[num_packets] = Addr::User(to_user_addr(*addr));
                    num_packets += 1;
                }
                Poll::Ready(Err(e)) => {
                    debug!(%addr, ?e, "TCP connection error, removing");
                    to_remove.push(*addr);
                }
                Poll::Pending => {
                    trace!(%addr, recv_buf_len = conn.recv_buf.len(), "TCP recv pending");
                }
            }
        }

        // Remove failed connections
        for addr in to_remove {
            conns.map.remove(&addr);
        }

        if num_packets > 0 {
            Poll::Ready(Ok(num_packets))
        } else {
            conns.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Debug)]
struct TcpSender {
    conns: Arc<Mutex<Conns>>,
}

impl UserSender for TcpSender {
    fn is_valid_send_addr(&self, addr: &UserAddr) -> bool {
        addr.id() == TCP_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: UserAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(dst) = from_user_addr(&dst) else {
            debug!(?dst, "TCP invalid destination address");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tcp dst addr",
            )));
        };
        let mut conns = self.conns.lock().expect("poisoned");
        let conn = conns.get(dst)?;
        let res = conn.poll_send(transmit, cx);
        if let Poll::Ready(Ok(())) = &res {
            trace!(%dst, len = transmit.contents.len(), "TCP send packet");
        }
        res
    }
}

#[derive(Debug, Default)]
struct Conns {
    map: HashMap<SocketAddr, TcpConn>,
    waker: Option<Waker>,
}

impl Conns {
    fn get(&mut self, dst: SocketAddr) -> io::Result<&mut TcpConn> {
        match self.map.entry(dst) {
            hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            hash_map::Entry::Vacant(e) => {
                debug!(%dst, "TCP initiating new outgoing connection");
                let conn = TcpConn::bind(dst)?;
                if let Some(waker) = self.waker.take() {
                    waker.wake();
                }
                Ok(e.insert(conn))
            }
        }
    }
}

#[derive(derive_more::Debug)]
struct TcpConn {
    state: SocketState,
    #[debug(skip)]
    recv_buf: BytesMut,
    /// Buffer for outgoing framed packets (length prefix + payload).
    #[debug(skip)]
    send_buf: BytesMut,
    /// Wakers for senders waiting for send capacity.
    #[debug(skip)]
    send_wakers: VecDeque<Waker>,
}

impl TcpConn {
    fn bind(dst: SocketAddr) -> io::Result<Self> {
        let socket = match dst.is_ipv4() {
            true => TcpSocket::new_v4()?,
            false => TcpSocket::new_v6()?,
        };
        let fut = socket.connect(dst);
        let state = SocketState::Connecting(Box::pin(fut));
        Ok(Self {
            state,
            recv_buf: BytesMut::new(),
            send_buf: BytesMut::new(),
            send_wakers: VecDeque::new(),
        })
    }

    fn from_stream(stream: TcpStream) -> Self {
        Self {
            state: SocketState::Ready(stream),
            recv_buf: BytesMut::new(),
            send_buf: BytesMut::new(),
            send_wakers: VecDeque::new(),
        }
    }

    /// Polls to send a transmit.
    ///
    /// Once the transmit is queued into the send buffer, returns `Poll::Ready(Ok(()))`.
    /// The caller must not retry with the same transmit after `Ready` is returned.
    ///
    /// Returns `Poll::Pending` if the send buffer is full and cannot accept new data.
    /// In this case, the sender's waker is stored and will be woken when there's capacity.
    fn poll_send(&mut self, transmit: &Transmit<'_>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First, try to flush any pending data
        self.poll_flush(cx)?;

        // Header: len (u32) + segment_size (u16) = 6 bytes
        let transmit_size = 6 + transmit.contents.len();
        if self.send_buf.len() + transmit_size > SEND_BUF_SIZE {
            // Buffer is too full, store sender's waker and return Pending
            self.send_wakers.push_back(cx.waker().clone());
            return Poll::Pending;
        }

        // Queue the transmit: len (u32) | segment_size (u16, 0 = None) | data
        self.send_buf.put_u32(transmit.contents.len() as u32);
        self.send_buf
            .put_u16(transmit.segment_size.unwrap_or(0) as u16);
        self.send_buf.extend_from_slice(transmit.contents);

        // Try to flush immediately
        self.poll_flush(cx)?;

        // Return Ready: the transmit is queued, caller should not retry.
        Poll::Ready(Ok(()))
    }

    /// Try to flush send_buf to the socket. Wakes waiting senders when buffer has capacity.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let had_data = self.send_buf.has_remaining();
        while self.send_buf.has_remaining() {
            match self.state.poll_send_buf(cx, &mut self.send_buf)? {
                Poll::Ready(0) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
                }
                Poll::Ready(_n) => {}
                Poll::Pending => break,
            }
        }
        // If we made progress, wake senders waiting for capacity
        if had_data && self.send_buf.len() < SEND_BUF_SIZE {
            while let Some(waker) = self.send_wakers.pop_front() {
                waker.wake();
            }
        }
        Ok(())
    }

    /// Polls for a complete packet from this connection.
    /// Returns (data, stride) where stride is the segment size for GSO.
    fn poll_recv_packet(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<(Bytes, usize)>> {
        loop {
            if let Some((packet, stride)) = self.try_extract_packet() {
                trace!(len = packet.len(), stride, "TCP extracted buffered packet");
                return Poll::Ready(Ok((packet.freeze(), stride)));
            }
            let n = ready!(self.state.poll_recv_buf(cx, &mut self.recv_buf))?;
            trace!(n, recv_buf_len = self.recv_buf.len(), "TCP read bytes");
        }
    }

    /// Try to extract a complete packet from recv_buf.
    /// Returns (data, stride) or None if not enough data is available.
    fn try_extract_packet(&mut self) -> Option<(BytesMut, usize)> {
        // Header: len (u32) + segment_size (u16) = 6 bytes
        if self.recv_buf.remaining() < 6 {
            return None;
        }

        // Peek at the header (don't consume yet)
        let len = (&self.recv_buf[..4]).get_u32() as usize;
        let segment_size = (&self.recv_buf[4..6]).get_u16() as usize;

        // Check if we have the full packet
        if self.recv_buf.remaining() < 6 + len {
            return None;
        }

        // Consume the header and extract the packet
        self.recv_buf.advance(6);
        let packet = self.recv_buf.split_to(len);

        // stride = segment_size if set, otherwise the full packet length
        let stride = if segment_size > 0 { segment_size } else { len };

        trace!(
            extracted_len = packet.len(),
            stride,
            remaining = self.recv_buf.remaining(),
            "TCP extracted packet"
        );
        Some((packet, stride))
    }
}

#[derive(derive_more::Debug)]
enum SocketState {
    #[debug("Connecting")]
    Connecting(BoxFuture<io::Result<TcpStream>>),
    Ready(TcpStream),
    Failed(io::Error),
}

impl SocketState {
    /// Polls to write from a buffer. Advances the buffer by the number of bytes written.
    fn poll_send_buf(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl Buf,
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_connected(cx))?;
        let stream = self.as_ready();
        tokio_util::io::poll_write_buf(Pin::new(stream), cx, buf)
    }

    fn poll_recv_buf(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl BufMut,
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_connected(cx))?;
        let stream = self.as_ready();
        match ready!(tokio_util::io::poll_read_buf(Pin::new(stream), cx, buf))? {
            0 => Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, ""))),
            n => Poll::Ready(Ok(n)),
        }
    }

    /// Panics if not [`SocketState::Ready`].
    ///
    /// Call only after [`Self::poll_connected`] returned [`Poll::Ready`]
    fn as_ready(&mut self) -> &mut TcpStream {
        match self {
            SocketState::Ready(tcp_stream) => tcp_stream,
            _ => panic!("SocketState::as_ready called but socket is not ready"),
        }
    }

    fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Connecting(fut) => match ready!(fut.as_mut().poll(cx)) {
                Ok(stream) => {
                    *self = Self::Ready(stream);
                    Poll::Ready(Ok(()))
                }
                Err(err) => {
                    *self = Self::Failed(clone_io_err(&err));
                    Poll::Ready(Err(err))
                }
            },
            Self::Failed(err) => Poll::Ready(Err(clone_io_err(err))),
            Self::Ready(_) => Poll::Ready(Ok(())),
        }
    }
}

fn clone_io_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), "broken")
}

pub mod addr {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    use iroh_base::UserAddr;

    use crate::magicsock::transports::tcp::TCP_TRANSPORT_ID;

    fn to_bytes(addr: SocketAddr) -> [u8; 18] {
        let ip = match addr.ip() {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        };

        let mut out = [0u8; 18];
        out[..16].copy_from_slice(&ip.octets());
        out[16..].copy_from_slice(&addr.port().to_be_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<SocketAddr> {
        if bytes.len() != 18 {
            None
        } else {
            let ip = Ipv6Addr::from_octets(bytes[..16].try_into().unwrap());
            let ip = ip.to_canonical();
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Some((ip, port).into())
        }
    }

    pub fn to_user_addr(addr: SocketAddr) -> UserAddr {
        UserAddr::from_parts(TCP_TRANSPORT_ID, &to_bytes(addr))
    }

    pub fn from_user_addr(addr: &UserAddr) -> Option<SocketAddr> {
        (addr.id() == TCP_TRANSPORT_ID).then(|| from_bytes(addr.data()))?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iroh_base::SecretKey;
    use tracing::info;

    use super::*;
    use crate::{Endpoint, EndpointAddr, TransportAddr, protocol::Router};

    const ALPN: &[u8] = b"iroh-test/tcp-echo/0";

    #[derive(Debug, Clone)]
    struct Echo;

    impl crate::protocol::ProtocolHandler for Echo {
        async fn accept(
            &self,
            connection: crate::endpoint::Connection,
        ) -> Result<(), crate::protocol::AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn tcp_transport_echo() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create secret keys for the endpoints (1 server + 3 clients)
        let server_key = SecretKey::generate(&mut rand::rng());
        let client_keys: Vec<_> = (0..3)
            .map(|_| SecretKey::generate(&mut rand::rng()))
            .collect();

        // Create server endpoint
        let server_tcp = Arc::new(TcpTransport::new("127.0.0.1:0".parse().unwrap()));
        let server_ep = Endpoint::builder()
            .secret_key(server_key.clone())
            .add_user_transport(server_tcp)
            .clear_ip_transports()
            .clear_relay_transports()
            .bind()
            .await
            .expect("failed to bind server");

        // Get the TCP address that server is listening on
        let server_addr = server_ep.addr();
        let server_tcp_addr = server_addr
            .addrs
            .iter()
            .find_map(|a| match a {
                TransportAddr::User(u) => Some(u.clone()),
                _ => None,
            })
            .expect("server should have a user transport address");

        // Start the echo server
        let server = Router::builder(server_ep).accept(ALPN, Echo).spawn();

        // Create and run 3 clients in parallel
        let mut client_tasks = Vec::new();
        for (i, client_key) in client_keys.into_iter().enumerate() {
            let server_public = server_key.public();
            let server_tcp_addr = server_tcp_addr.clone();

            let task = tokio::spawn(async move {
                let client_tcp = Arc::new(TcpTransport::new("127.0.0.1:0".parse().unwrap()));
                let client_ep = Endpoint::builder()
                    .secret_key(client_key)
                    .add_user_transport(client_tcp)
                    .clear_ip_transports()
                    .clear_relay_transports()
                    .bind()
                    .await
                    .expect("failed to bind client");

                let addr =
                    EndpointAddr::from_parts(server_public, [TransportAddr::User(server_tcp_addr)]);

                let conn = client_ep
                    .connect(addr, ALPN)
                    .await
                    .expect("failed to connect");
                info!(client = i, "connected");

                // Open a bidirectional stream and send data
                let (mut send, mut recv) = conn.open_bi().await.expect("failed to open bi stream");
                info!(client = i, "streams open");

                let message = format!("Hello from client {}!", i);
                send.write_all(message.as_bytes())
                    .await
                    .expect("failed to write");
                send.finish().expect("failed to finish");
                info!(client = i, "message sent");

                // Read the echoed response
                let response = recv
                    .read_to_end(1000)
                    .await
                    .expect("failed to read response");
                info!(client = i, "response received");

                assert_eq!(response, message.as_bytes());

                conn.close(0u32.into(), b"done");
                info!(client = i, "done");
            });
            client_tasks.push(task);
        }

        // Wait for all clients to complete
        for task in client_tasks {
            task.await.expect("client task panicked");
        }

        // Clean up
        server.shutdown().await.expect("failed to shutdown server");
    }
}
