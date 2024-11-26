use std::{
    future::Future,
    io::ErrorKind,
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::AtomicBool, RwLock, RwLockReadGuard, TryLockError},
    task::{Context, Poll},
};

use anyhow::{bail, ensure, Context as _, Result};
use atomic_waker::AtomicWaker;
use quinn_udp::Transmit;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Wrapper around a tokio UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<SocketState>,
    recv_waker: AtomicWaker,
    send_waker: AtomicWaker,
    /// Set to true, when an error occurred, that means we need to rebind the socket.
    is_broken: AtomicBool,
}

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the max supported by a default configuration of macOS. Some platforms will silently clamp the value.
const SOCKET_BUFFER_SIZE: usize = 7 << 20;
impl UdpSocket {
    /// Bind only Ipv4 on any interface.
    pub fn bind_v4(port: u16) -> Result<Self> {
        Self::bind(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on any interface.
    pub fn bind_v6(port: u16) -> Result<Self> {
        Self::bind(IpFamily::V6, port)
    }

    /// Bind only Ipv4 on localhost.
    pub fn bind_local_v4(port: u16) -> Result<Self> {
        Self::bind_local(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on localhost.
    pub fn bind_local_v6(port: u16) -> Result<Self> {
        Self::bind_local(IpFamily::V6, port)
    }

    /// Bind to the given port only on localhost.
    pub fn bind_local(network: IpFamily, port: u16) -> Result<Self> {
        let addr = SocketAddr::new(network.local_addr(), port);
        Self::bind_raw(addr).with_context(|| format!("{addr:?}"))
    }

    /// Bind to the given port and listen on all interfaces.
    pub fn bind(network: IpFamily, port: u16) -> Result<Self> {
        let addr = SocketAddr::new(network.unspecified_addr(), port);
        Self::bind_raw(addr).with_context(|| format!("{addr:?}"))
    }

    /// Bind to any provided [`SocketAddr`].
    pub fn bind_full(addr: impl Into<SocketAddr>) -> Result<Self> {
        Self::bind_raw(addr)
    }

    /// Is the socket broken and needs a rebind?
    pub fn is_broken(&self) -> bool {
        self.is_broken.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Marks this socket as needing a rebind
    fn mark_broken(&self) {
        self.is_broken
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Rebind the underlying socket.
    pub fn rebind(&self) -> Result<()> {
        {
            let mut guard = self.socket.write().unwrap();
            guard.rebind()?;

            // Clear errors
            self.is_broken
                .store(false, std::sync::atomic::Ordering::SeqCst);

            drop(guard);
        }

        // wakeup
        self.wake_all();

        Ok(())
    }

    fn bind_raw(addr: impl Into<SocketAddr>) -> Result<Self> {
        let socket = SocketState::bind(addr.into())?;

        Ok(UdpSocket {
            socket: RwLock::new(socket),
            recv_waker: AtomicWaker::default(),
            send_waker: AtomicWaker::default(),
            is_broken: AtomicBool::new(false),
        })
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    pub fn recv<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFut<'a, 'b> {
        RecvFut {
            socket: self,
            buffer,
        }
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    pub fn recv_from<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFromFut<'a, 'b> {
        RecvFromFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    ///
    /// # Return
    ///
    /// On success, the number of bytes sent is returned, otherwise, the
    /// encountered error is returned.
    pub fn send<'a, 'b>(&'b self, buffer: &'a [u8]) -> SendFut<'a, 'b> {
        SendFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    pub fn send_to<'a, 'b>(&'b self, buffer: &'a [u8], to: SocketAddr) -> SendToFut<'a, 'b> {
        SendToFut {
            socket: self,
            buffer,
            to,
        }
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via `recv` from the address specified in
    /// `addr`.
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        tracing::info!("connectnig to {}", addr);
        let guard = self.socket.read().unwrap();
        let (socket_tokio, _state) = guard.try_get_connected()?;

        let sock_ref = socket2::SockRef::from(&socket_tokio);
        sock_ref.connect(&socket2::SockAddr::from(addr))?;

        Ok(())
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let (socket, _state) = guard.try_get_connected()?;

        socket.local_addr()
    }

    /// Closes the socket, and waits for the underlying `libc::close` call to be finished.
    pub async fn close(&self) {
        let socket = self.socket.write().unwrap().close();
        self.wake_all();
        if let Some((sock, _)) = socket {
            let std_sock = sock.into_std();
            let res = tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    // Calls libc::close, which can block
                    drop(std_sock);
                })
                .await;
            if let Err(err) = res {
                warn!("failed to close socket: {:?}", err);
            }
        }
    }

    /// Check if this socket is closed.
    pub fn is_closed(&self) -> bool {
        self.socket.read().unwrap().is_closed()
    }

    /// Handle potential read errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_read_error(&self, error: std::io::Error) -> Option<std::io::Error> {
        match error.kind() {
            std::io::ErrorKind::NotConnected => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            _ => Some(error),
        }
    }

    /// Handle potential write errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_write_error(&self, error: std::io::Error) -> Option<std::io::Error> {
        match error.kind() {
            std::io::ErrorKind::BrokenPipe => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            _ => Some(error),
        }
    }

    /// Try to get a read lock for the sockets, but don't block for trying to acquire it.
    fn poll_read_socket(
        &self,
        waker: &AtomicWaker,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<RwLockReadGuard<'_, SocketState>> {
        let guard = match self.socket.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => {
                waker.register(cx.waker());

                match self.socket.try_read() {
                    Ok(guard) => {
                        // we're actually fine, no need to cause a spurious wakeup
                        waker.take();
                        guard
                    }
                    Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
                    Err(TryLockError::WouldBlock) => {
                        // Ok fine, we registered our waker, the lock is really closed,
                        // we can return pending.
                        return Poll::Pending;
                    }
                }
            }
        };
        Poll::Ready(guard)
    }

    fn wake_all(&self) {
        self.recv_waker.wake();
        self.send_waker.wake();
    }

    /// Checks if the socket needs a rebind, and if so does it.
    ///
    /// Returns an error if the rebind is needed, but failed.
    fn maybe_rebind(&self) -> std::io::Result<()> {
        if self.is_broken() {
            match self.rebind() {
                Ok(()) => {
                    // all good
                }
                Err(err) => {
                    warn!("failed to rebind socket: {:?}", err);
                    // TODO: improve error
                    let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = futures_lite::ready!(self.poll_read_socket(&self.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }

    /// Send a quinn based `Transmit`.
    pub fn try_send_quinn(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
        loop {
            self.maybe_rebind()?;

            let guard = match self.socket.try_read() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(e)) => {
                    panic!("lock poisoned: {:?}", e);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
                }
            };
            let (socket, state) = guard.try_get_connected()?;

            let res = socket.try_io(Interest::WRITABLE, || state.send(socket.into(), transmit));

            match res {
                Ok(()) => return Ok(()),
                Err(err) => match self.handle_write_error(err) {
                    Some(err) => return Err(err),
                    None => {
                        continue;
                    }
                },
            }
        }
    }

    /// quinn based `poll_recv`
    pub fn poll_recv_quinn(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = futures_lite::ready!(self.poll_read_socket(&self.recv_waker, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    // We are ready to read, continue
                }
                Poll::Ready(Err(err)) => match self.handle_read_error(err) {
                    Some(err) => return Poll::Ready(Err(err)),
                    None => {
                        continue;
                    }
                },
            }

            let res = socket.try_io(Interest::READABLE, || state.recv(socket.into(), bufs, meta));
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
                    match self.handle_read_error(err) {
                        Some(err) => return Poll::Ready(Err(err)),
                        None => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Returns `false` on targets which employ e.g. the `IPV6_DONTFRAG` socket option.
    pub fn may_fragment(&self) -> std::io::Result<bool> {
        let guard = self.socket.read().unwrap();
        let (_, state) = guard.try_get_connected()?;
        Ok(state.may_fragment())
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    pub fn max_gso_segments(&self) -> std::io::Result<usize> {
        let guard = self.socket.read().unwrap();
        let (_, state) = guard.try_get_connected()?;
        Ok(state.max_gso_segments())
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    pub fn gro_segments(&self) -> std::io::Result<usize> {
        let guard = self.socket.read().unwrap();
        let (_, state) = guard.try_get_connected()?;
        Ok(state.gro_segments())
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFut<'_, '_> {
    type Output = std::io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = futures_lite::ready!(socket.poll_read_socket(&socket.recv_waker, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv(buffer);
                    if let Err(err) = res {
                        if err.kind() == ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFromFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFromFut<'_, '_> {
    type Output = std::io::Result<(usize, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = futures_lite::ready!(socket.poll_read_socket(&socket.recv_waker, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv_from(buffer);
                    if let Err(err) = res {
                        if err.kind() == ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Send future
#[derive(Debug)]
pub struct SendFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
}

impl Future for SendFut<'_, '_> {
    type Output = std::io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                futures_lite::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send(self.buffer);
                    if let Err(err) = res {
                        if err.kind() == ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

/// Send future
#[derive(Debug)]
pub struct SendToFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
    to: SocketAddr,
}

impl Future for SendToFut<'_, '_> {
    type Output = std::io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                futures_lite::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send_to(self.buffer, self.to);
                    if let Err(err) = res {
                        if err.kind() == ErrorKind::WouldBlock {
                            continue;
                        }

                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(Debug)]
enum SocketState {
    Connected {
        socket: tokio::net::UdpSocket,
        state: quinn_udp::UdpSocketState,
        /// The addr we are binding to.
        addr: SocketAddr,
    },
    Closed,
}

impl SocketState {
    fn try_get_connected(
        &self,
    ) -> std::io::Result<(&tokio::net::UdpSocket, &quinn_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                socket,
                state,
                addr: _,
            } => Ok((socket, state)),
            Self::Closed => {
                warn!("socket closed");
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                ))
            }
        }
    }

    fn bind(addr: SocketAddr) -> Result<Self> {
        let network = IpFamily::from(addr.ip());
        let socket = socket2::Socket::new(
            network.into(),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .context("socket create")?;

        if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set recv_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set send_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if network == IpFamily::V6 {
            // Avoid dualstack
            socket.set_only_v6(true).context("only IPv6")?;
        }

        // Binding must happen before calling quinn, otherwise `local_addr`
        // is not yet available on all OSes.
        socket.bind(&addr.into()).context("binding")?;

        // Ensure nonblocking
        socket.set_nonblocking(true).context("nonblocking: true")?;

        let socket: std::net::UdpSocket = socket.into();

        // Convert into tokio UdpSocket
        let socket = tokio::net::UdpSocket::from_std(socket).context("conversion to tokio")?;
        let socket_ref = quinn_udp::UdpSockRef::from(&socket);
        let socket_state = quinn_udp::UdpSocketState::new(socket_ref)?;

        let local_addr = socket.local_addr().context("local addr")?;
        if addr.port() != 0 {
            ensure!(
                local_addr.port() == addr.port(),
                "wrong port bound: {:?}: wanted: {} got {}",
                network,
                addr.port(),
                local_addr.port(),
            );
        }

        Ok(Self::Connected {
            socket,
            state: socket_state,
            addr: local_addr,
        })
    }

    fn rebind(&mut self) -> Result<()> {
        let addr = match self {
            Self::Connected { addr, .. } => *addr,
            Self::Closed => {
                bail!("socket is closed and cannot be rebound");
            }
        };
        debug!("rebinding {}", addr);

        *self = SocketState::Closed;
        *self = Self::bind(addr)?;

        Ok(())
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    fn close(&mut self) -> Option<(tokio::net::UdpSocket, quinn_udp::UdpSocketState)> {
        match std::mem::replace(self, SocketState::Closed) {
            Self::Connected { socket, state, .. } => Some((socket, state)),
            Self::Closed => None,
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        trace!("dropping UdpSocket");
        match self.socket.write().unwrap().close() {
            Some((socket, _)) => {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    // No wakeup after dropping write lock here, since we're getting dropped.
                    // this will be empty if `close` was called before
                    let std_sock = socket.into_std();
                    handle.spawn_blocking(move || {
                        // Calls libc::close, which can block
                        drop(std_sock);
                    });
                }
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reconnect() -> anyhow::Result<()> {
        let (s_b, mut r_b) = tokio::sync::mpsc::channel(16);
        let handle_a = tokio::task::spawn(async move {
            let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
            let addr = socket.local_addr()?;
            s_b.send(addr).await?;
            println!("socket bound to {:?}", addr);

            let mut buffer = [0u8; 16];
            for i in 0..100 {
                println!("-- tick {i}");
                let read = socket.recv_from(&mut buffer).await;
                match read {
                    Ok((count, addr)) => {
                        println!("got {:?}", &buffer[..count]);
                        println!("sending {:?} to {:?}", &buffer[..count], addr);
                        socket.send_to(&buffer[..count], addr).await?;
                    }
                    Err(err) => {
                        eprintln!("error reading: {:?}", err);
                    }
                }
            }
            socket.close().await;
            anyhow::Ok(())
        });

        let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let first_addr = socket.local_addr()?;
        println!("socket2 bound to {:?}", socket.local_addr()?);
        let addr = r_b.recv().await.unwrap();

        let mut buffer = [0u8; 16];
        for i in 0u8..100 {
            println!("round one - {}", i);
            socket.send_to(&[i][..], addr).await.context("send")?;
            let (count, from) = socket.recv_from(&mut buffer).await.context("recv")?;
            assert_eq!(addr, from);
            assert_eq!(count, 1);
            assert_eq!(buffer[0], i);

            // check for errors
            assert!(!socket.is_broken());

            // rebind
            socket.rebind()?;

            // check that the socket has the same address as before
            assert_eq!(socket.local_addr()?, first_addr);
        }

        handle_a.await.ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_mark_broken() -> anyhow::Result<()> {
        let socket_a = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_a = socket_a.local_addr()?;
        println!("socket bound to {:?}", addr_a);

        let socket_b = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_b = socket_b.local_addr()?;
        println!("socket bound to {:?}", addr_b);

        let handle = tokio::task::spawn(async move {
            let mut buffer = [0u8; 16];
            for _ in 0..2 {
                match socket_b.recv_from(&mut buffer).await {
                    Ok((count, addr)) => {
                        println!("got {:?} from {:?}", &buffer[..count], addr);
                    }
                    Err(err) => {
                        eprintln!("error recv: {:?}", err);
                    }
                }
            }
        });
        socket_a.send_to(&[0][..], addr_b).await?;
        socket_a.mark_broken();
        assert!(socket_a.is_broken());
        socket_a.send_to(&[0][..], addr_b).await?;
        assert!(!socket_a.is_broken());

        handle.await?;
        Ok(())
    }
}
