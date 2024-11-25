use std::{
    future::Future,
    io::ErrorKind,
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::AtomicBool, RwLock},
    task::{Context, Poll},
};

use anyhow::{bail, ensure, Context as _, Result};
use quinn_udp::Transmit;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Wrapper around a tokio UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<Option<(tokio::net::UdpSocket, quinn_udp::UdpSocketState)>>,
    /// The addr we are binding to.
    addr: SocketAddr,
    /// Set to true, when an error occurred, that means we need to rebind the socket.
    is_broken: AtomicBool,
}

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the ma supported by a default configuration of macOS. Some platforms will silently clamp the value.
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
        debug!("rebinding {}", self.addr);
        // Remove old socket
        let mut guard = self.socket.write().unwrap();
        {
            let Some(socket) = guard.take() else {
                bail!("cannot rebind closed socket");
            };
            drop(socket);
        }

        // Prepare new socket
        let new_socket = inner_bind(self.addr)?;

        // Insert new socket
        guard.replace(new_socket);

        // Clear errors
        self.is_broken
            .store(false, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    fn bind_raw(addr: impl Into<SocketAddr>) -> Result<Self> {
        let mut addr = addr.into();
        let socket = inner_bind(addr)?;
        // update to use selected port
        addr.set_port(socket.0.local_addr()?.port());

        Ok(UdpSocket {
            socket: RwLock::new(Some(socket)),
            addr,
            is_broken: AtomicBool::new(false),
        })
    }

    /// Use the socket
    pub fn with_socket<F, T>(&self, f: F) -> std::io::Result<T>
    where
        F: FnOnce(&tokio::net::UdpSocket, &quinn_udp::UdpSocketState) -> T,
    {
        let guard = self.socket.read().unwrap();
        let Some((socket, state)) = guard.as_ref() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };
        Ok(f(socket, state))
    }

    /// TODO
    pub fn recv<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFut<'a, 'b> {
        RecvFut {
            socket: self,
            buffer,
        }
    }

    /// TODO
    pub fn recv_from<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFromFut<'a, 'b> {
        RecvFromFut {
            socket: self,
            buffer,
        }
    }

    /// TODO
    pub fn send<'a, 'b>(&'b self, buffer: &'a [u8]) -> SendFut<'a, 'b> {
        SendFut {
            socket: self,
            buffer,
        }
    }

    /// TODO
    pub fn send_to<'a, 'b>(&'b self, buffer: &'a [u8], to: SocketAddr) -> SendToFut<'a, 'b> {
        SendToFut {
            socket: self,
            buffer,
            to,
        }
    }

    /// TODO
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        tracing::info!("connectnig to {}", addr);
        let mut guard = self.socket.write().unwrap();
        // dance around to make non async connect work
        let Some((socket_tokio, state)) = guard.take() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };

        let socket_std = socket_tokio.into_std()?;
        socket_std.connect(addr)?;
        let socket_tokio = tokio::net::UdpSocket::from_std(socket_std)?;
        guard.replace((socket_tokio, state));
        Ok(())
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let Some((socket, _)) = guard.as_ref() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };

        socket.local_addr()
    }

    /// Closes the socket, and waits for the underlying `libc::close` call to be finished.
    pub async fn close(&self) {
        let socket = self.socket.write().unwrap().take();
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
        self.socket.read().unwrap().is_none()
    }

    /// Handle potential read errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    pub fn handle_read_error(&self, error: std::io::Error) -> Option<std::io::Error> {
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
    pub fn handle_write_error(&self, error: std::io::Error) -> Option<std::io::Error> {
        match error.kind() {
            std::io::ErrorKind::BrokenPipe => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            _ => Some(error),
        }
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            // check if the socket needs a rebind
            if self.is_broken() {
                match self.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }
            let guard = self.socket.read().unwrap();
            let Some((socket, _state)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match socket.poll_send_ready(cx) {
                Poll::Pending => return Poll::Pending,
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
            // check if the socket needs a rebind
            if self.is_broken() {
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
            let guard = self.socket.read().unwrap();
            let Some((socket, state)) = guard.as_ref() else {
                warn!("socket closed");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                ));
            };

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
            // check if the socket needs a rebind
            if self.is_broken() {
                match self.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }
            let guard = self.socket.read().unwrap();
            let Some((socket, state)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
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

    /// TODO
    pub fn may_fragment(&self) -> std::io::Result<bool> {
        let guard = self.socket.read().unwrap();
        let Some((_, state)) = guard.as_ref() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };
        Ok(state.may_fragment())
    }

    /// TODO
    pub fn max_transmit_segments(&self) -> std::io::Result<usize> {
        let guard = self.socket.read().unwrap();
        let Some((_, state)) = guard.as_ref() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };
        Ok(state.max_gso_segments())
    }

    /// TODO
    pub fn max_receive_segments(&self) -> std::io::Result<usize> {
        let guard = self.socket.read().unwrap();
        let Some((_, state)) = guard.as_ref() else {
            warn!("socket closed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            ));
        };
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
            // check if the socket needs a rebind
            if socket.is_broken() {
                match socket.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }

            let guard = socket.socket.read().unwrap();
            let Some((inner_socket, _)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
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
            // check if the socket needs a rebind
            if socket.is_broken() {
                match socket.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }
            let guard = socket.socket.read().unwrap();
            let Some((inner_socket, _)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
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

/// Writable future
#[derive(Debug)]
pub struct WritableFut<'a> {
    socket: &'a UdpSocket,
}

impl Future for WritableFut<'_> {
    type Output = std::io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.socket.poll_writable(cx)
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

    fn poll(self: Pin<&mut Self>, c: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            // check if the socket needs a rebind
            if self.socket.is_broken() {
                match self.socket.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }
            let guard = self.socket.socket.read().unwrap();
            let Some((socket, _)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match socket.poll_send_ready(c) {
                Poll::Pending => return Poll::Pending,
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
            // check if the socket needs a rebind
            if self.socket.is_broken() {
                match self.socket.rebind() {
                    Ok(()) => {
                        // all good
                    }
                    Err(err) => {
                        warn!("failed to rebind socket: {:?}", err);
                        // TODO: improve error
                        let err =
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string());
                        return Poll::Ready(Err(err));
                    }
                }
            }

            let guard = self.socket.socket.read().unwrap();
            let Some((socket, _)) = guard.as_ref() else {
                warn!("socket closed");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "socket closed",
                )));
            };

            match socket.poll_send_ready(cx) {
                Poll::Pending => return Poll::Pending,
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

fn inner_bind(addr: SocketAddr) -> Result<(tokio::net::UdpSocket, quinn_udp::UdpSocketState)> {
    let network = IpFamily::from(addr.ip());
    let socket = socket2::Socket::new(
        network.into(),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("socket create")?;

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

    if addr.port() != 0 {
        let local_addr = socket.local_addr().context("local addr")?;
        ensure!(
            local_addr.port() == addr.port(),
            "wrong port bound: {:?}: wanted: {} got {}",
            network,
            addr.port(),
            local_addr.port(),
        );
    }

    Ok((socket, socket_state))
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        debug!("dropping UdpSocket");
        // Only spawn_blocking if we are inside a tokio runtime, otherwise we just drop.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if let Some((socket, _)) = self.socket.write().unwrap().take() {
                // this will be empty if `close` was called before
                let std_sock = socket.into_std();
                handle.spawn_blocking(move || {
                    // Calls libc::close, which can block
                    drop(std_sock);
                });
            }
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
