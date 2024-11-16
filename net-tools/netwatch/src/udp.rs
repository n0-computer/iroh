use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc, RwLock},
    task::Poll,
};

use anyhow::{ensure, Context, Result};
use tracing::warn;

use super::IpFamily;

/// Wrapper around a tokio UDP socket that handles the fact that
/// on drop `libc::close` can block for UDP sockets.
#[derive(Debug)]
pub struct UdpSocket {
    // TODO: can we drop the Arc and use lifetimes in the futures?
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
    /// The addr we are binding to.
    addr: SocketAddr,
    /// Set to true, when an error occured, that means we need to rebind the socket.
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
    pub fn needs_rebind(&self) -> bool {
        self.is_broken.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Marks this socket as needing a rebind
    pub fn mark_broken(&self) {
        self.is_broken
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Rebind the underlying socket.
    pub async fn rebind(&self) -> Result<()> {
        // Remove old socket
        {
            let mut guard = self.socket.write().unwrap();
            let std_sock = guard.take().expect("not yet dropped").into_std();
            tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    // Calls libc::close, which can block
                    drop(std_sock);
                })
                .await?;
        }

        // Prepare new socket
        let new_socket = inner_bind(self.addr)?;

        // Insert new socket
        self.socket.write().unwrap().replace(new_socket);

        // Clear errors
        self.is_broken
            .store(false, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    fn bind_raw(addr: impl Into<SocketAddr>) -> Result<Self> {
        let addr = addr.into();
        let socket = inner_bind(addr)?;

        Ok(UdpSocket {
            socket: Arc::new(RwLock::new(Some(socket))),
            addr,
            is_broken: AtomicBool::new(false),
        })
    }

    /// Use the socket
    pub fn with_socket<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&tokio::net::UdpSocket) -> T,
    {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");
        f(socket)
    }

    pub fn try_io<R>(
        &self,
        interest: tokio::io::Interest,
        f: impl FnOnce() -> std::io::Result<R>,
    ) -> std::io::Result<R> {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");
        socket.try_io(interest, f)
    }

    pub fn writable(&self) -> WritableFut {
        WritableFut {
            socket: self.socket.clone(),
        }
    }

    /// TODO
    pub fn recv<'a>(&self, buffer: &'a mut [u8]) -> RecvFut<'a> {
        RecvFut {
            socket: self.socket.clone(),
            buffer,
        }
    }

    /// TODO
    pub fn recv_from<'a>(&self, buffer: &'a mut [u8]) -> RecvFromFut<'a> {
        RecvFromFut {
            socket: self.socket.clone(),
            buffer,
        }
    }

    /// TODO
    pub fn send<'a>(&self, buffer: &'a [u8]) -> SendFut<'a> {
        SendFut {
            socket: self.socket.clone(),
            buffer,
        }
    }

    /// TODO
    pub fn send_to<'a>(&self, buffer: &'a [u8], to: SocketAddr) -> SendToFut<'a> {
        SendToFut {
            socket: self.socket.clone(),
            buffer,
            to,
        }
    }

    /// TODO
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        let mut guard = self.socket.write().unwrap();
        // dance around to make non async connect work
        let socket_tokio = guard.take().expect("missing socket");
        let socket_std = socket_tokio.into_std()?;
        socket_std.connect(addr)?;
        let socket_tokio = tokio::net::UdpSocket::from_std(socket_std)?;
        guard.replace(socket_tokio);
        Ok(())
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");
        socket.local_addr()
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFut<'a> {
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
    buffer: &'a mut [u8],
}

impl<'a> Future for RecvFut<'a> {
    type Output = std::io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;
        let guard = socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");

        match socket.poll_recv_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let res = socket.try_recv(buffer);
                Poll::Ready(res)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFromFut<'a> {
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
    buffer: &'a mut [u8],
}

impl<'a> Future for RecvFromFut<'a> {
    type Output = std::io::Result<(usize, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;
        let guard = socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");

        match socket.poll_recv_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let res = socket.try_recv_from(buffer);
                Poll::Ready(res)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

/// Writable future
#[derive(Debug)]
pub struct WritableFut {
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
}

impl Future for WritableFut {
    type Output = std::io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");

        socket.poll_send_ready(cx)
    }
}

/// Send future
#[derive(Debug)]
pub struct SendFut<'a> {
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
    buffer: &'a [u8],
}

impl<'a> Future for SendFut<'a> {
    type Output = std::io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");

        match socket.poll_send_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let res = socket.try_send(self.buffer);
                Poll::Ready(res)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

/// Send future
#[derive(Debug)]
pub struct SendToFut<'a> {
    socket: Arc<RwLock<Option<tokio::net::UdpSocket>>>,
    buffer: &'a [u8],
    to: SocketAddr,
}

impl<'a> Future for SendToFut<'a> {
    type Output = std::io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let guard = self.socket.read().unwrap();
        let socket = guard.as_ref().expect("missing socket");

        match socket.poll_send_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let res = socket.try_send_to(self.buffer, self.to);
                Poll::Ready(res)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }
}

fn inner_bind(addr: SocketAddr) -> Result<tokio::net::UdpSocket> {
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

    Ok(socket)
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // Only spawn_blocking if we are inside a tokio runtime, otherwise we just drop.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let std_sock = self
                .socket
                .write()
                .unwrap()
                .take()
                .expect("not yet dropped")
                .into_std();
            handle.spawn_blocking(move || {
                // Calls libc::close, which can block
                drop(std_sock);
            });
        }
    }
}
