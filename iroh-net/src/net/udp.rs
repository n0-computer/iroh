use std::net::SocketAddr;

use anyhow::{ensure, Context, Result};
use tracing::warn;

use super::IpFamily;

/// Wrapper around a tokio UDP socket that handles the fact that
/// on drop `libc::close` can block for UDP sockets.
#[derive(Debug)]
pub struct UdpSocket(Option<tokio::net::UdpSocket>);

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

    fn bind_raw(addr: impl Into<SocketAddr>) -> Result<Self> {
        let addr = addr.into();
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
        Ok(UdpSocket(Some(socket)))
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_ref().expect("not dropped").as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.0.as_ref().expect("not dropped").as_socket()
    }
}

impl From<tokio::net::UdpSocket> for UdpSocket {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self(Some(socket))
    }
}

impl std::ops::Deref for UdpSocket {
    type Target = tokio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("only removed on drop")
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let std_sock = self.0.take().expect("not yet dropped").into_std();

        // Only spawn_blocking if we are inside a tokio runtime, otherwise we just drop.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                // Calls libc::close, which can block
                drop(std_sock);
            });
        }
    }
}
