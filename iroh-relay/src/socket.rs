//! Socket configuration hooks shared by relay connections and endpoint transports.

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::{io, net::SocketAddr, sync::Arc};

/// The operation for which a socket is being configured.
///
/// The address is the local bind address for UDP or the remote address for a
/// relay connection. It also identifies the socket's IP family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketTarget {
    /// Bind a UDP transport socket to the given local address.
    UdpBind(SocketAddr),
    /// Connect a TCP socket to the given relay address.
    RelayConnect(SocketAddr),
}

/// A socket handed to a [`ConfigureSocket`] hook before bind or connect.
///
/// It implements [`AsFd`] on unix and [`AsSocket`] on Windows, so callers can
/// use a socket crate such as `socket2` to set options.
#[derive(Debug)]
pub struct SocketRef<'a> {
    #[cfg(unix)]
    inner: BorrowedFd<'a>,
    #[cfg(windows)]
    inner: BorrowedSocket<'a>,
    #[cfg(not(any(unix, windows)))]
    inner: std::marker::PhantomData<&'a ()>,
}

impl<'a> SocketRef<'a> {
    /// Borrows a socket for the duration of a hook call.
    #[cfg(unix)]
    pub fn new(socket: &'a impl AsFd) -> Self {
        Self {
            inner: socket.as_fd(),
        }
    }

    /// Borrows a socket for the duration of a hook call.
    #[cfg(windows)]
    pub fn new(socket: &'a impl AsSocket) -> Self {
        Self {
            inner: socket.as_socket(),
        }
    }
}

#[cfg(unix)]
impl AsFd for SocketRef<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner
    }
}

#[cfg(windows)]
impl AsSocket for SocketRef<'_> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.inner
    }
}

/// A hook run on a socket after it is created and before it is bound or connected.
///
/// Callers can set `SO_MARK` or `SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on
/// Apple platforms, or `IP_UNICAST_IF` / `IPV6_UNICAST_IF` on Windows.
///
/// Returning an error fails the bind or the dial, rather than leaving a socket
/// that silently missed its configuration.
pub type ConfigureSocket = Arc<dyn Fn(SocketRef<'_>, SocketTarget) -> io::Result<()> + Send + Sync>;
