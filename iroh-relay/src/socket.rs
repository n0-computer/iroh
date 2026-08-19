//! The hook that lets a caller configure the sockets this crate opens.
//!
//! Lives here rather than in `iroh` so that both the relay client's TCP dial and
//! `iroh`'s UDP transport hand out the same types.

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::{io, sync::Arc};

/// The address family a socket is being opened for.
///
/// Passed to a [`ConfigureSocket`] hook, which usually needs it: the socket
/// options it is there to set are per-family, and asking the socket itself is
/// not portable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// A socket that is about to be bound or connected, handed to a
/// [`ConfigureSocket`] hook.
///
/// It implements [`AsFd`] on unix and [`AsSocket`] on Windows, which is what
/// socket wrappers take, so the hook can set options with the socket crate of
/// its choice: `socket2::SockRef::from(&socket)`, or plain `libc::setsockopt` on
/// the raw fd.
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

/// A hook run on a socket after it is created and before it is bound or
/// connected.
///
/// Its purpose is to let the caller decide how the traffic is routed. The
/// options that do that are platform-specific (`SO_MARK` on Linux,
/// `IP_BOUND_IF` on Apple platforms), so this crate does not model them itself
/// and hands out the socket instead.
///
/// Returning an error fails the bind or the dial, rather than leaving a socket
/// that silently missed its configuration.
pub type ConfigureSocket = Arc<dyn Fn(SocketRef<'_>, IpFamily) -> io::Result<()> + Send + Sync>;
