use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::upgrade::{Parts, Upgraded};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use super::util;

#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStreamChained {
    Raw(util::Chain<std::io::Cursor<Bytes>, ProxyStream>),
    Tls(util::Chain<std::io::Cursor<Bytes>, tokio_rustls::client::TlsStream<ProxyStream>>),
    #[cfg(all(test, feature = "server"))]
    Mem(tokio::io::DuplexStream),
}

impl AsyncRead for MaybeTlsStreamChained {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(all(test, feature = "server"))]
            Self::Mem(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStreamChained {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream.get_mut().1).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.get_mut().1).poll_write(cx, buf),
            #[cfg(all(test, feature = "server"))]
            Self::Mem(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream.get_mut().1).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.get_mut().1).poll_flush(cx),
            #[cfg(all(test, feature = "server"))]
            Self::Mem(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream.get_mut().1).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.get_mut().1).poll_shutdown(cx),
            #[cfg(all(test, feature = "server"))]
            Self::Mem(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream.get_mut().1).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream.get_mut().1).poll_write_vectored(cx, bufs),
            #[cfg(all(test, feature = "server"))]
            Self::Mem(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}

pub fn downcast_upgrade(upgraded: Upgraded) -> Option<MaybeTlsStreamChained> {
    match upgraded.downcast::<TokioIo<MaybeTlsStream<ProxyStream>>>() {
        Ok(Parts { read_buf, io, .. }) => {
            // Prepend data to the reader to avoid data loss
            let read_buf = std::io::Cursor::new(read_buf);
            match io.into_inner() {
                MaybeTlsStream::Raw(conn) => {
                    Some(MaybeTlsStreamChained::Raw(util::chain(read_buf, conn)))
                }
                MaybeTlsStream::Tls(conn) => {
                    Some(MaybeTlsStreamChained::Tls(util::chain(read_buf, conn)))
                }
            }
        }
        Err(upgraded) => {
            if let Ok(Parts { read_buf, io, .. }) =
                upgraded.downcast::<TokioIo<tokio_rustls::client::TlsStream<ProxyStream>>>()
            {
                let conn = io.into_inner();

                // Prepend data to the reader to avoid data loss
                let conn = util::chain(std::io::Cursor::new(read_buf), conn);
                return Some(MaybeTlsStreamChained::Tls(conn));
            }

            None
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProxyStream {
    Raw(TcpStream),
    Proxied(util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream<TcpStream>>),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Proxied(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Proxied(stream) => Pin::new(stream.get_mut().1).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::Proxied(stream) => Pin::new(stream.get_mut().1).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Proxied(stream) => Pin::new(stream.get_mut().1).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Proxied(stream) => Pin::new(stream.get_mut().1).poll_write_vectored(cx, bufs),
        }
    }
}

impl ProxyStream {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.local_addr(),
            Self::Proxied(s) => s.get_ref().1.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.peer_addr(),
            Self::Proxied(s) => s.get_ref().1.peer_addr(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStream<IO> {
    Raw(IO),
    Tls(tokio_rustls::client::TlsStream<IO>),
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}

impl MaybeTlsStream<TcpStream> {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.local_addr(),
            Self::Tls(s) => s.get_ref().0.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.peer_addr(),
            Self::Tls(s) => s.get_ref().0.peer_addr(),
        }
    }
}

impl<IO> AsRef<IO> for MaybeTlsStream<IO> {
    fn as_ref(&self) -> &IO {
        match self {
            Self::Raw(s) => s,
            Self::Tls(s) => s.get_ref().0,
        }
    }
}
