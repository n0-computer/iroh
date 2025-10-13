use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use super::util;
use crate::ExportKeyingMaterial;

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

    fn is_write_vectored(&self) -> bool {
        match self {
            ProxyStream::Raw(stream) => stream.is_write_vectored(),
            ProxyStream::Proxied(stream) => stream.get_ref().1.is_write_vectored(),
        }
    }
}

impl ProxyStream {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.local_addr(),
            Self::Proxied(s) => s.get_ref().1.as_ref().local_addr(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Raw(s) => s.peer_addr(),
            Self::Proxied(s) => s.get_ref().1.as_ref().peer_addr(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStream<IO> {
    Raw(IO),
    Tls(tokio_rustls::client::TlsStream<IO>),
    #[cfg(all(test, feature = "server"))]
    Test(tokio::io::DuplexStream),
}

impl<IO> ExportKeyingMaterial for MaybeTlsStream<IO> {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let Self::Tls(tls) = self else {
            return None;
        };
        tls.get_ref()
            .1
            .export_keying_material(output, label, context)
            .ok()
    }
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
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => Pin::new(stream).poll_read(cx, buf),
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
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => Pin::new(stream).poll_shutdown(cx),
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
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Raw(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
            #[cfg(all(test, feature = "server"))]
            Self::Test(stream) => stream.is_write_vectored(),
        }
    }
}

impl<IO> AsRef<IO> for MaybeTlsStream<IO> {
    fn as_ref(&self) -> &IO {
        match self {
            Self::Raw(s) => s,
            Self::Tls(s) => s.get_ref().0,
            #[cfg(all(test, feature = "server"))]
            Self::Test(_) => unimplemented!("can't grab underlying IO in MaybeTlsStream::Test"),
        }
    }
}
