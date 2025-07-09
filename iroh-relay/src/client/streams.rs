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
    Raw(WithMetrics<TcpStream>),
    Proxied(util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream<WithMetrics<TcpStream>>>),
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
    #[cfg(test)]
    Test(tokio::io::DuplexStream),
}

impl<IO> ExportKeyingMaterial for MaybeTlsStream<IO> {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let Self::Tls(ref tls) = self else {
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
            #[cfg(test)]
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
            #[cfg(test)]
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
            #[cfg(test)]
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
            #[cfg(test)]
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
            #[cfg(test)]
            Self::Test(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Raw(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
            #[cfg(test)]
            Self::Test(stream) => stream.is_write_vectored(),
        }
    }
}

impl<IO> AsRef<IO> for MaybeTlsStream<IO> {
    fn as_ref(&self) -> &IO {
        match self {
            Self::Raw(s) => s,
            Self::Tls(s) => s.get_ref().0,
            #[cfg(test)]
            Self::Test(_) => unimplemented!("can't grab underlying IO in MaybeTlsStream::Test"),
        }
    }
}

#[derive(Debug)]
pub struct WithMetrics<IO> {
    inner: IO,
    metrics: std::sync::Arc<crate::client::Metrics>,
}

impl<IO> WithMetrics<IO> {
    pub fn new(inner: IO, metrics: std::sync::Arc<crate::client::Metrics>) -> Self {
        Self { inner, metrics }
    }
}

impl<IO> std::ops::Deref for WithMetrics<IO> {
    type Target = IO;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<IO> std::ops::DerefMut for WithMetrics<IO> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for WithMetrics<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.remaining();
        let result = std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, buf));
        if let Ok(_) = &result {
            let bytes_recv = before - buf.remaining();
            self.metrics.tcp_bytes_recv.inc_by(bytes_recv as u64);
        }
        Poll::Ready(result)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for WithMetrics<IO> {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let result = std::task::ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, bufs));
        if let Ok(bytes) = &result {
            self.metrics.tcp_bytes_sent.inc_by(*bytes as u64);
            self.metrics.tcp_write_calls.inc();
        }
        Poll::Ready(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let result = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf));
        if let Ok(bytes) = &result {
            self.metrics.tcp_bytes_sent.inc_by(*bytes as u64);
            self.metrics.tcp_write_calls.inc();
        }
        Poll::Ready(result)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
