//! Utilities for working with tokio io

use iroh_io::AsyncStreamReader;
use std::{io, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// A reader that tracks the number of bytes read
#[derive(Debug)]
pub struct TrackingReader<R> {
    inner: R,
    read: u64,
}

impl<R> TrackingReader<R> {
    /// Wrap a reader in a tracking reader
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }

    /// Get the number of bytes read
    #[allow(dead_code)]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    /// Get the inner reader
    pub fn into_parts(self) -> (R, u64) {
        (self.inner, self.read)
    }
}

impl<R> AsyncStreamReader for TrackingReader<R>
where
    R: AsyncStreamReader,
{
    async fn read_bytes(&mut self, len: usize) -> io::Result<bytes::Bytes> {
        let bytes = self.inner.read_bytes(len).await?;
        self.read = self.read.saturating_add(bytes.len() as u64);
        Ok(bytes)
    }

    async fn read<const L: usize>(&mut self) -> io::Result<[u8; L]> {
        let res = self.inner.read::<L>().await?;
        self.read = self.read.saturating_add(L as u64);
        Ok(res)
    }
}

impl<R> AsyncRead for TrackingReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let filled0 = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let size = buf.filled().len().saturating_sub(filled0);
            this.read = this.read.saturating_add(size as u64);
        }
        res
    }
}

/// A writer that tracks the number of bytes written
#[derive(Debug)]
pub struct TrackingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> TrackingWriter<W> {
    /// Wrap a writer in a tracking writer
    pub fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    /// Get the number of bytes written
    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// Get the inner writer
    pub fn into_parts(self) -> (W, u64) {
        (self.inner, self.written)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(size)) = res {
            this.written = this.written.saturating_add(size as u64);
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
