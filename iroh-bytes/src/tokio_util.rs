//! Utilities for working with tokio io
use std::{io, pin::Pin, task::Poll};

use bytes::Bytes;
use futures::{
    future::{Either, LocalBoxFuture},
    FutureExt,
};
use iroh_io::{AsyncSliceReader, AsyncSliceWriter, FileAdapter};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

/// A reader that tracks the number of bytes read
#[derive(Debug)]
pub(crate) struct TrackingReader<R> {
    inner: R,
    read: u64,
}

impl<R> TrackingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    pub fn into_parts(self) -> (R, u64) {
        (self.inner, self.read)
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

/// Converts an AsyncWrite into an AsyncSliceWriter by just ignoring the offsets
#[derive(Debug)]
pub struct ConcatenateSliceWriter<W>(W);

impl<W> ConcatenateSliceWriter<W> {
    /// Create a new `ConcatenateSliceWriter` from an inner writer
    pub fn new(inner: W) -> Self {
        Self(inner)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncWrite + Unpin + 'static> AsyncSliceWriter for ConcatenateSliceWriter<W> {
    type WriteBytesAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_bytes_at(&mut self, _offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        async move { self.0.write_all(&data).await }.boxed_local()
    }

    type WriteAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_at(&mut self, _offset: u64, bytes: &[u8]) -> Self::WriteAtFuture<'_> {
        let t: smallvec::SmallVec<[u8; 16]> = bytes.into();
        async move { self.0.write_all(&t).await }.boxed_local()
    }

    type SyncFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        self.0.flush().boxed_local()
    }

    type SetLenFuture<'a> = futures::future::Ready<io::Result<()>>;
    fn set_len(&mut self, _len: u64) -> Self::SetLenFuture<'_> {
        futures::future::ready(io::Result::Ok(()))
    }
}

/// A slice writer that adds a synchronous progress callback
#[derive(Debug)]
pub struct ProgressSliceWriter<W>(W, mpsc::Sender<(u64, usize)>);

impl<W: AsyncSliceWriter> ProgressSliceWriter<W> {
    /// Create a new `ProgressSliceWriter` from an inner writer and a progress callback
    pub fn new(inner: W, on_write: mpsc::Sender<(u64, usize)>) -> Self {
        Self(inner, on_write)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncSliceWriter + Send + 'static> AsyncSliceWriter for ProgressSliceWriter<W> {
    type WriteBytesAtFuture<'a> = W::WriteBytesAtFuture<'a>;
    fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        self.1.try_send((offset, Bytes::len(&data))).ok();
        self.0.write_bytes_at(offset, data)
    }

    type WriteAtFuture<'a> = W::WriteAtFuture<'a>;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Self::WriteAtFuture<'_> {
        self.0.write_at(offset, bytes)
    }

    type SyncFuture<'a> = W::SyncFuture<'a>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        self.0.sync()
    }

    type SetLenFuture<'a> = W::SetLenFuture<'a>;
    fn set_len(&mut self, size: u64) -> Self::SetLenFuture<'_> {
        self.0.set_len(size)
    }
}

/// A writer that tracks the number of bytes written
#[derive(Debug)]
pub(crate) struct TrackingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> TrackingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

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

/// A writer that tries to send the total number of bytes written after each write
///
/// It sends the total number instead of just an increment so the update is self-contained
#[derive(Debug)]
pub struct ProgressWriter<W> {
    inner: TrackingWriter<W>,
    sender: mpsc::Sender<u64>,
}

impl<W> ProgressWriter<W> {
    /// Create a new `ProgressWriter` from an inner writer
    pub fn new(inner: W) -> (Self, mpsc::Receiver<u64>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                inner: TrackingWriter::new(inner),
                sender,
            },
            receiver,
        )
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.inner.into_parts().0
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(_)) = res {
            this.sender.try_send(this.inner.bytes_written()).ok();
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

pub(crate) async fn read_as_bytes(mut reader: &mut impl AsyncSliceReader) -> io::Result<Bytes> {
    reader.read_at(0, usize::MAX).await
}
