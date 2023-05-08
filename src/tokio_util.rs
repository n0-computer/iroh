//! Utilities for working with tokio io
use std::{
    io::{self, Cursor, SeekFrom},
    pin::Pin,
    task::Poll,
};

use bao_tree::io::fsm::AsyncSliceWriter;
use bytes::Bytes;
use futures::{future::BoxFuture, ready, FutureExt};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tokio_util::either::Either;

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

impl<W: AsyncWrite + Send + Unpin + 'static> AsyncSliceWriter for ConcatenateSliceWriter<W> {
    type WriteFuture = BoxFuture<'static, (Self, io::Result<()>)>;

    fn write_at(mut self, _offset: u64, data: Bytes) -> Self::WriteFuture {
        async move {
            let res = self.0.write_all(&data).await;
            (self, res)
        }
        .boxed()
    }

    fn write_array_at<const N: usize>(mut self, _offset: u64, bytes: [u8; N]) -> Self::WriteFuture {
        async move {
            let res = self.0.write_all(&bytes).await;
            (self, res)
        }
        .boxed()
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
    type WriteFuture = BoxFuture<'static, (Self, io::Result<()>)>;

    fn write_at(self, offset: u64, data: Bytes) -> Self::WriteFuture {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, data.len())).ok();
        async move {
            let (this, res) = self.0.write_at(offset, data).await;
            (Self(this, self.1), res)
        }
        .boxed()
    }

    fn write_array_at<const N: usize>(self, offset: u64, bytes: [u8; N]) -> Self::WriteFuture {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, bytes.len())).ok();
        async move {
            let (this, res) = self.0.write_array_at(offset, bytes).await;
            (Self(this, self.1), res)
        }
        .boxed()
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

/// A wrapper that tracks the current position of the underlying reader or writer
/// and avoids noop seeks.
///
/// This is needed because while in sync io a noop seek is extremely cheap, in
/// current async io it involves spawning a blocking task, and therefore is
/// expensive.
///
/// The chunk downloader uses this to avoid noop seeks when writing to a file.
#[derive(Debug)]
pub struct SeekOptimized<T> {
    inner: T,
    state: SeekOptimizedState,
}

impl<T> SeekOptimized<T> {
    ///
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            state: SeekOptimizedState::Unknown,
        }
    }

    ///
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[derive(Debug)]
enum SeekOptimizedState {
    Unknown,
    Seeking,
    FakeSeeking(u64),
    Known(u64),
}

impl SeekOptimizedState {
    fn take(&mut self) -> Self {
        std::mem::replace(self, SeekOptimizedState::Unknown)
    }

    fn is_seeking(&self) -> bool {
        matches!(
            self,
            SeekOptimizedState::Seeking | SeekOptimizedState::FakeSeeking(_)
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SeekOptimized<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(if self.state.is_seeking() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot read while seeking",
            ))
        } else {
            let before = buf.remaining();
            ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
            let after = buf.remaining();
            let read = before - after;
            if let SeekOptimizedState::Known(offset) = &mut self.state {
                *offset += read as u64;
            }
            Ok(())
        })
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SeekOptimized<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(if self.state.is_seeking() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write while seeking",
            ))
        } else {
            let result = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
            if let SeekOptimizedState::Known(offset) = &mut self.state {
                *offset += result as u64;
            }
            Ok(result)
        })
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

impl<T: AsyncSeek + Unpin> AsyncSeek for SeekOptimized<T> {
    fn start_seek(mut self: Pin<&mut Self>, seek_from: SeekFrom) -> io::Result<()> {
        self.state = match (self.state.take(), seek_from) {
            (SeekOptimizedState::Known(offset), SeekFrom::Current(0)) => {
                // somebody wants to know the current position
                SeekOptimizedState::FakeSeeking(offset)
            }
            (SeekOptimizedState::Known(offset), SeekFrom::Start(current)) if offset == current => {
                // seek to the current position
                SeekOptimizedState::FakeSeeking(offset)
            }
            _ => {
                // if start_seek fails, we go into unknown state
                Pin::new(&mut self.inner).start_seek(seek_from)?;
                SeekOptimizedState::Seeking
            }
        };
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        // if we are in fakeseeking state, intercept the call to the inner
        if let SeekOptimizedState::FakeSeeking(offset) = self.state {
            self.state = SeekOptimizedState::Known(offset);
            return Poll::Ready(Ok(offset));
        }
        // in all other cases we have to do the call to the inner
        //
        // a tokio file can be busy even when it seems idle, because write ops
        // are buffered. so we have to poll_complete until it returns Ok.
        let res = ready!(Pin::new(&mut self.inner).poll_complete(cx))?;
        if let SeekOptimizedState::Seeking = self.state {
            self.state = SeekOptimizedState::Known(res);
        }
        Poll::Ready(Ok(res))
    }
}

pub(crate) async fn read_as_bytes(reader: &mut Either<Cursor<Bytes>, File>) -> io::Result<Bytes> {
    match reader {
        Either::Left(cursor) => Ok(cursor.get_ref().clone()),
        Either::Right(file) => {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).await?;
            Ok(buf.into())
        }
    }
}
