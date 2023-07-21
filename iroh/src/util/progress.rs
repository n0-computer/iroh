//! Generic utilities to track progress of data transfers.
//!
//! This is not especially specific to iroh but can be helpful together with it.  The
//! [`ProgressEmitter`] has a [`ProgressEmitter::wrap_async_read`] method which can make it
//! easy to track process of transfers.
//!
//! However based on your environment there might also be better choices for this, e.g. very
//! similar and more advanced functionality is available in the `indicatif` crate for
//! terminal applications.

use std::fmt;
use std::io::Read;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;

use bytes::Bytes;
use iroh_bytes::util::io::TrackingWriter;
use iroh_io::AsyncSliceWriter;
use portable_atomic::{AtomicU16, AtomicU64};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};

/// A generic progress event emitter.
///
/// It is created with a total value to reach and at which increments progress should be
/// emitted.  E.g. when downloading a file of any size but you want percentage increments
/// you would create `ProgressEmitter::new(file_size_in_bytes, 100)` and
/// [`ProgressEmitter::subscribe`] will yield numbers `1..100` only.
///
/// Progress is made by calling [`ProgressEmitter::inc`], which can be implicitly done by
/// [`ProgressEmitter::wrap_async_read`].
#[derive(Debug, Clone)]
pub struct ProgressEmitter {
    inner: Arc<InnerProgressEmitter>,
}

impl ProgressEmitter {
    /// Creates a new emitter.
    ///
    /// The emitter expects to see *total* being added via [`ProgressEmitter::inc`] and will
    /// emit *steps* updates.
    pub fn new(total: u64, steps: u16) -> Self {
        let (tx, _rx) = broadcast::channel(16);
        Self {
            inner: Arc::new(InnerProgressEmitter {
                total: AtomicU64::new(total),
                count: AtomicU64::new(0),
                steps,
                last_step: AtomicU16::new(0u16),
                tx,
            }),
        }
    }

    /// Sets a new total in case you did not now the total up front.
    pub fn set_total(&self, value: u64) {
        self.inner.set_total(value)
    }

    /// Returns a receiver that gets incremental values.
    ///
    /// The values yielded depend on *steps* passed to [`ProgressEmitter::new`]: it will go
    /// from `1..steps`.
    pub fn subscribe(&self) -> broadcast::Receiver<u16> {
        self.inner.subscribe()
    }

    /// Increments the progress by *amount*.
    pub fn inc(&self, amount: u64) {
        self.inner.inc(amount);
    }

    /// Wraps an [`AsyncRead`] which implicitly calls [`ProgressEmitter::inc`].
    pub fn wrap_async_read<R: AsyncRead + Unpin>(&self, read: R) -> ProgressAsyncReader<R> {
        ProgressAsyncReader {
            emitter: self.clone(),
            inner: read,
        }
    }
}

/// The actual implementation.
///
/// This exists so it can be Arc'd into [`ProgressEmitter`] and we can easily have multiple
/// `Send + Sync` copies of it.  This is used by the
/// [`ProgressAsyncReader`] to update the progress without intertwining
/// lifetimes.
#[derive(Debug)]
struct InnerProgressEmitter {
    total: AtomicU64,
    count: AtomicU64,
    steps: u16,
    last_step: AtomicU16,
    tx: broadcast::Sender<u16>,
}

impl InnerProgressEmitter {
    fn inc(&self, amount: u64) {
        let prev_count = self.count.fetch_add(amount, Ordering::Relaxed);
        let count = prev_count + amount;
        let total = self.total.load(Ordering::Relaxed);
        let step = (std::cmp::min(count, total) * u64::from(self.steps) / total) as u16;
        let last_step = self.last_step.swap(step, Ordering::Relaxed);
        if step > last_step {
            self.tx.send(step).ok();
        }
    }

    fn set_total(&self, value: u64) {
        self.total.store(value, Ordering::Relaxed);
    }

    fn subscribe(&self) -> broadcast::Receiver<u16> {
        self.tx.subscribe()
    }
}

/// A wrapper around [`AsyncRead`] which increments a [`ProgressEmitter`].
///
/// This can be used just like the underlying [`AsyncRead`] but increments progress for each
/// byte read.  Create this using [`ProgressEmitter::wrap_async_read`].
#[derive(Debug)]
pub struct ProgressAsyncReader<R: AsyncRead + Unpin> {
    emitter: ProgressEmitter,
    inner: R,
}

impl<R> AsyncRead for ProgressAsyncReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let prev_len = buf.filled().len() as u64;
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(val) => {
                let new_len = buf.filled().len() as u64;
                self.emitter.inc(new_len - prev_len);
                Poll::Ready(val)
            }
            Poll::Pending => Poll::Pending,
        }
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

impl<W: AsyncSliceWriter + 'static> AsyncSliceWriter for ProgressSliceWriter<W> {
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

/// A sender for progress messages.
///
/// This may optionally be a no-op if the [`Progress::none`] constructor is used.
#[derive(Debug)]
pub struct Progress<T>(Option<mpsc::Sender<T>>);

impl<T> Clone for Progress<T> {
    fn clone(&self) -> Self {
        Progress(self.0.clone())
    }
}

impl<T: fmt::Debug + Send + Sync + 'static> Progress<T> {
    /// Create a new progress sender.
    #[allow(dead_code)]
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self(Some(sender))
    }

    /// Create a no-op progress sender.
    pub fn none() -> Self {
        Self(None)
    }

    /// Try to send a message.
    pub fn try_send(&self, msg: T) {
        if let Some(progress) = &self.0 {
            progress.try_send(msg).ok();
        }
    }

    /// Block until the message is sent.
    pub fn blocking_send(&self, msg: T) {
        if let Some(progress) = &self.0 {
            progress.blocking_send(msg).ok();
        }
    }

    /// Send a message
    pub async fn send(&self, msg: T) -> anyhow::Result<()> {
        if let Some(progress) = &self.0 {
            progress.send(msg).await?;
        }
        Ok(())
    }
}

pub(crate) struct ProgressReader<R, F: Fn(ProgressReaderUpdate)> {
    inner: R,
    offset: u64,
    cb: F,
}

impl<R: Read, F: Fn(ProgressReaderUpdate)> ProgressReader<R, F> {
    #[allow(dead_code)]
    pub fn new(inner: R, cb: F) -> Self {
        Self {
            inner,
            offset: 0,
            cb,
        }
    }
}

impl<R: Read, F: Fn(ProgressReaderUpdate)> Read for ProgressReader<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.offset += read as u64;
        (self.cb)(ProgressReaderUpdate::Progress(self.offset));
        Ok(read)
    }
}

impl<R, F: Fn(ProgressReaderUpdate)> Drop for ProgressReader<R, F> {
    fn drop(&mut self) {
        (self.cb)(ProgressReaderUpdate::Done);
    }
}

/// Update from a [`ProgressReader`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum ProgressReaderUpdate {
    /// A progress event containing the current offset.
    Progress(u64),
    /// The reader has been dropped.
    Done,
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast::error::TryRecvError;

    use super::*;

    #[test]
    fn test_inc() {
        let progress = ProgressEmitter::new(160, 16);
        let mut rx = progress.subscribe();

        progress.inc(1);
        assert_eq!(progress.inner.count.load(Ordering::Relaxed), 1);
        let res = rx.try_recv();
        assert!(matches!(res, Err(TryRecvError::Empty)));

        progress.inc(9);
        assert_eq!(progress.inner.count.load(Ordering::Relaxed), 10);
        let res = rx.try_recv();
        assert!(matches!(res, Ok(1)));

        progress.inc(30);
        assert_eq!(progress.inner.count.load(Ordering::Relaxed), 40);
        let res = rx.try_recv();
        assert!(matches!(res, Ok(4)));

        progress.inc(120);
        assert_eq!(progress.inner.count.load(Ordering::Relaxed), 160);
        let res = rx.try_recv();
        assert!(matches!(res, Ok(16)));
    }

    #[tokio::test]
    async fn test_async_reader() {
        // Note that the broadcast::Receiver has 16 slots, pushing more into them without
        // consuming will result in a (Try)RecvError::Lagged.
        let progress = ProgressEmitter::new(160, 16);
        let mut rx = progress.subscribe();

        let data = [1u8; 100];
        let mut wrapped_reader = progress.wrap_async_read(&data[..]);
        io::copy(&mut wrapped_reader, &mut io::sink())
            .await
            .unwrap();

        // Most likely this test will invoke a single AsyncRead::poll_read and thus only a
        // single event will be emitted.  But we can not really rely on this and can only
        // check the last value.
        let mut current = 0;
        while let Ok(val) = rx.try_recv() {
            current = val;
        }
        assert_eq!(current, 10);
    }
}
