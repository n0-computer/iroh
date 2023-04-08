use std::{task::Poll, io::{self, SeekFrom}, pin::Pin};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, AsyncSeek};

#[derive(Debug)]
pub(crate) struct TrackingReader<R> {
    inner: R,
    read: u64,
}

impl<R> TrackingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }

    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    pub fn into_inner(self) -> R {
        self.inner
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

pub(crate) struct TrackingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> TrackingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn into_inner(self) -> W {
        self.inner
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

///
#[derive(Debug)]
pub(crate) struct SeekOptimized<T> {
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
        matches!(self, SeekOptimizedState::Seeking | SeekOptimizedState::FakeSeeking(_))
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
