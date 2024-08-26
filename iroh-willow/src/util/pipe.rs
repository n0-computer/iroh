use std::{
    cell::RefCell,
    future::{poll_fn, Future},
    io,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use futures_lite::Stream;
use iroh_io::AsyncStreamWriter;

/// In-memory local-io async pipe between a [`AsyncStreamWriter`] and a [`Stream`] of [`Bytes`].
///
/// The pipe maintains a shared in-memory buffer of `chunk_size`
///
/// [`PipeWriter`] is a [`AsyncStreamWriter`] that writes into the shared buffer.
///
/// [`PipeReader`] is [`Stream`] that emits [`Bytes`] of `chunk_size` length. The last chunk may be
/// smaller than `chunk_size`.
///
/// The pipe is closed once either the reader or the writer are dropped. If the reader is dropped,
/// subsequent writes will fail with [`io::ErrorKind::BrokenPipe`].
// TODO: Move to iroh-io?
pub fn chunked_pipe(chunk_size: usize) -> (PipeWriter, PipeReader) {
    let shared = Shared {
        buf: BytesMut::new(),
        chunk_size,
        read_waker: None,
        write_waker: None,
        closed: false,
    };
    let shared = Rc::new(RefCell::new(shared));
    let writer = PipeWriter {
        shared: shared.clone(),
    };
    let reader = PipeReader { shared };
    (writer, reader)
}

#[derive(Debug)]
struct Shared {
    buf: BytesMut,
    chunk_size: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    closed: bool,
}

impl Shared {
    fn poll_write(&mut self, data: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after close",
            )));
        }
        let remaining = self.chunk_size - self.buf.len();
        let amount = data.len().min(remaining);
        if amount > 0 {
            self.buf.extend_from_slice(&data[..amount]);
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Ok(amount))
        } else {
            self.write_waker = Some(cx.waker().to_owned());
            Poll::Pending
        }
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        if self.buf.len() == self.chunk_size {
            if let Some(write_waker) = self.write_waker.take() {
                write_waker.wake();
            }
            Poll::Ready(Some(Ok(self.buf.split().freeze())))
        } else if self.closed && !self.buf.is_empty() {
            Poll::Ready(Some(Ok(self.buf.split().freeze())))
        } else if self.closed {
            Poll::Ready(None)
        } else {
            self.read_waker = Some(cx.waker().to_owned());
            Poll::Pending
        }
    }

    fn close(&mut self) {
        self.closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

/// The writer returned from [`chunked_pipe`].
#[derive(Debug)]
pub struct PipeWriter {
    shared: Rc<RefCell<Shared>>,
}

/// The reader returned from [`chunked_pipe`].
#[derive(Debug)]
pub struct PipeReader {
    shared: Rc<RefCell<Shared>>,
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        let mut shared = self.shared.borrow_mut();
        shared.close();
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        let mut shared = self.shared.borrow_mut();
        shared.close();
    }
}

impl AsyncStreamWriter for PipeWriter {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < data.len() {
            written += poll_fn(|cx| {
                let mut shared = self.shared.borrow_mut();
                shared.poll_write(&data[written..], cx)
            })
            .await?;
        }
        Ok(())
    }

    async fn write_bytes(&mut self, data: bytes::Bytes) -> io::Result<()> {
        self.write(&data[..]).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream for PipeReader {
    type Item = io::Result<Bytes>;

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut shared = self.shared.borrow_mut();
        shared.poll_next(cx)
    }
}

pin_project_lite::pin_project! {
    /// A stream that polls a future on each call to poll_next.
    ///
    /// Once the future returned ready, it will not be polled anymore.
    ///
    /// If the future returns an error, the error will be forwarded.
    #[derive(Debug)]
    pub struct ProgressingStream<S, F> {
        #[pin]
        stream: S,
        #[pin]
        fut: F,
        fut_done: bool,
    }
}

impl<S, F, T, E> ProgressingStream<S, F>
where
    S: Stream<Item = Result<T, E>>,
    F: Future<Output = Result<(), E>>,
{
    pub fn new(stream: S, fut: F) -> Self {
        Self {
            stream,
            fut,
            fut_done: false,
        }
    }
}

impl<S, F, T, E> Stream for ProgressingStream<S, F>
where
    S: Stream<Item = Result<T, E>>,
    F: Future<Output = Result<(), E>>,
{
    type Item = Result<T, E>;

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if !*this.fut_done {
            match this.fut.poll(cx) {
                Poll::Ready(Ok(())) => {
                    *this.fut_done = true;
                }
                Poll::Ready(Err(err)) => {
                    *this.fut_done = true;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Pending => {}
            }
        }
        this.stream.poll_next(cx)
    }
}
