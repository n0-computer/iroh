use std::{
    future::poll_fn,
    io,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{self, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::AsyncWrite;
use tracing::trace;

use super::{DecodeOutcome, Decoder, Encoder};

pub fn pipe(cap: usize) -> (Writer, Reader) {
    let shared = Shared::new(cap);
    let writer = Writer {
        shared: shared.clone(),
    };
    let reader = Reader { shared };
    (writer, reader)
}

pub fn outbound_channel<T: Encoder>(cap: usize) -> (Sender<T>, Reader) {
    let shared = Shared::new(cap);
    let sender = Sender {
        shared: shared.clone(),
        _ty: PhantomData,
    };
    let reader = Reader { shared };
    (sender, reader)
}

pub fn inbound_channel<T: Decoder>(cap: usize) -> (Writer, Receiver<T>) {
    let shared = Shared::new(cap);
    let writer = Writer {
        shared: shared.clone(),
    };
    let receiver = Receiver {
        shared,
        _ty: PhantomData,
    };
    (writer, receiver)
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("writing to closed channel")]
    Closed,
    #[error("encoding failed: {0}")]
    Encode(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("channel closed with incomplete message")]
    ClosedIncomplete,
    #[error("decoding failed: {0}")]
    Decode(anyhow::Error),
}

// Shared state for a in-memory pipe.
//
// Roughly modeled after https://docs.rs/tokio/latest/src/tokio/io/util/mem.rs.html#58
#[derive(Debug)]
struct Shared {
    buf: BytesMut,
    max_buffer_size: usize,
    write_wakers: Vec<Waker>,
    read_wakers: Vec<Waker>,
    is_closed: bool,
}

impl Shared {
    fn new(cap: usize) -> Arc<Mutex<Self>> {
        let shared = Self {
            buf: BytesMut::new(),
            max_buffer_size: cap,
            write_wakers: Default::default(),
            read_wakers: Default::default(),
            is_closed: false,
        };
        Arc::new(Mutex::new(shared))
    }

    fn close(&mut self) {
        self.is_closed = true;
        self.wake_writable();
        self.wake_readable();
    }

    fn is_closed(&self) -> bool {
        self.is_closed
    }

    fn peek(&self) -> &[u8] {
        &self.buf[..]
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_bytes(&mut self) -> Bytes {
        let len = self.buf.len();
        if len > 0 {
            self.wake_writable();
        }
        self.buf.split_to(len).freeze()
    }

    fn writable_slice_exact(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.remaining_write_capacity() < len {
            None
        } else {
            let old_len = self.buf.len();
            let new_len = self.buf.remaining() + len;
            // TODO: check if the potential truncate harms perf
            self.buf.resize(new_len, 0u8);
            Some(&mut self.buf[old_len..new_len])
        }
    }

    fn poll_write(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.is_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let avail = self.max_buffer_size - self.buf.len();
        if avail == 0 {
            self.write_wakers.push(cx.waker().to_owned());
            return Poll::Pending;
        }

        let len = buf.len().min(avail);
        self.buf.extend_from_slice(&buf[..len]);
        self.wake_readable();
        Poll::Ready(Ok(len))
    }

    fn poll_read_bytes(&mut self, cx: &mut task::Context<'_>) -> Poll<Option<Bytes>> {
        if !self.is_empty() {
            Poll::Ready(Some(self.read_bytes()))
        } else if self.is_closed() {
            Poll::Ready(None)
        } else {
            self.read_wakers.push(cx.waker().to_owned());
            Poll::Pending
        }
    }

    fn poll_send_message<T: Encoder>(
        &mut self,
        item: &T,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), WriteError>> {
        if self.is_closed() {
            return Poll::Ready(Err(WriteError::Closed));
        }
        let len = item.encoded_len();
        if let Some(slice) = self.writable_slice_exact(len) {
            let mut cursor = io::Cursor::new(slice);
            item.encode_into(&mut cursor).map_err(WriteError::Encode)?;
            self.wake_readable();
            Poll::Ready(Ok(()))
        } else {
            self.write_wakers.push(cx.waker().to_owned());
            Poll::Pending
        }
    }

    fn poll_recv_message<T: Decoder>(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<T, ReadError>>> {
        let buf = self.peek();
        trace!("read, remaining {}", buf.len());
        if self.is_closed() && self.is_empty() {
            return Poll::Ready(None);
        }
        match T::decode_from(buf).map_err(ReadError::Decode)? {
            DecodeOutcome::NeedMoreData => {
                if self.is_closed() {
                    Poll::Ready(Some(Err(ReadError::ClosedIncomplete)))
                } else {
                    self.read_wakers.push(cx.waker().to_owned());
                    Poll::Pending
                }
            }
            DecodeOutcome::Decoded { item, consumed } => {
                self.buf.advance(consumed);
                self.wake_writable();
                Poll::Ready(Some(Ok(item)))
            }
        }
    }

    fn remaining_write_capacity(&self) -> usize {
        self.max_buffer_size - self.buf.len()
    }

    fn wake_readable(&mut self) {
        for waker in self.read_wakers.drain(..) {
            waker.wake();
        }
    }
    fn wake_writable(&mut self) {
        for waker in self.write_wakers.drain(..) {
            waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct Reader {
    shared: Arc<Mutex<Shared>>,
}

impl Reader {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    pub async fn read_bytes(&self) -> Option<Bytes> {
        poll_fn(|cx| self.shared.lock().unwrap().poll_read_bytes(cx)).await
    }
}

#[derive(Debug)]
pub struct Writer {
    shared: Arc<Mutex<Shared>>,
}

impl Writer {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.shared.lock().unwrap().poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<Mutex<Shared>>,
    _ty: PhantomData<T>,
}

impl<T: Encoder> Sender<T> {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    pub async fn send_message(&self, message: &T) -> Result<(), WriteError> {
        poll_fn(|cx| self.shared.lock().unwrap().poll_send_message(message, cx)).await
    }
}

#[derive(Debug)]
pub struct Receiver<T> {
    shared: Arc<Mutex<Shared>>,
    _ty: PhantomData<T>,
}

impl<T: Decoder> Receiver<T> {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    pub async fn recv_message(&self) -> Option<Result<T, ReadError>> {
        poll_fn(|cx| self.shared.lock().unwrap().poll_recv_message(cx)).await
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _ty: PhantomData,
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _ty: PhantomData,
        }
    }
}
