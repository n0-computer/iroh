use std::{
    future::poll_fn,
    io,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{self, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_lite::Stream;
use tokio::io::AsyncWrite;

use crate::util::codec::{DecodeOutcome, Decoder, Encoder};

pub fn pipe(cap: usize) -> (Writer, Reader) {
    let shared = Shared::new(cap, Guarantees::Unlimited);
    let writer = Writer {
        shared: shared.clone(),
    };
    let reader = Reader { shared };
    (writer, reader)
}

pub fn outbound_channel<T: Encoder>(cap: usize, guarantees: Guarantees) -> (Sender<T>, Reader) {
    let shared = Shared::new(cap, guarantees);
    let sender = Sender {
        shared: shared.clone(),
        _ty: PhantomData,
    };
    let reader = Reader { shared };
    (sender, reader)
}

pub fn inbound_channel<T: Decoder>(cap: usize) -> (Writer, Receiver<T>) {
    let shared = Shared::new(cap, Guarantees::Unlimited);
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

#[derive(Debug)]
pub enum Guarantees {
    Unlimited,
    Limited(u64),
}

impl Guarantees {
    pub fn add(&mut self, amount: u64) {
        *self = match self {
            Self::Unlimited => Self::Unlimited,
            Self::Limited(ref mut current) => Self::Limited(current.wrapping_add(amount)),
        }
    }

    pub fn get(&self) -> u64 {
        match self {
            Self::Unlimited => u64::MAX,
            Self::Limited(current) => *current,
        }
    }

    pub fn r#use(&mut self, amount: u64) {
        *self = match self {
            Self::Unlimited => Self::Unlimited,
            Self::Limited(current) => Self::Limited(current.wrapping_sub(amount)),
        }
    }
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
    guarantees: Guarantees,
}

impl Shared {
    fn new(cap: usize, guarantees: Guarantees) -> Arc<Mutex<Self>> {
        let shared = Self {
            buf: BytesMut::new(),
            max_buffer_size: cap,
            write_wakers: Default::default(),
            read_wakers: Default::default(),
            is_closed: false,
            guarantees,
        };
        Arc::new(Mutex::new(shared))
    }

    fn set_cap(&mut self, cap: usize) -> bool {
        if cap >= self.buf.len() {
            self.max_buffer_size = cap;
            self.wake_writable();
            true
        } else {
            false
        }
    }

    fn add_guarantees(&mut self, amount: u64) {
        let previous = self.remaining_write_capacity();
        self.guarantees.add(amount);
        if self.remaining_write_capacity() > previous {
            self.wake_writable();
        }
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
        tracing::trace!(
            "write {}, remaining {} (guarantees {}, buf capacity {})",
            len,
            self.remaining_write_capacity(),
            self.guarantees.get(),
            self.max_buffer_size - self.buf.len()
        );
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
        let avail = self.remaining_write_capacity();
        if avail == 0 {
            self.write_wakers.push(cx.waker().to_owned());
            return Poll::Pending;
        }

        let len = std::cmp::min(buf.len(), avail);
        self.buf.extend_from_slice(&buf[..len]);
        self.guarantees.r#use(len as u64);
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
            self.guarantees.r#use(len as u64);
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
        std::cmp::min(
            self.max_buffer_size - self.buf.len(),
            self.guarantees.get() as usize,
        )
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
    pub fn max_buffer_size(&self) -> usize {
        self.shared.lock().unwrap().max_buffer_size
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

    pub fn set_cap(&self, cap: usize) -> bool {
        self.shared.lock().unwrap().set_cap(cap)
    }

    pub async fn send_message(&self, message: &T) -> Result<(), WriteError> {
        poll_fn(|cx| self.shared.lock().unwrap().poll_send_message(message, cx)).await
    }

    pub fn add_guarantees(&self, amount: u64) {
        self.shared.lock().unwrap().add_guarantees(amount)
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

    pub fn set_cap(&self, cap: usize) -> bool {
        self.shared.lock().unwrap().set_cap(cap)
    }

    pub async fn recv(&self) -> Option<Result<T, ReadError>> {
        poll_fn(|cx| self.shared.lock().unwrap().poll_recv_message(cx)).await
    }
}

impl<T: Decoder> Stream for Receiver<T> {
    type Item = Result<T, ReadError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        self.shared.lock().unwrap().poll_recv_message(cx)
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
