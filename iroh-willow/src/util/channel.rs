use std::{
    io,
    marker::PhantomData,
    sync::{Arc, Mutex},
    task::Waker,
};

use anyhow::anyhow;
use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::Notify;
use tracing::trace;

use super::{DecodeOutcome, Decoder, Encoder};

pub fn channel<T: Encoder + Decoder>(cap: usize) -> (Sender<T>, Receiver<T>) {
    let shared = Shared::new(cap);
    let shared = Arc::new(Mutex::new(shared));
    let sender = Sender {
        shared: shared.clone(),
        _ty: PhantomData,
    };
    let receiver = Receiver {
        shared,
        _ty: PhantomData,
    };
    (sender, receiver)
}

#[derive(Debug)]
pub enum ReadOutcome<T> {
    BufferEmpty,
    Closed,
    Item(T),
}

#[derive(Debug)]
pub enum WriteOutcome {
    BufferFull,
    Closed,
    Ok,
}

#[derive(Debug)]
struct Shared {
    buf: BytesMut,
    max_buffer_size: usize,
    notify_readable: Arc<Notify>,
    notify_writable: Arc<Notify>,
    wakers_on_writable: Vec<Waker>,
    wakers_on_readable: Vec<Waker>,
    closed: bool,
}

impl Shared {
    fn new(cap: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_buffer_size: cap,
            notify_readable: Default::default(),
            notify_writable: Default::default(),
            wakers_on_writable: Default::default(),
            wakers_on_readable: Default::default(),
            closed: false,
        }
    }
    fn close(&mut self) {
        self.closed = true;
        self.notify_writable();
        self.notify_readable();
    }

    fn closed(&self) -> bool {
        self.closed
    }

    fn peek_read(&self) -> &[u8] {
        &self.buf[..]
    }

    fn recv_buf_is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_advance(&mut self, cnt: usize) {
        self.buf.advance(cnt);
        if cnt > 0 {
            self.notify_writable();
        }
    }

    fn recv_bytes(&mut self) -> Bytes {
        let len = self.buf.len();
        if len > 0 {
            self.notify_writable();
        }
        self.buf.split_to(len).freeze()
    }

    fn writable_mut(&mut self, len: usize) -> Option<&mut [u8]> {
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

    fn send_message<T: Encoder>(&mut self, item: &T) -> anyhow::Result<WriteOutcome> {
        let len = item.encoded_len();
        if self.closed() {
            return Ok(WriteOutcome::Closed);
        }
        if let Some(slice) = self.writable_mut(len) {
            let mut cursor = io::Cursor::new(slice);
            item.encode_into(&mut cursor)?;
            self.notify_readable();
            Ok(WriteOutcome::Ok)
        } else {
            Ok(WriteOutcome::BufferFull)
        }
    }

    fn recv_message<T: Decoder>(&mut self) -> anyhow::Result<ReadOutcome<T>> {
        let data = self.peek_read();
        trace!("read, remaining {}", data.len());
        let res = match T::decode_from(data)? {
            DecodeOutcome::NeedMoreData => {
                if self.closed() {
                    ReadOutcome::Closed
                } else {
                    ReadOutcome::BufferEmpty
                }
            }
            DecodeOutcome::Decoded { item, consumed } => {
                self.read_advance(consumed);
                ReadOutcome::Item(item)
            }
        };
        Ok(res)
    }

    fn remaining_write_capacity(&self) -> usize {
        self.max_buffer_size - self.buf.len()
    }

    fn notify_readable(&mut self) {
        self.notify_readable.notify_waiters();
        for waker in self.wakers_on_readable.drain(..) {
            waker.wake();
        }
    }
    fn notify_writable(&mut self) {
        self.notify_writable.notify_waiters();
        for waker in self.wakers_on_writable.drain(..) {
            waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct Receiver<T> {
    shared: Arc<Mutex<Shared>>,
    _ty: PhantomData<T>,
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _ty: PhantomData,
        }
    }
}

impl<T: Decoder> Receiver<T> {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    pub fn register_waker(&self, waker: Waker) {
        self.shared.lock().unwrap().wakers_on_readable.push(waker);
    }

    pub async fn read_bytes_async(&self) -> Option<Bytes> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                if !shared.recv_buf_is_empty() {
                    return Some(shared.recv_bytes());
                }
                if shared.closed() {
                    return None;
                }
                shared.notify_readable.clone()
            };
            notify.notified().await
        }
    }

    pub fn recv_message(&self) -> anyhow::Result<ReadOutcome<T>> {
        let mut shared = self.shared.lock().unwrap();
        let outcome = shared.recv_message()?;
        Ok(outcome)
    }

    pub async fn recv_message_async(&self) -> Option<anyhow::Result<T>> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                match shared.recv_message() {
                    Err(err) => return Some(Err(err)),
                    Ok(outcome) => match outcome {
                        ReadOutcome::BufferEmpty => shared.notify_readable.clone(),
                        ReadOutcome::Closed => return None,
                        ReadOutcome::Item(item) => {
                            return Some(Ok(item));
                        }
                    },
                }
            };
            notify.notified().await;
        }
    }
}

#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<Mutex<Shared>>,
    _ty: PhantomData<T>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _ty: PhantomData,
        }
    }
}

impl<T: Encoder> Sender<T> {
    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    pub fn register_waker(&self, waker: Waker) {
        self.shared.lock().unwrap().wakers_on_writable.push(waker);
    }

    pub async fn write_all_async(&self, data: &[u8]) -> anyhow::Result<()> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                if shared.closed() {
                    break Err(anyhow!("channel closed"));
                }
                if shared.remaining_write_capacity() < data.len() {
                    let notify = shared.notify_writable.clone();
                    notify.clone()
                } else {
                    let out = shared.writable_mut(data.len()).expect("just checked");
                    out.copy_from_slice(data);
                    shared.notify_readable();
                    break Ok(());
                }
            };
            notify.notified().await;
        }
    }

    pub fn send_message(&self, message: &T) -> anyhow::Result<WriteOutcome> {
        self.shared.lock().unwrap().send_message(message)
    }

    pub async fn send_message_async(&self, message: &T) -> anyhow::Result<()> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                match shared.send_message(message)? {
                    WriteOutcome::Ok => return Ok(()),
                    WriteOutcome::BufferFull => shared.notify_writable.clone(),
                    WriteOutcome::Closed => return Err(anyhow!("channel is closed")),
                }
            };
            notify.notified().await;
        }
    }
}
