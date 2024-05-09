use std::{
    io,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::anyhow;
use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::Notify;
use tracing::trace;

use crate::store::actor::AssignedWaker;

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
    ReadBufferEmpty,
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
    wakers_on_writable: Vec<AssignedWaker>,
    wakers_on_readable: Vec<AssignedWaker>,
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

    fn read_is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_advance(&mut self, cnt: usize) {
        self.buf.advance(cnt);
        if cnt > 0 {
            self.notify_writable();
        }
    }

    fn read_bytes(&mut self) -> Bytes {
        let len = self.buf.len();
        if len > 0 {
            self.notify_writable();
        }
        self.buf.split_to(len).freeze()
    }

    fn write_slice(&mut self, len: usize) -> Option<&mut [u8]> {
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

    fn write_message<T: Encoder>(&mut self, item: &T) -> anyhow::Result<WriteOutcome> {
        let len = item.encoded_len();
        if self.closed() {
            return Ok(WriteOutcome::Closed);
        }
        if let Some(slice) = self.write_slice(len) {
            let mut cursor = io::Cursor::new(slice);
            item.encode_into(&mut cursor)?;
            self.notify_readable();
            Ok(WriteOutcome::Ok)
        } else {
            Ok(WriteOutcome::BufferFull)
        }
    }

    fn read_message<T: Decoder>(&mut self) -> anyhow::Result<ReadOutcome<T>> {
        let data = self.peek_read();
        trace!("read, remaining {}", data.len());
        let res = match T::decode_from(data)? {
            DecodeOutcome::NeedMoreData => {
                if self.closed() {
                    ReadOutcome::Closed
                } else {
                    ReadOutcome::ReadBufferEmpty
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
            waker.wake().ok();
        }
    }
    fn notify_writable(&mut self) {
        self.notify_writable.notify_waiters();
        for waker in self.wakers_on_writable.drain(..) {
            waker.wake().ok();
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

    pub fn read_bytes(&self) -> Bytes {
        self.shared.lock().unwrap().read_bytes()
    }

    pub async fn read_bytes_async(&self) -> Option<Bytes> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                if !shared.read_is_empty() {
                    return Some(shared.read_bytes());
                }
                if shared.closed() {
                    return None;
                }
                shared.notify_readable.clone()
            };
            notify.notified().await
        }
    }

    pub fn read_message(&self) -> anyhow::Result<ReadOutcome<T>> {
        let mut shared = self.shared.lock().unwrap();
        let outcome = shared.read_message()?;
        Ok(outcome)
    }

    pub fn register_waker(&self, waker: AssignedWaker) {
        self.shared.lock().unwrap().wakers_on_readable.push(waker);
    }

    pub async fn recv_async(&self) -> Option<anyhow::Result<T>> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                match shared.read_message() {
                    Err(err) => return Some(Err(err)),
                    Ok(outcome) => match outcome {
                        ReadOutcome::ReadBufferEmpty => shared.notify_readable.clone(),
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

    pub fn register_waker(&self, waker: AssignedWaker) {
        self.shared.lock().unwrap().wakers_on_writable.push(waker);
    }

    pub async fn notify_closed(&self) {
        tracing::info!("notify_close IN");
        loop {
            let notify = {
                let shared = self.shared.lock().unwrap();
                if shared.closed() {
                    tracing::info!("notify_close closed!");
                    return;
                } else {
                    tracing::info!("notify_close not closed - wait");

                }
                shared.notify_writable.clone()
            };
            notify.notified().await;
        }
    }

    pub async fn write_slice_async(&self, data: &[u8]) -> anyhow::Result<()> {
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
                    let out = shared.write_slice(data.len()).expect("just checked");
                    out.copy_from_slice(data);
                    shared.notify_readable();
                    break Ok(());
                }
            };
            notify.notified().await;
        }
    }

    pub fn send(&self, message: &T) -> anyhow::Result<WriteOutcome> {
        self.shared.lock().unwrap().write_message(message)
    }

    pub async fn send_async(&self, message: &T) -> anyhow::Result<()> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                match shared.write_message(message)? {
                    WriteOutcome::Ok => return Ok(()),
                    WriteOutcome::BufferFull => shared.notify_writable.clone(),
                    WriteOutcome::Closed => return Err(anyhow!("channel is closed")),
                }
            };
            notify.notified().await;
        }
    }
}

// pub async fn notify_readable(&self) {
//     let shared = self.shared.lock().unwrap();
//     if !shared.peek_read().is_empty() {
//         return;
//     }
//     let notify = shared.notify_readable.clone();
//     drop(shared);
//     notify.notified().await
// }
//
