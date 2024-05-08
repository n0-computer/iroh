use std::{
    io,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::Notify;
use tracing::{debug, info, trace};

use crate::proto::wgps::Message;

use super::{DecodeOutcome, Decoder, Encoder};

#[derive(Debug)]
struct Shared {
    buf: BytesMut,
    max_buffer_size: usize,
    notify_readable: Arc<Notify>,
    notify_writable: Arc<Notify>,
    write_blocked: bool,
    need_read_notify: bool,
    need_write_notify: bool,
    closed: bool,
}

impl Shared {
    fn new(cap: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_buffer_size: cap,
            notify_readable: Default::default(),
            notify_writable: Default::default(),
            write_blocked: false,
            need_read_notify: false,
            need_write_notify: false,
            closed: false,
        }
    }
    fn close(&mut self) {
        self.closed = true;
        self.notify_writable.notify_waiters();
        self.notify_readable.notify_waiters();
    }
    fn closed(&self) -> bool {
        self.closed
    }
    fn read_slice(&self) -> &[u8] {
        &self.buf[..]
    }

    fn read_buf_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_advance(&mut self, cnt: usize) {
        self.buf.advance(cnt);
        if cnt > 0 {
            // self.write_blocked = false;
            self.notify_writable.notify_waiters();
        }
    }

    fn read_bytes(&mut self) -> Bytes {
        let len = self.buf.len();
        if len > 0 {
            // self.write_blocked = false;
            self.notify_writable.notify_waiters();
        }
        self.buf.split_to(len).freeze()
    }

    fn write_slice(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.remaining_write_capacity() < len {
            self.write_blocked = true;
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
        // debug!(?item, len = len, "write_message");
        if let Some(slice) = self.write_slice(len) {
            // debug!(len = slice.len(), "write_message got slice");
            let mut cursor = io::Cursor::new(slice);
            item.encode_into(&mut cursor)?;
            // debug!("RES {res:?}");
            // res?;
            self.notify_readable.notify_one();
            // debug!("wrote and notified");
            Ok(WriteOutcome::Ok)
        } else {
            Ok(WriteOutcome::BufferFull)
        }
    }

    fn read_message<T: Decoder>(&mut self) -> anyhow::Result<ReadOutcome<T>> {
        let data = self.read_slice();
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

    // fn receiver_want_notify(&mut self::) {
    //     self.need_read_notify = true;
    // }
    // fn need_write_notify(&mut self) {
    //     self.need_write_notify = true;
    // }

    fn remaining_write_capacity(&self) -> usize {
        self.max_buffer_size - self.buf.len()
    }
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
    Ok,
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
    pub fn read_bytes(&self) -> Bytes {
        self.shared.lock().unwrap().read_bytes()
    }

    pub async fn read_bytes_async(&self) -> Option<Bytes> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                if !shared.read_buf_empty() {
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

    pub fn read_message_or_set_notify(&self) -> anyhow::Result<ReadOutcome<T>> {
        let mut shared = self.shared.lock().unwrap();
        let outcome = shared.read_message()?;
        if matches!(outcome, ReadOutcome::ReadBufferEmpty) {
            shared.need_read_notify = true;
        }
        Ok(outcome)
    }

    pub fn set_notify_on_receivable(&self) {
        self.shared.lock().unwrap().need_read_notify = true;
    }
    pub fn is_sendable_notify_set(&self) -> bool {
        self.shared.lock().unwrap().need_write_notify
    }
    pub async fn notify_readable(&self) {
        let shared = self.shared.lock().unwrap();
        if !shared.read_slice().is_empty() {
            return;
        }
        let notify = shared.notify_readable.clone();
        drop(shared);
        notify.notified().await
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
                            // debug!("read_message_async read");
                            return Some(Ok(item));
                        }
                    },
                }
            };
            // debug!("read_message_async NeedMoreData wait");
            notify.notified().await;
            // debug!("read_message_async NeedMoreData notified");
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
    // fn write_slice_into(&self, len: usize) -> Option<&mut [u8]> {
    //     let mut shared = self.shared.lock().unwrap();
    //     shared.write_slice(len)
    // }
    pub fn set_notify_on_sendable(&self) {
        self.shared.lock().unwrap().need_write_notify = true;
    }

    pub fn is_receivable_notify_set(&self) -> bool {
        self.shared.lock().unwrap().need_read_notify
    }

    pub fn close(&self) {
        self.shared.lock().unwrap().close()
    }

    // fn write_slice(&self, data: &[u8]) -> bool {
    //     let mut shared = self.shared.lock().unwrap();
    //     match shared.write_slice(data.len()) {
    //         None => false,
    //         Some(out) => {
    //             out.copy_from_slice(data);
    //             true
    //         }
    //     }
    // }

    pub async fn write_slice_async(&self, data: &[u8]) {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                if shared.remaining_write_capacity() < data.len() {
                    let notify = shared.notify_writable.clone();
                    notify.clone()
                } else {
                    let out = shared.write_slice(data.len()).expect("just checked");
                    out.copy_from_slice(data);
                    shared.notify_readable.notify_waiters();
                    break;
                    // return true;
                }
            };
            notify.notified().await;
        }
    }

    pub async fn notify_writable(&self) {
        let shared = self.shared.lock().unwrap();
        if shared.remaining_write_capacity() > 0 {
            return;
        }
        let notify = shared.notify_readable.clone();
        drop(shared);
        notify.notified().await;
    }

    fn remaining_write_capacity(&self) -> usize {
        self.shared.lock().unwrap().remaining_write_capacity()
    }

    pub fn send_or_set_notify(&self, message: &T) -> anyhow::Result<WriteOutcome> {
        let mut shared = self.shared.lock().unwrap();
        let outcome = shared.write_message(message)?;
        if matches!(outcome, WriteOutcome::BufferFull) {
            shared.need_write_notify = true;
        }
        debug!("send buf remaining: {}", shared.remaining_write_capacity());
        Ok(outcome)
    }

    pub fn send(&self, message: &T) -> anyhow::Result<WriteOutcome> {
        self.shared.lock().unwrap().write_message(message)
    }

    // pub async fn sNamespacePublicKeyend_co<F, Fut>(
    //     &self,
    //     message: &T,
    //     yield_fn: F,
    //     // co: &genawaiter::sync::Co<Y, R>,
    //     // yield_value: Y,
    // ) -> anyhow::Result<()>
    // where
    //     F: Fn() -> Fut,
    //     Fut: std::future::Future<Output = ()>,
    // {
    //     loop {
    //         let res = self.shared.lock().unwrap().write_message(message)?;
    //         match res {
    //             WriteOutcome::BufferFull => (yield_fn)().await,
    //             WriteOutcome::Ok => break Ok(()),
    //         }
    //     }
    // }

    pub async fn send_async(&self, message: &T) -> anyhow::Result<()> {
        loop {
            let notify = {
                let mut shared = self.shared.lock().unwrap();
                match shared.write_message(message)? {
                    WriteOutcome::Ok => return Ok(()),
                    WriteOutcome::BufferFull => shared.notify_writable.clone(),
                }
            };
            notify.notified().await;
        }
    }
}

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

// #[derive(Debug)]
// pub struct ChannelSender {
//     id: u64,
//     buf: rtrb::Producer<u8>,
//     // waker: Option<Waker>,
// }
//
// impl ChannelSender {
//     pub fn remaining_capacity(&self) -> usize {
//         self.buf.slots()
//     }
//     pub fn can_write_message(&mut self, message: &Message) -> bool {
//         message.encoded_len() <= self.remaining_capacity()
//     }
//
//     pub fn write_message(&mut self, message: &Message) -> bool {
//         let encoded_len = message.encoded_len();
//         if encoded_len > self.remaining_capacity() {
//             return false;
//         }
//         message.encode_into(&mut self.buf).expect("length checked");
//         if let Some(waker) = self.waker.take() {
//             waker.wake();
//         }
//         true
//     }
//
//     pub fn set_waker(&mut self, waker: Waker) {
//         self.waker = Some(waker);
//     }
// }
//
// #[derive(Debug)]
// pub enum ToStoreActor {
//     // NotifyWake(u64, Arc<Notify>),
//     Resume(u64),
// }
//
// #[derive(Debug)]
// pub struct ChannelReceiver {
//     id: u64,
//     // buf: rtrb::Consumer<u8>,
//     buf: BytesMut,
//     to_actor: flume::Sender<ToStoreActor>,
//     notify_readable: Arc<Notify>,
// }
//
// impl ChannelReceiver {
//     pub async fn read_chunk(&mut self) -> Result<ReadChunk<'_, u8>, ChunkError> {
//         if self.is_empty() {
//             self.acquire().await;
//         }
//         self.buf.read_chunk(self.readable_len())
//     }
//
//     pub fn is_empty(&self) -> bool {
//         self.buf.is_empty()
//     }
//
//     pub fn readable_len(&self) -> usize {
//         self.buf.slots()
//     }
//
//     pub async fn resume(&mut self) {
//         self.to_actor
//             .send_async(ToStoreActor::Resume(self.id))
//             .await
//             .unwrap();
//     }
//
//     pub async fn acquire(&mut self) {
//         if !self.is_empty() {
//             return;
//         }
//         self.notify_readable.notified().await;
//     }
// }
//
// pub struct ChannelSender {
//     id: u64,
//     buf: rtrb::Producer<u8>,
//     to_actor: flume::Sender<ToStoreActor>,
//     notify_readable: Arc<Notify>,
// }
//
// impl ChannelSender {
//     pub
// }
