//! ufotofu wrappers for quinn send and receive streams

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use either::Either;
use futures_lite::Stream;
use quinn::{ReadError, RecvStream, SendStream};
use reusable_box_future::ReusableLocalBoxFuture as ReusableBoxFuture;
use tracing::trace;
use ufotofu::local_nb::{
    BufferedConsumer, BufferedProducer, BulkConsumer, BulkProducer, Consumer, Producer,
};
use willow_encoding::{Decodable, DecodeError, Encodable};

#[derive(Debug)]
pub struct Sender {
    stream: SendStream,
    buf: BytesMut,
    max_buffer_size: usize,
    state: ExposedSlots,
}

#[derive(Debug)]
enum ExposedSlots {
    None,
    Exposed { start: usize },
}

impl Sender {
    pub fn new(stream: SendStream, max_buffer_size: usize) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
            max_buffer_size,
            state: ExposedSlots::None,
        }
    }
    pub fn remaining(&self) -> usize {
        self.max_buffer_size - self.buf.len()
    }

    pub fn is_full(&self) -> bool {
        self.buf.len() == self.max_buffer_size
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub async fn send<T: Encodable>(&mut self, item: &T) -> io::Result<()> {
        item.encode(self).await?;
        self.flush().await?;
        Ok(())
    }
}

impl Consumer for Sender {
    type Item = u8;

    type Final = ();

    type Error = std::io::Error;

    async fn consume(&mut self, item: Self::Item) -> Result<(), Self::Error> {
        assert!(
            !matches!(self.state, ExposedSlots::None),
            "may not consume while slots are exposed"
        );
        if self.is_full() {
            self.flush().await?;
        }
        self.buf.put_u8(item);
        Ok(())
    }

    async fn close(&mut self, _fin: Self::Final) -> Result<(), Self::Error> {
        self.flush().await?;
        self.stream.finish().await?;
        Ok(())
    }
}

impl BufferedConsumer for Sender {
    async fn flush(&mut self) -> Result<(), Self::Error> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let buf = self.buf.split().freeze();
        trace!(len = buf.len(), "sender: flush");
        self.stream.write_chunk(buf).await?;
        Ok(())
    }
}

impl BulkConsumer for Sender {
    async fn expose_slots<'a>(&'a mut self) -> Result<&'a mut [Self::Item], Self::Error>
    where
        Self::Item: 'a,
    {
        assert!(
            matches!(self.state, ExposedSlots::None),
            "may not expose slots while slots are exposed"
        );

        if self.is_full() {
            self.flush().await?;
        }
        let start = self.buf.len();
        self.state = ExposedSlots::Exposed { start };
        self.buf.resize(self.max_buffer_size, 0u8);
        trace!(
            start = start,
            end = self.buf.len(),
            len = self.buf.len() - start,
            "expose_slots"
        );
        Ok(&mut self.buf[start..])
    }

    async fn consume_slots(&mut self, amount: usize) -> Result<(), Self::Error> {
        trace!(amount, "consume slots");
        match self.state {
            ExposedSlots::None => {
                panic!("may not consume slots without having slots exposed");
            }
            ExposedSlots::Exposed { start } => {
                let end = start + amount;
                if end > self.max_buffer_size {
                    panic!("amount cannot be larger than number of exposed slots");
                }
                self.buf.truncate(end);
                self.state = ExposedSlots::None;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct Receiver {
    stream: RecvStream,
    chunks: VecDeque<Bytes>,
    max_buffer_size: usize,
    closed: bool,
    produced: usize,
    exposed: bool,
}

impl Receiver {
    /// Create a new receiver.
    pub fn new(stream: RecvStream, max_buffer_size: usize) -> Self {
        Self {
            stream,
            max_buffer_size,
            chunks: Default::default(),
            closed: false,
            produced: 0,
            exposed: false,
        }
    }

    /// Returns true if the receiver stream is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns the number of bytes produced (emitted) by this receiver.
    pub fn produced(&self) -> usize {
        self.produced
    }

    fn remaining(&self) -> usize {
        self.max_buffer_size - self.len()
    }

    fn is_full(&self) -> bool {
        self.len() == self.max_buffer_size
    }

    fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// # Panics
    ///
    /// Panics if the buffer is empty.
    fn peek(&mut self) -> &[u8] {
        if !self.is_empty() {
            &self.chunks[0][..]
        } else {
            &[]
        }
    }

    /// # Panics
    ///
    /// Panics if the buffer is empty or `amount` is larger than the lenght of the slice returned
    /// by `peek`.
    fn consumed(&mut self, amount: usize) {
        let _ = self.chunks[0].split_to(amount);
        if self.chunks[0].is_empty() {
            let _ = self.chunks.pop_front();
        }
        self.produced += amount;
    }

    fn len(&self) -> usize {
        self.chunks.iter().map(|c| c.len()).sum()
    }
    /// # Panics
    ///
    /// Panics is our buffer is full.
    async fn progress(&mut self) -> Result<bool, ReadError> {
        assert!(!self.is_full());
        if self.closed {
            return Ok(false);
        }
        let chunk = self.stream.read_chunk(self.remaining(), true).await?;
        match chunk {
            None => {
                self.closed = true;
                Ok(false)
            }
            Some(buf) => {
                self.chunks.push_back(buf.bytes);
                Ok(true)
            }
        }
    }

    async fn progress_until(&mut self, min_len: usize) -> Result<bool, ReadError> {
        assert!(min_len <= self.max_buffer_size);
        while self.len() < min_len {
            if !self.progress().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Receives a decodable item from the stream.
    ///
    /// Returns `None` if the stream closed before having read anything.
    /// Returns an error if the decoding failed or the stream closed mid-message.
    pub async fn recv<T: Decodable>(&mut self) -> Option<Result<T, RecvError>> {
        let prev_amount = self.produced();
        match T::decode(self).await {
            Ok(item) => Some(Ok(item)),
            // TODO: Not sure if this is a hack or intended way of detecting graceful termination
            // (vs termination in the middle of a message)
            Err(DecodeError::InvalidInput)
                if self.is_closed() && self.produced() == prev_amount =>
            {
                None
            }
            Err(err) => Some(Err(RecvError(err))),
        }
    }
}

impl Producer for Receiver {
    type Item = u8;
    type Final = ();
    type Error = io::Error;

    async fn produce(&mut self) -> Result<Either<Self::Item, Self::Final>, Self::Error> {
        assert!(
            !self.exposed,
            "may not call produce while items are exposed"
        );
        if !self.progress_until(1).await? {
            return Ok(Either::Right(()));
        }
        let byte = self.peek()[0];
        self.consumed(1);
        Ok(Either::Left(byte))
    }
}

impl BufferedProducer for Receiver {
    async fn slurp(&mut self) -> Result<(), Self::Error> {
        if !self.is_full() {
            self.progress().await?;
        }
        Ok(())
    }
}

impl BulkProducer for Receiver {
    async fn expose_items<'a>(
        &'a mut self,
    ) -> Result<Either<&'a [Self::Item], Self::Final>, Self::Error>
    where
        Self::Item: 'a,
    {
        if self.is_empty() && !self.progress().await? {
            Ok(Either::Right(()))
        } else {
            self.exposed = true;
            Ok(Either::Left(self.peek()))
        }
    }

    async fn consider_produced(&mut self, amount: usize) -> Result<(), Self::Error> {
        self.consumed(amount);
        self.exposed = false;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RecvError(DecodeError<io::Error>);

/// Wrap a [`Receiver`] in a stream of decodable items.
#[derive(Debug)]
pub struct MessageReceiver<T> {
    #[allow(clippy::type_complexity)]
    next: Option<ReusableBoxFuture<(Receiver, Option<Result<T, RecvError>>)>>,
}

impl<T: Decodable> MessageReceiver<T> {
    /// Create a new [`MessageReceiver`]
    pub fn new(mut receiver: Receiver) -> Self {
        let fut = async move {
            let res = receiver.recv().await;
            (receiver, res)
        };
        let fut = ReusableBoxFuture::new(fut);
        Self { next: Some(fut) }
    }
}

impl<T: Decodable> Stream for MessageReceiver<T> {
    type Item = Result<T, RecvError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.next.as_mut() {
            None => Poll::Ready(None),
            Some(fut) => match fut.poll(cx) {
                Poll::Ready((mut receiver, res)) => {
                    if res.is_none() {
                        self.next = None;
                    } else {
                        let next_fut = async move {
                            let res = receiver.recv().await;
                            (receiver, res)
                        };
                        fut.set(next_fut);
                    }
                    Poll::Ready(res)
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use anyhow::Context;
    use futures_concurrency::future::TryJoin;
    use futures_lite::StreamExt;
    use iroh_blobs::Hash;
    use iroh_net::{relay::RelayMode, Endpoint};
    use tracing::info;

    use crate::proto::{
        data_model::{Component, Entry, Path, SubspaceId},
        keys::NamespaceId,
    };

    use super::*;

    const ALPN: &[u8] = b"foo";
    #[tokio::test(flavor = "multi_thread")]
    async fn ufo1() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let ep1 = Endpoint::builder()
            .secret_key([0u8; 32].into())
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let ep2 = Endpoint::builder()
            .secret_key([1u8; 32].into())
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;

        let addr1 = ep1.node_addr().await?;
        info!("endpoints ready");

        let (conn1, conn2) = (
            async {
                ep1.accept()
                    .await
                    .context("endpoint closed")?
                    .await
                    .context("accept failed")
            },
            ep2.connect(addr1, ALPN),
        )
            .try_join()
            .await?;

        info!("conns ready");

        let send_buf_size = 1024;
        let recv_buf_size = send_buf_size;

        let start = Instant::now();
        let send_count = 2000;
        let local = tokio::task::LocalSet::new();
        let task_send = local.spawn_local(async move {
            let send_stream = conn1.open_uni().await?;
            info!("send stream ready");
            let mut sender = Sender::new(send_stream, send_buf_size);
            info!("send start");
            let entry = some_entry();
            for i in 0..send_count {
                sender.send(&entry).await?;
                if i % 100 == 0 {
                    info!(?i, "sent");
                }
            }
            info!("send finished");
            sender.close(()).await?;
            info!("send closed");
            Result::<_, anyhow::Error>::Ok(())
        });

        let task_recv = local.spawn_local(async move {
            let recv_stream = conn2.accept_uni().await?;
            info!("recv stream ready");
            let receiver = Receiver::new(recv_stream, recv_buf_size);
            let mut receiver = MessageReceiver::<Entry>::new(receiver);
            let mut i = 0;
            while let Some(_received_entry) = receiver.try_next().await? {
                if i % 100 == 0 {
                    info!(?i, "recv decoded");
                }
                i += 1;
            }
            info!("recv closed after {i}");
            Result::<_, anyhow::Error>::Ok(i)
        });

        let i = local
            .run_until(async move {
                task_send.await??;
                let i = task_recv.await??;
                Result::<_, anyhow::Error>::Ok(i)
            })
            .await?;

        info!(time=?start.elapsed(), "done");
        assert_eq!(i, send_count);

        Ok(())
    }

    fn some_entry() -> Entry {
        let path = Path::new_from_slice(&[
            Component::new(&[42u8; 256]).unwrap(),
            Component::new(&[23u8; 512]).unwrap(),
            Component::new(&[11u8; 1024]).unwrap(),
        ])
        .unwrap();
        Entry::new(
            NamespaceId::from_bytes_unchecked([1u8; 32]),
            SubspaceId::from_bytes_unchecked([2u8; 32]),
            path,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
            12345,
            Hash::from_bytes([3u8; 32]).into(),
        )
    }
}
