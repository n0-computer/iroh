//! Utilities for iroh-gossip networking

use std::{collections::HashMap, io, pin::Pin, time::Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use iroh_net::{tls::PeerId, MagicEndpoint};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{sleep_until, Sleep},
};
use tokio_util::sync::CancellationToken;

use crate::proto::util::TimerMap;

use super::{ProtoMessage, MAX_MESSAGE_SIZE};

/// Write a [ProtoMessage] as a length-prefixed, postcard-encoded message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buffer: &mut BytesMut,
    frame: &ProtoMessage,
) -> Result<()> {
    let len = postcard::experimental::serialized_size(&frame)?;
    ensure!(len < MAX_MESSAGE_SIZE);
    buffer.clear();
    buffer.resize(len, 0u8);
    let slice = postcard::to_slice(&frame, buffer)?;
    writer.write_u32(len as u32).await?;
    writer.write_all(slice).await?;
    Ok(())
}

/// Read a length-prefixed message and decode as [[ProtoMessage]];
pub async fn read_message(
    reader: impl AsyncRead + Unpin,
    buffer: &mut BytesMut,
) -> Result<Option<ProtoMessage>> {
    match read_lp(reader, buffer).await? {
        None => Ok(None),
        Some(data) => {
            let message = postcard::from_bytes(&data)?;
            Ok(Some(message))
        }
    }
}

/// Reads a length prefixed message.
///
/// # Returns
///
/// The message as raw bytes.  If the end of the stream is reached and there is no partial
/// message, returns `None`.
pub async fn read_lp(
    mut reader: impl AsyncRead + Unpin,
    buffer: &mut BytesMut,
) -> Result<Option<Bytes>> {
    let size = match reader.read_u32().await {
        Ok(size) => size,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut reader = reader.take(size as u64);
    let size = usize::try_from(size).context("frame larger than usize")?;
    if size > MAX_MESSAGE_SIZE {
        bail!("Incoming message exceeds MAX_MESSAGE_SIZE");
    }
    buffer.reserve(size);
    loop {
        let r = reader.read_buf(buffer).await?;
        if r == 0 {
            break;
        }
    }
    Ok(Some(buffer.split_to(size).freeze()))
}

/// Future for a pending dial operation
pub type DialFuture = BoxFuture<'static, (PeerId, anyhow::Result<quinn::Connection>)>;

/// Dial peers and maintain a queue of pending dials
///
/// This wraps a [MagicEndpoint], connects to peers through the endpoint, stores
/// the pending connect futures and emits finished connect results.
///
/// TODO: Move to iroh-net
#[derive(Debug)]
pub struct Dialer {
    endpoint: MagicEndpoint,
    pending: FuturesUnordered<DialFuture>,
    pending_peers: HashMap<PeerId, CancellationToken>,
}
impl Dialer {
    /// Create a new dialer for a [`MagicEndpoint`]
    pub fn new(endpoint: MagicEndpoint) -> Self {
        Self {
            endpoint,
            pending: Default::default(),
            pending_peers: Default::default(),
        }
    }

    /// Start to dial a peer
    ///
    /// Note that the peer's addresses and/or derp region must be added to the endpoint's
    /// addressbook for a dial to succeed, see [`MagicEndpoint::add_known_addrs`].
    pub fn queue_dial(&mut self, peer_id: PeerId, alpn_protocol: &'static [u8]) {
        if self.is_pending(&peer_id) {
            return;
        }
        let cancel = CancellationToken::new();
        self.pending_peers.insert(peer_id, cancel.clone());
        let endpoint = self.endpoint.clone();
        let fut = async move {
            let res = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(anyhow!("Cancelled")),
                res = endpoint.connect(peer_id, alpn_protocol, None, &[]) => res
            };
            (peer_id, res)
        }
        .boxed();
        self.pending.push(fut.boxed());
    }

    /// Abort a pending dial
    pub fn abort_dial(&mut self, peer_id: &PeerId) {
        if let Some(cancel) = self.pending_peers.remove(peer_id) {
            cancel.cancel();
        }
    }

    /// Check if a peer is currently being dialed
    pub fn is_pending(&self, peer: &PeerId) -> bool {
        self.pending_peers.contains_key(peer)
    }

    /// Wait for the next dial operation to complete
    pub async fn next(&mut self) -> (PeerId, anyhow::Result<quinn::Connection>) {
        match self.pending_peers.is_empty() {
            false => {
                let (peer_id, res) = self.pending.next().await.unwrap();
                self.pending_peers.remove(&peer_id);
                (peer_id, res)
            }
            true => futures::future::pending().await,
        }
    }
}

/// A [`TimerMap`] with an async method to wait for the next timer expiration.
pub struct Timers<T> {
    next: Option<(Instant, Pin<Box<Sleep>>)>,
    map: TimerMap<T>,
}
impl<T> Timers<T> {
    /// Create a new timer map
    pub fn new() -> Self {
        Self {
            next: None,
            map: TimerMap::default(),
        }
    }

    /// Insert a new entry at the specified instant
    pub fn insert(&mut self, instant: Instant, item: T) {
        self.map.insert(instant, item);
    }

    fn reset(&mut self) {
        self.next = self
            .map
            .first()
            .map(|(instant, _)| (*instant, Box::pin(sleep_until((*instant).into()))))
    }

    /// Wait for the next timer to expire and return an iterator of all expired timers
    ///
    /// If the [TimerMap] is empty, this will return a future that is pending forever.
    /// After inserting a new entry, prior futures returned from this method will not become ready.
    /// They should be dropped after calling [Self::insert], and a new future as returned from
    /// this method should be awaited instead.
    pub async fn wait_and_drain(&mut self) -> impl Iterator<Item = (Instant, T)> {
        self.reset();
        match self.next.as_mut() {
            Some((instant, sleep)) => {
                sleep.await;
                self.map.drain_until(instant)
            }
            None => futures::future::pending().await,
        }
    }
}
