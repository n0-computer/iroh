//! Streams used in the server-side implementation of iroh relays.

use std::{
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll},
};

use n0_error::{ensure, stack_error};
use n0_future::{FutureExt, Sink, Stream, ready, time};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tracing::{instrument, warn};

use super::{ClientRateLimit, Metrics};
use crate::{
    ExportKeyingMaterial, KeyCache, MAX_PACKET_SIZE,
    protos::{
        relay::{ClientToRelayMsg, Error as ProtoError, RelayToClientMsg},
        streams::{StreamError, WsBytesFramed},
    },
};

/// The relay's connection to a client.
///
/// This implements
/// - a [`Stream`] of [`ClientToRelayMsg`]s that are received from the client,
/// - a [`Sink`] of [`RelayToClientMsg`]s that can be sent to the client.
///
/// Generic over the inner stream type to support different WebSocket implementations.
#[derive(Debug)]
pub struct RelayedStream<S> {
    pub(crate) inner: S,
    pub(crate) key_cache: KeyCache,
}

impl<S> RelayedStream<S> {
    /// Creates a new RelayedStream from an inner stream and key cache.
    ///
    /// This is the primary constructor for external integrations using custom
    /// WebSocket implementations.
    pub fn new(inner: S, key_cache: KeyCache) -> Self {
        Self { inner, key_cache }
    }
}

/// Type alias for the standard server-side relay stream
#[allow(dead_code)]
pub(super) type ServerRelayedStream = RelayedStream<WsBytesFramed<RateLimited<MaybeTlsStream>>>;

#[cfg(test)]
impl ServerRelayedStream {
    pub(crate) fn test(stream: tokio::io::DuplexStream) -> Self {
        let stream = MaybeTlsStream::Test(stream);
        let stream = RateLimited::unlimited(stream, Arc::new(Metrics::default()));
        Self {
            inner: WsBytesFramed {
                io: tokio_websockets::ServerBuilder::new()
                    .limits(Self::limits())
                    .serve(stream),
            },
            key_cache: KeyCache::test(),
        }
    }

    pub(crate) fn test_limited(
        stream: tokio::io::DuplexStream,
        max_burst_bytes: u32,
        bytes_per_second: u32,
    ) -> Result<Self, InvalidBucketConfig> {
        let stream = MaybeTlsStream::Test(stream);
        let stream = RateLimited::new(
            stream,
            max_burst_bytes,
            bytes_per_second,
            Arc::new(Metrics::default()),
        )?;
        Ok(Self {
            inner: WsBytesFramed {
                io: tokio_websockets::ServerBuilder::new()
                    .limits(Self::limits())
                    .serve(stream),
            },
            key_cache: KeyCache::test(),
        })
    }

    fn limits() -> tokio_websockets::Limits {
        tokio_websockets::Limits::default()
            .max_payload_len(Some(crate::protos::relay::MAX_FRAME_SIZE))
    }
}

/// Relay send errors
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SendError {
    /// Error from the underlying WebSocket stream
    #[error(transparent)]
    StreamError {
        #[error(from, std_err)]
        /// The underlying stream error
        source: StreamError,
    },
    /// Packet size exceeds the maximum allowed size
    #[error("Packet exceeds max packet size")]
    ExceedsMaxPacketSize {
        /// The size of the packet that was too large
        size: usize,
    },
    /// Attempted to send an empty packet
    #[error("Attempted to send empty packet")]
    EmptyPacket {},
}

impl<S> Sink<RelayToClientMsg> for RelayedStream<S>
where
    S: Sink<bytes::Bytes, Error = StreamError> + Unpin,
{
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: RelayToClientMsg) -> Result<(), Self::Error> {
        let size = item.encoded_len();
        ensure!(
            size <= MAX_PACKET_SIZE,
            SendError::ExceedsMaxPacketSize { size }
        );
        if let RelayToClientMsg::Datagrams { datagrams, .. } = &item {
            ensure!(!datagrams.contents.is_empty(), SendError::EmptyPacket);
        }

        Pin::new(&mut self.inner)
            .start_send(item.to_bytes().freeze())
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(Into::into)
    }
}

/// Relay receive errors
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum RecvError {
    /// Error decoding the relay protocol message
    #[error(transparent)]
    Proto {
        /// The protocol decoding error
        source: ProtoError,
    },
    /// Error from the underlying WebSocket stream
    #[error(transparent)]
    StreamError {
        #[error(std_err)]
        /// The underlying stream error
        source: StreamError,
    },
}

impl<S> Stream for RelayedStream<S>
where
    S: Stream<Item = Result<bytes::Bytes, StreamError>> + Unpin,
{
    type Item = Result<ClientToRelayMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
            Some(Ok(msg)) => {
                Some(ClientToRelayMsg::from_bytes(msg, &self.key_cache).map_err(Into::into))
            }
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        })
    }
}

/// The main underlying IO stream type used for the relay server.
///
/// Allows choosing whether or not the underlying [`tokio::net::TcpStream`] is served over TLS.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum MaybeTlsStream {
    /// A plain non-Tls [`tokio::net::TcpStream`]
    Plain(tokio::net::TcpStream),
    /// A Tls wrapped [`tokio::net::TcpStream`]
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    /// An in-memory bidirectional pipe.
    #[cfg(test)]
    Test(tokio::io::DuplexStream),
}

impl MaybeTlsStream {
    /// Tries to disable the nagle algorithm on the TCP stream.
    ///
    /// This sets the NO_DELAY option on the TCP stream, which turns off the
    /// nagle algorithm for coalecing writes together.
    ///
    /// If this fails, this will print a warning the first time it fails.
    pub(super) fn disable_nagle(&self) {
        let stream = match self {
            #[cfg(test)]
            Self::Test(_) => return,
            Self::Plain(stream) => stream,
            Self::Tls(tls_stream) => tls_stream.get_ref().0,
        };

        if stream.set_nodelay(true).is_err() {
            use std::sync::atomic::Ordering::Relaxed;

            static FAILED_NO_DELAY: AtomicBool = AtomicBool::new(false);
            if !FAILED_NO_DELAY.swap(true, Relaxed) {
                warn!(
                    "Failed to set TCP socket to NO_DELAY (turning off Nagle failed). This will impair relay performance."
                );
            }
        }
    }
}

impl ExportKeyingMaterial for MaybeTlsStream {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let Self::Tls(tls) = self else {
            return None;
        };

        tls.get_ref()
            .1
            .export_keying_material(output, label, context)
            .ok()
    }
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeTlsStream::Plain(s) => s.is_write_vectored(),
            MaybeTlsStream::Tls(s) => s.is_write_vectored(),
            #[cfg(test)]
            MaybeTlsStream::Test(s) => s.is_write_vectored(),
        }
    }
}

/// Rate limiter for reading from a [`RelayedStream`].
///
/// The writes to the sink are not rate limited.
///
/// This potentially buffers one frame if the rate limiter does not allow this frame.
/// While the frame is buffered the underlying stream is no longer polled.
#[derive(Debug)]
pub(crate) struct RateLimited<S> {
    inner: S,
    bucket: Option<Bucket>,
    bucket_refilled: Option<Pin<Box<time::Sleep>>>,
    /// Keeps track if this stream was ever rate-limited.
    limited_once: bool,
    /// Watcher for the per-client rate limit, if set.
    ///
    /// If set by constructing via [`RateLimited::from_watcher`], we check for
    /// updates on each poll and reconfigure [`Self::bucket`] on changes.
    ///
    /// Uses `tokio::sync::watch` and not `n0_watcher` because in tokio's watch channel,
    /// checking if a value changed is a cheap atomic version compare, whereas `n0_watcher`
    /// acquires a `ReadLock` for each change check. This matters because we need to check this
    /// on each read poll.
    rate_limit_watcher: Option<watch::Receiver<Option<ClientRateLimit>>>,
    metrics: Arc<Metrics>,
}

/// A token bucket used for rate-limiting.
///
/// The bucket holds up to `max` tokens, refilled at a fixed rate of
/// `bytes_per_second` over `refill_period` intervals. [`Bucket::consume`] drains
/// tokens and reports when the next attempt is allowed.
///
/// Exposed so that embedders mounting the relay protocol on a custom HTTP
/// server (where the stream is already framed and the internal
/// `RateLimited` wrapper cannot be used) can apply the same rate-limit
/// semantics at the frame layer.
#[derive(Debug)]
pub struct Bucket {
    // The current bucket fill
    fill: i64,
    // The maximum bucket fill
    max: i64,
    // The bucket's last fill time
    last_fill: time::Instant,
    // Interval length of one refill
    refill_period: time::Duration,
    // How much we re-fill per refill period
    refill: i64,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
pub struct InvalidBucketConfig {
    max: i64,
    bytes_per_second: i64,
    refill_period: time::Duration,
}

impl Bucket {
    /// Creates a new bucket starting full at `max` tokens, refilled at
    /// `bytes_per_second` over `refill_period` intervals.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBucketConfig`] when `max`, `bytes_per_second`, or
    /// `refill_period` are non-positive, or when the configuration would refill
    /// less than one token per period.
    pub fn new(
        max: i64,
        bytes_per_second: i64,
        refill_period: time::Duration,
    ) -> Result<Self, InvalidBucketConfig> {
        // milliseconds is the tokio timer resolution
        let refill = bytes_per_second.saturating_mul(refill_period.as_millis() as i64) / 1000;
        ensure!(
            max > 0 && bytes_per_second > 0 && refill_period.as_millis() as u32 > 0 && refill > 0,
            InvalidBucketConfig {
                max,
                bytes_per_second,
                refill_period
            }
        );
        Ok(Self {
            fill: max,
            max,
            last_fill: time::Instant::now(),
            refill_period,
            refill,
        })
    }

    fn from_config(cfg: Option<ClientRateLimit>) -> Result<Option<Self>, InvalidBucketConfig> {
        match cfg {
            Some(cfg) => {
                let bytes_per_second = u32::from(cfg.bytes_per_second);
                let max_burst_bytes = cfg.max_burst_bytes.map_or(bytes_per_second / 10, u32::from);
                Ok(Some(Bucket::new(
                    max_burst_bytes as i64,
                    bytes_per_second as i64,
                    time::Duration::from_millis(100),
                )?))
            }
            None => Ok(None),
        }
    }

    fn update_state(&mut self) {
        let now = time::Instant::now();
        // div safety: self.refill_period.as_millis() is checked to be non-null in constructor
        let refill_periods = now.saturating_duration_since(self.last_fill).as_millis() as u32
            / self.refill_period.as_millis() as u32;
        if refill_periods == 0 {
            // Nothing to do - we won't refill yet
            return;
        }

        self.fill = self
            .fill
            .saturating_add(refill_periods as i64 * self.refill);
        self.fill = std::cmp::min(self.fill, self.max);
        self.last_fill += self.refill_period * refill_periods;
    }

    /// Attempts to consume `bytes` tokens from the bucket.
    ///
    /// Returns `Ok(())` if enough tokens were available.
    ///
    /// # Errors
    ///
    /// Returns `Err(deadline)` with the [`time::Instant`] at which enough
    /// tokens will have refilled to allow the request.
    pub fn consume(&mut self, bytes: usize) -> Result<(), time::Instant> {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.update_state();

        self.fill = self.fill.saturating_sub(bytes);

        if self.fill > 0 {
            return Ok(());
        }

        let missing = self.fill.saturating_neg();

        let periods_needed = (missing / self.refill) + 1;
        let periods_needed = u32::try_from(periods_needed).unwrap_or(u32::MAX);

        Err(self.last_fill + periods_needed * self.refill_period)
    }
}

impl<S> RateLimited<S> {
    /// Wraps `io` with a live rate limit driven by `rate_limit_watcher`.
    ///
    /// The bucket is initialized from the watcher's current value and reconfigured
    /// whenever it changes.
    pub(crate) fn from_watcher(
        io: S,
        mut rate_limit_watcher: watch::Receiver<Option<ClientRateLimit>>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, InvalidBucketConfig> {
        let initial_cfg = *rate_limit_watcher.borrow_and_update();
        let bucket = Bucket::from_config(initial_cfg)?;
        Ok(Self {
            inner: io,
            bucket,
            bucket_refilled: None,
            limited_once: false,
            rate_limit_watcher: Some(rate_limit_watcher),
            metrics,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        inner: S,
        max_burst_bytes: u32,
        bytes_per_second: u32,
        metrics: Arc<Metrics>,
    ) -> Result<Self, InvalidBucketConfig> {
        Ok(Self {
            inner,
            bucket: Some(Bucket::new(
                max_burst_bytes as i64,
                bytes_per_second as i64,
                time::Duration::from_millis(100),
            )?),
            bucket_refilled: None,
            limited_once: false,
            rate_limit_watcher: None,
            metrics,
        })
    }

    #[cfg(test)]
    pub(crate) fn unlimited(inner: S, metrics: Arc<Metrics>) -> Self {
        Self {
            inner,
            bucket: None,
            bucket_refilled: None,
            limited_once: false,
            rate_limit_watcher: None,
            metrics,
        }
    }

    /// Records metrics about being rate-limited.
    fn record_rate_limited(&mut self, bytes: usize) {
        // TODO: add a label for the frame type.
        self.metrics.bytes_rx_ratelimited_total.inc_by(bytes as u64);
        if !self.limited_once {
            self.metrics.conns_rx_ratelimited_total.inc();
            self.limited_once = true;
        }
    }
}

impl<S: ExportKeyingMaterial> ExportKeyingMaterial for RateLimited<S> {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.inner.export_keying_material(output, label, context)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RateLimited<S> {
    #[instrument(name = "rate_limited_poll_read", skip_all)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;

        // Pick up a live rate change before consulting the bucket. `has_changed`
        // is a cheap atomic version compare, so we only take the watch lock via
        // `borrow_and_update` when the value actually changed.
        if let Some(rate_limit_watcher) = this.rate_limit_watcher.as_mut()
            && rate_limit_watcher.has_changed().unwrap_or(false)
        {
            let cfg = rate_limit_watcher.borrow_and_update();
            match Bucket::from_config(*cfg) {
                Ok(bucket) => {
                    this.bucket = bucket;
                    // The limit changed, so drop any pending refill wait: the new
                    // bucket starts full and should be consulted immediately.
                    this.bucket_refilled = None;
                }
                Err(err) => warn!(%err, "ignoring invalid live rate-limit update"),
            }
        }

        let Some(bucket) = &mut this.bucket else {
            // If there is no rate-limiter, then directly poll the inner.
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };

        // If we're currently limited, wait until we've got some bucket space again
        if let Some(bucket_refilled) = &mut this.bucket_refilled {
            ready!(bucket_refilled.poll(cx));
            this.bucket_refilled = None;
        }

        // We're not currently limited, let's read

        // Poll inner for a new item.
        let bytes_before = buf.remaining();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let bytes_read = bytes_before - buf.remaining();

        // Record how much we've read, rate limit accordingly, if need be.
        if let Err(refill_time) = bucket.consume(bytes_read) {
            this.record_rate_limited(bytes_read);
            this.bucket_refilled = Some(Box::pin(time::sleep_until(refill_time)));
        }

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RateLimited<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use n0_error::{Result, StdResultExt};
    use n0_future::time;
    use n0_tracing_test::traced_test;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::Bucket;
    use crate::server::{Metrics, streams::RateLimited};

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_ratelimiter() -> Result {
        let (read, mut write) = tokio::io::duplex(4096);

        let send_total = 10 * 1024 * 1024; // 10MiB
        let send_data = vec![42u8; send_total];

        let bytes_per_second = 12_345;

        let mut rate_limited = RateLimited::new(
            read,
            bytes_per_second / 10,
            bytes_per_second,
            Arc::new(Metrics::default()),
        )?;

        let before = time::Instant::now();
        n0_future::future::try_zip(
            async {
                let mut remaining = send_total;
                let mut buf = [0u8; 4096];
                while remaining > 0 {
                    remaining -= rate_limited.read(&mut buf).await?;
                }
                Ok(())
            },
            async {
                write.write_all(&send_data).await?;
                write.flush().await
            },
        )
        .await
        .anyerr()?;

        let duration = time::Instant::now().duration_since(before);
        assert_ne!(duration.as_millis(), 0);

        let actual_bytes_per_second = send_total as f64 / duration.as_secs_f64();
        println!("{actual_bytes_per_second}");
        assert_eq!(actual_bytes_per_second.round() as u32, bytes_per_second);

        Ok(())
    }

    /// A rate limit installed live through the watch channel takes effect on an
    /// existing stream without dropping it: the connection first reads a chunk
    /// unlimited at full speed, then a limit is pushed mid-connection and the
    /// throughput of the remainder matches the limit.
    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_ratelimiter_live_update() -> Result {
        use crate::server::ClientRateLimit;

        let (read, mut write) = tokio::io::duplex(4096);

        let bytes_per_second = 12_345u32;

        // Read this much at full speed before the limit is installed, then read
        // exactly 10MiB under the live limit and time only that second phase.
        let unlimited_total = 1024 * 1024; // 1MiB
        let limited_total = 10 * 1024 * 1024; // 10MiB
        let send_data = vec![42u8; unlimited_total + limited_total];

        // Start unlimited; the limit is installed mid-connection below.
        let (rate_tx, rate_rx) = tokio::sync::watch::channel(None);
        let mut rate_limited =
            RateLimited::from_watcher(read, rate_rx, Arc::new(Metrics::default()))?;
        let mut limit = ClientRateLimit::new(bytes_per_second.try_into().anyerr()?);
        limit.max_burst_bytes = Some((bytes_per_second / 10).try_into().anyerr()?);

        let mut unlimited_duration = time::Duration::ZERO;
        let mut limited_duration = time::Duration::ZERO;
        n0_future::future::try_zip(
            async {
                let mut buf = [0u8; 4096];

                // Phase 1: no limit installed yet, pull bytes at full speed.
                let before = time::Instant::now();
                let mut remaining = unlimited_total;
                while remaining > 0 {
                    let len = remaining.min(buf.len());
                    let n = rate_limited.read(&mut buf[..len]).await?;
                    remaining -= n;
                }
                unlimited_duration = time::Instant::now().duration_since(before);

                // Install the limit live, mid-connection, without dropping the stream.
                rate_tx.send_replace(Some(limit));

                // Phase 2: the limit is now in effect, time the remainder.
                let before = time::Instant::now();
                let mut remaining = limited_total;
                while remaining > 0 {
                    let len = remaining.min(buf.len());
                    let n = rate_limited.read(&mut buf[..len]).await?;
                    remaining -= n;
                }
                limited_duration = time::Instant::now().duration_since(before);
                Ok(())
            },
            async {
                write.write_all(&send_data).await?;
                write.flush().await
            },
        )
        .await
        .anyerr()?;

        // The unlimited phase is not throttled, so no (virtual) time passes.
        assert_eq!(
            unlimited_duration.as_millis(),
            0,
            "reading before the limit is installed runs at full speed",
        );

        let actual_bytes_per_second = limited_total as f64 / limited_duration.as_secs_f64();
        assert_eq!(
            actual_bytes_per_second.round() as u32,
            bytes_per_second,
            "the live-installed limit governs throughput once applied mid-connection",
        );

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_bucket_high_refill() -> Result {
        let bytes_per_second = i64::MAX;
        let mut bucket = Bucket::new(i64::MAX, bytes_per_second, time::Duration::from_millis(100))?;
        for _ in 0..100 {
            time::sleep(time::Duration::from_millis(100)).await;
            assert!(bucket.consume(1_000_000).is_ok());
        }

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn smoke_test_bucket_high_consume() -> Result {
        let bytes_per_second = 123_456;
        let mut bucket = Bucket::new(
            bytes_per_second / 10,
            bytes_per_second,
            time::Duration::from_millis(100),
        )?;
        for _ in 0..100 {
            let Err(until) = bucket.consume(usize::MAX) else {
                panic!("i64::MAX shouldn't be within limits");
            };
            time::sleep_until(until).await;
        }

        Ok(())
    }
}
