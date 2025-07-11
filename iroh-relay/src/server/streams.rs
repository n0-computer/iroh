//! Streams used in the server-side implementation of iroh relays.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use n0_future::{ready, time, FutureExt, Sink, Stream};
use snafu::{Backtrace, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::WebSocketStream;
use tracing::instrument;

use super::{ClientRateLimit, Metrics};
use crate::{
    protos::relay::{Frame, RecvError},
    KeyCache,
};

/// A Stream and Sink for [`Frame`]s connected to a single relay client.
///
/// The stream receives message from the client while the sink sends them to the client.
#[derive(Debug)]
pub(crate) struct RelayedStream {
    pub(crate) inner: WebSocketStream<RateLimited<MaybeTlsStream>>,
    pub(crate) key_cache: KeyCache,
}

#[cfg(test)]
impl RelayedStream {
    pub(crate) fn test_client(stream: tokio::io::DuplexStream) -> Self {
        let stream = MaybeTlsStream::Test(stream);
        let stream = RateLimited::unlimited(stream, Arc::new(Metrics::default()));
        Self {
            inner: tokio_websockets::ClientBuilder::new()
                .limits(Self::limits())
                .take_over(stream),
            key_cache: KeyCache::test(),
        }
    }

    pub(crate) fn test_server(stream: tokio::io::DuplexStream) -> Self {
        let stream = MaybeTlsStream::Test(stream);
        let stream = RateLimited::unlimited(stream, Arc::new(Metrics::default()));
        Self {
            inner: tokio_websockets::ServerBuilder::new()
                .limits(Self::limits())
                .serve(stream),
            key_cache: KeyCache::test(),
        }
    }

    pub(crate) fn test_server_limited(
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
            inner: tokio_websockets::ServerBuilder::new()
                .limits(Self::limits())
                .serve(stream),
            key_cache: KeyCache::test(),
        })
    }

    fn limits() -> tokio_websockets::Limits {
        tokio_websockets::Limits::default()
            .max_payload_len(Some(crate::protos::relay::MAX_FRAME_SIZE))
    }
}

fn ws_to_io_err(e: tokio_websockets::Error) -> std::io::Error {
    match e {
        tokio_websockets::Error::Io(io_err) => io_err,
        _ => std::io::Error::other(e.to_string()),
    }
}

impl Sink<Frame> for RelayedStream {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(ws_to_io_err)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Frame) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(tokio_websockets::Message::binary(
                tokio_websockets::Payload::from(item.to_bytes().freeze()),
            ))
            .map_err(ws_to_io_err)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(ws_to_io_err)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(ws_to_io_err)
    }
}

/// Relay stream errors
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum StreamError {
    #[snafu(transparent)]
    Proto { source: RecvError },
    #[snafu(transparent)]
    Ws { source: tokio_websockets::Error },
}

impl Stream for RelayedStream {
    type Item = Result<Frame, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                if msg.is_close() {
                    // Indicate the stream is done when we receive a close message.
                    // Note: We don't have to poll the stream to completion for it to close gracefully.
                    return Poll::Ready(None);
                }
                if !msg.is_binary() {
                    tracing::warn!(?msg, "Got websocket message of unsupported type, skipping.");
                    return Poll::Pending;
                }
                Poll::Ready(Some(
                    Frame::from_bytes(msg.into_payload().into(), &self.key_cache)
                        .map_err(Into::into),
                ))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The main underlying IO stream type used for the relay server.
///
/// Allows choosing whether or not the underlying [`tokio::net::TcpStream`] is served over Tls
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStream {
    /// A plain non-Tls [`tokio::net::TcpStream`]
    Plain(tokio::net::TcpStream),
    /// A Tls wrapped [`tokio::net::TcpStream`]
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    /// An in-memory bidirectional pipe.
    #[cfg(test)]
    Test(tokio::io::DuplexStream),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }
}

/// Rate limiter for reading from a [`RelayedStream`].
///
/// The writes to the sink are not rate limited.
///
/// This potentially buffers one frame if the rate limiter does not allows this frame.
/// While the frame is buffered the undernlying stream is no longer polled.
#[derive(Debug)]
pub(crate) struct RateLimited<S> {
    inner: S,
    bucket: Option<Bucket>,
    bucket_refilled: Option<Pin<Box<time::Sleep>>>,
    /// Keeps track if this stream was ever rate-limited.
    limited_once: bool,
    metrics: Arc<Metrics>,
}

#[derive(Debug)]
struct Bucket {
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
#[derive(Debug, Snafu)]
pub struct InvalidBucketConfig {
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
    max: i64,
    bytes_per_second: i64,
    refill_period: time::Duration,
}

impl Bucket {
    fn new(
        max: i64,
        bytes_per_second: i64,
        refill_period: time::Duration,
    ) -> Result<Self, InvalidBucketConfig> {
        // milliseconds is the tokio timer resolution
        let refill = bytes_per_second.saturating_mul(refill_period.as_millis() as i64) / 1000;
        snafu::ensure!(
            max > 0 && bytes_per_second > 0 && refill_period.as_millis() as u32 > 0 && refill > 0,
            InvalidBucketConfigSnafu {
                max,
                bytes_per_second,
                refill_period,
            },
        );
        Ok(Self {
            fill: max,
            max,
            last_fill: time::Instant::now(),
            refill_period,
            refill,
        })
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

    fn consume(&mut self, bytes: usize) -> Result<(), time::Instant> {
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
    pub(crate) fn from_cfg(
        cfg: Option<ClientRateLimit>,
        io: S,
        metrics: Arc<Metrics>,
    ) -> Result<Self, InvalidBucketConfig> {
        match cfg {
            Some(cfg) => {
                let bytes_per_second = cfg.bytes_per_second.into();
                let max_burst_bytes = cfg.max_burst_bytes.map_or(bytes_per_second / 10, u32::from);
                Self::new(io, max_burst_bytes, bytes_per_second, metrics)
            }
            None => Ok(Self::unlimited(io, metrics)),
        }
    }

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
            metrics,
        })
    }

    pub(crate) fn unlimited(inner: S, metrics: Arc<Metrics>) -> Self {
        Self {
            inner,
            bucket: None,
            bucket_refilled: None,
            limited_once: false,
            metrics,
        }
    }
}

impl<S> RateLimited<S> {
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

impl<S: AsyncRead + Unpin> AsyncRead for RateLimited<S> {
    #[instrument(name = "rate_limited_poll_read", skip_all)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
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

    use n0_future::time;
    use n0_snafu::{Result, ResultExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing_test::traced_test;

    use super::Bucket;
    use crate::server::{streams::RateLimited, Metrics};

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
        .e()?;

        let duration = time::Instant::now().duration_since(before);
        assert_ne!(duration.as_millis(), 0);

        let actual_bytes_per_second = send_total as f64 / duration.as_secs_f64();
        println!("{actual_bytes_per_second}");
        assert_eq!(actual_bytes_per_second.round() as u32, bytes_per_second);

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
