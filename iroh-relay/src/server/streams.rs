//! Streams used in the server-side implementation of iroh relays.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use n0_future::{ready, time, FutureExt, Sink, Stream};
use snafu::{Backtrace, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::instrument;

use super::{ClientRateLimit, Metrics};
use crate::{
    protos::{
        relay::{ClientToRelayMsg, Error as ProtoError, RelayToClientMsg},
        streams::{StreamError, WsBytesFramed},
    },
    ExportKeyingMaterial, KeyCache,
};

/// The relay's connection to a client.
///
/// This implements
/// - a [`Stream`] of [`ClientToRelayMsg`]s that are received from the client,
/// - a [`Sink`] of [`RelayToClientMsg`]s that can be sent to the client.
#[derive(Debug)]
pub(crate) struct RelayedStream {
    pub(crate) inner: WsBytesFramed<RateLimited<MaybeTlsStream>>,
    pub(crate) key_cache: KeyCache,
}

#[cfg(test)]
impl RelayedStream {
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

impl Sink<RelayToClientMsg> for RelayedStream {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: RelayToClientMsg) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item.write_to(BytesMut::new()).freeze())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Relay receive errors
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecvError {
    #[snafu(transparent)]
    Proto { source: ProtoError },
    #[snafu(transparent)]
    StreamError { source: StreamError },
}

impl Stream for RelayedStream {
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

impl ExportKeyingMaterial for MaybeTlsStream {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let Self::Tls(ref tls) = self else {
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
        snafu::ensure!(
            max > 0 && bytes_per_second > 0 && refill_period.as_millis() != 0,
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
            refill: bytes_per_second * refill_period.as_millis() as i64 / 1000,
        })
    }

    fn update_state(&mut self) {
        let now = time::Instant::now();
        let refill_periods = now.saturating_duration_since(self.last_fill).as_millis() as u32
            / self.refill_period.as_millis() as u32;
        if refill_periods == 0 {
            // Nothing to do - we won't refill yet
            return;
        }

        self.fill += refill_periods as i64 * self.refill;
        self.fill = std::cmp::min(self.fill, self.max);
        self.last_fill += self.refill_period * refill_periods;
    }

    fn consume(&mut self, bytes: i64) -> Result<(), time::Instant> {
        self.update_state();

        self.fill -= bytes;

        if self.fill > 0 {
            return Ok(());
        }

        let missing = -self.fill;

        let periods_needed = (missing / self.refill) + 1;

        Err(self.last_fill + periods_needed as u32 * self.refill_period)
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
        if let Err(refill_time) = bucket.consume(bytes_read as i64) {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use n0_future::time;
    use n0_snafu::{Result, ResultExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing_test::traced_test;

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
}
