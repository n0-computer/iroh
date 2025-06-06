//! Streams used in the server-side implementation of iroh relays.

use std::{
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use governor::clock::Clock;
use n0_future::{ready, time, FutureExt, Sink, Stream};
use snafu::Snafu;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::WebSocketStream;
use tracing::{error, instrument};

use crate::{
    protos::relay::{Frame, RecvError},
    ExportKeyingMaterial, KeyCache,
};

use super::{ClientRateLimit, Metrics};

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
        limiter: governor::DefaultDirectRateLimiter,
    ) -> Self {
        let stream = MaybeTlsStream::Test(stream);
        let stream = RateLimited::new(stream, limiter, Arc::new(Metrics::default()));
        Self {
            inner: tokio_websockets::ServerBuilder::new()
                .limits(Self::limits())
                .serve(stream),
            key_cache: KeyCache::test(),
        }
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
            .start_send(tokio_websockets::Message::binary({
                let mut buf = BytesMut::new();
                item.encode_for_ws_msg(&mut buf);
                tokio_websockets::Payload::from(buf.freeze())
            }))
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
                    Frame::decode_from_ws_msg(msg.into_payload().into(), &self.key_cache)
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
    limiter: Option<Arc<governor::DefaultDirectRateLimiter>>,
    state: State,
    /// Keeps track if this stream was ever rate-limited.
    limited_once: bool,
    metrics: Arc<Metrics>,
}

#[derive(derive_more::Debug)]
enum State {
    #[debug("Blocked")]
    Blocked {
        /// Future which will complete when the item can be yielded.
        delay: Pin<Box<time::Sleep>>,
    },
    Ready,
}

impl<S> RateLimited<S> {
    pub(crate) fn from_cfg(cfg: Option<ClientRateLimit>, io: S, metrics: Arc<Metrics>) -> Self {
        match cfg {
            Some(cfg) => {
                let mut quota = governor::Quota::per_second(cfg.bytes_per_second);
                if let Some(max_burst) = cfg.max_burst_bytes {
                    quota = quota.allow_burst(max_burst);
                }
                let limiter = governor::RateLimiter::direct(quota);
                Self::new(io, limiter, metrics)
            }
            None => Self::unlimited(io, metrics),
        }
    }

    pub(crate) fn new(
        inner: S,
        limiter: governor::DefaultDirectRateLimiter,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            inner,
            limiter: Some(Arc::new(limiter)),
            state: State::Ready,
            limited_once: false,
            metrics,
        }
    }

    pub(crate) fn unlimited(inner: S, metrics: Arc<Metrics>) -> Self {
        Self {
            inner,
            limiter: None,
            state: State::Ready,
            limited_once: false,
            metrics,
        }
    }
}

impl<S> RateLimited<S> {
    /// Records metrics about being rate-limited.
    fn record_rate_limited(&mut self, bytes: NonZeroU32) {
        // TODO: add a label for the frame type.
        self.metrics
            .bytes_rx_ratelimited_total
            .inc_by(u32::from(bytes) as u64);
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
        let Some(ref limiter) = self.limiter else {
            // If there is no rate-limiter directly poll the inner.
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        };
        let limiter = limiter.clone();
        loop {
            match &mut self.state {
                State::Ready => {
                    let bytes_before = buf.remaining();

                    // Poll inner for a new item.
                    ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;

                    let bytes_read = bytes_before - buf.remaining();
                    let Ok(bytes_read) = u32::try_from(bytes_read).and_then(NonZeroU32::try_from)
                    else {
                        // 0 bytes read, nothing to rate limit
                        return Poll::Ready(Ok(()));
                    };

                    match limiter.check_n(bytes_read) {
                        Ok(Ok(())) => {}
                        Ok(Err(not_until)) => {
                            let delay = not_until.wait_time_from(limiter.clock().now());
                            // Item is rate-limited.
                            self.record_rate_limited(bytes_read);
                            self.state = State::Blocked {
                                delay: Box::pin(time::sleep(delay)),
                            };
                            // Continue in `State::Blocked`
                            continue;
                        }
                        Err(capacity_err) => {
                            error!(
                                ?capacity_err,
                                ?bytes_read,
                                "read burst larger than bucket capacity"
                            );
                            // Continue as normal though
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
                State::Blocked { delay } => {
                    ready!(delay.poll(cx));
                    self.state = State::Ready;
                    // Allow polling again, since the delay expired
                    continue;
                }
            }
        }
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
