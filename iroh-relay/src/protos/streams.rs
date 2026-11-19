//! Implements logic for abstracting over a websocket stream that allows sending only [`Bytes`]-based
//! messages.
use std::{
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(not(wasm_browser))]
use std::{
    sync::Arc,
    task::{Wake, Waker},
};

use bytes::Bytes;
use n0_error::AnyError;
#[cfg(not(wasm_browser))]
use n0_error::anyerr;
use n0_future::{Sink, Stream, ready};
#[cfg(not(wasm_browser))]
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use crate::ExportKeyingMaterial;

#[cfg(not(wasm_browser))]
#[derive(derive_more::Debug)]
pub(crate) struct WsBytesFramed<T> {
    #[debug("WebSocketStream<T>")]
    pub(crate) io: tokio_websockets::WebSocketStream<T>,
    has_queued_pong: bool,
    stream_waker: Option<Waker>,
    sink_waker: Option<Waker>,
}

#[cfg(not(wasm_browser))]
impl<T> WsBytesFramed<T> {
    pub(crate) fn new(io: tokio_websockets::WebSocketStream<T>) -> Self {
        Self {
            io,
            has_queued_pong: false,
            stream_waker: None,
            sink_waker: None,
        }
    }
}

/// Records `cx`'s task in `own` and returns the waker for a write poll, which also wakes `other`.
#[cfg(not(wasm_browser))]
fn register_write(own: &mut Option<Waker>, other: Option<&Waker>, cx: &Context<'_>) -> Waker {
    *own = Some(cx.waker().clone());
    match other {
        Some(other) if !other.will_wake(cx.waker()) => {
            Waker::from(Arc::new(TwoWakers(cx.waker().clone(), other.clone())))
        }
        _ => cx.waker().clone(),
    }
}

#[cfg(not(wasm_browser))]
struct TwoWakers(Waker, Waker);

#[cfg(not(wasm_browser))]
impl Wake for TwoWakers {
    fn wake(self: Arc<Self>) {
        self.0.wake_by_ref();
        self.1.wake_by_ref();
    }
}

#[cfg(wasm_browser)]
#[derive(derive_more::Debug)]
pub(crate) struct WsBytesFramed {
    #[debug("WebSocketStream")]
    pub(crate) io: ws_stream_wasm::WsStream,
}

#[cfg(wasm_browser)]
impl WsBytesFramed {
    pub(crate) fn new(io: ws_stream_wasm::WsStream) -> Self {
        Self { io }
    }
}

/// Error type for WebSocket stream operations.
///
/// This is a generic [`AnyError`] and represents errors that can occur during WebSocket
/// communication. The underlying error type depends on the platform:
/// - On non-browser platforms: `tokio_websockets::Error`
/// - On browser WASM: `ws_stream_wasm::WsErr`
///
/// You can use [`AnyError::downcast_ref`] to downcast to the concrete error. However, the
/// downcast is not covered by any semver guarantees and the underlying error may change.
pub type StreamError = AnyError;

/// Shorthand for a type that implements both a websocket-based stream & sink for [`Bytes`].
pub trait BytesStreamSink:
    Stream<Item = Result<Bytes, StreamError>> + Sink<Bytes, Error = StreamError> + Unpin
{
}

impl<T> BytesStreamSink for T where
    T: Stream<Item = Result<Bytes, StreamError>> + Sink<Bytes, Error = StreamError> + Unpin
{
}

#[cfg(not(wasm_browser))]
impl<IO: ExportKeyingMaterial + AsyncRead + AsyncWrite + Unpin> ExportKeyingMaterial
    for WsBytesFramed<IO>
{
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.io
            .get_ref()
            .export_keying_material(output, label, context)
    }
}

#[cfg(wasm_browser)]
impl ExportKeyingMaterial for WsBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }
}

#[cfg(not(wasm_browser))]
impl<T: AsyncRead + AsyncWrite + Unpin> Stream for WsBytesFramed<T> {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // tokio_websockets queues a pong for every ping without limit.
            // TODO: remove this and `register_write` once it no longer does.
            if self.has_queued_pong {
                let this = &mut *self;
                let waker = register_write(&mut this.stream_waker, this.sink_waker.as_ref(), cx);
                let res = Pin::new(&mut this.io).poll_flush(&mut Context::from_waker(&waker));
                let res = ready!(res);
                self.has_queued_pong = false;
                if let Err(e) = res {
                    return Poll::Ready(Some(Err(anyerr!(e))));
                }
            }
            match ready!(Pin::new(&mut self.io).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(anyerr!(e)))),
                Some(Ok(msg)) => {
                    if msg.is_close() {
                        // Indicate the stream is done when we receive a close message.
                        // Note: We don't have to poll the stream to completion for it to close gracefully.
                        return Poll::Ready(None);
                    }
                    if msg.is_ping() || msg.is_pong() {
                        self.has_queued_pong |= msg.is_ping();
                        continue; // Responding appropriately to these is done inside of tokio_websockets/browser impls
                    }
                    if !msg.is_binary() {
                        warn!(?msg, "Got websocket message of unsupported type, skipping.");
                        continue;
                    }
                    return Poll::Ready(Some(Ok(msg.into_payload().into())));
                }
            }
        }
    }
}

#[cfg(wasm_browser)]
impl Stream for WsBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.io).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(ws_stream_wasm::WsMessage::Binary(msg)) => {
                    return Poll::Ready(Some(Ok(msg.into())));
                }
                Some(msg) => {
                    warn!(?msg, "Got websocket message of unsupported type, skipping.");
                    continue;
                }
            }
        }
    }
}

#[cfg(not(wasm_browser))]
impl<T: AsyncRead + AsyncWrite + Unpin> Sink<Bytes> for WsBytesFramed<T> {
    type Error = StreamError;

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let msg = tokio_websockets::Message::binary(tokio_websockets::Payload::from(bytes));
        Pin::new(&mut self.io)
            .start_send(msg)
            .map_err(AnyError::from_std)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        let waker = register_write(&mut this.sink_waker, this.stream_waker.as_ref(), cx);
        Pin::new(&mut this.io)
            .poll_ready(&mut Context::from_waker(&waker))
            .map_err(AnyError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        let waker = register_write(&mut this.sink_waker, this.stream_waker.as_ref(), cx);
        Pin::new(&mut this.io)
            .poll_flush(&mut Context::from_waker(&waker))
            .map_err(AnyError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        let waker = register_write(&mut this.sink_waker, this.stream_waker.as_ref(), cx);
        Pin::new(&mut this.io)
            .poll_close(&mut Context::from_waker(&waker))
            .map_err(AnyError::from_std)
    }
}

#[cfg(wasm_browser)]
impl Sink<Bytes> for WsBytesFramed {
    type Error = StreamError;

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let msg = ws_stream_wasm::WsMessage::Binary(Vec::from(bytes));
        Pin::new(&mut self.io)
            .start_send(msg)
            .map_err(AnyError::from_std)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_ready(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_flush(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io)
            .poll_close(cx)
            .map_err(AnyError::from_std)
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use n0_future::{SinkExt, StreamExt, split::split, task::AbortOnDropHandle};
    use tokio::{
        io::AsyncWriteExt,
        time::{sleep, timeout},
    };

    use super::WsBytesFramed;

    #[tokio::test(start_paused = true)]
    async fn split_halves_are_both_woken_after_ping_sink() {
        split_halves_are_woken(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn split_halves_are_both_woken_after_ping_stream() {
        split_halves_are_woken(false).await;
    }

    async fn split_halves_are_woken(sink_first: bool) {
        let (local, mut remote) = tokio::io::duplex(64);
        let local = WsBytesFramed::new(tokio_websockets::ClientBuilder::new().take_over(local));
        let (mut sink, mut stream) = split(local);

        let mut frames = [0x89, 0].repeat(20);
        frames.extend([0x82, 0]);
        remote.write_all(&frames).await.unwrap();

        let send = async move { sink.send(Bytes::from(vec![0; 1024])).await };
        let recv = async move { stream.next().await };

        let (send, recv) = if sink_first {
            let send = AbortOnDropHandle::new(tokio::spawn(send));
            sleep(Duration::from_secs(1)).await;
            (send, AbortOnDropHandle::new(tokio::spawn(recv)))
        } else {
            let recv = AbortOnDropHandle::new(tokio::spawn(recv));
            sleep(Duration::from_secs(1)).await;
            (AbortOnDropHandle::new(tokio::spawn(send)), recv)
        };

        sleep(Duration::from_secs(1)).await;
        assert!(!send.is_finished() && !recv.is_finished());

        let _reader = AbortOnDropHandle::new(tokio::spawn(async move {
            tokio::io::copy(&mut remote, &mut tokio::io::sink()).await
        }));
        let both = async { (send.await.unwrap(), recv.await.unwrap()) };
        let (sent, received) = timeout(Duration::from_secs(60), both)
            .await
            .expect("a half was not woken");
        sent.unwrap();
        assert_eq!(received.unwrap().unwrap(), Bytes::new());
    }

    #[tokio::test]
    async fn failed_pong_flush_ends_the_stream() {
        let (local, mut remote) = tokio::io::duplex(64);
        let mut local = WsBytesFramed::new(tokio_websockets::ClientBuilder::new().take_over(local));
        remote.write_all(&[0x89, 0]).await.unwrap();
        drop(remote);

        assert!(matches!(local.next().await, Some(Err(_))));
        assert!(local.next().await.is_none());
    }
}
