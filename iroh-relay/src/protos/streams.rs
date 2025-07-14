//! Implements logic for abstracting over a websocket stream that allows sending only [`Bytes`]-based
//! messages.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
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
}

#[cfg(wasm_browser)]
#[derive(derive_more::Debug)]
pub(crate) struct WsBytesFramed {
    #[debug("WebSocketStream")]
    pub(crate) io: ws_stream_wasm::WsStream,
}

#[cfg(not(wasm_browser))]
pub(crate) type StreamError = tokio_websockets::Error;

#[cfg(wasm_browser)]
pub(crate) type StreamError = ws_stream_wasm::WsErr;

/// Shorthand for a type that implements both a websocket-based stream & sink for [`Bytes`].
pub(crate) trait BytesStreamSink:
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
            match ready!(Pin::new(&mut self.io).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                Some(Ok(msg)) => {
                    if msg.is_close() {
                        // Indicate the stream is done when we receive a close message.
                        // Note: We don't have to poll the stream to completion for it to close gracefully.
                        return Poll::Ready(None);
                    }
                    if msg.is_ping() || msg.is_pong() {
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
        Pin::new(&mut self.io).start_send(msg)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_ready(cx).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_close(cx).map_err(Into::into)
    }
}

#[cfg(wasm_browser)]
impl Sink<Bytes> for WsBytesFramed {
    type Error = StreamError;

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let msg = ws_stream_wasm::WsMessage::Binary(Vec::from(bytes));
        Pin::new(&mut self.io).start_send(msg).map_err(Into::into)
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_ready(cx).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.io).poll_close(cx).map_err(Into::into)
    }
}
