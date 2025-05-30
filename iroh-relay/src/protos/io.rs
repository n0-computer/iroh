//! TODO(matheus23) docs
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use bytes::Bytes;
use n0_future::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ExportKeyingMaterial;

#[derive(derive_more::Debug)]
pub(crate) struct HandshakeIo<T> {
    #[cfg(not(wasm_browser))]
    #[debug("WebSocketStream<MaybeTlsStream<ProxyStream>>")]
    pub(crate) io: tokio_websockets::WebSocketStream<T>,
    #[cfg(wasm_browser)]
    #[debug("WebSocketStream")]
    pub(crate) io: ws_stream_wasm::WsStream,
}

impl<IO: ExportKeyingMaterial + AsyncRead + AsyncWrite + Unpin> ExportKeyingMaterial
    for HandshakeIo<IO>
{
    #[cfg(wasm_browser)]
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }

    #[cfg(not(wasm_browser))]
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

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for HandshakeIo<T> {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.io).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
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
                        tracing::warn!(
                            ?msg,
                            "Got websocket message of unsupported type, skipping."
                        );
                        continue;
                    }
                    return Poll::Ready(Some(Ok(msg.into_payload().into())));
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Sink<Bytes> for HandshakeIo<T> {
    type Error = anyhow::Error;

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        #[cfg(not(wasm_browser))]
        let msg = tokio_websockets::Message::binary(tokio_websockets::Payload::from(bytes));
        #[cfg(wasm_browser)]
        let msg = ws_stream_wasm::WsMessage::Binary(bytes.to_vec());
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
