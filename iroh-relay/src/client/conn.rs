//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};

#[cfg(not(wasm_browser))]
use bytes::BytesMut;
use iroh_base::SecretKey;
use n0_future::{Sink, Stream};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, Snafu};
use tracing::debug;

use super::KeyCache;
#[cfg(not(wasm_browser))]
use crate::client::streams::{MaybeTlsStream, ProxyStream};
use crate::{
    protos::{
        handshake,
        send_recv::{
            ClientToServerMsg, Error as RecvRelayError, ServerToClientMsg, MAX_PAYLOAD_SIZE,
        },
        streams::WsBytesFramed,
    },
    MAX_PACKET_SIZE,
};

/// Error for sending messages to the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SendError {
    #[snafu(transparent)]
    StreamError {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[snafu(display("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}"))]
    ExceedsMaxPacketSize { size: usize },
}

/// Errors when receiving messages from the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecvError {
    #[snafu(transparent)]
    Protocol { source: RecvRelayError },
    #[snafu(transparent)]
    StreamError {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
}

/// A connection to a relay server.
///
/// This holds a connection to a relay server.  It is:
///
/// - A [`Stream`] for [`ServerToClientMsg`] to receive from the server.
/// - A [`Sink`] for [`ClientToServerMsg`] to send to the server.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[debug("tokio_websockets::WebSocketStream")]
    #[cfg(not(wasm_browser))]
    pub(crate) conn: WsBytesFramed<MaybeTlsStream<ProxyStream>>,
    #[debug("ws_stream_wasm::WsStream")]
    #[cfg(wasm_browser)]
    pub(crate) conn: WsBytesFramed,
    pub(crate) key_cache: KeyCache,
}

impl Conn {
    #[cfg(test)]
    pub(crate) fn test(io: tokio::io::DuplexStream) -> Self {
        use crate::protos::send_recv::MAX_FRAME_SIZE;
        Self {
            conn: WsBytesFramed {
                io: tokio_websockets::ClientBuilder::new()
                    .limits(
                        tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)),
                    )
                    .take_over(MaybeTlsStream::Test(io)),
            },
            key_cache: KeyCache::test(),
        }
    }

    /// Constructs a new websocket connection, including the initial server handshake.
    pub(crate) async fn new(
        #[cfg(not(wasm_browser))] io: tokio_websockets::WebSocketStream<
            MaybeTlsStream<ProxyStream>,
        >,
        #[cfg(wasm_browser)] io: ws_stream_wasm::WsStream,
        key_cache: KeyCache,
        secret_key: &SecretKey,
    ) -> Result<Self, handshake::Error> {
        let mut conn = WsBytesFramed { io };

        // exchange information with the server
        debug!("server_handshake: started");
        handshake::clientside(&mut conn, secret_key).await?;
        debug!("server_handshake: done");

        Ok(Self { conn, key_cache })
    }
}

impl Stream for Conn {
    type Item = Result<ServerToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let msg = ready!(Pin::new(&mut self.conn).poll_next(cx));
        match msg {
            Some(Ok(msg)) => {
                let message = ServerToClientMsg::from_bytes(msg, &self.key_cache);
                Poll::Ready(Some(message.map_err(Into::into)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<ClientToServerMsg> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: ClientToServerMsg) -> Result<(), Self::Error> {
        if let ClientToServerMsg::SendDatagrams { datagrams, .. } = &frame {
            let size = datagrams.contents.len();
            snafu::ensure!(size <= MAX_PAYLOAD_SIZE, ExceedsMaxPacketSizeSnafu { size });
        }

        Pin::new(&mut self.conn)
            .start_send(frame.write_to(BytesMut::new()).freeze())
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}
