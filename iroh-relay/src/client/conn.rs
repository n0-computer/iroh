//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use iroh_base::SecretKey;
use n0_error::{ensure, stack_error};
use n0_future::{Sink, Stream};
use tracing::trace;

use super::KeyCache;
#[cfg(not(wasm_browser))]
use crate::client::streams::{MaybeTlsStream, ProxyStream};
use crate::{
    MAX_PACKET_SIZE,
    protos::{
        handshake,
        relay::{ClientToRelayMsg, Error as ProtoError, RelayToClientMsg},
        streams::WsBytesFramed,
    },
};

/// Error for sending messages to the relay server.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum SendError {
    #[error(transparent)]
    StreamError {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[error("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}")]
    ExceedsMaxPacketSize { size: usize },
    #[error("Attempted to send empty packet")]
    EmptyPacket {},
}

/// Errors when receiving messages from the relay server.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RecvError {
    #[error(transparent)]
    Protocol { source: ProtoError },
    #[error(transparent)]
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
/// - A [`Stream`] for [`RelayToClientMsg`] to receive from the server.
/// - A [`Sink`] for [`ClientToRelayMsg`] to send to the server.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[cfg(not(wasm_browser))]
    #[debug("tokio_websockets::WebSocketStream")]
    pub(crate) conn: WsBytesFramed<MaybeTlsStream<ProxyStream>>,
    #[cfg(wasm_browser)]
    #[debug("ws_stream_wasm::WsStream")]
    pub(crate) conn: WsBytesFramed,
    pub(crate) key_cache: KeyCache,
}

impl Conn {
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
        trace!("server_handshake: started");
        handshake::clientside(&mut conn, secret_key).await?;
        trace!("server_handshake: done");

        Ok(Self { conn, key_cache })
    }

    #[cfg(all(test, feature = "server"))]
    pub(crate) fn test(io: tokio::io::DuplexStream) -> Self {
        use crate::protos::relay::MAX_FRAME_SIZE;
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
}

impl Stream for Conn {
    type Item = Result<RelayToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.conn).poll_next(cx)) {
            Some(Ok(msg)) => {
                let message = RelayToClientMsg::from_bytes(msg, &self.key_cache);
                Poll::Ready(Some(message.map_err(Into::into)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<ClientToRelayMsg> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: ClientToRelayMsg) -> Result<(), Self::Error> {
        let size = frame.encoded_len();
        ensure!(
            size <= MAX_PACKET_SIZE,
            SendError::ExceedsMaxPacketSize { size }
        );
        if let ClientToRelayMsg::Datagrams { datagrams, .. } = &frame {
            ensure!(!datagrams.contents.is_empty(), SendError::EmptyPacket);
        }

        Pin::new(&mut self.conn)
            .start_send(frame.to_bytes().freeze())
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}
