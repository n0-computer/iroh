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
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum SendError {
    #[error(transparent)]
    StreamError {
        #[error(std_err)]
        source: crate::protos::streams::StreamError,
    },
    #[error("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}")]
    ExceedsMaxPacketSize { size: usize },
    #[error("Attempted to send empty packet")]
    EmptyPacket {},
}

/// Errors when receiving messages from the relay server.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RecvError {
    #[error(transparent)]
    Protocol { source: ProtoError },
    #[error(transparent)]
    StreamError {
        #[error(std_err)]
        source: crate::protos::streams::StreamError,
    },
}

/// The transport protocol used by a relay client connection.
///
/// Returned by [`Client::transport`](super::Client::transport).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// WebSocket over HTTP/1.1 (or browser WebSocket).
    Ws,
    /// WebTransport over QUIC.
    #[cfg(feature = "h3-transport")]
    H3,
}

/// Inner transport for the client connection.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ConnInner {
    /// WebSocket transport (native).
    #[cfg(not(wasm_browser))]
    Ws(WsBytesFramed<MaybeTlsStream<ProxyStream>>),
    /// WebSocket transport (browser).
    #[cfg(wasm_browser)]
    WsBrowser(WsBytesFramed),
    /// WebTransport over QUIC.
    #[cfg(feature = "h3-transport")]
    Wt {
        stream: crate::protos::h3_streams::WtBytesFramed,
        _state: super::h3_conn::WtConnState,
    },
}

/// A connection to a relay server.
///
/// It is:
///
/// - A [`Stream`] for [`RelayToClientMsg`] to receive from the server.
/// - A [`Sink`] for [`ClientToRelayMsg`] to send to the server.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[debug("ConnInner")]
    pub(crate) conn: ConnInner,
    pub(crate) key_cache: KeyCache,
}

impl Conn {
    /// Returns which transport protocol this connection uses.
    pub(crate) fn transport(&self) -> Transport {
        match &self.conn {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(_) => Transport::Ws,
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(_) => Transport::Ws,
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { .. } => Transport::H3,
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

        trace!("server_handshake: started");
        handshake::clientside(&mut conn, secret_key).await?;
        trace!("server_handshake: done");

        Ok(Self {
            #[cfg(not(wasm_browser))]
            conn: ConnInner::Ws(conn),
            #[cfg(wasm_browser)]
            conn: ConnInner::WsBrowser(conn),
            key_cache,
        })
    }

    /// Constructs a connection from an already-handshaken [`WtBytesFramed`](crate::protos::h3_streams::WtBytesFramed).
    #[cfg(feature = "h3-transport")]
    pub(crate) fn from_wt(
        stream: crate::protos::h3_streams::WtBytesFramed,
        state: super::h3_conn::WtConnState,
        key_cache: KeyCache,
    ) -> Self {
        Self {
            conn: ConnInner::Wt {
                stream,
                _state: state,
            },
            key_cache,
        }
    }

    #[cfg(all(test, feature = "server"))]
    pub(crate) fn test(io: tokio::io::DuplexStream) -> Self {
        use crate::protos::relay::MAX_FRAME_SIZE;
        Self {
            conn: ConnInner::Ws(WsBytesFramed {
                io: tokio_websockets::ClientBuilder::new()
                    .limits(
                        tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)),
                    )
                    .take_over(MaybeTlsStream::Test(io)),
            }),
            key_cache: KeyCache::test(),
        }
    }
}

// -- ConnInner Stream/Sink impls ----------------------------------------------

impl Stream for ConnInner {
    type Item = Result<bytes::Bytes, crate::protos::streams::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(ws) => Pin::new(ws).poll_next(cx),
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(ws) => Pin::new(ws).poll_next(cx),
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { stream, .. } => Pin::new(stream).poll_next(cx),
        }
    }
}

impl Sink<bytes::Bytes> for ConnInner {
    type Error = crate::protos::streams::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(ws) => Pin::new(ws).poll_ready(cx),
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(ws) => Pin::new(ws).poll_ready(cx),
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { stream, .. } => Pin::new(stream).poll_ready(cx),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: bytes::Bytes) -> Result<(), Self::Error> {
        match self.get_mut() {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(ws) => Pin::new(ws).start_send(item),
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(ws) => Pin::new(ws).start_send(item),
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { stream, .. } => Pin::new(stream).start_send(item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(ws) => Pin::new(ws).poll_flush(cx),
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(ws) => Pin::new(ws).poll_flush(cx),
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            #[cfg(not(wasm_browser))]
            ConnInner::Ws(ws) => Pin::new(ws).poll_close(cx),
            #[cfg(wasm_browser)]
            ConnInner::WsBrowser(ws) => Pin::new(ws).poll_close(cx),
            #[cfg(feature = "h3-transport")]
            ConnInner::Wt { stream, .. } => Pin::new(stream).poll_close(cx),
        }
    }
}

// -- Conn Stream/Sink impls ---------------------------------------------------

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
