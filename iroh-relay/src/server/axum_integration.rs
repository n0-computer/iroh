//! Axum integration for the iroh relay server.
//!
//! This module provides an axum-compatible handler that can be mounted
//! as a standard route, avoiding the need for connection-level routing.
//!
//! # Example
//!
//! ```ignore
//! use axum::{Router, routing::get};
//! use iroh_relay::server::axum_integration::{relay_handler, RelayState};
//! use std::sync::Arc;
//!
//! let state = RelayState::new(
//!     KeyCache::new(1024),
//!     Arc::new(AccessConfig::Everyone),
//!     metrics
//! );
//!
//! let app = Router::new()
//!     .route("/relay", get(relay_handler))
//!     .with_state(state)
//!     // ... other routes
//! ```

use axum::{
    extract::{
        State,
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::Response,
};
use bytes::Bytes;
use n0_future::{Sink, Stream};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio_websockets::Error as WsError;
use tracing::{debug, trace, warn};

use super::{AccessConfig, Metrics, client::Config};
use crate::{
    ExportKeyingMaterial, KeyCache,
    protos::{handshake, relay::PER_CLIENT_SEND_QUEUE_DEPTH, streams::StreamError},
    server::streams::RelayedStream,
};

/// State required for the relay handler
///
/// # Note on Rate Limiting
///
/// Unlike the native relay server which can apply rate limiting at the raw TCP/TLS stream level,
/// the axum integration receives already-established WebSocket connections and does not have
/// access to the underlying stream. Therefore, client-side rate limiting is not supported in
/// this integration. If rate limiting is required, consider using axum middleware or the
/// native relay server instead.
#[derive(Clone, Debug)]
pub struct RelayState {
    /// Key cache for the relay
    pub key_cache: KeyCache,
    /// Access control configuration (wrapped in Arc since AccessConfig can't be cloned)
    pub access: Arc<AccessConfig>,
    /// Metrics for the relay server
    pub metrics: Arc<Metrics>,
    /// Write timeout for client connections
    pub write_timeout: std::time::Duration,
    /// Clients registry
    pub(super) clients: super::clients::Clients,
}

impl RelayState {
    /// Create a new RelayState with default write timeout
    pub fn new(key_cache: KeyCache, access: Arc<AccessConfig>, metrics: Arc<Metrics>) -> Self {
        Self {
            key_cache,
            access,
            metrics,
            write_timeout: crate::defaults::timeouts::SERVER_WRITE_TIMEOUT,
            clients: super::clients::Clients::default(),
        }
    }
}

/// Axum handler for the relay WebSocket endpoint.
///
/// Mount this at the `/relay` path in your axum router.
pub async fn relay_handler(
    State(state): State<RelayState>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> Response {
    // Extract the client auth header if present
    let client_auth_header = headers.get(crate::http::CLIENT_AUTH_HEADER).cloned();

    debug!("Relay WebSocket upgrade request");

    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_relay_websocket(socket, state, client_auth_header).await {
            warn!("Error handling relay WebSocket: {:?}", e);
        }
    })
}

/// Adapter that wraps axum's WebSocket to implement the Stream/Sink traits needed by the relay
struct AxumWebSocketAdapter {
    inner: WebSocket,
}

impl AxumWebSocketAdapter {
    fn new(socket: WebSocket) -> Self {
        Self { inner: socket }
    }
}

impl Stream for AxumWebSocketAdapter {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the underlying axum WebSocket
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    AxumMessage::Binary(data) => Poll::Ready(Some(Ok(Bytes::from(data)))),
                    AxumMessage::Close(_) => Poll::Ready(None),
                    _ => {
                        // Skip non-binary messages and poll again
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                // Convert axum error to WsError
                Poll::Ready(Some(Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{:?}", e),
                )))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for AxumWebSocketAdapter {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(AxumMessage::Binary(item))
            .map_err(|e| {
                WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{:?}", e),
                ))
            })
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            )))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Axum WebSocket doesn't support TLS key export, so we return None
impl ExportKeyingMaterial for AxumWebSocketAdapter {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }
}

impl Unpin for AxumWebSocketAdapter {}

/// Handle the relay protocol over an axum WebSocket
async fn handle_relay_websocket(
    socket: WebSocket,
    state: RelayState,
    client_auth_header: Option<http::HeaderValue>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    trace!("Relay WebSocket connection established");

    // Wrap the axum WebSocket to implement Stream/Sink
    let mut adapter = AxumWebSocketAdapter::new(socket);

    // Perform the relay protocol handshake
    let authentication = handshake::serverside(&mut adapter, client_auth_header).await?;

    trace!(?authentication.mechanism, "accept: verified authentication");

    let is_authorized = state.access.is_allowed(authentication.client_key).await;
    let client_key = authentication
        .authorize_if(is_authorized, &mut adapter)
        .await?;

    trace!("accept: verified authorization");

    // Wrap in RelayedStream for encryption
    let io = RelayedStream {
        inner: adapter,
        key_cache: state.key_cache.clone(),
    };

    trace!("accept: build client conn");
    let client_conn_builder = Config {
        endpoint_id: client_key,
        stream: io,
        write_timeout: state.write_timeout,
        channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
    };

    // Register the client with the relay server
    state
        .clients
        .register(client_conn_builder, state.metrics.clone())
        .await;

    Ok(())
}
