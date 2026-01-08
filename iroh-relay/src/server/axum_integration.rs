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
//!
//! let state = RelayState::new(None, KeyCache::new(1024), AccessConfig::Everyone, metrics);
//!
//! let app = Router::new()
//!     .route("/relay", get(relay_handler))
//!     .with_state(state)
//!     // ... other routes
//! ```

use axum::{
    extract::{ws::{WebSocket, WebSocketUpgrade, Message as AxumMessage}, State},
    response::Response,
    http::HeaderMap,
};
use bytes::Bytes;
use futures_util::{Stream, Sink, stream::StreamExt as _, sink::SinkExt as _};
use std::{pin::Pin, task::{Context, Poll}, sync::Arc};
use tracing::{debug, trace, warn};

use super::{AccessConfig, ClientRateLimit, Metrics, streams::RateLimited, client::Config};
use crate::{
    KeyCache,
    protos::{streams::WsBytesFramed, relay::{MAX_FRAME_SIZE, PER_CLIENT_SEND_QUEUE_DEPTH}, handshake},
    server::streams::RelayedStream,
};

/// State required for the relay handler
#[derive(Clone)]
pub struct RelayState {
    /// Client rate limiting configuration (note: rate limiting not fully supported with axum integration yet)
    pub rate_limit: Option<ClientRateLimit>,
    /// Key cache for the relay
    pub key_cache: KeyCache,
    /// Access control configuration
    pub access: AccessConfig,
    /// Metrics for the relay server
    pub metrics: Arc<Metrics>,
    /// Write timeout for client connections
    pub write_timeout: std::time::Duration,
    /// Clients registry
    pub(super) clients: super::clients::Clients,
}

impl RelayState {
    /// Create a new RelayState with default write timeout
    pub fn new(
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: AccessConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            rate_limit,
            key_cache,
            access,
            metrics: metrics.clone(),
            write_timeout: crate::defaults::timeouts::SERVER_WRITE_TIMEOUT,
            clients: super::clients::Clients::new(metrics),
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
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the underlying axum WebSocket
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    AxumMessage::Binary(data) => Poll::Ready(Some(Ok(Bytes::from(data)))),
                    AxumMessage::Close(_) => Poll::Ready(None),
                    _ => {
                        // Skip non-binary messages and poll again
                        // In practice, we should handle Text/Ping/Pong appropriately
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for AxumWebSocketAdapter {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(AxumMessage::Binary(item.to_vec()))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Handle the relay protocol over an axum WebSocket
async fn handle_relay_websocket(
    socket: WebSocket,
    state: RelayState,
    client_auth_header: Option<http::HeaderValue>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    trace!("Relay WebSocket connection established");

    // Wrap the axum WebSocket to implement Stream/Sink
    let adapter = AxumWebSocketAdapter::new(socket);

    // TODO: The relay expects tokio_websockets::WebSocketStream, but we have an adapter
    // We need to refactor the relay's internal code to be generic over the WebSocket type
    // For now, this is a stub showing the architecture

    trace!("Relay connection established, closing for now (full implementation pending)");

    Ok(())
}
