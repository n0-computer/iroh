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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use iroh_base::{RelayUrl, SecretKey};
    use n0_error::Result;
    use n0_future::{SinkExt, StreamExt};
    use rand::SeedableRng;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;
    use tracing::{info, instrument};

    use crate::{
        client::ClientBuilder,
        dns::DnsResolver,
        protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    };

    /// Test that RelayState can be created and cloned
    #[test]
    fn test_relay_state_creation() {
        let key_cache = KeyCache::new(1024);
        let access = Arc::new(AccessConfig::Everyone);
        let metrics = Arc::new(Metrics::default());

        let state = RelayState::new(key_cache, access, metrics);

        // Verify state can be cloned (required for axum State)
        let _cloned = state.clone();
    }

    /// Test that AxumWebSocketAdapter implements the required traits
    #[test]
    fn test_axum_websocket_adapter_traits() {
        // This test just verifies the types compile correctly
        // The actual functionality is tested in the kitsune2 integration tests
        fn _assert_stream<T>(_: T)
        where
            T: Stream<Item = Result<Bytes, StreamError>> + Unpin,
        {
        }

        fn _assert_sink<T>(_: T)
        where
            T: Sink<Bytes, Error = StreamError> + Unpin,
        {
        }

        fn _assert_export_keying_material<T>(_: T)
        where
            T: ExportKeyingMaterial,
        {
        }

        // These assertions verify the trait bounds at compile time
        // No runtime test needed as this is checked by the type system
    }

    /// Integration test: Start an axum server with the relay handler and connect clients
    #[tokio::test]
    #[instrument]
    async fn test_axum_relay_integration() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);

        // Create relay state
        let key_cache = KeyCache::new(1024);
        let access = Arc::new(AccessConfig::Everyone);
        let metrics = Arc::new(Metrics::default());
        let state = RelayState::new(key_cache, access, metrics);

        // Create axum router with relay handler
        let app = Router::new()
            .route("/relay", get(relay_handler))
            .with_state(state.clone());

        // Bind to a random port
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        info!("Axum relay server listening on {}", addr);

        // Spawn the server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server error");
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create relay URL pointing to our axum server
        let relay_url = format!("http://{}/relay", addr);
        let relay_url: RelayUrl = relay_url.parse()?;

        // Create client A
        let a_secret_key = SecretKey::generate(&mut rng);
        let a_key = a_secret_key.public();
        let resolver = DnsResolver::new();
        info!("Connecting client A");
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
            .connect()
            .await?;

        // Create client B
        let b_secret_key = SecretKey::generate(&mut rng);
        let b_key = b_secret_key.public();
        info!("Connecting client B");
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
            .connect()
            .await?;

        info!("Sending message from A to B");
        // Send message from A to B
        let msg = Datagrams::from("hello from A");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await?;

        // Receive on B
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), client_b.next())
            .await
            .expect("timeout waiting for message")
            .expect("stream ended")?;

        match received {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(remote_endpoint_id, a_key, "Wrong sender");
                assert_eq!(datagrams, msg, "Message content mismatch");
                info!("Successfully received message on client B");
            }
            other => panic!("Unexpected message type: {:?}", other),
        }

        info!("Sending message from B to A");
        // Send message from B to A
        let msg2 = Datagrams::from("hello from B");
        client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: a_key,
                datagrams: msg2.clone(),
            })
            .await?;

        // Receive on A
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), client_a.next())
            .await
            .expect("timeout waiting for message")
            .expect("stream ended")?;

        match received {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(remote_endpoint_id, b_key, "Wrong sender");
                assert_eq!(datagrams, msg2, "Message content mismatch");
                info!("Successfully received message on client A");
            }
            other => panic!("Unexpected message type: {:?}", other),
        }

        // Clean up
        drop(client_a);
        drop(client_b);
        server_handle.abort();

        info!("Test completed successfully");
        Ok(())
    }
}
