//! Embeds iroh-relay into an [`axum::Router`].
//!
//! The relay handler upgrades the WebSocket via axum's [`WebSocketUpgrade`]
//! extractor, wraps the resulting [`WebSocket`] into a [`BytesStreamSink`]
//! as expected by iroh-relay's protocol handler, and then runs the
//! handshake plus client registration directly.
//!
//! [`BytesStreamSink`]: iroh_relay::protos::streams::BytesStreamSink

#![cfg(feature = "server")]

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    extract::{
        FromRequestParts, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, header::ACCESS_CONTROL_ALLOW_ORIGIN},
    response::Response,
    routing::get,
};
use bytes::Bytes;
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    ExportKeyingMaterial, KeyCache,
    client::ClientBuilder,
    http::{CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, RELAY_PROBE_PATH},
    protos::{handshake, streams::StreamError},
    server::{
        AccessConfig, ClientRequest, Metrics, client::Config, clients::Clients,
        streams::RelayedStream,
    },
    tls::{CaRootsConfig, default_provider},
};
use n0_error::{AnyError, Result, StdResultExt};
use n0_future::{Sink, Stream, task::AbortOnDropHandle};
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use tokio::net::TcpListener;
use tracing::{trace, warn};

#[derive(Clone, Debug)]
struct RelayState {
    key_cache: KeyCache,
    access: Arc<AccessConfig>,
    metrics: Arc<Metrics>,
    clients: Clients,
}

impl RelayState {
    fn new() -> Self {
        Self {
            key_cache: KeyCache::new(1024),
            access: Arc::new(AccessConfig::Everyone),
            metrics: Arc::new(Metrics::default()),
            clients: Clients::default(),
        }
    }
}

async fn serve_axum() -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let state = RelayState::new();
    let router = Router::new()
        .route(RELAY_PATH, get(relay_handler))
        .route(RELAY_PROBE_PATH, get(ping_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });
    Ok((addr, AbortOnDropHandle::new(task)))
}

async fn relay_handler(
    State(state): State<RelayState>,
    request: axum::extract::Request,
) -> Result<Response, StatusCode> {
    let (mut parts, _body) = request.into_parts();
    let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let client_auth_header = parts.headers.get(CLIENT_AUTH_HEADER).cloned();
    let ws = ws.protocols([ProtocolVersion::V2.to_str()]);
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(error) = handle_relay_websocket(socket, state, parts, client_auth_header).await {
            warn!("relay websocket error: {error:#}");
        }
    }))
}

async fn ping_handler() -> impl axum::response::IntoResponse {
    (StatusCode::OK, [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")])
}

/// Bridges axum's [`WebSocket`] to iroh-relay's [`BytesStreamSink`].
struct AxumWebSocketAdapter {
    inner: Pin<Box<WebSocket>>,
}

impl AxumWebSocketAdapter {
    fn new(socket: WebSocket) -> Self {
        Self {
            inner: Box::pin(socket),
        }
    }
}

impl Stream for AxumWebSocketAdapter {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            return match self.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => Poll::Ready(Some(Ok(data))),
                Poll::Ready(Some(Ok(Message::Close(_)))) => Poll::Ready(None),
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(AnyError::from_std(error)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

impl Sink<Bytes> for AxumWebSocketAdapter {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .as_mut()
            .poll_ready(cx)
            .map_err(AnyError::from_std)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.inner
            .as_mut()
            .start_send(Message::Binary(item))
            .map_err(AnyError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .as_mut()
            .poll_flush(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .as_mut()
            .poll_close(cx)
            .map_err(AnyError::from_std)
    }
}

// Axum's WebSocket has no access to TLS keying material.
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

async fn handle_relay_websocket(
    socket: WebSocket,
    state: RelayState,
    request_parts: http::request::Parts,
    client_auth_header: Option<http::HeaderValue>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut adapter = AxumWebSocketAdapter::new(socket);
    let authentication = handshake::serverside(&mut adapter, client_auth_header).await?;
    trace!(?authentication.mechanism, "verified authentication");

    let request = ClientRequest::new(authentication.client_key, request_parts);
    let is_authorized = state.access.is_allowed(&request).await;
    let client_key = authentication
        .authorize_if(is_authorized, &mut adapter)
        .await?;
    trace!("verified authorization");

    let stream = RelayedStream::new(adapter, state.key_cache.clone());
    let config = Config::new(client_key, stream, ProtocolVersion::V2);
    state.clients.register(config, state.metrics.clone());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn relay_embed_axum() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, _guard) = serve_axum().await?;

    let resp = reqwest::get(format!("http://{addr}/ping"))
        .await
        .std_context("ping request")?;
    assert_eq!(resp.status(), 200);

    // Connect a relay client to `/relay` on the same axum-fronted port.
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
    let relay_url: RelayUrl = format!("http://{addr}").parse()?;
    let tls_config = CaRootsConfig::default().client_config(default_provider())?;
    tokio::time::timeout(
        Duration::from_secs(5),
        ClientBuilder::new(
            relay_url,
            SecretKey::from_bytes(&rng.random()),
            DnsResolver::new(),
        )
        .tls_client_config(tls_config)
        .connect(),
    )
    .await
    .std_context("timeout")??;
    Ok(())
}
