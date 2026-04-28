//! Multitenant iroh-relay example.
//!
//! Stands up a single HTTP listener that fronts three independent
//! [`RelayService`] instances. The HTTP `Authorization: Bearer <token>` header
//! on the WebSocket upgrade request selects which `RelayService` handles the
//! connection, giving each tenant its own metrics, rate limits, and
//! [`AccessConfig`] hook.
//!
//! Run with:
//!
//!     cargo run --example multitenant --features=server
//!
//! And connect with:
//!
//!     cargo run --example transfer -- provide --relay-url http://localhost:8080 --relay-auth-token tenant-alpha-secret
//!
//! Notes:
//! - The example uses plain HTTP, not HTTPS
//! - QAD is not enabled in this example
//! - Each tenant's `AccessConfig::Restricted` hook receives the WebSocket
//!   upgrade request headers, including the bearer credential. This lets the
//!   tenant additionally bind the bearer to the `EndpointId` proven by the
//!   relay handshake (e.g. assert that the bearer claims the same key) -
//!   the example just logs them.

use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::{
    body::Incoming,
    server::conn::http1,
    service::{Service as _, service_fn},
};
use hyper_util::rt::TokioIo;
use iroh_relay::{
    KeyCache,
    server::{
        Access, AccessConfig, Metrics,
        http_server::{BytesBody, Handlers, RelayService, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
};
use n0_future::FutureExt;
use tokio::{net::TcpListener, sync::Notify};
use tracing::{debug, info, warn};

/// Static tenant configuration: `(tenant_name, bearer_token)`.
const TENANTS: &[(&str, &str)] = &[
    ("alpha", "tenant-alpha-secret"),
    ("beta", "tenant-beta-secret"),
    ("gamma", "tenant-gamma-secret"),
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Build one `RelayService` per tenant. Each tenant gets its own `Metrics`
    // and `AccessConfig` hook.
    let tenants: HashMap<String, RelayService> = TENANTS
        .iter()
        .map(|(name, token)| (token.to_string(), build_tenant(name)))
        .collect();
    let tenants = Arc::new(tenants);

    let bind: SocketAddr = "127.0.0.1:8080".parse()?;
    let listener = TcpListener::bind(bind).await?;
    info!(
        "multitenant relay listening on http://{}",
        listener.local_addr()?
    );
    info!("tenants:");
    for (name, token) in TENANTS {
        info!("  {name}: Authorization: Bearer {token}");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let tenants = tenants.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(MaybeTlsStream::Plain(stream));
            let conn = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let tenants = tenants.clone();
                        async move { Ok::<_, Infallible>(dispatch(req, tenants).await) }
                    }),
                )
                .with_upgrades();
            if let Err(err) = conn.await {
                warn!(%peer, "connection error: {err:#}");
            }
        });
    }
}

fn build_tenant(name: &'static str) -> RelayService {
    let access = AccessConfig::Restricted(Box::new(move |endpoint_id, headers| {
        // Snapshot the bearer for logging. In production this is where the
        // tenant would verify the credential and assert that it claims
        // `endpoint_id` (the key proven by the relay handshake).
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok().map(str::to_string));
        info!(
            tenant = name,
            endpoint = %endpoint_id.fmt_short(),
            bearer = ?bearer,
            "tenant accepting endpoint",
        );
        async move { Access::Allow }.boxed()
    }));
    RelayService::new(
        Handlers::default(),
        HeaderMap::new(),
        // Per-tenant rate limits would go here.
        None,
        KeyCache::new(1024),
        access,
        // A fresh `Metrics` per tenant: each tenant gets its own counters.
        Arc::new(Metrics::default()),
    )
}

async fn dispatch(
    req: Request<Incoming>,
    tenants: Arc<HashMap<String, RelayService>>,
) -> Response<BytesBody> {
    debug!("incoming request: {} {}", req.method(), req.uri());
    if matches!(
        (req.method(), req.uri().path()),
        (&Method::GET, "/" | "/index.html")
    ) {
        return simple_response(StatusCode::OK, "iroh multitenant relay");
    }
    if (req.method(), req.uri().path()) == (&Method::GET, "/ping") {
        return simple_response(StatusCode::OK, "");
    }
    if (req.method(), req.uri().path()) != (&Method::GET, "/relay") {
        return simple_response(StatusCode::NOT_FOUND, "not found");
    }
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return simple_response(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let Some(service) = tenants.get(token).cloned() else {
        return simple_response(StatusCode::UNAUTHORIZED, "unknown bearer token");
    };
    let service_with_notify = RelayServiceWithNotify::new(service, Arc::new(Notify::new()));
    match service_with_notify.call(req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!("relay handler error: {err:#}");
            simple_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

fn simple_response(status: StatusCode, body: &'static str) -> Response<BytesBody> {
    Response::builder()
        .status(status)
        .body(Box::new(Full::new(Bytes::from_static(body.as_bytes()))) as BytesBody)
        .expect("valid response")
}
