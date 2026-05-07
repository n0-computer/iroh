//! Embeds the relay inside a plain hyper HTTP server. Routes `/relay`
//! through [`RelayServiceWithNotify`] and serves a `/ping` probe matching
//! the iroh-relay server's built-in probe.

#![cfg(feature = "server")]

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode, header::ACCESS_CONTROL_ALLOW_ORIGIN};
use http_body_util::Full;
use hyper::{
    Request,
    body::Incoming,
    server::conn::http1,
    service::{Service as _, service_fn},
};
use hyper_util::rt::TokioIo;
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    KeyCache,
    client::ClientBuilder,
    http::{RELAY_PATH, RELAY_PROBE_PATH},
    server::{
        AccessConfig, Metrics,
        http_server::{BytesBody, Handlers, RelayService, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
    tls::{CaRootsConfig, default_provider},
};
use n0_error::{Result, StdResultExt};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use rand::{RngExt, SeedableRng};
use tokio::{net::TcpListener, sync::Notify};

async fn dispatch(req: Request<Incoming>, service: RelayService) -> Response<BytesBody> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, RELAY_PROBE_PATH) => Response::builder()
            .status(StatusCode::OK)
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Box::new(Full::new(Bytes::new())) as BytesBody)
            .expect("valid response"),
        (&Method::GET, RELAY_PATH) => RelayServiceWithNotify::new(service, Arc::new(Notify::new()))
            .call(req)
            .await
            .expect("RelayServiceWithNotify::call returns Ok"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Box::new(Full::new("not found".into())) as BytesBody)
            .expect("valid response"),
    }
}

async fn serve_hyper() -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let service = RelayService::new(
        Handlers::default(),
        HeaderMap::new(),
        None,
        KeyCache::new(1024),
        AccessConfig::Everyone,
        Arc::new(Metrics::default()),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            // The relay handler downcasts the hyper `Upgraded` back to
            // `TokioIo<MaybeTlsStream>`, so wrap the stream as such.
            let stream = MaybeTlsStream::Plain(stream);
            let service = service.clone();
            tokio::spawn(async move {
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let service = service.clone();
                            async move { Ok::<_, Infallible>(dispatch(req, service).await) }
                        }),
                    )
                    .with_upgrades()
                    .await
                    .expect("serve_connection failed");
            });
        }
    });
    Ok((addr, AbortOnDropHandle::new(task)))
}

#[tokio::test]
#[traced_test]
async fn relay_embed_hyper() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, _guard) = serve_hyper().await?;

    let res = reqwest::get(format!("http://{addr}/ping"))
        .await
        .std_context("ping request")?;
    assert_eq!(res.status(), 200);

    // Connect a relay client to `/relay`.
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
