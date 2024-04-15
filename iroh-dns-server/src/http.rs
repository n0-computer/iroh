//! HTTP server part of iroh-dns-server

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{ConnectInfo, Request},
    handler::Handler,
    http::Method,
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
    Router,
};
use iroh_metrics::{inc, inc_by};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task::JoinSet};
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, span, warn, Level};

mod doh;
mod error;
mod pkarr;
mod rate_limiting;
mod tls;

use crate::state::AppState;
use crate::{config::Config, metrics::Metrics};

pub use self::tls::CertMode;

/// Config for the HTTP server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpConfig {
    /// Port to bind to
    pub port: u16,
    /// Optionally set a custom bind address (will use 0.0.0.0 if unset)
    pub bind_addr: Option<IpAddr>,
}

/// Config for the HTTPS server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpsConfig {
    /// Port to bind to
    pub port: u16,
    /// Optionally set a custom bind address (will use 0.0.0.0 if unset)
    pub bind_addr: Option<IpAddr>,
    /// The list of domains for which SSL certificates should be created.
    pub domains: Vec<String>,
    /// The mode of SSL certificate creation
    pub cert_mode: CertMode,
    /// Letsencrypt contact email address (required if using [`CertMode::LetsEncrypt`])
    pub letsencrypt_contact: Option<String>,
    /// Whether to use the letsenrypt production servers (only applies to [`CertMode::LetsEncrypt`])
    pub letsencrypt_prod: Option<bool>,
}

/// The HTTP(S) server part of iroh-dns-server
pub struct HttpServer {
    tasks: JoinSet<std::io::Result<()>>,
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
}

impl HttpServer {
    /// Spawn the server
    pub async fn spawn(
        http_config: Option<HttpConfig>,
        https_config: Option<HttpsConfig>,
        state: AppState,
    ) -> Result<HttpServer> {
        if http_config.is_none() && https_config.is_none() {
            bail!("Either http or https config is required");
        }

        let app = create_app(state);

        let mut tasks = JoinSet::new();

        // launch http
        let http_addr = if let Some(config) = http_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                config.port,
            );
            let app = app.clone();
            let listener = TcpListener::bind(bind_addr).await?.into_std()?;
            let bound_addr = listener.local_addr()?;
            let fut = axum_server::from_tcp(listener)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTP server listening on {bind_addr}");
            tasks.spawn(fut);
            Some(bound_addr)
        } else {
            None
        };

        // launch https
        let https_addr = if let Some(config) = https_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                config.port,
            );
            let acceptor = {
                let cache_path = Config::data_dir()?
                    .join("cert_cache")
                    .join(config.cert_mode.to_string());
                tokio::fs::create_dir_all(&cache_path)
                    .await
                    .with_context(|| {
                        format!("failed to create cert cache dir at {cache_path:?}")
                    })?;
                config
                    .cert_mode
                    .build(
                        config.domains,
                        cache_path,
                        config.letsencrypt_contact,
                        config.letsencrypt_prod.unwrap_or(false),
                    )
                    .await?
            };
            let listener = TcpListener::bind(bind_addr).await?.into_std()?;
            let bound_addr = listener.local_addr()?;
            let fut = axum_server::from_tcp(listener)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTPS server listening on {bind_addr}");
            tasks.spawn(fut);
            Some(bound_addr)
        } else {
            None
        };

        Ok(HttpServer {
            tasks,
            http_addr,
            https_addr,
        })
    }

    /// Get the bound address of the HTTP socket.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Get the bound address of the HTTPS socket.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// Shutdown the server and wait for all tasks to complete.
    pub async fn shutdown(mut self) -> Result<()> {
        // TODO: Graceful cancellation.
        self.tasks.abort_all();
        self.run_until_done().await?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub async fn run_until_done(mut self) -> Result<()> {
        let mut final_res: anyhow::Result<()> = Ok(());
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Err(err) if err.is_cancelled() => {}
                Ok(Err(err)) => {
                    warn!(?err, "task failed");
                    final_res = Err(anyhow::Error::from(err));
                }
                Err(err) => {
                    warn!(?err, "task panicked");
                    final_res = Err(err.into());
                }
            }
        }
        final_res
    }
}

pub(crate) fn create_app(state: AppState) -> Router {
    // configure cors middleware
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        // allow requests from any origin
        .allow_origin(cors::Any);

    // configure tracing middleware
    let trace = TraceLayer::new_for_http().make_span_with(|request: &http::Request<_>| {
        let conn_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .expect("connectinfo extension to be present");
        let span = span!(
        Level::DEBUG,
            "http_request",
            method = ?request.method(),
            uri = ?request.uri(),
            src = %conn_info.0,
            );
        span
    });

    // configure rate limiting middleware
    let rate_limit = rate_limiting::create();

    // configure routes
    //
    // only the pkarr::put route gets a rate limit
    let router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/pkarr/:key",
            get(pkarr::get).put(pkarr::put.layer(rate_limit)),
        )
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state);

    // configure app
    router
        .layer(cors)
        .layer(trace)
        .route_layer(middleware::from_fn(metrics_middleware))
}

/// Record request metrics.
///
// TODO:
// * Request duration would be much better tracked as a histogram.
// * It would be great to attach labels to the metrics, so that the recorded metrics
// can filter by method etc.
//
// See also
// https://github.com/tokio-rs/axum/blob/main/examples/prometheus-metrics/src/main.rs#L114
async fn metrics_middleware(req: Request, next: Next) -> impl IntoResponse {
    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed().as_millis();
    let status = response.status();
    inc_by!(Metrics, http_requests_duration_ms, latency as u64);
    inc!(Metrics, http_requests);
    if status.is_success() {
        inc!(Metrics, http_requests_success);
    } else {
        inc!(Metrics, http_requests_error);
    }
    response
}
