//! HTTP server part of iroh-dns-server

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Instant,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    handler::Handler,
    http::Method,
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
};
use n0_error::{Result, StdResultExt, anyerr, bail_any};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task::JoinSet};
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};
use tracing::{Level, info, span, warn};

mod doh;
mod error;
mod pkarr;
mod rate_limiting;
mod tls;

pub use self::{rate_limiting::RateLimitConfig, tls::CertMode};
use crate::state::AppState;

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
        rate_limit_config: RateLimitConfig,
        state: AppState,
        cert_cache_dir: PathBuf,
    ) -> Result<HttpServer> {
        if http_config.is_none() && https_config.is_none() {
            bail_any!("Either http or https config is required");
        }

        let app = create_app(state, &rate_limit_config);

        let mut tasks = JoinSet::new();

        // launch http
        let http_addr = if let Some(config) = http_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
                config.port,
            );
            let app = app.clone();
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            let fut = axum_server::from_tcp(listener)?
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
                tokio::fs::create_dir_all(&cert_cache_dir)
                    .await
                    .with_std_context(|_| {
                        format!(
                            "failed to create cert cache dir at {}",
                            cert_cache_dir.display()
                        )
                    })?;
                config
                    .cert_mode
                    .build(
                        config.domains,
                        cert_cache_dir,
                        config.letsencrypt_contact,
                        config.letsencrypt_prod.unwrap_or(false),
                    )
                    .await?
            };
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            let fut = axum_server::from_tcp(listener)?
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
        let mut final_res: Result<()> = Ok(());
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Err(err) if err.is_cancelled() => {}
                Ok(Err(err)) => {
                    warn!(?err, "task failed");
                    final_res = Err(anyerr!(err, "task"));
                }
                Err(err) => {
                    warn!(?err, "task panicked");
                    final_res = Err(anyerr!(err, "join"));
                }
            }
        }
        final_res
    }
}

/// Health check response
#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    git_hash: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
    })
}

pub(crate) fn create_app(state: AppState, rate_limit_config: &RateLimitConfig) -> Router {
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
    let rate_limit = rate_limiting::create(rate_limit_config);

    // configure routes
    //
    // only the pkarr::put route gets a rate limit
    let router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/pkarr/{key}",
            if let Some(rate_limit) = rate_limit {
                get(pkarr::get).put(pkarr::put.layer(rate_limit))
            } else {
                get(pkarr::get).put(pkarr::put)
            },
        )
        // Deprecated: use /healthz instead
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/healthz", get(healthz))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state.clone());

    // configure app
    router
        .layer(cors)
        .layer(trace)
        .route_layer(middleware::from_fn_with_state(state, metrics_middleware))
}

/// Record request metrics.
// TODO:
// * Request duration would be much better tracked as a histogram.
// * It would be great to attach labels to the metrics, so that the recorded metrics
// can filter by method etc.
//
// See also
// https://github.com/tokio-rs/axum/blob/main/examples/prometheus-metrics/src/main.rs#L114
async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed().as_millis();
    let status = response.status();
    state
        .metrics
        .http_requests_duration_ms
        .inc_by(latency as u64);
    state.metrics.http_requests.inc();
    if status.is_success() {
        state.metrics.http_requests_success.inc();
    } else {
        state.metrics.http_requests_error.inc();
    }
    response
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        name_server::TokioConnectionProvider,
    };
    use hickory_server::proto::rr::RecordType;
    use iroh::{
        RelayUrl, SecretKey,
        address_lookup::{EndpointInfo, PkarrRelayClient},
        endpoint_info::EndpointIdExt,
        tls::{CaRootConfig, default_provider},
    };
    use n0_error::StdResultExt;
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;

    use crate::{http::HttpsConfig, server::Server};

    #[tokio::test]
    #[traced_test]
    async fn test_doh() -> n0_error::Result {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);
        let dir = tempfile::tempdir()?;
        let https_config = HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            domains: vec!["localhost".to_string()],
            cert_mode: crate::http::CertMode::SelfSigned,
            letsencrypt_contact: None,
            letsencrypt_prod: None,
        };
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config))
                .await?;

        const RELAY_URL: &str = "https://relay.example./";
        let (name_z32, signed_packet) = {
            let secret_key = SecretKey::generate(&mut rng);
            let endpoint_id = secret_key.public();
            let relay_url: RelayUrl = RELAY_URL.parse().expect("valid url");
            let endpoint_info =
                EndpointInfo::new(endpoint_id).with_relay_url(Some(relay_url.clone()));
            (
                secret_key.public().to_z32(),
                endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?,
            )
        };

        let http_url = server.http_url().expect("http is bound");
        let tls_config = CaRootConfig::default()
            .client_config(default_provider())
            .expect("infallible");
        let pkarr = PkarrRelayClient::new(format!("{http_url}pkarr").parse().anyerr()?, tls_config);
        pkarr.publish(&signed_packet).await?;

        // Create a reqwest client that does not verify certificates.
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .use_preconfigured_tls(self::tls::insecure_tls_config())
            .build()
            .anyerr()?;

        // Fetch as JSON via HTTP.
        let url = format!(
            "{http_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch as JSON via HTTPS.
        let https_url = server.https_url().expect("https is bound");
        let url = format!(
            "{https_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch over HTTPS via hickory-resolver
        let client = {
            let config = {
                let mut config = ResolverConfig::new();
                let mut name_server = NameServerConfig::new(
                    server.https_addr().expect("https is bound"),
                    hickory_server::proto::xfer::Protocol::Https,
                );
                name_server.tls_dns_name = Some("localhost".to_string());
                config.add_name_server(name_server);
                config
            };

            let opts = {
                let mut opts = ResolverOpts::default();
                opts.tls_config = self::tls::insecure_tls_config();
                opts
            };

            hickory_resolver::Resolver::builder_with_config(
                config,
                TokioConnectionProvider::default(),
            )
            .with_options(opts)
            .build()
        };

        let res = client
            .txt_lookup(format!("_iroh.{name_z32}."))
            .await
            .anyerr()?;
        let records = res.as_lookup().records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type(), RecordType::TXT);
        let txt_data = records[0].data().as_txt().unwrap().txt_data();
        assert_eq!(&txt_data[0][..], format!("relay={RELAY_URL}").as_bytes());

        server.shutdown().await?;
        Ok(())
    }

    mod tls {
        use std::sync::Arc;

        use rustls::{
            DigitallySignedStruct, RootCertStore,
            client::{
                ClientConfig,
                danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            },
            crypto::{
                CryptoProvider, ring::default_provider, verify_tls12_signature,
                verify_tls13_signature,
            },
            pki_types::{CertificateDer, ServerName, UnixTime},
        };

        #[derive(Debug)]
        struct NoCertificateVerification(CryptoProvider);

        impl Default for NoCertificateVerification {
            fn default() -> Self {
                Self(default_provider())
            }
        }

        impl ServerCertVerifier for NoCertificateVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }

        pub(super) fn insecure_tls_config() -> ClientConfig {
            let mut cfg = ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification::default()));
            cfg
        }
    }
}
