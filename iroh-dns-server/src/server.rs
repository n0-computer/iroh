//! The main server which combines the DNS and HTTP(S) servers.
use std::sync::Arc;
#[cfg(test)]
use std::{net::SocketAddr, path::Path};

use iroh_metrics::service::start_metrics_server;
use n0_error::{Result, StdResultExt};
use tracing::info;
#[cfg(test)]
use url::Url;

#[cfg(test)]
use crate::http::HttpsConfig;
use crate::{
    config::Config,
    dns::{DnsHandler, DnsServer},
    http::HttpServer,
    metrics::Metrics,
    state::AppState,
    store::ZoneStore,
};

/// Spawn the server and run until the `Ctrl-C` signal is received, then shutdown.
pub async fn run_with_config_until_ctrl_c(config: Config) -> Result<()> {
    let metrics = Arc::new(Metrics::default());
    let zone_store_options = config.zone_store.clone().unwrap_or_default();
    let mut store = ZoneStore::persistent(
        config.signed_packet_store_path()?,
        zone_store_options.into(),
        metrics.clone(),
    )?;
    if let Some(bootstrap) = config.mainline_enabled() {
        info!("mainline fallback enabled");
        store = store.with_mainline_fallback(bootstrap);
    };
    let server = Server::spawn(config, store, metrics).await?;
    tokio::signal::ctrl_c().await.anyerr()?;
    info!("shutdown");
    server.shutdown().await?;
    Ok(())
}

/// The iroh-dns server.
pub struct Server {
    http_server: HttpServer,
    dns_server: DnsServer,
    metrics_task: tokio::task::JoinHandle<Result<()>>,
}

impl Server {
    /// Spawn the server.
    ///
    /// This will spawn several background tasks:
    /// * A DNS server task
    /// * A HTTP server task, if `config.http` is not empty
    /// * A HTTPS server task, if `config.https` is not empty
    pub async fn spawn(config: Config, store: ZoneStore, metrics: Arc<Metrics>) -> Result<Self> {
        let cert_cache_dir = config.data_dir()?.join("cert_cache");
        let dns_handler = DnsHandler::new(store.clone(), &config.dns, metrics.clone())?;

        let state = AppState {
            store,
            dns_handler,
            metrics: metrics.clone(),
        };

        let metrics_addr = config.metrics_addr();
        let metrics_task = tokio::task::spawn(async move {
            if let Some(addr) = metrics_addr {
                let mut registry = iroh_metrics::Registry::default();
                registry.register(metrics);
                start_metrics_server(addr, Arc::new(registry))
                    .await
                    .anyerr()?;
            }
            Ok(())
        });
        let http_server = HttpServer::spawn(
            config.http,
            config.https,
            config.pkarr_put_rate_limit,
            state.clone(),
            cert_cache_dir,
        )
        .await?;
        let dns_server = DnsServer::spawn(config.dns, state.dns_handler.clone()).await?;
        Ok(Self {
            http_server,
            dns_server,
            metrics_task,
        })
    }

    /// Cancel the server tasks and wait for all tasks to complete.
    pub async fn shutdown(self) -> Result<()> {
        self.metrics_task.abort();
        let (res1, res2) = tokio::join!(self.dns_server.shutdown(), self.http_server.shutdown(),);
        res1?;
        res2?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// This will run forever unless all tasks close with an error, or `Self::cancel` is called.
    pub async fn run_until_error(self) -> Result<()> {
        tokio::select! {
            res = self.dns_server.run_until_done() => res?,
            res = self.http_server.run_until_done() => res?,
        }
        self.metrics_task.abort();
        Ok(())
    }

    /// Spawn a server suitable for testing.
    ///
    /// This will run the DNS and HTTP servers, but not the HTTPS server.
    ///
    /// It returns the server handle, the [`SocketAddr`] of the DNS server and the [`Url`] of the
    /// HTTP server.
    #[cfg(test)]
    pub async fn spawn_for_tests(dir: impl AsRef<Path>) -> Result<Self> {
        Self::spawn_for_tests_with_options(dir, None, None, None).await
    }

    /// Spawn a server suitable for testing, while optionally enabling mainline with custom
    /// bootstrap addresses.
    #[cfg(test)]
    pub async fn spawn_for_tests_with_options(
        dir: impl AsRef<Path>,
        mainline: Option<crate::config::BootstrapOption>,
        options: Option<crate::store::ZoneStoreOptions>,
        https: Option<HttpsConfig>,
    ) -> Result<Self> {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::config::MetricsConfig;

        let mut config = Config::default();
        config.dns.port = 0;
        config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.http.as_mut().unwrap().port = 0;
        config.http.as_mut().unwrap().bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.https = https;
        config.metrics = Some(MetricsConfig::disabled());
        config.data_dir = Some(dir.as_ref().to_owned());

        let mut store = ZoneStore::in_memory(options.unwrap_or_default(), Default::default())?;
        if let Some(bootstrap) = mainline {
            info!("mainline fallback enabled");
            store = store.with_mainline_fallback(bootstrap);
        }
        let server = Self::spawn(config, store, Default::default()).await?;
        Ok(server)
    }

    #[cfg(test)]
    pub(crate) fn dns_addr(&self) -> SocketAddr {
        self.dns_server.local_addr()
    }

    #[cfg(test)]
    pub(crate) fn http_url(&self) -> Option<Url> {
        let http_addr = self.http_server.http_addr()?;
        Some(
            format!("http://{http_addr}")
                .parse::<url::Url>()
                .expect("valid url"),
        )
    }

    #[cfg(test)]
    pub(crate) fn https_url(&self) -> Option<Url> {
        let https_addr = self.https_addr()?;
        Some(
            format!("https://{https_addr}")
                .parse::<url::Url>()
                .expect("valid url"),
        )
    }

    #[cfg(test)]
    pub(crate) fn https_addr(&self) -> Option<SocketAddr> {
        self.http_server.https_addr()
    }
}
