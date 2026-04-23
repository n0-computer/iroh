//! The main server which combines the DNS and HTTP(S) servers.
#[cfg(test)]
use std::path::Path;
use std::{net::SocketAddr, sync::Arc};

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

/// A running iroh-dns server.
///
/// Combines a DNS listener and an HTTP/HTTPS listener into a single handle.
/// Construct with [`Self::bind`] and drive to completion with [`Self::join`], or
/// stop the tasks with [`Self::shutdown`].
pub struct Server {
    http_server: HttpServer,
    dns_server: DnsServer,
    metrics_task: tokio::task::JoinHandle<Result<()>>,
}

impl Server {
    /// Binds and spawns the server from a [`Config`].
    ///
    /// Opens (or creates) the persistent signed-packet store at the path returned
    /// by [`Config::signed_packet_store_path`], enables the mainline DHT fallback
    /// when configured, and then spawns the DNS, HTTP(S), and metrics tasks.
    ///
    /// Returns once all listeners are bound. Use [`Self::join`] to wait for the
    /// tasks to finish.
    ///
    /// # Errors
    ///
    /// Returns an error if the data directory cannot be created, the store
    /// cannot be opened, or any of the listeners fails to bind.
    pub async fn bind(config: Config) -> Result<Self> {
        let metrics = Arc::new(Metrics::default());
        let mut store = ZoneStore::persistent(
            config.signed_packet_store_path()?,
            config.zone_store.clone().unwrap_or_default().into(),
            metrics.clone(),
        )?;
        if let Some(bootstrap) = config.mainline_enabled() {
            info!("mainline fallback enabled");
            store = store.with_mainline_fallback(bootstrap);
        };
        Self::bind_with_store(config, store, metrics).await
    }

    /// Spawn the server.
    ///
    /// This will spawn several background tasks:
    /// * A DNS server task
    /// * A HTTP server task, if `config.http` is not empty
    /// * A HTTPS server task, if `config.https` is not empty
    async fn bind_with_store(
        config: Config,
        store: ZoneStore,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
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

    /// Cancels the server tasks and waits for them to complete.
    pub async fn shutdown(self) -> Result<()> {
        self.metrics_task.abort();
        let (res1, res2) = tokio::join!(self.dns_server.shutdown(), self.http_server.shutdown(),);
        res1?;
        res2?;
        Ok(())
    }

    /// Waits for the server tasks to complete.
    ///
    /// Runs until one of the listener tasks returns (with success or an error),
    /// or until [`Self::shutdown`] is called on a separate handle.
    pub async fn join(self) -> Result<()> {
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
    pub(crate) async fn spawn_for_tests(dir: impl AsRef<Path>) -> Result<Self> {
        Self::spawn_for_tests_with_options(dir, None, None, None).await
    }

    /// Spawn a server suitable for testing, while optionally enabling mainline with custom
    /// bootstrap addresses.
    #[cfg(test)]
    pub(crate) async fn spawn_for_tests_with_options(
        dir: impl AsRef<Path>,
        mainline: Option<crate::config::BootstrapOption>,
        options: Option<crate::store::Options>,
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
        let server = Self::bind_with_store(config, store, Default::default()).await?;
        Ok(server)
    }

    /// Returns the local address that the DNS listener is bound to.
    ///
    /// Useful when the config requested port `0` and the actual port needs to be
    /// discovered after binding.
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_server.local_addr()
    }

    /// Returns the local address of the HTTP listener, if one is running.
    ///
    /// Returns `None` when no [`HttpConfig`](crate::config::HttpConfig) was
    /// configured.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_server.http_addr()
    }

    /// Returns the local address of the HTTPS listener, if one is running.
    ///
    /// Returns `None` when no [`HttpsConfig`](crate::config::HttpsConfig) was
    /// configured.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.http_server.https_addr()
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
}
