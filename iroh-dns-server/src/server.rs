//! The main server which combines the DNS and HTTP(S) servers.

use anyhow::Result;
use iroh_metrics::metrics::start_metrics_server;
use tracing::info;

use crate::{
    config::Config,
    dns::{DnsHandler, DnsServer},
    http::HttpServer,
    state::AppState,
    store::ZoneStore,
};

/// Spawn the server and run until the `Ctrl-C` signal is received, then shutdown.
pub async fn run_with_config_until_ctrl_c(config: Config) -> Result<()> {
    let store = ZoneStore::persistent(Config::signed_packet_store_path()?)?;
    let server = Server::spawn(config, store).await?;
    tokio::signal::ctrl_c().await?;
    info!("shutdown");
    server.shutdown().await?;
    Ok(())
}

/// The iroh-dns server.
pub struct Server {
    http_server: HttpServer,
    dns_server: DnsServer,
    metrics_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Server {
    /// Spawn the server.
    ///
    /// This will spawn several background tasks:
    /// * A DNS server task
    /// * A HTTP server task, if `config.http` is not empty
    /// * A HTTPS server task, if `config.https` is not empty
    pub async fn spawn(config: Config, store: ZoneStore) -> Result<Self> {
        let dns_handler = DnsHandler::new(store.clone(), &config.dns)?;

        let state = AppState { store, dns_handler };

        let metrics_addr = config.metrics_addr();
        let metrics_task = tokio::task::spawn(async move {
            if let Some(addr) = metrics_addr {
                start_metrics_server(addr).await?;
            }
            Ok(())
        });
        let http_server = HttpServer::spawn(config.http, config.https, state.clone()).await?;
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
    pub async fn spawn_for_tests() -> Result<(Self, std::net::SocketAddr, url::Url)> {
        use crate::config::MetricsConfig;
        use std::net::{IpAddr, Ipv4Addr};

        let mut config = Config::default();
        config.dns.port = 0;
        config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.http.as_mut().unwrap().port = 0;
        config.http.as_mut().unwrap().bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.https = None;
        config.metrics = Some(MetricsConfig::disabled());

        let store = ZoneStore::in_memory()?;
        let server = Self::spawn(config, store).await?;
        let dns_addr = server.dns_server.local_addr();
        let http_addr = server.http_server.http_addr().expect("http is set");
        let http_url = format!("http://{http_addr}").parse()?;
        Ok((server, dns_addr, http_url))
    }
}
