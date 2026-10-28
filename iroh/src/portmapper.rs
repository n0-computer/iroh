//! Portmapper integration.
//!
//! Wraps the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

use std::net::SocketAddrV4;

use tokio_util::sync::CancellationToken;
#[cfg(all(not(wasm_browser), feature = "portmapper"))]
use {
    n0_future::time::{self, Duration},
    rand::RngExt,
    tokio::sync::watch,
    tracing::{debug, trace},
};

use crate::metrics::EndpointMetrics;

/// Configuration for the portmapper service (UPnP, PCP, NAT-PMP).
///
/// Port mapping asks the local router to open an external port so peers can
/// reach this endpoint directly, improving connectivity behind NATs. The
/// discovery step (UPnP uses SSDP multicast) can, however, trigger firewall
/// prompts on some networks — see [`PortmapperConfig::Disabled`].
///
/// Used with [`crate::endpoint::Builder::portmapper_config`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PortmapperConfig {
    /// Enable portmapping with default settings.
    ///
    /// This is the default.
    #[non_exhaustive]
    Enabled {},
    /// Disable portmapping.
    ///
    /// Skips the UPnP/PCP/NAT-PMP gateway probing. Use this to avoid the
    /// SSDP multicast discovery that can raise firewall dialogs (notably on
    /// macOS), at the cost of potentially worse direct connectivity behind
    /// some NATs.
    Disabled,
}

impl Default for PortmapperConfig {
    fn default() -> Self {
        PortmapperConfig::Enabled {}
    }
}

pub(crate) fn create_client(
    config: &PortmapperConfig,
    metrics: EndpointMetrics,
    shutdown: CancellationToken,
) -> Client {
    #[cfg(all(not(wasm_browser), feature = "portmapper"))]
    if matches!(config, PortmapperConfig::Enabled { .. }) {
        let service = ::portmapper::Client::default();
        let external = service.watch_external_address();
        let interval = rand::rng().random_range(Duration::from_secs(20)..=Duration::from_secs(26));
        return Client::Enabled {
            service,
            external,
            retry: time::interval(interval),
            metrics,
            shutdown,
        };
    }
    let _ = (config, metrics, shutdown);
    Client::Disabled
}

/// Owns mapping retries, address notifications, and mapping release on drop.
#[derive(Debug)]
pub(crate) enum Client {
    #[cfg(all(not(wasm_browser), feature = "portmapper"))]
    Enabled {
        service: ::portmapper::Client,
        external: watch::Receiver<Option<SocketAddrV4>>,
        retry: time::Interval,
        metrics: EndpointMetrics,
        shutdown: CancellationToken,
    },
    Disabled,
}

impl Client {
    /// Waits for a changed mapping while retrying failed acquisition attempts.
    pub(crate) async fn updated(&mut self) -> Option<SocketAddrV4> {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        while let Self::Enabled {
            external,
            retry,
            metrics,
            ..
        } = self
        {
            tokio::select! {
                changed = external.changed() => {
                    if changed.is_err() { break; }
                    let external = *external.borrow_and_update();
                    metrics.socket.actor_tick_portmap_changed.inc();
                    if external.is_some() {
                        metrics.net_report.portmap_external_address_updated.inc();
                    }
                    debug!(?external, "external address updated");
                    return external;
                }
                _ = retry.tick() => {
                    metrics.socket.actor_tick_re_stun.inc();
                }
            }
            self.procure_mapping();
        }
        std::future::pending().await
    }

    pub(crate) fn external_address(&self) -> Option<SocketAddrV4> {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Self::Enabled { external, .. } => *external.borrow(),
            Self::Disabled => None,
        }
    }

    /// Asks for a mapping if none exists; the service renews existing mappings.
    pub(crate) fn procure_mapping(&self) {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        if let Self::Enabled {
            service,
            metrics,
            shutdown,
            ..
        } = self
        {
            if shutdown.is_cancelled() {
                trace!("skipping port mapping: shutting down");
                return;
            }
            metrics.net_report.portmap_attempts.inc();
            service.procure_mapping();
        }
    }

    pub(crate) fn update_local_port(&self, _port: std::num::NonZeroU16) {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        if let Self::Enabled { service, .. } = self {
            service.update_local_port(_port);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        if let Self::Enabled { service, .. } = self {
            service.deactivate();
        }
    }
}
