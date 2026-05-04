//! Portmapper integration.
//!
//! Re-exports the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

use std::net::SocketAddrV4;

#[cfg(all(not(wasm_browser), feature = "portmapper"))]
pub use ::portmapper::Metrics;
use tokio::sync::watch;

#[cfg(not(all(not(wasm_browser), feature = "portmapper")))]
pub use self::stub::Metrics;

/// Configuration for the portmapper service (UPnP, PCP, NAT-PMP).
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
    Disabled,
}

impl Default for PortmapperConfig {
    fn default() -> Self {
        PortmapperConfig::Enabled {}
    }
}

pub(crate) fn create_client(
    metrics: &crate::metrics::EndpointMetrics,
    config: &PortmapperConfig,
) -> Client {
    match config {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        PortmapperConfig::Enabled {} => Client::Enabled(::portmapper::Client::with_metrics(
            Default::default(),
            metrics.portmapper.clone(),
        )),
        _ => {
            let _ = metrics;
            let (tx, rx) = watch::channel(None);
            Client::Disabled { _tx: tx, rx }
        }
    }
}

/// Portmapper client: either the real implementation or a no-op.
///
/// The disabled variant is used when the `portmapper` feature is off, on wasm,
/// or when portmapping is disabled via [`PortmapperConfig::Disabled`].
#[derive(Debug)]
pub(crate) enum Client {
    /// The real portmapper client (requires the `portmapper` feature).
    #[cfg(all(not(wasm_browser), feature = "portmapper"))]
    Enabled(::portmapper::Client),
    /// No-op: keeps the sender alive so the receiver never closes.
    Disabled {
        _tx: watch::Sender<Option<SocketAddrV4>>,
        rx: watch::Receiver<Option<SocketAddrV4>>,
    },
}

impl Client {
    pub(crate) fn procure_mapping(&self) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.procure_mapping(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn update_local_port(&self, _port: std::num::NonZeroU16) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.update_local_port(_port),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn deactivate(&self) {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.deactivate(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        match self {
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.watch_external_address(),
            Client::Disabled { rx, .. } => rx.clone(),
        }
    }
}

#[cfg(not(all(not(wasm_browser), feature = "portmapper")))]
mod stub {
    use iroh_metrics::{Counter, MetricsGroup};
    use serde::{Deserialize, Serialize};

    /// Stub portmapper metrics used when the `portmapper` feature is disabled.
    #[derive(Debug, Default, MetricsGroup, Serialize, Deserialize)]
    #[metrics(name = "portmap")]
    pub struct Metrics {
        /// Number of probing tasks started.
        pub probes_started: Counter,
        /// Number of updates to the local port.
        pub local_port_updates: Counter,
        /// Number of mapping tasks started.
        pub mapping_attempts: Counter,
        /// Number of failed mapping tasks.
        pub mapping_failures: Counter,
        /// Number of times the external address obtained via port mapping was updated.
        pub external_address_updated: Counter,
        /// Number of UPnP probes executed.
        pub upnp_probes: Counter,
        /// Number of failed UPnP probes.
        pub upnp_probes_failed: Counter,
        /// Number of UPnP probes that found it available.
        pub upnp_available: Counter,
        /// Number of UPnP probes that resulted in a gateway different to the previous one.
        pub upnp_gateway_updated: Counter,
        /// Number of PCP probes executed.
        pub pcp_probes: Counter,
        /// Number of PCP probes that found it available.
        pub pcp_available: Counter,
    }
}
