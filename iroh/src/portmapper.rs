//! Portmapper integration.
//!
//! Wraps the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

use std::net::SocketAddrV4;

use tokio::sync::watch;

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

pub(crate) fn create_client(config: &PortmapperConfig) -> Client {
    match config {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        PortmapperConfig::Enabled {} => Client::Enabled(::portmapper::Client::default()),
        _ => {
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
