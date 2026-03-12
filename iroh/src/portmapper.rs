//! Portmapper integration.
//!
//! Re-exports the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

#[cfg(all(not(wasm_browser), feature = "portmapper"))]
pub(crate) use ::portmapper::Client;
#[cfg(all(not(wasm_browser), feature = "portmapper"))]
pub use ::portmapper::Metrics;

#[cfg(all(not(wasm_browser), feature = "portmapper"))]
pub(crate) fn create_client(metrics: &crate::metrics::EndpointMetrics) -> Client {
    Client::with_metrics(Default::default(), metrics.portmapper.clone())
}

#[cfg(not(all(not(wasm_browser), feature = "portmapper")))]
pub(crate) use stub::Client;

#[cfg(not(all(not(wasm_browser), feature = "portmapper")))]
pub(crate) fn create_client(_metrics: &crate::metrics::EndpointMetrics) -> Client {
    Client::new()
}

#[cfg(not(all(not(wasm_browser), feature = "portmapper")))]
mod stub {
    use std::net::SocketAddrV4;

    use tokio::sync::watch;

    /// No-op portmapper client used when the `portmapper` feature is disabled.
    #[derive(Debug)]
    pub(crate) struct Client {
        // Keep the sender alive so the receiver is never closed.
        _tx: watch::Sender<Option<SocketAddrV4>>,
        rx: watch::Receiver<Option<SocketAddrV4>>,
    }

    impl Client {
        pub(crate) fn new() -> Self {
            let (tx, rx) = watch::channel(None);
            Client { _tx: tx, rx }
        }

        pub(crate) fn procure_mapping(&self) {}
        pub(crate) fn update_local_port(&self, _: std::num::NonZeroU16) {}
        pub(crate) fn deactivate(&self) {}

        pub(crate) fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
            self.rx.clone()
        }
    }
}
