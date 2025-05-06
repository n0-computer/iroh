//! Shared state and store for the iroh-dns-server

use std::sync::Arc;

use crate::{dns::DnsHandler, metrics::Metrics, store::ZoneStore};

/// The shared app state.
#[derive(Clone)]
pub struct AppState {
    /// The pkarr DNS store
    pub store: ZoneStore,
    /// Handler for DNS requests
    pub dns_handler: DnsHandler,
    /// Metrics collector.
    pub metrics: Arc<Metrics>,
}
