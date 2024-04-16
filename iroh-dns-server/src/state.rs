//! Shared state and store for the iroh-dns-server

use crate::{dns::DnsHandler, store::ZoneStore};

/// The shared app state.
#[derive(Clone)]
pub struct AppState {
    /// The pkarr DNS store
    pub store: ZoneStore,
    /// Handler for DNS requests
    pub dns_handler: DnsHandler,
}
