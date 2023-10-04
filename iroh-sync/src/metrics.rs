//! Metrics for iroh-sync

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Metrics for iroh-sync
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub new_entries_local: Counter,
    pub new_entries_remote: Counter,
    pub new_entries_local_size: Counter,
    pub new_entries_remote_size: Counter,
    pub sync_via_connect_success: Counter,
    pub sync_via_connect_failure: Counter,
    pub sync_via_accept_success: Counter,
    pub sync_via_accept_failure: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            new_entries_local: Counter::new("Number of document entries added locally"),
            new_entries_remote: Counter::new("Number of document entries added by peers"),
            new_entries_local_size: Counter::new("Total size of entry contents added locally"),
            new_entries_remote_size: Counter::new("Total size of entry contents added by peers"),
            sync_via_accept_success: Counter::new("Number of successfull syncs (via accept)"),
            sync_via_accept_failure: Counter::new("Number of failed syncs (via accept)"),
            sync_via_connect_success: Counter::new("Number of successfull syncs (via connect)"),
            sync_via_connect_failure: Counter::new("Number of failed syncs (via connect)"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh_sync"
    }
}
