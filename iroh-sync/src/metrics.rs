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
    pub initial_sync_success: Counter,
    pub initial_sync_failed: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            new_entries_local: Counter::new("Number of document entries added locally"),
            new_entries_remote: Counter::new("Number of document entries added by peers"),
            new_entries_local_size: Counter::new("Total size of entry contents added locally"),
            new_entries_remote_size: Counter::new("Total size of entry contents added by peers"),
            initial_sync_success: Counter::new("Number of successfull initial syncs "),
            initial_sync_failed: Counter::new("Number of failed initial syncs"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh-sync"
    }
}
