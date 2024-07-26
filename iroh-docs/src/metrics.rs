//! Metrics for iroh-docs

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Metrics for iroh-docs
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

    pub actor_tick_main: Counter,

    pub doc_gossip_tick_main: Counter,
    pub doc_gossip_tick_event: Counter,
    pub doc_gossip_tick_actor: Counter,
    pub doc_gossip_tick_pending_join: Counter,

    pub doc_live_tick_main: Counter,
    pub doc_live_tick_actor: Counter,
    pub doc_live_tick_replica_event: Counter,
    pub doc_live_tick_running_sync_connect: Counter,
    pub doc_live_tick_running_sync_accept: Counter,
    pub doc_live_tick_pending_downloads: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            new_entries_local: Counter::new("Number of document entries added locally"),
            new_entries_remote: Counter::new("Number of document entries added by peers"),
            new_entries_local_size: Counter::new("Total size of entry contents added locally"),
            new_entries_remote_size: Counter::new("Total size of entry contents added by peers"),
            sync_via_accept_success: Counter::new("Number of successful syncs (via accept)"),
            sync_via_accept_failure: Counter::new("Number of failed syncs (via accept)"),
            sync_via_connect_success: Counter::new("Number of successful syncs (via connect)"),
            sync_via_connect_failure: Counter::new("Number of failed syncs (via connect)"),

            actor_tick_main: Counter::new("Number of times the main actor loop ticked"),

            doc_gossip_tick_main: Counter::new("Number of times the gossip actor loop ticked"),
            doc_gossip_tick_event: Counter::new(
                "Number of times the gossip actor processed an event",
            ),
            doc_gossip_tick_actor: Counter::new(
                "Number of times the gossip actor processed an actor event",
            ),
            doc_gossip_tick_pending_join: Counter::new(
                "Number of times the gossip actor processed a pending join",
            ),

            doc_live_tick_main: Counter::new("Number of times the live actor loop ticked"),
            doc_live_tick_actor: Counter::new(
                "Number of times the live actor processed an actor event",
            ),
            doc_live_tick_replica_event: Counter::new(
                "Number of times the live actor processed a replica event",
            ),
            doc_live_tick_running_sync_connect: Counter::new(
                "Number of times the live actor processed a running sync connect",
            ),
            doc_live_tick_running_sync_accept: Counter::new(
                "Number of times the live actor processed a running sync accept",
            ),
            doc_live_tick_pending_downloads: Counter::new(
                "Number of times the live actor processed a pending download",
            ),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh_docs"
    }
}
