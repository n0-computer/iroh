use std::collections::BTreeMap;

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

use crate::rpc_protocol::node::CounterStats;

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
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
            doc_gossip_tick_main: Counter::new("Number of times the main gossip actor loop ticked"),
            doc_gossip_tick_event: Counter::new(
                "Number of times the gossip actor ticked for an event",
            ),
            doc_gossip_tick_actor: Counter::new(
                "Number of times the gossip actor ticked for an actor message",
            ),
            doc_gossip_tick_pending_join: Counter::new(
                "Number of times the gossip actor ticked pending join",
            ),

            doc_live_tick_main: Counter::new("Number of times the main live actor loop ticked"),
            doc_live_tick_actor: Counter::new(
                "Number of times the live actor ticked for an actor message",
            ),
            doc_live_tick_replica_event: Counter::new(
                "Number of times the live actor ticked for a replica event",
            ),
            doc_live_tick_running_sync_connect: Counter::new(
                "Number of times the live actor ticked for a running sync connect",
            ),
            doc_live_tick_running_sync_accept: Counter::new(
                "Number of times the live actor ticked for a running sync accept",
            ),
            doc_live_tick_pending_downloads: Counter::new(
                "Number of times the live actor ticked for a pending download",
            ),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh"
    }
}

/// Initialize the global metrics collection.
///
/// Will return an error if the global metrics collection was already initialized.
pub fn try_init_metrics_collection() -> std::io::Result<()> {
    iroh_metrics::core::Core::try_init(|reg, metrics| {
        metrics.insert(crate::metrics::Metrics::new(reg));
        metrics.insert(iroh_docs::metrics::Metrics::new(reg));
        metrics.insert(iroh_net::metrics::MagicsockMetrics::new(reg));
        metrics.insert(iroh_net::metrics::NetcheckMetrics::new(reg));
        metrics.insert(iroh_net::metrics::PortmapMetrics::new(reg));
    })
}

/// Collect the current metrics into a hash map.
///
/// TODO: Only counters are supported for now, other metrics will be skipped without error.
pub fn get_metrics() -> anyhow::Result<BTreeMap<String, CounterStats>> {
    let mut map = BTreeMap::new();
    let core =
        iroh_metrics::core::Core::get().ok_or_else(|| anyhow::anyhow!("metrics are disabled"))?;
    collect(
        core.get_collector::<iroh_docs::metrics::Metrics>(),
        &mut map,
    );
    collect(
        core.get_collector::<iroh_net::metrics::MagicsockMetrics>(),
        &mut map,
    );
    collect(
        core.get_collector::<iroh_net::metrics::NetcheckMetrics>(),
        &mut map,
    );
    collect(
        core.get_collector::<iroh_net::metrics::PortmapMetrics>(),
        &mut map,
    );
    Ok(map)
}

// TODO: support other things than counters
fn collect(metrics: Option<&impl Iterable>, map: &mut BTreeMap<String, CounterStats>) {
    let Some(metrics) = metrics else {
        return;
    };
    for (name, counter) in metrics.iter() {
        if let Some(counter) = counter.downcast_ref::<Counter>() {
            let value = counter.get();
            let description = counter.description.to_string();
            map.insert(name.to_string(), CounterStats { value, description });
        }
    }
}
