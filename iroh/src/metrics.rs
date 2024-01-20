use std::collections::BTreeMap;

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

use crate::rpc_protocol::CounterStats;

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub requests_total: Counter,
    pub bytes_sent: Counter,
    pub bytes_received: Counter,
    pub download_bytes_total: Counter,
    pub download_time_total: Counter,
    pub downloads_success: Counter,
    pub downloads_error: Counter,
    pub downloads_notfound: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: Counter::new("Total number of requests received"),
            bytes_sent: Counter::new("Number of bytes streamed"),
            bytes_received: Counter::new("Number of bytes received"),
            download_bytes_total: Counter::new("Total number of content bytes downloaded"),
            download_time_total: Counter::new("Total time in ms spent downloading content bytes"),
            downloads_success: Counter::new("Total number of successful downloads"),
            downloads_error: Counter::new("Total number of downloads failed with error"),
            downloads_notfound: Counter::new("Total number of downloads failed with not found"),
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
        metrics.insert(iroh_sync::metrics::Metrics::new(reg));
        metrics.insert(iroh_net::metrics::MagicsockMetrics::new(reg));
        metrics.insert(iroh_net::metrics::NetcheckMetrics::new(reg));
        metrics.insert(iroh_net::metrics::PortmapMetrics::new(reg));
        metrics.insert(iroh_net::metrics::DerpMetrics::new(reg));
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
        core.get_collector::<iroh_sync::metrics::Metrics>(),
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
    collect(
        core.get_collector::<iroh_net::metrics::DerpMetrics>(),
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
