//! Co-locating all of the iroh metrics structs
use std::sync::Arc;

use iroh_metrics::{MetricsGroup, MetricsGroupSet};
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, net_report::Metrics as NetReportMetrics};

/// Metrics collected by an [`crate::endpoint::Endpoint`].
///
/// The metrics for an endpoint can be accessed via [`crate::endpoint::Endpoint::metrics`].
/// You can access individual metrics directly by using the public fields.
/// ```rust
/// # use std::collections::BTreeMap;
/// # use iroh_metrics::{MetricsGroup, MetricValue, MetricsGroupSet};
/// # use iroh::endpoint::Endpoint;
/// # async fn wrapper() -> testresult::TestResult {
/// let endpoint = Endpoint::builder().bind().await?;
/// let metrics = endpoint.metrics();
///
/// assert_eq!(metrics.magicsock.recv_datagrams.get(), 0);
/// # Ok(())
/// # }
/// ```
///
/// [`EndpointMetrics] implements [`MetricsGroupSet`], and all fields of this struct implement
/// implement [`iroh_metrics::MetricsGroup`]. These trait provides various methods to iterate
/// the groups in the set, and over the individual metrics in each group, without having
/// to access each field manually. With these methods, it is straightforward to collect
/// all metrics into a map or push their values to some other metrics collector.
///
/// For example, the following snippet collects all metrics into a map:
/// ```rust
/// # use std::collections::BTreeMap;
/// # use iroh_metrics::{MetricsGroup, MetricValue, MetricsGroupSet};
/// # use iroh::endpoint::Endpoint;
/// # async fn wrapper() -> testresult::TestResult {
/// let endpoint = Endpoint::builder().bind().await?;
/// let metrics: BTreeMap<String, MetricValue> = endpoint
///     .metrics()
///     .iter()
///     .flat_map(|group| {
///         group.values().map(|item| {
///             let name = [group.name(), item.name].join(":");
///             (name, item.value)
///         })
///     })
///     .collect();
///
/// assert_eq!(metrics["magicsock:recv_datagrams"], MetricValue::Counter(0));
/// # Ok(())
/// # }
/// ```
///
/// The metrics can also be used with the types from the `prometheus_client` crate.
/// With [`EndpointMetrics::register`], you can register all metrics onto a onto a
/// [`prometheus_client::Registry`]. [`iroh_metrics`] provides functions to easily start
/// services to serve the metrics with a HTTP server, dump them to a file, or push them
/// to a Prometheus gateway. See the `service` module in `iroh_metrics` for details.
///
/// [`prometheus_client::Registry`]: https://docs.rs/prometheus-client/latest/prometheus_client/registry/struct.Registry.html
#[derive(Default, Debug, Clone)]
pub struct EndpointMetrics {
    /// Metrics collected by the endpoint's socket.
    pub magicsock: Arc<MagicsockMetrics>,
    /// Metrics collected by net reports.
    pub net_report: Arc<NetReportMetrics>,
    /// Metrics collected by the portmapper service.
    #[cfg(not(wasm_browser))]
    pub portmapper: Arc<PortmapMetrics>,
}

impl MetricsGroupSet for EndpointMetrics {
    fn iter(&self) -> impl Iterator<Item = &dyn MetricsGroup> {
        #[cfg(not(wasm_browser))]
        return [
            &*self.magicsock as &dyn MetricsGroup,
            &*self.net_report as &dyn MetricsGroup,
            &*self.portmapper as &dyn MetricsGroup,
        ]
        .into_iter();
        #[cfg(wasm_browser)]
        return [
            &*self.magicsock as &dyn MetricsGroup,
            &*self.net_report as &dyn MetricsGroup,
        ]
        .into_iter();
    }

    fn name(&self) -> &'static str {
        "endpoint"
    }
}
