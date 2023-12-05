use anyhow::Error;
use erased_set::ErasedSyncSet;
use once_cell::sync::OnceCell;
#[cfg(feature = "metrics")]
use prometheus_client::{encoding::text::encode, registry::Registry};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::trace;
#[cfg(not(feature = "metrics"))]
type Registry = ();

static CORE: OnceCell<Core> = OnceCell::new();

/// Core is the base metrics struct.
/// It manages the mapping between the metrics name and the actual metrics.
/// It also carries a single prometheus registry to be used by all metrics.
#[derive(Debug, Default)]
pub struct Core {
    #[cfg(feature = "metrics")]
    registry: Registry,
    metrics_map: ErasedSyncSet,
    #[cfg(feature = "metrics")]
    usage_reporter: UsageReporter,
}
/// Open Metrics [`Counter`] to measure discrete events.
///
/// Single monotonically increasing value metric.
#[derive(Debug, Clone)]
pub struct Counter {
    /// The actual prometheus counter.
    #[cfg(feature = "metrics")]
    pub counter: prometheus_client::metrics::counter::Counter,
    /// What this counter measures.
    pub description: &'static str,
}

impl Counter {
    /// Constructs a new counter, based on the given `description`.
    pub fn new(description: &'static str) -> Self {
        Counter {
            #[cfg(feature = "metrics")]
            counter: Default::default(),
            description,
        }
    }

    /// Increase the [`Counter`] by 1, returning the previous value.
    pub fn inc(&self) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.counter.inc()
        }
        #[cfg(not(feature = "metrics"))]
        0
    }

    /// Increase the [`Counter`] by `u64`, returning the previous value.
    #[cfg(feature = "metrics")]
    pub fn inc_by(&self, v: u64) -> u64 {
        self.counter.inc_by(v)
    }

    /// Increase the [`Counter`] by `u64`, returning the previous value.
    #[cfg(not(feature = "metrics"))]
    pub fn inc_by(&self, _v: u64) -> u64 {
        0
    }

    /// Get the current value of the [`Counter`].
    pub fn get(&self) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.counter.get()
        }
        #[cfg(not(feature = "metrics"))]
        0
    }
}

/// Description of a group of metrics.
pub trait Metric:
    Default + struct_iterable::Iterable + Sized + std::fmt::Debug + 'static + Send + Sync
{
    /// Initializes this metric group.
    #[cfg(feature = "metrics")]
    fn new(registry: &mut prometheus_client::registry::Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix(Self::name());

        let this = Self::default();
        for (metric, counter) in this.iter() {
            if let Some(counter) = counter.downcast_ref::<Counter>() {
                sub_registry.register(metric, counter.description, counter.counter.clone());
            }
        }
        this
    }

    /// Initializes this metric group.
    #[cfg(not(feature = "metrics"))]
    fn new(_: &mut ()) -> Self {
        Self::default()
    }

    /// The name of this metric group.
    fn name() -> &'static str;

    /// Access to this metrics group to record a metric.
    /// Only records if this metric is registered in the global registry.
    #[cfg(feature = "metrics")]
    fn with_metric<T, F: FnOnce(&Self) -> T>(f: F) {
        Self::try_get().map(f);
    }

    /// Access to this metrics group to record a metric.
    #[cfg(not(feature = "metrics"))]
    fn with_metric<T, F: FnOnce(&Self) -> T>(_f: F) {
        // nothing to do
    }

    /// Attempts to get the current metric from the global registry.
    fn try_get() -> Option<&'static Self> {
        Core::get().and_then(|c| c.get_collector::<Self>())
    }
}

impl Core {
    /// Must only be called once to init metrics.
    ///
    /// Panics if called a second time.
    pub fn init<F: FnOnce(&mut Registry, &mut ErasedSyncSet)>(f: F) {
        Self::try_init(f).expect("must only be called once");
    }

    /// Trieds to init the metrics.
    pub fn try_init<F: FnOnce(&mut Registry, &mut ErasedSyncSet)>(f: F) -> std::io::Result<()> {
        let mut registry = Registry::default();
        let mut metrics_map = ErasedSyncSet::new();
        f(&mut registry, &mut metrics_map);

        #[cfg(feature = "metrics")]
        let usage_reporter = UsageReporter::new();

        CORE.set(Core {
            metrics_map,
            #[cfg(feature = "metrics")]
            registry,
            #[cfg(feature = "metrics")]
            usage_reporter,
        })
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "already set"))
    }

    /// Returns a reference to the core metrics.
    pub fn get() -> Option<&'static Self> {
        CORE.get()
    }

    /// Returns a reference to the prometheus registry.
    #[cfg(feature = "metrics")]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Returns a reference to the mapped metrics instance.
    pub fn get_collector<T: Metric>(&self) -> Option<&T> {
        self.metrics_map.get::<T>()
    }

    #[cfg(feature = "metrics")]
    pub(crate) fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry)?;
        Ok(buf)
    }

    #[cfg(feature = "metrics")]
    pub(crate) fn usage_reporter(&self) -> &UsageReporter {
        &self.usage_reporter
    }
}

/// Interface for all single value based metrics.
pub trait MetricType {
    /// Returns the name of the metric
    fn name(&self) -> &'static str;
}

/// Interface for all distribution based metrics.
pub trait HistogramType {
    /// Returns the name of the metric
    fn name(&self) -> &'static str;
}

/// Exposes a simple API to report usage statistics.
#[derive(Debug, Default)]
pub struct UsageReporter {
    pub(crate) report_endpoint: Option<String>,
    pub(crate) report_token: Option<String>,
}

impl UsageReporter {
    /// Creates a new usage reporter.
    pub fn new() -> Self {
        let report_endpoint = std::env::var("IROH_METRICS_USAGE_STATS_ENDPOINT").ok();
        let report_token = std::env::var("IROH_METRICS_USAGE_STATS_TOKEN").ok();
        UsageReporter {
            report_endpoint,
            report_token,
        }
    }

    /// Reports usage statistics to the configured endpoint.
    pub async fn report_usage_stats(&self, report: &UsageStatsReport) -> Result<(), Error> {
        if let Some(report_endpoint) = &self.report_endpoint {
            trace!("reporting usage stats to {}", report_endpoint);
            let mut client = reqwest::Client::new().post(report_endpoint);

            if let Some(report_token) = &self.report_token {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::COOKIE,
                    format!("token={}", report_token).parse().unwrap(),
                );
                client = client.headers(headers);
            }
            let _ = client.json(report).send().await?;
        }
        Ok(())
    }
}

/// Usage statistics report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageStatsReport {
    /// The timestamp of the report.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// The resource being consumed.
    pub resource: String,
    /// Reference to the resource reporter.
    pub resource_ref: String,
    /// The value of the resource being consumed.
    pub value: i64,
    /// Identifier of the user consuming the resource.
    pub attribution_id: Option<String>,
    /// Public key of the user consuming the resource.
    pub attribution_key: Option<String>,
}

/// Type alias for a metered resource.
pub type UsageResource = String;

impl UsageStatsReport {
    /// Creates a new usage stats report.
    pub fn new(
        resource: UsageResource,
        resource_ref: String,
        value: i64,
        attribution_id: Option<String>,
        attribution_key: Option<String>,
    ) -> Self {
        let timestamp = OffsetDateTime::now_utc();
        UsageStatsReport {
            timestamp,
            resource,
            resource_ref,
            value,
            attribution_id,
            attribution_key,
        }
    }
}
