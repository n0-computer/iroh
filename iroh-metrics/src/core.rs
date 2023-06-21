use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::Lazy;
use prometheus_client::{encoding::text::encode, registry::Registry};

use crate::{iroh, magicsock, netcheck};

pub static CORE: Lazy<Core> = Lazy::new(Core::default);

#[derive(Debug)]
pub struct Core {
    enabled: AtomicBool,
    registry: Registry,
    iroh_metrics: iroh::Metrics,
    magicsock_metrics: magicsock::Metrics,
    netcheck_metrics: netcheck::Metrics,
}

impl Default for Core {
    fn default() -> Self {
        let mut reg = Registry::default();
        Core {
            enabled: AtomicBool::new(false),
            iroh_metrics: iroh::Metrics::new(&mut reg),
            magicsock_metrics: magicsock::Metrics::new(&mut reg),
            netcheck_metrics: netcheck::Metrics::new(&mut reg),
            registry: reg,
        }
    }
}

impl Core {
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn iroh_metrics(&self) -> &iroh::Metrics {
        &self.iroh_metrics
    }

    pub fn magicsock_metrics(&self) -> &magicsock::Metrics {
        &self.magicsock_metrics
    }

    pub fn netcheck_metrics(&self) -> &netcheck::Metrics {
        &self.netcheck_metrics
    }

    pub(crate) fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        encode(&mut buf, self.registry())?;
        Ok(buf)
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.swap(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
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

/// Definition of the base metrics collection interfaces.
///
/// Instances imlementing the MetricsRecorder are expected to have a defined mapping between
/// types for the respective modules.
pub trait MetricsRecorder {
    /// Records a metric for any point in time metric (e.g. counter, gauge, etc.)
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display;
    /// Observes a metric for any metric over time (e.g. histogram, summary, etc.)
    fn observe<M>(&self, m: M, value: f64)
    where
        M: HistogramType + std::fmt::Display;
}

/// Interface to record metrics.
///
/// Helps expose the record interface when using metrics as a library
pub trait MRecorder {
    /// Records a value for the metric.
    ///
    /// Recording is for single-value metrics, each recorded metric represents a metric
    /// value.
    fn record(&self, value: u64);
}

/// Interface to observe metrics.
///
/// Helps expose the observe interface when using metrics as a library.
pub trait MObserver {
    /// Observes a value for the metric.
    ///
    /// Observing is for distribution metrics, when multiple observations are combined in a
    /// single metric value.
    fn observe(&self, value: f64);
}

/// Internal wrapper to record metrics only if the core is enabled.
///
/// Recording is for single-value metrics, each recorded metric represents a metric value.
pub(crate) fn record<M>(c: Collector, m: M, v: u64)
where
    M: MetricType + std::fmt::Display,
{
    if CORE.is_enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().record(m, v),
            Collector::Magicsock => CORE.magicsock_metrics().record(m, v),
            Collector::Netcheck => CORE.netcheck_metrics().record(m, v),
        };
    }
}

/// Internal wrapper to observe metrics only if the core is enabled.
///
/// Observing is for distribution metrics, when multiple observations are combined in a
/// single metric value.
#[allow(dead_code)]
pub(crate) fn observe<M>(c: Collector, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if CORE.is_enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().observe(m, v),
            Collector::Magicsock => CORE.magicsock_metrics().observe(m, v),
            Collector::Netcheck => CORE.netcheck_metrics().observe(m, v),
        };
    }
}

/// List of all collectors
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum Collector {
    /// Iroh collector aggregates all metrics from the iroh binary
    Iroh,
    /// Magicsock related metrics.
    Magicsock,
    /// Netcheck related metrics.
    Netcheck,
}
