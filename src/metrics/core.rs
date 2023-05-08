use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::Lazy;
use prometheus_client::{encoding::text::encode, registry::Registry};

use crate::metrics::iroh;

pub(crate) static CORE: Lazy<Core> = Lazy::new(Core::default);

pub(crate) struct Core {
    enabled: AtomicBool,
    registry: Registry,
    iroh_metrics: iroh::Metrics,
}

impl Default for Core {
    fn default() -> Self {
        let mut reg = Registry::default();
        Core {
            enabled: AtomicBool::new(false),
            iroh_metrics: iroh::Metrics::new(&mut reg),
            registry: reg,
        }
    }
}

impl Core {
    pub(crate) fn registry(&self) -> &Registry {
        &self.registry
    }

    pub(crate) fn iroh_metrics(&self) -> &iroh::Metrics {
        &self.iroh_metrics
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![];
        encode(&mut buf, self.registry())?;
        Ok(buf)
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.swap(enabled, Ordering::Relaxed);
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Defines the metric trait which provides a common interface for all value based metrics
pub trait MetricType {
    /// Returns the name of the metric
    fn name(&self) -> &'static str;
}

/// Defines the histogram trait which provides a common interface for all  based metrics
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

/// Interface to record metrics
/// Helps expose the record interface when using metrics as a library
pub trait MRecorder {
    /// Records a value for the metric
    fn record(&self, value: u64);
}

/// Interface to observe metrics
/// Helps expose the observe interface when using metrics as a library
pub trait MObserver {
    /// Observes a value for the metric
    fn observe(&self, value: f64);
}

// Internal wrapper to record metrics only if the core is enabled
#[allow(unreachable_patterns)]
pub(crate) fn record<M>(c: Collector, m: M, v: u64)
where
    M: MetricType + std::fmt::Display,
{
    if CORE.is_enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().record(m, v),
            _ => unimplemented!("not enabled/implemented"),
        };
    }
}

// Internal wrapper to observe metrics only if the core is enabled
#[allow(unreachable_patterns, dead_code)]
pub(crate) fn observe<M>(c: Collector, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if CORE.is_enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().observe(m, v),
            _ => unimplemented!("not enabled/implemented"),
        };
    }
}

/// List of all collectors
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum Collector {
    /// Iroh collector aggregates all metrics from the iroh binary
    Iroh,
}
