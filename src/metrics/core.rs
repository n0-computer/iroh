use std::sync::atomic::{AtomicBool, Ordering};

use prometheus_client::{encoding::text::encode, registry::Registry};

use crate::metrics::iroh;

lazy_static! {
    pub(crate) static ref CORE: Core = Core::default();
}

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

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// defines the metric trait
pub trait MetricType {
    /// returns the name of the metric
    fn name(&self) -> &'static str;
}

/// defines the histogram trait
pub trait HistogramType {
    /// returns the name of the metric
    fn name(&self) -> &'static str;
}

/// definition of the metrics collection interfaces
pub trait MetricsRecorder {
    /// records a metric for any point in time metric (e.g. counter, gauge, etc.)
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display;
    /// observes a metric for any metric over time (e.g. histogram, summary, etc.)
    fn observe<M>(&self, m: M, value: f64)
    where
        M: HistogramType + std::fmt::Display;
}

/// interface to record metrics
pub trait MRecorder {
    /// records a value for the metric
    fn record(&self, value: u64);
}

/// interface to observe metrics
pub trait MObserver {
    /// observes a value for the metric
    fn observe(&self, value: f64);
}

/// defines the generic record function
#[allow(unused_variables, unreachable_patterns)]
pub fn record<M>(c: Collector, m: M, v: u64)
where
    M: MetricType + std::fmt::Display,
{
    if CORE.enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().record(m, v),
            _ => panic!("not enabled/implemented"),
        };
    }
}

// not currently used
#[allow(unused_variables, unreachable_patterns, dead_code)]
fn observe<M>(c: Collector, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if CORE.enabled() {
        match c {
            Collector::Iroh => CORE.iroh_metrics().observe(m, v),
            _ => panic!("not enabled/implemented"),
        };
    }
}

/// list of all collectors
#[derive(Debug, PartialEq, Eq)]
pub enum Collector {
    /// Iroh collector aggregates all metrics from the iroh binary
    Iroh,
}
