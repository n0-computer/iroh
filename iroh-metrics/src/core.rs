use std::{any::Any, collections::HashMap};

use once_cell::sync::OnceCell;
use prometheus_client::{encoding::text::encode, registry::Registry};

static CORE: OnceCell<Core> = OnceCell::new();

#[derive(Debug, Default)]
pub struct Core {
    registry: Registry,
    metrics_map: HashMap<&'static str, Box<dyn Metric>>,
}

pub trait Metric: MetricsRecorder + 'static + Send + Sync + std::fmt::Debug {
    fn as_any(&self) -> &dyn Any;
}

impl Core {
    /// Must only be called once to init metrics.
    ///
    /// Panics if called a second time.
    pub fn init<F: FnOnce(&mut Registry) -> HashMap<&'static str, Box<dyn Metric>>>(f: F) {
        let mut registry = Registry::default();
        let metrics_map = f(&mut registry);

        CORE.set(Core {
            metrics_map,
            registry,
        })
        .expect("must only be called once");
    }

    pub fn get() -> Option<&'static Self> {
        CORE.get()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn get_collector(&self, name: &str) -> Option<&dyn Metric> {
        self.metrics_map.get(name).map(|t| t.as_ref())
    }

    pub fn get_collector_as<T: Metric>(&self, name: &str) -> Option<&T> {
        let t = self.metrics_map.get(name)?;
        let t: &dyn Metric = t.as_ref();
        let t: &dyn Any = t.as_any();
        t.downcast_ref()
    }

    pub(crate) fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry)?;
        Ok(buf)
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
    fn record(&self, m: &str, value: u64);
    /// Observes a metric for any metric over time (e.g. histogram, summary, etc.)
    fn observe(&self, m: &str, value: f64);
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

    /// Records a value of `+1`.
    fn inc(&self) {
        self.record(1);
    }
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
pub fn record<M>(c: &str, m: M, v: u64)
where
    M: MetricType + std::fmt::Display,
{
    if let Some(core) = Core::get() {
        match core.get_collector(c) {
            Some(coll) => {
                coll.record(m.name(), v);
            }
            None => {
                tracing::warn!("record: {} not found", c);
            }
        }
    }
}

/// Internal wrapper to observe metrics only if the core is enabled.
///
/// Observing is for distribution metrics, when multiple observations are combined in a
/// single metric value.
#[allow(dead_code)]
pub fn observe<M>(c: &str, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if let Some(core) = Core::get() {
        match core.get_collector(c) {
            Some(coll) => {
                coll.observe(m.name(), v);
            }
            None => {
                tracing::warn!("observe: {} not found", c);
            }
        }
    }
}
