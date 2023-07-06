use std::collections::HashMap;

use once_cell::sync::OnceCell;
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::{mpsc::channel, mpsc::Sender};

static CORE: OnceCell<Core> = OnceCell::new();

#[derive(Debug, Default)]
pub struct Core {
    registry: Registry,
    metrics_map: HashMap<&'static str, Sender<MMsg>>,
}

#[derive(Debug, Clone, Default)]
pub struct MMsg {
    pub m_type: MMsgType,
    pub m: String,
    pub m_val_u64: u64,
    pub m_val_f64: f64,
    pub m_callback: Option<Sender<MMsg>>,
}

#[derive(Debug, Clone, Default)]
pub enum MMsgType {
    #[default]
    Unknown,
    Record,
    Observe,
}

impl Core {
    /// Must only be called once to init metrics.
    pub fn init<F: FnOnce(&mut Registry) -> HashMap<&'static str, Sender<MMsg>>>(f: F) {
        let mut registry = Registry::default();
        let metrics_map = f(&mut registry);

        CORE.set(Core {
            metrics_map,
            registry,
        })
        .expect("must only be called once");
    }

    pub fn is_enabled() -> bool {
        CORE.get().is_some()
    }

    pub fn get() -> &'static Self {
        CORE.get().expect("must only be called after init")
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn get_collector(&self, name: &str) -> Option<Sender<MMsg>> {
        self.metrics_map.get(name).cloned()
    }

    pub async fn get_metric(&self, collector: &str, metric: &str) -> Option<MMsg> {
        let c = self.get_collector(collector);

        if let Some(coll) = c {
            let (tx, mut rx) = channel(1);

            let _ = coll
                .send(MMsg {
                    m_type: MMsgType::Unknown,
                    m: metric.to_string(),
                    m_val_u64: 0,
                    m_val_f64: 0.0,
                    m_callback: Some(tx),
                })
                .await;
            return rx.recv().await;
        }
        None
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
    if Core::is_enabled() {
        let cc = c.to_string();
        let mn = m.name().to_string();

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async move {
            match Core::get().get_collector(&cc) {
                Some(sender) => {
                    let _ = sender
                        .send(MMsg {
                            m_type: MMsgType::Record,
                            m: mn,
                            m_val_u64: v,
                            m_val_f64: 0.0,
                            m_callback: None,
                        })
                        .await;
                }
                None => {
                    tracing::warn!("record: {} not found", cc);
                }
            }
        });
    }
}

/// Internal wrapper to observe metrics only if the core is enabled.
///
/// Observing is for distribution metrics, when multiple observations are combined in a
/// single metric value.
#[allow(dead_code)]
pub async fn observe<M>(c: &str, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if Core::is_enabled() {
        let cc = c.to_string();
        let mn = m.name().to_string();

        match Core::get().get_collector(&cc) {
            Some(sender) => {
                let _ = sender
                    .send(MMsg {
                        m_type: MMsgType::Observe,
                        m: mn,
                        m_val_u64: 0,
                        m_val_f64: v,
                        m_callback: None,
                    })
                    .await;
            }
            None => {
                tracing::warn!("observe: {} not found", cc);
            }
        }
    }
}
