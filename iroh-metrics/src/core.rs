use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::SyncSender,
};

use once_cell::sync::Lazy;
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::{mpsc::channel, mpsc::Sender, Mutex, RwLock};

pub static CORE: Lazy<Core> = Lazy::new(Core::default);

#[derive(Debug)]
pub struct Core {
    enabled: AtomicBool,
    registry: Mutex<Registry>,
    metrics_map: RwLock<std::collections::HashMap<String, SyncSender<MMsg>>>,
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

impl Default for Core {
    fn default() -> Self {
        Core {
            enabled: AtomicBool::new(false),
            metrics_map: RwLock::new(std::collections::HashMap::new()),
            registry: Mutex::new(Registry::default()),
        }
    }
}

impl Core {
    pub fn registry(&self) -> &Mutex<Registry> {
        &self.registry
    }

    pub async fn register_collector(&self, name: &str, sender: SyncSender<MMsg>) {
        self.metrics_map
            .write()
            .await
            .insert(name.to_string(), sender);
    }

    pub async fn get_collector(&self, name: &str) -> Option<SyncSender<MMsg>> {
        self.metrics_map.read().await.get(name).cloned()
    }

    pub async fn get_metric(&self, collector: &str, metric: &str) -> Option<MMsg> {
        let c = self.get_collector(collector).await;

        if let Some(coll) = c {
            let (tx, mut rx) = channel(1);

            let _ = coll.send(MMsg {
                m_type: MMsgType::Unknown,
                m: metric.to_string(),
                m_val_u64: 0,
                m_val_f64: 0.0,
                m_callback: Some(tx),
            });
            return rx.recv().await;
        }
        None
    }

    pub(crate) async fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        let reg = self.registry.lock().await;
        encode(&mut buf, &reg)?;
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
    if CORE.is_enabled() {
        tracing::warn!("record: {}", c);
        let cc = c.to_string();
        let mn = m.name().to_string();
        tokio::task::spawn(async move {
            match CORE.get_collector(&cc).await {
                Some(sender) => {
                    let _ = sender.send(MMsg {
                        m_type: MMsgType::Record,
                        m: mn,
                        m_val_u64: v,
                        m_val_f64: 0.0,
                        m_callback: None,
                    });
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
    if CORE.is_enabled() {
        tracing::warn!("observe: {}", c);
        let cc = c.to_string();
        let mn = m.name().to_string();
        tokio::task::spawn(async move {
            match CORE.get_collector(&cc).await {
                Some(sender) => {
                    let _ = sender.send(MMsg {
                        m_type: MMsgType::Observe,
                        m: mn,
                        m_val_u64: 0,
                        m_val_f64: v,
                        m_callback: None,
                    });
                }
                None => {
                    tracing::warn!("observe: {} not found", cc);
                }
            }
        });
    }
}
