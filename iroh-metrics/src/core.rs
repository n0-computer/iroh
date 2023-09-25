use erased_set::ErasedSyncSet;
use once_cell::sync::OnceCell;
#[cfg(feature = "metrics")]
use prometheus_client::{encoding::text::encode, registry::Registry};
#[cfg(not(feature = "metrics"))]
type Registry = ();

pub(crate) static CORE: OnceCell<Core> = OnceCell::new();

/// Core is the base metrics struct.
/// It manages the mapping between the metrics name and the actual metrics.
/// It also carries a single prometheus registry to be used by all metrics.
#[derive(Debug)]
pub struct Core {
    #[cfg(feature = "metrics")]
    registry: Registry,
    metrics_map: ErasedSyncSet,
    event_bus_tx: tokio::sync::mpsc::UnboundedSender<crate::Event>,
    _h: Option<tokio::task::JoinHandle<()>>,
}
/// Open Metrics [`Counter`] to measure discrete events.
///
/// Single monotonically increasing value metric.
#[derive(Debug, Clone)]
pub struct Counter {
    /// The actual prometheus counter.
    #[cfg(feature = "metrics")]
    pub counter: prometheus_client::metrics::family::Family::<Vec<(String, String)>, prometheus_client::metrics::counter::Counter>,
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
    pub fn inc(&self, labels: Vec<(String, String)>) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.counter.get_or_create(&labels).inc()
        }
        #[cfg(not(feature = "metrics"))]
        0
    }

    /// Increase the [`Counter`] by `u64`, returning the previous value.
    pub fn inc_by(&self, v: u64) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.counter.inc_by(v)
        }
        #[cfg(not(feature = "metrics"))]
	 pub fn inc_by(&self, _v: u64) -> u64 {
        0
    }

    /// Get the current value of the [`Counter`].
    pub fn get(&self) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.get_with_labels(vec![])
        }
        #[cfg(not(feature = "metrics"))]
        0
    }

    /// Get the current value of the [`Counter`] with expected labels.
    pub fn get_with_labels(&self, labels: Vec<(String, String)>) -> u64 {
        #[cfg(feature = "metrics")]
        {
            self.counter.get_or_create(&labels).get()
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

        let (event_bus_tx, mut event_bus_rx) = tokio::sync::mpsc::unbounded_channel();

        tracing::info!("Starting event bus");
        let eb_handle = tokio::task::spawn_blocking(move ||{
             tokio::task::spawn(async move {
            while let Some(event) = event_bus_rx.recv().await {
                tracing::error!("Event: {:?}", event);
            }
            tracing::error!("Event bus died");
        });
        });

        CORE.set(Core {
            metrics_map,
            #[cfg(feature = "metrics")]
            registry,
            event_bus_tx: event_bus_tx.clone(),
            _h: Some(eb_handle),
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

    /// Returns a reference to the event bus sender.
    pub fn event_bus(&self) -> &tokio::sync::mpsc::UnboundedSender<crate::Event> {
        &self.event_bus_tx
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
