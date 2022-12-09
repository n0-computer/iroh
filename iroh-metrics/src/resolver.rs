use std::{fmt, time::Instant};

use prometheus_client::{metrics::counter::Counter, registry::Registry};
use tracing::error;

use crate::{
    core::{HistogramType, MObserver, MRecorder, MetricType, MetricsRecorder},
    gateway::{GatewayHistograms, GatewayMetrics},
    Collector,
};

#[derive(Clone)]
pub(crate) struct Metrics {
    cache_hit: Counter,
    cache_miss: Counter,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway Metrics").finish()
    }
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("resolver");
        let cache_hit = Counter::default();
        sub_registry.register(
            METRICS_CACHE_HIT,
            "Number of cache hits",
            Box::new(cache_hit.clone()),
        );

        let cache_miss = Counter::default();
        sub_registry.register(
            METRICS_CACHE_MISS,
            "Number of cache misses",
            Box::new(cache_miss.clone()),
        );

        Self {
            cache_hit,
            cache_miss,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        Metrics::new(&mut registry)
    }
}

impl MetricsRecorder for Metrics {
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display,
    {
        if m.name() == ResolverMetrics::CacheHit.name() {
            self.cache_hit.inc_by(value);
        } else if m.name() == ResolverMetrics::CacheMiss.name() {
            self.cache_miss.inc_by(value);
        } else {
            error!("record (resolver): unknown metric {}", m.name());
        }
    }

    fn observe<M>(&self, m: M, _value: f64)
    where
        M: HistogramType + std::fmt::Display,
    {
        error!("observe (resolver): unknown metric {}", m.name());
    }
}

#[derive(Clone, Debug)]
pub enum ResolverMetrics {
    CacheHit,
    CacheMiss,
}

impl MetricType for ResolverMetrics {
    fn name(&self) -> &'static str {
        match self {
            ResolverMetrics::CacheHit => METRICS_CACHE_HIT,
            ResolverMetrics::CacheMiss => METRICS_CACHE_MISS,
        }
    }
}

impl MRecorder for ResolverMetrics {
    fn record(&self, value: u64) {
        crate::record(Collector::Resolver, self.clone(), value);
    }
}

impl std::fmt::Display for ResolverMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

const METRICS_CACHE_HIT: &str = "cache_hit";
const METRICS_CACHE_MISS: &str = "cache_miss";

#[derive(Debug)]
pub struct OutMetrics {
    pub start: Instant,
}

impl OutMetrics {
    pub fn observe_bytes_read(&self, pos: usize, bytes_read: usize) {
        if pos == 0 && bytes_read > 0 {
            record!(
                GatewayMetrics::TimeToServeFirstBlock,
                self.start.elapsed().as_millis() as u64
            );
        }
        if bytes_read == 0 {
            record!(
                GatewayMetrics::TimeToServeFullFile,
                self.start.elapsed().as_millis() as u64
            );
            observe!(
                GatewayHistograms::TimeToServeFullFile,
                self.start.elapsed().as_millis() as f64
            );
        }
        record!(GatewayMetrics::BytesStreamed, bytes_read as u64);
    }
}

impl Default for OutMetrics {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}
