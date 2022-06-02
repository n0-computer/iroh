use std::fmt;

use prometheus_client::{metrics::counter::Counter, registry::Registry};

#[derive(Clone)]
pub struct Metrics {
    pub cache_hit: Counter,
    pub cache_miss: Counter,
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

const METRICS_CACHE_HIT: &str = "cache_hit";
const METRICS_CACHE_MISS: &str = "cache_miss";
