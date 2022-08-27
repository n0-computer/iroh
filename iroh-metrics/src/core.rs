use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::RwLock;

#[cfg(feature = "bitswap")]
use crate::bitswap;
#[cfg(feature = "gateway")]
use crate::gateway;
#[cfg(feature = "p2p")]
use crate::p2p;
#[cfg(feature = "resolver")]
use crate::resolver;
#[cfg(feature = "store")]
use crate::store;

lazy_static! {
    pub(crate) static ref CORE: RwLock<Core> = RwLock::new(Core::default());
}

pub(crate) struct Core {
    enabled: bool,
    registry: Registry,
    #[cfg(feature = "gateway")]
    gateway_metrics: gateway::Metrics,
    #[cfg(feature = "resolver")]
    resolver_metrics: resolver::Metrics,
    #[cfg(feature = "bitswap")]
    bitswap_metrics: bitswap::Metrics,
    #[cfg(feature = "store")]
    store_metrics: store::Metrics,
    #[cfg(feature = "p2p")]
    p2p_metrics: p2p::Metrics,
}

impl Default for Core {
    fn default() -> Self {
        let mut reg = Registry::default();
        Core {
            enabled: false,
            #[cfg(feature = "gateway")]
            gateway_metrics: gateway::Metrics::new(&mut reg),
            #[cfg(feature = "resolver")]
            resolver_metrics: resolver::Metrics::new(&mut reg),
            #[cfg(feature = "bitswap")]
            bitswap_metrics: bitswap::Metrics::new(&mut reg),
            #[cfg(feature = "store")]
            store_metrics: store::Metrics::new(&mut reg),
            #[cfg(feature = "p2p")]
            p2p_metrics: p2p::Metrics::new(&mut reg),
            registry: reg,
        }
    }
}

impl Core {
    pub(crate) fn registry(&self) -> &Registry {
        &self.registry
    }

    #[cfg(feature = "gateway")]
    pub(crate) fn gateway_metrics(&self) -> &gateway::Metrics {
        &self.gateway_metrics
    }

    #[cfg(feature = "resolver")]
    pub(crate) fn resolver_metrics(&self) -> &resolver::Metrics {
        &self.resolver_metrics
    }

    #[cfg(feature = "bitswap")]
    pub(crate) fn bitswap_metrics(&self) -> &bitswap::Metrics {
        &self.bitswap_metrics
    }

    #[cfg(feature = "store")]
    pub(crate) fn store_metrics(&self) -> &store::Metrics {
        &self.store_metrics
    }

    #[cfg(feature = "p2p")]
    pub(crate) fn p2p_metrics(&self) -> &p2p::Metrics {
        &self.p2p_metrics
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut buf = vec![];
        encode(&mut buf, self.registry()).unwrap();
        buf
    }

    pub(crate) fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
}

pub trait MetricType {
    fn name(&self) -> &str;
}

pub trait HistogramType {
    fn name(&self) -> &str;
}

pub trait MetricsRecorder {
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display;
    fn observe<M>(&self, m: M, value: f64)
    where
        M: HistogramType + std::fmt::Display;
}
