#[macro_use]
mod macros;
#[cfg(feature = "bitswap")]
pub mod bitswap;
pub mod config;
pub mod core;
#[cfg(feature = "gateway")]
pub mod gateway;
#[cfg(feature = "p2p")]
pub mod p2p;
#[cfg(feature = "rpc-grpc")]
pub mod req;
#[cfg(feature = "resolver")]
pub mod resolver;
#[cfg(feature = "store")]
pub mod store;

#[macro_use]
extern crate lazy_static;

use crate::config::Config;
use crate::core::HistogramType;
use crate::core::MetricType;
#[cfg(any(
    feature = "bitswap",
    feature = "gateway",
    feature = "resolver",
    feature = "store",
    feature = "p2p"
))]
#[allow(unused_imports)]
use crate::core::MetricsRecorder;
use crate::core::CORE;
use opentelemetry::{
    global,
    sdk::{propagation::TraceContextPropagator, trace, Resource},
    trace::{TraceContextExt, TraceId},
};
use opentelemetry_otlp::WithExportConfig;
use std::env::consts::{ARCH, OS};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::log::{debug, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub struct MetricsHandle {
    metrics_task: Option<JoinHandle<()>>,
}

impl MetricsHandle {
    /// Shutdown the tracing and metrics subsystems.
    pub fn shutdown(&self) {
        opentelemetry::global::shutdown_tracer_provider();
        if let Some(mt) = &self.metrics_task {
            mt.abort();
        }
    }

    /// Initialize the tracing and metrics subsystems.
    pub async fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        init_tracer(cfg.clone())?;
        let metrics_task = init_metrics(cfg).await;
        Ok(MetricsHandle { metrics_task })
    }
}

/// Initialize the metrics subsystem.
async fn init_metrics(cfg: Config) -> Option<JoinHandle<()>> {
    if cfg.collect {
        CORE.set_enabled(true);
        let prom_gateway_uri = format!(
            "{}/metrics/job/{}/instance/{}",
            cfg.prom_gateway_endpoint, cfg.service_name, cfg.instance_id
        );
        let push_client = reqwest::Client::new();
        return Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let buff = CORE.encode();
                let res = match push_client.post(&prom_gateway_uri).body(buff).send().await {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("failed to push metrics: {}", e);
                        continue;
                    }
                };
                match res.status() {
                    reqwest::StatusCode::OK => {
                        debug!("pushed metrics to gateway");
                    }
                    _ => {
                        warn!("failed to push metrics to gateway: {:?}", res);
                        let body = res.text().await.unwrap();
                        warn!("error body: {}", body);
                    }
                }
            }
        }));
    }
    None
}

/// Initialize the tracing subsystem.
fn init_tracer(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let log_subscriber = fmt::layer()
        .pretty()
        .with_filter(EnvFilter::from_default_env());
    if !cfg.tracing {
        tracing_subscriber::registry().with(log_subscriber).init();
    } else {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(cfg.collector_endpoint)
            .with_timeout(std::time::Duration::from_secs(5));

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(trace::config().with_resource(Resource::new(vec![
                opentelemetry::KeyValue::new("instance.id", cfg.instance_id),
                opentelemetry::KeyValue::new("service.name", cfg.service_name),
                opentelemetry::KeyValue::new("service.version", cfg.version),
                opentelemetry::KeyValue::new("service.build", cfg.build),
                opentelemetry::KeyValue::new("service.os", OS),
                opentelemetry::KeyValue::new("service.ARCH", ARCH),
                opentelemetry::KeyValue::new("service.environment", cfg.service_env),
            ])))
            .install_batch(opentelemetry::runtime::Tokio)?;

        let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        tracing_subscriber::registry()
            .with(log_subscriber)
            .with(opentelemetry)
            .try_init()?;
    }
    Ok(())
}

pub fn get_current_trace_id() -> TraceId {
    tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
}

#[derive(PartialEq)]
pub enum Collector {
    #[cfg(feature = "gateway")]
    Gateway,
    #[cfg(feature = "resolver")]
    Resolver,
    #[cfg(feature = "bitswap")]
    Bitswap,
    #[cfg(feature = "store")]
    Store,
}

#[allow(unused_variables, unreachable_patterns)]
pub fn record<M>(c: Collector, m: M, v: u64)
where
    M: MetricType + std::fmt::Display,
{
    if CORE.enabled() {
        match c {
            #[cfg(feature = "gateway")]
            Collector::Gateway => CORE.gateway_metrics().record(m, v),
            #[cfg(feature = "resolver")]
            Collector::Resolver => CORE.resolver_metrics().record(m, v),
            #[cfg(feature = "bitswap")]
            Collector::Bitswap => CORE.bitswap_metrics().record(m, v),
            #[cfg(feature = "store")]
            Collector::Store => CORE.store_metrics().record(m, v),
            _ => panic!("not enabled/implemented"),
        };
    }
}

#[allow(unused_variables, unreachable_patterns)]
pub fn observe<M>(c: Collector, m: M, v: f64)
where
    M: HistogramType + std::fmt::Display,
{
    if CORE.enabled() {
        match c {
            #[cfg(feature = "gateway")]
            Collector::Gateway => CORE.gateway_metrics().observe(m, v),
            #[cfg(feature = "resolver")]
            Collector::Resolver => CORE.resolver_metrics().observe(m, v),
            #[cfg(feature = "bitswap")]
            Collector::Bitswap => CORE.bitswap_metrics().observe(m, v),
            #[cfg(feature = "store")]
            Collector::Store => CORE.store_metrics().observe(m, v),
            _ => panic!("not enabled/implemented"),
        };
    }
}

#[cfg(feature = "p2p")]
pub fn p2p_metrics() -> &'static p2p::Metrics {
    CORE.p2p_metrics()
}
