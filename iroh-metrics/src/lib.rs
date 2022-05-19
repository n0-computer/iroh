pub mod config;
pub mod req;

use config::Config;
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::{
    global,
    sdk::{propagation::TraceContextPropagator, trace, Resource},
};
use opentelemetry_otlp::WithExportConfig;
use std::env::consts::{ARCH, OS};
use std::time::Duration;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize the tracing and metrics subsystems.
pub fn init(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    init_metrics(cfg.clone())?;
    init_tracer(cfg)
}

/// Initialize the metrics subsystem.
pub fn init_metrics(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    if !cfg.debug {
        let builder = PrometheusBuilder::new().with_push_gateway(
            format!(
                "{}/metrics/job/{}/instance/{}",
                cfg.prometheus_gateway_endpoint, cfg.service_name, cfg.instance_id
            ),
            Duration::from_secs(5),
        )?;
        builder.install()?;
    }
    Ok(())
}

/// Initialize the tracing subsystem.
pub fn init_tracer(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let log_subscriber = fmt::layer()
        .pretty()
        .with_filter(EnvFilter::from_default_env());
    if cfg.debug {
        tracing_subscriber::registry().with(log_subscriber).init();
    } else {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(cfg.collector_endpoint)
                    .with_timeout(std::time::Duration::from_secs(5)),
            )
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

/// Shutdown the tracing and metrics subsystems.
pub fn shutdown_tracing() {
    opentelemetry::global::shutdown_tracer_provider();
}
