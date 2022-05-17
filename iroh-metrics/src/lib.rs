use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::sdk::{trace, Resource};
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

#[derive(Debug, Clone)]
pub struct Config {
    /// The name of the service. Should be the same as the Cargo package name.
    pub service_name: String,
    /// A unique identifier for this instance of the service.
    pub instance_id: String,
    /// The build version of the service (commit hash).
    pub build: String,
    /// The version of the service. Should be the same as the Cargo package version.
    pub version: String,
    /// The environment of the service.
    pub service_env: String,
    /// Flag to enable debug mode.
    pub debug: bool,
    /// The endpoint of the trace collector.
    pub collector_endpoint: String,
    /// The endpoint of the prometheus push gateway.
    pub prometheus_gateway_endpoint: String,
}

impl Config {
    pub fn new(
        service_name: String,
        instance_id: String,
        build: String,
        version: String,
        service_env: String,
        debug: bool,
    ) -> Self {
        let debug =
            std::env::var("IROH_METRICS_DEBUG").unwrap_or_else(|_| debug.to_string()) == "true";
        let collector_endpoint = std::env::var("IROH_METRICS_COLLECTOR_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string());
        let prometheus_gateway_endpoint = std::env::var("IROH_METRICS_PROM_GATEWAY_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9091".to_string());

        Config {
            service_name,
            instance_id,
            build,
            version,
            service_env,
            debug,
            collector_endpoint,
            prometheus_gateway_endpoint,
        }
    }
}
