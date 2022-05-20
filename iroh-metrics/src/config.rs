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
        let debug: bool = std::env::var("IROH_METRICS_DEBUG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(debug);
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
