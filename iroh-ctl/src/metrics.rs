use git_version::git_version;
use iroh_metrics::config::Config as MetricsConfig;

pub fn metrics_config_with_compile_time_info(cfg: MetricsConfig) -> MetricsConfig {
    // compile time configuration
    cfg.with_service_name(env!("CARGO_PKG_NAME").to_string())
        .with_build(git_version!().to_string())
        .with_version(env!("CARGO_PKG_VERSION").to_string())
}
