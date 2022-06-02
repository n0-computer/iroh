use git_version::git_version;

pub fn metrics_config(logger_only: bool) -> iroh_metrics::config::Config {
    // compile time configuration
    let service_name = env!("CARGO_PKG_NAME").to_string();
    let build = git_version!().to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    // runtime configuration
    let instance_id = std::env::var("IROH_INSTANCE_ID")
        .unwrap_or_else(|_| names::Generator::default().next().unwrap());
    let service_env = std::env::var("IROH_ENV").unwrap_or_else(|_| "dev".to_string());
    iroh_metrics::config::Config::new(
        service_name,
        instance_id,
        build,
        version,
        service_env,
        logger_only,
    )
}
