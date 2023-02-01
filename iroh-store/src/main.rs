use anyhow::anyhow;
use clap::Parser;
use iroh_store::{
    cli::Args,
    config::{config_data_path, Config, ServerConfig, CONFIG_FILE_NAME, ENV_PREFIX},
    metrics, rpc, Store,
};
use iroh_util::lock::ProgramLock;
use iroh_util::{block_until_sigint, iroh_config_path, make_config};
use tracing::info;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut lock = ProgramLock::new("iroh-store")?;
    lock.acquire_or_exit();

    let args = Args::parse();

    let version = env!("CARGO_PKG_VERSION");
    println!("Starting iroh-store, version {version}");

    let config_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = &[Some(config_path.as_path()), args.cfg.as_deref()];
    let config_data_path = config_data_path(args.path.clone())?;
    let config = make_config(
        // default
        ServerConfig::new(config_data_path),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();
    let metrics_config = config.metrics.clone();

    let metrics_handle = iroh_metrics::MetricsHandle::new(
        metrics::metrics_config_with_compile_time_info(metrics_config),
    )
    .await
    .expect("failed to initialize metrics");

    #[cfg(unix)]
    {
        match iroh_util::increase_fd_limit() {
            Ok(soft) => tracing::debug!("NOFILE limit: soft = {}", soft),
            Err(err) => tracing::error!("Error increasing NOFILE limit: {}", err),
        }
    }

    let config = Config::from(config);
    let rpc_addr = config
        .rpc_addr()
        .ok_or_else(|| anyhow!("missing store rpc addr"))?;
    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    block_until_sigint().await;
    rpc_task.abort();
    metrics_handle.shutdown();

    Ok(())
}
