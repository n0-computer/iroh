use crate::{metrics, rpc, Config, Store};
use anyhow::anyhow;
use iroh_util::block_until_sigint;
use tracing::{debug, error, info};

pub async fn run(config: Config) -> anyhow::Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    println!("Starting iroh-store, version {version}");

    let metrics_config = config.metrics.clone();

    let metrics_handle = iroh_metrics::MetricsHandle::new(
        metrics::metrics_config_with_compile_time_info(metrics_config),
    )
    .await
    .expect("failed to initialize metrics");

    #[cfg(unix)]
    {
        match iroh_util::increase_fd_limit() {
            Ok(soft) => debug!("NOFILE limit: soft = {}", soft),
            Err(err) => error!("Error increasing NOFILE limit: {}", err),
        }
    }

    let rpc_addr = config
        .server_rpc_addr()?
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
