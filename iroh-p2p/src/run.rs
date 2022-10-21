use crate::config::Config;
use crate::{metrics, DiskStorage, Keychain, Node};
use anyhow::{anyhow, Result};
use tokio::task;
use tracing::{debug, error};

pub fn run(network_config: Config) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(2048)
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async move {
        let version = option_env!("IROH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
        println!("Starting iroh-p2p, version {version}");

        let metrics_config =
            metrics::metrics_config_with_compile_time_info(network_config.metrics.clone());

        let metrics_handle = iroh_metrics::MetricsHandle::new(metrics_config)
            .await
            .map_err(|e| anyhow!("metrics init failed: {:?}", e))?;

        #[cfg(unix)]
        {
            match iroh_util::increase_fd_limit() {
                Ok(soft) => debug!("NOFILE limit: soft = {}", soft),
                Err(err) => error!("Error increasing NOFILE limit: {}", err),
            }
        }

        let kc = Keychain::<DiskStorage>::new(network_config.key_store_path.clone()).await?;
        let rpc_addr = network_config
            .server_rpc_addr()?
            .ok_or_else(|| anyhow!("missing p2p rpc addr"))?;
        let mut p2p = Node::new(network_config, rpc_addr, kc).await?;

        // Start services
        let p2p_task = task::spawn(async move {
            if let Err(err) = p2p.run().await {
                error!("{:?}", err);
            }
        });

        iroh_util::block_until_sigint().await;

        // Cancel all async services
        p2p_task.abort();
        p2p_task.await.ok();

        metrics_handle.shutdown();
        Ok(())
    })
}
