use std::sync::Arc;

use crate::{
    bad_bits::{self, BadBits},
    core::Core,
};
use anyhow::{anyhow, Result};
use iroh_rpc_client::Client as RpcClient;
use tokio::sync::RwLock;
use tracing::{debug, error};

pub async fn run(config: crate::config::Config) -> Result<()> {
    let metrics_config = config.metrics.clone();
    let bad_bits = match config.denylist {
        true => Arc::new(Some(RwLock::new(BadBits::new()))),
        false => Arc::new(None),
    };
    let rpc_addr = config
        .server_rpc_addr()?
        .ok_or_else(|| anyhow!("missing gateway rpc addr"))?;
    let content_loader = RpcClient::new(config.rpc_client.clone()).await?;
    let handler = Core::new(
        Arc::new(config),
        rpc_addr,
        Arc::clone(&bad_bits),
        content_loader,
    )
    .await?;

    let bad_bits_handle = bad_bits::spawn_bad_bits_updater(Arc::clone(&bad_bits));

    let metrics_handle = iroh_metrics::MetricsHandle::new(metrics_config)
        .await
        .expect("failed to initialize metrics");

    #[cfg(unix)]
    {
        match iroh_util::increase_fd_limit() {
            Ok(soft) => debug!("NOFILE limit: soft = {}", soft),
            Err(err) => error!("Error increasing NOFILE limit: {}", err),
        }
    }

    let server = handler.server();
    println!("listening on {}", server.local_addr());
    let core_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    iroh_util::block_until_sigint().await;
    core_task.abort();

    metrics_handle.shutdown();
    if let Some(handle) = bad_bits_handle {
        handle.abort();
    }

    Ok(())
}
