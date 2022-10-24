use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::Parser;
use iroh_gateway::{
    bad_bits::{self, BadBits},
    cli::Args,
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    core::Core,
    metrics,
};
use iroh_resolver::racing::RacingLoader;
use iroh_rpc_client::Client as RpcClient;
use iroh_util::lock::ProgramLock;
use iroh_util::{iroh_config_path, make_config};
use tokio::sync::RwLock;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let mut lock = ProgramLock::new("iroh-gateway")?;
    lock.acquire_or_exit();

    let args = Args::parse();

    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), args.cfg.clone()];
    let mut config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();
    config.metrics = metrics::metrics_config_with_compile_time_info(config.metrics);
    println!("{:#?}", config);

    let metrics_config = config.metrics.clone();
    let bad_bits = match config.use_denylist {
        true => Arc::new(Some(RwLock::new(BadBits::new()))),
        false => Arc::new(None),
    };
    let rpc_addr = config
        .server_rpc_addr()?
        .ok_or_else(|| anyhow!("missing gateway rpc addr"))?;

    let content_loader = RacingLoader::new(
        RpcClient::new(config.rpc_client.clone()).await?,
        config.http_resolvers.clone().unwrap_or_default(),
    );
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
            Ok(soft) => tracing::debug!("NOFILE limit: soft = {}", soft),
            Err(err) => tracing::error!("Error increasing NOFILE limit: {}", err),
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
