use std::sync::Arc;

#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use clap::Parser;
use iroh_gateway::{bad_bits::BadBits, core::Core, metrics};
#[cfg(all(feature = "http-uds-gateway", unix))]
use iroh_one::uds;
use iroh_one::{
    cli::Args,
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
};
use iroh_rpc_client::Client as RpcClient;
use iroh_rpc_types::Addr;
use iroh_unixfs::content_loader::{FullLoader, FullLoaderConfig};
use iroh_util::lock::ProgramLock;
use iroh_util::{iroh_config_path, make_config};
use tokio::sync::RwLock;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let mut lock = ProgramLock::new("iroh-one")?;
    lock.acquire_or_exit();

    let args = Args::parse();

    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = [Some(cfg_path.as_path()), args.cfg.as_deref()];
    let mut config = make_config(
        // default
        Config::default(),
        // potential config files
        &sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();

    #[cfg(unix)]
    {
        match iroh_util::increase_fd_limit() {
            Ok(soft) => tracing::debug!("NOFILE limit: soft = {}", soft),
            Err(err) => tracing::error!("Error increasing NOFILE limit: {}", err),
        }
    }

    let (store_rpc, p2p_rpc) = {
        let store_recv = Addr::new_mem();
        let store_sender = store_recv.clone();
        let p2p_recv = Addr::new_mem();
        let p2p_sender = p2p_recv.clone();
        config.rpc_client.store_addr = Some(store_sender);
        config.rpc_client.p2p_addr = Some(p2p_sender);
        config.synchronize_subconfigs();

        let store_rpc = iroh_one::mem_store::start(store_recv, config.store.clone()).await?;

        let p2p_rpc = iroh_one::mem_p2p::start(p2p_recv, config.p2p.clone()).await?;
        (store_rpc, p2p_rpc)
    };

    config.metrics = metrics::metrics_config_with_compile_time_info(config.metrics);
    println!("{config:#?}");

    let metrics_config = config.metrics.clone();

    let gateway_rpc_addr = config
        .gateway
        .rpc_addr()
        .ok_or_else(|| anyhow!("missing gateway rpc addr"))?;

    let bad_bits = match config.gateway.use_denylist {
        true => Arc::new(Some(RwLock::new(BadBits::new()))),
        false => Arc::new(None),
    };

    let content_loader = FullLoader::new(
        RpcClient::new(config.rpc_client.clone()).await?,
        FullLoaderConfig {
            http_gateways: config
                .gateway
                .http_resolvers
                .iter()
                .flatten()
                .map(|u| u.parse())
                .collect::<Result<_>>()?,
            indexer: None, // TODO
        },
    )?;
    let shared_state = Core::make_state(
        Arc::new(config.clone()),
        Arc::clone(&bad_bits),
        content_loader,
        config.gateway.dns_resolver,
    )
    .await?;

    let handler = Core::new_with_state(gateway_rpc_addr, Arc::clone(&shared_state)).await?;

    let metrics_handle = iroh_metrics::MetricsHandle::new(metrics_config)
        .await
        .expect("failed to initialize metrics");
    let server = handler.server();
    println!("HTTP endpoint listening on {}", server.local_addr());
    let core_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    #[cfg(all(feature = "http-uds-gateway", unix))]
    let uds_server_task = {
        let mut path = tempfile::Builder::new()
            .prefix("iroh")
            .tempdir()?
            .path()
            .join("ipfsd.http");
        if let Some(uds_path) = config.gateway_uds_path {
            path = uds_path;
        } else {
            // Create the parent path when using the default value since it's likely
            // it won't exist yet.
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        tokio::spawn(async move {
            if let Some(uds_server) = uds::uds_server(shared_state, path) {
                if let Err(err) = uds_server.await {
                    tracing::error!("Failure in http uds handler: {}", err);
                }
            }
        })
    };

    iroh_util::block_until_sigint().await;

    store_rpc.abort();
    p2p_rpc.abort();
    #[cfg(all(feature = "http-uds-gateway", unix))]
    uds_server_task.abort();
    core_task.abort();

    metrics_handle.shutdown();
    Ok(())
}
