use std::path::Path;

use anyhow::Result;
use clap::Parser;
use dirs::home_dir;
use iroh_gateway::{
    config::{Config, RpcConfig},
    core::Core,
    metrics,
};
use iroh_metrics::gateway::Metrics;
use iroh_rpc_client::RpcClientConfig;
use prometheus_client::registry::Registry;

const IROH_DIR: &str = ".iroh";
const CONFIG: &str = "gateway.config.toml";

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, required = false, default_value_t = 9050)]
    port: u16,
    #[clap(short, long)]
    writeable: bool,
    #[clap(short, long)]
    fetch: bool,
    #[clap(short, long)]
    cache: bool,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // TODO: rpc config is the only config we are pulling from a file right now
    let mut rpc_config = RpcConfig::default();
    if let Ok(rpc_client_config) = RpcClientConfig::from_file(Path::new(
        &home_dir()
            .expect("Error locating home directory.")
            .join(IROH_DIR)
            .join(CONFIG),
    )) {
        rpc_config = RpcConfig {
            listen_addr: rpc_client_config.gateway_addr,
            client_config: rpc_client_config,
        }
    }

    // TODO: configurable
    let mut config = Config::new(
        args.writeable,
        args.fetch,
        args.cache,
        args.port,
        rpc_config,
    );
    config.set_default_headers();
    println!("{:#?}", config);

    let mut prom_registry = Registry::default();
    let gw_metrics = Metrics::new(&mut prom_registry);
    let handler = Core::new(config, gw_metrics, &mut prom_registry).await?;

    let metrics_handle =
        iroh_metrics::init_with_registry(metrics::metrics_config(args.no_metrics), prom_registry)
            .await
            .expect("failed to initialize metrics");
    let server = handler.server();
    println!("listening on {}", server.local_addr());
    let core_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    iroh_util::block_until_sigint().await;
    core_task.abort();

    metrics_handle.shutdown();
    Ok(())
}
