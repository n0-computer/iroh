use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use iroh_dns_server::{config::Config, server::run_with_config_until_ctrl_c};
use tracing::debug;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to config file
    #[clap(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let config = if let Some(path) = args.config {
        debug!("loading config from {:?}", path);
        Config::load(path).await?
    } else {
        debug!("using default config");
        Config::default()
    };

    run_with_config_until_ctrl_c(config).await
}
