use std::path::PathBuf;

use clap::Parser;
use iroh_dns_server::{config::Config, server::run_with_config_until_ctrl_c};
use n0_error::Result;
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

    // Install `ring` as default crypto provider for rustls.
    // This helps when both ring and aws-lc-rs rustls features are enabled
    // (e.g. via `--all-features` in the release build), otherwise rustls
    // panics because it can't determine a default provider from crate features.
    // `ring` is enabled by the default `ring` feature of this crate.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to set default crypto provider");

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
