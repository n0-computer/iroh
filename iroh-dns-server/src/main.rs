use std::path::PathBuf;

use clap::Parser;
use iroh_dns_server::{Server, config::Config};
use n0_error::{Result, StdResultExt};
use tracing::{debug, info};

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

    let server = Server::bind(config).await?;
    tokio::signal::ctrl_c().await.anyerr()?;
    info!("shutdown");
    server.shutdown().await?;
    Ok(())
}
