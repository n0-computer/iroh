#![allow(unused_imports)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::Result;
use axum::{routing::get, Router};
use clap::Parser;
use futures_lite::FutureExt;
use iroh_dns_server::{
    config::Config, metrics::init_metrics, server::run_with_config_until_ctrl_c,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, error_span, Instrument, Span};

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
        Config::load(path).await?
    } else {
        Config::default()
    };

    init_metrics();
    run_with_config_until_ctrl_c(config).await
}
