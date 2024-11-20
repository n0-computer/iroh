use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use config::BIN_NAME;
use iroh_node_util::config::data_root;

mod commands;
mod config;

use crate::commands::Cli;

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("main-runtime")
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(main_impl())?;
    // give the runtime some time to finish, but do not wait indefinitely.
    // there are cases where the a runtime thread is blocked doing io.
    // e.g. reading from stdin.
    rt.shutdown_timeout(Duration::from_millis(500));
    Ok(())
}

async fn main_impl() -> Result<()> {
    let data_dir = data_root(BIN_NAME)?;
    let cli = Cli::parse();
    cli.run(&data_dir).await
}
