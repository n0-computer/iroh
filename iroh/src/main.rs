use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{prelude::*, EnvFilter};

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
    let lp = tokio_util::task::LocalPoolHandle::new(num_cpus::get());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::OFF.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();
    cli.run(lp).await
}
