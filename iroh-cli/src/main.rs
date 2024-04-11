use std::time::Duration;

use anyhow::Result;
use clap::Parser;

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
    let data_dir = config::iroh_data_root()?;
    let cli = Cli::parse();

    // TODO(@divma): remove
    // #[cfg(unix)]
    // if let Some(log_fd) = cli.log_fd {
    //     use std::fs::File;
    //     use std::mem::ManuallyDrop;
    //     use std::os::unix::io::FromRawFd;
    //
    //     // SAFETY: We take ownership but ensure it is never dropped, thus we never close the
    //     // filedescriptor.  So even if the users chooses 0, 1 or 2 we do not close it,
    //     // making sure those keep working as expected until process termination.
    //     let inner = unsafe { ManuallyDrop::new(File::from_raw_fd(log_fd)) };
    //     let writer = ManuallyDropFile(inner);
    //     tracing_subscriber::registry()
    //         .with(
    //             tracing_subscriber::fmt::layer()
    //                 .event_format(tracing_subscriber::fmt::format().with_line_number(true))
    //                 .with_writer(writer),
    //         )
    //         .with(EnvFilter::from_default_env())
    //         .init();
    //     return cli.run(&data_dir).await;
    // }
    //
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
    //     .with(EnvFilter::from_default_env())
    //     .init();
    cli.run(&data_dir).await
}
