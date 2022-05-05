use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use clap::Parser;
use iroh_store::{Config, Store};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the store
    #[clap(long, short)]
    path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env())
        .init();

    let version = env!("CARGO_PKG_VERSION");
    println!("Starting iroh-store, version {version}");

    let args = Args::parse();
    let config = Config {
        path: args.path.clone(),
    };

    let _store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config).await?
    };

    // TODO: receive commands and do things

    block_until_sigint().await;

    Ok(())
}

// TODO: share code with iroh-p2p
/// Blocks current thread until ctrl-c is received
async fn block_until_sigint() {
    let (ctrlc_send, ctrlc_oneshot) = futures::channel::oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));

    let running = Arc::new(AtomicUsize::new(0));
    ctrlc::set_handler(move || {
        let prev = running.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("Got interrupt, shutting down...");
            // Send sig int in channel to blocking task
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                ctrlc_send.send(()).expect("Error sending ctrl-c message");
            }
        } else {
            std::process::exit(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    ctrlc_oneshot.await.unwrap();
}
