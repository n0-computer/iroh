use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use iroh_p2p::Libp2pService;
use libp2p::identity::{ed25519, Keypair};
use tokio::task;
use tracing::error;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Starts daemon process
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env())
        .init();

    let version = option_env!("IROH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));

    println!("Starting iroh-p2p, version {version}");

    // TODO: read keypair from disk
    // TODO: configurable keypair
    let net_keypair = {
        // Keypair not found, generate and save generated keypair
        let gen_keypair = ed25519::Keypair::generate();
        // TODO: Save Ed25519 keypair to file
        Keypair::Ed25519(gen_keypair)
    };

    // TODO: configurable network
    let network_config = iroh_p2p::Libp2pConfig::default();
    let mut p2p_service = Libp2pService::new(network_config, net_keypair).await;

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p_service.run().await {
            error!("{:?}", err);
        }
    });

    block_until_sigint().await;

    // Cancel all async services
    p2p_task.abort();

    Ok(())
}

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
