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
    let mut p2p_service = Libp2pService::new(network_config, net_keypair).await?;

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p_service.run().await {
            error!("{:?}", err);
        }
    });

    iroh_util::block_until_sigint().await;

    // Cancel all async services
    p2p_task.abort();

    Ok(())
}
