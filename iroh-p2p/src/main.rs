use std::cell::RefCell;
use std::fs::File;
use std::io::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::pin_mut;
use futures::prelude::*;
use iroh_p2p::Libp2pService;
use iroh_rpc_gateway::mem_gateway_rpc;
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

    // TODO: read keypair for disk
    // TODO: configurable keypair
    let rpc_keypair = {
        // Keypair not found, generate and save generated keypair
        let gen_keypair = ed25519::Keypair::generate();
        // TODO: Save Ed25519 keypair to file
        Keypair::Ed25519(gen_keypair)
    };
    let rpc_peer_id = rpc_keypair.public().to_peer_id();

    // TODO: configurable network
    let network_config = iroh_p2p::Libp2pConfig::default();
    let mut p2p_service = Libp2pService::new(network_config, net_keypair, rpc_keypair).await;

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p_service.run().await {
            error!("{:?}", err);
        }
    });

    // TODO: using `iroh_rpc_gateway` as a stand in for
    // some irohctl
    let ctr_rpc_keypair = {
        // Keypair not found, generate and save generated keypair
        let gen_keypair = ed25519::Keypair::generate();
        // TODO: Save Ed25519 keypair to file
        Keypair::Ed25519(gen_keypair)
    };
    let (mut ctr_rpc_client, ctr_rpc_server) = mem_gateway_rpc(ctr_rpc_keypair).unwrap();

    let ctr_rpc_task = tokio::spawn(async move { ctr_rpc_server.run().await });

    if let Err(e) = ctr_rpc_client.listen("/memory/0".parse().unwrap()).await {
        error!("error ctr rpc failed trying to listen: {:?}", e);
    }

    if let Err(e) = ctr_rpc_client
        .dial("p2p", "/memory/1".parse().unwrap(), rpc_peer_id)
        .await
    {
        error!("error dialing from ctr rpc to p2p rpc: {:?}", e);
    }

    // bootstrapping the network should be better thought out
    // the idea here is: if we are in a situation where one node knows all the addrs (for example,
    // the irohctl node), it can just send it's addressbook to everyone else
    if let Err(e) = ctr_rpc_client.send_address_book("p2p").await {
        error!(
            "error sharing address book from ctr rpc to p2p rpc: {:?}",
            e
        );
    }

    match ctr_rpc_client
        .network
        .fetch_bitswap(
            "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
                .parse()
                .unwrap(),
            None,
        )
        .await
    {
        Ok(stream) => {
            let mut v = Vec::new();
            pin_mut!(stream);
            while let Some(b) = stream.next().await {
                v.extend(b.unwrap());
            }
            let mut f = File::create("gremlin.jpeg").unwrap();
            f.write_all(&v).unwrap();
        }
        Err(e) => error!(
            "error fetching block from bitswap (command from ctl rpc to p2p rpc): {:?}",
            e
        ),
    }

    block_until_sigint().await;

    // Cancel all async services
    p2p_task.abort();
    ctr_rpc_task.abort();

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
