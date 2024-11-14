//! The smallest possible example to spin up a node and serve a single blob.
//!
//! This is using an in memory database and a random node id.
//! run this example from the project root:
//!     $ cargo run --example hello-world-provide
use std::str::FromStr;

use anyhow::Context;
use iroh_base::{node_addr::AddrInfoOptions, ticket::BlobTicket};
use iroh_net::{relay::RelayUrl, RelayMap, RelayMode};
use tracing_subscriber::{prelude::*, EnvFilter};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    println!("Hammer time!");

    // get iterations from command line
    let args: Vec<String> = std::env::args().collect();
    let iterations = if args.len() == 2 {
        args[1]
            .parse::<u32>()
            .context("failed to parse iterations")?
    } else {
        10
    };

    for i in 0..iterations {
        // create a new node
        println!("node: {}", i);
        let relay_url = RelayUrl::from_str("http://localhost:3340").unwrap();
        let relay_map = RelayMap::from_url(relay_url.clone());
        tokio::task::spawn(async move {
            let node = iroh::node::Node::memory()
                .relay_mode(RelayMode::Custom(relay_map.clone()))
                .spawn()
                .await
                .unwrap();

            // add some data and remember the hash
            let res = node.blobs().add_bytes("Hello, world!").await.unwrap();

            // create a ticket
            let mut addr = node.net().node_addr().await.unwrap();
            addr.apply_options(AddrInfoOptions::RelayAndAddresses);
            let ticket = BlobTicket::new(addr, res.hash, res.format).unwrap();

            tokio::task::spawn(async move {
                let client_node = iroh::node::Node::memory()
                    .relay_mode(RelayMode::Custom(relay_map.clone()))
                    .spawn()
                    .await
                    .unwrap();

                // `download` returns a stream of `DownloadProgress` events. You can iterate through these updates to get progress
                // on the state of your download.
                let download_stream = client_node
                    .blobs()
                    .download(ticket.hash(), ticket.node_addr().clone())
                    .await
                    .unwrap();

                // You can also just `await` the stream, which will poll the `DownloadProgress` stream for you.
                let outcome = download_stream
                    .await
                    .context("unable to download hash")
                    .unwrap();

                println!(
                    "\ndownloaded {} bytes from node {}",
                    outcome.downloaded_size,
                    ticket.node_addr().node_id
                );

                // Get the content we have just fetched from the iroh database.

                let bytes = client_node
                    .blobs()
                    .read_to_bytes(ticket.hash())
                    .await
                    .unwrap();
                let s = std::str::from_utf8(&bytes)
                    .context("unable to parse blob as as utf-8 string")
                    .unwrap();
                println!("content: {}", s);

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            });

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            node.shutdown().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::signal::ctrl_c().await?;
    Ok(())
}
