//! An example that runs an iroh node that can be controlled via RPC.
//!
//! Run this example with
//!   $ cargo run --example rpc
//! Then in another terminal, run any of the normal iroh CLI commands, which you can run from
//! cargo as well:
//!   $ cargo run node stats
//! The `node stats` command will reach out over RPC to the node constructed in the example

use clap::Parser;
use iroh_bytes::store::Store;
use tracing_subscriber::{prelude::*, EnvFilter};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

async fn run<S, D>(builder: iroh::node::Builder<S>) -> anyhow::Result<()>
where
    S: Store,
{
    let node = builder
        .enable_rpc()
        .await? // enable the RPC endpoint
        .spawn()
        .await?;

    // print some info about the node
    let peer = node.node_id();
    let addrs = node.local_endpoint_addresses().await?;
    println!("node PeerID:     {peer}");
    println!("node listening addresses:");
    for addr in addrs {
        println!("    {}", addr);
    }
    // wait for the node to finish, this will block indefinitely
    // stop with SIGINT (ctrl+c)
    node.await?;
    Ok(())
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to use to store the iroh database.
    ///
    /// If this is not set, an in memory database will be used.
    #[clap(long)]
    path: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();

    let args = Args::parse();
    match args.path {
        Some(path) => {
            tokio::fs::create_dir_all(&path).await?;
            let builder = iroh::node::Node::persistent(path).await?;
            run(builder).await
        }
        None => {
            let builder = iroh::node::Node::memory();
            run(builder).await
        }
    }
}
