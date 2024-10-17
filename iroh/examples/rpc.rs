//! An example that runs an iroh node that can be controlled via RPC.
//!
//! Run this example with
//!   $ cargo run --features=examples --example rpc
//! This will print the rpc address of the node. Copy it to use it to connect from the CLI.
//! Then in another terminal, run any of the normal iroh CLI commands supplying the rpc address,
//! which you can run from cargo as well,
//!   $ cargo run -- --rpc-addr <RPC_ADDR> net node-addr
//! The `net node-addr` command will reach out over RPC to the node constructed in the example.

use clap::Parser;
use iroh_blobs::store::Store;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

async fn run<S>(builder: iroh::node::Builder<S>) -> anyhow::Result<()>
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
    let rpc_addr = node.my_rpc_addr().expect("rpc enabled");
    println!("Started node with RPC enabled ({rpc_addr}). Exit with Ctrl+C");
    // wait for the node to finish, this will block indefinitely
    // stop with SIGINT (ctrl+c)
    tokio::signal::ctrl_c().await?;
    node.shutdown().await?;

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
