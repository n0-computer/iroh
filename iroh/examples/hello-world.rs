//! The smallest possible example to spin up a node and serve a single blob.
//!
//! This can be downloaded using the iroh CLI.
//!
//! This is using an in memory database and a random node id.
//! run this example from the project root:
//!     $ cargo run --example hello-world
use iroh::bytes::util::runtime;
use iroh_bytes::BlobFormat;
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
    // create a new, empty in memory database
    let mut db = iroh_bytes::store::readonly_mem::Store::default();
    // create an in-memory doc store (not used in the example)
    let doc_store = iroh_sync::store::memory::Store::default();
    // create a new iroh runtime with 1 worker thread, reusing the existing tokio runtime
    let rt = runtime::Handle::from_current(1)?;
    // add some data and remember the hash
    let hash = db.insert(b"Hello, world!");
    // create a new node
    let node = iroh::node::Node::builder(db, doc_store)
        .runtime(&rt)
        .spawn()
        .await?;
    // create a ticket
    let ticket = node.ticket(hash, BlobFormat::Raw).await?;
    // print some info about the node
    println!("serving hash:    {}", ticket.hash());
    println!("node NodeId:     {}", ticket.node_addr().node_id);
    println!("node listening addresses:");
    for addr in ticket.node_addr().direct_addresses() {
        println!("\t{:?}", addr);
    }
    // print the ticket, containing all the above information
    println!("in another terminal, run:");
    println!("\t$ cargo run -- get --ticket {}", ticket);
    // wait for the node to finish
    node.await?;
    Ok(())
}
