//! An example that serves an iroh collection from memory.
//!
//! Since this is using the default iroh collection format, it can be downloaded
//! recursively using the iroh CLI.
//!
//! This is using an in memory database and a random node id.
//! run this example from the project root:
//!     $ cargo run --example collection-provide
use bytes::Bytes;
use iroh::rpc_protocol::SetTagOption;
use iroh_bytes::{format::collection::Collection, BlobFormat};
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
    println!("\ncollection provide example!");
    // create a new node
    // we must configure the iroh collection parser so the node understands iroh collections
    let node = iroh::node::Node::memory().spawn().await?;

    // Add two blobs
    let blob1 = node
        .client()
        .blobs
        .add_bytes(
            Bytes::from_static(b"the first blob of bytes"),
            SetTagOption::Auto,
        )
        .await?;
    let blob2 = node
        .client()
        .blobs
        .add_bytes(
            Bytes::from_static(b"the second blob of bytes"),
            SetTagOption::Auto,
        )
        .await?;

    // Create blobs from the data
    let collection: Collection = [("blob1", blob1.hash), ("blob2", blob2.hash)]
        .into_iter()
        .collect();

    // Create a collection
    let (hash, _) = node
        .client()
        .blobs
        .create_collection(collection, SetTagOption::Auto, Default::default())
        .await?;

    // create a ticket
    // tickets wrap all details needed to get a collection
    let ticket = node.ticket(hash, BlobFormat::HashSeq).await?;
    // print some info about the node
    println!("serving hash:    {}", ticket.hash());
    println!("node id:         {}", ticket.node_addr().node_id);
    println!("node listening addresses:");
    for addr in ticket.node_addr().direct_addresses() {
        println!("\t{:?}", addr);
    }
    println!(
        "node DERP server url: {:?}",
        ticket
            .node_addr()
            .derp_url()
            .expect("a default DERP url should be provided")
            .to_string()
    );
    // print the ticket, containing all the above information
    println!("\nin another terminal, run:");
    println!("\tcargo run --example collection-fetch {}", ticket);
    // wait for the node to finish, this will block indefinitely
    // stop with SIGINT (ctrl+c)
    node.await?;
    Ok(())
}
