//! An example that serves an iroh collection from memory.
//!
//! Since this is using the default iroh collection format, it can be downloaded
//! recursively using the iroh CLI.
//!
//! This is using an in memory database and a random peer id.
//! run this example from the project root:
//!     $ cargo run -p collection
use iroh::bytes::util::runtime;
use iroh::collection::{Blob, Collection, IrohCollectionParser};
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
    // create a new database and add two blobs
    let (mut db, names) = iroh::baomap::readonly_mem::Store::new([
        ("blob1", b"the first blob of bytes".to_vec()),
        ("blob2", b"the second blob of bytes".to_vec()),
    ]);
    // create blobs from the data
    let blobs = names
        .into_iter()
        .map(|(name, hash)| Blob {
            name,
            hash: hash.into(),
        })
        .collect();
    // create a collection and add it to the db as well
    let collection = Collection::new(blobs, 0)?;
    let hash = db.insert(collection.to_bytes()?);
    // create a new iroh runtime with 1 worker thread, reusing the existing tokio runtime
    let rt = runtime::Handle::from_current(1)?;

    // create an in-memory doc store for iroh sync (not used here)
    let doc_store = iroh_sync::store::memory::Store::default();

    // create a new node
    // we must configure the iroh collection parser so the node understands iroh collections
    let node = iroh::node::Node::builder(db, doc_store)
        .collection_parser(IrohCollectionParser)
        .runtime(&rt)
        .spawn()
        .await?;
    // create a ticket
    // tickets wrap all details needed to get a collection
    let ticket = node.ticket(hash).await?;
    // print some info about the node
    println!("serving hash:    {}", ticket.hash());
    println!("node PeerID:     {}", ticket.node_addr().node_id);
    println!("node listening addresses:");
    for addr in ticket.node_addr().endpoints.iter() {
        println!("\t{:?}", addr);
    }
    // print the ticket, containing all the above information
    println!("in another terminal, run:");
    println!("\t$ cargo run -- get --ticket {}", ticket);
    // wait for the node to finish, this will block indefinitely
    // stop with SIGINT (ctrl+c)
    node.await?;
    Ok(())
}
