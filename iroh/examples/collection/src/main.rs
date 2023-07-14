//! An example that serves an iroh collection from memory.
//!
//! Since this is using the default iroh collection format, it can be downloaded
//! recursively using the iroh CLI.
//!
//! This is using an in memory database and a random peer id.
use iroh::bytes::util::runtime;
use iroh::collection::{Blob, Collection, IrohCollectionParser};
use iroh::database::mem;
use tracing_subscriber::{prelude::*, EnvFilter};

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
    // create a new database and add some data
    let (mut db, names) = mem::Database::new([
        ("file1", b"the first file. ".to_vec()),
        ("file2", b"the second file".to_vec()),
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
    let rt = runtime::Handle::from_currrent(1)?;

    // create a new node
    // we must configure the iroh collection parser so the node understands iroh collections
    let node = iroh::node::Node::builder(db)
        .collection_parser(IrohCollectionParser)
        .runtime(&rt)
        .spawn()
        .await?;
    // create a ticket
    let ticket = node.ticket(hash).await?;
    // print some info about the node
    println!(
        "Node {} serving {} on {:?}",
        ticket.peer(),
        ticket.hash(),
        ticket.addrs()
    );
    // print the ticket, containing all the above information
    println!("Ticket: {}", ticket);
    // wait for the node to finish
    node.await?;
    Ok(())
}
