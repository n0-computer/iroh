//! The smallest possible example to spin up a node and serve a single blob.
//!
//! This is using an in memory database and a random peer id.
use iroh::bytes::util::runtime;
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
    // create a new, empty in memory database
    let mut db = mem::Database::default();
    // create a new iroh runtime with 1 worker thread, reusing the existing tokio runtime
    let rt = runtime::Handle::from_currrent(1)?;
    // add some data and remember the hash
    let hash = db.insert(b"Hello, world!");
    // create a new node
    let node = iroh::node::Node::builder(db).runtime(&rt).spawn().await?;
    // create a ticket
    let ticket = node.ticket(hash).await?.with_recursive(false);
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
