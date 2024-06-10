//! An example that fetches an iroh collection and prints the contents.
//! Will only work with collections that contain text, and is meant as a companion to the and `collection-provide` example.
//!
//! This is using an in memory database and a random node id.
//! Run the `collection-provide` example, which will give you instructions on how to run this example.
use std::{env, str::FromStr};

use anyhow::{bail, ensure, Context, Result};
use iroh::{base::ticket::BlobTicket, blobs::BlobFormat};
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
async fn main() -> Result<()> {
    setup_logging();
    println!("\ncollection fetch example!");
    // get the ticket
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        bail!("expected one argument [BLOB_TICKET]\n\nGet a ticket by running the follow command in a separate terminal:\n\n`cargo run --example collection-provide`");
    }

    // deserialize ticket string into a ticket
    let ticket =
        BlobTicket::from_str(&args[1]).context("failed parsing blob ticket\n\nGet a ticket by running the follow command in a separate terminal:\n\n`cargo run --example collection-provide`")?;

    // create a new node
    let node = iroh::node::Node::memory().spawn().await?;

    println!("fetching hash:  {}", ticket.hash());
    println!("node id:        {}", node.node_id());
    println!("node listening addresses:");
    let addrs = node.my_addr().await?;
    for addr in addrs.direct_addresses() {
        println!("\t{:?}", addr);
    }
    println!(
        "node relay server url: {:?}",
        node.my_relay()
            .expect("a default relay url should be provided")
            .to_string()
    );

    // Get the content we have just fetched from the iroh database.
    ensure!(
        ticket.format() == BlobFormat::HashSeq,
        "'collection' example expects to fetch a collection, but the ticket indicates a single blob."
    );

    // `download` returns a stream of `DownloadProgress` events. You can iterate through these updates to get progress
    // on the state of your download.
    let download_stream = node
        .blobs()
        .download_hash_seq(ticket.hash(), ticket.node_addr().clone())
        .await?;

    // You can also just `await` the stream, which poll the `DownloadProgress` stream for you.
    let outcome = download_stream.await.context("unable to download hash")?;

    println!(
        "\ndownloaded {} bytes from node {}",
        outcome.downloaded_size,
        ticket.node_addr().node_id
    );

    // If the `BlobFormat` is `HashSeq`, then we can assume for the example (and for any `HashSeq` that is derived from any iroh API), that it can be parsed as a `Collection`
    // A `Collection` is a special `HashSeq`, where we preserve the names of any blobs added to the collection. (We do this by designating the first entry in the `Collection` as meta data.)
    // To get the content of the collection, we first get the collection from the database using the `blobs` API
    let collection = node
        .blobs()
        .get_collection(ticket.hash())
        .await
        .context("expect hash with `BlobFormat::HashSeq` to be a collection")?;

    // Then we iterate through the collection, which gives us the name and hash of each entry in the collection.
    for (name, hash) in collection.iter() {
        println!("\nname: {name}, hash: {hash}");
        // Use the hash of the blob to get the content.
        let content = node.blobs().read_to_bytes(*hash).await?;
        let s = std::str::from_utf8(&content).context("unable to parse blob as as utf-8 string")?;
        println!("{s}");
    }

    Ok(())
}
