//! An example that fetches an iroh collection and prints the contents.
//! Will only work with collections that contain text, and is meant as a companion to the and `collection-provide` example.
//!
//! This is using an in memory database and a random node id.
//! Run the `collection-provide` example, which will give you instructions on how to run this example.
use anyhow::{bail, ensure, Context, Result};
use iroh::rpc_protocol::{BlobDownloadRequest, DownloadMode};
use iroh_bytes::BlobFormat;
use std::env;
use std::str::FromStr;
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
        iroh::ticket::BlobTicket::from_str(&args[1]).context("failed parsing blob ticket\n\nGet a ticket by running the follow command in a separate terminal:\n\n`cargo run --example collection-provide`")?;

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
    let req = BlobDownloadRequest {
        // The hash of the content we are trying to download. Provided in the ticket.
        hash: ticket.hash(),

        // The format here is referring to the `BlobFormat`. We can request to download a single blob (which you can think of as a single file) or a `HashSeq` ("hash sequence"), which is a list of blobs you want to download.
        // Iroh has a special kind of `HashSeq` called a "collection". A collection is just a `HashSeq` that reserves the first blob in the sequence for metadata about the `HashSeq`
        // The metadata primarily contains the names of the blobs, which allows us, for example, to preserve filenames.
        // When interacting with the iroh API, you will most likely be using blobs and collections.
        format: ticket.format(),

        // The `nodes` field is a list of `NodeAddr`, where each combines all of the known address information we have for the remote node.
        // This includes the `node_id` (or `PublicKey` of the node), any direct UDP addresses we know about for that node, as well as the relay url of that node. The relay url is the url of the relay server that that node is connected to.
        // If the direct UDP addresses to that node do not work, than we can use the relay node to attempt to holepunch between your current node and the remote node.
        // If holepunching fails, iroh will use the relay node to proxy a connection to the remote node over HTTPS.
        // Thankfully, the ticket contains all of this information
        nodes: vec![ticket.node_addr().clone()],

        // You can create a special tag name (`SetTagOption::Named`), or create an automatic tag that is derived from the timestamp.
        tag: iroh::rpc_protocol::SetTagOption::Auto,

        // Whether to use the download queue, or do a direct download.
        mode: DownloadMode::Direct,
    };

    // `download` returns a stream of `DownloadProgress` events. You can iterate through these updates to get progress on the state of your download.
    let download_stream = node.blobs.download(req).await?;

    // You can also just `await` the stream, which poll the `DownloadProgress` stream for you.
    let outcome = download_stream.await.context("unable to download hash")?;

    println!(
        "\ndownloaded {} bytes from node {}",
        outcome.downloaded_size,
        ticket.node_addr().node_id
    );

    // Get the content we have just fetched from the iroh database.
    ensure!(
        ticket.format() == BlobFormat::HashSeq,
        "'collection' example expects to fetch a collection, but the ticket indicates a single blob."
    );

    // If the `BlobFormat` is `HashSeq`, then we can assume for the example (and for any `HashSeq` that is derived from any iroh API), that it can be parsed as a `Collection`
    // A `Collection` is a special `HashSeq`, where we preserve the names of any blobs added to the collection. (We do this by designating the first entry in the `Collection` as meta data.)
    // To get the content of the collection, we first get the collection from the database using the `blobs` API
    let collection = node
        .blobs
        .get_collection(ticket.hash())
        .await
        .context("expect hash with `BlobFormat::HashSeq` to be a collection")?;

    // Then we iterate through the collection, which gives us the name and hash of each entry in the collection.
    for (name, hash) in collection.iter() {
        println!("\nname: {name}, hash: {hash}");
        // Use the hash of the blob to get the content.
        let content = node.blobs.read_to_bytes(*hash).await?;
        let s = std::str::from_utf8(&content).context("unable to parse blob as as utf-8 string")?;
        println!("{s}");
    }

    Ok(())
}
