//! An example that fetches an iroh collection and prints the contents.
//! Will only work with collections that contain text, and is meant as a companion to the and `collection-provide` example.
//!
//! This is using an in memory database and a random node id.
//! Run the `collection-provide` example, which will give you instructions on how to run this example.
use anyhow::{bail, Context, Result};
use iroh::{client::BlobDownloadProgress, rpc_protocol::BlobDownloadRequest};
use iroh_bytes::BlobFormat;
use std::env;
use std::str::FromStr;
use tokio_util::task::LocalPoolHandle;
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

    // create a new, empty in memory database
    let db = iroh_bytes::store::mem::Store::default();
    // create an in-memory doc store (not used in the example)
    let doc_store = iroh_sync::store::memory::Store::default();
    // create a new iroh runtime with 1 worker thread
    let lp = LocalPoolHandle::new(1);
    // create a new node
    let node = iroh::node::Node::builder(db, doc_store)
        .local_pool(&lp)
        .spawn()
        .await?;
    // create a client that allows us to interact with the running node
    let client = node.client();

    println!("fetching hash:  {}", ticket.hash());
    println!("node id:        {}", node.node_id());
    println!("node listening addresses:");
    let addrs = node.my_addr().await?;
    for addr in addrs.direct_addresses() {
        println!("\t{:?}", addr);
    }
    println!(
        "node DERP server url: {:?}",
        node.my_derp()
            .expect("a default DERP url should be provided")
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

        // The `peer` field is a `NodeAddr`, which combines all of the known address information we have for the remote node.
        // This includes the `node_id` (or `PublicKey` of the node), any direct UDP addresses we know about for that node, as well as the DERP url of that node. The DERP url is the url of the DERP server that that node is connected to.
        // If the direct UDP addresses to that node do not work, than we can use the DERP node to attempt to holepunch between your current node and the remote node.
        // If holepunching fails, iroh will use the DERP node to proxy a connection to the remote node over HTTPS.
        // Thankfully, the ticket contains all of this information
        peer: ticket.node_addr().clone(),

        // You can create a special tag name (`SetTagOption::Named`), or create an automatic tag that is derived from the timestamp.
        tag: iroh::rpc_protocol::SetTagOption::Auto,

        // The `DownloadLocation` can be `Internal`, which saves the blob in the internal data store, or `External`, which saves the data to the provided path (and optionally also inside the iroh internal data store as well).
        out: iroh::rpc_protocol::DownloadLocation::Internal,
    };

    // `download` returns a stream of `DownloadProgress` events. You can iterate through these updates to get progress on the state of your download.
    let download_stream = client.blobs.download(req).await?;

    // You can also use the `BlobDownloadProgress` struct, that has the method `finish` that will poll the `DownloadProgress` stream for you.
    let outcome = BlobDownloadProgress::new(download_stream)
        .finish()
        .await
        .context("unable to download hash")?;

    println!(
        "\ndownloaded {} bytes from node {}",
        outcome.downloaded_size,
        ticket.node_addr().node_id
    );

    // Get the content we have just fetched from the iroh database.
    if ticket.format() == BlobFormat::HashSeq {
        // If the `BlobFormat` is `HashSeq`, then we can assume for the example (and for any `HashSeq` that is derived from any iroh API), that it can be parsed as a `Collection`
        // A `Collection` is a special `HashSeq`, where we preserve the names of any blobs added to the collection. (We do this by designating the first entry in the `Collection` as meta data.)
        // To get the content of the collection, we first get the collection from the database using the `blobs` API
        let collection = client
            .blobs
            .get_collection(ticket.hash())
            .await
            .context("expect hash with `BlobFormat::HashSeq` to be a collection")?;
        // Then we iterate through the collection, which gives us the name and hash of each entry in the collection.
        for (name, hash) in collection.iter() {
            println!("\nname: {name}, hash: {hash}");
            // Use the hash of the blob to get the content.
            let content = client.blobs.read_to_bytes(*hash).await?;
            println!(
                "{}",
                String::from_utf8(content.to_vec())
                    .context("unable to parse blob as as utf-8 string")?
            );
        }
    } else {
        bail!("'collection' example expects to fetch a collection, but the ticket indicates a single blob.");
    }

    Ok(())
}
