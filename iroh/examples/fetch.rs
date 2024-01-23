//! An example that fetches an iroh blob and prints the contents.
//! Will only work with blobs and collections that contain text, and is meant as a companion to the `hello_world` and `collections` examples.
//!
//! This is using an in memory database and a random node id.
//! Run the `provide` example, copy the ticket, and run this example from the project root:
//!     $ cargo run -p fetch [TICKET]
use anyhow::{bail, Context, Result};
use iroh::{
    client::{BlobDownloadProgress, TagsClient},
    rpc_protocol::BlobDownloadRequest,
};
use iroh_bytes::{format::collection::Collection, BlobFormat};
use iroh_net::NodeAddr;
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
    println!("ran example");
    // get the ticket
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        bail!("expected one argument [BLOB_TICKET], get a ticket by running `cargo run --example hello_world` in a separate terminal.");
    }

    // deserialize ticket string into a ticket
    let ticket =
        iroh::ticket::BlobTicket::from_str(&args[1]).context("failed parsing blob ticket")?;

    // create a new, empty in memory database
    let db = iroh_bytes::store::readonly_mem::Store::default();
    // create an in-memory doc store (not used in the example)
    let doc_store = iroh_sync::store::memory::Store::default();
    // create a new iroh runtime with 1 worker thread, reusing the existing tokio has a special kind of `HashSeq` called a "collection". A collection is just a `HashSeq` that reserves the first blob in the sequence for metadata about the `HashSeq`.
    // This metadata is where things like the
    let lp = LocalPoolHandle::new(1);
    // create a new node
    let node = iroh::node::Node::builder(db, doc_store)
        .local_pool(&lp)
        .spawn()
        .await?;
    // create a client that allows us to interact with the running node
    let client = node.client();

    let addr = ticket.node_addr();

    let format = ticket.format();
    let req = BlobDownloadRequest {
        // The hash of the content we are trying to download. Provided in the ticket.
        hash: ticket.hash(),

        // The format here is referring to the `BlobFormat`. We can request to download a single blob (which you can think of as a single file) or a `HashSeq` ("hash sequence"), which is a list of blobs you want to download.
        // Iroh has a special kind of `HashSeq` called a "collection". A collection is just a `HashSeq` that reserves the first blob in the sequence for metadata about the `HashSeq`
        // The metadata primarily contains the names of the blobs, which allows us, for example, to preserve filenames.
        format: ticket.format(),

        // The `NodeAddr`, which combines all of the known address information we have for the remote node.
        // This includes the `node_id` (or `PublicKey` of the node), any direct UDP addresses we know about for that node, as well as the DERP url of that node. The DERP url is the url of the DERP server that that node is connected to.
        // If the direct UDP addresses to that node do not work, than we can use the DERP node to attempt to holepunch between your current node and the remote node.
        // If holepunching fails, iroh will use the DERP node to proxy a connection to the remote node over HTTPS.
        // Thankfully, the ticket contains all of this information
        peer: ticket.node_addr().clone(),
        // In iroh, we garbage collect any blobs that are not tagged. You can create a special tag name, or create an automatic tag that is derived from the timestamp.
        tag: iroh::rpc_protocol::SetTagOption::Auto,
        // The `DownloadLocation` can be `Internal`, which saves the blob in the internal data store, or `External`, which saves the data to the provided path and optionally also inside the iroh internal data store as well.
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
        "downloaded {} bytes from node {}",
        outcome.downloaded_size,
        ticket.node_addr().node_id
    );

    // Get the contend from the iroh database.
    if ticket.format() == BlobFormat::Raw {
        let bytes = client.blobs.read_to_bytes(ticket.hash()).await?;
        let s = String::from_utf8(bytes.to_vec()).context("unable to parse string as utf-8")?;
        println!("{s}");
    } else {
        let collection = Collection::load(db, &ticket.hash());
    }

    Ok(())
}
