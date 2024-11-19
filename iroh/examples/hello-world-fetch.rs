//! An example that fetches an iroh blob and prints the contents.
//! Will only work with blobs and collections that contain text, and is meant as a companion to the `hello-world-get` examples.
//!
//! This is using an in memory database and a random node id.
//! Run the `provide` example, which will give you instructions on how to run this example.
use std::{env, str::FromStr, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use iroh::base::ticket::BlobTicket;
use iroh_blobs::{
    downloader::Downloader, net_protocol::Blobs, util::local_pool::LocalPool, BlobFormat,
};
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
    println!("\n'Hello World' fetch example!");
    // get the ticket
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        bail!("expected one argument [BLOB_TICKET]\n\nGet a ticket by running the follow command in a separate terminal:\n\n`cargo run --example hello-world-provide`");
    }

    // deserialize ticket string into a ticket
    let ticket =
        BlobTicket::from_str(&args[1]).context("failed parsing blob ticket\n\nGet a ticket by running the follow command in a separate terminal:\n\n`cargo run --example hello-world-provide`")?;

    // create a new node
    let mut builder = iroh::node::Node::memory().build().await?;
    let local_pool = LocalPool::default();
    let store = iroh_blobs::store::mem::Store::new();
    let downloader = Downloader::new(
        store.clone(),
        builder.endpoint().clone(),
        local_pool.handle().clone(),
    );
    let blobs = Arc::new(Blobs::new_with_events(
        store,
        local_pool.handle().clone(),
        Default::default(),
        downloader,
        builder.endpoint().clone(),
    ));
    let blobs_client = blobs.clone().client();
    builder = builder.accept(iroh_blobs::protocol::ALPN.to_vec(), blobs);
    let node = builder.spawn().await?;

    println!("fetching hash:  {}", ticket.hash());
    println!("node id:        {}", node.node_id());
    println!("node listening addresses:");
    let addrs = node.net().node_addr().await?;
    for addr in addrs.direct_addresses() {
        println!("\t{:?}", addr);
    }
    println!(
        "node relay server url: {:?}",
        node.home_relay()
            .expect("a default relay url should be provided")
            .to_string()
    );

    // If the `BlobFormat` is `Raw`, we have the hash for a single blob, and simply need to read the blob using the `blobs` API on the client to get the content.
    ensure!(
        ticket.format() == BlobFormat::Raw,
        "'Hello World' example expects to fetch a single blob, but the ticket indicates a collection.",
    );

    // `download` returns a stream of `DownloadProgress` events. You can iterate through these updates to get progress
    // on the state of your download.
    let download_stream = blobs_client
        .download(ticket.hash(), ticket.node_addr().clone())
        .await?;

    // You can also just `await` the stream, which will poll the `DownloadProgress` stream for you.
    let outcome = download_stream.await.context("unable to download hash")?;

    println!(
        "\ndownloaded {} bytes from node {}",
        outcome.downloaded_size,
        ticket.node_addr().node_id
    );

    // Get the content we have just fetched from the iroh database.

    let bytes = blobs_client.read_to_bytes(ticket.hash()).await?;
    let s = std::str::from_utf8(&bytes).context("unable to parse blob as as utf-8 string")?;
    println!("{s}");

    Ok(())
}
