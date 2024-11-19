//! Example for adding a custom protocol to a iroh node.
//!
//! We are building a very simple custom protocol here, and make our iroh nodes speak this protocol
//! in addition to the built-in protocols (blobs, gossip, docs).
//!
//! Our custom protocol allows querying the blob store of other nodes for text matches. For
//! this, we keep a very primitive index of the UTF-8 text of our blobs.
//!
//! The example is contrived - we only use memory nodes, and our database is a hashmap in a mutex,
//! and our queries just match if the query string appears as-is in a blob.
//! Nevertheless, this shows how powerful systems can be built with custom protocols by also using
//! the existing iroh protocols (blobs in this case).
//!
//! ## Usage
//!
//! In one terminal, run
//!
//!     cargo run --example custom-protocol --features=examples  -- listen "hello-world" "foo-bar" "hello-moon"
//!
//! This spawns an iroh nodes with three blobs. It will print the node's node id.
//!
//! In another terminal, run
//!
//!     cargo run --example custom-protocol --features=examples  -- query <node-id> hello
//!
//! Replace <node-id> with the node id from above. This will connect to the listening node with our
//! custom protocol and query for the string `hello`. The listening node will return a list of
//! blob hashes that contain `hello`. We will then download all these blobs with iroh-blobs,
//! and then print a list of the hashes with their content.
//!
//! For this example, this will print:
//!
//!     moobakc6gao3ufmk: hello moon
//!     25eyd35hbigiqc4n: hello world
//!
//! That's it! Follow along in the code below, we added a bunch of comments to explain things.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use clap::Parser;
use futures_lite::future::Boxed as BoxedFuture;
use iroh::{
    net::{
        endpoint::{get_remote_node_id, Connecting},
        Endpoint, NodeId,
    },
    router::ProtocolHandler,
};
use iroh_base::hash::Hash;
use iroh_blobs::{
    downloader::Downloader, net_protocol::Blobs, rpc::client::blobs::MemClient,
    util::local_pool::LocalPool,
};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Spawn a node in listening mode.
    Listen {
        /// Each text string will be imported as a blob and inserted into the search database.
        text: Vec<String>,
    },
    /// Query a remote node for data and print the results.
    Query {
        /// The node id of the node we want to query.
        node_id: NodeId,
        /// The text we want to match.
        query: String,
    },
}

/// Each custom protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both nodes pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/text-search/0";

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    let args = Cli::parse();

    // Build a in-memory node. For production code, you'd want a persistent node instead usually.
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

    // Build our custom protocol handler. The `builder` exposes access to various subsystems in the
    // iroh node. In our case, we need a blobs client and the endpoint.
    let proto = BlobSearch::new(blobs_client.clone(), builder.endpoint().clone());

    // Add our protocol, identified by our ALPN, to the node, and spawn the node.
    let node = builder.accept(ALPN.to_vec(), proto.clone()).spawn().await?;

    match args.command {
        Command::Listen { text } => {
            let node_id = node.node_id();
            println!("our node id: {node_id}");

            // Insert the text strings as blobs and index them.
            for text in text.into_iter() {
                proto.insert_and_index(text).await?;
            }

            // Wait for Ctrl-C to be pressed.
            tokio::signal::ctrl_c().await?;
        }
        Command::Query { node_id, query } => {
            // Query the remote node.
            // This will send the query over our custom protocol, read hashes on the reply stream,
            // and download each hash over iroh-blobs.
            let hashes = proto.query_remote(node_id, &query).await?;

            // Print out our query results.
            for hash in hashes {
                read_and_print(&blobs_client, hash).await?;
            }
        }
    }

    node.shutdown().await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct BlobSearch {
    blobs: MemClient,
    endpoint: Endpoint,
    index: Arc<Mutex<HashMap<String, Hash>>>,
}

impl ProtocolHandler for BlobSearch {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    fn accept(self: Arc<Self>, connecting: Connecting) -> BoxedFuture<Result<()>> {
        // We have to return a boxed future from the handler.
        Box::pin(async move {
            // Wait for the connection to be fully established.
            let connection = connecting.await?;
            // We can get the remote's node id from the connection.
            let node_id = get_remote_node_id(&connection)?;
            println!("accepted connection from {node_id}");

            // Our protocol is a simple request-response protocol, so we expect the
            // connecting peer to open a single bi-directional stream.
            let (mut send, mut recv) = connection.accept_bi().await?;

            // We read the query from the receive stream, while enforcing a max query length.
            let query_bytes = recv.read_to_end(64).await?;

            // Now, we can perform the actual query on our local database.
            let query = String::from_utf8(query_bytes)?;
            let hashes = self.query_local(&query);

            // We want to return a list of hashes. We do the simplest thing possible, and just send
            // one hash after the other. Because the hashes have a fixed size of 32 bytes, this is
            // very easy to parse on the other end.
            for hash in hashes {
                send.write_all(hash.as_bytes()).await?;
            }

            // By calling `finish` on the send stream we signal that we will not send anything
            // further, which makes the receive stream on the other end terminate.
            send.finish()?;
            // By calling stopped we wait until the remote iroh Endpoint has acknowledged
            // all data.  This does not mean the remote application has received all data
            // from the Endpoint.
            send.stopped().await?;
            Ok(())
        })
    }
}

impl BlobSearch {
    /// Create a new protocol handler.
    pub fn new(blobs: MemClient, endpoint: Endpoint) -> Arc<Self> {
        Arc::new(Self {
            blobs,
            endpoint,
            index: Default::default(),
        })
    }

    /// Query a remote node, download all matching blobs and print the results.
    pub async fn query_remote(&self, node_id: NodeId, query: &str) -> Result<Vec<Hash>> {
        // Establish a connection to our node.
        // We use the default node discovery in iroh, so we can connect by node id without
        // providing further information.
        let conn = self.endpoint.connect(node_id, ALPN).await?;

        // Open a bi-directional in our connection.
        let (mut send, mut recv) = conn.open_bi().await?;

        // Send our query.
        send.write_all(query.as_bytes()).await?;

        // Finish the send stream, signalling that no further data will be sent.
        // This makes the `read_to_end` call on the accepting side terminate.
        send.finish()?;
        // By calling stopped we wait until the remote iroh Endpoint has acknowledged all
        // data.  This does not mean the remote application has received all data from the
        // Endpoint.
        send.stopped().await?;

        // In this example, we simply collect all results into a vector.
        // For real protocols, you'd usually want to return a stream of results instead.
        let mut out = vec![];

        // The response is sent as a list of 32-byte long hashes.
        // We simply read one after the other into a byte buffer.
        let mut hash_bytes = [0u8; 32];
        loop {
            // Read 32 bytes from the stream.
            match recv.read_exact(&mut hash_bytes).await {
                // FinishedEarly means that the remote side did not send further data,
                // so in this case we break our loop.
                Err(quinn::ReadExactError::FinishedEarly(_)) => break,
                // Other errors are connection errors, so we bail.
                Err(err) => return Err(err.into()),
                Ok(_) => {}
            };
            // Upcast the raw bytes to the `Hash` type.
            let hash = Hash::from_bytes(hash_bytes);
            // Download the content via iroh-blobs.
            self.blobs.download(hash, node_id.into()).await?.await?;
            // Add the blob to our local database.
            self.add_to_index(hash).await?;
            out.push(hash);
        }
        Ok(out)
    }

    /// Query the local database.
    ///
    /// Returns the list of hashes of blobs which contain `query` literally.
    pub fn query_local(&self, query: &str) -> Vec<Hash> {
        let db = self.index.lock().unwrap();
        db.iter()
            .filter_map(|(text, hash)| text.contains(query).then_some(*hash))
            .collect::<Vec<_>>()
    }

    /// Insert a text string into the database.
    ///
    /// This first imports the text as a blob into the iroh blob store, and then inserts a
    /// reference to that hash in our (primitive) text database.
    pub async fn insert_and_index(&self, text: String) -> Result<Hash> {
        let hash = self.blobs.add_bytes(text.into_bytes()).await?.hash;
        self.add_to_index(hash).await?;
        Ok(hash)
    }

    /// Index a blob which is already in our blob store.
    ///
    /// This only indexes complete blobs that are smaller than 1KiB.
    ///
    /// Returns `true` if the blob was indexed.
    async fn add_to_index(&self, hash: Hash) -> Result<bool> {
        let mut reader = self.blobs.read(hash).await?;
        // Skip blobs larger than 1KiB.
        if reader.size() > 1024 * 1024 {
            return Ok(false);
        }
        let bytes = reader.read_to_bytes().await?;
        match String::from_utf8(bytes.to_vec()) {
            Ok(text) => {
                let mut db = self.index.lock().unwrap();
                db.insert(text, hash);
                Ok(true)
            }
            Err(_err) => Ok(false),
        }
    }
}

/// Read a blob from the local blob store and print it to STDOUT.
async fn read_and_print(blobs: &MemClient, hash: Hash) -> Result<()> {
    let content = blobs.read_to_bytes(hash).await?;
    let message = String::from_utf8(content.to_vec())?;
    println!("{}: {message}", hash.fmt_short());
    Ok(())
}

/// Set the RUST_LOG env var to one of {debug,info,warn} to see logging.
fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}
