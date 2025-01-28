//! Example protocol for running search on a remote node.
//!
//! We are building a very simple protocol here.
//!
//! Our protocol allows querying the text stored on the other node.
//!
//! The example is contrived - we only use memory nodes, and our database is a hashmap in a mutex,
//! and our queries just match if the query string appears as-is.
//!
//! ## Usage
//!
//! In one terminal, run
//!
//!     cargo run --example search --features=examples  -- listen "hello-world" "foo-bar" "hello-moon"
//!
//! This spawns an iroh endpoint with three blobs. It will print the node's node id.
//!
//! In another terminal, run
//!
//!     cargo run --example search --features=examples  -- query <node-id> hello
//!
//! Replace <node-id> with the node id from above. This will connect to the listening node with our
//! protocol and query for the string `hello`. The listening node will return a number of how many
//! strings match the query.
//!
//! For this example, this will print:
//!
//! Found 2 matches
//!
//! That's it! Follow along in the code below, we added a bunch of comments to explain things.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::Result;
use clap::Parser;
use iroh::{
    endpoint::Connecting,
    protocol::{ProtocolHandler, Router},
    Endpoint, NodeId,
};
use n0_future::boxed::BoxFuture;
use tokio::sync::Mutex;
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

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both nodes pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/text-search/0";

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    let args = Cli::parse();

    // Build an endpoint
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Build our protocol handler. The `builder` exposes access to various subsystems in the
    // iroh node. In our case, we need a blobs client and the endpoint.
    let proto = BlobSearch::new(endpoint.clone());

    let builder = Router::builder(endpoint);

    // Add our protocol, identified by our ALPN, to the node, and spawn the node.
    let router = builder.accept(ALPN, proto.clone()).spawn().await?;

    match args.command {
        Command::Listen { text } => {
            let node_id = router.endpoint().node_id();
            println!("our node id: {node_id}");

            // Insert the text strings as blobs and index them.
            for text in text.into_iter() {
                proto.insert(text).await?;
            }

            // Wait for Ctrl-C to be pressed.
            tokio::signal::ctrl_c().await?;
        }
        Command::Query { node_id, query } => {
            // Query the remote node.
            // This will send the query over our protocol, read hashes on the reply stream,
            // and download each hash over iroh-blobs.
            let num_matches = proto.query_remote(node_id, &query).await?;

            // Print out our query results.
            println!("Found {} matches", num_matches);
        }
    }

    router.shutdown().await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct BlobSearch {
    endpoint: Endpoint,
    blobs: Arc<Mutex<BTreeSet<String>>>,
}

impl ProtocolHandler for BlobSearch {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    fn accept(&self, connecting: Connecting) -> BoxFuture<Result<()>> {
        let this = self.clone();
        // We have to return a boxed future from the handler.
        Box::pin(async move {
            // Wait for the connection to be fully established.
            let connection = connecting.await?;
            // We can get the remote's node id from the connection.
            let node_id = connection.remote_node_id()?;
            println!("accepted connection from {node_id}");

            // Our protocol is a simple request-response protocol, so we expect the
            // connecting peer to open a single bi-directional stream.
            let (mut send, mut recv) = connection.accept_bi().await?;

            // We read the query from the receive stream, while enforcing a max query length.
            let query_bytes = recv.read_to_end(64).await?;

            // Now, we can perform the actual query on our local database.
            let query = String::from_utf8(query_bytes)?;
            let num_matches = this.query_local(&query).await;

            // We want to return a list of hashes. We do the simplest thing possible, and just send
            // one hash after the other. Because the hashes have a fixed size of 32 bytes, this is
            // very easy to parse on the other end.
            send.write_all(&num_matches.to_le_bytes()).await?;

            // By calling `finish` on the send stream we signal that we will not send anything
            // further, which makes the receive stream on the other end terminate.
            send.finish()?;

            // Wait until the remote closes the connection, which it does once it
            // received the response.
            connection.closed().await;

            Ok(())
        })
    }
}

impl BlobSearch {
    /// Create a new protocol handler.
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            blobs: Default::default(),
        }
    }

    /// Query a remote node, download all matching blobs and print the results.
    pub async fn query_remote(&self, node_id: NodeId, query: &str) -> Result<u64> {
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

        // The response is a 64 bit integer
        // We simply read it into a byte buffer.
        let mut num_matches = [0u8; 8];

        // Read 8 bytes from the stream.
        recv.read_exact(&mut num_matches).await?;

        let num_matches = u64::from_le_bytes(num_matches);

        // Dropping the connection here will close it.

        Ok(num_matches)
    }

    /// Query the local database.
    ///
    /// Returns how many matches were found.
    pub async fn query_local(&self, query: &str) -> u64 {
        let guard = self.blobs.lock().await;
        let count: usize = guard.iter().filter(|text| text.contains(query)).count();
        count as u64
    }

    /// Insert a text string into the database.
    pub async fn insert(&self, text: String) -> Result<()> {
        let mut guard = self.blobs.lock().await;
        guard.insert(text);
        Ok(())
    }
}

/// Set the RUST_LOG env var to one of {debug,info,warn} to see logging.
fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}
