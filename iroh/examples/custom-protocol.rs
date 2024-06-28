use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use futures_lite::future::Boxed as BoxedFuture;
use iroh::{
    client::Iroh,
    net::{
        endpoint::{get_remote_node_id, Connecting},
        Endpoint, NodeId,
    },
    node::ProtocolHandler,
};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    Accept,
    Connect { node: NodeId },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    let args = Cli::parse();
    // create a new node
    let builder = iroh::node::Node::memory().build().await?;
    let proto = ExampleProto::new(builder.client().clone(), builder.endpoint().clone());
    let node = builder
        .accept(EXAMPLE_ALPN, Arc::new(proto.clone()))
        .spawn()
        .await?;

    // print the ticket if this is the accepting side
    match args.command {
        Command::Accept => {
            let node_id = node.node_id();
            println!("node id: {node_id}");
            // wait until ctrl-c
            tokio::signal::ctrl_c().await?;
        }
        Command::Connect { node: node_id } => {
            proto.connect(node_id).await?;
        }
    }

    node.shutdown().await?;

    Ok(())
}

const EXAMPLE_ALPN: &[u8] = b"example-proto/0";

#[derive(Debug, Clone)]
struct ExampleProto {
    client: Iroh,
    endpoint: Endpoint,
}

impl ProtocolHandler for ExampleProto {
    fn accept(self: Arc<Self>, connecting: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move {
            let connection = connecting.await?;
            let peer = get_remote_node_id(&connection)?;
            println!("accepted connection from {peer}");
            let mut send_stream = connection.open_uni().await?;
            // Let's create a new blob for each incoming connection.
            // This functions as an example of using existing iroh functionality within a protocol
            // (you likely don't want to create a new blob for each connection for real)
            let content = format!("this blob is created for my beloved peer {peer} ♥");
            let hash = self
                .client
                .blobs()
                .add_bytes(content.as_bytes().to_vec())
                .await?;
            // Send the hash over our custom protocol.
            send_stream.write_all(hash.hash.as_bytes()).await?;
            send_stream.finish().await?;
            println!("closing connection from {peer}");
            Ok(())
        })
    }
}

impl ExampleProto {
    pub fn new(client: Iroh, endpoint: Endpoint) -> Self {
        Self { client, endpoint }
    }

    pub async fn connect(&self, remote_node_id: NodeId) -> Result<()> {
        println!("our node id: {}", self.endpoint.node_id());
        println!("connecting to {remote_node_id}");
        let conn = self
            .endpoint
            .connect_by_node_id(&remote_node_id, EXAMPLE_ALPN)
            .await?;
        let mut recv_stream = conn.accept_uni().await?;
        let hash_bytes = recv_stream.read_to_end(32).await?;
        let hash = iroh::blobs::Hash::from_bytes(hash_bytes.try_into().unwrap());
        println!("received hash: {hash}");
        self.client
            .blobs()
            .download(hash, remote_node_id.into())
            .await?
            .await?;
        println!("blob downloaded");
        let content = self.client.blobs().read_to_bytes(hash).await?;
        let message = String::from_utf8(content.to_vec())?;
        println!("blob content: {message}");
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
