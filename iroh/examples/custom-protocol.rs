use anyhow::Result;
use clap::Parser;
use iroh::node::{AcceptMode, Node};
use iroh_net::{magic_endpoint::get_remote_node_id, NodeId};
use tracing::warn;
use tracing_subscriber::{prelude::*, EnvFilter};

const EXAMPLE_ALPN: &'static [u8] = b"example-proto/0";

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
    let alpns = vec![EXAMPLE_ALPN.to_vec()];
    let node = iroh::node::Node::memory()
        .accept_mode(AcceptMode::Manual { alpns })
        .spawn()
        .await?;

    // print the ticket if this is the accepting side
    match args.command {
        Command::Accept => {
            let node_id = node.node_id();
            // let ticket = NodeTicket::new(node)?;
            println!("node id: {node_id}");
            // spawn a task to accept connections, handling our example connection and passing
            // other connections back to iroh.
            // when we set AcceptMode::Manual, this flow is required for iroh to accept any
            // incoming connctions.
            while let Some(connecting) = node.accept_connection().await {
                let node = node.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = handle_connection(node, connecting).await {
                        warn!("handling connection failed: {err}");
                    }
                });
            }
            // wait until ctrl-c
            tokio::signal::ctrl_c().await?;
        }
        Command::Connect { node: node_id } => {
            connect_example(&node, node_id).await?;
        }
    }

    node.shutdown().await?;

    Ok(())
}

async fn handle_connection<D: iroh::blobs::store::Store>(
    node: Node<D>,
    mut connecting: iroh_net::magic_endpoint::Connecting,
) -> anyhow::Result<()> {
    let alpn = connecting.alpn().await?;
    match alpn.as_bytes() {
        EXAMPLE_ALPN => accept_example(&node, connecting.await?).await,
        _ => node.handle_connection(connecting).await,
    }
}

async fn accept_example<D: iroh::blobs::store::Store>(
    node: &Node<D>,
    conn: iroh_net::magic_endpoint::Connection,
) -> anyhow::Result<()> {
    let remote_node_id = get_remote_node_id(&conn)?;
    println!("accepting new connection from {remote_node_id}");
    let mut send_stream = conn.open_uni().await?;
    println!("stream open!");
    // not that this is something that you wanted to do, but let's create a new blob for each
    // incoming connection. this could be any mechanism, but we want to demonstrate how to use a
    // custom protocol together with built-in iroh functionality
    let content = format!("this blob is created for my beloved peer {remote_node_id} ♥");
    let hash = node.blobs.add_bytes(content.as_bytes().to_vec()).await?;
    // send the hash over our custom proto
    send_stream.write_all(hash.hash.as_bytes()).await?;
    send_stream.finish().await?;
    Ok(())
}

async fn connect_example<D: iroh::blobs::store::Store>(
    node: &Node<D>,
    remote_node_id: NodeId,
) -> anyhow::Result<()> {
    println!("connecting to {remote_node_id}");
    let conn = node
        .magic_endpoint()
        .connect_by_node_id(&remote_node_id, EXAMPLE_ALPN)
        .await?;
    let mut recv_stream = conn.accept_uni().await?;
    let hash_bytes = recv_stream.read_to_end(32).await?;
    let hash = iroh::blobs::Hash::from_bytes(*(&hash_bytes.try_into().unwrap()));
    println!("received hash: {hash}");
    node.blobs
        .download(hash, remote_node_id.into())
        .await?
        .await?;
    println!("blob downloaded");
    let content = node.blobs.read_to_bytes(hash).await?;
    let message = String::from_utf8(content.to_vec())?;
    println!("blob content: {message}");
    Ok(())
}

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}
