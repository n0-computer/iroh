//! The smallest example showing how to use iroh-net and `MagicEndpoint` to connect to a remote node.
//!
//! We use the node ID (the PublicKey of the remote node), the direct UDP addresses, and the relay url to achieve a connection.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//!
//! Run the `listen` example first (`iroh-net/examples/listen.rs`), which will give you instructions on how to run this example to watch two nodes connect and exchange bytes.
use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use futures_lite::StreamExt;
use iroh_base::base32;
use iroh_net::relay::RelayUrl;
use iroh_net::{key::SecretKey, relay::RelayMode, MagicEndpoint, NodeAddr};
use tracing::info;

// An example ALPN that we are using to communicate over the `MagicEndpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    /// The id of the remote node.
    #[clap(long)]
    node_id: iroh_net::NodeId,
    /// The list of direct UDP addresses for the remote node.
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    addrs: Vec<SocketAddr>,
    /// The url of the relay server the remote node can also be reached at.
    #[clap(long)]
    relay_url: RelayUrl,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nconnect example!\n");
    let args = Cli::parse();
    let secret_key = SecretKey::generate();
    println!("secret key: {}", base32::fmt(secret_key.to_bytes()));

    // Build a `MagicEndpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the relay protocol and relay servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = MagicEndpoint::builder()
        // The secret key is used to authenticate with other nodes. The PublicKey portion of this secret key is how we identify nodes, often referred to as the `node_id` in our codebase.
        .secret_key(secret_key)
        // Set the ALPN protocols this endpoint will accept on incoming connections
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        // `RelayMode::Default` means that we will use the default relay servers to holepunch and relay.
        // Use `RelayMode::Custom` to pass in a `RelayMap` with custom relay urls.
        // Use `RelayMode::Disable` to disable holepunching and relaying over HTTPS
        // If you want to experiment with relaying using your own relay server, you must pass in the same custom relay url to both the `listen` code AND the `connect` code
        .relay_mode(RelayMode::Default)
        // You can choose a port to bind to, but passing in `0` will bind the socket to a random available port
        .bind(0)
        .await?;

    let me = endpoint.node_id();
    println!("node id: {me}");
    println!("node listening addresses:");
    for local_endpoint in endpoint
        .local_endpoints()
        .next()
        .await
        .context("no endpoints")?
    {
        println!("\t{}", local_endpoint.addr)
    }

    let relay_url = endpoint
        .my_relay()
        .expect("should be connected to a relay server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected relay server");
    println!("node relay server url: {relay_url}\n");
    // Build a `NodeAddr` from the node_id, relay url, and UDP addresses.
    let addr = NodeAddr::from_parts(args.node_id, Some(args.relay_url), args.addrs);

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
    info!("connected");

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await?;

    let message = format!("{me} is saying 'hello!'");
    send.write_all(message.as_bytes()).await?;

    // Call `finish` to close the send side of the connection gracefully.
    send.finish().await?;
    let message = recv.read_to_end(100).await?;
    let message = String::from_utf8(message)?;
    println!("received: {message}");

    Ok(())
}
