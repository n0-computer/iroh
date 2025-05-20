//! The smallest example showing how to use iroh and [`iroh::Endpoint`] to connect to a remote node and pass bytes using unreliable datagrams.
//!
//! We use the node ID (the PublicKey of the remote node), the direct UDP addresses, and the relay url to achieve a connection.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//!
//! Run the `listen-unreliable` example first (`iroh/examples/listen-unreliable.rs`), which will give you instructions on how to run this example to watch two nodes connect and exchange bytes.
use std::net::SocketAddr;

use clap::Parser;
use iroh::{watcher::Watcher as _, Endpoint, NodeAddr, RelayMode, RelayUrl, SecretKey};
use tracing::info;

// An example ALPN that we are using to communicate over the `Endpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    /// The id of the remote node.
    #[clap(long)]
    node_id: iroh::NodeId,
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
    println!("\nconnect (unreliable) example!\n");
    let args = Cli::parse();
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    println!("secret key: {secret_key}");

    // Build a `Endpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the relay protocol and relay servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = Endpoint::builder()
        // The secret key is used to authenticate with other nodes. The PublicKey portion of this secret key is how we identify nodes, often referred to as the `node_id` in our codebase.
        .secret_key(secret_key)
        // Set the ALPN protocols this endpoint will accept on incoming connections
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        // `RelayMode::Default` means that we will use the default relay servers to holepunch and relay.
        // Use `RelayMode::Custom` to pass in a `RelayMap` with custom relay urls.
        // Use `RelayMode::Disable` to disable holepunching and relaying over HTTPS
        // If you want to experiment with relaying using your own relay server, you must pass in the same custom relay url to both the `listen` code AND the `connect` code
        .relay_mode(RelayMode::Default)
        // You can choose an address to bind to, but passing in `None` will bind the socket to a random available port
        .bind()
        .await?;

    let node_addr = endpoint.node_addr().initialized().await?;
    let me = node_addr.node_id;
    println!("node id: {me}");
    println!("node listening addresses:");
    node_addr
        .direct_addresses
        .iter()
        .for_each(|addr| println!("\t{addr}"));
    let relay_url = node_addr
        .relay_url
        .expect("Should have a relay URL, assuming a default endpoint setup.");
    println!("node relay server url: {relay_url}\n");
    // Build a `NodeAddr` from the node_id, relay url, and UDP addresses.
    let addr = NodeAddr::from_parts(args.node_id, Some(args.relay_url), args.addrs);

    // Attempt to connect, over the given ALPN.
    // Returns a QUIC connection.
    let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
    info!("connected");

    // Send a datagram over the connection.
    let message = format!("{me} is saying 'hello!'");
    conn.send_datagram(message.as_bytes().to_vec().into())?;

    // Read a datagram over the connection.
    let message = conn.read_datagram().await?;
    let message = String::from_utf8(message.into())?;
    println!("received: {message}");

    Ok(())
}
