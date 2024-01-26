//! The smallest example showing how to use iroh-net and `MagicEndpoint` to connect to a remote node, and pass bytes using unreliable datagrams.
//!
//! We use the node ID (the PublicKey of the remote node), the direct UDP addresses, and the DERP url to achieve a connection.
//!
//! This example uses the default DERP servers to attempt to holepunch, and will use that DERP server to relay packets if the two devices cannot establish a direct UDP connection.
//!
//! Run the `listen-unreliable` example first (`iroh-net/examples/listen-unreliable.rs`), which will give you instructions on how to run this example to watch two nodes connect and exchange bytes.
use std::net::SocketAddr;

use clap::Parser;
use iroh_base::base32;
use iroh_net::{derp::DerpMode, key::SecretKey, MagicEndpoint, NodeAddr};
use tracing::info;
use url::Url;

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
    /// The url of the DERP server the remote node can also be reached at.
    #[clap(long)]
    derp_url: Url,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nconnect (unreliable) example!\n");
    let args = Cli::parse();
    let secret_key = SecretKey::generate();
    println!("secret key: {}", base32::fmt(secret_key.to_bytes()));

    // Build a `MagicEndpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the DERP protocol and DERP servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the DERP servers.
    let endpoint = MagicEndpoint::builder()
        // The secret key is used to authenticate with other nodes. The PublicKey portion of this secret key is how we identify nodes, often referred to as the `node_id` in our codebase.
        .secret_key(secret_key)
        // Set the ALPN protocols this endpoint will accept on incoming connections
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        // `DerpMode::Default` means that we will use the default DERP servers to holepunch and relay.
        // Use `DerpMode::Custom` to pass in a `DerpMap` with custom DERP urls.
        // Use `DerpMode::Disable` to disable holepunching and relaying over HTTPS
        // If you want to experiment with relaying using your own DERP server, you must pass in the same custom DERP url to both the `listen` code AND the `connect` code
        .derp_mode(DerpMode::Default)
        // You can choose a port to bind to, but passing in `0` will bind the socket to a random available port
        .bind(0)
        .await?;

    let me = endpoint.node_id();
    println!("node id: {me}");
    println!("node listening addresses:");
    for local_endpoint in endpoint.local_endpoints().await? {
        println!("\t{}", local_endpoint.addr)
    }

    let derp_url = endpoint
        .my_derp()
        .expect("should be connected to a DERP server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected DERP server");
    println!("node DERP server url: {derp_url}\n");
    // Build a `NodeAddr` from the node_id, DERP url, and UDP addresses.
    let addr = NodeAddr::from_parts(args.node_id, Some(args.derp_url), args.addrs);

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
