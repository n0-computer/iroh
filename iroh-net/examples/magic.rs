//! The smallest example showing how to use iroh-net and `MagicEndpoint` to connect
//! two devices.
//!
//! This example uses the default DERP servers to attempt to holepunch, and will use that DERP server to relay packets if the two devices cannot establish a direct UDP connection.
use std::net::SocketAddr;

use clap::Parser;
use iroh_base::base32;
use iroh_net::{derp::DerpMode, key::SecretKey, MagicEndpoint, NodeAddr};
use tracing::{debug, info};
use url::Url;

// An example ALPN that we are using to communicate over the `MagicEndpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Listen for incoming connections.
    Listen,
    ListenUnreliable,
    /// Connect to a listening node.
    Connect {
        /// The id of the remote node.
        node_id: String,
        /// The list of direct UDP addresses for the remote node.
        #[clap(long)]
        addrs: Option<Vec<SocketAddr>>,
        /// The url of the DERP server the remote node can also be reached at.
        #[clap(long)]
        derp_url: Option<Url>,
    },
    ConnectUnreliable {
        node_id: String,
        #[clap(long)]
        addrs: Option<Vec<SocketAddr>>,
        #[clap(long)]
        derp_url: Option<Url>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
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
        .derp_mode(DerpMode::Default)
        // You can choose a port to bind to, but passing in `0` will bind the socket to a random available port
        .bind(0)
        .await?;

    let me = endpoint.node_id();
    let local_addr = endpoint.local_endpoints().await?;
    let derp_url = endpoint
        .my_derp()
        .expect("should be connected to a DERP server");
    println!("magic socket listening on {local_addr:?}");
    println!("derp URL: {derp_url}");
    println!("node id: {me}");

    match args.command {
        Command::Listen => {
            println!("\nin a separate terminal run:");
            println!("\tcargo run --example magic connect {me} --addrs {local_addr:?} --derp_url {derp_url}");
            // Accept incoming connections. Returns a normal `Quinn` connection.
            while let Some(conn) = endpoint.accept().await {
                // Accept the connection and extract the `node_id` and ALPN.
                let (node_id, alpn, conn) = iroh_net::magic_endpoint::accept_conn(conn).await?;
                info!(
                    "new connection from {node_id} with ALPN {alpn} (coming from {})",
                    conn.remote_address()
                );
                tokio::spawn(async move {
                    // Accept a bi-directional Quinn connection.
                    // Use the Quinn APIs to send and recv content.
                    let (mut send, mut recv) = conn.accept_bi().await?;
                    debug!("accepted bi stream, waiting for data...");
                    let message = recv.read_to_end(100).await?;
                    let message = String::from_utf8(message)?;
                    println!("received: {message}");

                    let message = format!("hi! you connected to {me}. bye bye");
                    send.write_all(message.as_bytes()).await?;
                    // Call `finish` to close the connection gracefully.
                    send.finish().await?;

                    Ok::<_, anyhow::Error>(())
                });
            }
        }
        Command::ListenUnreliable => {
            while let Some(conn) = endpoint.accept().await {
                let (node_id, alpn, conn) = accept_conn(conn).await?;
                info!(
                    "new (unreliable) connection from {node_id} with ALPN {alpn} (coming from {})",
                    conn.remote_address()
                );
                tokio::spawn(async move {
                    while let Ok(message) = conn.read_datagram().await {
                        let message = String::from_utf8(message.into())?;
                        println!("received: {message}");

                        let message = format!("hi! you connected to {me}. bye bye");
                        conn.send_datagram(message.as_bytes().to_vec().into())?;
                    }

                    Ok::<_, anyhow::Error>(())
                });
            }
        }
        Command::Connect {
            node_id,
            addrs,
            derp_url,
        } => {
            // Build a `NodeAddr` from the node_id, DERP url, and UDP addresses.
            let addr = NodeAddr::from_parts(node_id.parse()?, derp_url, addrs.unwrap_or_default());

            // Attempt to connect, over the given ALPN.
            // Returns a Quinn connection.
            let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
            info!("connected");

            // Use the Quinn API to send and recv content.
            let (mut send, mut recv) = conn.open_bi().await?;

            let message = format!("hello here's {me}");
            send.write_all(message.as_bytes()).await?;

            // Call `finish` to close the send side of the connection gracefully.
            send.finish().await?;
            let message = recv.read_to_end(100).await?;
            let message = String::from_utf8(message)?;
            println!("received: {message}");
        }
        Command::ConnectUnreliable {
            node_id,
            addrs,
            derp_url,
        } => {
            let addr = NodeAddr::from_parts(node_id.parse()?, derp_url, addrs.unwrap_or_default());
            let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
            info!("connected");

            let message = format!("hello here's {me}");
            conn.send_datagram(message.as_bytes().to_vec().into())?;
            let message = conn.read_datagram().await?;
            let message = String::from_utf8(message.into())?;
            println!("received: {message}");
        }
    }
    Ok(())
}
