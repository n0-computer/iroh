//! The smallest example showing how to use iroh-net and `MagicEndpoint` to connect two devices and pass bytes using unreliable datagrams.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//! run this example from the project root:
//!     $ cargo run --example listen-unreliable
use anyhow::Context;
use futures_lite::StreamExt;
use iroh_base::base32;
use iroh_net::{key::SecretKey, relay::RelayMode, MagicEndpoint};
use tracing::info;

// An example ALPN that we are using to communicate over the `MagicEndpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nlisten (unreliable) example!\n");
    let secret_key = SecretKey::generate();
    println!("secret key: {}", base32::fmt(secret_key.to_bytes()));

    // Build a `MagicEndpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the relay servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = MagicEndpoint::builder()
        // The secret key is used to authenticate with other nodes. The PublicKey portion of this secret key is how we identify nodes, often referred to as the `node_id` in our codebase.
        .secret_key(secret_key)
        // set the ALPN protocols this endpoint will accept on incoming connections
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        // `RelayMode::Default` means that we will use the default relay servers to holepunch and relay.
        // Use `RelayMode::Custom` to pass in a `RelayMap` with custom relay urls.
        // Use `RelayMode::Disable` to disable holepunching and relaying over HTTPS
        // If you want to experiment with relaying using your own relay server, you must pass in the same custom relay url to both the `listen` code AND the `connect` code
        .relay_mode(RelayMode::Default)
        // you can choose a port to bind to, but passing in `0` will bind the socket to a random available port
        .bind(0)
        .await?;

    let me = endpoint.node_id();
    println!("node id: {me}");
    println!("node listening addresses:");

    let local_addrs = endpoint
        .local_endpoints()
        .next()
        .await
        .context("no endpoints")?
        .into_iter()
        .map(|endpoint| {
            let addr = endpoint.addr.to_string();
            println!("\t{addr}");
            addr
        })
        .collect::<Vec<_>>()
        .join(" ");

    let relay_url = endpoint
        .my_relay()
        .expect("should be connected to a relay server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected relay server");
    println!("node relay server url: {relay_url}");
    println!("\nin a separate terminal run:");

    println!(
        "\tcargo run --example connect-unreliable -- --node-id {me} --addrs \"{local_addrs}\" --relay-url {relay_url}\n"
    );
    // accept incoming connections, returns a normal QUIC connection

    while let Some(conn) = endpoint.accept().await {
        // accept the connection and extract the `node_id` and ALPN
        let (node_id, alpn, conn) = iroh_net::magic_endpoint::accept_conn(conn).await?;
        info!(
            "new (unreliable) connection from {node_id} with ALPN {alpn} (coming from {})",
            conn.remote_address()
        );
        // spawn a task to handle reading and writing off of the connection
        tokio::spawn(async move {
            // use the `quinn` API to read a datagram off the connection, and send a datagra, in return
            while let Ok(message) = conn.read_datagram().await {
                let message = String::from_utf8(message.into())?;
                println!("received: {message}");

                let message = format!("hi! you connected to {me}. bye bye");
                conn.send_datagram(message.as_bytes().to_vec().into())?;
            }

            Ok::<_, anyhow::Error>(())
        });
    }
    // stop with SIGINT (ctrl-c)

    Ok(())
}
