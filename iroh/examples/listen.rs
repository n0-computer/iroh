//! The smallest example showing how to use iroh and [`iroh::Endpoint`] to connect two devices.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//! run this example from the project root:
//!     $ cargo run --example listen
use std::time::Duration;

use iroh::{endpoint::ConnectionError, Endpoint, RelayMode, SecretKey};
use tracing::{debug, info, warn};

// An example ALPN that we are using to communicate over the `Endpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nlisten example!\n");
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    println!("secret key: {secret_key}");

    // Build a `Endpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the relay protocol and relay servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = Endpoint::builder()
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
        .bind()
        .await?;

    let me = endpoint.node_id();
    println!("node id: {me}");

    endpoint.direct_addresses().initialized().await?;
    endpoint.home_relay().initialized().await?;
    println!("node listening addresses:");
    let node_addr = endpoint.node_addr();
    let local_addrs = node_addr
        .direct_addresses
        .into_iter()
        .map(|addr| {
            let addr = addr.to_string();
            println!("\t{addr}");
            addr
        })
        .collect::<Vec<_>>()
        .join(" ");
    let relay_url = node_addr
        .relay_url
        .expect("Should have a relay URL, assuming a default endpoint setup.");
    println!("node relay server url: {relay_url}");
    println!("\nin a separate terminal run:");

    println!(
        "\tcargo run --example connect -- --node-id {me} --addrs \"{local_addrs}\" --relay-url {relay_url}\n"
    );
    // accept incoming connections, returns a normal QUIC connection
    while let Some(incoming) = endpoint.accept().await {
        let mut connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        let alpn = connecting.alpn().await?;
        let conn = connecting.await?;
        let node_id = conn.remote_node_id()?;
        info!(
            "new connection from {node_id} with ALPN {}",
            String::from_utf8_lossy(&alpn),
        );

        // spawn a task to handle reading and writing off of the connection
        tokio::spawn(async move {
            // accept a bi-directional QUIC connection
            // use the `quinn` APIs to send and recv content
            let (mut send, mut recv) = conn.accept_bi().await?;
            debug!("accepted bi stream, waiting for data...");
            let message = recv.read_to_end(100).await?;
            let message = String::from_utf8(message)?;
            println!("received: {message}");

            let message = format!("hi! you connected to {me}. bye bye");
            send.write_all(message.as_bytes()).await?;
            // call `finish` to close the connection gracefully
            send.finish()?;

            // We sent the last message, so wait for the client to close the connection once
            // it received this message.
            let res = tokio::time::timeout(Duration::from_secs(3), async move {
                let closed = conn.closed().await;
                if !matches!(closed, ConnectionError::ApplicationClosed(_)) {
                    println!("node {node_id} disconnected with an error: {closed:#}");
                }
            })
            .await;
            if res.is_err() {
                println!("node {node_id} did not disconnect within 3 seconds");
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    // stop with SIGINT (ctrl-c)

    Ok(())
}
