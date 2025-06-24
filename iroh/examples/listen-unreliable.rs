//! The smallest example showing how to use iroh and [`iroh::Endpoint`] to connect two devices and pass bytes using unreliable datagrams.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//! run this example from the project root:
//!     $ cargo run --example listen-unreliable
use iroh::{Endpoint, RelayMode, SecretKey};
use n0_snafu::{Error, Result, ResultExt};
use n0_watcher::Watcher as _;
use tracing::{info, warn};

// An example ALPN that we are using to communicate over the `Endpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nlisten (unreliable) example!\n");
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    println!("public key: {}", secret_key.public());

    // Build a `Endpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the relay servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
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
    println!("node listening addresses:");

    let node_addr = endpoint.node_addr().initialized().await?;
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
        "\tcargo run --example connect-unreliable -- --node-id {me} --addrs \"{local_addrs}\" --relay-url {relay_url}\n"
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
        let conn = connecting.await.e()?;
        let node_id = conn.remote_node_id()?;
        info!(
            "new (unreliable) connection from {node_id} with ALPN {}",
            String::from_utf8_lossy(&alpn),
        );
        // spawn a task to handle reading and writing off of the connection
        tokio::spawn(async move {
            // use the `quinn` API to read a datagram off the connection, and send a datagra, in return
            while let Ok(message) = conn.read_datagram().await {
                let message = String::from_utf8(message.into()).e()?;
                println!("received: {message}");

                let message = format!("hi! you connected to {me}. bye bye");
                conn.send_datagram(message.as_bytes().to_vec().into()).e()?;
            }

            Ok::<_, Error>(())
        });
    }
    // stop with SIGINT (ctrl-c)

    Ok(())
}
