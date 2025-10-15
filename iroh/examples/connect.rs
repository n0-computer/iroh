//! The smallest example showing how to use iroh and [`iroh::Endpoint`] to connect to a remote endpoint.
//!
//! We use the endpoint ID (the PublicKey of the remote endpoint), the direct UDP addresses, and the relay url to achieve a connection.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//!
//! Run the `listen` example first (`iroh/examples/listen.rs`), which will give you instructions on how to run this example to watch two endpoints connect and exchange bytes.
use std::net::SocketAddr;

use clap::Parser;
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey};
use n0_snafu::{Result, ResultExt};
use tracing::info;

// An example ALPN that we are using to communicate over the `Endpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    /// The id of the remote endpoint.
    #[clap(long)]
    endpoint_id: iroh::EndpointId,
    /// The list of direct UDP addresses for the remote endpoint.
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    addrs: Vec<SocketAddr>,
    /// The url of the relay server the remote endpoint can also be reached at.
    #[clap(long)]
    relay_url: RelayUrl,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nconnect example!\n");
    let args = Cli::parse();
    let secret_key = SecretKey::generate(&mut rand::rng());
    println!("public key: {}", secret_key.public());

    // Build a `Endpoint`, which uses PublicKeys as endpoint identifiers, uses QUIC for directly connecting to other endpoints, and uses the relay protocol and relay servers to holepunch direct connections between endpoints when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = Endpoint::builder()
        // The secret key is used to authenticate with other endpoints. The PublicKey portion of this secret key is how we identify endpoints, often referred to as the `endpoint_id` in our codebase.
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

    // wait for the endpoint to be online
    endpoint.online().await;

    let endpoint_addr = endpoint.addr();
    let me = endpoint.id();
    println!("endpoint id: {me}");
    println!("endpoint listening addresses:");
    for addr in endpoint_addr.direct_addresses() {
        println!("\t{addr}")
    }

    let relay_url = endpoint_addr
        .relay_url
        .expect("should be connected to a relay server");
    println!("endpoint relay server url: {relay_url}\n");
    // Build a `EndpointAddr` from the endpoint_id, relay url, and UDP addresses.
    let addr = EndpointAddr::from_parts(args.endpoint_id, Some(args.relay_url), args.addrs);

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint.connect(addr, EXAMPLE_ALPN).await?;
    info!("connected");

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await.e()?;

    let message = format!("{me} is saying 'hello!'");
    send.write_all(message.as_bytes()).await.e()?;

    // Call `finish` to close the send side of the connection gracefully.
    send.finish().e()?;
    let message = recv.read_to_end(100).await.e()?;
    let message = String::from_utf8(message).e()?;
    println!("received: {message}");

    // We received the last message: close all connections and allow for the close
    // message to be sent.
    endpoint.close().await;
    Ok(())
}
