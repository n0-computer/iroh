//! The smallest example showing how to use iroh-net and `MagicEndpoint` to connect two devices.
//!
//! This example uses the default DERP servers to attempt to holepunch, and will use that DERP server to relay packets if the two devices cannot establish a direct UDP connection.
//! run this example from the project root:
//!     $ cargo run --example listen
use iroh_base::base32;
use iroh_net::{derp::DerpMode, key::SecretKey, MagicEndpoint};
use tracing::{debug, info};

// An example ALPN that we are using to communicate over the `MagicEndpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nlisten example!\n");
    let secret_key = SecretKey::generate();
    println!("secret key: {}", base32::fmt(secret_key.to_bytes()));

    // Build a `MagicEndpoint`, which uses PublicKeys as node identifiers, uses QUIC for directly connecting to other nodes, and uses the DERP protocol and DERP servers to holepunch direct connections between nodes when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the DERP servers.
    let endpoint = MagicEndpoint::builder()
        // The secret key is used to authenticate with other nodes. The PublicKey portion of this secret key is how we identify nodes, often referred to as the `node_id` in our codebase.
        .secret_key(secret_key)
        // set the ALPN protocols this endpoint will accept on incoming connections
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        // `DerpMode::Default` means that we will use the default DERP servers to holepunch and relay.
        // Use `DerpMode::Custom` to pass in a `DerpMap` with custom DERP urls.
        // Use `DerpMode::Disable` to disable holepunching and relaying over HTTPS
        // If you want to experiment with relaying using your own DERP server, you must pass in the same custom DERP url to both the `listen` code AND the `connect` code
        .derp_mode(DerpMode::Default)
        // you can choose a port to bind to, but passing in `0` will bind the socket to a random available port
        .bind(0)
        .await?;

    let me = endpoint.node_id();
    println!("node id: {me}");
    println!("node listening addresses:");

    let local_addrs = endpoint
        .local_endpoints()
        .await?
        .into_iter()
        .map(|endpoint| {
            let addr = endpoint.addr.to_string();
            println!("\t{addr}");
            addr
        })
        .collect::<Vec<_>>()
        .join(" ");

    let derp_url = endpoint
        .my_derp()
        .expect("should be connected to a DERP server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected DERP server");
    println!("node DERP server url: {derp_url}");
    println!("\nin a separate terminal run:");

    println!(
        "\tcargo run --example connect -- --node-id {me} --addrs \"{local_addrs}\" --derp-url {derp_url}\n"
    );
    // accept incoming connections, returns a normal QUIC connection
    while let Some(conn) = endpoint.accept().await {
        // accept the connection and extract the `node_id` and ALPN
        let (node_id, alpn, conn) = iroh_net::magic_endpoint::accept_conn(conn).await?;
        info!(
            "new connection from {node_id} with ALPN {alpn} (coming from {})",
            conn.remote_address()
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
            send.finish().await?;

            Ok::<_, anyhow::Error>(())
        });
    }
    // stop with SIGINT (ctrl-c)

    Ok(())
}
