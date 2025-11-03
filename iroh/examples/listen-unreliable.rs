//! The smallest example showing how to use iroh and [`iroh::Endpoint`] to connect two devices and pass bytes using unreliable datagrams.
//!
//! This example uses the default relay servers to attempt to holepunch, and will use that relay server to relay packets if the two devices cannot establish a direct UDP connection.
//! run this example from the project root:
//!     $ cargo run --example listen-unreliable
use iroh::{Endpoint, RelayMode, SecretKey};
use n0_error::{AnyError as Error, Result, StdResultExt};
use tracing::{info, warn};

// An example ALPN that we are using to communicate over the `Endpoint`
const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("\nlisten (unreliable) example!\n");
    let secret_key = SecretKey::generate(&mut rand::rng());
    println!("public key: {}", secret_key.public());

    // Build a `Endpoint`, which uses PublicKeys as endpoint identifiers, uses QUIC for directly connecting to other endpoints, and uses the relay servers to holepunch direct connections between endpoints when there are NATs or firewalls preventing direct connections. If no direct connection can be made, packets are relayed over the relay servers.
    let endpoint = Endpoint::builder()
        // The secret key is used to authenticate with other endpoints. The PublicKey portion of this secret key is how we identify endpoints, often referred to as the `endpoint_id` in our codebase.
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

    let me = endpoint.id();
    println!("endpoint id: {me}");
    println!("endpoint listening addresses:");

    // wait for the endpoint to be online
    endpoint.online().await;

    let endpoint_addr = endpoint.addr();
    let local_addrs = endpoint_addr
        .ip_addrs()
        .map(|addr| {
            let addr = addr.to_string();
            println!("\t{addr}");
            addr
        })
        .collect::<Vec<_>>()
        .join(" ");
    let relay_url = endpoint_addr
        .relay_urls()
        .next()
        .expect("Should have a relay URL, assuming a default endpoint setup.");
    println!("endpoint relay server url: {relay_url}");
    println!("\nin a separate terminal run:");

    println!(
        "\tcargo run --example connect-unreliable -- --endpoint-id {me} --addrs \"{local_addrs}\" --relay-url {relay_url}\n"
    );
    // accept incoming connections, returns a normal QUIC connection

    while let Some(incoming) = endpoint.accept().await {
        let mut accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        let alpn = accepting.alpn().await?;
        let conn = accepting.await?;
        let endpoint_id = conn.remote_id();
        info!(
            "new (unreliable) connection from {endpoint_id} with ALPN {}",
            String::from_utf8_lossy(&alpn),
        );
        // spawn a task to handle reading and writing off of the connection
        tokio::spawn(async move {
            // use the `quinn` API to read a datagram off the connection, and send a datagra, in return
            while let Ok(message) = conn.read_datagram().await {
                let message = String::from_utf8(message.into()).anyerr()?;
                println!("received: {message}");

                let message = format!("hi! you connected to {me}. bye bye");
                conn.send_datagram(message.as_bytes().to_vec().into())
                    .anyerr()?;
            }

            Ok::<_, Error>(())
        });
    }
    // stop with SIGINT (ctrl-c)

    Ok(())
}
