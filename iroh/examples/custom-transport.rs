use std::{sync::Arc, time::Duration};

use clap::Parser;
use iroh::{
    Endpoint, SecretKey, TransportAddr,
    endpoint::{Builder, Connection, transports::{AddrKind, TransportBias}},
    protocol::{AcceptError, ProtocolHandler, Router},
    test_utils::test_transport::{TestNetwork, TestTransport, TEST_TRANSPORT_ID},
};
use n0_error::{Result, StdResultExt};
use n0_watcher::Watcher;

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both endpoints pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/echo/0";

/// Example demonstrating custom transport usage.
#[derive(Parser, Debug, Clone)]
struct Args {
    /// Keep IP transports enabled (in addition to custom transport)
    #[arg(long)]
    keep_ip: bool,

    /// Keep relay transports enabled (in addition to custom transport)
    #[arg(long)]
    keep_relay: bool,

    /// Delay in seconds to wait after connecting before re-checking the selected transport
    #[arg(long, default_value = "0")]
    delay: u64,
}

/// Strong RTT advantage for the custom transport (100ms) to ensure it wins path selection.
const CUSTOM_TRANSPORT_RTT_ADVANTAGE: Duration = Duration::from_millis(100);

impl Args {
    /// Configure an endpoint builder with the custom transport and optional IP/relay transports.
    fn configure(&self, secret_key: SecretKey, transport: Arc<TestTransport>) -> Builder {
        let mut builder = Endpoint::builder()
            .secret_key(secret_key)
            .preset(transport)
            // Give the custom transport a strong RTT advantage so it always wins path selection
            .transport_bias(
                AddrKind::Custom(TEST_TRANSPORT_ID),
                TransportBias::primary().with_rtt_advantage(CUSTOM_TRANSPORT_RTT_ADVANTAGE),
            );
        if !self.keep_ip {
            builder = builder.clear_ip_transports();
        }
        if !self.keep_relay {
            builder = builder.clear_relay_transports();
        }
        builder
    }
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // We can get the remote's endpoint id from the connection.
        let endpoint_id = connection.remote_id();
        println!("accepted connection from {endpoint_id}");

        // Our protocol is a simple request-response protocol, so we expect the
        // connecting peer to open a single bi-directional stream.
        let (mut send, mut recv) = connection.accept_bi().await?;

        // Echo any bytes received back directly.
        // This will keep copying until the sender signals the end of data on the stream.
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        println!("Copied over {bytes_sent} byte(s)");

        // By calling `finish` on the send stream we signal that we will not send anything
        // further, which makes the receive stream on the other end terminate.
        send.finish()?;

        // Wait until the remote closes the connection, which it does once it
        // received the response.
        connection.closed().await;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    println!(
        "Config: keep_ip={}, keep_relay={}, delay={}s",
        args.keep_ip, args.keep_relay, args.delay
    );

    let network = TestNetwork::new();
    let s1 = SecretKey::from([0u8; 32]);
    let s2 = SecretKey::from([1u8; 32]);

    // Create transports and configure builders with transport + address lookup
    let t1 = network.create_transport(s1.public())?;
    let ep1 = args.configure(s1.clone(), t1).bind().await?;

    let t2 = network.create_transport(s2.public())?;
    let ep2 = args.configure(s2.clone(), t2).bind().await?;
    println!("ep2 addr: {:?}", ep2.addr());
    let server = Router::builder(ep2).accept(ALPN, Echo).spawn();

    // Connect using just the endpoint ID - discovery will resolve addresses
    // Note: The test network's discovery is very fast (in-memory), so the custom
    // transport address is available immediately and wins before IP discovery runs.
    println!("Connecting to: {:?}", s2.public());
    let conn = ep1.connect(s2.public(), ALPN).await?;

    // Helper to print paths and verify test transport is selected
    let verify_test_transport = |label: &str| {
        let paths = conn.paths().get();
        println!("Paths {}:", label);
        for path in paths.iter() {
            println!(
                "  {} selected={} rtt={:?}",
                path.remote_addr(),
                path.is_selected(),
                path.rtt()
            );
        }
        let selected_path = paths.iter().find(|p| p.is_selected());
        let is_test_transport = selected_path.is_some_and(|p| {
            matches!(p.remote_addr(), TransportAddr::Custom(addr) if addr.id() == TEST_TRANSPORT_ID)
        });
        assert!(
            is_test_transport,
            "Expected test transport (id={}) to be selected {}, got: {:?}",
            TEST_TRANSPORT_ID,
            label,
            selected_path.map(|p| p.remote_addr())
        );
        println!(
            "Verified: test transport (id={}) is selected {}",
            TEST_TRANSPORT_ID, label
        );
    };

    // Verify test transport is selected immediately after connecting
    verify_test_transport("immediately after connecting");

    // If a delay is specified, wait and then re-check to see if the transport is still selected
    // after other discovery mechanisms have had time to run.
    if args.delay > 0 {
        println!(
            "Waiting {}s to let other discovery mechanisms run...",
            args.delay
        );
        tokio::time::sleep(Duration::from_secs(args.delay)).await;
        verify_test_transport(&format!("after {}s delay", args.delay));
    }

    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello custom transport!").await.anyerr()?;
    send.finish().anyerr()?;
    let response = recv.read_to_end(1000).await.anyerr()?;
    assert_eq!(&response, b"Hello custom transport!");
    conn.close(0u32.into(), b"bye!");
    server.shutdown().await.anyerr()?;
    drop(server);
    Ok(())
}
