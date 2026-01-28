use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
    test_utils::test_transport::{TestNetwork, to_custom_addr},
};
use n0_error::{Result, StdResultExt};

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both endpoints pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/echo/0";

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
    let network = TestNetwork::new();
    let s1 = SecretKey::from([0u8; 32]);
    let s2 = SecretKey::from([1u8; 32]);
    let tt1 = network.create_transport(s1.public())?;
    let tt2 = network.create_transport(s2.public())?;
    let _d = network.discovery();
    let ep1 = Endpoint::builder()
        .secret_key(s1.clone())
        // .clear_discovery()
        // .discovery(d.clone())
        .add_custom_transport(tt1)
        .clear_ip_transports()
        .clear_relay_transports()
        .bind()
        .await?;
    let ep2 = Endpoint::builder()
        .secret_key(s2.clone())
        // .clear_discovery()
        // .discovery(d.clone())
        .add_custom_transport(tt2)
        .clear_ip_transports()
        .clear_relay_transports()
        .bind()
        .await?;
    let addr2 = ep2.addr();
    println!("ep2 addr: {:?}", addr2);
    let server = Router::builder(ep2).accept(ALPN, Echo).spawn();
    let addr2 = EndpointAddr::from_parts(
        s2.public(),
        [TransportAddr::Custom(to_custom_addr(s2.public()))],
    );
    println!("ep2 addr: {:?}", addr2);
    let conn = ep1.connect(addr2, ALPN).await?;
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
