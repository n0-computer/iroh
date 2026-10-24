//! Tests for connection timeouts on the captive-portal and relay listeners.
//!
//! Clients stop progressing at different stages of establishment. Advancing the server's
//! clock must cause it to close the connection. In these tests we ensure this by observing
//! the connection closing on the client side.

#![cfg(feature = "server")]

use std::{io::ErrorKind, net::Ipv4Addr, sync::Arc, time::Duration};

use http::header::SEC_WEBSOCKET_PROTOCOL;
use iroh_relay::{
    server::{CertConfig, RelayConfig, Server, ServerConfig, TlsConfig},
    tls::{CaTlsConfig, default_provider},
};
use n0_future::StreamExt;
use n0_tracing_test::traced_test;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{advance, pause, resume, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

// The server keeps its default 30-second timeouts.
const ADVANCE: Duration = Duration::from_secs(31);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// A silent client on port 80 never sends an HTTP request.
///
/// This is a regression test for https://github.com/n0-computer/iroh/issues/4612.
/// The captive-portal listener used to keep connections open forever when clients sent nothing.
#[tokio::test]
#[traced_test]
async fn captive_portal_silent() {
    let (server, _) = server().await;
    let stream = TcpStream::connect(server.http_addr().unwrap())
        .await
        .unwrap();
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// A client begins a probe request but never finishes its headers.
///
/// This is a regression test for the missing timeout reported in
/// https://github.com/n0-computer/iroh/issues/4612. Sending only part of an HTTP request could
/// also leave the connection open forever.
#[tokio::test]
#[traced_test]
async fn captive_portal_partial_headers() {
    let (server, _) = server().await;
    let mut stream = TcpStream::connect(server.http_addr().unwrap())
        .await
        .unwrap();
    stream
        .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// A client connects to the TLS listener without sending a ClientHello.
#[tokio::test]
#[traced_test]
async fn relay_before_tls() {
    let (server, _) = server().await;
    let stream = TcpStream::connect(server.https_addr().unwrap())
        .await
        .unwrap();
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// TLS completes, but the client never sends an HTTP request.
#[tokio::test]
#[traced_test]
async fn relay_before_http() {
    let (server, connector) = server().await;
    let stream = tls_connect(&server, connector).await;
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// The client starts a relay upgrade request but never finishes its headers.
#[tokio::test]
#[traced_test]
async fn relay_partial_http_headers() {
    let (server, connector) = server().await;
    let mut stream = tls_connect(&server, connector).await;
    stream
        .write_all(b"GET /relay HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n")
        .await
        .unwrap();
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// WebSocket upgrade completes and the server sends a challenge. The client never answers.
///
/// This is a regression test for a timeout gap after the WebSocket upgrade. The HTTP timeout
/// no longer covered the connection, so the server could wait forever for an auth response.
#[tokio::test]
#[traced_test]
async fn relay_waiting_for_auth() {
    let (server, connector) = server().await;
    let stream = receive_auth_challenge(&server, connector).await;
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

/// The client starts a masked WebSocket authentication frame but never finishes its payload.
///
/// This is another regression test for the post-upgrade timeout gap. A client could start
/// sending an auth response and then stop, leaving the server waiting forever for the rest
/// of the frame.
#[tokio::test]
#[traced_test]
async fn relay_partial_auth() {
    let (server, connector) = server().await;
    let mut stream = receive_auth_challenge(&server, connector).await;
    stream
        .write_all(&[0x82, 0x80 | 10, 0, 0, 0, 0, 1])
        .await
        .unwrap();
    assert_times_out(stream).await;
    server.shutdown().await.unwrap();
}

async fn assert_times_out(mut stream: impl AsyncRead + Unpin) {
    let mut buf = [0; 1];
    // Give the real socket I/O and accept task time to run before advancing the clock,
    // and check that the connection was not rejected before reaching its timeout.
    assert!(
        timeout(Duration::from_millis(50), stream.read(&mut buf))
            .await
            .is_err(),
        "connection should remain open before its timeout"
    );

    pause();
    advance(ADVANCE).await;
    resume();

    // Time is running again: this bounds actual client-observed closure, not just a timer
    // or task completing on the server. Do not send a WebSocket close or shut down the server.
    match timeout(CLOSE_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Err(err))
            if matches!(
                err.kind(),
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
            ) => {}
        result => panic!("expected server to close the connection within two seconds: {result:?}"),
    }
}

async fn receive_auth_challenge(server: &Server, connector: TlsConnector) -> TlsStream<TcpStream> {
    let stream = tls_connect(server, connector).await;
    let (mut websocket, response) = tokio_websockets::ClientBuilder::new()
        .uri("wss://localhost/relay")
        .unwrap()
        .add_header(SEC_WEBSOCKET_PROTOCOL, "iroh-relay-v2".parse().unwrap())
        .unwrap()
        .connect_on(stream)
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    let challenge = timeout(CLOSE_TIMEOUT, websocket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(challenge.is_binary());
    assert_eq!(challenge.as_payload()[0], 0, "expected ServerChallenge");
    websocket.into_inner()
}

async fn tls_connect(server: &Server, connector: TlsConnector) -> TlsStream<TcpStream> {
    let stream = TcpStream::connect(server.https_addr().unwrap())
        .await
        .unwrap();
    timeout(
        CLOSE_TIMEOUT,
        connector.connect("localhost".try_into().unwrap(), stream),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn server() -> (Server, TlsConnector) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client = CaTlsConfig::custom_roots([cert.cert.der().clone()])
        .client_config(default_provider())
        .unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(default_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(TlsConfig::new(
        (Ipv4Addr::LOCALHOST, 0),
        CertConfig::Manual { server_config: tls },
    ));
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await.unwrap();
    (server, TlsConnector::from(Arc::new(client)))
}
