//! Native relay server for the browser WebTransport tests.
//!
//! Spawns a relay that serves WebTransport over HTTP/3 with a browser-compatible
//! self-signed certificate (ECDSA P-256, short-lived), then prints the SHA-256
//! hash of that certificate and the relay URL so the wasm test can connect via
//! `serverCertificateHashes`. Runs until interrupted.
//!
//! Used by `bench/wasm/run.sh`; not part of the crate's public surface.

use std::net::Ipv4Addr;

use iroh_relay::server::{Server, testing::webtransport_server_config};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Install a process-default rustls crypto provider (needed by the QUIC/H3
    // server setup).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    let (cert_der, config) = webtransport_server_config((Ipv4Addr::LOCALHOST, port));
    let hash = Sha256::digest(&cert_der);

    let server = Server::spawn(config)
        .await
        .expect("failed to spawn relay server");

    // Machine-readable lines consumed by the orchestration script. Print them on
    // stdout after the server is up so the script can proceed.
    println!("CERT_SHA256={}", data_encoding::HEXLOWER.encode(&hash));
    println!("RELAY_URL=https://localhost:{port}");
    println!(
        "RELAY_H3_ADDR={:?}",
        server.h3_addr().expect("H3 server should be running")
    );
    println!("RELAY_READY");
    // Flush stdout so the script sees the lines immediately.
    use std::io::Write;
    let _ = std::io::stdout().flush();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    server.shutdown().await.ok();
}
