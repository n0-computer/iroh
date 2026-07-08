//! Native relay + echo peer for the browser WebTransport `Endpoint` test.
//!
//! Spawns a relay serving WebTransport over HTTP/3 with a browser-compatible
//! self-signed certificate, then binds an iroh [`Endpoint`] (the echo peer) that
//! uses that relay. Prints the relay URL, the certificate SHA-256 hash, and the
//! peer's endpoint id so the wasm test (`iroh/tests/wt_browser_endpoint.rs`) can
//! dial the peer through the relay from a browser. Runs until interrupted.
//!
//! Used by `bench/wasm/run_iroh.sh`; not part of the crate's public surface.

use std::net::Ipv4Addr;

use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, RelayUrl, endpoint::presets};
use iroh_relay::{
    server::{Server, testing::webtransport_server_config},
    tls::CaTlsConfig,
};
use n0_error::{Result, StdResultExt};
use sha2::{Digest, Sha256};
use tracing::info;

const ECHO_ALPN: &[u8] = b"echo";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4434);

    let (cert_der, config) = webtransport_server_config((Ipv4Addr::LOCALHOST, port));
    let hash = Sha256::digest(&cert_der);
    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let _server: Server = Server::spawn(config).await?;

    let relay_url: RelayUrl = format!("https://localhost:{port}")
        .parse()
        .expect("valid url");
    // Advertise WebTransport (h3) for this relay (the default for RelayConfig).
    let relay_config = RelayConfig::new(relay_url.clone(), None);
    let relay_map: RelayMap = relay_config.into();

    let endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![ECHO_ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(relay_map))
        // Trust the relay's self-signed certificate on the native side.
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;

    // Wait until the peer is registered with the relay so the browser can reach it.
    endpoint.online().await;

    println!("CERT_SHA256={hash_hex}");
    println!("RELAY_URL={relay_url}");
    println!("PROVIDER_ID={}", endpoint.id());
    println!("RELAY_READY");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    info!(id = %endpoint.id().fmt_short(), %relay_url, "echo peer online");

    // Echo loop: copy every stream's bytes back to the sender.
    let accept_endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            tokio::spawn(async move {
                let conn = incoming.await?;
                let id = conn.remote_id();
                info!(remote = %id.fmt_short(), "accepted connection");
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let mut total = 0;
                    while let Some(chunk) = recv.read_chunk(10_000).await.anyerr()? {
                        total += chunk.len();
                        send.write_chunk(chunk).await.anyerr()?;
                    }
                    send.finish().anyerr()?;
                    info!(total, "echoed stream");
                }
                n0_error::Ok(())
            });
        }
    });

    tokio::signal::ctrl_c().await?;
    endpoint.close().await;
    Ok(())
}
