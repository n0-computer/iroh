//! Force iroh to negotiate ONLY a post-quantum key exchange (X25519MLKEM768).
//!
//! Requires `tls-aws-lc-rs` (the only rustls backend with ML-KEM today).
//! Stripping `kx_groups` to the PQ group makes PQ *required* rather than
//! *preferred*: peers without it fail the TLS handshake.
//!
//! Note: iroh's `crypto_provider` is shared with relay/discovery TLS, and
//! n0's infra does not support PQ key exchange yet — so a PQ-only endpoint
//! can't use n0 public relays or discovery servers.
//!
//! ## Usage
//!
//! `tls-aws-lc-rs` is required (the example explicitly constructs an
//! aws-lc-rs `CryptoProvider`, so the backend must be linked):
//!
//!     cargo run --example pq-key-exchange --features=tls-aws-lc-rs
//!
//! With iroh's default features still on, both `ring` and `aws-lc-rs` get
//! linked. That's harmless — we wire the aws-lc-rs provider in directly via
//! `Builder::crypto_provider`.
use std::sync::Arc;

use iroh::{
    RelayMode,
    endpoint::{Endpoint, presets::Empty},
};
use n0_error::{Result, StdResultExt};
use rustls::crypto::aws_lc_rs;

const ALPN: &[u8] = b"iroh-example/pq-key-exchange/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let pq = pq_only_provider();

    let server = Endpoint::builder(Empty)
        .crypto_provider(pq.clone())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let server_addr = server.addr();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .accept()
                .anyerr()?
                .await
                .anyerr()?;
            let mut recv = conn.accept_uni().await.anyerr()?;
            let msg = recv.read_to_end(1024).await.anyerr()?;
            println!("server  received: {:?}", String::from_utf8_lossy(&msg));
            let mut send = conn.open_uni().await.anyerr()?;
            send.write_all(b"pong over PQ").await.anyerr()?;
            send.finish().anyerr()?;
            conn.closed().await;
            n0_error::Ok(())
        }
    });

    let client = Endpoint::builder(Empty)
        .crypto_provider(pq)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = client.connect(server_addr, ALPN).await.anyerr()?;
    println!("client  handshake done (X25519MLKEM768 was the only kx offered)");

    let mut send = conn.open_uni().await.anyerr()?;
    send.write_all(b"ping over PQ").await.anyerr()?;
    send.finish().anyerr()?;
    let mut recv = conn.accept_uni().await.anyerr()?;
    let msg = recv.read_to_end(1024).await.anyerr()?;
    println!("client  received: {:?}", String::from_utf8_lossy(&msg));

    conn.close(0u32.into(), b"done");
    server_task.await.anyerr()?.anyerr()?;
    client.close().await;
    server.close().await;
    Ok(())
}

fn pq_only_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(p)
}
