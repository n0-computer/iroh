//! Prefer post-quantum key exchange when available, fall back to classical.
//!
//! Unlike `pq-only-key-exchange`, this example keeps classical kx groups in
//! the list so the endpoint can still talk to peers that don't support
//! ML-KEM, *and* so n0's relay/discovery TLS (classical kx) keeps working.
//! Putting `X25519MLKEM768` first in `kx_groups` means rustls negotiates PQ
//! whenever both peers support it, classical otherwise.
//!
//! Note: rustls' `aws_lc_rs::default_provider()` only puts `X25519MLKEM768`
//! first when rustls is built with its `prefer-post-quantum` feature; without
//! it, PQ is offered last. We override `kx_groups` here so the policy is
//! independent of how rustls was compiled, and print the list at startup.
//!
//! ## Usage
//!
//! `tls-aws-lc-rs` is required:
//!
//!     cargo run --example prefer-pq-key-exchange --features=tls-aws-lc-rs
use std::sync::Arc;

use iroh::endpoint::{Endpoint, presets::N0};
use n0_error::{Result, StdResultExt};
use rustls::crypto::aws_lc_rs::{self, kx_group};

const ALPN: &[u8] = b"iroh-example/prefer-pq-key-exchange/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ];
    let kx_names: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
    println!("kx_groups (in offer order): {kx_names:?}");
    let pq = Arc::new(provider);

    let server = Endpoint::builder(N0)
        .crypto_provider(pq.clone())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    server.online().await;
    let server_addr = server.addr();
    println!("server  addr: {server_addr:?}");

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
            send.write_all(b"pong over PQ-preferred").await.anyerr()?;
            send.finish().anyerr()?;
            conn.closed().await;
            n0_error::Ok(())
        }
    });

    let client = Endpoint::builder(N0).crypto_provider(pq).bind().await?;
    client.online().await;
    let conn = client.connect(server_addr, ALPN).await.anyerr()?;
    println!("client  handshake done (X25519MLKEM768 preferred, classical kx kept as fallback)");

    let mut send = conn.open_uni().await.anyerr()?;
    send.write_all(b"ping over PQ-preferred").await.anyerr()?;
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
