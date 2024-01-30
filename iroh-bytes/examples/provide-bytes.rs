//! An example that provides a collection over a Quinn connection.
//!
//! Since this example does not use `iroh-net::MagicEndpoint`, it does not do any holepunching, and so will only work locally or between two processes that have public IP addresses.
//!
//! Run this example with
//!    cargo run --examples provide-bytes
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_util::task::LocalPoolHandle;
use tracing_subscriber::{prelude::*, EnvFilter};

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/bytes/0";

// path to save the certificates
const CERT_PATH: &str = "./certs";

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\nprovide bytes example!");

    // create a new database and add two blobs
    let (db, names) =
        iroh_bytes::store::readonly_mem::Store::new([("blob", b"hello world!".to_vec())]);

    // get the hash of the content
    let hash = names.get("blob").unwrap();

    // create tls certs and save to CERT_PATH
    let (key, cert) = make_and_write_certs().await?;

    // create an endpoint to listen for incoming connections
    let endpoint = make_quinn_endpoint(key, cert)?;
    let addr = endpoint.local_addr()?;
    println!("\nlistening on {addr}");
    println!("providing hash {hash}");

    println!("\nfetch the hash using a finite state machine by running the following example:\n\ncargo run --example fetch-bytes {hash} \"{addr}\"");

    // create a new local pool handle with 1 worker thread
    let lp = LocalPoolHandle::new(1);

    let accept_task = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            println!("connection incoming");

            let db = db.clone();
            let lp = lp.clone();

            // spawn a task to handle the connection
            tokio::spawn(async move {
                iroh_bytes::provider::handle_connection(conn, db, MockEventSender, lp).await
            });
        }
    });

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            tokio::fs::remove_dir_all(std::path::PathBuf::from(CERT_PATH)).await?;
            accept_task.abort();
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("unable to listen for ctrl-c: {e}")),
    }
}

#[derive(Clone)]
struct MockEventSender;

use futures::future::FutureExt;

impl iroh_bytes::provider::EventSender for MockEventSender {
    fn send(&self, _event: iroh_bytes::provider::Event) -> futures::future::BoxFuture<()> {
        async move {}.boxed()
    }
}

// derived from `quinn/examples/server.rs`
// creates a self signed certificate and saves it to "./certs"
async fn make_and_write_certs() -> Result<(rustls::PrivateKey, rustls::Certificate)> {
    let path = std::path::PathBuf::from(CERT_PATH);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key_path = path.join("key.der");
    let cert_path = path.join("cert.der");

    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der().unwrap();
    tokio::fs::create_dir_all(path)
        .await
        .context("failed to create certificate directory")?;
    tokio::fs::write(cert_path, &cert)
        .await
        .context("failed to write certificate")?;
    tokio::fs::write(key_path, &key)
        .await
        .context("failed to write private key")?;

    Ok((rustls::PrivateKey(key), rustls::Certificate(cert)))
}

// derived from `quinn/examples/server.rs`
// makes a quinn endpoint
fn make_quinn_endpoint(
    key: rustls::PrivateKey,
    cert: rustls::Certificate,
) -> Result<quinn::Endpoint> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![EXAMPLE_ALPN.to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, "[::1]:4433".parse()?)?;
    Ok(endpoint)
}
