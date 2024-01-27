//! An example that provides a collection over a Quinn connection.
//!
//! Since this example does not use `iroh-net::MagicEndpoint`, it does not do any holepunching, and so will only work locally or between two processes that have public IP addresses.
//!
//! Run this example with
//!    cargo run --examples provide-bytes
use std::sync::Arc;

use anyhow::Result;
use tokio_util::task::LocalPoolHandle;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{format::collection::Collection, Hash};

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/bytes/0";
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
    println!("provide bytes example!");
    // create a new database and add two blobs
    let (mut db, names) = iroh_bytes::store::readonly_mem::Store::new([
        ("blob1", b"the first blob of bytes".to_vec()),
        ("blob2", b"the second blob of bytes".to_vec()),
    ]);
    // create blobs from the data
    let collection: Collection = names
        .into_iter()
        .map(|(name, hash)| (name, Hash::from(hash)))
        .collect();
    // create a collection and add it to the db as well
    let hash = db.insert_many(collection.to_blobs()).unwrap();

    // create an endpoint to listen for incoming connections
    let endpoint = make_quinn_endpoint()?;
    println!("listening on {}", endpoint.local_addr()?);
    println!("providing hash {hash}");

    // create a new local pool handle with 1 worker thread
    let lp = LocalPoolHandle::new(1);

    while let Some(conn) = endpoint.accept().await {
        println!("connection incoming");

        let db = db.clone();
        let lp = lp.clone();

        // spawn a task to handle the connection
        tokio::spawn(async move {
            iroh_bytes::provider::handle_connection(conn, db, MockEventSender, lp).await
        });
    }

    Ok(())
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
fn make_quinn_endpoint() -> Result<quinn::Endpoint> {
    tracing::info!("generating self-signed certificate");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());
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
