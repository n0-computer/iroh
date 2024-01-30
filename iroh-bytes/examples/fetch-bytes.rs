//! An example how to download a single blob from a node and write it to stdout.
//!
//! This is using the get finite state machine directly.
//!
//! Since this example does not use `iroh-net::MagicEndpoint`, it does not do any holepunching, and so will only work locally or between two processes that have public IP addresses.
//!
//! Run the provide-bytes example first. It will give instructions on how to run this example properly.
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use iroh_io::ConcatenateSliceWriter;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{
    get::fsm::{ConnectedNext, EndBlobNext},
    protocol::GetRequest,
    Hash,
};

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/bytes/0";

// Path where the tls certificates are saved. This example expects that you have run the `provide-bytes` example first, which generates the certificates.
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
    println!("\nfetch bytes example!");
    setup_logging();
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        anyhow::bail!("usage: fetch-bytes [HASH] [SOCKET_ADDR]");
    }
    let hash: Hash = args[1].parse().context("unable to parse [HASH]")?;
    let addr: SocketAddr = args[2].parse().context("unable to parse [SOCKET_ADDR]")?;

    // load tls certificates
    // This will error if you have not run the `provide-bytes` example
    let roots = load_certs().await?;

    // create an endpoint to listen for incoming connections
    let endpoint = make_quinn_endpoint(roots)?;
    println!("\nlistening on {}", endpoint.local_addr()?);
    println!("fetching hash {hash} from {addr}\n");

    // connect
    let connection = endpoint.connect(addr, "localhost")?.await?;

    // create a request for a single blob
    let request = GetRequest::single(hash);

    // create the initial state of the finite state machine
    let initial = iroh_bytes::get::fsm::start(connection, request);

    // connect (create a stream pair)
    let connected = initial.next().await?;

    // we expect a start root message, since we requested a single blob
    let ConnectedNext::StartRoot(start_root) = connected.next().await? else {
        panic!("expected start root")
    };
    // we can just call next to proceed to the header, since we know the root hash
    let header = start_root.next();

    // we need to wrap stdout in a struct that implements AsyncSliceWriter. Since we can not
    // seek in stdout we use ConcatenateSliceWriter which just concatenates all the writes.
    let writer = ConcatenateSliceWriter::new(tokio::io::stdout());

    // use the utility function write_all to write the entire blob
    let end = header.write_all(writer).await?;

    // we requested a single blob, so we expect to enter the closing state
    let EndBlobNext::Closing(closing) = end.next() else {
        panic!("expected closing")
    };

    // close the connection and get the stats
    let _stats = closing.next().await?;
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

// derived from `quinn/examples/client.rs`
// load the certificates from CERT_PATH
// Assumes that you have already run the `provide-bytes` example, that generates the certificates
async fn load_certs() -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let path = std::path::PathBuf::from(CERT_PATH).join("cert.der");
    match tokio::fs::read(path).await {
        Ok(cert) => {
            roots.add(&rustls::Certificate(cert))?;
        }
        Err(e) => {
            anyhow::bail!("failed to open local server certificate: {}\nYou must run the `provide-bytes` example to create the certificate.\n\tcargo run --example provide-bytes", e);
        }
    }
    Ok(roots)
}

// derived from `quinn/examples/client.rs`
// Creates a client quinnendpoint
fn make_quinn_endpoint(roots: rustls::RootCertStore) -> Result<quinn::Endpoint> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![EXAMPLE_ALPN.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
