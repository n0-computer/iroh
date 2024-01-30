//! An example how to download a single blob from a node and write it to stdout, using a helper method to turn the `get` finite state machine into a stream.
//!
//! Since this example does not use `iroh-net::MagicEndpoint`, it does not do any holepunching, and so will only work locally or between two processes that have public IP addresses.
//!
//! Run the provide-bytes example first. It will give instructions on how to run this example properly.
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use tracing_subscriber::{prelude::*, EnvFilter};

use std::io;

use bao_tree::io::fsm::BaoContentItem;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use genawaiter::sync::Co;
use genawaiter::sync::Gen;
use tokio::io::AsyncWriteExt;

use iroh_bytes::{
    get::fsm::{AtInitial, BlobContentNext, ConnectedNext, EndBlobNext},
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
    println!("\nfetch stream example!");
    setup_logging();
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        anyhow::bail!("usage: fetch-bytes [HASH] [SOCKET_ADDR] [FORMAT]");
    }
    let hash: Hash = args[1].parse().context("unable to parse [HASH]")?;
    let addr: SocketAddr = args[2].parse().context("unable to parse [SOCKET_ADDR]")?;
    let format = {
        if args[3] != "blob" && args[3] != "collection" {
            anyhow::bail!(
                "expected either 'blob' or 'collection' for FORMAT argument, got {}",
                args[3]
            );
        }
        args[3].clone()
    };

    // load tls certificates
    // This will error if you have not run the `provide-bytes` example
    let roots = load_certs().await?;

    // create an endpoint to listen for incoming connections
    let endpoint = make_quinn_endpoint(roots)?;
    println!("\nlistening on {}", endpoint.local_addr()?);
    println!("fetching hash {hash} from {addr}\n");

    // connect
    let connection = endpoint.connect(addr, "localhost")?.await?;

    let mut stream = if format == "collection" {
        // create a request for a single blob
        let request = GetRequest::all(hash);

        // create the initial state of the finite state machine
        let initial = iroh_bytes::get::fsm::start(connection, request);

        // create a stream that yields all the data of the blob
        stream_children(initial).boxed_local()
    } else {
        // create a request for a single blob
        let request = GetRequest::single(hash);

        // create the initial state of the finite state machine
        let initial = iroh_bytes::get::fsm::start(connection, request);

        // create a stream that yields all the data of the blob
        stream_blob(initial).boxed_local()
    };
    while let Some(item) = stream.next().await {
        let item = item?;
        tokio::io::stdout().write_all(&item).await?;
    }
    Ok(())
}

/// Stream the response for a request for a single blob.
///
/// If the request was for a part of the blob, this will stream just the requested
/// blocks.
///
/// This will stream the root blob and close the connection.
fn stream_blob(initial: AtInitial) -> impl Stream<Item = io::Result<Bytes>> + 'static {
    async fn inner(initial: AtInitial, co: &Co<io::Result<Bytes>>) -> io::Result<()> {
        // connect
        let connected = initial.next().await?;
        // read the first bytes
        let ConnectedNext::StartRoot(start_root) = connected.next().await? else {
            return Err(io::Error::new(io::ErrorKind::Other, "expected start root"));
        };
        // move to the header
        let header = start_root.next();
        // get the size of the content
        let (mut content, _size) = header.next().await?;
        // manually loop over the content and yield all data
        let done = loop {
            match content.next().await {
                BlobContentNext::More((next, data)) => {
                    if let BaoContentItem::Leaf(leaf) = data? {
                        // yield the data
                        co.yield_(Ok(leaf.data)).await;
                    }
                    content = next;
                }
                BlobContentNext::Done(done) => {
                    // we are done with the root blob
                    break done;
                }
            }
        };
        // close the connection even if there is more data
        let closing = match done.next() {
            EndBlobNext::Closing(closing) => closing,
            EndBlobNext::MoreChildren(more) => more.finish(),
        };
        // close the connection
        let _stats = closing.next().await?;
        Ok(())
    }

    Gen::new(|co| async move {
        if let Err(e) = inner(initial, &co).await {
            co.yield_(Err(e)).await;
        }
    })
}

/// Stream the response for a request for an iroh collection and its children.
///
/// If the request was for a part of the children, this will stream just the requested
/// blocks.
///
/// The root blob is not streamed. It must be fully included in the response.
fn stream_children(initial: AtInitial) -> impl Stream<Item = io::Result<Bytes>> + 'static {
    async fn inner(initial: AtInitial, co: &Co<io::Result<Bytes>>) -> io::Result<()> {
        // connect
        let connected = initial.next().await?;
        // read the first bytes
        let ConnectedNext::StartRoot(start_root) = connected.next().await? else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to parse collection",
            ));
        };
        // check that we requested the whole collection
        if !start_root.ranges().is_all() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "collection was not requested completely",
            ));
        }
        // move to the header
        let header: iroh_bytes::get::fsm::AtBlobHeader = start_root.next();
        let (root_end, links_bytes) = header.concatenate_into_vec().await?;
        let EndBlobNext::MoreChildren(at_meta) = root_end.next() else {
            return Err(io::Error::new(io::ErrorKind::Other, "missing meta blob"));
        };
        let links: Box<[iroh_bytes::Hash]> = postcard::from_bytes(&links_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to parse links"))?;
        let meta_link = *links
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "missing meta link"))?;
        let (meta_end, _meta_bytes) = at_meta.next(meta_link).concatenate_into_vec().await?;
        let mut curr = meta_end.next();
        let closing = loop {
            match curr {
                EndBlobNext::MoreChildren(more) => {
                    let Some(hash) = links.get(more.child_offset() as usize) else {
                        break more.finish();
                    };
                    let header = more.next(*hash);
                    let (mut content, _size) = header.next().await?;
                    // manually loop over the content and yield all data
                    let done = loop {
                        match content.next().await {
                            BlobContentNext::More((next, data)) => {
                                if let BaoContentItem::Leaf(leaf) = data? {
                                    // yield the data
                                    co.yield_(Ok(leaf.data)).await;
                                }
                                content = next;
                            }
                            BlobContentNext::Done(done) => {
                                // we are done with the root blob
                                break done;
                            }
                        }
                    };
                    curr = done.next();
                }
                EndBlobNext::Closing(closing) => {
                    break closing;
                }
            }
        };
        // close the connection
        let _stats = closing.next().await?;
        Ok(())
    }

    Gen::new(|co| async move {
        if let Err(e) = inner(initial, &co).await {
            co.yield_(Err(e)).await;
        }
    })
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
