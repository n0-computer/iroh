//! An example how to download a single blob or collection from a node and write it to stdout using the `get` finite state machine directly.
//!
//! Since this example does not use `iroh-net::MagicEndpoint`, it does not do any holepunching, and so will only work locally or between two processes that have public IP addresses.
//!
//! Run the provide-bytes example first. It will give instructions on how to run this example properly.
use std::net::SocketAddr;

use anyhow::{Context, Result};
use iroh_io::ConcatenateSliceWriter;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{
    get::fsm::{AtInitial, ConnectedNext, EndBlobNext},
    hashseq::HashSeq,
    protocol::GetRequest,
    Hash,
};

mod connect;
use connect::{load_certs, make_client_endpoint};

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
    let endpoint = make_client_endpoint(roots)?;
    println!("\nlistening on {}", endpoint.local_addr()?);
    println!("fetching hash {hash} from {addr}");

    // connect
    let connection = endpoint.connect(addr, "localhost")?.await?;

    if format == "collection" {
        // create a request for a collection
        let request = GetRequest::all(hash);
        // create the initial state of the finite state machine
        let initial = iroh_bytes::get::fsm::start(connection, request);

        write_collection(initial).await
    } else {
        // create a request for a single blob
        let request = GetRequest::single(hash);
        // create the initial state of the finite state machine
        let initial = iroh_bytes::get::fsm::start(connection, request);

        write_blob(initial).await
    }
}

async fn write_blob(initial: AtInitial) -> Result<()> {
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

    // make the spacing nicer in the terminal
    println!();
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

async fn write_collection(initial: AtInitial) -> Result<()> {
    // connect
    let connected = initial.next().await?;
    // read the first bytes
    let ConnectedNext::StartRoot(start_root) = connected.next().await? else {
        anyhow::bail!("failed to parse collection");
    };
    // check that we requested the whole collection
    if !start_root.ranges().is_all() {
        anyhow::bail!("collection was not requested completely");
    }

    // move to the header
    let header: iroh_bytes::get::fsm::AtBlobHeader = start_root.next();
    let (root_end, hashes_bytes) = header.concatenate_into_vec().await?;
    let next = root_end.next();
    let EndBlobNext::MoreChildren(at_meta) = next else {
        anyhow::bail!("missing meta blob, got {next:?}");
    };
    // parse the hashes from the hash sequence bytes
    let hashes = HashSeq::try_from(bytes::Bytes::from(hashes_bytes))
        .context("failed to parse hashes")?
        .into_iter()
        .collect::<Vec<_>>();
    let meta_hash = hashes.first().context("missing meta hash")?;

    let (meta_end, _meta_bytes) = at_meta.next(*meta_hash).concatenate_into_vec().await?;
    let mut curr = meta_end.next();
    let closing = loop {
        match curr {
            EndBlobNext::MoreChildren(more) => {
                let Some(hash) = hashes.get(more.child_offset() as usize) else {
                    break more.finish();
                };
                let header = more.next(*hash);

                // we need to wrap stdout in a struct that implements AsyncSliceWriter. Since we can not
                // seek in stdout we use ConcatenateSliceWriter which just concatenates all the writes.
                let writer = ConcatenateSliceWriter::new(tokio::io::stdout());

                // use the utility function write_all to write the entire blob
                let end = header.write_all(writer).await?;
                println!();
                curr = end.next();
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

#[derive(Clone)]
struct MockEventSender;

use futures_lite::future::FutureExt;

impl iroh_bytes::provider::EventSender for MockEventSender {
    fn send(&self, _event: iroh_bytes::provider::Event) -> futures_lite::future::Boxed<()> {
        async move {}.boxed()
    }
}
