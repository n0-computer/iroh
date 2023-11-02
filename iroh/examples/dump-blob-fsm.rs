//! An example how to download a single blob from a node and write it to stdout.
//!
//! This is using the get finite state machine directly.
//! Run this example on any `iroh get` ticket. You can create a "hello world" ticket with:
//!     $ cargo run --example hello-world
//! hello-world will give you a "ticket" argument & example to use with `cargo run -- get --ticket`
//! copy that ticket value (the long string after `--ticket`) & feed it to this example:
//!     $ cargo run --example dump-blob-fsm <ticket>
use std::env::args;

use iroh::ticket::blob::Ticket;
use iroh_bytes::get::fsm::{ConnectedNext, EndBlobNext};
use iroh_bytes::protocol::GetRequest;
use iroh_io::ConcatenateSliceWriter;
use iroh_net::key::SecretKey;
use tracing_subscriber::{prelude::*, EnvFilter};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();

    let ticket: Ticket = args().nth(1).expect("missing ticket").parse()?;

    // generate a transient secretkey for this connection
    //
    // in real applications, it would be very much preferable to use a persistent secret key
    let secret_key = SecretKey::generate();
    let dial_options = ticket.as_get_options(secret_key, None);

    // connect to the peer
    //
    // note that dial creates a new endpoint, so it should only be used for short lived command line tools
    let connection = iroh::dial::dial(dial_options).await?;

    // create a request for a single blob
    let request = GetRequest::single(ticket.hash());

    // create the initial state of the finite state machine
    let initial = iroh::bytes::get::fsm::start(connection, request);

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
