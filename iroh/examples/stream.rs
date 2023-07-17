//! An example how to download a single blob from a node and write it to stdout.
//!
//! This is using the get finite state machine directly.
use std::env::args;
use std::io::{self};
use std::str::FromStr;

use bytes::Bytes;
use futures::Stream;
use genawaiter::sync::Gen;
use iroh::dial::Ticket;
use iroh_bytes::get::fsm::{ConnectedNext, EndBlobNext, AtInitial};
use iroh_bytes::protocol::GetRequest;
use iroh_io::ConcatenateSliceWriter;
use iroh_net::tls::Keypair;
use tracing_subscriber::{prelude::*, EnvFilter};
use genawaiter::{sync::Co, yield_};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

async fn stream_inner(initial: AtInitial, co: Co<io::Result<Bytes>>) {

}

fn stream(initial: AtInitial) -> impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static {
    let gen = Gen::new(|co| stream_inner(initial, co));
    gen
}

fn main() {

}