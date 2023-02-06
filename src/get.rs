//! The client side API
//!
//! The main entry point is [`run`]. This function takes callbacks that will
//! be invoked when blobs or collections are received. It is up to the caller
//! to store the received data.
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::BytesMut;
use futures::Future;
use postcard::experimental::max_size::MaxSize;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::bao_slice_decoder::AsyncSliceDecoder;
use crate::blobs::Collection;
use crate::protocol::{
    read_bao_encoded, read_lp_data, write_lp, AuthToken, Handshake, Request, Res, Response,
};
use crate::tls::{self, Keypair, PeerId};

pub use crate::util::Hash;

const MAX_DATA_SIZE: u64 = 1024 * 1024 * 1024;

/// Options for the client
#[derive(Clone, Debug)]
pub struct Options {
    /// The address to connect to
    pub addr: SocketAddr,
    /// The peer id to expect
    pub peer_id: Option<PeerId>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            addr: "127.0.0.1:4433".parse().unwrap(),
            peer_id: None,
        }
    }
}

/// Setup a QUIC connection to the provided address.
async fn setup(opts: Options) -> Result<quinn::Connection> {
    let keypair = Keypair::generate();

    let tls_client_config = tls::make_client_config(&keypair, opts.peer_id)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);

    debug!("connecting to {}", opts.addr);
    let connect = endpoint.connect(opts.addr, "localhost")?;
    let connection = connect.await?;

    Ok(connection)
}

/// Stats about the transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct Stats {
    /// The number of bytes transferred
    pub data_len: u64,
    /// The time it took to transfer the data
    pub elapsed: Duration,
}

impl Stats {
    /// Transfer rate in megabits per second
    pub fn mbits(&self) -> f64 {
        let data_len_bit = self.data_len * 8;
        data_len_bit as f64 / (1000. * 1000.) / self.elapsed.as_secs_f64()
    }
}

/// A verified stream of data coming from the provider
///
/// We guarantee that the data is correct by incrementally verifying a hash
#[repr(transparent)]
#[derive(Debug)]
pub struct DataStream(AsyncSliceDecoder<quinn::RecvStream>);

impl DataStream {
    fn new(inner: quinn::RecvStream, hash: Hash) -> Self {
        DataStream(AsyncSliceDecoder::new(inner, hash.into(), 0, u64::MAX))
    }

    async fn read_size(&mut self) -> io::Result<u64> {
        self.0.read_size().await
    }

    fn into_inner(self) -> quinn::RecvStream {
        self.0.into_inner()
    }
}

impl AsyncRead for DataStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// Get a collection and all its blobs from a provider
pub async fn run<A, B, C, FutA, FutB, FutC>(
    hash: Hash,
    token: AuthToken,
    opts: Options,
    on_connected: A,
    mut on_collection: B,
    mut on_blob: C,
) -> Result<Stats>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    B: FnMut(Collection) -> FutB,
    FutB: Future<Output = Result<()>>,
    C: FnMut(Hash, DataStream, String) -> FutC,
    FutC: Future<Output = Result<DataStream>>,
{
    let now = Instant::now();
    let connection = setup(opts).await?;

    let (mut writer, mut reader) = connection.open_bi().await?;

    on_connected().await?;

    let mut out_buffer = BytesMut::zeroed(std::cmp::max(
        Request::POSTCARD_MAX_SIZE,
        Handshake::POSTCARD_MAX_SIZE,
    ));

    // 1. Send Handshake
    {
        debug!("sending handshake");
        let handshake = Handshake::new(token);
        let used = postcard::to_slice(&handshake, &mut out_buffer)?;
        write_lp(&mut writer, used).await?;
    }

    // 2. Send Request
    {
        debug!("sending request");
        let req = Request { id: 1, name: hash };

        let used = postcard::to_slice(&req, &mut out_buffer)?;
        write_lp(&mut writer, used).await?;
    }

    // 3. Read response
    {
        debug!("reading response");
        let mut in_buffer = BytesMut::with_capacity(1024);

        // track total amount of blob data transferred
        let mut data_len = 0;
        // read next message
        match read_lp_data(&mut reader, &mut in_buffer).await? {
            Some(response_buffer) => {
                let response: Response = postcard::from_bytes(&response_buffer)?;
                match response.data {
                    // server is sending over a collection of blobs
                    Res::FoundCollection { total_blobs_size } => {
                        ensure!(
                            total_blobs_size <= MAX_DATA_SIZE,
                            "size too large: {} > {}",
                            total_blobs_size,
                            MAX_DATA_SIZE
                        );

                        data_len = total_blobs_size;

                        // read entire collection data into buffer
                        let data = read_bao_encoded(&mut reader, hash).await?;

                        // decode the collection
                        let collection = Collection::from_bytes(&data)?;
                        on_collection(collection.clone()).await?;

                        // expect to get blob data in the order they appear in the collection
                        let mut remaining_size = total_blobs_size;
                        for blob in collection.blobs {
                            let mut blob_reader =
                                handle_blob_response(blob.hash, reader, &mut in_buffer).await?;

                            let size = blob_reader.read_size().await?;
                            anyhow::ensure!(
                                size <= MAX_DATA_SIZE,
                                "size too large: {size} > {MAX_DATA_SIZE}"
                            );
                            anyhow::ensure!(
                                size <= remaining_size,
                                "downloaded more than {total_blobs_size}"
                            );
                            remaining_size -= size;
                            let blob_reader = on_blob(blob.hash, blob_reader, blob.name).await?;
                            reader = blob_reader.into_inner();
                        }
                    }

                    // unexpected message
                    Res::Found { .. } => {
                        // we should only receive `Res::FoundCollection` or `Res::NotFound` from the
                        // provider at this point in the exchange
                        bail!("Unexpected message from provider. Ending transfer early.");
                    }

                    // data associated with the hash is not found
                    Res::NotFound => {
                        Err(anyhow!("data not found"))?;
                    }
                }

                // Shut down the stream
                debug!("shutting down stream");
                writer.shutdown().await?;

                let elapsed = now.elapsed();

                let stats = Stats { data_len, elapsed };

                Ok(stats)
            }
            None => {
                bail!("provider disconnected");
            }
        }
    }
}

/// Read next response, and if `Res::Found`, reads the next blob of data off the reader.
///
/// Returns an `AsyncReader`
/// The `AsyncReader` can be used to read the content.
async fn handle_blob_response(
    hash: Hash,
    mut reader: quinn::RecvStream,
    buffer: &mut BytesMut,
) -> Result<DataStream> {
    match read_lp_data(&mut reader, buffer).await? {
        Some(response_buffer) => {
            let response: Response = postcard::from_bytes(&response_buffer)?;
            match response.data {
                // unexpected message
                Res::FoundCollection { .. } => Err(anyhow!(
                    "Unexpected message from provider. Ending transfer early."
                ))?,
                // blob data not found
                Res::NotFound => Err(anyhow!("data for {} not found", hash))?,
                // next blob in collection will be sent over
                Res::Found => {
                    assert!(buffer.is_empty());
                    let decoder = DataStream::new(reader, hash);
                    Ok(decoder)
                }
            }
        }
        None => Err(anyhow!("server disconnected"))?,
    }
}
