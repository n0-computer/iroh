use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::BytesMut;
use futures::Future;
use postcard::experimental::max_size::MaxSize;
use s2n_quic::stream::ReceiveStream;
use s2n_quic::Connection;
use s2n_quic::{client::Connect, Client};
use tokio::io::{AsyncRead, ReadBuf};
use tracing::debug;

use crate::bao_slice_decoder::AsyncSliceDecoder;
use crate::blobs::Collection;
use crate::protocol::{
    read_bao_encoded, read_lp_data, write_lp, AuthToken, Handshake, Request, Res, Response,
};
use crate::tls::{self, Keypair, PeerId};
use crate::util::Hash;

const MAX_DATA_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Options {
    pub addr: SocketAddr,
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
async fn setup(opts: Options) -> Result<(Client, Connection)> {
    let keypair = Keypair::generate();

    let client_config = tls::make_client_config(&keypair, opts.peer_id)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    debug!("connecting to {}", opts.addr);
    let connect = Connect::new(opts.addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    connection.keep_alive(true)?;
    Ok((client, connection))
}

/// Stats about the transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct Stats {
    pub data_len: u64,
    pub elapsed: Duration,
    pub mbits: f64,
}

/// A verified stream of data coming from the provider
///
/// We guarantee that the data is correct by incrementally verifying a hash
#[repr(transparent)]
#[derive(Debug)]
pub struct DataStream(AsyncSliceDecoder<ReceiveStream>);

impl DataStream {
    fn new(inner: ReceiveStream, hash: Hash) -> Self {
        DataStream(AsyncSliceDecoder::new(inner, hash.into(), 0, u64::MAX))
    }

    async fn read_size(&mut self) -> io::Result<u64> {
        self.0.read_size().await
    }

    fn into_inner(self) -> ReceiveStream {
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
    C: FnMut(Hash, DataStream, Option<String>) -> FutC,
    FutC: Future<Output = Result<DataStream>>,
{
    let now = Instant::now();
    let (_client, mut connection) = setup(opts).await?;

    let stream = connection.open_bidirectional_stream().await?;
    let (mut reader, mut writer) = stream.split();

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
                            let blob_reader =
                                on_blob(blob.hash, blob_reader, Some(blob.name)).await?;
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
                writer.close().await?;

                let elapsed = now.elapsed();
                let elapsed_s = elapsed.as_secs_f64();
                let data_len_bit = data_len * 8;
                let mbits = data_len_bit as f64 / (1000. * 1000.) / elapsed_s;

                let stats = Stats {
                    data_len,
                    elapsed,
                    mbits,
                };

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
    mut reader: ReceiveStream,
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
