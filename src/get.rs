use std::fmt::Debug;
use std::time::{Duration, Instant};
use std::{io::Read, net::SocketAddr};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::Stream;
use genawaiter::sync::{Co, Gen};
use postcard::experimental::max_size::MaxSize;
use s2n_quic::Connection;
use s2n_quic::{client::Connect, Client};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::debug;

use crate::blobs::Collection;
use crate::protocol::{
    read_lp_data, read_size_data, write_lp, AuthToken, Handshake, Request, Res, Response,
};
use crate::tls::{self, Keypair, PeerId};

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

/// The events that are emitted while running a transfer.
pub enum Event {
    /// The connection to the provider was established.
    Connected,
    /// The provider has the Collection.
    ReceivedCollection(Collection),
    /// Content is being received.
    Receiving {
        /// The hash of the content we received.
        hash: bao::Hash,
        /// The actual data we are receiving.
        reader: Box<dyn AsyncRead + Unpin + Sync + Send + 'static>,
        /// An optional name associated with the data
        name: Option<String>,
    },
    /// The transfer is done.
    Done(Stats),
}

impl Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "Event::Connected"),
            Self::ReceivedCollection(c) => {
                write!(f, "Event::ReceivedCollection({c:#?})")
            }
            Self::Receiving { hash, name, .. } => {
                write!(
                    f,
                    "Event::Receiving {{ hash: {hash}, reader: Box<AsyncReader>, name: {name:#?} }}"
                )
            }
            Self::Done(s) => write!(f, "Event::Done({s:#?})"),
        }
    }
}

pub fn run(hash: bao::Hash, token: AuthToken, opts: Options) -> impl Stream<Item = Result<Event>> {
    Gen::new(|co| producer(hash, token, opts, co))
}

async fn producer(hash: bao::Hash, token: AuthToken, opts: Options, mut co: Co<Result<Event>>) {
    match inner_producer(hash, token, opts, &mut co).await {
        Ok(()) => {}
        Err(err) => {
            co.yield_(Err(err)).await;
        }
    }
}
async fn inner_producer(
    hash: bao::Hash,
    token: AuthToken,
    opts: Options,
    co: &mut Co<Result<Event>>,
) -> Result<()> {
    let now = Instant::now();
    let (_client, mut connection) = setup(opts).await?;

    let stream = connection.open_bidirectional_stream().await?;
    let (mut reader, mut writer) = stream.split();

    co.yield_(Ok(Event::Connected)).await;

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
        let req = Request {
            id: 1,
            name: hash.into(),
        };

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
                    Res::FoundCollection {
                        size,
                        outboard,
                        total_blobs_size,
                    } => {
                        ensure!(
                            total_blobs_size <= MAX_DATA_SIZE,
                            "size too large: {} > {}",
                            total_blobs_size,
                            MAX_DATA_SIZE
                        );

                        data_len = total_blobs_size;

                        // read entire collection data into buffer :(
                        let data = read_size_data(size, &mut reader, &mut in_buffer).await?;

                        // decode the collection
                        let collection = Collection::decode_from(data, outboard, hash).await?;

                        co.yield_(Ok(Event::ReceivedCollection(collection.clone())))
                            .await;

                        // expect to get blob data in the order they appear in the collection
                        for blob in collection.blobs {
                            let (blob_reader, task) =
                                handle_blob_response(blob.hash, &mut reader, &mut in_buffer)
                                    .await?;
                            co.yield_(Ok(Event::Receiving {
                                hash: blob.hash,
                                reader: blob_reader,
                                name: Some(blob.name),
                            }))
                            .await;

                            task.await??;
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

                co.yield_(Ok(Event::Done(stats))).await;
                Ok(())
            }
            None => {
                bail!("provider disconnected");
            }
        }
    }
}

/// Read next response, and if `Res::Found`, reads the next blob of data off the reader.
/// Returns an `AsyncReader` and a `JoinHandle`.
/// The `JoinHandle` task must be `await`-ed to begin decoding the blob data and writing the
/// verified data to the `AsyncReader`.
async fn handle_blob_response<'a, R: AsyncRead + futures::io::AsyncRead + Unpin>(
    hash: bao::Hash,
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<(
    Box<dyn AsyncRead + Unpin + Sync + Send + 'static>,
    tokio::task::JoinHandle<Result<()>>,
)> {
    match read_lp_data(&mut reader, buffer).await? {
        Some(response_buffer) => {
            let response: Response = postcard::from_bytes(&response_buffer)?;
            match response.data {
                // unexpected message
                Res::FoundCollection { .. } => Err(anyhow!(
                    "Unexpected message from provider. Ending transfer early."
                ))?,
                // blob data not found
                Res::NotFound => Err(anyhow!("data for {} not found", hash.to_hex()))?,
                // next blob in collection will be sent over
                Res::Found { size, outboard } => {
                    // reads entire blob into buffer :(
                    let data = read_size_data(size, &mut reader, buffer).await?;
                    decode_data_to_reader(data, outboard, hash).await
                }
            }
        }
        None => Err(anyhow!("server disconnected"))?,
    }
}

/// Returns an `AsyncRead` and a `JoinHandle`.
/// The `JoinHandle` task must be `await`-ed to begin decoding the given data and writing the
/// verified data to the `AsyncRead`er.
async fn decode_data_to_reader(
    data: Bytes,
    outboard: &[u8],
    hash: bao::Hash,
) -> Result<(
    Box<dyn AsyncRead + Unpin + Sync + Send + 'static>,
    tokio::task::JoinHandle<Result<()>>,
)> {
    let (a, mut b) = tokio::io::duplex(1024);

    // TODO: avoid copy
    let outboard = outboard.to_vec();
    let t = tokio::task::spawn(async move {
        // verify content of data matches the expected hash
        let mut decoder =
            bao::decode::Decoder::new_outboard(std::io::Cursor::new(&data[..]), &*outboard, &hash);

        let mut buf = [0u8; 1024];
        loop {
            // TODO: write & use an `async decoder`
            let read = decoder
                .read(&mut buf)
                .context("hash of Collection data does not match")?;
            if read == 0 {
                break;
            }
            b.write_all(&buf[..read]).await?;
        }
        b.flush().await?;
        debug!("finished writing");
        Ok::<(), anyhow::Error>(())
    });

    Ok((Box::new(a), t))
}
