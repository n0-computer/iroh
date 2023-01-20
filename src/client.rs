use std::time::Duration;
use std::{io::Read, net::SocketAddr, time::Instant};

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use futures::Stream;
use postcard::experimental::max_size::MaxSize;
use s2n_quic::Connection;
use s2n_quic::{client::Connect, Client};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::protocol::{read_lp_data, write_lp, Handshake, Request, Res, Response};
use crate::tls::{self, Keypair, PeerId};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

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

/// Setup a QUIC connection to the provided server address
async fn setup(opts: Options) -> Result<(Client, Connection)> {
    let keypair = Keypair::generate();

    let client_config = tls::make_client_config(&keypair, opts.peer_id)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    debug!("client: connecting to {}", opts.addr);
    let connect = Connect::new(opts.addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    connection.keep_alive(true)?;
    Ok((client, connection))
}

/// Stats about the transfer.
pub struct Stats {
    pub data_len: usize,
    pub elapsed: Duration,
    pub mbits: f64,
}

/// The events that are emitted while running a transfer.
pub enum Event {
    /// The connection to the server was established.
    Connected,
    /// The server has the content.
    Requested {
        /// The size of the requested content.
        size: usize,
    },
    /// Content is being received.
    Receiving {
        /// The hash of the content we received.
        hash: bao::Hash,
        /// The actual data we are receiving.
        reader: Box<dyn AsyncRead + Unpin + Sync + Send + 'static>,
    },
    /// The transfer is done.
    Done(Stats),
}

pub fn run(hash: bao::Hash, opts: Options) -> impl Stream<Item = Result<Event>> {
    async_stream::try_stream! {
        let now = Instant::now();
        let (_client, mut connection) = setup(opts).await?;

        let stream = connection.open_bidirectional_stream().await?;
        let (mut reader, mut writer) = stream.split();

        yield Event::Connected;


        let mut out_buffer = BytesMut::zeroed(std::cmp::max(
            Request::POSTCARD_MAX_SIZE,
            Handshake::POSTCARD_MAX_SIZE,
        ));

        // 1. Send Handshake
        {
            debug!("sending handshake");
            let handshake = Handshake::default();
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

            // read next message
            match read_lp_data(&mut reader, &mut in_buffer).await? {
                Some(response_buffer) => {
                    let response: Response = postcard::from_bytes(&response_buffer)?;
                    match response.data {
                        Res::Found { size, outboard } => {
                            yield Event::Requested { size };

                            // Need to read the message now
                            if size > MAX_DATA_SIZE {
                                Err(anyhow!("size too large: {} > {}", size, MAX_DATA_SIZE))?;
                            }

                            // TODO: avoid buffering

                            // remove response buffered data
                            while in_buffer.len() < size {
                                reader.read_buf(&mut in_buffer).await?;
                            }

                            debug!("received data: {}bytes", in_buffer.len());
                            if size != in_buffer.len() {
                                Err(anyhow!("expected {} bytes, got {} bytes", size, in_buffer.len()))?;
                            }
                            let (a, mut b) = tokio::io::duplex(1024);

                            let outboard = outboard.to_vec();
                            let t = tokio::task::spawn(async move {
                                let mut decoder = bao::decode::Decoder::new_outboard(
                                    std::io::Cursor::new(&in_buffer[..]),
                                    &*outboard,
                                    &hash,
                                );


                                let mut buf = [0u8; 1024];
                                loop {
                                    // TODO: avoid blocking
                                    let read = decoder.read(&mut buf)?;
                                    if read == 0 {
                                        break;
                                    }
                                    b.write_all(&buf[..read]).await?;
                                }
                                b.flush().await?;
                                Ok::<(), anyhow::Error>(())
                            });

                            yield Event::Receiving { hash, reader: Box::new(a) };

                            t.await??;

                            // Shut down the stream
                            debug!("shutting down stream");
                            writer.close().await?;

                            let data_len = size;
                            let elapsed = now.elapsed();
                            let elapsed_s = elapsed.as_secs_f64();
                            let data_len_bit = data_len * 8;
                            let mbits = data_len_bit as f64 / (1000. * 1000.) / elapsed_s;

                            let stats = Stats {
                                data_len,
                                elapsed,
                                mbits,
                            };

                            yield Event::Done(stats);
                        }
                        Res::NotFound => {
                            Err(anyhow!("data not found"))?;
                        }
                    }
                }
                None => {
                    Err(anyhow!("server disconnected"))?;
                }
            }
        }
    }
}
