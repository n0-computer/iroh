use std::time::Duration;
use std::{io::Read, net::SocketAddr, time::Instant};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::BytesMut;
use s2n_quic::Connection;
use s2n_quic::{client::Connect, Client};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::protocol::{read_lp, write_lp, Request, Res, Response};
use crate::tls::{self, Keypair};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Clone, Default, Debug)]
pub struct Options {
    pub addr: Option<SocketAddr>,
}

/// Setup a QUIC connection to the provided server address
async fn setup(server_addr: SocketAddr) -> Result<(Client, Connection)> {
    let keypair = Keypair::generate();

    let client_config = tls::make_client_config(&keypair, None)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    debug!("client: connecting to {}", server_addr);
    let connect = Connect::new(server_addr).with_server_name("localhost");
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

pub async fn run<D: AsyncWrite + Unpin>(
    hash: bao::Hash,
    opts: Options,
    mut dest: D,
) -> Result<Stats> {
    let server_addr = opts
        .addr
        .unwrap_or_else(|| "127.0.0.1:4433".parse().unwrap());
    let (_client, mut connection) = setup(server_addr).await?;

    let now = Instant::now();

    let stream = connection.open_bidirectional_stream().await?;
    let (mut reader, mut writer) = stream.split();

    let req = Request {
        id: 1,
        name: hash.into(),
    };

    let mut out_buffer = BytesMut::zeroed(15 + req.name.len());
    let used = postcard::to_slice(&req, &mut out_buffer)?;

    write_lp(&mut writer, used).await?;

    // read response
    {
        let mut in_buffer = BytesMut::with_capacity(1024);

        // read next message
        match read_lp::<_, Response>(&mut reader, &mut in_buffer).await? {
            Some((response, response_size)) => match response.data {
                Res::Found { size, outboard } => {
                    // Need to read the message now
                    ensure!(
                        size <= MAX_DATA_SIZE,
                        "size too large: {} > {}",
                        size,
                        MAX_DATA_SIZE
                    );

                    let outboard = outboard.to_vec();
                    // TODO: avoid buffering

                    // remove response buffered data
                    let _ = in_buffer.split_to(response_size);
                    while in_buffer.len() < size {
                        reader.read_buf(&mut in_buffer).await?;
                    }

                    debug!("client: received data: {}bytes", in_buffer.len());
                    ensure!(
                        size == in_buffer.len(),
                        "expected {} bytes, got {} bytes",
                        size,
                        in_buffer.len()
                    );

                    let mut decoder = bao::decode::Decoder::new_outboard(
                        std::io::Cursor::new(&in_buffer[..]),
                        &*outboard,
                        &hash,
                    );

                    {
                        let mut buf = [0u8; 1024];
                        loop {
                            // TODO: avoid blocking
                            let read = decoder.read(&mut buf)?;
                            if read == 0 {
                                break;
                            }
                            dest.write_all(&buf[..read]).await?;
                        }
                    }

                    // Shut down the stream
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

                    Ok(stats)
                }
                Res::NotFound => {
                    bail!("data not found");
                }
            },
            None => {
                bail!("server disconnected");
            }
        }
    }
}
