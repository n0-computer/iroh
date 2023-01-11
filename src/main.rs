use std::{collections::HashMap, env, io::Read, net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use bytes::{Bytes, BytesMut};
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::{client::Connect, Client, Server};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Request {
    id: u64,
    /// blake3 hash
    name: [u8; 32],
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Response<'a> {
    id: u64,
    #[serde(borrow)]
    data: Res<'a>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
enum Res<'a> {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found {
        /// The size of the coming data in bytes, raw content size.
        size: usize,
        outboard: &'a [u8],
    },
}

impl Res<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Found { outboard, .. } => outboard.len(),
            _ => 0,
        }
    }
}

async fn main_client(hash: bao::Hash) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let client_config = libp2p_tls::make_client_config(&keypair, None)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    connection.keep_alive(true)?;

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
        let mut in_buffer = BytesMut::zeroed(1024);

        // read length prefix
        let size = unsigned_varint::aio::read_u64(&mut reader).await.unwrap();

        // read next message
        in_buffer.clear();
        while (in_buffer.len() as u64) < size {
            reader.read_buf(&mut in_buffer).await?;
        }
        let response_size = usize::try_from(size).unwrap();
        let response: Response = postcard::from_bytes(&in_buffer[..response_size])?;
        println!("read response of size {}", response_size);
        match response.data {
            Res::Found { size, outboard } => {
                // Need to read the message now
                if size > MAX_DATA_SIZE {
                    bail!("size too large: {} > {}", size, MAX_DATA_SIZE);
                }

                let outboard = outboard.to_vec();

                let pb = indicatif::ProgressBar::new(size as u64);
                let mut wrapped_reader = pb.wrap_async_read(reader);

                // TODO: avoid buffering

                // remove response buffered data
                let _ = in_buffer.split_to(response_size);
                while in_buffer.len() < size {
                    wrapped_reader.read_buf(&mut in_buffer).await?;
                }

                println!("received data {} bytes", in_buffer.len());
                assert_eq!(
                    size,
                    in_buffer.len(),
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
                    // Ignore the output, not needed
                    let mut buf = [0u8; 1024];
                    while decoder.read(&mut buf)? > 0 {}
                }

                // print stats
                let data_len = size;
                let elapsed = now.elapsed().as_millis();
                let elapsed_s = elapsed as f64 / 1000.;
                let data_len_bit = data_len * 8;
                let mbits = data_len_bit as f64 / (1000. * 1000.) / elapsed_s;
                pb.println(format!(
                    "Data size: {}MiB\nTime Elapsed: {:.4}s\n{:.2}MBit/s",
                    data_len / 1024 / 1024,
                    elapsed_s,
                    mbits
                ));
            }
            Res::NotFound => {
                bail!("data not found");
            }
        }
    }

    Ok(())
}

async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    // send length prefix
    let mut buffer = [0u8; 10];
    let lp = unsigned_varint::encode::u64(data.len() as u64, &mut buffer);
    writer.write_all(lp).await?;

    // write message
    writer.write_all(data).await?;
    Ok(())
}

async fn main_server(db: Arc<HashMap<bao::Hash, Data>>) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let server_config = libp2p_tls::make_server_config(&keypair)?;
    let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
    let limits = s2n_quic::provider::limits::Default::default();
    let mut server = Server::builder()
        .with_tls(tls)?
        .with_io("127.0.0.1:4433")?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    while let Some(mut connection) = server.accept().await {
        let db = db.clone();
        tokio::spawn(async move {
            println!("Connection accepted from {:?}", connection.remote_addr());

            while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                let db = db.clone();
                tokio::spawn(async move {
                    println!("Stream opened from {:?}", stream.connection().remote_addr());
                    let (mut reader, mut writer) = stream.split();
                    let mut out_buffer = BytesMut::zeroed(1024);
                    let mut in_buffer = BytesMut::zeroed(1024);

                    // read length prefix
                    while let Ok(size) = unsigned_varint::aio::read_u64(&mut reader).await {
                        // read next message
                        in_buffer.clear();
                        while (in_buffer.len() as u64) < size {
                            reader.read_buf(&mut in_buffer).await.unwrap();
                        }
                        let size = usize::try_from(size).unwrap();

                        // decode next message
                        let request: Request = postcard::from_bytes(&in_buffer[..size]).unwrap();
                        let name = bao::Hash::from(request.name);
                        let (data, piece) = if let Some(data) = db.get(&name) {
                            (
                                Res::Found {
                                    size: data.data.len(),
                                    outboard: &data.outboard,
                                },
                                Some(data.clone()),
                            )
                        } else {
                            (Res::NotFound, None)
                        };

                        let response = Response {
                            id: request.id,
                            data,
                        };

                        if out_buffer.len() < 20 + response.data.len() {
                            out_buffer.resize(20 + response.data.len(), 0u8);
                        }
                        let used = postcard::to_slice(&response, &mut out_buffer).unwrap();

                        if let Err(e) = write_lp(&mut writer, used).await {
                            eprintln!("failed to write response: {:?}", e);
                        }

                        println!("written response of length {}", used.len());

                        if let Some(piece) = piece {
                            println!("writing data {}", piece.data.len());
                            // if we found the data, write it out now
                            if let Err(err) = writer.write_all(&piece.data).await {
                                eprintln!("failed to write data: {:?}", err);
                            }
                            println!("done writing data");
                        }
                    }

                    println!("Disconnected");
                });
            }
        });
    }

    Ok(())
}

#[derive(Clone)]
struct Data {
    /// outboard data from bo
    outboard: Bytes,
    /// actual data
    data: Bytes,
}

fn create_db(range: Vec<usize>) -> Arc<HashMap<bao::Hash, Data>> {
    println!("Available Data:");

    let mut db = HashMap::new();
    for num in range {
        let data = vec![1u8; 1024 * 1024 * num];
        let (outboard, hash) = bao::encode::outboard(&data);

        println!("- {}: {}MiB", hash.to_hex(), num);
        db.insert(
            hash,
            Data {
                outboard: Bytes::from(outboard),
                data: Bytes::from(data),
            },
        );
    }

    Arc::new(db)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("invalid arguments");
    }

    match args[1].as_str() {
        "client" => {
            let hash = &args[2];
            let hash = bao::Hash::from_hex(hash)?;
            println!("Requesting: {}", hash.to_hex());
            main_client(hash).await?
        }
        "server" => {
            let db = create_db(vec![1, 10, 100]);
            main_server(db).await?
        }
        _ => bail!("unknown argument: {}", &args[0]),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn basics() {
        let db = create_db(vec![1]);
        let hash = *db.iter().next().unwrap().0;
        tokio::task::spawn(async move {
            main_server(db).await.unwrap();
        });

        main_client(hash).await.unwrap();
    }
}
