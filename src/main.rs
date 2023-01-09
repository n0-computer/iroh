use std::{collections::HashMap, env, io::Read, net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use bytes::{Bytes, BytesMut};
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::{client::Connect, Client, Server};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Request {
    id: u64,
    name: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Response {
    id: u64,
    data: Res,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
enum Res {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found {
        /// The size of the coming data in bytes, raw content size.
        size: usize,
    },
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
        name: hash.to_hex().to_string(),
    };
    let mut bytes = BytesMut::zeroed(15 + req.name.len());
    let used = postcard::to_slice(&req, &mut bytes)?;

    // send length prefix
    let mut buffer = [0u8; 10];
    let lp = unsigned_varint::encode::u64(used.len() as u64, &mut buffer);
    writer.write_all(lp).await?;

    // write message
    writer.write_all(used).await?;

    // read response
    {
        let mut in_buffer = BytesMut::zeroed(1024);

        // read length prefix
        let size = unsigned_varint::aio::read_u64(&mut reader).await.unwrap();

        // read next message
        in_buffer.clear();
        while (in_buffer.len() as u64) < size {
            reader.read_buf(&mut in_buffer).await.unwrap();
        }
        let size = usize::try_from(size).unwrap();
        let response: Response = postcard::from_bytes(&in_buffer[..size])?;
        match response.data {
            Res::Found { size } => {
                // Need to read the message now
                if size > MAX_DATA_SIZE {
                    bail!("size too large: {} > {}", size, MAX_DATA_SIZE);
                }

                let limit_reader = reader; // .take(size as u64);
                let bridge = tokio_util::io::SyncIoBridge::new(limit_reader);
                let (send, recv) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let mut decoder = bao::decode::Decoder::new(bridge, &hash);
                    let mut data = Vec::with_capacity(size); // TODO: do not overallocate;
                    if let Err(err) = decoder.read_to_end(&mut data) {
                        eprintln!("failed to read all data: {:?}", err);
                    } else {
                        // print stats

                        let data_len = size;
                        let elapsed = now.elapsed().as_millis();
                        let elapsed_s = elapsed as f64 / 1000.;
                        let data_len_bit = data_len * 8;
                        let mbits = data_len_bit as f64 / (1000. * 1000.) / elapsed_s;
                        println!(
                            "Data size: {}MiB\nTime Elapsed: {:.4}s\n{:.2}MBit/s",
                            data_len / 1024 / 1024,
                            elapsed_s,
                            mbits
                        );
                    }

                    send.send(()).ok();
                });

                recv.await?;
            }
            Res::NotFound => {
                bail!("data not found");
            }
        }
    }

    Ok(())
}

async fn main_server() -> Result<()> {
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

    let db = create_db();

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
                    let mut lp_buffer = [0u8; 10];

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
                        let (data, piece) = if let Some(data) = db.get(&request.name) {
                            (Res::Found { size: data.len() }, Some(data.clone()))
                        } else {
                            (Res::NotFound, None)
                        };

                        let response = Response {
                            id: request.id,
                            data,
                        };

                        let used = postcard::to_slice(&response, &mut out_buffer).unwrap();

                        let lp = unsigned_varint::encode::u64(used.len() as u64, &mut lp_buffer);
                        writer.write_all(lp).await.unwrap();

                        if let Err(e) = writer.write_all(used).await {
                            eprintln!("failed to write response: {:?}", e);
                        }
                        if let Some(piece) = piece {
                            // if we found the data, write it out now

                            // TODO: avoid buffering
                            let (encoded, _hash) =
                                tokio::task::spawn_blocking(move || bao::encode::encode(piece))
                                    .await
                                    .unwrap();

                            if let Err(e) = writer.write_all(&encoded).await {
                                eprintln!("failed to write data: {:?}", e);
                            }
                        }
                    }

                    println!("Disconnected");
                });
            }
        });
    }

    Ok(())
}

fn create_db() -> Arc<HashMap<String, Bytes>> {
    println!("Available Data:");

    let mut db = HashMap::new();
    for num in [1, 10, 100] {
        let data = vec![1u8; 1024 * 1024 * num];
        let hash = blake3::hash(&data);
        let name = format!("{}", hash.to_hex());

        println!("- {name}: {num}MiB");
        db.insert(name, Bytes::from(data));
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
        "server" => main_server().await?,
        _ => bail!("unknown argument: {}", &args[0]),
    }

    Ok(())
}
