use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{anyhow, ensure, Result};
use bytes::{Bytes, BytesMut};
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{write_lp, Request, Res, Response};

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub port: Option<u16>,
}

pub async fn run(db: Arc<HashMap<bao::Hash, Data>>, opts: Options) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let server_config = libp2p_tls::make_server_config(&keypair)?;
    let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
    let limits = s2n_quic::provider::limits::Default::default();
    let port = if let Some(port) = opts.port {
        port
    } else {
        4433
    };
    let addr = format!("127.0.0.1:{port}");
    let mut server = Server::builder()
        .with_tls(tls)?
        .with_io(addr.as_str())?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    println!("\nlistening at: {:#?}", server.local_addr().unwrap());

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
pub struct Data {
    /// outboard data from bo
    outboard: Bytes,
    /// actual data
    data: Bytes,
}

pub async fn create_db(paths: Vec<&Path>) -> Result<Arc<HashMap<bao::Hash, Data>>> {
    println!("Available Data:");

    let mut db = HashMap::new();
    for path in paths {
        ensure!(path.is_file(), "can only transfer blob data");
        let data = tokio::fs::read(path).await?;
        let num = data.len();
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

    Ok(Arc::new(db))
}
