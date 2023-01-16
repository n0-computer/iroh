use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{anyhow, ensure, Result};
use bytes::{Bytes, BytesMut};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

use crate::protocol::{read_lp, write_lp, Request, Res, Response};
use crate::tls::{self, Keypair};

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub port: Option<u16>,
}

pub async fn run(db: Arc<HashMap<bao::Hash, Data>>, opts: Options) -> Result<()> {
    let keypair = Keypair::generate();
    let server_config = tls::make_server_config(&keypair)?;
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

    debug!("\nlistening at: {:#?}", server.local_addr().unwrap());

    while let Some(mut connection) = server.accept().await {
        let db = db.clone();
        tokio::spawn(async move {
            debug!("connection accepted from {:?}", connection.remote_addr());

            while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                let db = db.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_stream(db, stream).await {
                        error!("error: {:#?}", err);
                    }
                    debug!("disconnected");
                });
            }
        });
    }

    Ok(())
}

async fn handle_stream(
    db: Arc<HashMap<bao::Hash, Data>>,
    stream: BidirectionalStream,
) -> Result<()> {
    debug!("stream opened from {:?}", stream.connection().remote_addr());
    let (mut reader, mut writer) = stream.split();
    let mut out_buffer = BytesMut::with_capacity(1024);
    let mut in_buffer = BytesMut::with_capacity(1024);

    // decode next message
    loop {
        in_buffer.clear();
        match read_lp::<_, Request>(&mut reader, &mut in_buffer).await? {
            Some((request, _size)) => {
                let name = bao::Hash::from(request.name);
                let (data, piece) = if let Some(data) = db.get(&name) {
                    debug!("found {}", name.to_hex());
                    (
                        Res::Found {
                            size: data.data.len(),
                            outboard: &data.outboard,
                        },
                        Some(data.clone()),
                    )
                } else {
                    debug!("not found {}", name.to_hex());
                    (Res::NotFound, None)
                };

                let response = Response {
                    id: request.id,
                    data,
                };

                if out_buffer.len() < 20 + response.data.len() {
                    out_buffer.resize(20 + response.data.len(), 0u8);
                }
                let used = postcard::to_slice(&response, &mut out_buffer)?;

                write_lp(&mut writer, used).await?;

                debug!("written response of length {}", used.len());

                if let Some(piece) = piece {
                    debug!("writing data {}", piece.data.len());
                    // if we found the data, write it out now
                    writer.write_all(&piece.data).await?;
                    debug!("done writing data");
                }
            }
            None => {
                break;
            }
        }
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

        println!("- {}: {}bytes", hash.to_hex(), num);
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
