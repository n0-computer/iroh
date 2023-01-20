use std::net::SocketAddr;
use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::{Bytes, BytesMut};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server as QuicServer;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

use crate::protocol::{read_lp, write_lp, Handshake, Request, Res, Response, VERSION};
use crate::tls::{self, Keypair, PeerId};

#[derive(Clone, Debug)]
pub struct Options {
    /// Address to listen on.
    pub addr: SocketAddr,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            addr: "127.0.0.1:4433".parse().unwrap(),
        }
    }
}

const MAX_CLIENTS: u64 = 1024;
const MAX_STREAMS: u64 = 10;

pub type Database = Arc<HashMap<bao::Hash, Data>>;

pub struct Server {
    keypair: Keypair,
    db: Database,
}

impl Server {
    pub fn new(db: Database) -> Self {
        let keypair = Keypair::generate();
        Server { keypair, db }
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().into()
    }

    pub async fn run(&mut self, opts: Options) -> Result<()> {
        let server_config = tls::make_server_config(&self.keypair)?;
        let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
        let limits = s2n_quic::provider::limits::Limits::default()
            .with_max_active_connection_ids(MAX_CLIENTS)?
            .with_max_open_local_bidirectional_streams(MAX_STREAMS)?
            .with_max_open_remote_bidirectional_streams(MAX_STREAMS)?;

        let mut server = QuicServer::builder()
            .with_tls(tls)?
            .with_io(opts.addr)?
            .with_limits(limits)?
            .start()
            .map_err(|e| anyhow!("{:?}", e))?;

        debug!("\nlistening at: {:#?}", server.local_addr().unwrap());

        while let Some(mut connection) = server.accept().await {
            let db = self.db.clone();
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
}

async fn handle_stream(
    db: Arc<HashMap<bao::Hash, Data>>,
    stream: BidirectionalStream,
) -> Result<()> {
    debug!("stream opened from {:?}", stream.connection().remote_addr());
    let (mut reader, mut writer) = stream.split();
    let mut out_buffer = BytesMut::with_capacity(1024);
    let mut in_buffer = BytesMut::with_capacity(1024);

    // 1. Read Handshake
    debug!("reading handshake");
    if let Some((handshake, size)) = read_lp::<_, Handshake>(&mut reader, &mut in_buffer).await? {
        ensure!(
            handshake.version == VERSION,
            "expected version {} but got {}",
            VERSION,
            handshake.version
        );
        let _ = in_buffer.split_to(size);
    } else {
        bail!("no valid handshake received");
    }

    // 2. Decode protocol messages.
    loop {
        debug!("reading request");
        match read_lp::<_, Request>(&mut reader, &mut in_buffer).await? {
            Some((request, _size)) => {
                let name = bao::Hash::from(request.name);
                debug!("got request({}): {}", request.id, name.to_hex());

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
        in_buffer.clear();
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
