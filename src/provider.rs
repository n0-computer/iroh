use std::net::SocketAddr;
use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::{Bytes, BytesMut};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server as QuicServer;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use crate::blobs::{Blob, Collection};
use crate::protocol::{read_lp, write_lp, AuthToken, Handshake, Request, Res, Response, VERSION};
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

const MAX_CONNECTIONS: u64 = 1024;
const MAX_STREAMS: u64 = 10;

pub type Database = Arc<HashMap<bao::Hash, BlobOrCollection>>;

#[derive(Debug)]
pub struct Provider {
    keypair: Keypair,
    auth_token: AuthToken,
    db: Database,
}

#[derive(Debug)]
pub enum BlobOrCollection {
    Blob(Data),
    Collection((Bytes, Bytes)),
}

/// Builder to configure a `Provider`.
#[derive(Debug, Default)]
pub struct ProviderBuilder {
    auth_token: Option<AuthToken>,
    keypair: Option<Keypair>,
    db: Option<Database>,
}

impl ProviderBuilder {
    /// Set the authentication token, if none is provided a new one is generated.
    pub fn auth_token(mut self, auth_token: AuthToken) -> Self {
        self.auth_token = Some(auth_token);
        self
    }

    /// Set the keypair, if none is provided a new one is generated.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set the database.
    pub fn database(mut self, db: Database) -> Self {
        self.db = Some(db);
        self
    }

    /// Consumes the builder and constructs a `Provider`.
    pub fn build(self) -> Result<Provider> {
        ensure!(self.db.is_some(), "missing database");

        Ok(Provider {
            auth_token: self.auth_token.unwrap_or_else(AuthToken::generate),
            keypair: self.keypair.unwrap_or_else(Keypair::generate),
            db: self.db.unwrap(),
        })
    }
}

impl Provider {
    /// Returns a new `ProviderBuilder`.
    pub fn builder() -> ProviderBuilder {
        ProviderBuilder::default()
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().into()
    }

    pub fn auth_token(&self) -> AuthToken {
        self.auth_token
    }

    pub async fn run(&mut self, opts: Options) -> Result<()> {
        let server_config = tls::make_server_config(&self.keypair)?;
        let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
        let limits = s2n_quic::provider::limits::Limits::default()
            .with_max_active_connection_ids(MAX_CONNECTIONS)?
            .with_max_open_local_bidirectional_streams(MAX_STREAMS)?
            .with_max_open_remote_bidirectional_streams(MAX_STREAMS)?;

        let mut server = QuicServer::builder()
            .with_tls(tls)?
            .with_io(opts.addr)?
            .with_limits(limits)?
            .start()
            .map_err(|e| anyhow!("{:?}", e))?;
        let token = self.auth_token;
        debug!("\nlistening at: {:#?}", server.local_addr().unwrap());

        while let Some(mut connection) = server.accept().await {
            let db = self.db.clone();
            tokio::spawn(async move {
                debug!("connection accepted from {:?}", connection.remote_addr());

                while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                    let db = db.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_stream(db, token, stream).await {
                            warn!("error: {:#?}", err);
                        }
                        debug!("disconnected");
                    });
                }
            });
        }

        Ok(())
    }
}

async fn handle_stream(db: Database, token: AuthToken, stream: BidirectionalStream) -> Result<()> {
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
        ensure!(handshake.token == token, "AuthToken mismatch");
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

                match db.get(&name) {
                    // We only respond to requests for collections, not individual blobs
                    Some(BlobOrCollection::Collection((outboard, data))) => {
                        debug!("found collection {}", name.to_hex());

                        let c: Collection = postcard::from_bytes(data)?;

                        // TODO: we should check if the blobs referenced in this container
                        // actually exist in this provider before returning `FoundCollection`
                        write_response(
                            &mut writer,
                            &mut out_buffer,
                            request.id,
                            Res::FoundCollection {
                                size: data.len() as u64,
                                total_blobs_size: c.total_blobs_size,
                                outboard,
                            },
                        )
                        .await?;

                        let mut data = BytesMut::from(&data[..]);
                        writer.write_buf(&mut data).await?;
                        for blob in c.blobs {
                            if SentStatus::NotFound
                                == send_blob(
                                    db.clone(),
                                    blob.hash,
                                    &mut writer,
                                    &mut out_buffer,
                                    request.id,
                                )
                                .await?
                            {
                                break;
                            }
                        }
                    }
                    _ => {
                        debug!("not found {}", name.to_hex());
                        write_response(&mut writer, &mut out_buffer, request.id, Res::NotFound)
                            .await?;
                    }
                }

                debug!("finished response");
            }
            None => {
                break;
            }
        }
        in_buffer.clear();
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SentStatus {
    Sent,
    NotFound,
}

async fn send_blob<W: AsyncWrite + Unpin>(
    db: Database,
    name: bao::Hash,
    mut writer: W,
    buffer: &mut BytesMut,
    id: u64,
) -> Result<SentStatus> {
    match db.get(&name) {
        Some(BlobOrCollection::Blob(Data {
            outboard,
            path,
            size,
        })) => {
            debug!("found {}", name.to_hex());
            write_response(
                &mut writer,
                buffer,
                id,
                Res::Found {
                    size: *size,
                    outboard,
                },
            )
            .await?;

            debug!("writing data");
            let file = tokio::fs::File::open(&path).await?;
            let mut reader = tokio::io::BufReader::new(file);
            tokio::io::copy(&mut reader, &mut writer).await?;
            Ok(SentStatus::Sent)
        }
        _ => {
            debug!("not found {}", name.to_hex());
            write_response(&mut writer, buffer, id, Res::NotFound).await?;
            Ok(SentStatus::NotFound)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// Outboard data from bao.
    outboard: Bytes,
    /// Path to the original data, which must not change while in use.
    path: PathBuf,
    /// Size of the original data.
    size: u64,
}

#[derive(Debug)]
pub enum DataSource {
    File(PathBuf),
}

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_db(data_sources: Vec<DataSource>) -> Result<(Database, bao::Hash)> {
    println!("Available Data:");

    // +1 is for the collection itself
    let mut db = HashMap::with_capacity(data_sources.len() + 1);
    let mut blobs = Vec::with_capacity(data_sources.len());
    let mut total_blobs_size: u64 = 0;

    let mut blobs_encoded_size_estimate = 0;
    for data in data_sources {
        match data {
            DataSource::File(path) => {
                ensure!(
                    path.is_file(),
                    "can only transfer blob data: {}",
                    path.display()
                );
                let data = tokio::fs::read(&path).await?;
                let (outboard, hash) = bao::encode::outboard(&data);

                println!("- {}: {} bytes", hash.to_hex(), data.len());
                db.insert(
                    hash,
                    BlobOrCollection::Blob(Data {
                        outboard: Bytes::from(outboard),
                        path: path.clone(),
                        size: data.len() as u64,
                    }),
                );
                total_blobs_size += data.len() as u64;
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                blobs_encoded_size_estimate += name.len() + 32;
                blobs.push(Blob { name, hash });
            }
        }
    }
    let c = Collection {
        name: "collection".to_string(),
        blobs,
        total_blobs_size,
    };
    blobs_encoded_size_estimate += c.name.len();

    // NOTE: we can't use the postcard::MaxSize to estimate the encoding buffer size
    // because the Collection and Blobs have `String` fields.
    // So instead, we are tracking the filename + hash sizes of each blob, plus an extra 1024
    // to account for any postcard encoding data.
    let mut buffer = BytesMut::zeroed(blobs_encoded_size_estimate + 1024);
    let data = postcard::to_slice(&c, &mut buffer)?;
    let (outboard, hash) = bao::encode::outboard(&data);
    db.insert(
        hash,
        BlobOrCollection::Collection((Bytes::from(outboard), Bytes::from(data.to_vec()))),
    );
    println!("\ncollection:\n- {}", hash.to_hex());

    Ok((Arc::new(db), hash))
}

async fn write_response<W: AsyncWrite + Unpin>(
    mut writer: W,
    buffer: &mut BytesMut,
    id: u64,
    res: Res<'_>,
) -> Result<()> {
    let response = Response { id, data: res };

    // TODO: do not transfer blob data as part of the responses
    if buffer.len() < 1024 + response.data.len() {
        buffer.resize(1024 + response.data.len(), 0u8);
    }
    let used = postcard::to_slice(&response, buffer)?;

    write_lp(&mut writer, used).await?;

    debug!("written response of length {}", used.len());
    Ok(())
}
