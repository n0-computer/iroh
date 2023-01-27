use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server as QuicServer;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, warn};

use crate::blobs::{Blob, Collection};
use crate::protocol::{read_lp, write_lp, AuthToken, Handshake, Request, Res, Response, VERSION};
use crate::tls::{self, Keypair, PeerId};

const MAX_CONNECTIONS: u64 = 1024;
const MAX_STREAMS: u64 = 10;

pub type Database = Arc<HashMap<bao::Hash, BlobOrCollection>>;

/// Builder for the [`Provider`].
///
/// You must supply a database which can be created using [`create_db`], everything else is
/// optional.  Finally you can create and run the provider by calling [`Builder::spawn`].
///
/// The returned [`Provider`] provides [`Provider::join`] to wait for the spawned task.
/// Currently it needs to be aborted using [`Provider::abort`], graceful shutdown will come.
#[derive(Debug)]
pub struct Builder {
    bind_addr: SocketAddr,
    keypair: Keypair,
    auth_token: AuthToken,
    db: Database,
}

#[derive(Debug)]
pub enum BlobOrCollection {
    Blob(Data),
    Collection((Bytes, Bytes)),
}

impl Builder {
    /// Creates a new builder for [`Provider`] using the given [`Database`].
    pub fn with_db(db: Database) -> Self {
        Self {
            bind_addr: "127.0.0.1:4433".parse().unwrap(),
            keypair: Keypair::generate(),
            auth_token: AuthToken::generate(),
            db,
        }
    }

    /// Binds the provider service to a different socket.
    ///
    /// By default it binds to `127.0.0.1:4433`.
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Uses the given [`Keypair`] for the [`PeerId`] instead of a newly generated one.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }

    /// Uses the given [`AuthToken`] instead of a newly generated one.
    pub fn auth_token(mut self, auth_token: AuthToken) -> Self {
        self.auth_token = auth_token;
        self
    }

    /// Spawns the [`Provider`] in a tokio task.
    ///
    /// This will create the underlying network server and spawn a tokio task accepting
    /// connections.  The returned [`Provider`] can be used to control the task as well as
    /// get information about it.
    pub fn spawn(self) -> Result<Provider> {
        let server_config = tls::make_server_config(&self.keypair)?;
        let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
        let limits = s2n_quic::provider::limits::Limits::default()
            .with_max_active_connection_ids(MAX_CONNECTIONS)?
            .with_max_open_local_bidirectional_streams(MAX_STREAMS)?
            .with_max_open_remote_bidirectional_streams(MAX_STREAMS)?;

        let server = QuicServer::builder()
            .with_tls(tls)?
            .with_io(self.bind_addr)?
            .with_limits(limits)?
            .start()
            .map_err(|e| anyhow!("{:?}", e))?;
        let listen_addr = server.local_addr().unwrap();
        let db2 = self.db.clone();
        let task = tokio::spawn(async move { Self::run(server, db2, self.auth_token).await });

        Ok(Provider {
            listen_addr,
            keypair: self.keypair,
            auth_token: self.auth_token,
            task,
        })
    }

    async fn run(mut server: s2n_quic::server::Server, db: Database, token: AuthToken) {
        debug!("\nlistening at: {:#?}", server.local_addr().unwrap());
        while let Some(mut connection) = server.accept().await {
            let db = db.clone();
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
    }
}

/// A server which implements the sendme provider.
///
/// Clients can connect to this server and requests hashes from it.
///
/// The only way to create this is by using the [`Builder::spawn`].  [`Provider::builder`]
/// is a shorthand to create a suitable [`Builder`].
///
/// This runs a tokio task which can be aborted and joined if desired.
pub struct Provider {
    listen_addr: SocketAddr,
    keypair: Keypair,
    auth_token: AuthToken,
    task: JoinHandle<()>,
}

impl Provider {
    /// Returns a new builder for the [`Provider`].
    ///
    /// Once the done with the builder call [`Builder::spawn`] to create the provider.
    pub fn builder(db: Database) -> Builder {
        Builder::with_db(db)
    }

    /// Returns the address on which the server is listening for connections.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Returns the [`PeerId`] of the provider.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().into()
    }

    /// Returns the [`AuthToken`] needed to connect to the provider.
    pub fn auth_token(&self) -> AuthToken {
        self.auth_token
    }

    /// Blocks until the provider task completes.
    // TODO: Maybe implement Future directly?
    pub async fn join(self) -> Result<(), JoinError> {
        self.task.await
    }

    /// Aborts the provider.
    ///
    /// TODO: temporary, do graceful shutdown instead.
    pub fn abort(&self) {
        self.task.abort();
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

/// Synchronously compute the outboard of a file, and return hash and outboard.
///
/// It is assumed that the file is not modified while this is running.
///
/// If it is modified while or after this is running, the outboard will be
/// invalid, so any attempt to compute a slice from it will fail.
///
/// If the size of the file is changed while this is running, an error will be
/// returned.
fn compute_outboard(path: PathBuf) -> anyhow::Result<(blake3::Hash, Vec<u8>)> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    // compute outboard size so we can pre-allocate the buffer.
    //
    // outboard is ~1/16 of data size, so this will fail for really large files
    // on really small devices. E.g. you want to transfer a 1TB file from a pi4 with 1gb ram.
    //
    // The way to solve this would be to have larger blocks than the blake3 chunk size of 1024.
    // I think we really want to keep the outboard in memory for simplicity.
    let outboard_size = usize::try_from(bao::encode::outboard_size(len))
        .context("outboard too large to fit in memory")?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // copy the file into the encoder. Data will be skipped by the encoder in outboard mode.
    let outboard_cursor = std::io::Cursor::new(&mut outboard);
    let mut encoder = bao::encode::Encoder::new_outboard(outboard_cursor);

    let mut reader = BufReader::new(file);
    // the length we have actually written, should be the same as the length of the file.
    let len2 = std::io::copy(&mut reader, &mut encoder)?;
    // this can fail if the file was appended to during encoding.
    ensure!(len == len2, "file changed during encoding");
    // this flips the outboard encoding from post-order to pre-order
    let hash = encoder.finalize()?;
    anyhow::Ok((hash, outboard))
}

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_db(data_sources: Vec<DataSource>) -> Result<(Database, bao::Hash)> {
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
                // spawn a blocking task for computing the hash and outboard.
                // pretty sure this is best to remain sync even once bao is async.
                let path2 = path.clone();
                let (hash, outboard) =
                    tokio::task::spawn_blocking(move || compute_outboard(path2)).await??;

                debug_assert!(outboard.len() >= 8, "outboard must at least contain size");
                let size = u64::from_le_bytes(outboard[..8].try_into().unwrap());
                db.insert(
                    hash,
                    BlobOrCollection::Blob(Data {
                        outboard: Bytes::from(outboard),
                        path: path.clone(),
                        size,
                    }),
                );
                total_blobs_size += size;
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
    println!("Collection: {}\n", hash.to_hex());
    for el in db.values() {
        if let BlobOrCollection::Blob(blob) = el {
            println!("- {}: {} bytes", blob.path.display(), blob.size);
        }
    }
    println!();
    db.insert(
        hash,
        BlobOrCollection::Collection((Bytes::from(outboard), Bytes::from(data.to_vec()))),
    );

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
