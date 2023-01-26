use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::{Bytes, BytesMut};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server as QuicServer;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, warn};

use crate::protocol::{read_lp, write_lp, AuthToken, Handshake, Request, Res, Response, VERSION};
use crate::tls::{self, Keypair, PeerId};

const MAX_CONNECTIONS: u64 = 1024;
const MAX_STREAMS: u64 = 10;

pub type Database = Arc<HashMap<bao::Hash, Data>>;

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

    /// Return a single token containing everything needed to get a hash.
    ///
    /// See [`Ticket`] for more details of how it can be used.
    pub fn ticket(&self, hash: bao::Hash) -> Ticket {
        // TODO: Verify that the hash exists in the db?
        Ticket {
            hash,
            peer: self.peer_id(),
            addr: self.listen_addr,
            token: self.auth_token,
        }
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

async fn handle_stream(
    db: Arc<HashMap<bao::Hash, Data>>,
    token: AuthToken,
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
                    Some(Data {
                        outboard,
                        path,
                        size,
                    }) => {
                        debug!("found {}", name.to_hex());
                        write_response(
                            &mut writer,
                            &mut out_buffer,
                            request.id,
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
                    }
                    None => {
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

#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// Outboard data from bao.
    outboard: Bytes,
    /// Path to the original data, which must not change while in use.
    path: PathBuf,
    /// Size of the original data.
    size: usize,
}

#[derive(Debug)]
pub enum DataSource {
    File(PathBuf),
}

pub async fn create_db(data_sources: Vec<DataSource>) -> Result<Arc<HashMap<bao::Hash, Data>>> {
    println!("Available Data:");

    let mut db = HashMap::new();
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

                println!("- {}: {}bytes", hash.to_hex(), data.len());
                db.insert(
                    hash,
                    Data {
                        outboard: Bytes::from(outboard),
                        path,
                        size: data.len(),
                    },
                );
            }
        }
    }

    Ok(Arc::new(db))
}

async fn write_response<W: AsyncWrite + Unpin>(
    mut writer: W,
    buffer: &mut BytesMut,
    id: u64,
    res: Res<'_>,
) -> Result<()> {
    let response = Response { id, data: res };

    if buffer.len() < 20 + response.data.len() {
        buffer.resize(20 + response.data.len(), 0u8);
    }
    let used = postcard::to_slice(&response, buffer)?;

    write_lp(&mut writer, used).await?;

    debug!("written response of length {}", used.len());
    Ok(())
}

/// A token containing everything to get a file from the provider.
///
/// This token contains various things needed for getting a file from a provider:
///
/// - The *hash* to retrieve.
/// - The *peer ID* identifying the provider.
/// - The *socket address* the provider is listening on.
/// - The *authentication token* with permission for the root hash.
///
/// It is a single item which can be easily serialised and deserialised.  The [`Display`]
/// and [`FromStr`] implementations serialise to hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    #[serde(with = "crate::protocol::serde_hash")]
    pub hash: bao::Hash,
    pub peer: PeerId,
    pub addr: SocketAddr,
    pub token: AuthToken,
}

/// Serialises to hex.
impl Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = postcard::to_stdvec(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", hex::encode(encoded))
    }
}

/// Deserialises from hex.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        let slf = postcard::from_bytes(&bytes)?;
        Ok(slf)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_ticket_hex_roundtrip() {
        let (_encoded, hash) = bao::encode::encode(b"hi there");
        let peer = PeerId::from(Keypair::generate().public());
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let token = AuthToken::generate();
        let ticket = Ticket {
            hash,
            peer,
            addr,
            token,
        };
        let hex = ticket.to_string();
        println!("Ticket: {hex}");
        println!("{} bytes", hex.len());

        let ticket2: Ticket = hex.parse().unwrap();
        assert_eq!(ticket2, ticket);
    }
}
