//! An example that runs an iroh node that can be controlled via RPC.
//!
//! Run this example with
//!   $ cargo run --example rpc
//! Then in another terminal, run any of the normal iroh CLI commands, which you can run from
//! cargo as well:
//!   $ cargo run node stats
//! The `node stats` command will reach out over RPC to the node constructed in the example
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use bao_tree::{ChunkNum, ChunkRanges, ByteNum};
use iroh_bytes::get::fsm::{BlobContentNext, EndBlobNext};
use iroh_bytes::hashseq::HashSeq;
use iroh_bytes::protocol::RangeSpecSeq;
use iroh_bytes::util::Hash;

const TRACKER_ALPN: &[u8] = b"n0/tracker/1";

/// Announce kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnnounceKind {
    /// The peer supposedly has the complete data.
    Complete,
    /// The peer supposedly has some of the data.
    Partial,
}

/// Announce that a peer claims to have some blobs or set of blobs.
///
/// A peer can announce having some data, but it should also be able to announce
/// that another peer has the data. This is why the peer is included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    /// The peer that supposedly has the data.
    peer: PeerAddr,
    /// The blobs or sets that the peer claims to have.
    content: BTreeSet<HashAndFormat>,
    /// The mode of the announcement.
    kind: AnnounceKind,
}

///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFlags {
    /// Only return peers that supposedly have the complete data.
    ///
    /// If this is false, the response might contain peers that only have some of the data.
    complete: bool,

    /// Only return peers that have been validated.
    ///
    /// In case of a partial query, validation just means a check that the peer exists
    /// and returns the size for the data.
    ///
    /// In case of a complete query, validation means that the peer has been randomly
    /// probed for the data.
    validated: bool,
}

/// Query a peer for a blob or set of blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// The content we want to find.
    ///
    /// It's a difference if a peer has a blob or a hash seq and all of its children.
    content: HashAndFormat,
    /// The mode of the query.
    flags: QueryFlags,
    /// The regions we are interested in. Empty means all regions.
    regions: BTreeSet<u16>,
}

/// A response to a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// The content that was queried.
    content: HashAndFormat,
    /// The peers that supposedly have the content.
    ///
    /// If there are any addrs, they are as seen from the tracker,
    /// so they might or might not be useful.
    peers: Vec<PeerAddr>,
}

/// A request to the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Request {
    /// Announce info
    Announce(Announce),
    /// Query info
    Query(Query),
}

/// A response from the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Response {
    /// Response to a query
    QueryResponse(QueryResponse),
}

use clap::{Parser, Subcommand};
use derive_more::Display;
use iroh::dial::Ticket;
use iroh_bytes::util::HashAndFormat;
use iroh_net::key::{PublicKey, SecretKey};
use iroh_net::{AddrInfo, PeerAddr, MagicEndpoint};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{prelude::*, EnvFilter};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Server(ServerArgs),
    Announce(AnnounceArgs),
    Query(QueryArgs),
}

#[derive(Parser, Debug)]
struct ServerArgs {
    /// The port to listen on.
    #[clap(long, default_value_t = 0xacacu16)]
    port: u16,
}

#[derive(Parser, Debug)]
struct AnnounceArgs {
    #[clap(long)]
    host: PeerAddrTicket,
    #[clap(long)]
    ticket: Ticket,
    #[clap(long, default_value_t = true)]
    complete: bool,
}

#[derive(Parser, Debug)]
struct QueryArgs {
    #[clap(long)]
    host: PeerAddrTicket,

    #[clap(long)]
    hash: iroh_bytes::Hash,

    #[clap(long, default_value_t = true)]
    complete: bool,

    #[clap(long, default_value_t = false)]
    validated: bool,

    #[clap(long)]
    regions: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct PeerAddrTicket(PeerAddr);

impl Display for PeerAddrTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = postcard::to_stdvec(&self.0).unwrap();
        let mut text = data_encoding::BASE32_NOPAD.encode(&bytes);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

impl FromStr for PeerAddrTicket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let peer = postcard::from_bytes(&bytes)?;
        Ok(Self(peer))
    }
}

#[derive(Debug, Clone, Default)]
struct Db(Arc<DbInner>);

#[derive(Debug, Default)]
struct DbInner {
    state: RwLock<DbState>,
    options: Options,
}

#[derive(Debug, Clone, Default)]
struct DbState {
    // key of the inner map is the bytes of the public key
    peer_info: BTreeMap<HashAndFormat, BTreeMap<[u8; 32], PeerInfo>>,
    // cache for verified sizes of hashes, used during probing
    sizes: BTreeMap<Hash, u64>,
    // cache for collections, used during collection probing
    collections: BTreeMap<Hash, HashSeq>,
}

#[derive(Debug, Clone, Default)]
struct PeerInfo {
    /// The addresses of the peer.
    addr_info: BTreeMap<Instant, AddrInfo>,
    /// The last time the peer was announced by itself or another peer.
    last_announced: Option<Instant>,
    /// Somebody claims that the peer has the complete data.
    complete: bool,
    /// last time the peer was asked for the data and answered.
    last_size_probed: Option<Instant>,
    /// last time the peer was randomly probed for the data and answered.
    last_probed: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct Options {
    announce_timeout: Duration,
    probe_timeout: Duration,
    size_probe_timeout: Duration,
    probe_interval: Duration,
    size_probe_interval: Duration,
    addr_expiration: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            announce_timeout: Duration::from_secs(60 * 60 * 24),
            probe_timeout: Duration::from_secs(60 * 60 * 24),
            size_probe_timeout: Duration::from_secs(60 * 60 * 24),
            probe_interval: Duration::from_secs(60 * 5),
            size_probe_interval: Duration::from_secs(60 * 5),
            addr_expiration: Duration::from_secs(60 * 60 * 24),
        }
    }
}

const REQUEST_SIZE_LIMIT: usize = 1024 * 16;

async fn unverified_size(connection: &quinn::Connection, hash: &Hash) -> anyhow::Result<u64> {
    let request = iroh_bytes::protocol::GetRequest::new(*hash, RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX) ..)])).into();
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        anyhow::bail!("expected start root");
    };
    let header = start.next();
    let (_curr, size) = header.next().await?;
    // todo: finish connection
    Ok(size)
}

async fn verified_size(connection: &quinn::Connection, hash: &Hash) -> anyhow::Result<u64> {
    let request = iroh_bytes::protocol::GetRequest::new(*hash, RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX) ..)])).into();
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        anyhow::bail!("expected start root");
    };
    let header = start.next();
    let (mut curr, size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            BlobContentNext::More((next, res)) => {
                let _ = res?;
                curr = next;
            }
            BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let EndBlobNext::Closing(closing) = end.next() else {
        anyhow::bail!("expected closing");
    };
    let _stats = closing.next().await?;
    Ok(size)
}

async fn chunk_probe(connection: &quinn::Connection, hash: &Hash, chunk: ChunkNum) -> anyhow::Result<bool> {
    let request = iroh_bytes::protocol::GetRequest::new(*hash, RangeSpecSeq::from_ranges(vec![ChunkRanges::from(chunk .. chunk + 1)])).into();
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        anyhow::bail!("expected start root");
    };
    let header = start.next();
    let (mut curr, _size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            BlobContentNext::More((next, res)) => {
                if let Err(_cause) = res {
                    return Ok(false);
                }
                curr = next;
            }
            BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let EndBlobNext::Closing(closing) = end.next() else {
        anyhow::bail!("expected closing");
    };
    let _stats = closing.next().await?;
    Ok(true)
}

async fn probe(endpoint: MagicEndpoint, db: Db, content: HashAndFormat, peer: [u8; 32], info: &AddrInfo) -> anyhow::Result<bool> {
    let peer_addr = PeerAddr {
        peer_id: PublicKey::from_bytes(&peer).unwrap(),
        info: info.clone(),
    };
    let state = &db.0.state;
    let conn = endpoint.connect(peer_addr, &iroh_bytes::protocol::ALPN).await?;
    let HashAndFormat(hash, format) = content;
    match format {
        iroh_bytes::util::BlobFormat::RAW => {
            let size = match state.read().unwrap().sizes.get(&hash).copied() {
                Some(size) => size,
                None => {
                    let size = verified_size(&conn, &hash).await?;
                    state.write().unwrap().sizes.insert(content.0, size);
                    size
                }
            };
            let mut rng = rand::thread_rng();
            let random_chunk = rng.gen_range(0..ByteNum(size).chunks().0);
            let probe = chunk_probe(&conn, &hash, ChunkNum(random_chunk)).await?;
            Ok(probe)
        }
        iroh_bytes::util::BlobFormat::HASHSEQ => {
            todo!()
        }
        _ => {
            Ok(false)
        }
    }
}

async fn handle_connecting(db: Db, connecting: quinn::Connecting) -> anyhow::Result<()> {
    let connection = connecting.await?;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let request = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    let request = postcard::from_bytes::<Request>(&request)?;
    match request {
        Request::Announce(announce) => {
            println!("got announce: {:?}", announce);
            handle_announce(db, announce).await;
            send.finish().await?;
        }

        Request::Query(query) => {
            let response = handle_query(db, query).await?;
            let response = Response::QueryResponse(response);
            let response = postcard::to_stdvec(&response)?;
            send.write_all(&response).await?;
            send.finish().await?;
        }
    }
    Ok(())
}

async fn handle_announce(db: Db, announce: Announce) {
    let mut state = db.0.state.write().unwrap();
    let peer = announce.peer;
    for content in announce.content {
        let entry = state.peer_info.entry(content).or_default();
        let peer_info = entry.entry(*peer.peer_id.as_bytes()).or_default();
        let now = Instant::now();
        peer_info.last_announced = Some(now);
        if !peer.info.is_empty() {
            // store the addrinfo if it's not empty
            peer_info.addr_info.insert(now, peer.info.clone());
        }
        peer_info.complete = announce.kind == AnnounceKind::Complete;
    }
}

async fn handle_query(db: Db, query: Query) -> anyhow::Result<QueryResponse> {
    let state = db.0.state.read().unwrap();
    let entry = state.peer_info.get(&query.content);
    let options = &db.0.options;
    let mut peers = vec![];
    if let Some(entry) = entry {
        for (peer_id, peer_info) in entry {
            let recently_announced = peer_info
                .last_announced
                .map(|t| t.elapsed() <= options.announce_timeout)
                .unwrap_or_default();
            let recently_probed = peer_info
                .last_probed
                .map(|t| t.elapsed() <= options.probe_timeout)
                .unwrap_or_default();
            let recently_size_probed = peer_info
                .last_size_probed
                .map(|t| t.elapsed() <= options.size_probe_timeout)
                .unwrap_or_default();
            if query.flags.complete && !peer_info.complete {
                // query asks for complete peers, but the peer is not complete
                continue;
            }
            if !recently_announced {
                // info is too old
                continue;
            }
            if query.flags.validated && !recently_size_probed {
                // query asks for validated peers, but the size probe is too old
                continue;
            }
            if query.flags.complete && query.flags.validated && !recently_probed {
                // query asks for validated complete peers, but the probe is too old
                continue;
            }
            let info = peer_info
                .addr_info
                .iter()
                .filter(|(t, i)| {
                    let recent_addr = t.elapsed() <= options.addr_expiration;
                    let right_derp_region = if query.regions.is_empty() {
                        true
                    } else if let Some(region) = i.derp_region {
                        query.regions.contains(&region)
                    } else {
                        true
                    };
                    recent_addr && right_derp_region
                })
                .map(|(_, i)| i)
                .last()
                .cloned()
                .unwrap_or_default();
            peers.push(PeerAddr {
                peer_id: PublicKey::from_bytes(peer_id).unwrap(),
                info,
            });
        }
    }
    Ok(QueryResponse {
        content: query.content,
        peers,
    })
}

async fn server(args: ServerArgs) -> anyhow::Result<()> {
    let key = SecretKey::generate();
    let db = Db::default();
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(args.port)
        .await?;
    let ep = endpoint.local_endpoints().await?;
    let addr = endpoint.my_addr().await?;
    println!("listening on {:?}", addr);
    println!("peer addr: {}", PeerAddrTicket(addr));
    while let Some(connecting) = endpoint.accept().await {
        println!("got connecting");
        if let Err(cause) = handle_connecting(db.clone(), connecting).await {
            tracing::error!("error handling connection: {}", cause);
        }
    }
    Ok(())
}

async fn announce(args: AnnounceArgs) -> anyhow::Result<()> {
    let key = SecretKey::generate();
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(0)
        .await?;
    let peer_addr = args.host.0;
    println!("trying to connect to {:?}", peer_addr);
    let connection = endpoint.connect(peer_addr, &TRACKER_ALPN).await?;
    println!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("opened bi stream");
    let kind = if args.complete {
        AnnounceKind::Complete
    } else {
        AnnounceKind::Partial
    };
    let mut content = BTreeSet::new();
    content.insert(HashAndFormat(args.ticket.hash(), args.ticket.format()));
    let announce = Announce {
        peer: args.ticket.node_addr().clone(),
        kind,
        content,
    };
    let request = Request::Announce(announce);
    let request = postcard::to_stdvec(&request)?;
    println!("sending announce");
    send.write_all(&request).await?;
    send.finish().await?;
    let _response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    Ok(())
}

async fn query(args: QueryArgs) -> anyhow::Result<()> {
    let key = SecretKey::generate();
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(0)
        .await?;
    let query = Query {
        content: HashAndFormat(args.hash, iroh_bytes::util::BlobFormat::RAW),
        flags: QueryFlags {
            complete: args.complete,
            validated: args.validated,
        },
        regions: args.regions.into_iter().collect(),
    };
    let peer_addr = args.host.0;
    println!("trying to connect to tracker at {:?}", peer_addr);
    let connection = endpoint.connect(peer_addr, &TRACKER_ALPN).await?;
    println!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("opened bi stream");
    let request = Request::Query(query);
    let request = postcard::to_stdvec(&request)?;
    println!("sending query");
    send.write_all(&request).await?;
    send.finish().await?;
    let response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    let response = postcard::from_bytes::<Response>(&response)?;
    match response {
        Response::QueryResponse(response) => {
            println!("got response: {:?}", response);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let args = Args::parse();
    match args.command {
        Commands::Server(args) => server(args).await,
        Commands::Announce(args) => announce(args).await,
        Commands::Query(args) => query(args).await,
    }
}
