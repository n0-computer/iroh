//! An example that runs an iroh node that can be controlled via RPC.
//!
//! Run this example with
//!   $ cargo run --example rpc
//! Then in another terminal, run any of the normal iroh CLI commands, which you can run from
//! cargo as well:
//!   $ cargo run node stats
//! The `node stats` command will reach out over RPC to the node constructed in the example
use bao_tree::{ByteNum, ChunkNum, ChunkRanges};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::FutureExt;
use iroh::util::fs::load_secret_key;
use iroh_bytes::get::fsm::{BlobContentNext, EndBlobNext};
use iroh_bytes::hashseq::HashSeq;
use iroh_bytes::protocol::{GetRequest, RangeSpec, RangeSpecSeq};
use iroh_bytes::util::Hash;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio_util::task::LocalPoolHandle;

const TRACKER_ALPN: &[u8] = b"n0/tracker/1";

/// Interface for an ideal magic endpoint that can dial by peer.
trait DialByPeer: Clone {
    fn dial_by_peer<'a>(
        &'a self,
        peer: &PublicKey,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, anyhow::Result<quinn::Connection>>;
    fn accept(&self) -> quinn::Accept<'_>;
}

#[derive(Debug, Clone)]
struct Dialer {
    endpoint: MagicEndpoint,
}

impl DialByPeer for Dialer {
    fn dial_by_peer<'a>(
        &'a self,
        peer: &PublicKey,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, anyhow::Result<quinn::Connection>> {
        let peer_addr = PeerAddr {
            peer_id: peer.clone(),
            info: AddrInfo {
                derp_region: Some(2),
                direct_addresses: Default::default(),
            },
        };
        self.endpoint.connect(peer_addr, alpn).boxed()
    }

    fn accept(&self) -> quinn::Accept<'_> {
        self.endpoint.accept()
    }
}

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
    peer: PublicKey,
    /// The blobs or sets that the peer claims to have.
    content: BTreeSet<HashAndFormat>,
    /// The kind of the announcement.
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
    peers: Vec<PublicKey>,
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
use iroh_net::{AddrInfo, MagicEndpoint, PeerAddr};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HashAndFormat2(HashAndFormat);

impl Display for HashAndFormat2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut slice = [0u8; 64];
        hex::encode_to_slice(self.0.hash.as_bytes(), &mut slice).unwrap();
        write!(f, "{}", std::str::from_utf8(&slice).unwrap())?;
        if self.0.format.is_hash_seq() {
            write!(f, "s")?;
        }
        Ok(())
    }
}

impl FromStr for HashAndFormat2 {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.as_bytes();
        let mut hash = [0u8; 32];
        match s.len() {
            64 => {
                hex::decode_to_slice(s, &mut hash)?;
                Ok(Self(HashAndFormat::raw(hash.into())))
            }
            65 if s[64].to_ascii_lowercase() == b's' => {
                hex::decode_to_slice(s, &mut hash)?;
                Ok(Self(HashAndFormat::hash_seq(hash.into())))
            }
            _ => anyhow::bail!("invalid hash and format"),
        }
    }
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
    host: PublicKey,
    #[clap(long)]
    ticket: Ticket,
    #[clap(long, default_value_t = true)]
    complete: bool,
}

#[derive(Parser, Debug)]
struct QueryArgs {
    #[clap(long)]
    host: PublicKey,

    #[clap(long, conflicts_with = "ticket", required_unless_present = "ticket")]
    content: Option<HashAndFormat2>,

    #[clap(long)]
    ticket: Option<Ticket>,

    #[clap(long, default_value_t = true)]
    complete: bool,

    #[clap(long, default_value_t = false)]
    validated: bool,
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
    collections: BTreeMap<Hash, (HashSeq, Vec<u64>)>,
}

#[derive(Debug, Clone, Default)]
struct PeerInfo {
    /// Somebody claims that the peer has the complete data.
    complete: bool,
    /// The last time the peer was announced by itself or another peer.
    last_announced: Option<Instant>,
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
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    )
    .into();
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
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    )
    .into();
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

async fn chunk_probe(
    connection: &quinn::Connection,
    hash: &Hash,
    chunk: ChunkNum,
) -> anyhow::Result<bool> {
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(chunk..chunk + 1)]),
    )
    .into();
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

async fn get_hash_seq(
    connection: &quinn::Connection,
    hash: Hash,
) -> anyhow::Result<(HashSeq, Vec<u64>)> {
    println!("probing hash seq");
    let request = iroh_bytes::protocol::GetRequest::new(
        hash,
        RangeSpecSeq::from_ranges_infinite([
            ChunkRanges::all(),
            ChunkRanges::from(ChunkNum(u64::MAX)..),
        ]),
    );
    let at_start = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = at_start.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        anyhow::bail!("expected start root");
    };
    let (mut curr, hash_seq) = start.next().concatenate_into_vec().await?;
    let hash_seq = HashSeq::try_from(Bytes::from(hash_seq))?;
    println!("got hash seq {}", hash_seq.len());
    let mut sizes = Vec::with_capacity(hash_seq.len());
    let closing = loop {
        match curr.next() {
            EndBlobNext::MoreChildren(more) => {
                let hash = match hash_seq.get(sizes.len()) {
                    Some(hash) => hash,
                    None => break more.finish(),
                };
                let at_header = more.next(hash);
                let (at_content, size) = at_header.next().await?;
                let next = at_content.drain().await?;
                println!("got size {}", size);
                sizes.push(size);
                curr = next;
            }
            EndBlobNext::Closing(closing) => break closing,
        }
    };
    let _stats = closing.next().await?;
    println!("got sizes {:?}", sizes);
    Ok((hash_seq, sizes))
}

fn random_hash_seq_probe(sizes: &[u64]) -> RangeSpecSeq {
    let mut rng = rand::thread_rng();
    let total_chunks = sizes
        .iter()
        .map(|size| ByteNum(*size).full_chunks().0)
        .sum::<u64>();
    let random_chunk = rng.gen_range(0..total_chunks);
    println!("random chunk {}", random_chunk);
    let mut remaining = random_chunk;
    let mut ranges = vec![];
    ranges.push(ChunkRanges::empty());
    for size in sizes {
        let chunks = ByteNum(*size).full_chunks().0;
        if remaining < chunks {
            ranges.push(ChunkRanges::from(
                ChunkNum(remaining)..ChunkNum(remaining + 1),
            ));
            break;
        } else {
            remaining -= chunks;
            ranges.push(ChunkRanges::empty());
        }
    }
    println!("random ranges {:?}", ranges);
    RangeSpecSeq::from_ranges(ranges)
}

async fn probe(
    connection: &quinn::Connection,
    db: &Db,
    content: &HashAndFormat,
) -> anyhow::Result<bool> {
    let state = &db.0.state;
    let HashAndFormat { hash, format } = content;
    match format {
        iroh_bytes::util::BlobFormat::Raw => {
            let size = match state.read().unwrap().sizes.get(&hash).copied() {
                Some(size) => size,
                None => {
                    let size = verified_size(&connection, &hash).await?;
                    state.write().unwrap().sizes.insert(content.hash, size);
                    size
                }
            };

            let random_chunk = {
                let mut rng = rand::thread_rng();
                rng.gen_range(0..ByteNum(size).chunks().0)
            };
            let probe = chunk_probe(&connection, &hash, ChunkNum(random_chunk)).await?;
            Ok(probe)
        }
        iroh_bytes::util::BlobFormat::HashSeq => {
            let entry = state.read().unwrap().collections.get(&hash).cloned();
            let (hs, sizes) = match entry {
                Some(hs) => hs,
                None => {
                    let hs = get_hash_seq(connection, *hash).await?;
                    println!("got hash seq");
                    state
                        .write()
                        .unwrap()
                        .collections
                        .insert(content.hash, hs.clone());
                    println!("inserted hash seq");
                    hs
                }
            };
            let probe = random_hash_seq_probe(&sizes);
            println!("random probe {:?}", probe);
            let request = GetRequest::new(*hash, probe);
            let request = iroh_bytes::get::fsm::start(connection.clone(), request);
            let connected = request.next().await?;
            let iroh_bytes::get::fsm::ConnectedNext::StartChild(child) = connected.next().await?
            else {
                anyhow::bail!("expected start root");
            };
            let index = usize::try_from(child.child_offset())?;
            let Some(hash) = hs.get(index) else {
                anyhow::bail!("hash seq is empty");
            };
            let at_blob_header = child.next(hash);
            let at_end_blob = at_blob_header.drain().await?;
            println!("probed random hash seq blob");
            let EndBlobNext::Closing(closing) = at_end_blob.next() else {
                anyhow::bail!("expected closing");
            };
            let _stats = closing.next().await?;
            Ok(true)
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
        let peer_info = entry.entry(*peer.as_bytes()).or_default();
        let now = Instant::now();
        peer_info.last_announced = Some(now);
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
            peers.push(PublicKey::from_bytes(peer_id).unwrap());
        }
    }
    Ok(QueryResponse {
        content: query.content,
        peers,
    })
}

fn utf8_or_hex(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        format!("\"{}\"", s)
    } else {
        hex::encode(bytes)
    }
}

async fn probe_peer(
    dialer: impl DialByPeer,
    peer: &PublicKey,
    content: &HashAndFormat,
    db: &Db,
) -> anyhow::Result<()> {
    println!(
        "connecting to peer {} using alpn {} to probe it",
        peer,
        utf8_or_hex(&iroh_bytes::protocol::ALPN)
    );
    let connection = dialer
        .dial_by_peer(peer, &iroh_bytes::protocol::ALPN)
        .await?;
    println!("connected to peer {}", connection.remote_address());
    let ok = probe(&connection, db, content).await?;
    println!("result of probing {:?} is {}", content, ok);
    Ok(())
}

async fn probe_loop(dialer: impl DialByPeer, db: Db) -> anyhow::Result<()> {
    loop {
        let state = db.0.state.read().unwrap().peer_info.clone();
        for (content, peers) in state {
            for (peer, _info) in peers {
                let peer = PublicKey::from_bytes(&peer)?;
                if let Err(cause) = probe_peer(dialer.clone(), &peer, &content, &db).await {
                    tracing::error!("error probing peer {}: {}", peer, cause);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn server(args: ServerArgs, rt: iroh_bytes::util::runtime::Handle) -> anyhow::Result<()> {
    let key = load_secret_key("server.key".into()).await?;
    let db = Db::default();
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(args.port)
        .await?;
    let t0 = Instant::now();
    loop {
        let addr = endpoint.my_addr().await?;
        if addr.derp_region().is_some() {
            break;
        }
        if t0.elapsed() > Duration::from_secs(10) {
            anyhow::bail!("timeout waiting for DERP region");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let addr = endpoint.my_addr().await?;
    println!("listening on {:?}", addr);
    println!("peer addr: {}", addr.peer_id);
    let dialer = Dialer {
        endpoint: endpoint.clone(),
    };
    let db2 = db.clone();
    let x = rt.local_pool().spawn_pinned(|| probe_loop(dialer, db2));
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
    let peer_addr = PeerAddr {
        peer_id: args.host,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
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
    content.insert(HashAndFormat {
        hash: args.ticket.hash(),
        format: args.ticket.format(),
    });
    let announce = Announce {
        peer: args.ticket.node_addr().peer_id,
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
    let dialer = Dialer { endpoint };
    let query = Query {
        content: if let Some(content) = args.content {
            content.0
        } else if let Some(ticket) = args.ticket {
            HashAndFormat {
                hash: ticket.hash(),
                format: ticket.format(),
            }
        } else {
            anyhow::bail!("either content or ticket must be specified");
        },
        flags: QueryFlags {
            complete: args.complete,
            validated: args.validated,
        },
    };
    let peer_addr = args.host;
    println!("trying to connect to tracker at {:?}", peer_addr);
    let connection = dialer.dial_by_peer(&peer_addr, &TRACKER_ALPN).await?;
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
            println!("content {}", HashAndFormat2(response.content));
            for peer in response.peers {
                println!("- peer {}", peer);
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let args = Args::parse();
    match args.command {
        Commands::Server(args) => {
            let rt = tokio::runtime::Handle::current();
            let tpc = LocalPoolHandle::new(2);
            let rt = iroh_bytes::util::runtime::Handle::new(rt, tpc);
            server(args, rt).await
        }
        Commands::Announce(args) => announce(args).await,
        Commands::Query(args) => query(args).await,
    }
}
