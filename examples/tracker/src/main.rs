#![allow(dead_code)]
//! An example that runs an iroh node that can be controlled via RPC.
//!
//! Run this example with
//!   $ cargo run --example rpc
//! Then in another terminal, run any of the normal iroh CLI commands, which you can run from
//! cargo as well:
//!   $ cargo run node stats
//! The `node stats` command will reach out over RPC to the node constructed in the example
use anyhow::Context;
use bao_tree::{ByteNum, ChunkNum, ChunkRanges};
use bytes::Bytes;
use iroh::util::fs::load_secret_key;
use iroh_bytes::get::fsm::{BlobContentNext, EndBlobNext};
use iroh_bytes::get::Stats;
use iroh_bytes::hashseq::HashSeq;
use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
use iroh_bytes::util::Hash;
use iroh_bytes::BlobFormat;
use iroh_net::magic_endpoint::{get_alpn, get_peer_id};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::task::LocalPoolHandle;

mod discovery;

type ShortNodeId = [u8; 32];

const TRACKER_ALPN: &[u8] = b"n0/tracker/1";
const PKARR_RELAY_URL: &str = "https://iroh-discovery.rklaehn.workers.dev/";

/// Announce kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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
use iroh_net::key::PublicKey;
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

/// Various ways to specify content.
#[derive(Debug, Clone, derive_more::From)]
enum ContentArg {
    Hash(Hash),
    HashAndFormat(HashAndFormat),
    Ticket(Ticket),
}

impl ContentArg {
    fn hash_and_format(&self) -> HashAndFormat {
        match self {
            ContentArg::Hash(hash) => HashAndFormat::raw(*hash),
            ContentArg::HashAndFormat(haf) => *haf,
            ContentArg::Ticket(ticket) => HashAndFormat {
                hash: ticket.hash(),
                format: ticket.format(),
            },
        }
    }

    fn peer(&self) -> Option<PublicKey> {
        match self {
            ContentArg::Hash(_) => None,
            ContentArg::HashAndFormat(_) => None,
            ContentArg::Ticket(ticket) => Some(ticket.node_addr().peer_id),
        }
    }
}

impl Display for ContentArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentArg::Hash(hash) => Display::fmt(hash, f),
            ContentArg::HashAndFormat(haf) => Display::fmt(haf, f),
            ContentArg::Ticket(ticket) => Display::fmt(ticket, f),
        }
    }
}

impl FromStr for ContentArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(hash) = Hash::from_str(s) {
            Ok(hash.into())
        } else if let Ok(haf) = HashAndFormat::from_str(s) {
            Ok(haf.into())
        } else if let Ok(ticket) = Ticket::from_str(s) {
            Ok(ticket.into())
        } else {
            anyhow::bail!("invalid hash and format")
        }
    }
}

#[derive(Parser, Debug)]
struct AnnounceArgs {
    /// the peer if of the tracker
    #[clap(long)]
    tracker: PublicKey,

    /// the port to use for announcing
    #[clap(long)]
    port: Option<u16>,

    /// The content to announce.
    content: ContentArg,

    /// The peer to announce. Not needed if content is a ticket.
    #[clap(long)]
    peer: Option<PublicKey>,

    /// Announce that the peer has the complete data.
    #[clap(long, default_value_t = true)]
    complete: bool,
}

#[derive(Parser, Debug)]
struct QueryArgs {
    #[clap(long)]
    tracker: PublicKey,

    /// the port to use for querying
    #[clap(long)]
    port: Option<u16>,

    /// The content to find peers for.
    content: ContentArg,

    #[clap(long, default_value_t = true)]
    complete: bool,

    #[clap(long, default_value_t = false)]
    validated: bool,
}

#[derive(Debug, Clone, Default)]
struct Tracker(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    state: RwLock<State>,
    options: Options,
}

#[derive(Debug, Clone, Default)]
struct State {
    // key of the inner map is the bytes of the public key
    peer_info: BTreeMap<HashAndFormat, BTreeMap<[u8; 32], PeerInfo>>,
    // cache for verified sizes of hashes, used during probing
    sizes: BTreeMap<Hash, u64>,
    // cache for collections, used during collection probing
    collections: BTreeMap<Hash, (HashSeq, Arc<[u64]>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Incomplete,
    Complete,
}

impl ProbeKind {
    fn new(complete: bool) -> Self {
        if complete {
            Self::Complete
        } else {
            Self::Incomplete
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    announce_timeout: Duration,
    probe_timeout: Duration,
    size_probe_timeout: Duration,
    probe_interval: Duration,
    max_hash_seq_size: u64,
    dial_log: Option<PathBuf>,
    probe_log: Option<PathBuf>,
    announce_data_path: Option<PathBuf>,
}

type AnnounceData = BTreeMap<HashAndFormat, BTreeMap<[u8; 32], bool>>;

impl Options {
    /// Make the paths in the options relative to the given base path.
    pub fn make_paths_relative(&mut self, base: &Path) {
        if let Some(path) = &mut self.dial_log {
            *path = base.join(&path);
        }
        if let Some(path) = &mut self.probe_log {
            *path = base.join(&path);
        }
        if let Some(path) = &mut self.announce_data_path {
            *path = base.join(&path);
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            announce_timeout: Duration::from_secs(60 * 60 * 24),
            probe_timeout: Duration::from_secs(60 * 60 * 24),
            size_probe_timeout: Duration::from_secs(60 * 60 * 24),
            // interval between probing peers
            probe_interval: Duration::from_secs(10),
            // max hash seq size is 1000 hashes
            max_hash_seq_size: 1024 * 16 * 32,
            dial_log: Some("dial.log".into()),
            probe_log: Some("probe.log".into()),
            announce_data_path: Some("announce.data".into()),
        }
    }
}

const REQUEST_SIZE_LIMIT: usize = 1024 * 16;

/// Get the claimed size of a blob from a peer.
///
/// This is just reading the size header and then immediately closing the connection.
/// It can be used to check if a peer has any data at all.
pub async fn unverified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("expected start root");
    };
    let at_blob_header = start.next();
    let (curr, size) = at_blob_header.next().await?;
    let stats = curr.finish().next().await?;
    Ok((size, stats))
}

/// Get the verified size of a blob from a peer.
///
/// This asks for the last chunk of the blob and validates the response.
/// Note that this does not validate that the peer has all the data.
pub async fn verified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("expected start root");
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
        unreachable!("expected closing");
    };
    let stats = closing.next().await?;
    Ok((size, stats))
}

/// Probe for a single chunk of a blob.
async fn chunk_probe(
    connection: &quinn::Connection,
    hash: &Hash,
    chunk: ChunkNum,
) -> anyhow::Result<Stats> {
    let ranges = ChunkRanges::from(chunk..chunk + 1);
    println!("random blob probe, chunks {:?}", ranges);
    let ranges = RangeSpecSeq::from_ranges([ranges]);
    let request = GetRequest::new(*hash, ranges);
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("query includes root");
    };
    let header = start.next();
    let (mut curr, _size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            BlobContentNext::More((next, res)) => {
                res?;
                curr = next;
            }
            BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let EndBlobNext::Closing(closing) = end.next() else {
        unreachable!("query contains only one blob");
    };
    let stats = closing.next().await?;
    Ok(stats)
}

async fn get_hash_seq_and_sizes(
    connection: &quinn::Connection,
    hash: &Hash,
    max_size: u64,
) -> anyhow::Result<(HashSeq, Arc<[u64]>)> {
    println!("probing hash seq");
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges_infinite([
            ChunkRanges::all(),
            ChunkRanges::from(ChunkNum(u64::MAX)..),
        ]),
    );
    let at_start = iroh_bytes::get::fsm::start(connection.clone(), request);
    let at_connected = at_start.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = at_connected.next().await? else {
        unreachable!("query includes root");
    };
    let at_start_root = start.next();
    let (at_blob_content, size) = at_start_root.next().await?;
    // check the size to avoid parsing a maliciously large hash seq
    if size > max_size {
        anyhow::bail!("size too large");
    }
    let (mut curr, hash_seq) = at_blob_content.concatenate_into_vec().await?;
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
    Ok((hash_seq, sizes.into()))
}

/// Given a sequence of sizes of children, generate a range spec that selects a
/// random chunk of a random child.
///
/// The random chunk is chosen uniformly from the chunks of the children, so
/// larger children are more likely to be selected.
fn random_hash_seq_ranges(sizes: &[u64], mut rng: impl Rng) -> RangeSpecSeq {
    let total_chunks = sizes
        .iter()
        .map(|size| ByteNum(*size).full_chunks().0)
        .sum::<u64>();
    let random_chunk = rng.gen_range(0..total_chunks);
    let mut remaining = random_chunk;
    let mut ranges = vec![];
    ranges.push(ChunkRanges::empty());
    for (i, size) in sizes.iter().enumerate() {
        let chunks = ByteNum(*size).full_chunks().0;
        if remaining < chunks {
            let range = ChunkRanges::from(ChunkNum(remaining)..ChunkNum(remaining + 1));
            println!("random hash seq probe, child {}, ranges {:?}", i, range);
            ranges.push(range);
            break;
        } else {
            remaining -= chunks;
            ranges.push(ChunkRanges::empty());
        }
    }
    RangeSpecSeq::from_ranges(ranges)
}

impl Tracker {
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let announce_data = if let Some(data_path) = &options.announce_data_path {
            load_from_file::<AnnounceData>(data_path)?
        } else {
            Default::default()
        };
        let mut state = State::default();
        for (content, peers) in announce_data {
            for (peer, complete) in peers {
                let peer_info = state.peer_info.entry(content).or_default();
                let peer_info = peer_info.entry(peer).or_default();
                peer_info.complete = complete;
            }
        }
        Ok(Self(Arc::new(Inner {
            state: RwLock::new(state),
            options,
        })))
    }

    async fn get_or_insert_size(
        &self,
        connection: &quinn::Connection,
        hash: &Hash,
    ) -> anyhow::Result<u64> {
        let state = &self.0.state;
        let size_opt = state.read().unwrap().sizes.get(hash).copied();
        let size = match size_opt {
            Some(size) => size,
            None => {
                let (size, _) = verified_size(connection, hash).await?;
                state.write().unwrap().sizes.insert(*hash, size);
                size
            }
        };
        Ok(size)
    }

    async fn get_or_insert_sizes(
        &self,
        connection: &quinn::Connection,
        hash: &Hash,
    ) -> anyhow::Result<(HashSeq, Arc<[u64]>)> {
        let state = &self.0.state;
        let entry = state.read().unwrap().collections.get(hash).cloned();
        let res = match entry {
            Some(hs) => hs,
            None => {
                let hs = get_hash_seq_and_sizes(connection, hash, self.0.options.max_hash_seq_size)
                    .await?;
                state.write().unwrap().collections.insert(*hash, hs.clone());
                hs
            }
        };
        Ok(res)
    }

    async fn probe(
        &self,
        connection: &quinn::Connection,
        content: &HashAndFormat,
        probe_kind: ProbeKind,
    ) -> anyhow::Result<Stats> {
        let HashAndFormat { hash, format } = content;
        let mut rng = rand::thread_rng();
        let stats = if probe_kind == ProbeKind::Incomplete {
            let (_size, stats) = unverified_size(connection, hash).await?;
            stats
        } else {
            match format {
                BlobFormat::Raw => {
                    let size = self.get_or_insert_size(connection, hash).await?;
                    let random_chunk = rng.gen_range(0..ByteNum(size).chunks().0);
                    chunk_probe(connection, hash, ChunkNum(random_chunk)).await?
                }
                BlobFormat::HashSeq => {
                    let (hs, sizes) = self.get_or_insert_sizes(connection, hash).await?;
                    let ranges = random_hash_seq_ranges(&sizes, rand::thread_rng());
                    let request = GetRequest::new(*hash, ranges);
                    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
                    let connected = request.next().await?;
                    let iroh_bytes::get::fsm::ConnectedNext::StartChild(child) =
                        connected.next().await?
                    else {
                        unreachable!("request does not include root");
                    };
                    let index =
                        usize::try_from(child.child_offset()).expect("child offset too large");
                    let hash = hs.get(index).expect("request inconsistent with hash seq");
                    let at_blob_header = child.next(hash);
                    let at_end_blob = at_blob_header.drain().await?;
                    let EndBlobNext::Closing(closing) = at_end_blob.next() else {
                        unreachable!("request contains only one blob");
                    };
                    closing.next().await?
                }
            }
        };
        Ok(stats)
    }

    async fn handle_connection(&self, connection: quinn::Connection) -> anyhow::Result<()> {
        println!("calling accept_bi");
        let (mut send, mut recv) = connection.accept_bi().await?;
        println!("got bi stream");
        let request = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
        let request = postcard::from_bytes::<Request>(&request)?;
        match request {
            Request::Announce(announce) => {
                println!("got announce: {:?}", announce);
                self.handle_announce(announce).await?;
                send.finish().await?;
            }

            Request::Query(query) => {
                println!("handle query: {:?}", query);
                let response = self.handle_query(query).await?;
                let response = Response::QueryResponse(response);
                let response = postcard::to_stdvec(&response)?;
                send.write_all(&response).await?;
                send.finish().await?;
            }
        }
        Ok(())
    }

    async fn handle_announce(&self, announce: Announce) -> anyhow::Result<()> {
        let mut state = self.0.state.write().unwrap();
        let peer = announce.peer;
        for content in announce.content {
            let entry = state.peer_info.entry(content).or_default();
            let peer_info = entry.entry(*peer.as_bytes()).or_default();
            let now = Instant::now();
            peer_info.last_announced = Some(now);
            peer_info.complete = announce.kind == AnnounceKind::Complete;
        }
        if let Some(path) = &self.0.options.announce_data_path {
            let mut data: AnnounceData = Default::default();
            for (content, peers) in state.peer_info.iter() {
                let mut peers2 = BTreeMap::new();
                for (peer, info) in peers {
                    peers2.insert(*peer, info.complete);
                }
                data.insert(*content, peers2);
            }
            drop(state);
            save_to_file(&data, path)?;
        }
        Ok(())
    }

    async fn handle_query(&self, query: Query) -> anyhow::Result<QueryResponse> {
        let state = self.0.state.read().unwrap();
        let entry = state.peer_info.get(&query.content);
        let options = &self.0.options;
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
                if !query.flags.complete && query.flags.validated && !recently_size_probed {
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

    /// Get the content that is supposedly available, grouped by peers
    fn get_content_by_peers(&self) -> BTreeMap<ShortNodeId, BTreeMap<HashAndFormat, bool>> {
        let state = self.0.state.read().unwrap();
        let mut content_by_peers = BTreeMap::<[u8; 32], BTreeMap<HashAndFormat, bool>>::new();
        for (content, peers) in state.peer_info.iter() {
            for (peer, info) in peers {
                content_by_peers
                    .entry(*peer)
                    .or_default()
                    .insert(*content, info.complete);
            }
        }
        content_by_peers
    }

    fn apply_result(
        &self,
        results: BTreeMap<HashAndFormat, Vec<(ShortNodeId, ProbeKind)>>,
        now: Instant,
    ) {
        let mut state = self.0.state.write().unwrap();
        for (haf, peers) in results {
            let entry = state.peer_info.entry(haf).or_default();
            for (peer, kind) in peers {
                let peer_info = entry.entry(peer).or_default();
                match kind {
                    ProbeKind::Incomplete => {
                        peer_info.last_size_probed = Some(now);
                    }
                    ProbeKind::Complete => {
                        peer_info.last_probed = Some(now);
                    }
                }
            }
        }
    }

    fn log_connection_attempt(
        &self,
        peer: &PublicKey,
        t0: Instant,
        outcome: &anyhow::Result<quinn::Connection>,
    ) -> anyhow::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        if let Some(path) = &self.0.options.dial_log {
            let outcome = match outcome {
                Ok(_) => "ok",
                Err(_) => "err",
            };
            let line = format!(
                "{:.6},{},{:.6},{}\n",
                now,
                peer,
                t0.elapsed().as_secs_f64(),
                outcome
            );
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap();
            file.write_all(line.as_bytes())?;
        }
        Ok(())
    }

    fn log_probe_attempt(
        &self,
        peer: &PublicKey,
        content: &HashAndFormat,
        kind: ProbeKind,
        t0: Instant,
        outcome: &anyhow::Result<Stats>,
    ) -> anyhow::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        if let Some(path) = &self.0.options.probe_log {
            let outcome = match outcome {
                Ok(_) => "ok",
                Err(_) => "err",
            };
            let line = format!(
                "{:.6},{},{},{:?},{:.6},{}\n",
                now,
                peer,
                content,
                kind,
                t0.elapsed().as_secs_f64(),
                outcome
            );
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap();
            file.write_all(line.as_bytes())?;
        }
        Ok(())
    }

    async fn probe_loop(self, endpoint: MagicEndpoint) -> anyhow::Result<()> {
        loop {
            let content_by_peers = self.get_content_by_peers();
            let mut results = BTreeMap::<HashAndFormat, Vec<(ShortNodeId, ProbeKind)>>::new();
            let now = Instant::now();
            for (short_peer, content) in content_by_peers {
                let peer = PublicKey::from_bytes(&short_peer)?;
                let t0 = Instant::now();
                let res = endpoint
                    .connect_by_peer(&peer, &iroh_bytes::protocol::ALPN)
                    .await;
                self.log_connection_attempt(&peer, t0, &res)?;
                let connection = match res {
                    Ok(connection) => connection,
                    Err(cause) => {
                        tracing::error!("error dialing peer {}: {}", peer, cause);
                        continue;
                    }
                };
                for (haf, complete) in content {
                    let probe_kind = ProbeKind::new(complete);
                    let t0 = Instant::now();
                    let res = self.probe(&connection, &haf, probe_kind).await;
                    self.log_probe_attempt(&peer, &haf, probe_kind, t0, &res)?;
                    match res {
                        Ok(_) => {
                            results
                                .entry(haf)
                                .or_default()
                                .push((short_peer, probe_kind));
                        }
                        Err(cause) => {
                            tracing::error!("error probing peer {}: {}", peer, cause)
                        }
                    }
                }
            }
            self.apply_result(results, now);
            tokio::time::sleep(self.0.options.probe_interval).await;
        }
    }
}

fn save_to_file(data: impl Serialize, path: &Path) -> anyhow::Result<()> {
    let data = postcard::to_stdvec(&data)?;
    let data_dir = path.parent().context("non absolute data file")?;
    let mut temp = tempfile::NamedTempFile::new_in(data_dir)?;
    temp.write_all(&data)?;
    std::fs::rename(temp.into_temp_path(), path)?;
    Ok(())
}

fn load_from_file<T: DeserializeOwned + Default>(path: &Path) -> anyhow::Result<T> {
    Ok(if path.exists() {
        let data = std::fs::read(path)?;
        postcard::from_bytes(&data)?
    } else {
        T::default()
    })
}

#[allow(dead_code)]
fn utf8_or_hex(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        format!("\"{}\"", s)
    } else {
        hex::encode(bytes)
    }
}

/// Wait until the endpoint has figured out it's own DERP region.
async fn await_derp_region(endpoint: &MagicEndpoint) -> anyhow::Result<()> {
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
    Ok(())
}

pub fn tracker_home() -> anyhow::Result<PathBuf> {
    Ok(if let Some(val) = env::var_os("IROH_TRACKER_HOME") {
        PathBuf::from(val)
    } else {
        dirs_next::data_dir()
            .ok_or_else(|| {
                anyhow::anyhow!("operating environment provides no directory for application data")
            })?
            .join("iroh_tracker")
    })
}

pub fn tracker_path(file_name: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    Ok(tracker_home()?.join(file_name))
}

async fn create_endpoint(
    key: iroh_net::key::SecretKey,
    port: u16,
) -> anyhow::Result<MagicEndpoint> {
    // let pkarr_relay_discovery = discovery::PkarrRelayDiscovery::new(key.clone(), PKARR_RELAY_URL.parse().unwrap());
    let region_discover = discovery::HardcodedRegionDiscovery::new(2);
    iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .discovery(Box::new(region_discover))
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(port)
        .await
}

async fn server(args: ServerArgs, rt: iroh_bytes::util::runtime::Handle) -> anyhow::Result<()> {
    let home = tracker_home()?;
    println!("tracker starting using {}", tracker_home()?.display());
    let key_path = tracker_path("server.key")?;
    let key = load_secret_key(key_path).await?;
    let endpoint = create_endpoint(key, args.port).await?;
    let config_path = tracker_path("server.config")?;
    let mut options = if config_path.exists() {
        let config = std::fs::read_to_string(config_path)?;
        toml::from_str(&config)?
    } else {
        Options::default()
    };
    options.make_paths_relative(&home);
    let db = Tracker::new(options)?;
    await_derp_region(&endpoint).await?;
    let addr = endpoint.my_addr().await?;
    println!("listening on {:?}", addr);
    println!("peer addr: {}", addr.peer_id);
    let db2 = db.clone();
    let endpoint2 = endpoint.clone();
    let _task = rt
        .local_pool()
        .spawn_pinned(move || db2.probe_loop(endpoint2));
    while let Some(connecting) = endpoint.accept().await {
        let db = db.clone();
        tokio::task::spawn(async move {
            println!("got connecting");
            let Ok((pk, h, conn)) = accept_conn(connecting).await else {
                tracing::error!("error accepting connection");
                return;
            };
            println!("got connection from {} {}", pk, h);
            if let Err(cause) = db.handle_connection(conn).await {
                tracing::error!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Accept an incoming connection and extract the client-provided [`PublicKey`] and ALPN protocol.
pub async fn accept_conn(
    mut conn: quinn::Connecting,
) -> anyhow::Result<(PublicKey, String, quinn::Connection)> {
    let alpn = get_alpn(&mut conn).await?;
    println!("awaiting conn");
    let conn = conn.await?;
    println!("got conn");
    let peer_id = get_peer_id(&conn).await?;
    Ok((peer_id, alpn, conn))
}

async fn announce(args: AnnounceArgs) -> anyhow::Result<()> {
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path("client.key")?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, 11112).await?;
    println!("announce {:?}", args);
    println!("trying to connect to {:?}", args.tracker);
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
    println!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("opened bi stream");
    let kind = if args.complete {
        AnnounceKind::Complete
    } else {
        AnnounceKind::Partial
    };
    let peer = if let Some(peer) = args.peer {
        peer
    } else if let Some(peer) = args.content.peer() {
        peer
    } else {
        anyhow::bail!("either peer or ticket must be specified {:?}", args.content);
    };
    let mut content = BTreeSet::new();
    content.insert(args.content.hash_and_format());
    let announce = Announce {
        peer,
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
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path("client.key")?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, args.port.unwrap_or_default()).await?;
    let query = Query {
        content: args.content.hash_and_format(),
        flags: QueryFlags {
            complete: args.complete,
            validated: args.validated,
        },
    };
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    println!("trying to connect to tracker at {:?}", args.tracker);
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
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
            println!("content {}", response.content);
            for peer in response.peers {
                println!("- peer {}", peer);
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
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
