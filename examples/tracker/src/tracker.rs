//! The tracker server
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::Instant,
};

use bao_tree::{ByteNum, ChunkNum};
use futures::StreamExt;
use iroh_bytes::{
    get::{fsm::EndBlobNext, Stats},
    hashseq::HashSeq,
    protocol::GetRequest,
    BlobFormat, Hash, HashAndFormat,
};
use iroh_net::MagicEndpoint;
use rand::Rng;

use crate::{
    io::{log_connection_attempt, log_probe_attempt, AnnounceData},
    iroh_bytes_util::{
        chunk_probe, get_hash_seq_and_sizes, random_hash_seq_ranges, unverified_size, verified_size,
    },
    log,
    options::Options,
    protocol::{
        Announce, AnnounceKind, Query, QueryResponse, Request, Response, REQUEST_SIZE_LIMIT,
    },
    NodeId,
};

/// The tracker server.
///
/// This is a cheaply cloneable handle to the state and the options.
#[derive(Debug, Clone, Default)]
pub struct Tracker(Arc<Inner>);

/// The inner state of the tracker server. Options are immutable and don't need to be locked.
#[derive(Debug, Default)]
struct Inner {
    state: RwLock<State>,
    options: Options,
}

/// The mutable state of the tracker server.
#[derive(Debug, Clone, Default)]
struct State {
    // every announce we ever got, indexed by hash, kind and peer
    announce_data: BTreeMap<HashAndFormat, BTreeMap<AnnounceKind, BTreeMap<NodeId, PeerInfo>>>,
    // cache for verified sizes of hashes, used during probing
    sizes: BTreeMap<Hash, u64>,
    // cache for collections, used during collection probing
    collections: BTreeMap<Hash, (HashSeq, Arc<[u64]>)>,
}

impl State {
    /// Get the part of the announce data that is persisted
    fn get_persisted_announce_data(&self) -> AnnounceData {
        let mut data: AnnounceData = Default::default();
        for (content, by_kind_and_peers) in self.announce_data.iter() {
            let mut peers = BTreeMap::<AnnounceKind, BTreeSet<NodeId>>::new();
            for (kind, by_peer) in by_kind_and_peers {
                for peer in by_peer.keys() {
                    peers.entry(*kind).or_default().insert(*peer);
                }
            }
            data.0.insert(*content, peers);
        }
        data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Incomplete,
    Complete,
}

impl From<AnnounceKind> for ProbeKind {
    fn from(kind: AnnounceKind) -> Self {
        match kind {
            AnnounceKind::Partial => Self::Incomplete,
            AnnounceKind::Complete => Self::Complete,
        }
    }
}

impl From<ProbeKind> for AnnounceKind {
    fn from(kind: ProbeKind) -> Self {
        match kind {
            ProbeKind::Incomplete => Self::Partial,
            ProbeKind::Complete => Self::Complete,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PeerInfo {
    /// The last time the peer was announced by itself or another peer.
    last_announced: Option<Instant>,
    /// last time the peer was randomly probed for the data and answered.
    last_probed: Option<Instant>,
}

impl Tracker {
    /// Create a new tracker server.
    ///
    /// You will have to drive the tracker server yourself, using `handle_connection` and `probe_loop`.
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let announce_data = if let Some(data_path) = &options.announce_data_path {
            crate::io::load_from_file::<AnnounceData>(data_path)?
        } else {
            Default::default()
        };
        let mut state = State::default();
        let now = Instant::now();
        for (content, peers_by_kind) in announce_data.0 {
            for (kind, peers) in peers_by_kind {
                for peer in peers {
                    let by_kind_and_peer = state.announce_data.entry(content).or_default();
                    let peer_info = by_kind_and_peer
                        .entry(kind)
                        .or_default()
                        .entry(peer)
                        .or_default();
                    // set the last announced time to now on startup, otherwise
                    // it would be considered too old
                    peer_info.last_announced = Some(now);
                }
            }
        }
        Ok(Self(Arc::new(Inner {
            state: RwLock::new(state),
            options,
        })))
    }

    /// The main loop that probes peers.
    pub async fn probe_loop(self, endpoint: MagicEndpoint) -> anyhow::Result<()> {
        loop {
            let content_by_peers = self.get_content_by_peers();
            let now = Instant::now();
            let results = futures::stream::iter(content_by_peers.into_iter())
                .map(|(peer, by_kind_and_content)| {
                    let endpoint = endpoint.clone();
                    let this = self.clone();
                    this.probe_one(endpoint, peer, by_kind_and_content)
                })
                .buffer_unordered(self.0.options.probe_parallelism)
                .collect::<Vec<_>>()
                .await;
            let results = results
                .into_iter()
                .filter_map(|x| x.ok())
                .collect::<BTreeMap<_, _>>();
            self.apply_result(results, now);
            tokio::time::sleep(self.0.options.probe_interval).await;
        }
    }

    /// Handle a single incoming connection on the tracker ALPN.
    pub async fn handle_connection(&self, connection: quinn::Connection) -> anyhow::Result<()> {
        log!("calling accept_bi");
        let (mut send, mut recv) = connection.accept_bi().await?;
        log!("got bi stream");
        let request = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
        let request = postcard::from_bytes::<Request>(&request)?;
        match request {
            Request::Announce(announce) => {
                log!("got announce: {:?}", announce);
                self.handle_announce(announce).await?;
                send.finish().await?;
            }

            Request::Query(query) => {
                log!("handle query: {:?}", query);
                let response = self.handle_query(query).await?;
                let response = Response::QueryResponse(response);
                let response = postcard::to_stdvec(&response)?;
                send.write_all(&response).await?;
                send.finish().await?;
            }
        }
        Ok(())
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
        host: &NodeId,
        content: &HashAndFormat,
        probe_kind: ProbeKind,
    ) -> anyhow::Result<Stats> {
        let cap = format!("{} at {}", content, host);
        let HashAndFormat { hash, format } = content;
        let mut rng = rand::thread_rng();
        let stats = if probe_kind == ProbeKind::Incomplete {
            log!("Size probing {}...", cap);
            let (size, stats) = unverified_size(connection, hash).await?;
            log!(
                "Size probed {}, got unverified size {}, {:.6}s",
                cap,
                size,
                stats.elapsed.as_secs_f64()
            );
            stats
        } else {
            match format {
                BlobFormat::Raw => {
                    let size = self.get_or_insert_size(connection, hash).await?;
                    let random_chunk = rng.gen_range(0..ByteNum(size).chunks().0);
                    log!("Chunk probing {}, chunk {}", cap, random_chunk);
                    let stats = chunk_probe(connection, hash, ChunkNum(random_chunk)).await?;
                    log!(
                        "Chunk probed {}, chunk {}, {:.6}s",
                        cap,
                        random_chunk,
                        stats.elapsed.as_secs_f64()
                    );
                    stats
                }
                BlobFormat::HashSeq => {
                    let (hs, sizes) = self.get_or_insert_sizes(connection, hash).await?;
                    let ranges = random_hash_seq_ranges(&sizes, rand::thread_rng());
                    let text = ranges
                        .iter_non_empty()
                        .map(|(index, ranges)| {
                            format!("child={}, ranges={:?}", index, ranges.to_chunk_ranges())
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    log!("Seq probing {} using {}", cap, text);
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
                    let stats = closing.next().await?;
                    log!(
                        "Seq probed {} using {}, {:.6}s",
                        cap,
                        text,
                        stats.elapsed.as_secs_f64()
                    );
                    stats
                }
            }
        };
        Ok(stats)
    }

    async fn handle_announce(&self, announce: Announce) -> anyhow::Result<()> {
        let mut state = self.0.state.write().unwrap();
        for content in announce.content {
            let entry = state.announce_data.entry(content).or_default();
            let peer_info = entry
                .entry(announce.kind)
                .or_default()
                .entry(announce.host)
                .or_default();
            let now = Instant::now();
            peer_info.last_announced = Some(now);
        }
        if let Some(path) = &self.0.options.announce_data_path {
            let data = state.get_persisted_announce_data();
            drop(state);
            crate::io::save_to_file(&data, path)?;
        }
        Ok(())
    }

    async fn handle_query(&self, query: Query) -> anyhow::Result<QueryResponse> {
        let state = self.0.state.read().unwrap();
        let entry = state.announce_data.get(&query.content);
        let options = &self.0.options;
        let kind = AnnounceKind::from_complete(query.flags.complete);
        let mut peers = vec![];
        if let Some(by_kind_and_peer) = entry {
            if let Some(entry) = by_kind_and_peer.get(&kind) {
                for (peer_id, peer_info) in entry {
                    let recently_announced = peer_info
                        .last_announced
                        .map(|t| t.elapsed() <= options.announce_timeout)
                        .unwrap_or_default();
                    let recently_probed = peer_info
                        .last_probed
                        .map(|t| t.elapsed() <= options.probe_timeout)
                        .unwrap_or_default();
                    if !recently_announced {
                        // info is too old
                        tracing::error!("content is too old");
                        continue;
                    }
                    if query.flags.validated && !recently_probed {
                        // query asks for validated complete peers, but the probe is too old
                        tracing::error!("validation of complete data is too old");
                        continue;
                    }
                    peers.push(*peer_id);
                }
            }
        } else {
            tracing::error!("no peers for content");
        }
        Ok(QueryResponse {
            content: query.content,
            hosts: peers,
        })
    }

    /// Get the content that is supposedly available, grouped by peers
    fn get_content_by_peers(&self) -> BTreeMap<NodeId, BTreeMap<AnnounceKind, HashAndFormat>> {
        let state = self.0.state.read().unwrap();
        let mut content_by_peers = BTreeMap::<NodeId, BTreeMap<AnnounceKind, HashAndFormat>>::new();
        for (content, by_kind_and_peer) in state.announce_data.iter() {
            for (kind, by_peer) in by_kind_and_peer {
                for peer in by_peer.keys() {
                    content_by_peers
                        .entry(*peer)
                        .or_default()
                        .insert(*kind, *content);
                }
            }
        }
        content_by_peers
    }

    fn apply_result(
        &self,
        results: BTreeMap<NodeId, Vec<(HashAndFormat, AnnounceKind, anyhow::Result<Stats>)>>,
        now: Instant,
    ) {
        let mut state = self.0.state.write().unwrap();
        for (peer, probes) in results {
            for (content, announce_kind, result) in probes {
                if result.is_ok() {
                    let state_for_content = state.announce_data.entry(content).or_default();
                    let peer_info = state_for_content
                        .entry(announce_kind)
                        .or_default()
                        .entry(peer)
                        .or_default();
                    peer_info.last_probed = Some(now);
                }
            }
        }
    }

    /// Execute probes for a single peer.
    ///
    /// This will fail if the connection fails, or if local logging fails.
    /// Individual probes can fail, but the probe will continue.
    async fn probe_one(
        self,
        endpoint: MagicEndpoint,
        host: NodeId,
        by_kind_and_content: BTreeMap<AnnounceKind, HashAndFormat>,
    ) -> anyhow::Result<(
        NodeId,
        Vec<(HashAndFormat, AnnounceKind, anyhow::Result<Stats>)>,
    )> {
        let t0 = Instant::now();
        let res = endpoint
            .connect_by_node_id(&host, &iroh_bytes::protocol::ALPN)
            .await;
        log_connection_attempt(&self.0.options.dial_log, &host, t0, &res)?;
        let connection = match res {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::error!("error dialing host {}: {}", host, cause);
                return Err(cause);
            }
        };
        let mut results = Vec::new();
        for (announce_kind, content) in by_kind_and_content {
            let probe_kind = ProbeKind::from(announce_kind);
            let t0 = Instant::now();
            let res = self.probe(&connection, &host, &content, probe_kind).await;
            log_probe_attempt(
                &self.0.options.probe_log,
                &host,
                &content,
                probe_kind,
                t0,
                &res,
            )?;
            if let Err(cause) = &res {
                tracing::error!("error probing host {}: {}", host, cause);
            }
            results.push((content, announce_kind, res));
        }
        anyhow::Ok((host, results))
    }
}
