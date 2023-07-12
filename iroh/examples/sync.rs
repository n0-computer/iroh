//! Live edit a p2p document
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--private-key` CLI flag with the private key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.

use std::{fmt, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{anyhow, bail};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::SigningKey;
use futures::{future::BoxFuture, FutureExt};
use iroh::sync::{BlobStore, Doc, DownloadMode, LiveSync, PeerSource, SYNC_ALPN};
use iroh_bytes::provider::Database;
use iroh_gossip::{
    net::{GossipHandle, GOSSIP_ALPN},
    proto::TopicId,
};
use iroh_net::{
    defaults::{default_derp_map, DEFAULT_DERP_STUN_PORT},
    derp::{DerpMap, UseIpv4, UseIpv6},
    magic_endpoint::get_alpn,
    tls::Keypair,
    MagicEndpoint,
};
use iroh_sync::sync::{Author, Namespace, NamespaceId, Replica, ReplicaStore, SignedEntry};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;

#[derive(Parser, Debug)]
struct Args {
    /// Private key to derive our peer id from
    #[clap(long)]
    private_key: Option<String>,
    /// Path to a data directory where blobs will be persisted
    #[clap(short, long)]
    storage_path: Option<PathBuf>,
    /// Set a custom DERP server. By default, the DERP server hosted by n0 will be used.
    #[clap(short, long)]
    derp: Option<Url>,
    /// Disable DERP completeley
    #[clap(long)]
    no_derp: bool,
    /// Set your nickname
    #[clap(short, long)]
    name: Option<String>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    Open { doc_name: String },
    Join { ticket: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    run(args).await
}

async fn run(args: Args) -> anyhow::Result<()> {
    // parse or generate our keypair
    let keypair = match args.private_key {
        None => Keypair::generate(),
        Some(key) => parse_keypair(&key)?,
    };
    println!("> our private key: {}", fmt_secret(&keypair));

    // configure our derp map
    let derp_map = match (args.no_derp, args.derp) {
        (false, None) => Some(default_derp_map()),
        (false, Some(url)) => Some(derp_map_from_url(url)?),
        (true, None) => None,
        (true, Some(_)) => bail!("You cannot set --no-derp and --derp at the same time"),
    };
    println!("> using DERP servers: {}", fmt_derp_map(&derp_map));

    // build our magic endpoint
    let (endpoint, gossip, initial_endpoints) = {
        // init a cell that will hold our gossip handle to be used in endpoint callbacks
        let gossip_cell: OnceCell<GossipHandle> = OnceCell::new();
        // init a channel that will emit once the initial endpoints of our local node are discovered
        let (initial_endpoints_tx, mut initial_endpoints_rx) = mpsc::channel(1);

        let endpoint = MagicEndpoint::builder()
            .keypair(keypair.clone())
            .alpns(vec![
                GOSSIP_ALPN.to_vec(),
                SYNC_ALPN.to_vec(),
                iroh_bytes::protocol::ALPN.to_vec(),
            ])
            .derp_map(derp_map)
            .on_endpoints({
                let gossip_cell = gossip_cell.clone();
                Box::new(move |endpoints| {
                    // send our updated endpoints to the gossip protocol to be sent as PeerData to peers
                    if let Some(gossip) = gossip_cell.get() {
                        gossip.update_endpoints(endpoints).ok();
                    }
                    // trigger oneshot on the first endpoint update
                    initial_endpoints_tx.try_send(endpoints.to_vec()).ok();
                })
            })
            .bind(args.bind_port)
            .await?;

        // create the gossip protocol
        let gossip = {
            let gossip = GossipHandle::from_endpoint(endpoint.clone(), Default::default());
            // insert the gossip handle into the gossip cell to be used in the endpoint callbacks above
            gossip_cell.set(gossip.clone()).unwrap();
            gossip
        };
        // wait for a first endpoint update so that we know about at least one of our addrs
        let initial_endpoints = initial_endpoints_rx.recv().await.unwrap();
        // pass our initial endpoints to the gossip protocol
        gossip.update_endpoints(&initial_endpoints)?;
        (endpoint, gossip, initial_endpoints)
    };
    println!("> our peer id: {}", endpoint.peer_id());

    let (topic, peers) = match &args.command {
        Command::Open { doc_name } => {
            let topic: TopicId = blake3::hash(doc_name.as_bytes()).into();
            println!(
                "> opening document {doc_name} as namespace {} and waiting for peers to join us...",
                fmt_hash(topic.as_bytes())
            );
            (topic, vec![])
        }
        Command::Join { ticket } => {
            let Ticket { topic, peers } = Ticket::from_str(ticket)?;
            println!("> joining topic {topic} and connecting to {peers:?}",);
            (topic, peers)
        }
    };

    // println!("> our endpoints: {initial_endpoints:?}");
    let our_ticket = {
        // add our local endpoints to the ticket and print it for others to join
        let addrs = initial_endpoints.iter().map(|ep| ep.addr).collect();
        let mut peers = peers.clone();
        peers.push(PeerSource {
            peer_id: endpoint.peer_id(),
            addrs,
            derp_region: endpoint.my_derp().await,
        });
        Ticket { peers, topic }
    };
    println!("> ticket to join us: {our_ticket}");

    // unwrap our storage path or default to temp
    let storage_path = args.storage_path.unwrap_or_else(|| {
        let dir = format!("/tmp/iroh-example-sync-{}", endpoint.peer_id());
        let dir = PathBuf::from(dir);
        if !dir.exists() {
            std::fs::create_dir(&dir).expect("failed to create temp dir");
        }
        dir
    });
    println!("> persisting data in {storage_path:?}");

    // create a runtime
    // we need this because some things need to spawn !Send futures
    let rt = create_rt()?;
    // create the sync doc and store
    // we need to pass the runtime because a !Send task is spawned for
    // the downloader in the blob store
    let blobs = BlobStore::new(rt.clone(), storage_path.clone(), endpoint.clone()).await?;
    let (store, author, doc) =
        create_or_open_document(&storage_path, blobs.clone(), topic, &keypair).await?;

    // construct the state that is passed to the endpoint loop and from there cloned
    // into to the connection handler task for incoming connections.
    let state = Arc::new(State {
        gossip: gossip.clone(),
        replica_store: store.clone(),
        db: blobs.db().clone(),
        rt,
    });
    // spawn our endpoint loop that forwards incoming connections
    tokio::spawn(endpoint_loop(endpoint.clone(), state));

    // create the live syncer
    let sync_handle = LiveSync::spawn(endpoint.clone(), gossip.clone());
    sync_handle
        .sync_doc(doc.replica().clone(), peers.clone())
        .await?;

    // spawn an input thread that reads stdin and parses each line as a `Cmd` command
    // not using tokio here because they recommend this for "technical reasons"
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<Cmd>(1);
    std::thread::spawn(move || input_loop(cmd_tx));

    // process commands in a loop
    println!("> ready to accept commands: set <key> <value> | get <key> | ls | exit");
    loop {
        let cmd = tokio::select! {
            Some(cmd) = cmd_rx.recv() => cmd,
            _ = tokio::signal::ctrl_c() => Cmd::Exit

        };
        match cmd {
            Cmd::Set { key, value } => {
                doc.insert(&key, &author, value.into_bytes().into()).await?;
            }
            Cmd::Get { key } => {
                let entries = doc.replica().all_for_key(key.as_bytes());
                for (_id, entry) in entries {
                    let content = fmt_content(&doc, &entry).await?;
                    println!("{} -> {content}", fmt_entry(&entry),);
                }
            }
            Cmd::Ls => {
                let all = doc.replica().all();
                println!("> {} entries", all.len());
                for (_id, entry) in all {
                    println!(
                        "{} -> {}",
                        fmt_entry(&entry),
                        fmt_content(&doc, &entry).await?
                    );
                }
            }
            Cmd::Exit => {
                break;
            }
        }
    }

    let res = sync_handle.cancel().await;
    if let Err(err) = res {
        println!("> syncer closed with error: {err:?}");
    }

    println!("> persisting document and blob database at {storage_path:?}");
    blobs.save().await?;
    save_document(&storage_path, doc.replica()).await?;

    Ok(())
}

pub enum Cmd {
    Set { key: String, value: String },
    Get { key: String },
    Ls,
    Exit,
}
impl FromStr for Cmd {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(' ');
        match [parts.next(), parts.next(), parts.next()] {
            [Some("set"), Some(key), Some(value)] => Ok(Self::Set {
                key: key.into(),
                value: value.into(),
            }),
            [Some("get"), Some(key), None] => Ok(Self::Get { key: key.into() }),
            [Some("ls"), None, None] => Ok(Self::Ls),
            [Some("exit"), None, None] => Ok(Self::Exit),
            _ => Err(anyhow!("invalid command")),
        }
    }
}

async fn create_or_open_document(
    storage_path: &PathBuf,
    blobs: BlobStore,
    topic: TopicId,
    keypair: &Keypair,
) -> anyhow::Result<(ReplicaStore, Author, Doc)> {
    let author = Author::from(keypair.secret().clone());
    let namespace = Namespace::from_bytes(topic.as_bytes());
    let store = ReplicaStore::default();

    let replica_path = replica_path(storage_path, namespace.id());
    let replica = if replica_path.exists() {
        let bytes = tokio::fs::read(replica_path).await?;
        store.open_replica(&bytes)?
    } else {
        store.new_replica(namespace)
    };

    // do some logging
    replica.on_insert(Box::new(move |origin, entry| {
        println!("> insert from {origin:?}: {}", fmt_entry(&entry));
    }));

    let doc = Doc::new(replica, blobs, DownloadMode::Always);
    Ok((store, author, doc))
}

async fn save_document(base_path: &PathBuf, replica: &Replica) -> anyhow::Result<()> {
    let replica_path = replica_path(base_path, &replica.namespace());
    tokio::fs::create_dir_all(replica_path.parent().unwrap()).await?;
    let bytes = replica.to_bytes()?;
    tokio::fs::write(replica_path, bytes).await?;
    Ok(())
}

fn replica_path(storage_path: &PathBuf, namespace: &NamespaceId) -> PathBuf {
    storage_path
        .join("docs")
        .join(hex::encode(namespace.as_bytes()))
}

#[derive(Debug)]
struct State {
    rt: iroh_bytes::runtime::Handle,
    gossip: GossipHandle,
    replica_store: ReplicaStore,
    db: Database,
}

async fn endpoint_loop(endpoint: MagicEndpoint, state: Arc<State>) -> anyhow::Result<()> {
    while let Some(conn) = endpoint.accept().await {
        // spawn a new task for each incoming connection.
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(conn, state).await {
                println!("> connection closed, reason: {err}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(mut conn: quinn::Connecting, state: Arc<State>) -> anyhow::Result<()> {
    let alpn = get_alpn(&mut conn).await?;
    println!("> incoming connection with alpn {alpn}");
    match alpn.as_bytes() {
        GOSSIP_ALPN => state.gossip.handle_connection(conn.await?).await,
        SYNC_ALPN => iroh::sync::handle_connection(conn, state.replica_store.clone()).await,
        alpn if alpn == iroh_bytes::protocol::ALPN => {
            handle_iroh_byes_connection(conn, state).await
        }
        _ => bail!("ignoring connection: unsupported ALPN protocol"),
    }
}

async fn handle_iroh_byes_connection(
    conn: quinn::Connecting,
    state: Arc<State>,
) -> anyhow::Result<()> {
    use iroh_bytes::{
        protocol::{GetRequest, RequestToken},
        provider::{
            CustomGetHandler, EventSender, IrohCollectionParser, RequestAuthorizationHandler,
        },
    };
    iroh_bytes::provider::handle_connection(
        conn,
        state.db.clone(),
        NoopEventSender,
        IrohCollectionParser,
        Arc::new(NoopCustomGetHandler),
        Arc::new(NoopRequestAuthorizationHandler),
        state.rt.clone(),
    )
    .await;

    #[derive(Debug, Clone)]
    struct NoopEventSender;
    impl EventSender for NoopEventSender {
        fn send(&self, _event: iroh_bytes::provider::Event) -> Option<iroh_bytes::provider::Event> {
            None
        }
    }
    #[derive(Debug)]
    struct NoopCustomGetHandler;
    impl CustomGetHandler for NoopCustomGetHandler {
        fn handle(
            &self,
            _token: Option<RequestToken>,
            _request: Bytes,
        ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
            async move { Err(anyhow::anyhow!("no custom get handler defined")) }.boxed()
        }
    }
    #[derive(Debug)]
    struct NoopRequestAuthorizationHandler;
    impl RequestAuthorizationHandler for NoopRequestAuthorizationHandler {
        fn authorize(
            &self,
            token: Option<RequestToken>,
            _request: &iroh_bytes::protocol::Request,
        ) -> BoxFuture<'static, anyhow::Result<()>> {
            async move {
                if let Some(token) = token {
                    anyhow::bail!(
                        "no authorization handler defined, but token was provided: {:?}",
                        token
                    );
                }
                Ok(())
            }
            .boxed()
        }
    }
    Ok(())
}

fn create_rt() -> anyhow::Result<iroh::bytes::runtime::Handle> {
    let rt = iroh::bytes::runtime::Handle::from_currrent(num_cpus::get())?;
    Ok(rt)
}

fn input_loop(line_tx: tokio::sync::mpsc::Sender<Cmd>) -> anyhow::Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        stdin.read_line(&mut buffer)?;
        let cmd = match Cmd::from_str(buffer.trim()) {
            Ok(cmd) => cmd,
            Err(err) => {
                println!("> failed to parse command: {}", err);
                continue;
            }
        };
        line_tx.blocking_send(cmd)?;
        buffer.clear();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    peers: Vec<PeerSource>,
}
impl Ticket {
    /// Deserializes from bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(Into::into)
    }
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
}

/// Serializes to base32.
impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = self.to_bytes();
        let mut text = data_encoding::BASE32_NOPAD.encode(&encoded);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let slf = Self::from_bytes(&bytes)?;
        Ok(slf)
    }
}

// helpers

fn fmt_entry(entry: &SignedEntry) -> String {
    let id = entry.entry().id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.entry().record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    format!("@{author}: {key} = {hash}")
}
async fn fmt_content(doc: &Doc, entry: &SignedEntry) -> anyhow::Result<String> {
    let content = match doc.get_content(entry).await {
        None => "<missing content>".to_string(),
        Some(content) => match String::from_utf8(content.into()) {
            Ok(str) => str,
            Err(_err) => "<invalid utf8>".to_string(),
        },
    };
    Ok(content)
}
fn fmt_hash(hash: &[u8]) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(hash);
    text.make_ascii_lowercase();
    format!("{}…{}", &text[..5], &text[(text.len() - 2)..])
}
fn fmt_secret(keypair: &Keypair) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&keypair.secret().to_bytes());
    text.make_ascii_lowercase();
    text
}
fn parse_keypair(secret: &str) -> anyhow::Result<Keypair> {
    let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
    let key = SigningKey::from_bytes(&bytes);
    Ok(key.into())
}
fn fmt_derp_map(derp_map: &Option<DerpMap>) -> String {
    match derp_map {
        None => "None".to_string(),
        Some(map) => {
            let regions = map.regions.iter().map(|(id, region)| {
                let nodes = region.nodes.iter().map(|node| node.url.to_string());
                (*id, nodes.collect::<Vec<_>>())
            });
            format!("{:?}", regions.collect::<Vec<_>>())
        }
    }
}
fn derp_map_from_url(url: Url) -> anyhow::Result<DerpMap> {
    Ok(DerpMap::default_from_node(
        url,
        DEFAULT_DERP_STUN_PORT,
        UseIpv4::TryDns,
        UseIpv6::TryDns,
        0
    ))
}
