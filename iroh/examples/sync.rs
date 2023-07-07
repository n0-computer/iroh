//! Live edit a p2p document
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--private-key` CLI flag with the private key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.

use std::{fmt, str::FromStr};

use anyhow::{anyhow, bail};
use clap::Parser;
use ed25519_dalek::SigningKey;
use iroh::sync::{LiveSync, PeerSource, SYNC_ALPN};
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
use iroh_sync::sync::{Author, Namespace, Replica, ReplicaStore, SignedEntry};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;

#[derive(Parser, Debug)]
struct Args {
    /// Private key to derive our peer id from
    #[clap(long)]
    private_key: Option<String>,
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
            .alpns(vec![GOSSIP_ALPN.to_vec(), SYNC_ALPN.to_vec()])
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

    // create the sync doc and store
    let (store, author, doc) = create_document(topic, &keypair)?;

    // spawn our endpoint loop that forwards incoming connections
    tokio::spawn(endpoint_loop(
        endpoint.clone(),
        gossip.clone(),
        store.clone(),
    ));

    // spawn an input thread that reads stdin
    // not using tokio here because they recommend this for "technical reasons"
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(1);
    std::thread::spawn(move || input_loop(line_tx));

    // create the live syncer
    let sync_handle = LiveSync::spawn(endpoint.clone(), gossip.clone());
    sync_handle.sync_doc(doc.clone(), peers.clone()).await?;

    // do some logging
    doc.on_insert(Box::new(move |origin, entry| {
        println!("> insert from {origin:?}: {}", fmt_entry(&entry));
    }));

    // process stdin lines
    println!("> read to accept commands: set <key> <value> | get <key> | ls | exit");
    while let Some(text) = line_rx.recv().await {
        let cmd = match Cmd::from_str(&text) {
            Ok(cmd) => cmd,
            Err(err) => {
                println!("> failed to parse command: {}", err);
                continue;
            }
        };
        match cmd {
            Cmd::Set { key, value } => {
                doc.insert(&key, &author, value);
            }
            Cmd::Get { key } => {
                let mut entries = doc
                    .all()
                    .into_iter()
                    .filter_map(|(id, entry)| (id.key() == key.as_bytes()).then(|| entry));
                while let Some(entry) = entries.next() {
                    println!("{} -> {}", fmt_entry(&entry), fmt_content(&doc, &entry));
                }
            }
            Cmd::Ls => {
                let all = doc.all();
                println!("> {} entries", all.len());
                for (_id, entry) in all {
                    println!("{} -> {}", fmt_entry(&entry), fmt_content(&doc, &entry));
                }
            }
            Cmd::Exit => {
                let res = sync_handle.cancel().await?;
                println!("syncer closed with {res:?}");
                break;
            }
        }
    }

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

fn create_document(
    topic: TopicId,
    keypair: &Keypair,
) -> anyhow::Result<(ReplicaStore, Author, Replica)> {
    let author = Author::from(keypair.secret().clone());
    let namespace = Namespace::from_bytes(topic.as_bytes());
    let store = ReplicaStore::default();
    let doc = store.new_replica(namespace);
    Ok((store, author, doc))
}

async fn endpoint_loop(
    endpoint: MagicEndpoint,
    gossip: GossipHandle,
    replica_store: ReplicaStore,
) -> anyhow::Result<()> {
    while let Some(mut conn) = endpoint.accept().await {
        let alpn = get_alpn(&mut conn).await?;
        println!("> incoming connection with alpn {alpn}");
        // let (peer_id, alpn, conn) = accept_conn(conn).await?;
        let res = match alpn.as_bytes() {
            GOSSIP_ALPN => gossip.handle_connection(conn.await?).await,
            SYNC_ALPN => iroh::sync::handle_connection(conn, replica_store.clone()).await,
            _ => Err(anyhow::anyhow!(
                "ignoring connection: unsupported ALPN protocol"
            )),
        };
        if let Err(err) = res {
            println!("> connection for {alpn} closed, reason: {err}");
        }
    }
    Ok(())
}

fn input_loop(line_tx: tokio::sync::mpsc::Sender<String>) -> anyhow::Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin(); // We get `Stdin` here.
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.trim().to_string())?;
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
fn fmt_content(doc: &Replica, entry: &SignedEntry) -> String {
    let hash = entry.entry().record().content_hash();
    let content = doc.get_content(hash);
    let content = content
        .map(|content| String::from_utf8(content.into()).unwrap_or_else(|_| "<bad content>".into()))
        .unwrap_or_else(|| "<missing content>".into());
    content
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
