//! Live edit a p2p document
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--private-key` CLI flag with the private key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.

use std::{collections::HashSet, fmt, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{anyhow, bail};
use clap::{CommandFactory, FromArgMatches, Parser};
use ed25519_dalek::SigningKey;
use indicatif::HumanBytes;
use iroh::sync::{BlobStore, Doc, DocStore, DownloadMode, LiveSync, PeerSource, SYNC_ALPN};
use iroh_bytes_handlers::IrohBytesHandlers;
use iroh_gossip::{
    net::{GossipHandle, GOSSIP_ALPN},
    proto::TopicId,
};
use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};
use iroh_net::{
    defaults::{default_derp_map, DEFAULT_DERP_STUN_PORT},
    derp::{DerpMap, UseIpv4, UseIpv6},
    magic_endpoint::get_alpn,
    tls::Keypair,
    MagicEndpoint,
};
use iroh_sync::sync::{Author, Namespace, SignedEntry};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
};
use tracing::warn;
use tracing_subscriber::{EnvFilter, Registry};
use url::Url;

const MAX_DISPLAY_CONTENT_LEN: u64 = 1024 * 1024;

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
    /// Bind address on which to serve Prometheus metrics
    #[clap(long)]
    metrics_addr: Option<SocketAddr>,
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
    let args = Args::parse();
    run(args).await
}

pub fn init_metrics_collection(
    metrics_addr: Option<SocketAddr>,
) -> Option<tokio::task::JoinHandle<()>> {
    iroh_metrics::core::Core::init(|reg, metrics| {
        metrics.insert(iroh::sync::metrics::Metrics::new(reg));
        metrics.insert(iroh_gossip::metrics::Metrics::new(reg));
    });

    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        return Some(tokio::spawn(async move {
            if let Err(e) = iroh_metrics::metrics::start_metrics_server(metrics_addr).await {
                eprintln!("Failed to start metrics server: {e}");
            }
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}

async fn run(args: Args) -> anyhow::Result<()> {
    // setup logging
    let log_filter = init_logging();

    let metrics_fut = init_metrics_collection(args.metrics_addr);

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

    // build our magic endpoint and the gossip protocol
    let (endpoint, gossip, initial_endpoints) = {
        // init a cell that will hold our gossip handle to be used in endpoint callbacks
        let gossip_cell: OnceCell<GossipHandle> = OnceCell::new();
        // init a channel that will emit once the initial endpoints of our local node are discovered
        let (initial_endpoints_tx, mut initial_endpoints_rx) = mpsc::channel(1);
        // build the magic endpoint
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

        // initialize the gossip protocol
        let gossip = GossipHandle::from_endpoint(endpoint.clone(), Default::default());
        // insert into the gossip cell to be used in the endpoint callbacks above
        gossip_cell.set(gossip.clone()).unwrap();

        // wait for a first endpoint update so that we know about at least one of our addrs
        let initial_endpoints = initial_endpoints_rx.recv().await.unwrap();
        // pass our initial endpoints to the gossip protocol so that they can be announced to peers
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
        let name = format!("iroh-sync-{}", endpoint.peer_id());
        let dir = std::env::temp_dir().join(name);
        if !dir.exists() {
            std::fs::create_dir(&dir).expect("failed to create temp dir");
        }
        dir
    });
    println!("> storage directory: {storage_path:?}");

    // create a runtime that can spawn tasks on a local-thread executors (to support !Send futures)
    let rt = iroh_bytes::util::runtime::Handle::from_currrent(num_cpus::get())?;

    // create a blob store (with a iroh-bytes database inside)
    let blobs = BlobStore::new(rt.clone(), storage_path.join("blobs"), endpoint.clone()).await?;

    // create a doc store for the iroh-sync docs
    let author = Author::from(keypair.secret().clone());
    let docs = DocStore::new(blobs.clone(), author, storage_path.join("docs"));

    // create the live syncer
    let live_sync = LiveSync::spawn(endpoint.clone(), gossip.clone());

    // construct the state that is passed to the endpoint loop and from there cloned
    // into to the connection handler task for incoming connections.
    let state = Arc::new(State {
        gossip: gossip.clone(),
        docs: docs.clone(),
        bytes: IrohBytesHandlers::new(rt.clone(), blobs.db().clone()),
    });

    // spawn our endpoint loop that forwards incoming connections
    tokio::spawn(endpoint_loop(endpoint.clone(), state));

    // open our document and add to the live syncer
    let namespace = Namespace::from_bytes(topic.as_bytes());
    println!("> opening doc {}", fmt_hash(namespace.id().as_bytes()));
    let doc = docs.create_or_open(namespace, DownloadMode::Always).await?;
    live_sync.add(doc.replica().clone(), peers.clone()).await?;

    // spawn an repl thread that reads stdin and parses each line as a `Cmd` command
    let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
    std::thread::spawn(move || repl_loop(cmd_tx).expect("input loop crashed"));
    // process commands in a loop
    println!("> ready to accept commands");
    println!("> type `help` for a list of commands");

    let current_watch: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let watch = current_watch.clone();
    doc.on_insert(Box::new(move |_origin, entry| {
        let matcher = watch.lock().unwrap();
        if let Some(matcher) = &*matcher {
            let key = entry.entry().id().key();
            if key.starts_with(matcher.as_bytes()) {
                println!("change: {}", fmt_entry(&entry));
            }
        }
    }));

    loop {
        // wait for a command from the input repl thread
        let Some((cmd, to_repl_tx)) = cmd_rx.recv().await else {
            break;
        };
        // exit command: break early
        if let Cmd::Exit = cmd {
            to_repl_tx.send(ToRepl::Exit).ok();
            break;
        }

        // handle the command, but select against Ctrl-C signal so that commands can be aborted
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                println!("> aborted");
            }
            res = handle_command(cmd, &doc, &our_ticket, &log_filter, &current_watch) => if let Err(err) = res {
                println!("> error: {err}");
            },
        };
        // notify to the repl that we want to get the next command
        to_repl_tx.send(ToRepl::Continue).ok();
    }

    // exit: cancel the sync and store blob database and document
    if let Err(err) = live_sync.cancel().await {
        println!("> syncer closed with error: {err:?}");
    }
    println!("> persisting document and blob database at {storage_path:?}");
    blobs.save().await?;
    docs.save(&doc).await?;

    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
        drop(metrics_fut);
    }

    Ok(())
}

async fn handle_command(
    cmd: Cmd,
    doc: &Doc,
    ticket: &Ticket,
    log_filter: &LogLevelReload,
    current_watch: &Arc<std::sync::Mutex<Option<String>>>,
) -> anyhow::Result<()> {
    match cmd {
        Cmd::Set { key, value } => {
            doc.insert_bytes(&key, value.into_bytes().into()).await?;
        }
        Cmd::Get { key, print_content } => {
            let entries = doc.replica().all_for_key(key.as_bytes());
            for (_id, entry) in entries {
                println!("{}", fmt_entry(&entry));
                if print_content {
                    println!("{}", fmt_content(doc, &entry).await);
                }
            }
        }
        Cmd::Watch { key } => {
            println!("watching key: '{key}'");
            current_watch.lock().unwrap().replace(key);
        }
        Cmd::WatchCancel => match current_watch.lock().unwrap().take() {
            Some(key) => {
                println!("canceled watching key: '{key}'");
            }
            None => {
                println!("no watch active");
            }
        },
        Cmd::Ls { prefix } => {
            let entries = match prefix {
                None => doc.replica().all(),
                Some(prefix) => doc.replica().all_with_key_prefix(prefix.as_bytes()),
            };
            println!("> {} entries", entries.len());
            for (_id, entry) in entries {
                println!("{}", fmt_entry(&entry),);
            }
        }
        Cmd::Ticket => {
            println!("Ticket: {ticket}");
        }
        Cmd::Log { directive } => {
            let next_filter = EnvFilter::from_str(&directive)?;
            log_filter.modify(|layer| *layer = next_filter)?;
        }
        Cmd::Stats => get_stats(),
        Cmd::Fs(cmd) => handle_fs_command(cmd, doc).await?,
        Cmd::Hammer {
            prefix,
            count,
            size,
        } => {
            println!(
                "> hammering with prefix {prefix} for {count} messages of size {size} bytes",
                prefix = prefix,
                count = count,
                size = size,
            );
            let mut bytes = vec![0; size];
            bytes.fill(97);
            for i in 0..count {
                let value = String::from_utf8(bytes.clone())?;
                let key = format!("{}/{}", prefix, i);
                doc.insert_bytes(key, value.into_bytes().into()).await?;
            }
        }
        Cmd::Exit => {}
    }
    Ok(())
}

async fn handle_fs_command(cmd: FsCmd, doc: &Doc) -> anyhow::Result<()> {
    match cmd {
        FsCmd::ImportFile { file_path, key } => {
            let file_path = canonicalize_path(&file_path)?.canonicalize()?;
            let (hash, len) = doc.insert_from_file(&key, &file_path).await?;
            println!(
                "> imported {file_path:?}: {} ({})",
                fmt_hash(hash),
                HumanBytes(len)
            );
        }
        FsCmd::ImportDir {
            dir_path,
            mut key_prefix,
        } => {
            if key_prefix.ends_with("/") {
                key_prefix.pop();
            }
            let root = canonicalize_path(&dir_path)?.canonicalize()?;
            let files = walkdir::WalkDir::new(&root).into_iter();
            // TODO: parallelize
            for file in files {
                let file = file?;
                if file.file_type().is_file() {
                    let relative = file.path().strip_prefix(&root)?.to_string_lossy();
                    if relative.is_empty() {
                        warn!("invalid file path: {:?}", file.path());
                        continue;
                    }
                    let key = format!("{key_prefix}/{relative}");
                    let (hash, len) = doc.insert_from_file(key, file.path()).await?;
                    println!(
                        "> imported {relative}: {} ({})",
                        fmt_hash(hash),
                        HumanBytes(len)
                    );
                }
            }
        }
        FsCmd::ExportDir {
            mut key_prefix,
            dir_path,
        } => {
            if !key_prefix.ends_with("/") {
                key_prefix.push('/');
            }
            let root = canonicalize_path(&dir_path)?;
            println!("> exporting {key_prefix} to {root:?}");
            let entries = doc.replica().get_latest_by_prefix(key_prefix.as_bytes());
            let mut checked_dirs = HashSet::new();
            for entry in entries {
                let key = entry.entry().id().key();
                let relative = String::from_utf8(key[key_prefix.len()..].to_vec())?;
                let len = entry.entry().record().content_len();
                if let Some(mut reader) = doc.get_content_reader(&entry).await {
                    let path = root.join(&relative);
                    let parent = path.parent().unwrap();
                    if !checked_dirs.contains(parent) {
                        tokio::fs::create_dir_all(&parent).await?;
                        checked_dirs.insert(parent.to_owned());
                    }
                    let mut file = tokio::fs::File::create(&path).await?;
                    copy(&mut reader, &mut file).await?;
                    println!(
                        "> exported {} to {path:?} ({})",
                        fmt_hash(entry.content_hash()),
                        HumanBytes(len)
                    );
                }
            }
        }
        FsCmd::ExportFile { key, file_path } => {
            let path = canonicalize_path(&file_path)?;
            // TODO: Fix
            let entry = doc.replica().get_latest_by_key(&key).next();
            if let Some(entry) = entry {
                println!("> exporting {key} to {path:?}");
                let parent = path.parent().ok_or_else(|| anyhow!("Invalid path"))?;
                tokio::fs::create_dir_all(&parent).await?;
                let mut file = tokio::fs::File::create(&path).await?;
                let mut reader = doc
                    .get_content_reader(&entry)
                    .await
                    .ok_or_else(|| anyhow!(format!("content for {key} is not available")))?;
                copy(&mut reader, &mut file).await?;
            } else {
                println!("> key not found, abort");
            }
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
pub enum Cmd {
    /// Set an entry
    Set {
        /// Key to the entry (parsed as UTF-8 string).
        key: String,
        /// Content to store for this entry (parsed as UTF-8 string)
        value: String,
    },
    /// Get entries by key
    ///
    /// Shows the author, content hash and content length for all entries for this key.
    Get {
        /// Key to the entry (parsed as UTF-8 string).
        key: String,
        /// Print the value (but only if it is valid UTF-8 and smaller than 1MB)
        #[clap(short = 'c', long)]
        print_content: bool,
    },
    /// List entries.
    Ls {
        /// Optionally list only entries whose key starts with PREFIX.
        prefix: Option<String>,
    },

    /// Import from and export to the local file system.
    #[clap(subcommand)]
    Fs(FsCmd),

    /// Print the ticket with which other peers can join our document.
    Ticket,
    /// Change the log level
    Log {
        /// The log level or log filtering directive
        ///
        /// Valid log levels are: "trace", "debug", "info", "warn", "error"
        ///
        /// You can also set one or more filtering directives to enable more fine-grained log
        /// filtering. The supported filtering directives and their semantics are documented here:
        /// https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
        ///
        /// To disable logging completely, set to the empty string (via empty double quotes: "").
        #[clap(verbatim_doc_comment)]
        directive: String,
    },
    /// Watch for changes.
    Watch {
        /// The key to watch.
        key: String,
    },
    /// Cancels any running watch command.
    WatchCancel,
    /// Show stats about the current session
    Stats,
    /// Stress test with the hammer
    Hammer {
        /// The key prefix
        prefix: String,
        /// The number of entries to create
        count: usize,
        /// The size of each entry in Bytes
        size: usize,
    },
    /// Quit
    Exit,
}

#[derive(Parser, Debug)]
pub enum FsCmd {
    /// Import a file system directory into the document.
    ImportDir {
        /// The file system path to import recursively
        dir_path: String,
        /// The key prefix to apply to the document keys
        key_prefix: String,
    },
    /// Import a file into the document.
    ImportFile {
        /// The path to the file
        file_path: String,
        /// The key in the document
        key: String,
    },
    /// Export a part of the document into a file system directory
    ExportDir {
        /// The key prefix to filter on
        key_prefix: String,
        /// The file system path to export to
        dir_path: String,
    },
    /// Import a file into the document.
    ExportFile {
        /// The key in the document
        key: String,
        /// The path to the file
        file_path: String,
    },
}

impl FromStr for Cmd {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let args = shell_words::split(s)?;
        let matches = Cmd::command()
            .multicall(true)
            .subcommand_required(true)
            .try_get_matches_from(args)?;
        let cmd = Cmd::from_arg_matches(&matches)?;
        Ok(cmd)
    }
}

#[derive(Debug)]
struct State {
    gossip: GossipHandle,
    docs: DocStore,
    bytes: IrohBytesHandlers,
}

async fn endpoint_loop(endpoint: MagicEndpoint, state: Arc<State>) -> anyhow::Result<()> {
    while let Some(conn) = endpoint.accept().await {
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
        SYNC_ALPN => state.docs.handle_connection(conn).await,
        alpn if alpn == iroh_bytes::protocol::ALPN => state.bytes.handle_connection(conn).await,
        _ => bail!("ignoring connection: unsupported ALPN protocol"),
    }
}

#[derive(Debug)]
enum ToRepl {
    Continue,
    Exit,
}

fn repl_loop(cmd_tx: mpsc::Sender<(Cmd, oneshot::Sender<ToRepl>)>) -> anyhow::Result<()> {
    use rustyline::{error::ReadlineError, Config, DefaultEditor};
    let mut rl = DefaultEditor::with_config(Config::builder().check_cursor_position(true).build())?;
    loop {
        // prepare a channel to receive a signal from the main thread when a command completed
        let (to_repl_tx, to_repl_rx) = oneshot::channel();
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) if line.is_empty() => continue,
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                match Cmd::from_str(&line) {
                    Ok(cmd) => cmd_tx.blocking_send((cmd, to_repl_tx))?,
                    Err(err) => {
                        println!("{err}");
                        continue;
                    }
                };
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                cmd_tx.blocking_send((Cmd::Exit, to_repl_tx))?;
            }
            Err(ReadlineError::WindowResized) => continue,
            Err(err) => return Err(err.into()),
        }
        // wait for reply from main thread
        match to_repl_rx.blocking_recv()? {
            ToRepl::Continue => continue,
            ToRepl::Exit => break,
        }
    }
    Ok(())
}

fn get_stats() {
    let core = iroh_metrics::core::Core::get().expect("Metrics core not initialized");
    println!("# sync");
    let metrics = core
        .get_collector::<iroh::sync::metrics::Metrics>()
        .unwrap();
    fmt_metrics(metrics);
    println!("# gossip");
    let metrics = core
        .get_collector::<iroh_gossip::metrics::Metrics>()
        .unwrap();
    fmt_metrics(metrics);
}

fn fmt_metrics(metrics: &impl Iterable) {
    for (name, counter) in metrics.iter() {
        if let Some(counter) = counter.downcast_ref::<Counter>() {
            let value = counter.get();
            println!("{name:23} : {value:>6}    ({})", counter.description);
        } else {
            println!("{name:23} : unsupported metric kind");
        }
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

type LogLevelReload = tracing_subscriber::reload::Handle<EnvFilter, Registry>;
fn init_logging() -> LogLevelReload {
    use tracing_subscriber::{filter, fmt, prelude::*, reload};
    let filter = filter::EnvFilter::from_default_env();
    let (filter, reload_handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::Layer::default())
        .init();
    reload_handle
}

// helpers

fn fmt_entry(entry: &SignedEntry) -> String {
    let id = entry.entry().id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.entry().record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.entry().record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}
async fn fmt_content(doc: &Doc, entry: &SignedEntry) -> String {
    let len = entry.entry().record().content_len();
    if len > MAX_DISPLAY_CONTENT_LEN {
        format!("<{}>", HumanBytes(len))
    } else {
        match doc.get_content_bytes(entry).await {
            None => "<missing content>".to_string(),
            Some(content) => match String::from_utf8(content.into()) {
                Ok(str) => str,
                Err(_err) => format!("<invalid utf8 {}>", HumanBytes(len)),
            },
        }
    }
}
fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(hash.as_ref());
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
        0,
    ))
}

fn canonicalize_path(path: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(shellexpand::tilde(&path).to_string());
    Ok(path)
}

/// Copy from a [`iroh_io::AsyncSliceReader`] into a [`tokio::io::AsyncWrite`]
///
/// TODO: move to iroh-io or iroh-bytes
async fn copy(
    mut reader: impl iroh_io::AsyncSliceReader,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
) -> anyhow::Result<()> {
    // this is the max chunk size.
    // will only allocate this much if the resource behind the reader is at least this big.
    let chunk_size = 1024 * 16;
    let mut pos = 0u64;
    loop {
        let chunk = reader.read_at(pos, chunk_size).await?;
        if chunk.is_empty() {
            break;
        }
        writer.write_all(&chunk).await?;
        pos += chunk.len() as u64;
    }
    Ok(())
}

/// handlers for iroh_bytes connections
mod iroh_bytes_handlers {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::{future::BoxFuture, FutureExt};
    use iroh_bytes::{
        protocol::{GetRequest, RequestToken},
        provider::{CustomGetHandler, EventSender, RequestAuthorizationHandler},
    };

    use iroh::{collection::IrohCollectionParser, database::flat::Database};

    #[derive(Debug, Clone)]
    pub struct IrohBytesHandlers {
        db: Database,
        rt: iroh_bytes::util::runtime::Handle,
        event_sender: NoopEventSender,
        get_handler: Arc<NoopCustomGetHandler>,
        auth_handler: Arc<NoopRequestAuthorizationHandler>,
    }
    impl IrohBytesHandlers {
        pub fn new(rt: iroh_bytes::util::runtime::Handle, db: Database) -> Self {
            Self {
                db,
                rt,
                event_sender: NoopEventSender,
                get_handler: Arc::new(NoopCustomGetHandler),
                auth_handler: Arc::new(NoopRequestAuthorizationHandler),
            }
        }
        pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
            iroh_bytes::provider::handle_connection(
                conn,
                self.db.clone(),
                self.event_sender.clone(),
                IrohCollectionParser,
                self.get_handler.clone(),
                self.auth_handler.clone(),
                self.rt.clone(),
            )
            .await;
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct NoopEventSender;
    impl EventSender for NoopEventSender {
        fn send(&self, _event: iroh_bytes::provider::Event) -> BoxFuture<()> {
            async {}.boxed()
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
}
