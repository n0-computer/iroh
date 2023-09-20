//! Live edit a p2p document
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--secret-key` CLI flag with the secret key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.

use std::{
    collections::HashSet, fmt, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, bail};
use bytes::Bytes;
use clap::{CommandFactory, FromArgMatches, Parser};
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::{
    downloader::Downloader,
    sync_engine::{LiveEvent, PeerSource, SyncEngine, SYNC_ALPN},
};
use iroh_bytes::util::runtime;
use iroh_bytes::{
    baomap::{ImportMode, Map, MapEntry, Store as BaoStore},
    util::progress::IgnoreProgressSender,
};
use iroh_gossip::{
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use iroh_io::AsyncSliceReaderExt;
use iroh_net::{
    defaults::default_derp_map, derp::DerpMap, key::SecretKey, magic_endpoint::get_alpn,
    MagicEndpoint,
};
use iroh_sync::{
    store::{self, GetFilter, Store as _},
    sync::{Author, Entry, Namespace, Replica, SignedEntry},
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::warn;
use tracing_subscriber::{EnvFilter, Registry};
use url::Url;

use iroh_bytes_handlers::IrohBytesHandlers;

const MAX_DISPLAY_CONTENT_LEN: u64 = 1024 * 1024;

type Doc = Replica<<store::fs::Store as store::Store>::Instance>;

#[derive(Parser, Debug)]
struct Args {
    /// Secret key for this node
    #[clap(long)]
    secret_key: Option<String>,
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
    iroh::metrics::try_init_metrics_collection().ok();
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

    // parse or generate our secret_key
    let secret_key = match args.secret_key {
        None => SecretKey::generate(),
        Some(key) => SecretKey::from_str(&key)?,
    };
    println!("> our secret key: {}", secret_key);

    // configure our derp map
    let derp_map = match (args.no_derp, args.derp) {
        (false, None) => Some(default_derp_map()),
        (false, Some(url)) => Some(DerpMap::from_url(url, 0)),
        (true, None) => None,
        (true, Some(_)) => bail!("You cannot set --no-derp and --derp at the same time"),
    };
    println!("> using DERP servers: {}", fmt_derp_map(&derp_map));

    // build our magic endpoint and the gossip protocol
    let (endpoint, gossip, initial_endpoints) = {
        // init a cell that will hold our gossip handle to be used in endpoint callbacks
        let gossip_cell: OnceCell<Gossip> = OnceCell::new();
        // init a channel that will emit once the initial endpoints of our local node are discovered
        let (initial_endpoints_tx, mut initial_endpoints_rx) = mpsc::channel(1);
        // build the magic endpoint
        let endpoint = MagicEndpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![
                GOSSIP_ALPN.to_vec(),
                SYNC_ALPN.to_vec(),
                iroh_bytes::protocol::ALPN.to_vec(),
            ])
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
            });
        let endpoint = match derp_map {
            Some(derp_map) => endpoint.enable_derp(derp_map),
            None => endpoint,
        };
        let endpoint = endpoint.bind(args.bind_port).await?;

        // initialize the gossip protocol
        let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default());
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
            let topic: TopicId = iroh_bytes::Hash::new(doc_name.as_bytes()).into();
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
            std::fs::create_dir_all(&dir).expect("failed to create temp dir");
        }
        dir
    });
    println!("> storage directory: {storage_path:?}");

    // create a runtime that can spawn tasks on a local-thread executors (to support !Send futures)
    let rt = iroh_bytes::util::runtime::Handle::from_current(num_cpus::get())?;

    // create a doc store for the iroh-sync docs
    let author = Author::from_bytes(&secret_key.to_bytes());
    let docs_path = storage_path.join("docs.db");
    let docs = iroh_sync::store::fs::Store::new(&docs_path)?;

    // create a bao store for the iroh-bytes blobs
    let blob_path = storage_path.join("blobs");
    std::fs::create_dir_all(&blob_path)?;
    let db = iroh::baomap::flat::Store::load(&blob_path, &blob_path, &blob_path, &rt).await?;

    let collection_parser = iroh::collection::IrohCollectionParser;

    // create the live syncer
    let downloader =
        Downloader::new(db.clone(), collection_parser, endpoint.clone(), rt.clone()).await;
    let live_sync = SyncEngine::spawn(
        rt.clone(),
        endpoint.clone(),
        gossip.clone(),
        docs.clone(),
        db.clone(),
        downloader,
    );

    // construct the state that is passed to the endpoint loop and from there cloned
    // into to the connection handler task for incoming connections.
    let state = Arc::new(State {
        gossip: gossip.clone(),
        docs: docs.clone(),
        bytes: IrohBytesHandlers::new(rt.clone(), db.clone()),
    });

    // spawn our endpoint loop that forwards incoming connections
    rt.main().spawn(endpoint_loop(endpoint.clone(), state));

    // open our document and add to the live syncer
    let namespace = Namespace::from_bytes(topic.as_bytes());
    println!("> opening doc {}", fmt_hash(namespace.id().as_bytes()));
    let doc = match docs.open_replica(&namespace.id()) {
        Ok(Some(doc)) => doc,
        Err(_) | Ok(None) => docs.new_replica(namespace)?,
    };
    live_sync.start_sync(doc.namespace(), peers.clone()).await?;

    // spawn an repl thread that reads stdin and parses each line as a `Cmd` command
    let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
    std::thread::spawn(move || repl_loop(cmd_tx).expect("input loop crashed"));
    // process commands in a loop
    println!("> ready to accept commands");
    println!("> type `help` for a list of commands");

    let current_watch: Arc<tokio::sync::Mutex<Option<String>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let watch = current_watch.clone();
    let mut doc_events = live_sync
        .doc_subscribe(iroh::rpc_protocol::DocSubscribeRequest {
            doc_id: doc.namespace(),
        })
        .await;
    rt.main().spawn(async move {
        while let Some(Ok(event)) = doc_events.next().await {
            let matcher = watch.lock().await;
            if let Some(matcher) = &*matcher {
                match event.event {
                    LiveEvent::ContentReady { .. } => {}
                    LiveEvent::InsertLocal { entry } | LiveEvent::InsertRemote { entry, .. } => {
                        let key = entry.id().key();
                        if key.starts_with(matcher.as_bytes()) {
                            println!("change: {}", fmt_entry(&entry));
                        }
                    }
                }
            }
        }
    });

    let repl_state = ReplState {
        rt,
        store: docs,
        author,
        doc,
        db,
        ticket: our_ticket,
        log_filter,
        current_watch,
    };

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
            res = repl_state.handle_command(cmd) => if let Err(err) = res {
                println!("> error: {err}");
            },
        };
        // notify to the repl that we want to get the next command
        to_repl_tx.send(ToRepl::Continue).ok();
    }

    // exit: cancel the sync and store blob database and document
    if let Err(err) = live_sync.shutdown().await {
        println!("> syncer closed with error: {err:?}");
    }
    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
        drop(metrics_fut);
    }

    Ok(())
}

struct ReplState {
    rt: runtime::Handle,
    store: store::fs::Store,
    author: Author,
    doc: Doc,
    db: iroh::baomap::flat::Store,
    ticket: Ticket,
    log_filter: LogLevelReload,
    current_watch: Arc<tokio::sync::Mutex<Option<String>>>,
}

impl ReplState {
    async fn handle_command(&self, cmd: Cmd) -> anyhow::Result<()> {
        match cmd {
            Cmd::Set { key, value } => {
                let value = value.into_bytes();
                let len = value.len();
                let hash = self.db.import_bytes(value.into(), Format::Blob).await?;
                self.doc.insert(key, &self.author, hash, len as u64)?;
            }
            Cmd::Get {
                key,
                print_content,
                prefix,
            } => {
                let entries = if prefix {
                    self.store.get_many(
                        self.doc.namespace(),
                        GetFilter::Prefix(key.as_bytes().to_vec()),
                    )?
                } else {
                    self.store.get_many(
                        self.doc.namespace(),
                        GetFilter::Key(key.as_bytes().to_vec()),
                    )?
                };
                for entry in entries {
                    let entry = entry?;
                    println!("{}", fmt_entry(entry.entry()));
                    if print_content {
                        println!("{}", fmt_content(&self.db, &entry).await);
                    }
                }
            }
            Cmd::Watch { key } => {
                println!("watching key: '{key}'");
                self.current_watch.lock().await.replace(key);
            }
            Cmd::WatchCancel => match self.current_watch.lock().await.take() {
                Some(key) => {
                    println!("canceled watching key: '{key}'");
                }
                None => {
                    println!("no watch active");
                }
            },
            Cmd::Ls { prefix } => {
                let entries = match prefix {
                    None => self.store.get_many(self.doc.namespace(), GetFilter::All)?,
                    Some(prefix) => self.store.get_many(
                        self.doc.namespace(),
                        GetFilter::Prefix(prefix.as_bytes().to_vec()),
                    )?,
                };
                let mut count = 0;
                for entry in entries {
                    let entry = entry?;
                    count += 1;
                    println!("{}", fmt_entry(entry.entry()),);
                }
                println!("> {} entries", count);
            }
            Cmd::Ticket => {
                println!("Ticket: {}", self.ticket);
            }
            Cmd::Log { directive } => {
                let next_filter = EnvFilter::from_str(&directive)?;
                self.log_filter.modify(|layer| *layer = next_filter)?;
            }
            Cmd::Stats => get_stats(),
            Cmd::Fs(cmd) => self.handle_fs_command(cmd).await?,
            Cmd::Hammer {
                prefix,
                threads,
                count,
                size,
                mode,
            } => {
                println!(
                "> Hammering with prefix \"{prefix}\" for {threads} x {count} messages of size {size} bytes in {mode} mode",
                mode = format!("{mode:?}").to_lowercase()
            );
                let start = Instant::now();
                let mut handles: Vec<JoinHandle<anyhow::Result<usize>>> = Vec::new();
                match mode {
                    HammerMode::Set => {
                        let mut bytes = vec![0; size];
                        // TODO: Add a flag to fill content differently per entry to be able to
                        // test downloading too
                        bytes.fill(97);
                        for t in 0..threads {
                            let prefix = prefix.clone();
                            let doc = self.doc.clone();
                            let bytes = bytes.clone();
                            let db = self.db.clone();
                            let author = self.author.clone();
                            let handle = self.rt.main().spawn(async move {
                                for i in 0..count {
                                    let value =
                                        String::from_utf8(bytes.clone()).unwrap().into_bytes();
                                    let len = value.len();
                                    let key = format!("{}/{}/{}", prefix, t, i);
                                    let hash = db.import_bytes(value.into(), Format::Blob).await?;
                                    doc.insert(key, &author, hash, len as u64)?;
                                }
                                Ok(count)
                            });
                            handles.push(handle);
                        }
                    }
                    HammerMode::Get => {
                        for t in 0..threads {
                            let prefix = prefix.clone();
                            let doc = self.doc.clone();
                            let store = self.store.clone();
                            let handle = self.rt.main().spawn(async move {
                                let mut read = 0;
                                for i in 0..count {
                                    let key = format!("{}/{}/{}", prefix, t, i);
                                    let entries = store.get_many(
                                        doc.namespace(),
                                        GetFilter::Key(key.as_bytes().to_vec()),
                                    )?;
                                    for entry in entries {
                                        let entry = entry?;
                                        let _content = fmt_content_simple(&doc, &entry);
                                        read += 1;
                                    }
                                }
                                Ok(read)
                            });
                            handles.push(handle);
                        }
                    }
                }

                let mut total_count = 0;
                for result in futures::future::join_all(handles).await {
                    // Check that no errors ocurred and count rows inserted/read
                    total_count += result??;
                }

                let diff = start.elapsed().as_secs_f64();
                println!(
                "> Hammering done in {diff:.2}s for {total_count} messages with total of {size}",
                size = HumanBytes(total_count as u64 * size as u64),
            );
            }
            Cmd::Exit => {}
        }
        Ok(())
    }

    async fn handle_fs_command(&self, cmd: FsCmd) -> anyhow::Result<()> {
        match cmd {
            FsCmd::ImportFile { file_path, key } => {
                let file_path = canonicalize_path(&file_path)?.canonicalize()?;
                let (hash, len) = self
                    .db
                    .import(
                        file_path.clone(),
                        ImportMode::Copy,
                        Format::Blob,
                        IgnoreProgressSender::default(),
                    )
                    .await?;
                self.doc.insert(key, &self.author, hash, len)?;
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
                if key_prefix.ends_with('/') {
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
                        let (hash, len) = self
                            .db
                            .import(
                                file.path().into(),
                                ImportMode::Copy,
                                Format::Blob,
                                IgnoreProgressSender::default(),
                            )
                            .await?;
                        self.doc.insert(key, &self.author, hash, len)?;
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
                if !key_prefix.ends_with('/') {
                    key_prefix.push('/');
                }
                let root = canonicalize_path(&dir_path)?;
                println!("> exporting {key_prefix} to {root:?}");
                let entries = self.store.get_many(
                    self.doc.namespace(),
                    GetFilter::Prefix(key_prefix.as_bytes().to_vec()),
                )?;
                let mut checked_dirs = HashSet::new();
                for entry in entries {
                    let entry = entry?;
                    let key = entry.entry().id().key();
                    let relative = String::from_utf8(key[key_prefix.len()..].to_vec())?;
                    let len = entry.entry().record().content_len();
                    let blob = self.db.get(&entry.content_hash());
                    if let Some(blob) = blob {
                        let mut reader = blob.data_reader().await?;
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
                let entry = self
                    .store
                    .get_many(
                        self.doc.namespace(),
                        GetFilter::Key(key.as_bytes().to_vec()),
                    )?
                    .next();
                if let Some(entry) = entry {
                    let entry = entry?;
                    println!("> exporting {key} to {path:?}");
                    let parent = path.parent().ok_or_else(|| anyhow!("Invalid path"))?;
                    tokio::fs::create_dir_all(&parent).await?;
                    let mut file = tokio::fs::File::create(&path).await?;
                    let blob = self
                        .db
                        .get(&entry.content_hash())
                        .ok_or_else(|| anyhow!(format!("content for {key} is not available")))?;
                    let mut reader = blob.data_reader().await?;
                    copy(&mut reader, &mut file).await?;
                } else {
                    println!("> key not found, abort");
                }
            }
        }

        Ok(())
    }
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
        /// Match the key as prefix, not an exact match.
        #[clap(short = 'p', long)]
        prefix: bool,
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
    /// Hammer time - stress test with the hammer
    Hammer {
        /// The hammer mode
        #[clap(value_enum)]
        mode: HammerMode,
        /// The key prefix
        prefix: String,
        /// The number of threads to use (each thread will create it's own replica)
        #[clap(long, short, default_value = "2")]
        threads: usize,
        /// The number of entries to create
        #[clap(long, short, default_value = "1000")]
        count: usize,
        /// The size of each entry in Bytes
        #[clap(long, short, default_value = "1024")]
        size: usize,
    },
    /// Quit
    Exit,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum HammerMode {
    /// Create entries
    Set,
    /// Read entries
    Get,
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
    gossip: Gossip,
    docs: iroh_sync::store::fs::Store,
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
        SYNC_ALPN => iroh_sync::net::handle_connection(conn, state.docs.clone()).await,
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
    let Ok(stats) = iroh::metrics::get_metrics() else {
        println!("metrics collection is disabled");
        return;
    };
    for (name, details) in stats.iter() {
        println!(
            "{:23} : {:>6}    ({})",
            name, details.value, details.description
        );
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

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

async fn fmt_content_simple(_doc: &Doc, entry: &SignedEntry) -> String {
    let len = entry.entry().record().content_len();
    format!("<{}>", HumanBytes(len))
}

async fn fmt_content<B: BaoStore>(db: &B, entry: &SignedEntry) -> String {
    let len = entry.entry().record().content_len();
    if len > MAX_DISPLAY_CONTENT_LEN {
        format!("<{}>", HumanBytes(len))
    } else {
        match read_content(db, entry).await {
            Err(err) => format!("<missing content: {err}>"),
            Ok(content) => match String::from_utf8(content.into()) {
                Ok(str) => str,
                Err(_err) => format!("<invalid utf8 {}>", HumanBytes(len)),
            },
        }
    }
}

async fn read_content<B: BaoStore>(db: &B, entry: &SignedEntry) -> anyhow::Result<Bytes> {
    let data = db
        .get(&entry.content_hash())
        .ok_or_else(|| anyhow!("not found"))?
        .data_reader()
        .await?
        .read_to_end()
        .await?;
    Ok(data)
}
fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(hash.as_ref());
    text.make_ascii_lowercase();
    format!("{}…{}", &text[..5], &text[(text.len() - 2)..])
}
fn fmt_derp_map(derp_map: &Option<DerpMap>) -> String {
    match derp_map {
        None => "None".to_string(),
        Some(map) => map
            .regions()
            .flat_map(|region| region.nodes.iter().map(|node| node.url.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
    }
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

    use iroh::collection::IrohCollectionParser;

    #[derive(Debug, Clone)]
    pub struct IrohBytesHandlers {
        db: iroh::baomap::flat::Store,
        rt: iroh_bytes::util::runtime::Handle,
        event_sender: NoopEventSender,
        get_handler: Arc<NoopCustomGetHandler>,
        auth_handler: Arc<NoopRequestAuthorizationHandler>,
    }
    impl IrohBytesHandlers {
        pub fn new(rt: iroh_bytes::util::runtime::Handle, db: iroh::baomap::flat::Store) -> Self {
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
