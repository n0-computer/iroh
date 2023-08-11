//! Create a list of tasks that can be shared among devices
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--private-key` CLI flag with the private key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.
//!
//!
//! just need to figure out how to create an iroh node?
//!
//! create doc or import doc
//!
//! then you have a handle to a doc, you can just use that? do i need a store still?

use std::collections::HashMap;
use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::bail;
use bytes::Bytes;
use clap::{CommandFactory, FromArgMatches, Parser};
use comfy_table::{presets::UTF8_FULL, Cell, CellAlignment, Table};
use ed25519_dalek::SigningKey;
use iroh::sync::{
    BlobStore, Doc as SyncDoc, DocStore, DownloadMode, LiveSync, PeerSource, SYNC_ALPN,
};
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
use iroh_sync::{
    store::{self, Store as _},
    sync::{Author, Namespace, OnInsertCallback, SignedEntry},
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing_subscriber::{EnvFilter, Registry};
use url::Url;

use iroh_bytes_handlers::IrohBytesHandlers;

type Doc = SyncDoc<store::fs::Store>;

#[derive(Parser, Debug)]
pub struct Args {
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

    let (send, recv) = mpsc::channel(32);
    let tasks = Tasks::new(
        args,
        Some(Box::new(move |_origin, _entry| {
            println!("GOT ENTRY");
            send.try_send(()).expect("receiver dropped");
        })),
    )
    .await?;
    println!("> ticket: {}", tasks.ticket());

    let (mut tasks_app, mut update_error) = TasksApp::new(tasks, recv).await?;

    // spawn an repl thread that reads stdin and parses each line as a `Cmd` command
    let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
    std::thread::spawn(move || repl_loop(cmd_tx).expect("input loop crashed"));
    // process commands in a loop
    println!("> ready to accept commands");
    println!("> type `help` for a list of commands");

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

            err = &mut update_error => {
                println!("> error updating task list: {err:?}");
            }

            res = handle_command(cmd, &mut tasks_app, &log_filter) => if let Err(err) = res {
                println!("> error: {err}");
            },
        };
        // notify to the repl that we want to get the next command
        to_repl_tx.send(ToRepl::Continue).ok();
    }

    tasks_app.shutdown().await
}

async fn handle_command(
    cmd: Cmd,
    tasks_app: &mut TasksApp,
    log_filter: &LogLevelReload,
) -> anyhow::Result<()> {
    match cmd {
        Cmd::Add { label } => tasks_app.add(label).await?,
        Cmd::Done { index } => tasks_app.toggle_done(index).await?,
        Cmd::Delete { index } => tasks_app.delete(index).await?,
        Cmd::Ls => tasks_app.list().await?,
        Cmd::Ticket => {
            let ticket = tasks_app.ticket().await;
            println!("ticket -> {ticket}");
        }
        Cmd::Log { directive } => {
            let next_filter = EnvFilter::from_str(&directive)?;
            log_filter.modify(|layer| *layer = next_filter)?;
        }
        Cmd::Stats => get_stats(),
        Cmd::Exit => {}
    }

    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
/// Task in a list of tasks
pub struct Task {
    /// Description of the task
    /// Limited to 2000 characters
    label: String,
    /// Record creation timestamp. Counted as micros since the Unix epoch.
    created: u64,
    /// Whether or not the task has been completed. Done tasks will show up in the task list until
    /// they are archived.
    done: bool,
    /// Indicates whether or not the task is tombstoned
    is_delete: bool,
    /// String id
    id: String,
}

const MAX_TASK_SIZE: usize = 2 * 1024;
const MAX_LABEL_LEN: usize = 2 * 1000;

impl Task {
    fn from_bytes(bytes: Bytes) -> anyhow::Result<Self> {
        let task = postcard::from_bytes(&bytes)?;
        Ok(task)
    }

    fn as_bytes(self) -> anyhow::Result<Bytes> {
        let mut buf = bytes::BytesMut::zeroed(MAX_TASK_SIZE);
        postcard::to_slice(&self, &mut buf)?;
        Ok(buf.freeze())
    }

    fn missing_task(id: String) -> Self {
        Self {
            label: String::from("Missing Content"),
            created: 0,
            done: false,
            is_delete: false,
            id,
        }
    }
}

/// List of tasks, including completed tasks that have not been archived
pub struct Tasks {
    doc: Doc,
    store: DocStore,
    ticket: Ticket,
    live_sync: LiveSync<store::fs::Store>,
    blob_store: BlobStore,
    metrics_fut: Option<tokio::task::JoinHandle<()>>,
}

impl Tasks {
    pub async fn new(args: Args, on_insert: Option<OnInsertCallback>) -> anyhow::Result<Self> {
        let metrics_fut = init_metrics_collection(args.metrics_addr);

        // parse or generate our keypair
        let keypair = match args.private_key {
            None => Keypair::generate(),
            Some(key) => parse_keypair(&key)?,
        };

        // configure our derp map
        let derp_map = match (args.no_derp, args.derp) {
            (false, None) => Some(default_derp_map()),
            (false, Some(url)) => Some(derp_map_from_url(url)?),
            (true, None) => None,
            (true, Some(_)) => bail!("You cannot set --no-derp and --derp at the same time"),
        };

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

        // unwrap our storage path or default to temp
        let storage_path = args.storage_path.unwrap_or_else(|| {
            let name = format!("iroh-todo-{}", endpoint.peer_id());
            let dir = std::env::temp_dir().join(name);
            if !dir.exists() {
                std::fs::create_dir(&dir).expect("failed to create temp dir");
            }
            dir
        });

        // create a runtime that can spawn tasks on a local-thread executors (to support !Send futures)
        let rt = iroh_bytes::util::runtime::Handle::from_currrent(num_cpus::get())?;

        // create a blob store (with a iroh-bytes database inside)
        let blobs =
            BlobStore::new(rt.clone(), storage_path.join("blobs"), endpoint.clone()).await?;

        // create a doc store for the iroh-sync docs
        let author = Author::from(keypair.secret().clone());
        let docs_path = storage_path.join("docs");
        tokio::fs::create_dir_all(&docs_path).await?;
        let docs = DocStore::new(blobs.clone(), author, docs_path)?;

        // create the live syncer
        let live_sync = LiveSync::<store::fs::Store>::spawn(endpoint.clone(), gossip.clone());

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
        let doc = docs.create_or_open(namespace, DownloadMode::Always).await?;
        live_sync.add(doc.replica().clone(), peers.clone()).await?;

        if let Some(on_insert) = on_insert {
            doc.on_insert(on_insert);
        }
        Ok(Tasks {
            doc,
            store: docs,
            ticket: our_ticket,
            live_sync,
            blob_store: blobs,
            metrics_fut,
        })
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        // exit: cancel the sync and store blob database and document
        self.live_sync.cancel().await?;
        self.blob_store.save().await?;

        if let Some(metrics_fut) = &self.metrics_fut {
            metrics_fut.abort();
            drop(metrics_fut);
        }
        Ok(())
    }

    pub fn ticket(&self) -> String {
        self.ticket.to_string()
    }

    pub async fn add(&mut self, id: String, label: String) -> anyhow::Result<()> {
        if label.len() > MAX_LABEL_LEN {
            bail!("label is too long, max size is {MAX_LABEL_LEN} characters");
        }
        let created = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("time drift")
            .as_secs();
        let task = Task {
            label,
            created,
            done: false,
            is_delete: false,
            id: id.clone(),
        };
        self.insert_bytes(id.as_bytes(), task.as_bytes()?).await
    }
    pub async fn toggle_done(&mut self, id: String) -> anyhow::Result<()> {
        let mut task = self.get_task(id.clone()).await?;
        task.done = !task.done;
        self.update_task(id.as_bytes(), task).await
    }

    pub async fn delete(&mut self, id: String) -> anyhow::Result<()> {
        println!("delete {id}");
        let mut task = self.get_task(id.clone()).await?;
        task.is_delete = true;
        self.update_task(id.as_bytes(), task).await
    }

    pub async fn get_tasks(&self) -> anyhow::Result<Vec<Task>> {
        let entries = self
            .store
            .store()
            .get_latest(self.doc.replica().namespace())?;
        let mut hash_entries: HashMap<Vec<u8>, SignedEntry> = HashMap::new();

        // only get most recent entry for the key
        // wish this had an easier api -> get_latest_for_each_key?
        for entry in entries {
            let (id, entry) = entry?;
            if let Some(other_entry) = hash_entries.get(id.key()) {
                let other_timestamp = other_entry.entry().record().timestamp();
                let this_timestamp = entry.entry().record().timestamp();
                if this_timestamp > other_timestamp {
                    hash_entries.insert(id.key().to_owned(), entry);
                }
            } else {
                hash_entries.insert(id.key().to_owned(), entry);
            }
        }
        let entries: Vec<_> = hash_entries.values().collect();
        let mut tasks = Vec::new();
        for entry in entries {
            let task = self.task_from_entry(entry).await?;
            if !task.is_delete {
                tasks.push(task);
            }
        }
        tasks.sort_by_key(|t| t.created);
        Ok(tasks)
    }

    async fn insert_bytes(&self, key: impl AsRef<[u8]>, content: Bytes) -> anyhow::Result<()> {
        self.doc.insert_bytes(key, content).await?;
        Ok(())
    }

    async fn update_task(&mut self, key: impl AsRef<[u8]>, task: Task) -> anyhow::Result<()> {
        let content = task.as_bytes()?;
        self.insert_bytes(key, content).await
    }

    async fn get_task(&self, id: String) -> anyhow::Result<Task> {
        match self
            .store
            .store()
            .get_latest_by_key(self.doc.replica().namespace(), id.as_bytes())?
            .next()
        {
            Some(entry) => {
                let (_, entry) = entry?;
                self.task_from_entry(&entry).await
            }
            None => {
                bail!("key not found")
            }
        }
    }

    async fn task_from_entry(&self, entry: &SignedEntry) -> anyhow::Result<Task> {
        let id = String::from_utf8(entry.entry().id().key().to_owned())?;
        match self.doc.get_content_bytes(entry).await {
            Some(b) => Task::from_bytes(b),
            None => Ok(Task::missing_task(id.clone())),
        }
    }
}

fn fmt_tasks(tasks: &Vec<Task>) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_width(100)
        .set_header(vec!["Index", "Done", "Task", "ID"])
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic);

    for (num, task) in tasks.iter().enumerate() {
        let num = num.to_string();
        let done = if task.done { "✓" } else { "" };
        table.add_row(vec![
            Cell::new(num).set_alignment(CellAlignment::Center),
            Cell::new(done).set_alignment(CellAlignment::Center),
            Cell::new(task.label.clone()).set_alignment(CellAlignment::Left),
            Cell::new(task.id.clone()).set_alignment(CellAlignment::Left),
        ]);
    }
    table.to_string()
}

/// TODO: make actual error
#[derive(Debug)]
pub enum UpdateError {
    NoMoreUpdates,
    GetTasksError,
}

/// Allows the user to interact with the tasks using the "indexes"
/// that are printed to the screen
struct TasksApp {
    tasks: Arc<Mutex<Tasks>>,
    order: Arc<Mutex<Vec<String>>>,
    update_handle: tokio::task::JoinHandle<()>,
}

impl TasksApp {
    async fn new(
        tasks: Tasks,
        mut updates: mpsc::Receiver<()>,
    ) -> anyhow::Result<(Self, oneshot::Receiver<UpdateError>)> {
        let order: Vec<String> = tasks
            .get_tasks()
            .await?
            .iter()
            .map(|t| t.id.to_string())
            .collect();
        let order = Arc::new(Mutex::new(order));
        let tasks = Arc::new(Mutex::new(tasks));
        let (sender, recv) = oneshot::channel();
        let updates_tasks = Arc::clone(&tasks);
        let updates_order = Arc::clone(&order);
        let update_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        return;
                    }
                    res = updates.recv() => {
                        match res {
                            Some(()) => {
                                let t = updates_tasks.lock().await;
                                let tasks = match t.get_tasks().await {
                                    Ok(tasks) => tasks,
                                    Err(_) => {
                                        let _ = sender.send(UpdateError::GetTasksError);
                                        return;
                                    }
                                };
                                let mut order = updates_order.lock().await;
                                *order = tasks.iter().map(|t| t.id.clone()).collect();
                                let table = fmt_tasks(&tasks);
                                println!("\n{table}");
                            },
                            None => {
                                let _ = sender.send(UpdateError::NoMoreUpdates);
                                return;
                            }
                        }
                    }
                }
            }
        });
        Ok((
            TasksApp {
                tasks,
                order,
                update_handle,
            },
            recv,
        ))
    }

    async fn ticket(&self) -> String {
        let tasks = self.tasks.lock().await;
        tasks.ticket()
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        let tasks = self.tasks.lock().await;
        tasks.shutdown().await?;
        self.update_handle.abort();
        Ok(())
    }

    async fn add(&mut self, label: String) -> anyhow::Result<()> {
        let mut tasks = self.tasks.lock().await;
        let id = uuid::Uuid::new_v4();
        tasks.add(id.to_string(), label).await
    }

    async fn toggle_done(&mut self, index: usize) -> anyhow::Result<()> {
        let id = self.get_id(index).await?;
        let mut tasks = self.tasks.lock().await;
        tasks.toggle_done(id).await
    }

    async fn delete(&mut self, index: usize) -> anyhow::Result<()> {
        let id = self.get_id(index).await?;
        let mut tasks = self.tasks.lock().await;
        tasks.delete(id).await
    }

    async fn get_id(&self, index: usize) -> anyhow::Result<String> {
        let order = self.order.lock().await;
        match order.get(index) {
            Some(id) => Ok(id.to_string()),
            None => bail!("No task with index {index} exists"),
        }
    }

    async fn list(&self) -> anyhow::Result<()> {
        let t = self.tasks.lock().await;
        let tasks = t.get_tasks().await?;
        let table = fmt_tasks(&tasks);
        println!("\n{table}");
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub enum Cmd {
    /// Add a task. The task label must be in quotes.
    Add {
        /// the content of the actual task
        label: String,
    },
    /// Mark a task as finished. `done <INDEX>`
    Done {
        /// The index of the task
        index: usize,
    },
    /// Remove a task. `delete <INDEX>`
    Delete {
        /// The index of the task
        index: usize,
    },
    /// Print all the tasks.
    Ls,
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
    /// Show stats about the current session
    Stats,
    /// Quit
    Exit,
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
fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(hash.as_ref());
    text.make_ascii_lowercase();
    format!("{}…{}", &text[..5], &text[(text.len() - 2)..])
}
fn parse_keypair(secret: &str) -> anyhow::Result<Keypair> {
    let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
    let key = SigningKey::from_bytes(&bytes);
    Ok(key.into())
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
