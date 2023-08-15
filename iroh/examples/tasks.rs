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
use futures::StreamExt;
use iroh::client::Doc;
use iroh::rpc_protocol::{DocTicket, ProviderRequest, ProviderResponse, ShareMode};
use iroh::sync::{LiveEvent, PeerSource};
use iroh_gossip::proto::TopicId;
use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};
use iroh_net::defaults::default_derp_map;
use iroh_net::{
    defaults::DEFAULT_DERP_STUN_PORT,
    derp::{DerpMap, UseIpv4, UseIpv6},
    tls::Keypair,
};
use iroh_sync::sync::NamespaceId;
use iroh_sync::sync::{AuthorId, SignedEntry};
use quic_rpc::transport::flume::FlumeConnection;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing_subscriber::{EnvFilter, Registry};
use url::Url;

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
pub enum Command {
    List,
    Create,
    Open { key: String },
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
        metrics.insert(iroh_sync::metrics::Metrics::new(reg));
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

mod iroh_node {
    use anyhow::{Context, Result};
    use iroh::baomap::{flat::Store as BaoFileStore, mem::Store as BaoMemStore};
    use iroh::node::Node;
    use iroh_bytes::{baomap::Store as BaoStore, util::runtime};
    use iroh_net::derp::DerpMap;
    use iroh_net::tls::Keypair;
    use iroh_sync::store::fs::Store as DocFileStore;
    use iroh_sync::store::memory::Store as DocMemStore;
    use iroh_sync::store::Store as DocStore;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    const DOCS_PATH: &str = "docs";

    pub enum Iroh {
        FileStore(Node<BaoFileStore, DocFileStore>),
        MemStore(Node<BaoMemStore, DocMemStore>),
    }

    impl Iroh {
        pub async fn new(
            rt: runtime::Handle,
            keypair: Keypair,
            derp_map: Option<DerpMap>,
            bind_addr: SocketAddr,
            data_root: Option<PathBuf>,
        ) -> Result<Self> {
            match data_root {
                Some(path) => Ok(Iroh::FileStore(
                    create_iroh_node_file_store(&rt, keypair, derp_map, bind_addr, path).await?,
                )),
                None => Ok(Iroh::MemStore(
                    create_iroh_node_mem_store(rt, keypair, derp_map, bind_addr).await?,
                )),
            }
        }

        pub fn client(&self) -> iroh::client::mem::Iroh {
            match self {
                Iroh::FileStore(node) => node.client(),
                Iroh::MemStore(node) => node.client(),
            }
        }

        pub fn shutdown(self) {
            match self {
                Iroh::FileStore(node) => node.shutdown(),
                Iroh::MemStore(node) => node.shutdown(),
            }
        }
    }

    pub async fn create_iroh_node_mem_store(
        rt: runtime::Handle,
        keypair: Keypair,
        derp_map: Option<DerpMap>,
        bind_addr: SocketAddr,
    ) -> Result<Node<BaoMemStore, DocMemStore>> {
        let rt_handle = rt.clone();
        create_iroh_node(
            BaoMemStore::new(rt),
            DocMemStore::default(),
            &rt_handle,
            keypair,
            derp_map,
            bind_addr,
        )
        .await
    }

    pub async fn create_iroh_node_file_store(
        rt: &runtime::Handle,
        keypair: Keypair,
        derp_map: Option<DerpMap>,
        bind_addr: SocketAddr,
        data_root: PathBuf,
    ) -> Result<Node<BaoFileStore, DocFileStore>> {
        let path = {
            if data_root.is_absolute() {
                data_root
            } else {
                std::env::current_dir()?.join(data_root)
            }
        };
        let bao_store = {
            tokio::fs::create_dir_all(&path).await?;
            BaoFileStore::load(&path, &path, &rt)
                .await
                .with_context(|| format!("Failed to load tasks database from {}", path.display()))?
        };
        let doc_store = {
            let path = path.join(DOCS_PATH);
            DocFileStore::new(path.clone()).with_context(|| {
                format!("Failed to load docs database from {:?}", path.display())
            })?
        };

        create_iroh_node(bao_store, doc_store, rt, keypair, derp_map, bind_addr).await
    }

    pub async fn create_iroh_node<B: BaoStore, D: DocStore>(
        bao_store: B,
        doc_store: D,
        rt: &runtime::Handle,
        keypair: Keypair,
        derp_map: Option<DerpMap>,
        bind_addr: SocketAddr,
    ) -> Result<Node<B, D>> {
        let mut builder = Node::builder(bao_store, doc_store);
        if let Some(dm) = derp_map {
            builder = builder.derp_map(dm);
        }
        builder
            .bind_addr(bind_addr)
            .runtime(rt)
            .keypair(keypair)
            .spawn()
            .await
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
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
    // create a runtime that can spawn tasks on a local-thread executors (to support !Send futures)
    let rt = iroh_bytes::util::runtime::Handle::from_currrent(num_cpus::get())?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.bind_port).parse().unwrap();
    let iroh = iroh_node::Iroh::new(rt, keypair, derp_map, bind_addr, args.storage_path).await?;

    if let Command::List = args.command {
        let mut docs = iroh.client().list_docs().await?;
        println!("Available Task Lists:");
        while let Some(doc) = docs.next().await {
            let doc = doc?;
            println!("\t{doc}");
        }
        iroh.shutdown();
        return Ok(());
    }

    let tasks = Tasks::new(iroh.client(), args.command).await?;
    println!("> ticket: {}", tasks.ticket());

    let (mut tasks_app, mut update_error) = TasksApp::new(tasks).await?;

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
    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
        drop(metrics_fut);
    }
    iroh.shutdown();
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

#[derive(Clone, Serialize, Deserialize, Debug)]
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

    fn as_vec(self) -> anyhow::Result<Vec<u8>> {
        let buf = self.as_bytes()?;
        Ok(buf[..].to_vec())
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
    doc: Doc<FlumeConnection<ProviderResponse, ProviderRequest>>,
    iroh: iroh::client::mem::Iroh,
    ticket: DocTicket,
    author: AuthorId,
}

impl Tasks {
    pub async fn new(iroh: iroh::client::mem::Iroh, command: Command) -> anyhow::Result<Self> {
        let author = iroh.create_author().await?;

        let doc = match &command {
            Command::Create => {
                let doc = iroh.create_doc().await?;
                println!(
                    "> creating document with namespace {} and waiting for peers to join us...",
                    doc.id()
                );
                doc
            }
            Command::Open { key } => {
                let id = NamespaceId::from_str(&key)?;
                println!(
                    "> opening document {key} as namespace {id:?} and waiting for peers to join us...",
                );
                iroh.get_doc(id)?
            }
            Command::Join { ticket } => {
                let ticket = DocTicket::from_str(ticket)?;
                println!(
                    "> joining topic {:?} and connecting to {:?}",
                    ticket.key, ticket.peers
                );
                iroh.import_doc(ticket).await?
            }
            Command::List => {
                unreachable!("Command::List should have never made it to here");
            }
        };

        let ticket = doc.share(ShareMode::Write).await?;

        Ok(Tasks {
            author,
            doc,
            ticket,
            iroh,
        })
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
        self.insert_bytes(id.as_bytes(), task.as_vec()?).await
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
        let mut entries = self.doc.get_all_keys_latest().await?;
        let mut hash_entries: HashMap<Vec<u8>, SignedEntry> = HashMap::new();

        // only get most recent entry for the key
        // wish this had an easier api -> get_latest_for_each_key?
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            let id = entry.entry().id();
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

    async fn insert_bytes(&self, key: impl AsRef<[u8]>, content: Vec<u8>) -> anyhow::Result<()> {
        self.doc
            .set_bytes(self.author, key.as_ref().to_vec(), content)
            .await?;
        Ok(())
    }

    async fn update_task(&mut self, key: impl AsRef<[u8]>, task: Task) -> anyhow::Result<()> {
        let content = task.as_vec()?;
        self.insert_bytes(key, content).await
    }

    async fn get_task(&self, id: String) -> anyhow::Result<Task> {
        let entry = self.doc.get_latest_by_key(id.as_bytes().to_vec()).await?;
        self.task_from_entry(&entry).await
    }

    async fn task_from_entry(&self, entry: &SignedEntry) -> anyhow::Result<Task> {
        let id = String::from_utf8(entry.entry().id().key().to_owned())?;
        match self.doc.get_content_bytes(entry).await {
            Ok(b) => Task::from_bytes(b),
            Err(_) => Ok(Task::missing_task(id.clone())),
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
    Error(String),
}

/// Allows the user to interact with the tasks using the "indexes"
/// that are printed to the screen
struct TasksApp {
    tasks: Arc<Mutex<Tasks>>,
    order: Arc<Mutex<Vec<String>>>,
    update_handle: tokio::task::JoinHandle<()>,
}

impl TasksApp {
    async fn new(tasks: Tasks) -> anyhow::Result<(Self, oneshot::Receiver<UpdateError>)> {
        let order: Vec<String> = tasks
            .get_tasks()
            .await?
            .iter()
            .map(|t| t.id.to_string())
            .collect();
        let mut events = tasks.doc.subscribe().await?;
        let order = Arc::new(Mutex::new(order));
        let tasks = Arc::new(Mutex::new(tasks));
        let (sender, recv) = oneshot::channel();
        let update_tasks = Arc::clone(&tasks);
        let update_order = Arc::clone(&order);
        let update_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        return;
                    }
                    res = events.next() => {
                        match res {
                            Some(Ok(event)) => {
                                let t = update_tasks.lock().await;
                                let tasks = match t.get_tasks().await {
                                    Ok(tasks) => tasks,
                                    Err(_) => {
                                        let _ = sender.send(UpdateError::GetTasksError);
                                        return;
                                    }
                                };
                                let mut order = update_order.lock().await;
                                *order = tasks.iter().map(|t| t.id.clone()).collect();
                                if let LiveEvent::InsertRemote { .. } = event {
                                    // must wait for remote content to download before displaying
                                    continue;
                                }
                                let table = fmt_tasks(&tasks);
                                println!("\n{table}");
                            },
                            Some(Err(e)) => {
                                let _ = sender.send(UpdateError::Error(e.to_string()));
                                return;
                            }
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
    let metrics = core.get_collector::<iroh_sync::metrics::Metrics>().unwrap();
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
fn fmt_secret(keypair: &Keypair) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&keypair.secret().to_bytes());
    text.make_ascii_lowercase();
    text
}
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
