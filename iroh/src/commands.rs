use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, Table};
use console::style;
use futures::{Stream, StreamExt};
use human_time::ToHumanTimeString;
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh::client::quic::Iroh;
use iroh::rpc_protocol::*;
use iroh::ticket::blob::Ticket;
use iroh_bytes::{protocol::RequestToken, util::runtime, BlobFormat, Hash, Tag};
use iroh_net::magicsock::DirectAddrInfo;
use iroh_net::NodeAddr;
use iroh_net::{
    key::{PublicKey, SecretKey},
    magic_endpoint::ConnectionInfo,
};

use crate::config::{get_iroh_data_root_with_env, ConsoleEnv, NodeConfig};

use self::node::StartOptions;
use self::rpc::RpcStatus;
use self::sync::{AuthorCommands, DocCommands};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod add;
pub mod delete;
pub mod doctor;
pub mod get;
pub mod list;
pub mod node;
pub mod repl;
pub mod sync;
pub mod validate;

mod rpc;

/// iroh is a tool for syncing bytes
/// https://iroh.computer/docs
#[derive(Parser, Debug, Clone)]
#[clap(version, verbatim_doc_comment)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(flatten)]
    #[clap(next_help_heading = "Options for start, get, doctor")]
    pub full_args: FullArgs,
}

/// Options for commands that may start an Iroh node
#[derive(Args, Debug, Clone)]
pub struct FullArgs {
    /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
    #[clap(long)]
    pub keylog: bool,
    /// Bind address on which to serve Prometheus metrics
    #[cfg(feature = "metrics")]
    #[clap(long)]
    pub metrics_addr: Option<SocketAddr>,
    #[clap(long)]
    pub cfg: Option<PathBuf>,

    /// RPC port of the Iroh node.
    #[clap(long, global = true, default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u16,
}

async fn iroh_quic_connect(rt: runtime::Handle) -> Result<iroh::client::quic::Iroh> {
    let root = get_iroh_data_root_with_env()?;
    let rpc_status = RpcStatus::load(root).await?;
    match rpc_status {
        RpcStatus::Stopped => {
            bail!("iroh is not running, please start it");
        }
        RpcStatus::Running(rpc_port) => {
            let iroh = iroh::client::quic::connect(rpc_port, Some(rt))
                .await
                .context("quic::connect")?;
            Ok(iroh)
        }
    }
}

impl Cli {
    pub async fn run(self, rt: runtime::Handle) -> Result<()> {
        match self.command {
            Commands::Console => {
                let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                let env = ConsoleEnv::for_console()?;
                repl::run(&iroh, &env).await
            }
            Commands::Rpc(command) => {
                let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                let env = ConsoleEnv::for_cli()?;
                command.run(&iroh, &env).await
            }
            Commands::Full(command) => {
                let FullArgs {
                    cfg,
                    metrics_addr,
                    keylog,
                    rpc_port,
                } = self.full_args;

                let config = NodeConfig::from_env(cfg.as_deref())?;

                #[cfg(feature = "metrics")]
                let metrics_fut = start_metrics_server(metrics_addr, &rt);

                let res = command.run(&rt, &config, keylog, rpc_port).await;

                #[cfg(feature = "metrics")]
                if let Some(metrics_fut) = metrics_fut {
                    metrics_fut.abort();
                }

                res
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub enum Commands {
    /// Open the iroh console
    ///
    /// The console is a REPL for interacting with a running iroh node.
    /// For more info on available commands, see https://iroh.computer/docs/api
    Console,
    #[clap(flatten)]
    Full(#[clap(subcommand)] FullCommands),
    #[clap(flatten)]
    Rpc(#[clap(subcommands)] RpcCommands),
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum FullCommands {
    /// Start an iroh node
    ///
    /// A node is a long-running process that serves data and connects to other nodes.
    /// The console, doc, author, blob, node, and tag commands require a running node.
    ///
    /// start optionally takes a PATH argument, which can be a file or a folder to serve on startup.
    /// If PATH is a folder all files in that folder will be served. If no PATH is specified start
    /// reads from STDIN.
    /// Data can be added after startup with commands like `iroh blob add`
    /// or by adding content to documents.
    Start {
        /// Listening address to bind to
        #[clap(long, short, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// Use a token to authenticate requests for data
        ///
        /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
        #[clap(long)]
        request_token: Option<RequestTokenOptions>,

        /// Add data when starting the node
        #[clap(flatten)]
        add_options: BlobAddOptions,
    },
    /// Fetch data from a provider
    ///
    /// Fetches the content identified by HASH.
    /// `iroh start` does not need to be running to use `iroh get`. Get starts a temporary iroh
    /// node to fetch the data, and shuts it down when done.
    Get {
        /// The hash to retrieve, as a Blake3 CID
        #[clap(conflicts_with = "ticket", required_unless_present = "ticket")]
        hash: Option<Hash>,
        /// PublicKey of the provider
        #[clap(
            long,
            short,
            conflicts_with = "ticket",
            required_unless_present = "ticket"
        )]
        peer: Option<PublicKey>,
        /// Addresses of the provider
        #[clap(long, short)]
        addrs: Vec<SocketAddr>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long)]
        token: Option<RequestToken>,
        /// DERP region of the provider
        #[clap(long)]
        region: Option<u16>,
        /// Directory in which to save the file(s). When passed `STDOUT` will be written to stdout,
        /// otherwise the content will be stored in the provided path.
        ///
        /// If the directory exists and contains a partial download, the download will
        /// be resumed.
        ///
        /// Otherwise, all files in the collection will be overwritten. Other files
        /// in the directory will be left untouched.
        #[clap(long, short)]
        out: OutputTarget,
        #[clap(conflicts_with_all = &["hash", "peer", "addrs", "token"])]
        /// Ticket containing everything to retrieve the data from a provider.
        #[clap(long)]
        ticket: Option<Ticket>,
        /// If set assume that the hash refers to a collection and download it with all children.
        #[clap(long, default_value_t = false)]
        collection: bool,
    },
    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

/// Where the data should be stored.
#[derive(Debug, Clone, derive_more::Display, PartialEq, Eq)]
pub enum OutputTarget {
    /// Writes to stdout
    #[display("STDOUT")]
    Stdout,
    /// Writes to the provided path
    #[display("{}", _0.display())]
    Path(PathBuf),
}

impl From<String> for OutputTarget {
    fn from(s: String) -> Self {
        if s == "STDOUT" {
            return OutputTarget::Stdout;
        }

        OutputTarget::Path(s.into())
    }
}

impl FullCommands {
    pub async fn run(
        self,
        rt: &runtime::Handle,
        config: &NodeConfig,
        keylog: bool,
        rpc_port: u16,
    ) -> Result<()> {
        match self {
            FullCommands::Start {
                addr,
                request_token,
                add_options,
            } => {
                let request_token = match request_token {
                    Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
                    Some(RequestTokenOptions::Token(token)) => Some(token),
                    None => None,
                };
                self::node::run(
                    rt,
                    StartOptions {
                        addr,
                        rpc_port,
                        keylog,
                        request_token,
                        derp_map: config.derp_map()?,
                    },
                    add_options,
                )
                .await
            }
            FullCommands::Get {
                hash,
                peer,
                addrs,
                region,
                ticket,
                token,
                out,
                collection,
            } => {
                let get = if let Some(ticket) = ticket {
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash: ticket.hash(),
                        opts: ticket.as_get_options(SecretKey::generate(), config.derp_map()?),
                        token: ticket.token().cloned(),
                        format: ticket.format(),
                    }
                } else if let (Some(peer), Some(hash)) = (peer, hash) {
                    let format = match collection {
                        true => BlobFormat::HashSeq,
                        false => BlobFormat::Raw,
                    };
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash,
                        opts: iroh::dial::Options {
                            peer: NodeAddr::from_parts(peer, region, addrs),
                            keylog,
                            derp_map: config.derp_map()?,
                            secret_key: SecretKey::generate(),
                        },
                        token,
                        format,
                    }
                } else {
                    anyhow::bail!("Either ticket or hash and peer must be specified")
                };
                tokio::select! {
                    biased;
                    res = get.get_interactive(out) => res,
                    _ = tokio::signal::ctrl_c() => {
                        println!("Ending transfer early...");
                        Ok(())
                    }
                }
            }
            FullCommands::Doctor { command } => self::doctor::run(command, config).await,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RpcCommands {
    /// Manage documents
    ///
    /// Documents are mutable, syncable key-value stores.
    /// For more on docs see https://iroh.computer/docs/layers/documents
    Doc {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage document authors
    ///
    /// Authors are keypairs that identify writers to documents.
    Author {
        #[clap(subcommand)]
        command: AuthorCommands,
    },
    /// Manage blobs
    ///
    /// Blobs are immutable, opaque chunks of arbirary-sized data.
    /// For more on blobs see https://iroh.computer/docs/layers/blobs
    Blob {
        #[clap(subcommand)]
        command: BlobCommands,
    },
    /// Manage a running iroh node
    Node {
        #[clap(subcommand)]
        command: NodeCommands,
    },
    /// Manage tags
    ///
    /// Tags are local, human-readable names for things iroh should keep.
    /// Anything added with explicit commands like `iroh get` or `doc join`
    /// will be tagged & kept until the tag is removed. If no tag is given
    /// while running an explicit command, iroh will automatically generate
    /// a tag.
    ///
    /// Any data iroh fetches without a tag will be periodically deleted.
    Tag {
        #[clap(subcommand)]
        command: TagCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NodeCommands {
    /// Get information about the different connections we have made
    Connections,
    /// Get connection information about a particular node
    Connection { node_id: PublicKey },
    /// Get status of the running node.
    Status,
    /// Get statistics and metrics from the running node.
    Stats,
    /// Shutdown the running node.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
    },
}

impl NodeCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Connections => {
                let connections = iroh.node.connections().await?;
                let timestamp = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc2822)
                    .unwrap_or_else(|_| String::from("failed to get current time"));

                println!(
                    " {}: {}\n\n{}",
                    "current time".bold(),
                    timestamp,
                    fmt_connections(connections).await
                );
            }
            Self::Connection { node_id } => {
                let conn_info = iroh.node.connection_info(node_id).await?;
                match conn_info {
                    Some(info) => println!("{}", fmt_connection(info)),
                    None => println!("Not Found"),
                }
            }
            Self::Shutdown { force } => {
                iroh.node.shutdown(force).await?;
            }
            Self::Stats => {
                let stats = iroh.node.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
            }
            Self::Status => {
                let response = iroh.node.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node public key: {}", response.addr.node_id);
                println!("Version: {}", response.version);
            }
        }
        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TagCommands {
    /// List all tags
    List,
    /// Delete a tag
    Delete {
        tag: String,
        #[clap(long, default_value_t = false)]
        hex: bool,
    },
}

impl TagCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::List => {
                let mut response = iroh.tags.list().await?;
                while let Some(res) = response.next().await {
                    let res = res?;
                    println!("{}: {} ({:?})", res.name, res.hash, res.format,);
                }
            }
            Self::Delete { tag, hex } => {
                let tag = if hex {
                    Tag::from(Bytes::from(hex::decode(tag)?))
                } else {
                    Tag::from(tag)
                };
                iroh.tags.delete(tag).await?;
            }
        }
        Ok(())
    }
}

impl RpcCommands {
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Node { command } => command.run(iroh).await,
            Self::Blob { command } => command.run(iroh).await,
            Self::Doc { command } => command.run(iroh, env).await,
            Self::Author { command } => command.run(iroh, env).await,
            Self::Tag { command } => command.run(iroh).await,
        }
    }
}

/// Where the data should be read from.
#[derive(Debug, Clone, derive_more::Display, PartialEq, Eq)]
pub enum BlobSource {
    /// Reads from stdin
    #[display("STDIN")]
    Stdin,
    /// Reads from the provided path
    #[display("{}", _0.display())]
    Path(PathBuf),
}

impl From<String> for BlobSource {
    fn from(s: String) -> Self {
        if s == "STDIN" {
            return BlobSource::Stdin;
        }

        BlobSource::Path(s.into())
    }
}

/// Options for the `blob add` command.
#[derive(clap::Args, Debug, Clone)]
pub struct BlobAddOptions {
    /// The source of the file or folder to add.
    ///
    /// If `STDIN` is specified, the data will be read from stdin.
    ///
    /// When left empty no content is added.
    #[clap(long, short)]
    source: Option<BlobSource>,

    /// Add in place
    ///
    /// Set this to true only if you are sure that the data in its current location
    /// will not change.
    #[clap(long, default_value_t = false)]
    in_place: bool,

    /// Tag to tag the data with.
    #[clap(long)]
    tag: Option<String>,

    /// Wrap the added file or directory in a collection.
    ///
    /// When adding a single file, without `wrap` the file is added as a single blob and no
    /// collection is created. When enabling `wrap` it also creates a collection with a
    /// single entry, where the entry's name is the filename and the entry's content is blob.
    ///
    /// When adding a directory, a collection is always created.
    /// Without `wrap`, the collection directly contains the entries from the added direcory.
    /// With `wrap`, the directory will be nested so that all names in the collection are
    /// prefixed with the directory name, thus preserving the name of the directory.
    ///
    /// When adding content from STDIN and setting `wrap` you also need to set `filename` to name
    /// the entry pointing to the content from STDIN.
    #[clap(long, default_value_t = false)]
    wrap: bool,

    /// Override the filename used for the entry in the created collection.
    ///
    /// Only supported `wrap` is set.
    /// Required when adding content from STDIN and setting `wrap`.
    #[clap(long, requires = "wrap")]
    filename: Option<String>,

    /// Do not print the all-in-one ticket to get the added data from this node.
    #[clap(long)]
    no_ticket: bool,
}

/// An argument that can be either "none" or a value of type `T`.
#[derive(Debug, Clone)]
pub enum Optional<T: FromStr> {
    None,
    Some(T),
}

impl<T: FromStr> FromStr for Optional<T> {
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            _ => T::from_str(s).map(Self::Some),
        }
    }
}

// Helper struct to model a ticket or the arguments that would make a ticket. This works as a
// subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum TicketOrArgs {
    /// Use a blob ticket to download the data.
    #[command(arg_required_else_help = true)]
    Ticket {
        /// Ticket to use.
        ticket: Ticket,
        /// Additonal socket address to use to contact the node. Can be used multiple times.
        #[clap(long)]
        address: Vec<SocketAddr>,
        /// Override the Derp region to use to contact the node.
        #[clap(long, value_name = "\"none\" | DERP_REGION")]
        derp_region: Option<Optional<u16>>,
        /// Override to treat the blob as a raw blob or a hash sequence.
        #[clap(long)]
        recursive: Option<bool>,
        /// Override the ticket token.
        #[clap(long, value_name = "\"none\" | TOKEN")]
        request_token: Option<Optional<RequestToken>>,
        /// If set, the ticket's direct addresses will not be used.
        #[clap(long)]
        override_addresses: bool,
        #[command(flatten)]
        ops: DownloadOps,
    },
    /// Supply the content and node-addressing information directly to perform a download.
    #[command(arg_required_else_help = true)]
    Hash {
        /// Hash of the content to download.
        hash: Hash,
        /// NodeId of the provider.
        #[clap(long, required = true)]
        node: PublicKey,
        /// Additonal socket address to use to contact the node. Can be used multiple times.
        /// Necessary if no derp region provided.
        #[clap(long, required_unless_present = "derp_region")]
        address: Vec<SocketAddr>,
        /// Derp region to use to contact the node. Necessary if no addresses provided.
        #[clap(long, required_unless_present = "address")]
        derp_region: Option<u16>,
        /// Whether to treat the blob as a raw blob or a hash sequence.
        #[clap(long)]
        recursive: bool,
        /// Token to use.
        #[clap(long)]
        request_token: Option<RequestToken>,
        #[command(flatten)]
        ops: DownloadOps,
    },
}

#[derive(Debug, Clone, Args)]
pub struct DownloadOps {
    /// Directory or file in which to save the file(s).
    #[clap(long, short, global = true, value_name = "PATH")]
    out: Option<PathBuf>,
    /// If set, the data will be moved to the output directory, and iroh will assume that it
    /// will not change.
    #[clap(long, default_value_t = false, global = true)]
    stable: bool,
    /// Tag to tag the data with.
    #[clap(long, global = true)]
    tag: Option<String>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum BlobCommands {
    /// Add data from PATH to the running node.
    Add(BlobAddOptions),
    /// Download data to the running node's database and provide it.
    ///
    /// In addition to downloading the data, you can also specify an optional output directory
    /// where the data will be exported to after it has been downloaded.
    Download {
        #[clap(subcommand)]
        command: TicketOrArgs,
    },
    /// List availble content on the node.
    #[clap(subcommand)]
    List(self::list::Commands),
    /// Validate hashes on the running node.
    Validate {
        /// Repair the store by removing invalid data
        #[clap(long, default_value_t = false)]
        repair: bool,
    },
    /// Delete content on the node.
    #[clap(subcommand)]
    Delete(self::delete::Commands),
    /// Get a ticket to share this blob.
    Share {
        /// Hash of the blob to share.
        hash: Hash,
        /// Include an optional authentication token in the ticket.
        #[clap(long)]
        token: Option<String>,
        /// Do not include DERP reion information in the ticket. (advanced)
        #[clap(long, conflicts_with = "derp_only", default_value_t = false)]
        no_derp: bool,
        /// Include only the DERP region information in the ticket. (advanced)
        #[clap(long, conflicts_with = "no_derp", default_value_t = false)]
        derp_only: bool,
        /// If the blob is a collection, the requester will also fetch the listed blobs.
        #[clap(long, default_value_t = false)]
        recursive: bool,
        /// Display the contents of this ticket too.
        #[clap(long, hide = true)]
        debug: bool,
    },
}

impl BlobCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Download { command } => {
                let (node_addr, hash, format, token, ops) = match command {
                    TicketOrArgs::Ticket {
                        ticket,
                        mut address,
                        derp_region,
                        recursive,
                        request_token,
                        override_addresses,
                        ops,
                    } => {
                        let (node_addr, hash, blob_format, maybe_token) = ticket.into_parts();

                        // create the node address with the appropriate overrides
                        let node_addr = {
                            let NodeAddr { node_id, info } = node_addr;
                            let addresses = if override_addresses {
                                // use only the cli supplied ones
                                address
                            } else {
                                // use both the cli supploes ones and the ticket ones
                                address.extend(info.direct_addresses.into_iter());
                                address
                            };
                            let region = match derp_region {
                                Some(Optional::None) => None,
                                Some(Optional::Some(region)) => Some(region),
                                None => info.derp_region,
                            };
                            NodeAddr::from_parts(node_id, region, addresses)
                        };

                        // check if the blob format has an override
                        let format = match recursive {
                            Some(true) => BlobFormat::HashSeq,
                            Some(false) => BlobFormat::Raw,
                            None => blob_format,
                        };

                        // check if the token has an override
                        let token = match request_token {
                            Some(Optional::None) => None,
                            Some(Optional::Some(token)) => Some(token),
                            None => maybe_token,
                        };

                        (node_addr, hash, format, token, ops)
                    }
                    TicketOrArgs::Hash {
                        hash,
                        node,
                        address,
                        derp_region,
                        recursive,
                        request_token,
                        ops,
                    } => {
                        let format = if recursive {
                            BlobFormat::HashSeq
                        } else {
                            BlobFormat::Raw
                        };
                        let node_addr = NodeAddr::from_parts(node, derp_region, address);
                        (node_addr, hash, format, request_token, ops)
                    }
                };

                if node_addr.info.is_empty() {
                    return Err(anyhow::anyhow!(
                        "no derp region provided and no direct addresses provided"
                    ));
                }

                let DownloadOps {
                    out,
                    stable: in_place,
                    tag,
                } = ops;

                let out = match out {
                    None => DownloadLocation::Internal,
                    Some(path) => {
                        let absolute = std::env::current_dir()?.join(&path);
                        tracing::info!(
                            "output path is {} -> {}",
                            path.display(),
                            absolute.display()
                        );
                        DownloadLocation::External {
                            path: absolute.display().to_string(),
                            in_place,
                        }
                    }
                };

                let tag = match tag {
                    Some(tag) => SetTagOption::Named(Tag::from(tag)),
                    None => SetTagOption::Auto,
                };
                let mut stream = iroh
                    .blobs
                    .download(BlobDownloadRequest {
                        hash,
                        format,
                        peer: node_addr,
                        token,
                        out,
                        tag,
                    })
                    .await?;

                show_download_progress(hash, &mut stream).await
            }
            Self::List(cmd) => cmd.run(iroh).await,
            Self::Delete(cmd) => cmd.run(iroh).await,
            Self::Validate { repair } => self::validate::run(iroh, repair).await,
            Self::Add(opts) => {
                // TODO: This is where we are missing the request token from the running
                // node (last argument to run_with_opts).
                self::add::run_with_opts(iroh, opts, None).await
            }
            Self::Share {
                hash,
                token,
                no_derp,
                derp_only,
                recursive,
                debug,
            } => {
                let NodeStatusResponse { addr, .. } = iroh.node.status().await?;
                let node_addr = if no_derp {
                    NodeAddr::new(addr.node_id)
                        .with_direct_addresses(addr.direct_addresses().copied())
                } else if derp_only {
                    if let Some(region) = addr.derp_region() {
                        NodeAddr::new(addr.node_id).with_derp_region(region)
                    } else {
                        addr
                    }
                } else {
                    addr
                };

                let blob_reader = iroh
                    .blobs
                    .read(hash)
                    .await
                    .context("failed to retrieve blob info")?;
                let blob_status = if blob_reader.is_complete() {
                    "blob"
                } else {
                    "incomplete blob"
                };

                let format = if recursive {
                    BlobFormat::HashSeq
                } else {
                    BlobFormat::Raw
                };

                let request_token = token.map(RequestToken::new).transpose()?;

                let ticket =
                    Ticket::new(node_addr, hash, format, request_token).expect("correct ticket");
                println!(
                    "Ticket for {blob_status} {hash} ({})\n{ticket}",
                    HumanBytes(blob_reader.size())
                );
                if debug {
                    println!("{ticket:#?}")
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "metrics")]
pub fn start_metrics_server(
    metrics_addr: Option<SocketAddr>,
    rt: &iroh_bytes::util::runtime::Handle,
) -> Option<tokio::task::JoinHandle<()>> {
    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        // metrics are initilaized in iroh::node::Node::spawn
        // here we only start the server
        return Some(rt.main().spawn(async move {
            if let Err(e) = iroh_metrics::metrics::start_metrics_server(metrics_addr).await {
                eprintln!("Failed to start metrics server: {e}");
            }
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}

#[derive(Debug, Clone)]
pub enum RequestTokenOptions {
    Random,
    Token(RequestToken),
}

impl FromStr for RequestTokenOptions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_lowercase().trim() == "random" {
            return Ok(Self::Random);
        }
        let token = RequestToken::from_str(s)?;
        Ok(Self::Token(token))
    }
}

fn bold_cell(s: &str) -> Cell {
    Cell::new(s).add_attribute(comfy_table::Attribute::Bold)
}

async fn fmt_connections(
    mut infos: impl Stream<Item = Result<ConnectionInfo, anyhow::Error>> + Unpin,
) -> String {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        ["node id", "region", "conn type", "latency", "last used"]
            .into_iter()
            .map(bold_cell),
    );
    while let Some(Ok(conn_info)) = infos.next().await {
        let node_id: Cell = conn_info.public_key.to_string().into();
        let region = conn_info
            .derp_region
            .map_or(String::new(), |region| region.to_string())
            .into();
        let conn_type = conn_info.conn_type.to_string().into();
        let latency = match conn_info.latency {
            Some(latency) => latency.to_human_time_string(),
            None => String::from("unknown"),
        }
        .into();
        let last_used = conn_info
            .last_used
            .map(fmt_how_long_ago)
            .map(Cell::new)
            .unwrap_or_else(never);
        table.add_row([node_id, region, conn_type, latency, last_used]);
    }
    table.to_string()
}

fn fmt_connection(info: ConnectionInfo) -> String {
    let ConnectionInfo {
        id: _,
        public_key,
        derp_region,
        addrs,
        conn_type,
        latency,
        last_used,
    } = info;
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| String::from("failed to get current time"));
    let mut table = Table::new();
    table.load_preset(NOTHING);
    table.add_row([bold_cell("current time"), timestamp.into()]);
    table.add_row([bold_cell("node id"), public_key.to_string().into()]);
    let derp_region = derp_region
        .map(|r| r.to_string())
        .unwrap_or_else(|| String::from("unknown"));
    table.add_row([bold_cell("derp region"), derp_region.into()]);
    table.add_row([bold_cell("connection type"), conn_type.to_string().into()]);
    table.add_row([bold_cell("latency"), fmt_latency(latency).into()]);
    table.add_row([
        bold_cell("last used"),
        last_used
            .map(fmt_how_long_ago)
            .map(Cell::new)
            .unwrap_or_else(never),
    ]);
    table.add_row([bold_cell("known addresses"), addrs.len().into()]);

    let general_info = table.to_string();

    let addrs_info = fmt_addrs(addrs);
    format!("{general_info}\n\n{addrs_info}",)
}

fn direct_addr_row(info: DirectAddrInfo) -> comfy_table::Row {
    let DirectAddrInfo {
        addr,
        latency,
        last_control,
        last_payload,
    } = info;

    let last_control = match last_control {
        None => never(),
        Some((how_long_ago, kind)) => {
            format!("{kind} ( {} )", fmt_how_long_ago(how_long_ago)).into()
        }
    };
    let last_payload = last_payload
        .map(fmt_how_long_ago)
        .map(Cell::new)
        .unwrap_or_else(never);

    [
        addr.into(),
        fmt_latency(latency).into(),
        last_control,
        last_payload,
    ]
    .into()
}

fn fmt_addrs(addrs: Vec<DirectAddrInfo>) -> comfy_table::Table {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        vec!["addr", "latency", "last control", "last data"]
            .into_iter()
            .map(bold_cell),
    );
    table.add_rows(addrs.into_iter().map(direct_addr_row));
    table
}

fn never() -> Cell {
    Cell::new("never").add_attribute(comfy_table::Attribute::Dim)
}

fn fmt_how_long_ago(duration: Duration) -> String {
    duration
        .to_human_time_string()
        .split_once(',')
        .map(|(first, _rest)| first)
        .unwrap_or("-")
        .to_string()
}

fn fmt_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(latency) => latency.to_human_time_string(),
        None => String::from("unknown"),
    }
}

fn make_overall_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template(
            "{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb
}

fn make_individual_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );
    pb
}

pub async fn show_download_progress(
    hash: Hash,
    mut stream: impl Stream<Item = Result<DownloadProgress>> + Unpin,
) -> Result<()> {
    eprintln!("Fetching: {}", hash);
    let mp = MultiProgress::new();
    mp.set_draw_target(ProgressDrawTarget::stderr());
    let op = mp.add(make_overall_progress());
    let ip = mp.add(make_individual_progress());
    op.set_message(format!("{} Connecting ...\n", style("[1/3]").bold().dim()));
    let mut seq = false;
    while let Some(x) = stream.next().await {
        match x? {
            DownloadProgress::Connected => {
                op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
            }
            DownloadProgress::FoundHashSeq { children, .. } => {
                op.set_message(format!(
                    "{} Downloading {} blob(s)\n",
                    style("[3/3]").bold().dim(),
                    children + 1,
                ));
                op.set_length(children + 1);
                op.reset();
                seq = true;
            }
            DownloadProgress::Found { size, child, .. } => {
                if seq {
                    op.set_position(child);
                } else {
                    op.finish_and_clear();
                }
                ip.set_length(size);
                ip.reset();
            }
            DownloadProgress::Progress { offset, .. } => {
                ip.set_position(offset);
            }
            DownloadProgress::Done { .. } => {
                ip.finish_and_clear();
            }
            DownloadProgress::NetworkDone {
                bytes_read,
                elapsed,
                ..
            } => {
                op.finish_and_clear();
                eprintln!(
                    "Transferred {} in {}, {}/s",
                    HumanBytes(bytes_read),
                    HumanDuration(elapsed),
                    HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                );
            }
            DownloadProgress::AllDone => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_source() {
        assert_eq!(
            BlobSource::from(BlobSource::Stdin.to_string()),
            BlobSource::Stdin
        );

        assert_eq!(
            BlobSource::from(BlobSource::Path("hello/world".into()).to_string()),
            BlobSource::Path("hello/world".into()),
        );
    }

    #[test]
    fn test_output_target() {
        assert_eq!(
            OutputTarget::from(OutputTarget::Stdout.to_string()),
            OutputTarget::Stdout
        );

        assert_eq!(
            OutputTarget::from(OutputTarget::Path("hello/world".into()).to_string()),
            OutputTarget::Path("hello/world".into()),
        );
    }
}
