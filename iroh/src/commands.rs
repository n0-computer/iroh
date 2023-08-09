use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::client::connect_raw;
use iroh::dial::Ticket;
use iroh::rpc_protocol::*;
use iroh_bytes::{protocol::RequestToken, util::runtime, Hash};
use iroh_net::tls::{Keypair, PeerId};
use quic_rpc::transport::quinn::QuinnConnection;

use crate::config::Config;

use self::provide::{ProvideOptions, ProviderRpcPort};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod add;
pub mod doctor;
pub mod get;
pub mod list;
pub mod provide;
pub mod sync;
pub mod validate;

/// RPC client to an iroh node.
pub type RpcClient =
    quic_rpc::RpcClient<ProviderService, QuinnConnection<ProviderResponse, ProviderRequest>>;

/// Send data.
///
/// The iroh command line tool has two modes: provide and get.
///
/// The provide mode is a long-running process binding to a socket which the get mode
/// contacts to request data.  By default the provide process also binds to an RPC port
/// which allows adding additional data to be provided as well as a few other maintenance
/// commands.
///
/// The get mode retrieves data from the provider, for this it needs the hash, provider
/// address and PeerID as well as an authentication code.  The get --ticket option is a
/// shortcut to provide all this information conveniently in a single ticket.
#[derive(Parser, Debug, Clone)]
#[clap(version)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
    /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
    #[clap(long)]
    pub keylog: bool,
    /// Bind address on which to serve Prometheus metrics
    #[cfg(feature = "metrics")]
    #[clap(long)]
    pub metrics_addr: Option<SocketAddr>,
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Cli {
    pub async fn run(self, rt: &runtime::Handle, config: &Config) -> Result<()> {
        match self.command {
            Commands::Get {
                hash,
                peer,
                addrs,
                region,
                ticket,
                token,
                out,
                single,
            } => {
                let get = if let Some(ticket) = ticket {
                    self::get::GetInteractive {
                        hash: ticket.hash(),
                        opts: ticket.as_get_options(Keypair::generate(), config.derp_map()),
                        token: ticket.token().cloned(),
                        single: !ticket.recursive(),
                    }
                } else if let (Some(peer), Some(hash)) = (peer, hash) {
                    self::get::GetInteractive {
                        hash,
                        opts: iroh::dial::Options {
                            addrs,
                            peer_id: peer,
                            keylog: self.keylog,
                            derp_region: region,
                            derp_map: config.derp_map(),
                            keypair: Keypair::generate(),
                        },
                        token,
                        single,
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
            Commands::Provide {
                path,
                addr,
                rpc_port,
                request_token,
            } => {
                let request_token = match request_token {
                    Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
                    Some(RequestTokenOptions::Token(token)) => Some(token),
                    None => None,
                };
                self::provide::run(
                    rt,
                    path,
                    ProvideOptions {
                        addr,
                        rpc_port,
                        keylog: self.keylog,
                        request_token,
                        derp_map: config.derp_map(),
                    },
                )
                .await
            }
            Commands::List(cmd) => cmd.run().await,
            Commands::Validate { rpc_port } => self::validate::run(rpc_port).await,
            Commands::Shutdown { force, rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                client.rpc(ShutdownRequest { force }).await?;
                Ok(())
            }
            Commands::Id { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let response = client.rpc(IdRequest).await?;

                println!("Listening address: {:#?}", response.listen_addrs);
                println!("PeerID: {}", response.peer_id);
                Ok(())
            }
            Commands::Add { path, rpc_port } => self::add::run(path, rpc_port).await,
            Commands::Addresses { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let response = client.rpc(AddrsRequest).await?;
                println!("Listening addresses: {:?}", response.addrs);
                Ok(())
            }
            Commands::Doctor { command } => self::doctor::run(command, config).await,
            Commands::Sync { command, rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                command.run(client).await
            }
        }
    }
}
#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },

    /// Serve data from the given path.
    ///
    /// If PATH is a folder all files in that folder will be served.  If no PATH is
    /// specified reads from STDIN.
    Provide {
        /// Path to initial file or directory to provide
        path: Option<PathBuf>,
        #[clap(long, short)]
        /// Listening address to bind to
        #[clap(long, short, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// RPC port, set to "disabled" to disable RPC
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
        /// Use a token to authenticate requests for data
        ///
        /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
        #[clap(long)]
        request_token: Option<RequestTokenOptions>,
    },
    /// List availble content on the provider.
    #[clap(subcommand)]
    List(self::list::Commands),
    /// Validate hashes on the running provider.
    Validate {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Shutdown provider.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Identify the running provider.
    Id {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Add data from PATH to the running provider's database.
    Add {
        /// The path to the file or folder to add
        path: PathBuf,
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Fetch the data identified by HASH from a provider
    Get {
        /// The hash to retrieve, as a Blake3 CID
        #[clap(conflicts_with = "ticket", required_unless_present = "ticket")]
        hash: Option<Hash>,
        /// PeerId of the provider
        #[clap(
            long,
            short,
            conflicts_with = "ticket",
            required_unless_present = "ticket"
        )]
        peer: Option<PeerId>,
        /// Addresses of the provider
        #[clap(long, short)]
        addrs: Vec<SocketAddr>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long)]
        token: Option<RequestToken>,
        /// DERP region of the provider
        #[clap(long)]
        region: Option<u16>,
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        ///
        /// If the directory exists and contains a partial download, the download will
        /// be resumed.
        ///
        /// Otherwise, all files in the collection will be overwritten. Other files
        /// in the directory will be left untouched.
        #[clap(long, short)]
        out: Option<PathBuf>,
        #[clap(conflicts_with_all = &["hash", "peer", "addrs", "token"])]
        /// Ticket containing everything to retrieve the data from a provider.
        #[clap(long)]
        ticket: Option<Ticket>,
        /// True to download a single blob, false (default) to download a collection and its children.
        #[clap(long, default_value_t = false)]
        single: bool,
    },
    /// List listening addresses of the provider.
    Addresses {
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    Sync {
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
        #[clap(subcommand)]
        command: sync::Commands,
    },
}

pub async fn make_rpc_client(rpc_port: u16) -> anyhow::Result<RpcClient> {
    connect_raw(rpc_port).await
}

#[cfg(feature = "metrics")]
pub fn init_metrics_collection(
    metrics_addr: Option<SocketAddr>,
    rt: &iroh_bytes::util::runtime::Handle,
) -> Option<tokio::task::JoinHandle<()>> {
    use iroh_metrics::core::Metric;

    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        iroh_metrics::core::Core::init(|reg, metrics| {
            metrics.insert(iroh::metrics::Metrics::new(reg));
            metrics.insert(iroh_net::metrics::MagicsockMetrics::new(reg));
            metrics.insert(iroh_net::metrics::NetcheckMetrics::new(reg));
            metrics.insert(iroh_net::metrics::PortmapMetrics::new(reg));
            metrics.insert(iroh_net::metrics::DerpMetrics::new(reg));
        });

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
