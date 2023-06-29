use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh_bytes::{cid::Blake3Cid, protocol::RequestToken, provider::Ticket, runtime};
use iroh_net::tls::PeerId;
use quic_rpc::transport::quinn::QuinnConnection;
use quic_rpc::RpcClient;

use crate::{config::Config, rpc_protocol::*};

use self::provide::ProviderRpcPort;

const DEFAULT_RPC_PORT: u16 = 0x1337;
const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod add;
pub mod doctor;
pub mod get;
pub mod list;
pub mod provide;
pub mod validate;

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
/// address and PeerID as well as an authentication code.  The get-ticket subcommand is a
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
                token,
                out,
                single,
            } => {
                let get = self::get::GetInteractive::Hash {
                    hash: *hash.as_hash(),
                    opts: iroh_bytes::get::Options {
                        addrs,
                        peer_id: peer,
                        keylog: self.keylog,
                        derp_map: config.derp_map(),
                    },
                    token,
                    single,
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
            Commands::GetTicket { out, ticket } => {
                let get = self::get::GetInteractive::Ticket {
                    ticket,
                    keylog: self.keylog,
                    derp_map: config.derp_map(),
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
            } => self::provide::run(config, rt, path, addr, rpc_port, self.keylog).await,
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
        #[clap(long, short, default_value_t = SocketAddr::from(crate::node::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// RPC port, set to "disabled" to disable RPC
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
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
        hash: Blake3Cid,
        /// PeerId of the provider
        #[clap(long, short)]
        peer: PeerId,
        /// Addresses of the provider
        #[clap(long, short)]
        addrs: Vec<SocketAddr>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long)]
        token: Option<RequestToken>,
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// True to download a single blob, false (default) to download a collection and its children.
        #[clap(long, default_value_t = false)]
        single: bool,
    },
    /// Fetch data from a provider using a ticket.
    ///
    /// The ticket contains all hash, authentication and connection information to connect
    /// to the provider.  It is a simpler, but slightly less flexible alternative to the
    /// `get` subcommand.
    GetTicket {
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// Ticket containing everything to retrieve the data from a provider.
        ticket: Ticket,
    },
    /// List listening addresses of the provider.
    Addresses {
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
}

async fn make_rpc_client(
    rpc_port: u16,
) -> anyhow::Result<RpcClient<ProviderService, QuinnConnection<ProviderResponse, ProviderRequest>>>
{
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let endpoint = create_quinn_client(bind_addr, vec![RPC_ALPN.to_vec()], false)?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), rpc_port);
    let server_name = "localhost".to_string();
    let connection = QuinnConnection::new(endpoint, addr, server_name);
    let client = RpcClient::<ProviderService, _>::new(connection);
    // Do a version request to check if the server is running.
    let _version = tokio::time::timeout(Duration::from_secs(1), client.rpc(VersionRequest))
        .await
        .context("iroh server is not running")??;
    Ok(client)
}

pub fn create_quinn_client(
    bind_addr: SocketAddr,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<quinn::Endpoint> {
    let keypair = iroh_net::tls::Keypair::generate();
    let tls_client_config = iroh_net::tls::make_client_config(&keypair, None, alpn_protocols, keylog)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[cfg(feature = "metrics")]
pub fn init_metrics_collection(
    metrics_addr: Option<SocketAddr>,
    rt: &iroh_bytes::runtime::Handle,
) -> Option<tokio::task::JoinHandle<()>> {
    iroh_metrics::metrics::init_metrics();
    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        return Some(rt.main().spawn(async move {
            iroh_metrics::metrics::start_metrics_server(metrics_addr)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Failed to start metrics server: {e}");
                });
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}
