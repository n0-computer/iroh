use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use clap::Subcommand;
use colored::Colorize;
use comfy_table::Table;
use comfy_table::{presets::NOTHING, Cell};
use futures::{Stream, StreamExt};
use human_time::ToHumanTimeString;
use iroh::{
    client::quic::{Iroh, RPC_ALPN},
    node::{Node, StaticTokenAuthHandler},
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
    util::{fs::load_secret_key, path::IrohPaths},
};
use iroh_bytes::{protocol::RequestToken, util::runtime};
use iroh_net::{
    derp::{DerpMap, DerpMode},
    key::{PublicKey, SecretKey},
    magic_endpoint::ConnectionInfo,
    magicsock::DirectAddrInfo,
};
use quic_rpc::{transport::quinn::QuinnServerEndpoint, ServiceEndpoint};
use tracing::{info_span, Instrument};

use crate::{
    commands::{
        blob::{add_with_opts, BlobSource},
        rpc::clear_rpc,
    },
    config::{get_iroh_data_root_with_env, path_with_env},
};

use super::{
    blob::BlobAddOptions,
    rpc::{store_rpc, RpcStatus},
    MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS,
};

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

#[derive(Debug)]
pub struct StartOptions {
    pub addr: SocketAddr,
    pub rpc_port: u16,
    pub request_token: Option<RequestToken>,
    pub derp_map: Option<DerpMap>,
}

pub async fn run(rt: &runtime::Handle, opts: StartOptions, add_opts: BlobAddOptions) -> Result<()> {
    let token = opts.request_token.clone();
    if let Some(t) = token.as_ref() {
        println!("Request token: {}", t);
    }

    let node = start_daemon_node(rt, opts).await?;
    let client = node.client();

    let add_task = match add_opts.source {
        Some(ref source) => {
            if let BlobSource::Path(ref p) = source {
                ensure!(
                    p.exists(),
                    "Cannot provide nonexistent path: {}",
                    p.display()
                );
            }

            Some(tokio::spawn(
                async move {
                    if let Err(e) = add_with_opts(&client, add_opts, token).await {
                        eprintln!("Failed to add data: {}", e);
                        std::process::exit(1);
                    }
                }
                .instrument(info_span!("node-add")),
            ))
        }
        None => None,
    };

    let node2 = node.clone();
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down provider...");
            node2.shutdown();
        }
        res = node => {
            res?;
        }
    }

    // the future holds a reference to the temp file, so we need to
    // keep it for as long as the provider is running. The drop(fut)
    // makes this explicit.
    if let Some(add_task) = add_task {
        add_task.abort();
        drop(add_task);
    }
    clear_rpc(get_iroh_data_root_with_env()?).await?;

    Ok(())
}

async fn start_daemon_node(
    rt: &runtime::Handle,
    opts: StartOptions,
) -> Result<Node<iroh_bytes::store::flat::Store>> {
    let rpc_status = RpcStatus::load(get_iroh_data_root_with_env()?).await?;
    match rpc_status {
        RpcStatus::Running(port) => {
            bail!("iroh is already running on port {}", port);
        }
        RpcStatus::Stopped => {
            // all good, we can go ahead
        }
    }

    let blob_dir = path_with_env(IrohPaths::BaoFlatStoreComplete)?;
    let partial_blob_dir = path_with_env(IrohPaths::BaoFlatStorePartial)?;
    let meta_dir = path_with_env(IrohPaths::BaoFlatStoreMeta)?;
    let peer_data_path = path_with_env(IrohPaths::PeerData)?;
    tokio::fs::create_dir_all(&blob_dir).await?;
    tokio::fs::create_dir_all(&partial_blob_dir).await?;
    let bao_store =
        iroh_bytes::store::flat::Store::load(&blob_dir, &partial_blob_dir, &meta_dir, rt)
            .await
            .with_context(|| format!("Failed to load iroh database from {}", blob_dir.display()))?;
    let key = Some(path_with_env(IrohPaths::SecretKey)?);
    let doc_store = iroh_sync::store::fs::Store::new(path_with_env(IrohPaths::DocsDatabase)?)?;
    spawn_daemon_node(rt, bao_store, doc_store, key, peer_data_path, opts).await
}

async fn spawn_daemon_node<B: iroh_bytes::store::Store, D: iroh_sync::store::Store>(
    rt: &runtime::Handle,
    bao_store: B,
    doc_store: D,
    key: Option<PathBuf>,
    peers_data_path: PathBuf,
    opts: StartOptions,
) -> Result<Node<B>> {
    let secret_key = get_secret_key(key).await?;

    let mut builder = Node::builder(bao_store, doc_store)
        .custom_auth_handler(Arc::new(StaticTokenAuthHandler::new(opts.request_token)))
        .peers_data_path(peers_data_path);
    if let Some(dm) = opts.derp_map {
        builder = builder.derp_mode(DerpMode::Custom(dm));
    }
    let builder = builder.bind_addr(opts.addr).runtime(rt);

    let provider = if let Some(rpc_port) = opts.rpc_port.into() {
        let rpc_endpoint = make_rpc_endpoint(&secret_key, rpc_port).await?;
        builder
            .rpc_endpoint(rpc_endpoint)
            .secret_key(secret_key)
            .spawn()
            .await?
    } else {
        builder.secret_key(secret_key).spawn().await?
    };
    let eps = provider.local_endpoints().await?;
    println!("Listening addresses:");
    for ep in eps {
        println!("  {}", ep.addr);
    }
    let region = provider.my_derp();
    println!(
        "DERP Region: {}",
        region.map_or("None".to_string(), |r| r.to_string())
    );
    println!("PeerID: {}", provider.node_id());
    println!();
    Ok(provider)
}

async fn get_secret_key(key: Option<PathBuf>) -> Result<SecretKey> {
    match key {
        Some(key_path) => load_secret_key(key_path).await,
        None => {
            // No path provided, just generate one
            Ok(SecretKey::generate())
        }
    }
}

/// Makes a an RPC endpoint that uses a QUIC transport
async fn make_rpc_endpoint(
    secret_key: &SecretKey,
    rpc_port: u16,
) -> Result<impl ServiceEndpoint<ProviderService>> {
    let rpc_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port));
    let rpc_quinn_endpoint = quinn::Endpoint::server(
        iroh::node::make_server_config(
            secret_key,
            MAX_RPC_STREAMS,
            MAX_RPC_CONNECTIONS,
            vec![RPC_ALPN.to_vec()],
        )?,
        rpc_addr,
    )?;
    let actual_rpc_port = rpc_quinn_endpoint.local_addr()?.port();
    let rpc_endpoint =
        QuinnServerEndpoint::<ProviderRequest, ProviderResponse>::new(rpc_quinn_endpoint)?;

    // store rpc endpoint
    store_rpc(get_iroh_data_root_with_env()?, actual_rpc_port).await?;

    Ok(rpc_endpoint)
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

fn bold_cell(s: &str) -> Cell {
    Cell::new(s).add_attribute(comfy_table::Attribute::Bold)
}
