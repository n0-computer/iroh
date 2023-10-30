use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use iroh::{
    client::quic::RPC_ALPN,
    node::{Node, StaticTokenAuthHandler},
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
    util::{fs::load_secret_key, path::IrohPaths},
};
use iroh_bytes::{protocol::RequestToken, util::runtime};
use iroh_net::{
    derp::{DerpMap, DerpMode},
    key::SecretKey,
};
use quic_rpc::{transport::quinn::QuinnServerEndpoint, ServiceEndpoint};
use tracing::{info_span, Instrument};

use crate::{commands::add, config::path_with_env};

use super::{BlobAddOptions, MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS};

#[derive(Debug)]
pub struct StartOptions {
    pub addr: SocketAddr,
    pub rpc_port: RpcPort,
    pub keylog: bool,
    pub request_token: Option<RequestToken>,
    pub derp_map: Option<DerpMap>,
}

pub async fn run(rt: &runtime::Handle, opts: StartOptions, add_opts: BlobAddOptions) -> Result<()> {
    if let Some(ref path) = add_opts.path {
        ensure!(
            path.exists(),
            "Cannot provide nonexistent path: {}",
            path.display()
        );
    }

    let token = opts.request_token.clone();
    if let Some(t) = token.as_ref() {
        println!("Request token: {}", t);
    }

    let node = start_daemon_node(rt, opts).await?;
    let client = node.client();

    let add_task = {
        tokio::spawn(
            async move {
                if let Err(e) = add::run_with_opts(&client, add_opts, token).await {
                    eprintln!("Failed to add data: {}", e);
                    std::process::exit(1);
                }
            }
            .instrument(info_span!("node-add")),
        )
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
    add_task.abort();
    drop(add_task);
    Ok(())
}

async fn start_daemon_node(
    rt: &runtime::Handle,
    opts: StartOptions,
) -> Result<Node<iroh_bytes::store::flat::Store>> {
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
        .peers_data_path(peers_data_path)
        .keylog(opts.keylog);
    if let Some(dm) = opts.derp_map {
        builder = builder.derp_mode(DerpMode::Custom(dm));
    }
    let builder = builder.bind_addr(opts.addr).runtime(rt);

    let provider = if let Some(rpc_port) = opts.rpc_port.into() {
        let rpc_endpoint = make_rpc_endpoint(&secret_key, rpc_port)?;
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
    println!("PeerID: {}", provider.peer_id());
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
fn make_rpc_endpoint(
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
    let rpc_endpoint =
        QuinnServerEndpoint::<ProviderRequest, ProviderResponse>::new(rpc_quinn_endpoint)?;
    Ok(rpc_endpoint)
}

#[derive(Debug, Clone)]
pub enum RpcPort {
    Enabled(u16),
    Disabled,
}

impl From<RpcPort> for Option<u16> {
    fn from(value: RpcPort) -> Self {
        match value {
            RpcPort::Enabled(port) => Some(port),
            RpcPort::Disabled => None,
        }
    }
}

impl fmt::Display for RpcPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcPort::Enabled(port) => write!(f, "{port}"),
            RpcPort::Disabled => write!(f, "disabled"),
        }
    }
}

impl FromStr for RpcPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "disabled" {
            Ok(RpcPort::Disabled)
        } else {
            Ok(RpcPort::Enabled(s.parse()?))
        }
    }
}
