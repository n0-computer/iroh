use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, ensure, Context, Result};
use iroh::{
    baomap::flat::{self, Store as BaoFsStore},
    client::quic::RPC_ALPN,
    collection::IrohCollectionParser,
    node::{Node, StaticTokenAuthHandler},
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
};
use iroh_bytes::{
    baomap::Store as BaoStore,
    protocol::RequestToken,
    util::{runtime, SetTagOption},
};
use iroh_net::{derp::DerpMap, key::SecretKey};
use iroh_sync::store::{fs::Store as DocFsStore, Store as DocStore};
use quic_rpc::{transport::quinn::QuinnServerEndpoint, ServiceEndpoint};
use tokio::io::AsyncWriteExt;
use tracing::{info_span, Instrument};

use crate::{
    commands::add::{self, BlobSource, TicketOption},
    config::IrohPaths,
};

use super::{MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS};

#[derive(Debug)]
pub struct StartOptions {
    pub addr: SocketAddr,
    pub rpc_port: RpcPort,
    pub keylog: bool,
    pub request_token: Option<RequestToken>,
    pub derp_map: Option<DerpMap>,
}

pub async fn run(
    rt: &runtime::Handle,
    path: Option<PathBuf>,
    in_place: bool,
    tag: SetTagOption,
    opts: StartOptions,
) -> Result<()> {
    if let Some(ref path) = path {
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

    let source = BlobSource::from_path_or_stdin(path, in_place, true);
    let ticket = TicketOption::Print(token);
    // task that will add data to the provider, either from a file or from stdin
    let add_task = {
        tokio::spawn(
            async move {
                if let Err(e) = add::run(&client, source, tag, ticket).await {
                    eprintln!("Failed to add data: {}", e);
                    std::process::exit(1);
                }
            }
            .instrument(info_span!("provider-add")),
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
) -> Result<Node<BaoFsStore, DocFsStore>> {
    let blob_dir = IrohPaths::BaoFlatStoreComplete.with_env()?;
    let partial_blob_dir = IrohPaths::BaoFlatStorePartial.with_env()?;
    let meta_dir = IrohPaths::BaoFlatStoreMeta.with_env()?;
    let peer_data_path = IrohPaths::PeerData.with_env()?;
    tokio::fs::create_dir_all(&blob_dir).await?;
    tokio::fs::create_dir_all(&partial_blob_dir).await?;
    let bao_store = flat::Store::load(&blob_dir, &partial_blob_dir, &meta_dir, rt)
        .await
        .with_context(|| format!("Failed to load iroh database from {}", blob_dir.display()))?;
    let key = Some(IrohPaths::SecretKey.with_env()?);
    let doc_store = iroh_sync::store::fs::Store::new(IrohPaths::DocsDatabase.with_env()?)?;
    spawn_daemon_node(rt, bao_store, doc_store, key, peer_data_path, opts).await
}

async fn spawn_daemon_node<B: BaoStore, D: DocStore>(
    rt: &runtime::Handle,
    bao_store: B,
    doc_store: D,
    key: Option<PathBuf>,
    peers_data_path: PathBuf,
    opts: StartOptions,
) -> Result<Node<B, D>> {
    let secret_key = get_secret_key(key).await?;

    let mut builder = Node::builder(bao_store, doc_store)
        .collection_parser(IrohCollectionParser)
        .custom_auth_handler(Arc::new(StaticTokenAuthHandler::new(opts.request_token)))
        .peers_data_path(peers_data_path)
        .keylog(opts.keylog);
    if let Some(dm) = opts.derp_map {
        builder = builder.enable_derp(dm);
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
    let region = provider.my_derp().await;
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
        Some(key_path) => {
            if key_path.exists() {
                let keystr = tokio::fs::read(key_path).await?;
                let secret_key = SecretKey::try_from_openssh(keystr).context("invalid keyfile")?;
                Ok(secret_key)
            } else {
                let secret_key = SecretKey::generate();
                let ser_key = secret_key.to_openssh()?;

                // Try to canoncialize if possible
                let key_path = key_path.canonicalize().unwrap_or(key_path);
                let key_path_parent = key_path.parent().ok_or_else(|| {
                    anyhow!("no parent directory found for '{}'", key_path.display())
                })?;
                tokio::fs::create_dir_all(&key_path_parent).await?;

                // write to tempfile
                let (file, temp_file_path) = tempfile::NamedTempFile::new_in(key_path_parent)
                    .context("unable to create tempfile")?
                    .into_parts();
                let mut file = tokio::fs::File::from_std(file);
                file.write_all(ser_key.as_bytes())
                    .await
                    .context("unable to write keyfile")?;
                file.flush().await?;
                drop(file);

                // move file
                tokio::fs::rename(temp_file_path, key_path)
                    .await
                    .context("failed to rename keyfile")?;

                Ok(secret_key)
            }
        }
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
