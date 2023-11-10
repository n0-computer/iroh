use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Result};
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

use crate::{
    commands::{add, rpc::clear_rpc, BlobSource},
    config::{get_iroh_data_root_with_env, path_with_env},
};

use super::{
    rpc::{store_rpc, RpcStatus},
    BlobAddOptions, MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS,
};

#[derive(Debug)]
pub struct StartOptions {
    pub addr: SocketAddr,
    pub rpc_port: u16,
    pub keylog: bool,
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
                    if let Err(e) = add::run_with_opts(&client, add_opts, token).await {
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
        .peers_data_path(peers_data_path)
        .keylog(opts.keylog);
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
pub(crate) async fn make_rpc_endpoint(
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
