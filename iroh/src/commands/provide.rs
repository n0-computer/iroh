use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use iroh::{
    baomap::flat,
    client::quic::RPC_ALPN,
    collection::IrohCollectionParser,
    node::{Node, StaticTokenAuthHandler},
    rpc_protocol::{ProvideRequest, ProviderRequest, ProviderResponse, ProviderService},
};
use iroh_bytes::{
    baomap::{GcMarkEvent, GcSweepEvent, Store as BaoStore},
    protocol::RequestToken,
    util::runtime,
};
use iroh_net::{derp::DerpMap, key::SecretKey};
use iroh_sync::store::Store as DocStore;
use quic_rpc::{transport::quinn::QuinnServerEndpoint, ServiceEndpoint};
use tokio::io::AsyncWriteExt;
use tracing::{info_span, Instrument};

use crate::config::IrohPaths;

use super::{
    add::{aggregate_add_response, print_add_response},
    MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS,
};

#[derive(Debug)]
pub struct ProvideOptions {
    pub addr: SocketAddr,
    pub rpc_port: ProviderRpcPort,
    pub keylog: bool,
    pub request_token: Option<RequestToken>,
    pub derp_map: Option<DerpMap>,
    pub gc_period: Duration,
}

pub async fn run(
    rt: &runtime::Handle,
    path: Option<PathBuf>,
    in_place: bool,
    tag: Option<Bytes>,
    opts: ProvideOptions,
) -> Result<()> {
    if let Some(ref path) = path {
        ensure!(
            path.exists(),
            "Cannot provide nonexistent path: {}",
            path.display()
        );
    }

    let gc_period = opts.gc_period;
    let blob_dir = IrohPaths::BaoFlatStoreComplete.with_env()?;
    let partial_blob_dir = IrohPaths::BaoFlatStorePartial.with_env()?;
    let meta_dir = IrohPaths::BaoFlatStorePartial.with_env()?;
    tokio::fs::create_dir_all(&blob_dir).await?;
    tokio::fs::create_dir_all(&partial_blob_dir).await?;
    let db = flat::Store::load(&blob_dir, &partial_blob_dir, &meta_dir, rt)
        .await
        .with_context(|| format!("Failed to load iroh database from {}", blob_dir.display()))?;
    let key = Some(IrohPaths::SecretKey.with_env()?);
    let store = iroh_sync::store::fs::Store::new(IrohPaths::DocsDatabase.with_env()?)?;
    let token = opts.request_token.clone();
    let provider = provide(db.clone(), store, rt, key, opts).await?;
    let controller = provider.controller();
    if let Some(t) = token.as_ref() {
        println!("Request token: {}", t);
    }

    // task that will add data to the provider, either from a file or from stdin
    let fut = {
        let provider = provider.clone();
        tokio::spawn(
            async move {
                let (path, tmp_path) = if let Some(path) = path {
                    let absolute = path.canonicalize()?;
                    println!("Adding {} as {}...", path.display(), absolute.display());
                    (absolute, None)
                } else {
                    // Store STDIN content into a temporary file
                    let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
                    let mut file = tokio::fs::File::from_std(file);
                    let path_buf = path.to_path_buf();
                    // Copy from stdin to the file, until EOF
                    tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
                    println!("Adding from stdin...");
                    // return the TempPath to keep it alive
                    (path_buf, Some(path))
                };
                // tell the provider to add the data
                let stream = controller
                    .server_streaming(ProvideRequest {
                        path,
                        in_place,
                        tag,
                    })
                    .await?;
                match aggregate_add_response(stream).await {
                    Ok((hash, entries)) => {
                        print_add_response(hash, entries);
                        let ticket = provider.ticket(hash).await?.with_token(token);
                        println!("All-in-one ticket: {ticket}");
                        anyhow::Ok(tmp_path)
                    }
                    Err(e) => {
                        eprintln!("Failed to add data: {}", e);
                        std::process::exit(-1);
                    }
                }
            }
            .instrument(info_span!("provider-add")),
        )
    };

    let db2 = db.clone();
    let gc_task = rt.local_pool().spawn_pinned(move || async move {
        'outer: loop {
            // do delay before the two phases of GC
            tokio::time::sleep(gc_period).await;
            tracing::info!("Starting GC mark phase");
            let mut stream = db2.gc_mark(IrohCollectionParser, None);
            while let Some(item) = stream.next().await {
                match item {
                    GcMarkEvent::CustomInfo(text) => {
                        tracing::info!("{}", text);
                    }
                    GcMarkEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcMarkEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
            tracing::info!("Starting GC sweep phase");
            let mut stream = db2.gc_sweep();
            while let Some(item) = stream.next().await {
                match item {
                    GcSweepEvent::CustomInfo(text) => {
                        tracing::info!("{}", text);
                    }
                    GcSweepEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcSweepEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
        }
    });

    let provider2 = provider.clone();
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down provider...");
            provider2.shutdown();
        }
        res = provider => {
            res?;
        }
    }

    gc_task.abort();
    drop(gc_task);

    // the future holds a reference to the temp file, so we need to
    // keep it for as long as the provider is running. The drop(fut)
    // makes this explicit.
    fut.abort();
    drop(fut);
    Ok(())
}

async fn provide<B: BaoStore, D: DocStore>(
    bao_store: B,
    doc_store: D,
    rt: &runtime::Handle,
    key: Option<PathBuf>,
    opts: ProvideOptions,
) -> Result<Node<B, D>> {
    let secret_key = get_secret_key(key).await?;

    let mut builder = Node::builder(bao_store, doc_store)
        .collection_parser(IrohCollectionParser)
        .custom_auth_handler(Arc::new(StaticTokenAuthHandler::new(opts.request_token)))
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
pub enum ProviderRpcPort {
    Enabled(u16),
    Disabled,
}

impl From<ProviderRpcPort> for Option<u16> {
    fn from(value: ProviderRpcPort) -> Self {
        match value {
            ProviderRpcPort::Enabled(port) => Some(port),
            ProviderRpcPort::Disabled => None,
        }
    }
}

impl fmt::Display for ProviderRpcPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderRpcPort::Enabled(port) => write!(f, "{port}"),
            ProviderRpcPort::Disabled => write!(f, "disabled"),
        }
    }
}

impl FromStr for ProviderRpcPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "disabled" {
            Ok(ProviderRpcPort::Disabled)
        } else {
            Ok(ProviderRpcPort::Enabled(s.parse()?))
        }
    }
}
