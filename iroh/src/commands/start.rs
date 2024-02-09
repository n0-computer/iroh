use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use colored::Colorize;
use futures::Future;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use iroh::{
    client::quic::RPC_ALPN,
    node::Node,
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
    util::{fs::load_secret_key, path::IrohPaths},
};
use iroh_net::{
    derp::{DerpMap, DerpMode},
    key::SecretKey,
};
use quic_rpc::{transport::quinn::QuinnServerEndpoint, ServiceEndpoint};
use tokio_util::task::LocalPoolHandle;
use tracing::{info_span, Instrument};

use crate::config::NodeConfig;

use super::rpc::RpcStatus;

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

/// Whether to stop the node after running a command or run forever until stopped.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RunType {
    /// Run a single command, and then shutdown the node. Allow to abort with Ctrl-C.
    SingleCommandAbortable,
    /// Run a single command, and then shutdown the node. Do not abort on Ctrl-C (expects Ctrl-C to be handled internally).
    SingleCommandNoAbort,
    /// Run until manually stopped (through Ctrl-C or shutdown RPC command)
    UntilStopped,
}

#[derive(thiserror::Error, Debug)]
#[error("iroh is already running on port {0}")]
pub struct AlreadyRunningError(u16);

pub async fn run_with_command<F, T>(
    rt: &LocalPoolHandle,
    config: &NodeConfig,
    iroh_data_root: &Path,
    run_type: RunType,
    command: F,
) -> Result<()>
where
    F: FnOnce(iroh::client::mem::Iroh) -> T + Send + 'static,
    T: Future<Output = Result<()>> + 'static,
{
    #[cfg(feature = "metrics")]
    let metrics_fut = start_metrics_server(config.metrics_addr);

    let res = run_with_command_inner(rt, config, iroh_data_root, run_type, command).await;

    #[cfg(feature = "metrics")]
    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
    }

    let (clear_rpc, res) = match res {
        Ok(()) => (true, res),
        Err(e) => match e.downcast::<AlreadyRunningError>() {
            // iroh is already running in a different process, do no remove the rpc lockfile
            Ok(already_running) => (false, Err(already_running.into())),
            Err(e) => (true, Err(e)),
        },
    };

    if clear_rpc {
        RpcStatus::clear(iroh_data_root).await?;
    }

    res
}

async fn run_with_command_inner<F, T>(
    rt: &LocalPoolHandle,
    config: &NodeConfig,
    iroh_data_root: &Path,
    run_type: RunType,
    command: F,
) -> Result<()>
where
    F: FnOnce(iroh::client::mem::Iroh) -> T + Send + 'static,
    T: Future<Output = Result<()>> + 'static,
{
    let derp_map = config.derp_map()?;

    let spinner = create_spinner("Iroh booting...");
    let node = start_node(rt, iroh_data_root, derp_map).await?;
    drop(spinner);

    eprintln!("{}", welcome_message(&node)?);

    let client = node.client();

    let mut command_task = rt.spawn_pinned(move || {
        async move {
            match command(client).await {
                Err(err) => Err(err),
                Ok(()) => {
                    // keep the task open forever if not running in single-command mode
                    if run_type == RunType::UntilStopped {
                        futures::future::pending().await
                    }
                    Ok(())
                }
            }
        }
        .instrument(info_span!("command"))
    });

    let node2 = node.clone();
    tokio::select! {
        biased;
        // always abort on signal-c
        _ = tokio::signal::ctrl_c(), if run_type != RunType::SingleCommandNoAbort => {
            command_task.abort();
            node.shutdown();
            node.await?;
        }
        // abort if the command task finishes (will run forever if not in single-command mode)
        res = &mut command_task => {
            node.shutdown();
            let _ = node.await;
            res??;
        }
        // abort if the node future completes (shutdown called or error)
        res = node2 => {
            command_task.abort();
            res?;
        }
    }
    Ok(())
}

/// Migrate the flat store from v0 to v1. This can not be done in the store itself, since the
/// constructor of the store now only takes a single directory.
fn migrate_flat_store_v0_v1(iroh_data_root: PathBuf) -> anyhow::Result<()> {
    let complete_v0 = iroh_data_root.join("blobs.v0");
    let partial_v0 = iroh_data_root.join("blobs-partial.v0");
    let meta_v0 = iroh_data_root.join("blobs-meta.v0");
    let complete_v1 = IrohPaths::BaoFlatStoreDir
        .with_root(&iroh_data_root)
        .join("complete");
    let partial_v1 = IrohPaths::BaoFlatStoreDir
        .with_root(&iroh_data_root)
        .join("partial");
    let meta_v1 = IrohPaths::BaoFlatStoreDir
        .with_root(&iroh_data_root)
        .join("meta");
    if complete_v0.exists() && !complete_v1.exists() {
        tracing::info!(
            "moving complete files from {} to {}",
            complete_v0.display(),
            complete_v1.display()
        );
        std::fs::rename(complete_v0, complete_v1).context("migrating complete store failed")?;
    }
    if partial_v0.exists() && !partial_v1.exists() {
        tracing::info!(
            "moving partial files from {} to {}",
            partial_v0.display(),
            partial_v1.display()
        );
        std::fs::rename(partial_v0, partial_v1).context("migrating partial store failed")?;
    }
    if meta_v0.exists() && !meta_v1.exists() {
        tracing::info!(
            "moving meta files from {} to {}",
            meta_v0.display(),
            meta_v1.display()
        );
        std::fs::rename(meta_v0, meta_v1).context("migrating meta store failed")?;
    }
    Ok(())
}

pub(crate) async fn start_node(
    rt: &LocalPoolHandle,
    iroh_data_root: &Path,
    derp_map: Option<DerpMap>,
) -> Result<Node<iroh_bytes::store::flat::Store>> {
    let rpc_status = RpcStatus::load(iroh_data_root).await?;
    match rpc_status {
        RpcStatus::Running(port) => {
            return Err(AlreadyRunningError(port).into());
        }
        RpcStatus::Stopped => {
            // all good, we can go ahead
        }
    }

    let blob_dir = IrohPaths::BaoFlatStoreDir.with_root(iroh_data_root);
    let peers_data_path = IrohPaths::PeerData.with_root(iroh_data_root);
    tokio::fs::create_dir_all(&blob_dir).await?;
    let root = iroh_data_root.to_path_buf();
    tokio::task::spawn_blocking(|| migrate_flat_store_v0_v1(root)).await??;
    let bao_store = iroh_bytes::store::flat::Store::load(&blob_dir)
        .await
        .with_context(|| format!("Failed to load iroh database from {}", blob_dir.display()))?;
    let secret_key_path = Some(IrohPaths::SecretKey.with_root(iroh_data_root));
    let doc_store =
        iroh_sync::store::fs::Store::new(IrohPaths::DocsDatabase.with_root(iroh_data_root))?;

    let secret_key = get_secret_key(secret_key_path).await?;
    let rpc_endpoint = make_rpc_endpoint(&secret_key, DEFAULT_RPC_PORT, iroh_data_root).await?;
    let derp_mode = match derp_map {
        None => DerpMode::Default,
        Some(derp_map) => DerpMode::Custom(derp_map),
    };

    Node::builder(bao_store, doc_store)
        .derp_mode(derp_mode)
        .peers_data_path(peers_data_path)
        .local_pool(rt)
        .rpc_endpoint(rpc_endpoint)
        .secret_key(secret_key)
        .spawn()
        .await
}

fn welcome_message<B: iroh_bytes::store::Store>(node: &Node<B>) -> Result<String> {
    let msg = format!(
        "{}\nNode ID: {}\n",
        "Iroh is running".green(),
        node.node_id()
    );

    Ok(msg)
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
    iroh_data_root: &Path,
) -> Result<impl ServiceEndpoint<ProviderService>> {
    let rpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port);
    let server_config = iroh::node::make_server_config(
        secret_key,
        MAX_RPC_STREAMS,
        MAX_RPC_CONNECTIONS,
        vec![RPC_ALPN.to_vec()],
    )?;

    let rpc_quinn_endpoint = quinn::Endpoint::server(server_config.clone(), rpc_addr.into());
    let rpc_quinn_endpoint = match rpc_quinn_endpoint {
        Ok(ep) => ep,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AddrInUse {
                tracing::warn!(
                    "RPC port {} already in use, switching to random port",
                    rpc_port
                );
                // Use a random port
                quinn::Endpoint::server(
                    server_config,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
                )?
            } else {
                return Err(err.into());
            }
        }
    };

    let actual_rpc_port = rpc_quinn_endpoint.local_addr()?.port();
    let rpc_endpoint =
        QuinnServerEndpoint::<ProviderRequest, ProviderResponse>::new(rpc_quinn_endpoint)?;

    // store rpc endpoint
    RpcStatus::store(iroh_data_root, actual_rpc_port).await?;

    Ok(rpc_endpoint)
}

/// Create a nice spinner.
fn create_spinner(msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg);
    pb.with_finish(indicatif::ProgressFinish::AndClear)
}

#[cfg(feature = "metrics")]
pub fn start_metrics_server(
    metrics_addr: Option<SocketAddr>,
) -> Option<tokio::task::JoinHandle<()>> {
    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        // metrics are initilaized in iroh::node::Node::spawn
        // here we only start the server
        return Some(tokio::task::spawn(async move {
            if let Err(e) = iroh_metrics::metrics::start_metrics_server(metrics_addr).await {
                eprintln!("Failed to start metrics server: {e}");
            }
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    #[tokio::test]
    async fn test_run_rpc_lock_file() -> Result<()> {
        let data_dir = tempfile::TempDir::with_prefix("rpc-lock-file-")?;
        let lock_file_path = data_dir
            .path()
            .join(IrohPaths::RpcLock.with_root(data_dir.path()));
        let data_dir_path = data_dir.path().to_path_buf();

        let rt1 = LocalPoolHandle::new(1);
        let rt2 = LocalPoolHandle::new(1);
        let (ready_s, ready_r) = tokio::sync::oneshot::channel();
        let (close_s, close_r) = tokio::sync::oneshot::channel();

        // run the first start command, using channels to coordinate so we know when the node has fully booted up, and when we need to shut the node down
        let start = tokio::spawn(async move {
            run_with_command(
                &rt1,
                &NodeConfig::default(),
                &data_dir_path,
                RunType::SingleCommandAbortable,
                |_| async move {
                    // inform the test the node is booted up
                    ready_s.send(()).unwrap();

                    // wait until the test tells us to shut down the node
                    close_r.await?;
                    Ok(())
                },
            )
            .await
        });

        // allow ample time for iroh to boot up
        if tokio::time::timeout(Duration::from_millis(20000), ready_r)
            .await
            .is_err()
        {
            start.abort();
            bail!("First `run_with_command` call never started");
        }

        // ensure the rpc lock file exists
        if !lock_file_path.try_exists()? {
            start.abort();
            bail!("First `run_with_command` call never made the rpc lockfile");
        }

        // run the second command, this should fail
        if run_with_command(
            &rt2,
            &NodeConfig::default(),
            data_dir.path(),
            RunType::SingleCommandAbortable,
            |_| async move { Ok(()) },
        )
        .await
        .is_ok()
        {
            start.abort();
            bail!("Second `run_with_command` call should return error");
        }

        // ensure the rpc lock file still exists
        if !lock_file_path.try_exists()? {
            start.abort();
            bail!("Second `run_with_command` removed the rpc lockfile");
        }

        // inform the node it should close
        close_s.send(()).unwrap();

        // wait for the node to close
        if tokio::time::timeout(Duration::from_millis(1000), start)
            .await
            .is_err()
        {
            bail!("First `run_with_command` never closed");
        }

        // ensure the lockfile no longer exists
        if lock_file_path.try_exists()? {
            bail!("First `run_with_command` closed without removing the rpc lockfile");
        }
        Ok(())
    }
}
