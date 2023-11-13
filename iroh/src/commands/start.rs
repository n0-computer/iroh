use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use colored::Colorize;
use futures::Future;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
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
    commands::{
        blob::{add_with_opts, BlobSource},
        rpc::clear_rpc,
    },
    config::{get_iroh_data_root_with_env, path_with_env, NodeConfig},
};

use super::{
    blob::BlobAddOptions,
    rpc::{store_rpc, RpcStatus},
    RequestTokenOptions, MAX_RPC_CONNECTIONS, MAX_RPC_STREAMS,
};

const DEFAULT_RPC_PORT: u16 = 0x1337;

#[derive(Args, Debug, Clone)]
pub struct StartArgs {
    /// Listening address to bind to.
    ///
    /// Only used with `start` or `--start`
    #[clap(long, short, global = true, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
    addr: SocketAddr,
    /// Use a token to authenticate requests for data.
    ///
    /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
    ///
    /// Only used with `start` or `--start`
    #[clap(long, global = true)]
    request_token: Option<RequestTokenOptions>,

    /// The RPC port that the the Iroh node will listen on.
    ///
    /// Only used with `start` or `--start`
    #[clap(long, global = true, default_value_t = DEFAULT_RPC_PORT)]
    rpc_port: u16,
}

impl StartArgs {
    fn request_token(&self) -> Option<RequestToken> {
        match self.request_token {
            Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
            Some(RequestTokenOptions::Token(ref token)) => Some(token.clone()),
            None => None,
        }
    }

    pub async fn run_with_command<F, T>(
        self,
        rt: &runtime::Handle,
        config: &NodeConfig,
        cmd: F,
    ) -> Result<()>
    where
        F: FnOnce(iroh::client::mem::Iroh) -> T,
        T: Future<Output = Result<()>>,
    {
        let token = self.request_token();
        let derp_map = config.derp_map()?;

        let spinner = create_spinner("Iroh booting...");
        let node = self.start_daemon_node(rt, token, derp_map).await?;
        drop(spinner);

        let msg = welcome_message(&node).await?;
        eprintln!("{}", msg);

        let client = node.client();

        let node2 = node.clone();
        tokio::select! {
            biased;
            res = cmd(client) => {
                res?;
                node2.shutdown();
            }
            res = node => {
                res?;
            }
        }

        clear_rpc(get_iroh_data_root_with_env()?).await?;

        Ok(())
    }

    pub async fn run(
        self,
        rt: &runtime::Handle,
        config: &NodeConfig,
        add_opts: BlobAddOptions,
    ) -> Result<()> {
        let token = self.request_token();
        let derp_map = config.derp_map()?;

        let spinner = create_spinner("Iroh is booting...");
        let node = self.start_daemon_node(rt, token.clone(), derp_map).await?;
        drop(spinner);

        let msg = welcome_message(&node).await?;
        eprintln!("{}", msg);

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
        &self,
        rt: &runtime::Handle,
        token: Option<RequestToken>,
        derp_map: Option<DerpMap>,
    ) -> Result<Node<iroh_bytes::store::flat::Store>> {
        if let Some(t) = token.as_ref() {
            eprintln!("Request token: {}", t);
        }

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
                .with_context(|| {
                    format!("Failed to load iroh database from {}", blob_dir.display())
                })?;
        let key = Some(path_with_env(IrohPaths::SecretKey)?);
        let doc_store = iroh_sync::store::fs::Store::new(path_with_env(IrohPaths::DocsDatabase)?)?;
        self.spawn_daemon_node(
            rt,
            bao_store,
            doc_store,
            key,
            peer_data_path,
            token,
            derp_map,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_daemon_node<B: iroh_bytes::store::Store, D: iroh_sync::store::Store>(
        &self,
        rt: &runtime::Handle,
        bao_store: B,
        doc_store: D,
        key: Option<PathBuf>,
        peers_data_path: PathBuf,
        token: Option<RequestToken>,
        derp_map: Option<DerpMap>,
    ) -> Result<Node<B>> {
        let secret_key = get_secret_key(key).await?;

        let mut builder = Node::builder(bao_store, doc_store)
            .custom_auth_handler(Arc::new(StaticTokenAuthHandler::new(token)))
            .peers_data_path(peers_data_path);
        if let Some(dm) = derp_map {
            builder = builder.derp_mode(DerpMode::Custom(dm));
        }
        let builder = builder.bind_addr(self.addr).runtime(rt);

        let node = if let Some(rpc_port) = self.rpc_port.into() {
            let rpc_endpoint = make_rpc_endpoint(&secret_key, rpc_port).await?;
            builder
                .rpc_endpoint(rpc_endpoint)
                .secret_key(secret_key)
                .spawn()
                .await?
        } else {
            builder.secret_key(secret_key).spawn().await?
        };
        Ok(node)
    }
}

async fn welcome_message<B: iroh_bytes::store::Store>(node: &Node<B>) -> Result<String> {
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
    store_rpc(get_iroh_data_root_with_env()?, actual_rpc_port).await?;

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
