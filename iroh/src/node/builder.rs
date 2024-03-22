use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use futures_lite::{FutureExt, StreamExt};
use iroh_base::key::SecretKey;
use iroh_bytes::{
    downloader::Downloader,
    protocol::Closed,
    store::{GcMarkEvent, GcSweepEvent, Map, Store as BaoStore},
};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_net::{
    magic_endpoint::get_alpn, relay::RelayMode, util::AbortingJoinHandle, MagicEndpoint,
};
use iroh_sync::net::SYNC_ALPN;
use quic_rpc::{
    transport::{misc::DummyServerEndpoint, quinn::QuinnServerEndpoint},
    RpcServer, ServiceEndpoint,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::LocalPoolHandle};
use tracing::{debug, error, error_span, info, trace, warn, Instrument};

use crate::{
    client::quic::RPC_ALPN,
    node::{Event, NodeInner},
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
    sync_engine::SyncEngine,
    util::{fs::load_secret_key, path::IrohPaths},
};

use super::{rpc, Callbacks, EventCallback, Node, RpcStatus};

pub const PROTOCOLS: [&[u8]; 3] = [&iroh_bytes::protocol::ALPN, GOSSIP_ALPN, SYNC_ALPN];

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_PORT: u16 = 11204;

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Default interval between GC runs.
const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60 * 5);

const MAX_CONNECTIONS: u32 = 1024;
const MAX_STREAMS: u64 = 10;

/// Builder for the [`Node`].
///
/// You must supply a blob store and a document store.
///
/// Blob store implementations are available in [`iroh_bytes::store`].
/// Document store implementations are available in [`iroh_sync::store`].
///
/// Everything else is optional.
///
/// Finally you can create and run the node by calling [`Builder::spawn`].
///
/// The returned [`Node`] is awaitable to know when it finishes.  It can be terminated
/// using [`Node::shutdown`].
#[derive(Debug)]
pub struct Builder<D, E = DummyServerEndpoint>
where
    D: Map,
    E: ServiceEndpoint<ProviderService>,
{
    storage: StorageConfig,
    bind_port: Option<u16>,
    secret_key: SecretKey,
    rpc_endpoint: E,
    blobs_store: D,
    keylog: bool,
    relay_mode: RelayMode,
    gc_policy: GcPolicy,
    docs_store: iroh_sync::store::fs::Store,
}

/// Configuration for storage.
#[derive(Debug)]
pub enum StorageConfig {
    /// In memory
    Mem,
    /// On disk persistet, at this location.
    Persistent(PathBuf),
}

impl Default for Builder<iroh_bytes::store::mem::Store> {
    fn default() -> Self {
        Self {
            storage: StorageConfig::Mem,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store: Default::default(),
            keylog: false,
            relay_mode: RelayMode::Default,
            rpc_endpoint: Default::default(),
            gc_policy: GcPolicy::Disabled,
            docs_store: iroh_sync::store::Store::memory(),
        }
    }
}

impl<D: Map> Builder<D> {
    /// Creates a new builder for [`Node`] using the given databases.
    pub fn with_db_and_store(
        blobs_store: D,
        docs_store: iroh_sync::store::Store,
        storage: StorageConfig,
    ) -> Self {
        Self {
            storage,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store,
            keylog: false,
            relay_mode: RelayMode::Default,
            rpc_endpoint: Default::default(),
            gc_policy: GcPolicy::Disabled,
            docs_store,
        }
    }
}

impl<D, E> Builder<D, E>
where
    D: BaoStore,
    E: ServiceEndpoint<ProviderService>,
{
    /// Persist all node data in the provided directory.
    pub async fn persist(
        self,
        root: impl AsRef<Path>,
    ) -> Result<Builder<iroh_bytes::store::fs::Store, E>> {
        let root = root.as_ref();
        let blob_dir = IrohPaths::BaoStoreDir.with_root(root);

        tokio::fs::create_dir_all(&blob_dir).await?;
        let blobs_store = iroh_bytes::store::fs::Store::load(&blob_dir)
            .await
            .with_context(|| format!("Failed to load iroh database from {}", blob_dir.display()))?;
        let docs_store =
            iroh_sync::store::fs::Store::persistent(IrohPaths::DocsDatabase.with_root(root))?;

        let v0 = blobs_store
            .import_flat_store(iroh_bytes::store::fs::FlatStorePaths {
                complete: root.join("blobs.v0"),
                partial: root.join("blobs-partial.v0"),
                meta: root.join("blobs-meta.v0"),
            })
            .await?;
        let v1 = blobs_store
            .import_flat_store(iroh_bytes::store::fs::FlatStorePaths {
                complete: root.join("blobs.v1").join("complete"),
                partial: root.join("blobs.v1").join("partial"),
                meta: root.join("blobs.v1").join("meta"),
            })
            .await?;
        if v0 || v1 {
            tracing::info!("flat data was imported - reapply inline options");
            blobs_store
                .update_inline_options(iroh_bytes::store::fs::InlineOptions::default(), true)
                .await?;
        }

        let secret_key_path = IrohPaths::SecretKey.with_root(root);
        let secret_key = load_secret_key(secret_key_path).await?;

        Ok(Builder {
            storage: StorageConfig::Persistent(root.into()),
            bind_port: self.bind_port,
            secret_key,
            blobs_store,
            keylog: self.keylog,
            rpc_endpoint: self.rpc_endpoint,
            relay_mode: self.relay_mode,
            gc_policy: self.gc_policy,
            docs_store,
        })
    }

    /// Configure rpc endpoint, changing the type of the builder to the new endpoint type.
    pub fn rpc_endpoint<E2: ServiceEndpoint<ProviderService>>(self, value: E2) -> Builder<D, E2> {
        // we can't use ..self here because the return type is different
        Builder {
            storage: self.storage,
            bind_port: self.bind_port,
            secret_key: self.secret_key,
            blobs_store: self.blobs_store,
            keylog: self.keylog,
            rpc_endpoint: value,
            relay_mode: self.relay_mode,
            gc_policy: self.gc_policy,
            docs_store: self.docs_store,
        }
    }

    /// Configure the default iroh rpc endpoint.
    pub async fn enable_rpc(
        self,
    ) -> Result<Builder<D, QuinnServerEndpoint<ProviderRequest, ProviderResponse>>> {
        let (ep, actual_rpc_port) = make_rpc_endpoint(&self.secret_key, DEFAULT_RPC_PORT)?;
        if let StorageConfig::Persistent(ref root) = self.storage {
            // store rpc endpoint
            RpcStatus::store(root, actual_rpc_port).await?;
        }

        Ok(Builder {
            storage: self.storage,
            bind_port: self.bind_port,
            secret_key: self.secret_key,
            blobs_store: self.blobs_store,
            keylog: self.keylog,
            rpc_endpoint: ep,
            relay_mode: self.relay_mode,
            gc_policy: self.gc_policy,
            docs_store: self.docs_store,
        })
    }

    /// Sets the garbage collection policy.
    ///
    /// By default garbage collection is disabled.
    pub fn gc_policy(mut self, gc_policy: GcPolicy) -> Self {
        self.gc_policy = gc_policy;
        self
    }

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to discover other nodes by `PublicKey` and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`iroh_net::relay::RelayMode`]
    /// is provided [`Self::spawn`] will result in an error.
    pub fn relay_mode(mut self, dm: RelayMode) -> Self {
        self.relay_mode = dm;
        self
    }

    /// Binds the node service to a different socket.
    ///
    /// By default it binds to `127.0.0.1:11204`.
    pub fn bind_port(mut self, port: u16) -> Self {
        self.bind_port.replace(port);
        self
    }

    /// Uses the given [`SecretKey`] for the `PublicKey` instead of a newly generated one.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = secret_key;
        self
    }

    /// Whether to log the SSL pre-master key.
    ///
    /// If `true` and the `SSLKEYLOGFILE` environment variable is the path to a file this
    /// file will be used to log the SSL pre-master key.  This is useful to inspect captured
    /// traffic.
    pub fn keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Spawns the [`Node`] in a tokio task.
    ///
    /// This will create the underlying network server and spawn a tokio task accepting
    /// connections.  The returned [`Node`] can be used to control the task as well as
    /// get information about it.
    pub async fn spawn(self) -> Result<Node<D>> {
        trace!("spawning node");
        let lp = LocalPoolHandle::new(num_cpus::get());

        // Initialize the metrics collection.
        //
        // The metrics are global per process. Subsequent calls do not change the metrics
        // collection and will return an error. We ignore this error. This means that if you'd
        // spawn multiple Iroh nodes in the same process, the metrics would be shared between the
        // nodes.
        #[cfg(feature = "metrics")]
        crate::metrics::try_init_metrics_collection().ok();

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(MAX_STREAMS.try_into()?)
            .max_concurrent_uni_streams(0u32.into());

        let endpoint = MagicEndpoint::builder()
            .secret_key(self.secret_key.clone())
            .alpns(PROTOCOLS.iter().map(|p| p.to_vec()).collect())
            .keylog(self.keylog)
            .transport_config(transport_config)
            .concurrent_connections(MAX_CONNECTIONS)
            .relay_mode(self.relay_mode);
        let endpoint = match self.storage {
            StorageConfig::Persistent(ref root) => {
                let peers_data_path = IrohPaths::PeerData.with_root(root);
                endpoint.peers_data_path(peers_data_path)
            }
            StorageConfig::Mem => endpoint,
        };
        let bind_port = self.bind_port.unwrap_or(DEFAULT_BIND_PORT);
        let endpoint = endpoint.bind(bind_port).await?;
        trace!("created quinn endpoint");

        let (cb_sender, cb_receiver) = mpsc::channel(8);
        let cancel_token = CancellationToken::new();

        debug!("rpc listening on: {:?}", self.rpc_endpoint.local_addr());

        let addr = endpoint.my_addr().await?;

        // initialize the gossip protocol
        let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default(), &addr.info);

        // spawn the sync engine
        let downloader = Downloader::new(self.blobs_store.clone(), endpoint.clone(), lp.clone());
        let ds = self.docs_store.clone();
        let sync = SyncEngine::spawn(
            endpoint.clone(),
            gossip.clone(),
            self.docs_store,
            self.blobs_store.clone(),
            downloader,
        );

        let callbacks = Callbacks::default();
        let gc_task = if let GcPolicy::Interval(gc_period) = self.gc_policy {
            tracing::info!("Starting GC task with interval {:?}", gc_period);
            let db = self.blobs_store.clone();
            let callbacks = callbacks.clone();
            let task = lp.spawn_pinned(move || Self::gc_loop(db, ds, gc_period, callbacks));
            Some(AbortingJoinHandle(task))
        } else {
            None
        };
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection(1);
        let client = crate::client::Iroh::new(quic_rpc::RpcClient::new(controller.clone()));

        let inner = Arc::new(NodeInner {
            db: self.blobs_store,
            endpoint: endpoint.clone(),
            secret_key: self.secret_key,
            controller,
            cancel_token,
            callbacks: callbacks.clone(),
            cb_sender,
            gc_task,
            rt: lp.clone(),
            sync,
        });
        let task = {
            let gossip = gossip.clone();
            let handler = rpc::Handler {
                inner: inner.clone(),
            };
            let me = endpoint.node_id().fmt_short();
            let ep = endpoint.clone();
            tokio::task::spawn(
                async move {
                    Self::run(
                        ep,
                        callbacks,
                        cb_receiver,
                        handler,
                        self.rpc_endpoint,
                        internal_rpc,
                        gossip,
                    )
                    .await
                }
                .instrument(error_span!("node", %me)),
            )
        };

        /*let task = Arc::new(
            async move {
                task.await?;
                anyhow::Ok(())
            }
            .boxed(),
        );*/

        let node = Node {
            inner,
            task: (),
            client,
        };

        // spawn a task that updates the gossip endpoints.
        // TODO: track task
        let mut stream = endpoint.local_endpoints();
        tokio::task::spawn(async move {
            while let Some(eps) = stream.next().await {
                if let Err(err) = gossip.update_endpoints(&eps) {
                    warn!("Failed to update gossip endpoints: {err:?}");
                }
            }
            warn!("failed to retrieve local endpoints");
        });

        // Wait for a single endpoint update, to make sure
        // we found some endpoints
        tokio::time::timeout(ENDPOINT_WAIT, endpoint.local_endpoints().next())
            .await
            .context("waiting for endpoint")?
            .context("no endpoints")?;

        Ok(node)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        server: MagicEndpoint,
        callbacks: Callbacks,
        mut cb_receiver: mpsc::Receiver<EventCallback>,
        handler: rpc::Handler<D>,
        rpc: E,
        internal_rpc: impl ServiceEndpoint<ProviderService>,
        gossip: Gossip,
    ) {
        let rpc = RpcServer::new(rpc);
        let internal_rpc = RpcServer::new(internal_rpc);
        if let Ok((ipv4, ipv6)) = server.local_addr() {
            debug!(
                "listening at: {}{}",
                ipv4,
                ipv6.map(|addr| format!(" and {addr}")).unwrap_or_default()
            );
        }
        let cancel_token = handler.inner.cancel_token.clone();

        // forward our initial endpoints to the gossip protocol
        // it may happen the the first endpoint update callback is missed because the gossip cell
        // is only initialized once the endpoint is fully bound
        if let Some(local_endpoints) = server.local_endpoints().next().await {
            debug!(me = ?server.node_id(), "gossip initial update: {local_endpoints:?}");
            gossip.update_endpoints(&local_endpoints).ok();
        }

        loop {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    // clean shutdown of the blobs db to close the write transaction
                    handler.inner.db.shutdown().await;
                    break
                },
                // handle rpc requests. This will do nothing if rpc is not configured, since
                // accept is just a pending future.
                request = rpc.accept() => {
                    match request {
                        Ok((msg, chan)) => {
                            handler.handle_rpc_request(msg, chan);
                        }
                        Err(e) => {
                            info!("rpc request error: {:?}", e);
                        }
                    }
                },
                // handle internal rpc requests.
                request = internal_rpc.accept() => {
                    match request {
                        Ok((msg, chan)) => {
                            handler.handle_rpc_request(msg, chan);
                        }
                        Err(_) => {
                            info!("last controller dropped, shutting down");
                            break;
                        }
                    }
                },
                // handle incoming p2p connections
                Some(mut connecting) = server.accept() => {
                    let alpn = match get_alpn(&mut connecting).await {
                        Ok(alpn) => alpn,
                        Err(err) => {
                            error!("invalid handshake: {:?}", err);
                            continue;
                        }
                    };
                    let gossip = gossip.clone();
                    let inner = handler.inner.clone();
                    let sync = handler.inner.sync.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = handle_connection(connecting, alpn, inner, gossip, sync).await {
                            warn!("Handling incoming connection ended with error: {err}");
                        }
                    });
                },
                // Handle new callbacks
                Some(cb) = cb_receiver.recv() => {
                    callbacks.push(cb).await;
                }
                else => break,
            }
        }

        // Closing the Endpoint is the equivalent of calling Connection::close on all
        // connections: Operations will immediately fail with
        // ConnectionError::LocallyClosed.  All streams are interrupted, this is not
        // graceful.
        let error_code = Closed::ProviderTerminating;
        server
            .close(error_code.into(), error_code.reason())
            .await
            .ok();
    }

    async fn gc_loop(
        db: D,
        ds: iroh_sync::store::fs::Store,
        gc_period: Duration,
        callbacks: Callbacks,
    ) {
        let mut live = BTreeSet::new();
        tracing::debug!("GC loop starting {:?}", gc_period);
        'outer: loop {
            if let Err(cause) = db.gc_start().await {
                tracing::error!("Error {} starting GC, skipping GC to be safe", cause);
                continue 'outer;
            }
            // do delay before the two phases of GC
            tokio::time::sleep(gc_period).await;
            tracing::debug!("Starting GC");
            callbacks
                .send(Event::Db(iroh_bytes::store::Event::GcStarted))
                .await;
            live.clear();
            let doc_hashes = match ds.content_hashes() {
                Ok(hashes) => hashes,
                Err(err) => {
                    tracing::error!("Error getting doc hashes: {}", err);
                    continue 'outer;
                }
            };
            let mut doc_db_error = false;
            let doc_hashes = doc_hashes
                .filter_map(|e| match e {
                    Ok(hash) => Some(hash),
                    Err(err) => {
                        tracing::error!("Error getting doc hash: {}", err);
                        doc_db_error = true;
                        None
                    }
                })
                .collect::<Vec<_>>();
            let short_hashes = doc_hashes
                .iter()
                .map(|h| h.to_hex()[..8].to_string())
                .collect::<Vec<_>>();
            tracing::info!("doc hashes {}", short_hashes.join(","));
            live.extend(doc_hashes);
            if doc_db_error {
                tracing::error!("Error getting doc hashes, skipping GC to be safe");
                continue 'outer;
            }

            tracing::debug!("Starting GC mark phase");
            let mut stream = db.gc_mark(&mut live);
            while let Some(item) = stream.next().await {
                match item {
                    GcMarkEvent::CustomDebug(text) => {
                        tracing::debug!("{}", text);
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
            drop(stream);

            tracing::debug!("Starting GC sweep phase");
            let mut stream = db.gc_sweep(&live);
            while let Some(item) = stream.next().await {
                match item {
                    GcSweepEvent::CustomDebug(text) => {
                        tracing::debug!("{}", text);
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
            callbacks
                .send(Event::Db(iroh_bytes::store::Event::GcCompleted))
                .await;
        }
    }
}

/// Policy for garbage collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcPolicy {
    /// Garbage collection is disabled.
    Disabled,
    /// Garbage collection is run at the given interval.
    Interval(Duration),
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self::Interval(DEFAULT_GC_INTERVAL)
    }
}

// TODO: Restructure this code to not take all these arguments.
#[allow(clippy::too_many_arguments)]
async fn handle_connection<D: BaoStore>(
    connecting: quinn::Connecting,
    alpn: String,
    node: Arc<NodeInner<D>>,
    gossip: Gossip,
    sync: SyncEngine,
) -> Result<()> {
    match alpn.as_bytes() {
        GOSSIP_ALPN => gossip.handle_connection(connecting.await?).await?,
        SYNC_ALPN => sync.handle_connection(connecting).await?,
        alpn if alpn == iroh_bytes::protocol::ALPN => {
            iroh_bytes::provider::handle_connection(
                connecting,
                node.db.clone(),
                node.callbacks.clone(),
                node.rt.clone(),
            )
            .await
        }
        _ => bail!("ignoring connection: unsupported ALPN protocol"),
    }
    Ok(())
}

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u32 = 1024;

/// Makes a an RPC endpoint that uses a QUIC transport
fn make_rpc_endpoint(
    secret_key: &SecretKey,
    rpc_port: u16,
) -> Result<(QuinnServerEndpoint<ProviderRequest, ProviderResponse>, u16)> {
    let rpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port);
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_concurrent_bidi_streams(MAX_RPC_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into());
    let mut server_config = iroh_net::magic_endpoint::make_server_config(
        secret_key,
        vec![RPC_ALPN.to_vec()],
        Some(transport_config),
        false,
    )?;
    server_config.concurrent_connections(MAX_RPC_CONNECTIONS);

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

    Ok((rpc_endpoint, actual_rpc_port))
}
