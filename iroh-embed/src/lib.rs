use anyhow::Result;
use iroh_api::Api;
use iroh_one::mem_p2p;
use iroh_one::mem_store;
use iroh_rpc_types::Addr;
use tokio::task::JoinHandle;

// TODO: This struct with all fields being pub is not suitable for an API as it is not
// extensible.  Probably should be turned into some kind of builder.
#[doc(inline)]
pub use iroh_one::config::Config;

/// The full iroh system.
///
/// Creating this will create an iroh system and start several tokio tasks.
#[derive(Debug)]
pub struct Iroh {
    store_server: JoinHandle<()>,
    p2p_server: JoinHandle<()>,
    api: Api,
}

impl Iroh {
    /// Creates a new running iroh system.
    ///
    /// Mind you, the config is a random set of things that might be ignored, configuration
    /// needs to be improved but I've been stuck too long.
    ///
    /// - Default::default results in using the on-system iroh environment (e.g. uses the
    ///   iroh store in the normal location) while this should be independent.
    /// - `rpc_client` is completely ignored.
    /// - `metrics` is partially ignored, it's weird.
    /// - http resolvers and indexers come from gateway config but are used even when there
    ///   is no gateway.
    /// - the metrics config is ignored, this is not our business when embedding.  tracing
    ///   is easy enough to hook up, maybe needs some docs.  hooking up prometheus metrics
    ///   may need some more support from us.
    pub async fn new(mut config: Config) -> Result<Self> {
        let (store_recv, store_sender) = Addr::new_mem();
        let (p2p_recv, p2p_sender) = Addr::new_mem();
        config.rpc_client.store_addr = Some(store_sender);
        config.rpc_client.p2p_addr = Some(p2p_sender);
        config.synchronize_subconfigs();

        let store_rpc = mem_store::start(store_recv, config.store).await?;
        let p2p_rpc = mem_p2p::start(p2p_recv, config.p2p).await?;

        let api_config = iroh_api::config::Config {
            rpc_client: config.rpc_client,
            metrics: config.metrics,
            http_resolvers: config.gateway.http_resolvers,
            indexer_endpoint: config.gateway.indexer_endpoint,
        };
        let api = Api::new(api_config).await?;

        Ok(Self {
            store_server: store_rpc,
            p2p_server: p2p_rpc,
            api,
        })
    }

    /// Returns a reference to the iroh API.
    ///
    /// This API gives you some high level functionality using the built-in p2p and store
    /// nodes as well as a few lower-level and p2p-specific functions.
    pub fn api(&self) -> &Api {
        &self.api
    }

    /// Gracefully stop the iroh system.
    pub fn stop(&self) {
        // TODO: Change the tonic RPC server to use `serve_with_shutdown`.
        todo!();
    }
}

impl Drop for Iroh {
    fn drop(&mut self) {
        self.p2p_server.abort();
        self.store_server.abort();
    }
}
