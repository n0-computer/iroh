use anyhow::Result;
use iroh_api::Api;
use iroh_rpc_client::Config as RpcClientConfig;

/// An address allowing internal communication with the iroh store service.
///
/// This is only needed to wire up the several services together and should not be used to
/// communicate directly to the service.
///
/// Can be created from [`store::RocksStoreService::addr`].
pub use iroh_rpc_types::p2p::P2pClientAddr;

/// An address allowing internal communication with the iroh p2p service.
///
/// This is only needed to wire up the several services together and should not be used to
/// communicate directly to the service.
///
/// Can be created from [`p2p::P2pService::addr`].
pub use iroh_rpc_types::store::StoreClientAddr;

mod p2p;
mod store;

pub use p2p::P2pService;
pub use store::RocksStoreService;

/// The full iroh system.
///
/// Creating this will create an iroh system and start several tokio tasks.  To make the
/// system do anything use the [`Iroh::api`] function to get an API.
#[derive(Debug)]
pub struct Iroh {
    store: RocksStoreService,
    p2p: P2pService,
    api: Api,
}

impl Iroh {
    /// Creates a new running iroh system.
    ///
    /// To create an iroh system first a store and p2p service must be created and must be
    /// wired up to communicate together.  This means the [`P2pService`] must be created
    /// with the [`StoreClientAddr`] from the store used.
    ///
    /// # Examples
    ///
    /// ```
    /// tokio_test::block_on(async {
    /// use iroh_embed::{Iroh, P2pService, RocksStoreService};
    /// use testdir::testdir;
    ///
    /// let dir = testdir!();
    /// let store = RocksStoreService::new(dir.join("store")).await.unwrap();
    /// let p2p = P2pService::new(Default::default(), dir, store.addr()).await.unwrap();
    /// let _iroh = Iroh::new(store, p2p, None, None).await.unwrap();
    /// # })
    /// ```
    // TODO: on this level we should use better API than parsing the resolvers and indexers
    // from strings.
    // TODO: the store will also want to support an in-memory version.
    pub async fn new(
        store: RocksStoreService,
        p2p: P2pService,
        http_resolvers: Option<Vec<String>>,
        indexer_endpoint: Option<String>,
    ) -> Result<Self> {
        let rpc_config = RpcClientConfig {
            gateway_addr: None,
            p2p_addr: Some(p2p.addr()),
            store_addr: Some(store.addr()),
            channels: Some(1),
        };
        let api_config = iroh_api::config::Config {
            rpc_client: rpc_config,
            metrics: Default::default(),
            http_resolvers,
            indexer_endpoint,
        };
        let api = Api::new(api_config).await?;

        Ok(Self { store, p2p, api })
    }

    /// Returns a reference to the iroh API.
    ///
    /// This API gives you some high level functionality using the built-in p2p and store
    /// nodes as well as a few lower-level and p2p-specific functions.
    pub fn api(&self) -> &Api {
        &self.api
    }

    /// Gracefully stop the iroh system.
    ///
    /// TODO: Graceful is a lie right now.
    /// TODO: Will probably become async.
    /// TODO: Maybe should consume self.
    pub fn stop(&self) {
        self.p2p.stop();
        self.store.stop();
    }
}
