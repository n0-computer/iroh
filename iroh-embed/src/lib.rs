//! Using iroh's peer-to-peer IPFS as a library.
//!
//! This crate supports embedding iroh in another application, enables running an IPFS node.
//! By default the system will not interfere with any other IPFS node, iroh or otherwise, on
//! the same host.
//!
//! An iroh system consists of several services, depending on how the IPFS node should
//! behave not all of them may be needed:
//!
//! - The **store** service.  Iroh needs somewhere to store data, currently only an on-disk
//!   storage is available as [`RocksStoreService`], in the future an in-memory version will
//!   be available too.
//! - The **p2p** service.  This service communicates with the wider IPFS network.
//! - The **gateway** service.  This provides an HTTP gateway into IPFS.  Currently not yet
//!   supported in iroh-embed.
//!
//! The current work-in-progress version of iroh-embed only allows using both a store and
//! p2p service.  Future combinations will become available as features are added.
//!
//! # Getting started
//!
//! To create an iroh system you will need a few things:
//!
//! - Create a store service using [`RocksStoreService`].
//! - Create a p2p service using [`P2pService`] and hooking it up to your earlier created
//!   store service.
//! - Create the [`Iroh`] system using [`IrohBuilder`].
//! - Use the system using [`Iroh::api`].
//!
//! An example is available in the repository under `examples/embed`.

use std::default;

use anyhow::{bail, Result};
use iroh_rpc_client::Config as RpcClientConfig;

pub use iroh_api::Api;
pub use iroh_p2p::Libp2pConfig;
pub use iroh_resolver::indexer::IndexerUrl;
pub use reqwest::Url;

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

/// Builder for an [`Iroh`] system.
///
/// At least a store and p2p service must be added using the [`IrohBuilder::with_store`] and
/// [`IrohBuilder::with_p2p`].
///
/// # Examples
///
/// ```no_run
/// use iroh_embed::{Iroh, IrohBuilder, Libp2pConfig, P2pService, RocksStoreService};
/// use testdir::testdir;
/// # tokio_test::block_on(async {
/// let dir = testdir!();
/// let store = RocksStoreService::new(dir.join("store")).await.unwrap();
/// let mut p2p_config = Libp2pConfig::default();
/// p2p_config.listening_multiaddrs = vec![
///     "/ip4/0.0.0.0/tcp/0".parse().unwrap(),  // random port
///     "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),  // random port
/// ];
/// let p2p = P2pService::new(p2p_config, dir, store.addr()).await.unwrap();
/// let _iroh: Iroh = IrohBuilder::new()
///                     .with_store(store)
///                     .with_p2p(p2p)
///                     .build()
///                     .await
///                     .unwrap();
/// # })
/// ```
#[derive(Debug)]
pub struct IrohBuilder {
    store: Option<RocksStoreService>,
    p2p: Option<P2pService>,
    http_resolvers: Vec<String>,
    indexer: Option<IndexerUrl>,
}

impl Default for IrohBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IrohBuilder {
    /// Creates a new [`IrohBuilder`].
    pub fn new() -> Self {
        Self {
            store: None,
            p2p: None,
            http_resolvers: vec![],
            indexer: Some(IndexerUrl::default()),
        }
    }

    /// Adds a store service.
    ///
    /// Every [`Iroh`] system needs a store so this can not be skipped.
    pub fn with_store(mut self, store: RocksStoreService) -> Self {
        self.store = Some(store);
        self
    }

    /// Adds a p2p service.
    ///
    /// This service **must** have been built using the address from the store service
    /// passed to [`IrohBuilder::with_store`].
    ///
    /// Every [`Iroh`] system currently needs a p2p service so this can not be skipped.
    pub fn with_p2p(mut self, p2p: P2pService) -> Self {
        self.p2p = Some(p2p);
        self
    }

    /// Adds IPFS HTTP gateways as resolvers to the iroh system.
    ///
    /// IPFS HTTP gateways can be used to resolve IPFS content in addition to retrieving the
    /// content from the IPFS peer-to-peer system.
    // TODO: Allow using this without a p2p node?
    pub fn with_http_resolvers(mut self, http_resolvers: impl Iterator<Item = Url>) -> Self {
        self.http_resolvers = http_resolvers.map(|u| u.to_string()).collect();
        self
    }

    /// Adds a single HTTP gateway to the list of HTTP gateways to use.
    ///
    /// IPFS HTTP gateways are used to look up providers of CIDs, in addition to looking
    /// them up in the Distrubuted Hash Table (DHT).
    pub fn push_http_gateway(mut self, http_gateway: Url) -> Self {
        self.http_resolvers.push(http_gateway.to_string());
        self
    }

    /// Removes all IPFS HTTP gateways.
    pub fn clear_http_gateways(mut self) -> Self {
        self.http_resolvers.clear();
        self
    }

    /// Use the given IPFS indexer with this iroh system.
    ///
    /// An IPFS indexer keeps an index of CIDs and IPFS nodes which currently provide the
    /// data for the CID.
    ///
    /// By default this uses the [`iroh_resolver::indexer::CID_CONTACT`] indexer.
    pub fn with_indexer(mut self, indexer: IndexerUrl) -> Self {
        self.indexer = Some(indexer);
        self
    }

    /// Do not use any indexer.
    pub fn clear_indexer(mut self) -> Self {
        self.indexer = None;
        self
    }

    /// Builds the iroh system.
    pub async fn build(self) -> Result<Iroh> {
        // TODO: would be good if we can verify the p2p service is correctly hooked up to
        // the store service.
        let store = match self.store {
            Some(store) => store,
            None => bail!("missing store service"),
        };
        let p2p = match self.p2p {
            Some(p2p) => p2p,
            None => bail!("missing p2p service"),
        };
        let http_resolvers = match self.http_resolvers.is_empty() {
            true => None,
            false => Some(self.http_resolvers),
        };

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
            indexer_endpoint: self.indexer,
        };
        let api = Api::new(api_config).await?;

        Ok(Iroh { store, p2p, api })
    }
}

/// The full iroh system.
///
/// This must be constructed using [`IrohBuilder`].  Creating an iroh system will start
/// various tokio tasks.  To make the system do anything use the [`Iroh::api`] function to
/// get an API.
#[derive(Debug)]
pub struct Iroh {
    store: RocksStoreService,
    p2p: P2pService,
    api: Api,
}

impl Iroh {
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
