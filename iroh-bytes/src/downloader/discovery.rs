use std::{collections::HashSet, future::Future};

use futures::{Stream, StreamExt};
use iroh_net::NodeAddr;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::warn;

use crate::Hash;

/// Trait for content discovery services.
pub trait ContentDiscovery: Send + 'static {
    /// Stream returned from [`Self::lookup`].
    type LookupStream: Stream<Item = anyhow::Result<NodeAddr>> + Send + Unpin + 'static;
    /// Future returned from [`Self::announce`]
    type AnnounceFuture: Future<Output = anyhow::Result<()>> + Send + 'static;
    /// Find content by its hash.
    fn lookup(&self, resource: Hash) -> Self::LookupStream;
    /// Announce that we are providing a hash.
    fn announce(&self, resource: Hash) -> Self::AnnounceFuture;
}

/// A no-op content discovery service.
#[derive(Debug)]
pub struct NoContentDiscovery;

impl ContentDiscovery for NoContentDiscovery {
    type LookupStream = futures::stream::Empty<anyhow::Result<NodeAddr>>;
    type AnnounceFuture = std::future::Ready<anyhow::Result<()>>;

    fn lookup(&self, _resource: Hash) -> Self::LookupStream {
        futures::stream::empty()
    }

    fn announce(&self, _resource: Hash) -> Self::AnnounceFuture {
        std::future::ready(Ok(()))
    }
}

/// Capacity of the channel for discovery results.
const DISCOVERY_CHANNEL_CAPACITY: usize = 1024;

/// Items returned from [`DiscoveryService::next`]
pub enum LookupProgress {
    /// A new provider for a resource was discovered.
    FoundProvider(Hash, NodeAddr),
    /// The discovery stream for a resource terminated.
    Finished(Hash),
}

/// Discovery service
#[derive(derive_more::Debug)]
pub struct DiscoveryService<C: ContentDiscovery> {
    #[debug("discovery")]
    discovery: C,
    pending: HashSet<Hash>,
    tx: mpsc::Sender<LookupProgress>,
    rx: mpsc::Receiver<LookupProgress>,
    tasks: JoinSet<()>,
}

impl<C: ContentDiscovery> DiscoveryService<C> {
    /// Create a new discovery service.
    pub fn new(discovery: C) -> Self {
        let (tx, rx) = mpsc::channel(DISCOVERY_CHANNEL_CAPACITY);
        Self {
            discovery,
            pending: HashSet::new(),
            tx,
            rx,
            tasks: JoinSet::new(),
        }
    }

    /// Start a query for a resource.
    ///
    /// You should avoid querying the same resource in parallel.
    pub fn lookup(&mut self, resource: Hash) {
        if self.pending.contains(&resource) {
            return;
        }
        self.pending.insert(resource);
        let mut stream = self.discovery.lookup(resource);
        let tx = self.tx.clone();
        self.tasks.spawn(async move {
            while let Some(res) = stream.next().await {
                let node_addr = match res {
                    Ok(node_addr) => node_addr,
                    Err(err) => {
                        warn!("discovery of {resource:?} produced error: {err:?}");
                        break;
                    }
                };
                if let Err(_) = tx.send(LookupProgress::FoundProvider(resource, node_addr)).await {
                    break;
                }
            }
            tx.send(LookupProgress::Finished(resource)).await.ok();
        });
    }

    /// Receive the next pending discovery result.
    ///
    /// This method is cancellation safe.
    pub async fn next(&mut self) -> Option<LookupProgress> {
        let next = self.rx.recv().await;
        if let Some(LookupProgress::Finished(resource)) = &next {
            self.pending.remove(resource);
        }
        next
    }

    /// Shutdown all runnign discoveries.
    pub fn shutdown(&mut self) {
        self.rx.close();
        self.tasks.abort_all();
    }
}
