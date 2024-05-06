//! Trait and utils for the node discovery mechanism.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use futures_lite::{stream::Boxed as BoxStream, StreamExt};
use iroh_base::node_addr::NodeAddr;
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, warn, Instrument};

use crate::{AddrInfo, NodeId};

/// Default amout of time we wait for discovery before closing the process.
pub(super) const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum duration since the last control or data message received from an endpoint to make us
/// start a discovery task.
pub(super) const MAX_AGE: Duration = Duration::from_secs(10);

/// Node discovery for [`super::MagicSock`].
///
/// The purpose of this trait is to hook up a node discovery mechanism that
/// allows finding information such as the relay URL and direct addresses
/// of a node given its [`NodeId`].
///
/// To allow for discovery, the [`super::MagicSock`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start its own task.
pub trait Discovery: std::fmt::Debug + Send + Sync {
    /// Publish the given [`AddrInfo`] to the discovery mechanisms.
    ///
    /// This is fire and forget, since the magicsock can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's
    /// own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::MagicSock`].
    fn publish(&self, _info: &AddrInfo) {}

    /// Resolve the [`AddrInfo`] for the given [`NodeId`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(&self, _node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        None
    }
}

/// The results returned from [`Discovery::resolve`].
#[derive(Debug, Clone)]
pub struct DiscoveryItem {
    /// A static string to identify the discovery source.
    ///
    /// Should be uniform per discovery service.
    pub provenance: &'static str,
    /// Optional timestamp when this node address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    pub last_updated: Option<u64>,
    /// The adress info for the node being resolved.
    pub addr_info: AddrInfo,
}
/// A discovery service that combines multiple discovery sources.
///
/// The discovery services will resolve concurrently.
#[derive(Debug, Default)]
pub struct ConcurrentDiscovery {
    services: Vec<Box<dyn Discovery>>,
}

impl ConcurrentDiscovery {
    /// Create a empty [`ConcurrentDiscovery`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a new [`ConcurrentDiscovery`].
    pub fn from_services(services: Vec<Box<dyn Discovery>>) -> Self {
        Self { services }
    }

    /// Add a [`Discovery`] service.
    pub fn add(&mut self, service: impl Discovery + 'static) {
        self.services.push(Box::new(service));
    }
}

impl<T> From<T> for ConcurrentDiscovery
where
    T: IntoIterator<Item = Box<dyn Discovery>>,
{
    fn from(iter: T) -> Self {
        let services = iter.into_iter().collect::<Vec<_>>();
        Self { services }
    }
}

impl Discovery for ConcurrentDiscovery {
    fn publish(&self, info: &AddrInfo) {
        for service in &self.services {
            service.publish(info);
        }
    }

    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let streams = self
            .services
            .iter()
            .filter_map(|service| service.resolve(node_id));

        let streams = futures_buffered::Merge::from_iter(streams);
        Some(Box::pin(streams))
    }
}

#[derive(Debug)]
pub(super) struct DiscoveryService {
    handle: JoinHandle<()>,
    sender: flume::Sender<DiscoveryServiceMessage>,
    cancel: CancellationToken,
}

impl DiscoveryService {
    pub(super) fn new(discovery: Arc<dyn Discovery>) -> Self {
        let cancel = CancellationToken::new();
        let (sender, recv) = flume::bounded(64);
        let handle = tokio::spawn(async move {
            let mut tasks: BTreeMap<NodeId, DiscoveryTask> = BTreeMap::default();
            loop {
                let msg = tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = recv.recv_async() => {
                        match msg {
                            Err(e) => {
                                debug!("{e:?}");
                                break;
                            },
                            Ok(msg) => msg,
                        }
                   }
                };
                match msg {
                    DiscoveryServiceMessage::Start{node_id, delay, on_first_tx} => {
                        if let Some(new_task) = DiscoveryTask::start_after_delay(discovery.clone(), node_id, delay, on_first_tx, cancel.clone()) {
                            if let Some(old_task) = tasks.insert(node_id, new_task) {
                                old_task.cancel();
                            }
                        }
                    }
                    DiscoveryServiceMessage::Cancel(node_id) => {
                        match tasks.remove(&node_id)                         {
                            None => trace!("Cancelled Discovery for {node_id}, but no Discovery for that id is currently running."),
                            Some(task) => task.cancel()
                        }
                    }
                    DiscoveryServiceMessage::Publish(addr_info) => {
                        discovery.publish(&addr_info);
                    }
                }
            }
        });
        Self {
            handle,
            sender,
            cancel,
        }
    }

    pub(super) fn publish(&self, info: &AddrInfo) {
        self.sender
            .send(DiscoveryServiceMessage::Publish(*info))
            .ok();
    }

    pub(super) fn start(&self, node_id: NodeId) {
        self.sender
            .send(DiscoveryServiceMessage::Start {
                node_id,
                delay: None,
                on_first_tx: None,
            })
            .ok();
    }

    pub(super) fn start_with_delay(&self, node_id: NodeId, delay: Duration) {
        self.sender
            .send(DiscoveryServiceMessage::Start {
                node_id,
                delay: Some(delay),
                on_first_tx: None,
            })
            .ok();
    }

    pub(super) fn start_with_alert(
        &self,
        node_id: NodeId,
        on_first_tx: oneshot::Sender<Result<NodeAddr>>,
    ) {
        self.sender
            .send(DiscoveryServiceMessage::Start {
                node_id,
                delay: None,
                on_first_tx: Some(on_first_tx),
            })
            .ok();
    }

    pub(super) fn cancel(&self, node_id: NodeId) {
        self.sender
            .send(DiscoveryServiceMessage::Cancel(node_id))
            .ok();
    }
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// Messages used by the [`DiscoveryService`] struct to manage [`DiscoveryService`]s.
#[derive(Debug)]
pub(super) enum DiscoveryServiceMessage {
    /// Launch discovery for the given [`NodeId`]
    Start {
        /// The node ID for the node we are trying to discover
        node_id: NodeId,
        /// When `None`, start discovery immediately
        /// When `Some`, start discovery after a delay.
        delay: Option<Duration>,
        /// If it exists, send the first address you receive,
        /// or send an error if the discovery was unable to occur.
        on_first_tx: Option<oneshot::Sender<Result<NodeAddr>>>,
    },
    /// Cancel any discovery for the given [`NodeId`]
    Cancel(NodeId),
    /// Publish your address info
    Publish(AddrInfo),
}

/// A wrapper around a tokio task which runs a node discovery.
#[derive(derive_more::Debug)]
pub(super) struct DiscoveryTask {
    task: JoinHandle<()>,
}

impl DiscoveryTask {
    /// Start a discovery task after a delay
    ///
    /// This returns `None` if we received data or control messages from the remote endpoint
    /// recently enough. If not it returns a [`DiscoveryTask`].
    ///
    /// If `delay` is set, the [`DiscoveryTask`] will first wait for `delay` and then check again
    /// if we recently received messages from remote endpoint. If true, the task will abort.
    /// Otherwise, or if no `delay` is set, the discovery will be started.
    pub fn start_after_delay(
        discovery: Arc<dyn Discovery>,
        node_id: NodeId,
        delay: Option<Duration>,
        on_first_tx: Option<oneshot::Sender<Result<NodeAddr>>>,
        cancel: CancellationToken,
    ) -> Option<Self> {
        let task = tokio::task::spawn(
            async move {
                // If delay is set, wait and recheck if discovery is needed. If not, early-exit.
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                Self::run(discovery, node_id, on_first_tx, cancel).await
            }
            .instrument(error_span!("discovery", node = %node_id.fmt_short())),
        );
        Some(Self { task })
    }

    /// Cancel the discovery task.
    pub fn cancel(&self) {
        self.task.abort();
    }

    fn create_stream(
        discovery: Arc<dyn Discovery>,
        node_id: NodeId,
    ) -> Result<BoxStream<Result<DiscoveryItem>>> {
        let stream = discovery
            .resolve(node_id)
            .ok_or_else(|| anyhow!("No discovery service can resolve node {node_id}",))?;
        Ok(stream)
    }

    async fn run(
        discovery: Arc<dyn Discovery>,
        node_id: NodeId,
        mut on_first_tx: Option<oneshot::Sender<Result<NodeAddr>>>,
        cancel: CancellationToken,
    ) {
        let mut stream = match Self::create_stream(discovery, node_id) {
            Ok(stream) => stream,
            Err(err) => {
                on_first_tx.map(|s| s.send(Err(err)).ok());
                return;
            }
        };
        debug!("discovery: start");
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = stream.next() => next
            };
            match next {
                Some(Ok(r)) => {
                    if r.addr_info.is_empty() {
                        debug!(provenance = %r.provenance, addr = ?r.addr_info, "discovery: empty address found");
                        continue;
                    }
                    debug!(provenance = %r.provenance, addr = ?r.addr_info, "discovery: new address found");
                    let addr = NodeAddr {
                        info: r.addr_info,
                        node_id,
                    };
                    if let Some(tx) = on_first_tx.take() {
                        tx.send(Ok(addr)).ok();
                    }
                }
                Some(Err(err)) => {
                    warn!(?err, "discovery service produced error");
                    break;
                }
                None => break,
            }
        }
        if let Some(tx) = on_first_tx.take() {
            let err = anyhow!("Discovery produced no results for {}", node_id.fmt_short());
            tx.send(Err(err)).ok();
        }
    }
}

impl Drop for DiscoveryTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}
