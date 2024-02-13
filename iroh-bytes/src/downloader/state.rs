use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    time::Duration,
};

use hashlink::{LinkedHashMap as IndexMap, LinkedHashSet as IndexSet};
use iroh_base::hash::BlobFormat;
use iroh_net::NodeId;
use tracing::debug;

use super::{
    limits::ConcurrencyLimits, DownloadOutcome, FailureAction, IDLE_PEER_TIMEOUT,
    INITIAL_RETRY_COUNT, INITIAL_RETRY_DELAY,
};
use crate::{Hash, HashAndFormat};

#[derive(Debug)]
pub enum InEvent {
    AddNode {
        node: NodeId,
        hints: NodeHints,
    },
    AddResource {
        intent: IntentId,
        resource: HashAndFormat,
        hints: ResourceHints,
    },
    CancelIntent {
        intent: IntentId,
        resource: Hash,
    },
    TransferFinished {
        id: TransferId,
        result: Result<DownloadOutcome, FailureAction>,
    },
    NodeConnectSuccess {
        node: NodeId,
    },
    NodeConnectFailed {
        node: NodeId,
    },
    TimerExpired {
        timer: Timer,
    },
    DiscoveryFinished {
        resource: Hash,
    },
}

#[must_use = "OutEvents must be handled"]
#[derive(Debug)]
pub enum OutEvent {
    StartTransfer {
        info: TransferInfo,
        intents: Vec<IntentId>,
    },
    StartDiscovery(Hash),
    StartConnect(NodeId),
    RegisterTimer(Duration, Timer),
    DropConnection(NodeId),
    CancelTransfer(TransferId),
    TransferFinished {
        resource: Hash,
        transfer_id: TransferId,
        intents: HashSet<IntentId>,
        result: Result<DownloadOutcome, ()>,
    },
}

#[derive(Debug)]
pub enum Timer {
    RetryNode(NodeId),
    IdleTimeout(NodeId),
}

type NodeMap = BTreeMap<NodeId, NodeInfo>;
type ResourceMap = IndexMap<Hash, ResourceInfo>;

/// Downloader state
#[derive(Debug, Default)]
pub struct State {
    resources: ResourceMap,
    nodes: NodeMap,
    transfers: BTreeMap<TransferId, TransferInfo>,
    limits: ConcurrencyLimits,
    transfer_id_gen: NextTransferId,
    actions: Vec<OutEvent>,
}

impl State {
    pub fn new(concurrency_limits: ConcurrencyLimits) -> Self {
        Self {
            limits: concurrency_limits,
            ..Default::default()
        }
    }
    pub fn handle(&mut self, in_event: InEvent) {
        debug!("handle {in_event:?}");
        match in_event {
            InEvent::AddNode { node, hints } => self.add_node(node, hints),
            InEvent::AddResource {
                resource,
                intent,
                hints,
            } => self.add_resource(resource, intent, hints),
            InEvent::CancelIntent { intent, resource } => self.cancel_intent(resource, intent),
            InEvent::TransferFinished { id, result } => self.on_transfer_finished(id, result),
            InEvent::NodeConnectSuccess { node } => self.on_node_connected(node),
            InEvent::NodeConnectFailed { node } => self.on_node_failed(node, true),
            InEvent::TimerExpired { timer } => self.on_timer(timer),
            InEvent::DiscoveryFinished { resource } => self.on_discovery_finished(resource),
        }
    }

    #[must_use = "actions must be handled"]
    pub fn drain_actions(&mut self) -> impl Iterator<Item = OutEvent> + '_ {
        self.actions.drain(..)
    }

    pub fn active_transfer_for_resource(&self, resource: &Hash) -> Option<TransferId> {
        self.resources.get(resource).and_then(|r| r.active_transfer)
    }

    fn add_node(&mut self, node: NodeId, hints: NodeHints) {
        let at_connections_capacity = self.at_connections_capacity();
        let node_info = self.nodes.entry(node).or_default();
        for resource in hints.resources {
            // TODO: I think if we add the resource *later*, then it will not be associated to the
            // node..
            if node_info.resources.insert(resource) {
                let resource_state = self
                    .resources
                    .entry(resource)
                    .or_insert_with(Default::default);
                resource_state.nodes.insert(node);
                resource_state.skip_nodes.remove(&node);
            }
        }
        match node_info.state {
            NodeState::Pending { .. } => {
                // node is pending - nothing to do
            }
            NodeState::Connected { .. } => {
                // node is connected: add more transfers if possible
                self.node_fill_transfers(node);
            }
            NodeState::Disconnected { .. } => {
                // node is disconnected
                if !at_connections_capacity
                    && node_should_connect(&self.resources, &node, node_info)
                {
                    node_info.set_connecting();
                    self.actions.push(OutEvent::StartConnect(node));
                }
            }
        }
    }

    fn connection_count(&self) -> usize {
        self.nodes.values().filter(|n| n.state.is_active()).count()
    }

    fn at_connections_capacity(&self) -> bool {
        self.limits.at_connections_capacity(self.connection_count())
    }

    fn add_resource(&mut self, resource: HashAndFormat, intent: IntentId, hints: ResourceHints) {
        let state = self
            .resources
            .entry(resource.hash)
            .or_insert_with(|| ResourceInfo::new(resource.format, hints.skip_discovery));
        state.skip_nodes.extend(hints.skip_nodes);
        state.intents.insert(intent);
        if !hints.skip_discovery && state.discovery == DiscoveryState::Disabled {
            state.discovery = DiscoveryState::Idle;
        }
        // start discovery if not already running or disabled
        if matches!(
            state.discovery,
            DiscoveryState::Idle | DiscoveryState::Finished
        ) {
            self.actions.push(OutEvent::StartDiscovery(resource.hash));
            state.discovery = DiscoveryState::Running;
        }
        // "upgrade" to hashseq if previously only requested as raw blob
        if resource.format == BlobFormat::HashSeq {
            state.format = BlobFormat::HashSeq;
        }
        for node in hints.nodes {
            self.add_node(node, NodeHints::with_resource(resource.hash));
        }
    }

    fn cancel_intent(&mut self, resource: Hash, intent: IntentId) {
        if let Some(resource_state) = self.resources.get_mut(&resource) {
            resource_state.intents.remove(&intent);
            if resource_state.intents.is_empty() {
                if let Some(id) = resource_state.active_transfer.take() {
                    self.actions.push(OutEvent::CancelTransfer(id));
                } else {
                    self.remove_resource(&resource);
                }
            }
        }
    }

    fn node_fill_transfers(&mut self, node: NodeId) {
        let Some(node_info) = self.nodes.get_mut(&node) else {
            return;
        };

        // if we are not connected or reached the maximum number of concurrent requests, nothing to
        // do.
        if !node_info.is_connected()
            || self
                .limits
                .node_at_request_capacity(node_info.active_transfers.len())
            || self.limits.at_requests_capacity(self.transfers.len())
        {
            return;
        }

        // Start new transfers, up to as many as the configured limits permit.
        if let Some(remaining) = self
            .limits
            .remaining_request(node_info.active_transfers.len(), self.transfers.len())
        {
            let remaining: usize = remaining.into();
            let candidates = resources_by_node(&self.resources, node_info);
            let mut next_resources = IndexSet::new();
            for (resource, resource_state) in candidates {
                if !resource_state.can_start_transfer(&node) {
                    continue;
                }
                next_resources.insert(*resource);
                if next_resources.len() == remaining {
                    break;
                }
            }

            for resource in next_resources {
                let resource_state = self.resources.get_mut(&resource).expect("just checked");

                let id = self.transfer_id_gen.next();
                let haf = HashAndFormat::new(resource, resource_state.format);
                let info = TransferInfo {
                    id,
                    resource: haf,
                    node,
                };
                let intents = resource_state.intents.iter().cloned().collect::<Vec<_>>();
                self.actions.push(OutEvent::StartTransfer {
                    info: info.clone(),
                    intents,
                });

                self.transfers.insert(id, info);
                node_info.active_transfers.insert(id);
                resource_state.active_transfer = Some(id);
            }
        }

        if node_info.is_newly_idle() {
            self.actions.push(OutEvent::RegisterTimer(
                IDLE_PEER_TIMEOUT,
                Timer::IdleTimeout(node),
            ));
            node_info.set_idle_timer_started();
        } else {
            node_info.set_connected();
        };
    }

    fn on_node_connected(&mut self, node: NodeId) {
        let Some(node_info) = self.nodes.get_mut(&node) else {
            return;
        };
        node_info.set_connected();
        self.node_fill_transfers(node)
    }

    fn on_node_failed(&mut self, node: NodeId, may_reconnect: bool) {
        let Some(node_info) = self.nodes.get_mut(&node) else {
            return;
        };
        if may_reconnect && node_info.can_reconnect() {
            let delay = INITIAL_RETRY_DELAY
                * (INITIAL_RETRY_COUNT.saturating_sub(node_info.remaining_retries()) as u32 + 1);
            // TODO: do we want to drop the connection here? This should only be invoked if we
            // received a transport-layer error from the connection. Not sure though if actually
            // dropping the connection is what we want to do. Maybe we also want to just wait until
            // we reuse the connection again?
            self.actions.push(OutEvent::DropConnection(node));
            self.actions
                .push(OutEvent::RegisterTimer(delay, Timer::RetryNode(node)));
            node_info.set_retrying();
        } else {
            self.actions.push(OutEvent::DropConnection(node));
            let mut removed_resources = IndexSet::default();
            std::mem::swap(&mut removed_resources, &mut node_info.resources);
            for r in removed_resources.iter() {
                if let Some(resource_state) = self.resources.get_mut(r) {
                    resource_state.nodes.remove(&node);
                }
            }
            // TODO: we should remove nodes at some point.
            node_info.set_disconnected(true);
        };

        // start connecting to other nodes now that this node has disconnected
        if let Some(remaining) = self.limits.remaining_connections(self.connection_count()) {
            for (node, node_info) in self
                .nodes
                .iter_mut()
                .filter(|(node, node_info)| node_should_connect(&self.resources, node, node_info))
                .take(remaining.into())
            {
                node_info.set_connecting();
                self.actions.push(OutEvent::StartConnect(*node));
            }
        }
    }

    fn on_transfer_finished(
        &mut self,
        id: TransferId,
        result: Result<DownloadOutcome, FailureAction>,
    ) {
        let Some(transfer) = self.transfers.remove(&id) else {
            debug_assert!(false, "transfer_finished called with unknown transfer id");
            return;
        };
        let TransferInfo { id, resource, node } = transfer;

        // update the node state
        if let Some(node_state) = self.nodes.get_mut(&node) {
            node_state.active_transfers.remove(&id);
            node_state.resources.remove(&resource.hash);
            match &result {
                // if the transfer was successful, or the transfer failed but the node is still
                // fine, give new work to the node
                Ok(_)
                | Err(
                    FailureAction::Cancelled
                    | FailureAction::NotFound
                    | FailureAction::AbortRequest(_),
                ) => self.node_fill_transfers(node),
                // the node failed and we should not reuse it
                Err(FailureAction::DropPeer(_)) => self.on_node_failed(node, false),
                // the node failed but we should retry connecting to the node
                Err(FailureAction::RetryLater(_)) => self.on_node_failed(node, true),
            }
        }

        // update the resource state
        if let Some(resource_state) = self.resources.get_mut(&resource.hash) {
            let keep_resource = match &result {
                Ok(_) => false,
                Err(_) => resource_state.should_be_alive(&self.nodes),
            };
            if keep_resource {
                resource_state.skip_nodes.insert(node);
                resource_state.active_transfer = None;
            } else {
                let resource_state = self.remove_resource(&resource.hash).expect("just checked");
                // notify downloader of the finished transfer
                self.actions.push(OutEvent::TransferFinished {
                    resource: resource.hash,
                    transfer_id: id,
                    intents: resource_state.intents,
                    result: result.map_err(|_| ()),
                });
            }
        };
    }

    fn remove_resource(&mut self, resource: &Hash) -> Option<ResourceInfo> {
        if let Some(resource_state) = self.resources.remove(resource) {
            for node in resource_state.nodes.iter() {
                if let Some(node_state) = self.nodes.get_mut(node) {
                    node_state.resources.remove(resource);
                }
            }
            Some(resource_state)
        } else {
            None
        }
    }

    fn on_timer(&mut self, timer: Timer) {
        match timer {
            Timer::RetryNode(node) => {
                let conn_count = self.connection_count();
                if let Some(node_info) = self.nodes.get_mut(&node) {
                    if let Some(_) = self.limits.remaining_connections(conn_count) {
                        node_info.set_connecting();
                        self.actions.push(OutEvent::StartConnect(node))
                    } else {
                        node_info.set_disconnected(false);
                    }
                }
            }
            Timer::IdleTimeout(node) => {
                if let Some(node_info) = self.nodes.get_mut(&node) {
                    match node_info.state {
                        NodeState::Connected {
                            idle_timer_started: true,
                        } => {
                            if node_info.active_transfers.is_empty() {
                                node_info.set_disconnected(false);
                                self.actions.push(OutEvent::DropConnection(node));
                            } else {
                                node_info.set_connected();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn on_discovery_finished(&mut self, resource: Hash) {
        if let Some(res) = self.resources.get_mut(&resource) {
            res.discovery = DiscoveryState::Finished;
        }
    }

    pub(super) fn resources(&self) -> &ResourceMap {
        &self.resources
    }
    pub(super) fn nodes(&self) -> &NodeMap {
        &self.nodes
    }
    pub(super) fn active_transfers(&self) -> &BTreeMap<TransferId, TransferInfo> {
        &self.transfers
    }
    pub(super) fn limits(&self) -> &ConcurrencyLimits {
        &self.limits
    }
}

fn node_should_connect(resource_map: &ResourceMap, node: &NodeId, node_info: &NodeInfo) -> bool {
    node_info.state.is_usable() && node_is_needed(resource_map, node, node_info)
}

fn node_is_needed(resource_map: &ResourceMap, node: &NodeId, node_info: &NodeInfo) -> bool {
    resources_by_node(resource_map, node_info)
        .any(|(_resource, state)| state.can_start_transfer(node))
}

fn resources_by_node<'a>(
    resource_map: &'a ResourceMap,
    node_info: &'a NodeInfo,
) -> impl Iterator<Item = (&'a Hash, &'a ResourceInfo)> {
    node_info
        .resources
        .iter()
        .filter_map(|r| resource_map.get(r).map(|rs| (r, rs)))
}

fn nodes_by_resource<'a>(
    node_map: &'a NodeMap,
    resource_state: &'a ResourceInfo,
) -> impl Iterator<Item = (&'a NodeId, &'a NodeInfo)> {
    resource_state
        .nodes
        .iter()
        .filter_map(|n| node_map.get(n).map(|state| (n, state)))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Display)]
pub struct IntentId(pub u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Display)]
pub struct TransferId(pub u64);

#[derive(Debug, Default)]
pub struct NodeInfo {
    resources: IndexSet<Hash>,
    active_transfers: HashSet<TransferId>,
    state: NodeState,
}

#[derive(Debug)]
pub enum NodeState {
    Disconnected {
        failed: bool,
    },
    Pending {
        state: PendingState,
        remaining_retries: u8,
    },
    Connected {
        idle_timer_started: bool,
    },
}

impl Default for NodeState {
    fn default() -> Self {
        Self::Disconnected { failed: false }
    }
}

impl NodeState {
    fn is_active(&self) -> bool {
        matches!(
            self,
            NodeState::Connected { .. }
                | NodeState::Pending {
                    state: PendingState::Connecting,
                    ..
                }
        )
    }

    fn is_usable(&self) -> bool {
        matches!(self, NodeState::Disconnected { failed: false })
    }
}

#[derive(Debug)]
pub enum PendingState {
    Connecting,
    RetryTimeout,
}

impl NodeInfo {
    pub(super) fn active_transfers(&self) -> &HashSet<TransferId> {
        &self.active_transfers
    }

    pub(super) fn state(&self) -> &NodeState {
        &self.state
    }

    fn remaining_retries(&self) -> u8 {
        match self.state {
            NodeState::Pending {
                remaining_retries, ..
            } => remaining_retries,
            _ => INITIAL_RETRY_COUNT,
        }
    }

    fn can_reconnect(&self) -> bool {
        self.remaining_retries() > 0
    }

    fn set_retrying(&mut self) {
        self.state = NodeState::Pending {
            state: PendingState::RetryTimeout,
            remaining_retries: self.remaining_retries() - 1,
        }
    }

    fn set_connecting(&mut self) {
        self.state = NodeState::Pending {
            state: PendingState::Connecting,
            remaining_retries: self.remaining_retries(),
        }
    }

    fn set_connected(&mut self) {
        self.state = NodeState::Connected {
            idle_timer_started: false,
        };
    }

    fn set_disconnected(&mut self, failed: bool) {
        self.state = NodeState::Disconnected { failed }
    }

    fn set_idle_timer_started(&mut self) {
        self.state = NodeState::Connected {
            idle_timer_started: true,
        };
    }

    fn is_connected(&self) -> bool {
        matches!(self.state, NodeState::Connected { .. })
    }

    fn is_newly_idle(&self) -> bool {
        self.active_transfers.is_empty()
            && matches!(
                self.state,
                NodeState::Connected {
                    idle_timer_started: false
                }
            )
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub enum DiscoveryState {
    #[default]
    Disabled,
    Idle,
    Running,
    Finished,
}

#[derive(Debug, Default)]
pub struct ResourceInfo {
    format: BlobFormat,
    nodes: IndexSet<NodeId>,
    skip_nodes: HashSet<NodeId>,
    intents: HashSet<IntentId>,
    active_transfer: Option<TransferId>,
    discovery: DiscoveryState,
}

impl ResourceInfo {
    fn new(format: BlobFormat, skip_discovery: bool) -> Self {
        let discovery = match skip_discovery {
            true => DiscoveryState::Disabled,
            false => DiscoveryState::Idle,
        };
        Self {
            format,
            discovery,
            ..Default::default()
        }
    }

    pub fn can_start_transfer(&self, node: &NodeId) -> bool {
        !self.intents.is_empty()
            && self.active_transfer.is_none()
            && !self.skip_nodes.contains(node)
    }

    /// Check if a resource may still be downloaded.
    ///
    /// This is called after a transfer of this resource has failed, and is used to check if it
    /// can still be retried. The heuristics are:
    /// * if no intents are left, no need to retry.
    /// * check if there are any providers left
    pub fn should_be_alive(&self, node_map: &NodeMap) -> bool {
        !self.intents.is_empty()
            && nodes_by_resource(node_map, &self)
                .any(|(n, node_info)| node_info.state.is_usable() && !self.skip_nodes.contains(n))
    }

    pub fn active_transfer(&self) -> Option<TransferId> {
        self.active_transfer
    }
}

#[derive(Clone)]
pub struct TransferInfo {
    pub id: TransferId,
    pub resource: HashAndFormat,
    pub node: NodeId,
}

impl fmt::Debug for TransferInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Transfer(id:{} node:{} {:?}",
            self.id.0,
            self.node.fmt_short(),
            self.resource,
        )
    }
}

/// Info on what to find on a node
#[derive(Debug, Default)]
pub struct NodeHints {
    /// Resources that can be found at this node
    pub resources: Vec<Hash>,
}

impl NodeHints {
    /// Create with a single resource
    pub fn with_resource(resource: Hash) -> Self {
        Self {
            resources: vec![resource],
        }
    }
}

/// Info on where to get a resource
#[derive(Debug, Default)]
pub struct ResourceHints {
    /// Nodes where we think the content is available.
    pub nodes: Vec<NodeId>,
    /// Nodes where we think the content is not available.
    pub skip_nodes: Vec<NodeId>,
    /// Do not query the configured discovery service for this node.
    pub skip_discovery: bool,
}

impl ResourceHints {
    /// Add a provider node for this resource.
    pub fn add_node(&mut self, node: NodeId) {
        self.nodes.push(node);
    }
    /// Add a node to skip for this resource.
    pub fn skip_node(&mut self, node: NodeId) {
        self.skip_nodes.push(node);
    }
    /// Create a [`ProviderHints`] with a single node.
    pub fn with_node(node: NodeId) -> Self {
        Self {
            nodes: vec![node],
            ..Default::default()
        }
    }
}

#[derive(Debug, Default)]
struct NextTransferId(u64);

impl NextTransferId {
    fn next(&mut self) -> TransferId {
        self.0 += 1;
        TransferId(self.0)
    }
}
