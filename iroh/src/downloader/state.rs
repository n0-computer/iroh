use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};

use iroh_bytes::Hash;
use iroh_net::NodeId;
use iroh_sync::NamespaceId;

use super::FailureAction;

use self::util::{IdGenerator, IndexSet};

mod util;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord)]
pub struct Resource {
    hash: Hash,
    kind: ResourceKind,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum ResourceKind {
    Blob,
    HashSeq,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord)]
pub enum Group {
    Doc(NamespaceId),
}

#[derive(Debug, Default)]
pub struct State {
    groups: BTreeMap<Group, GroupState>,
    resources: BTreeMap<Resource, ResourceState>,
    nodes: BTreeMap<NodeId, NodeState>,

    active_transfers: BTreeMap<TransferId, Transfer>,
    transfer_id: IdGenerator<TransferId>,

    actions: Vec<Action>,
}

#[derive(Debug, Default)]
pub struct NodeState {
    member_of: IndexSet<Group>,
    provider_of: IndexSet<Resource>,

    failed_resources: BTreeSet<Resource>,
    active_transfers: HashSet<TransferId>,

    remaining_retries: usize,
    status: NodeStatus,
}

#[derive(Debug, Default)]
pub enum NodeStatus {
    #[default]
    Idle,
    Active(ActiveState),
    Failed,
}

#[derive(Debug)]
pub enum ActiveState {
    Connecting,
    Idle,
    Transfering(TransferId),
    RetryTimeout,
}

impl NodeState {
    fn should_reconnect(&self) -> bool {
        self.remaining_retries > 0
    }
    fn is_transfering(&self) -> bool {
        self.active_transfers.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct ResourceState {
    member_of: IndexSet<Group>,
    provided_by: IndexSet<NodeId>,

    failed_nodes: HashSet<NodeId>,
    active_transfers: HashSet<TransferId>,
}

impl ResourceState {
    fn is_transfering(&self) -> bool {
        self.active_transfers.is_empty()
    }

    fn should_start_transfer(&self, node: &NodeId) -> bool {
        !self.is_transfering() && !self.failed_nodes.contains(node)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::From, Hash)]
pub struct TransferId(u64);

#[derive(Debug, Default)]
pub struct GroupState {
    resources: IndexSet<Resource>,
    nodes: IndexSet<NodeId>,
}

#[derive(Debug, Clone)]
pub struct Transfer {
    pub id: TransferId,
    pub resource: Resource,
    pub node: NodeId,
}

#[derive(Debug)]
pub enum Action {
    StartTransfer(Transfer),
    StartDial(NodeId),
    RegisterTimer(Duration, Timer),
    DropConnection(NodeId),
}

#[derive(Debug)]
pub enum Timer {
    RetryNode(NodeId),
    DropConnection(NodeId),
}

impl State {
    pub fn add_node(
        &mut self,
        node: NodeId,
        member_of: impl IntoIterator<Item = Group>,
        provider_of: impl IntoIterator<Item = Resource>,
    ) {
        let state = self.nodes.entry(node).or_default();
        for group in member_of {
            if state.member_of.insert(group) {
                self.groups.entry(group).or_default().nodes.insert(node);
            }
        }
        for resource in provider_of {
            if state.provider_of.insert(resource) {
                self.resources
                    .entry(resource)
                    .or_default()
                    .provided_by
                    .insert(node);
            }
        }
        match state.status {
            NodeStatus::Idle | NodeStatus::Failed => self.actions.push(Action::StartDial(node)),
            _ => {
                if !state.is_transfering() {
                    self.on_node_ready(node)
                }
            }
        }
    }

    pub fn add_resource(
        &mut self,
        resource: Resource,
        member_of: impl Iterator<Item = Group>,
        provided_by: impl Iterator<Item = NodeId>,
    ) {
        let state = self.resources.entry(resource).or_default();
        for group in member_of {
            if state.member_of.insert(group) {
                self.groups
                    .entry(group)
                    .or_default()
                    .resources
                    .insert(resource);
            }
        }
        for node in provided_by {
            if state.provided_by.insert(node) {
                self.nodes
                    .entry(node)
                    .or_default()
                    .provider_of
                    .insert(resource);
            }
        }
    }

    pub fn remove_node(&mut self, node: NodeId) {
        let Some(node_state) = self.nodes.remove(&node) else {
            return;
        };
        for group in node_state.member_of.iter() {
            if let Some(state) = self.groups.get_mut(&group) {
                state.nodes.remove(&node);
            }
        }
        for resource in node_state.provider_of.iter() {
            if let Some(state) = self.resources.get_mut(&resource) {
                state.provided_by.remove(&node);
            }
        }
    }

    pub fn on_node_ready(&mut self, node: NodeId) {
        let Some(node_state) = self.nodes.get_mut(&node) else {
            self.actions.push(Action::DropConnection(node));
            return
        };

        let resource = loop {
            match node_state.provider_of.pop_front() {
                None => break None,
                Some(resource) => match self.resources.get_mut(&resource) {
                    None => continue,
                    Some(resource_state) => {
                        // resource has previously failed on this node, skip
                        if resource_state.failed_nodes.contains(&node) {
                            continue;
                        }
                        // resource is in transfering from another node, move to back to retry
                        if resource_state.is_transfering() {
                            node_state.provider_of.insert(resource);
                        // start transfer!
                        } else {
                            break Some(resource);
                        }
                    }
                },
            }
        };
        let resource = match resource {
            Some(resource) => Some(resource),
            None => {
                let mut found = None;
                'groups: for group in node_state.member_of.iter() {
                    let Some(group_state) = self.groups.get_mut(&group) else {
                        continue 'groups;
                    };
                    for resource in group_state.resources.iter() {
                        match self.resources.get_mut(&resource) {
                            None => continue,
                            Some(resource_state) => {
                                // resource has previously failed on this node or is currently
                                // transfering from another node, skip
                                if !resource_state.should_start_transfer(&node) {
                                    continue;
                                }

                                // start transfer!
                                found = Some(*resource);
                                break 'groups;
                            }
                        }
                    }
                }
                found
            }
        };

        let status = if let Some(resource) = resource {
            let id = self.transfer_id.next();
            let transfer = Transfer { id, resource, node };
            self.active_transfers.insert(id, transfer.clone());
            self.actions.push(Action::StartTransfer(transfer));
            ActiveState::Transfering(id)
        } else {
            self.actions.push(Action::RegisterTimer(
                Duration::from_secs(30),
                Timer::DropConnection(node),
            ));
            ActiveState::Idle
        };
        node_state.status = NodeStatus::Active(status);
    }

    pub fn on_node_failed(&mut self, node: NodeId, may_reconnect: bool) {
        let Some(state) = self.nodes.get_mut(&node) else {
            return;
        };
        let status = if !may_reconnect || !state.should_reconnect() {
            self.actions.push(Action::DropConnection(node));
            // todo: remove failed nodes?
            // self.remove_node(node);
            NodeStatus::Failed
        } else {
            state.remaining_retries -= 1;
            // TODO: timeout
            let timeout = Duration::from_secs(1);
            self.actions
                .push(Action::RegisterTimer(timeout, Timer::RetryNode(node)));
            NodeStatus::Active(ActiveState::RetryTimeout)
        };
        state.status = status;
    }

    pub fn on_transfer_ready(&mut self, id: TransferId) {
        let Some(transfer) = self.active_transfers.remove(&id) else {
            debug_assert!(false, "transfer_ready called but TransferId not in active_transfers");
            return;
        };
        let Transfer { id, resource, node } = transfer;
        if let Some(resource_state) = self.resources.remove(&resource) {
            for node in resource_state.provided_by.iter() {
                if let Some(node_state) = self.nodes.get_mut(node) {
                    node_state.provider_of.remove(&resource);
                }
            }
            for group in resource_state.member_of.iter() {
                if let Some(group_state) = self.groups.get_mut(group) {
                    group_state.resources.remove(&resource);
                }
            }
        }
        if let Some(node_state) = self.nodes.get_mut(&node) {
            node_state.active_transfers.remove(&id);
            self.on_node_ready(node);
        }
    }

    pub fn on_transfer_failed(&mut self, id: TransferId, action: FailureAction) {
        let Some(transfer) = self.active_transfers.remove(&id) else {
            debug_assert!(false, "transfer_failed called but TransferId not in active_transfers");
            return;
        };
        let Transfer { id, resource, node } = transfer;
        if let Some(node_state) = self.nodes.get_mut(&node) {
            node_state.active_transfers.remove(&id);
            match action {
                FailureAction::NotFound | FailureAction::AbortRequest(_) => {
                    self.on_node_ready(node)
                }
                FailureAction::DropPeer(_) => self.on_node_failed(node, false),
                FailureAction::RetryLater(_) => self.on_node_failed(node, true),
            }
        }
        if let Some(resource_state) = self.resources.get_mut(&resource) {
            resource_state.failed_nodes.insert(node);
        }
    }

    pub fn actions(&mut self) -> impl Iterator<Item = Action> + '_ {
        self.actions.drain(..)
    }
}
