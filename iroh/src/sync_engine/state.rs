use anyhow::Result;
use iroh_net::NodeId;
use iroh_sync::{
    net::{AbortReason, AcceptOutcome, SyncFinished},
    NamespaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Instant, SystemTime};
use tracing::{debug, warn};

/// Why we started a sync request
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Copy)]
pub enum SyncReason {
    /// Direct join request via API
    DirectJoin,
    /// Peer showed up as new neighbor in the gossip swarm
    NewNeighbor,
    /// We synced after receiving a sync report that indicated news for us
    SyncReport,
    /// We received a sync report while a sync was running, so run again afterwars
    Resync,
}

/// Why we performed a sync exchange
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Origin {
    /// We initiated the exchange
    Connect(SyncReason),
    /// A node connected to us and we accepted the exchange
    Accept,
}

/// The state we're in for a node and a namespace
#[derive(Debug, Clone)]
pub enum SyncState {
    Idle,
    Running { start: SystemTime, origin: Origin },
}

impl Default for SyncState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Contains an entry for each active (syncing) namespace, and in there an entry for each node we
/// synced with.
#[derive(Default)]
pub struct NamespaceStates(BTreeMap<NamespaceId, NamespaceState>);

#[derive(Default)]
struct NamespaceState {
    nodes: BTreeMap<NodeId, PeerState>,
}

impl NamespaceStates {
    /// Are we syncing this namespace?
    pub fn is_syncing(&self, namespace: &NamespaceId) -> bool {
        self.0.contains_key(namespace)
    }

    /// Insert a namespace into the set of syncing namespaces.
    pub fn insert(&mut self, namespace: NamespaceId) {
        self.0.entry(namespace).or_default();
    }

    /// Start a sync request.
    ///
    /// Returns true if the request should be performed, and false if it should be aborted.
    pub fn start_connect(
        &mut self,
        namespace: &NamespaceId,
        node: NodeId,
        reason: SyncReason,
    ) -> bool {
        let Some(state) = self.entry(namespace, node) else {
            debug!("abort connect: namespace is not in sync set");
            return false;
        };
        if state.start_connect(reason) {
            true
        } else {
            debug!("abort connect: already syncing");
            false
        }
    }

    /// Accept a sync request.
    ///
    /// Returns the [`AcceptOutcome`] to be perfomed.
    pub fn accept_request(
        &mut self,
        me: &NodeId,
        namespace: &NamespaceId,
        node: NodeId,
    ) -> AcceptOutcome {
        let Some(state) = self.entry(namespace, node) else {
            return AcceptOutcome::Reject(AbortReason::NotFound);
        };
        state.accept_request(me, &node)
    }

    /// Insert a finished sync operation into the state.
    ///
    /// Returns the time when the operation was started, and a `bool` that is true if another sync
    /// request should be triggered right afterwards.
    ///
    /// Returns `None` if the namespace is not syncing or the sync state doesn't expect a finish
    /// event.
    pub fn finish(
        &mut self,
        namespace: &NamespaceId,
        node: NodeId,
        origin: &Origin,
        result: Result<SyncFinished>,
    ) -> Option<(SystemTime, bool)> {
        let state = self.entry(namespace, node)?;
        state.finish(origin, result)
    }

    /// Remove a namespace from the set of syncing namespaces.
    pub fn remove(&mut self, namespace: &NamespaceId) -> bool {
        self.0.remove(namespace).is_some()
    }

    /// Get the [`PeerState`] for a namespace and node.
    /// If the namespace is syncing and the node so far unknown, initialize and return a default [`PeerState`].
    /// If the namespace is not syncing return None.
    fn entry(&mut self, namespace: &NamespaceId, node: NodeId) -> Option<&mut PeerState> {
        self.0
            .get_mut(namespace)
            .map(|n| n.nodes.entry(node).or_default())
    }
}

/// State of a node with regard to a namespace.
#[derive(Default)]
struct PeerState {
    state: SyncState,
    resync_requested: bool,
    last_sync: Option<(Instant, Result<SyncFinished>)>,
}

impl PeerState {
    fn finish(
        &mut self,
        origin: &Origin,
        result: Result<SyncFinished>,
    ) -> Option<(SystemTime, bool)> {
        let start = match &self.state {
            SyncState::Running {
                start,
                origin: origin2,
            } => {
                if origin2 != origin {
                    warn!(actual = ?origin, expected = ?origin2, "finished sync origin does not match state")
                }
                Some(*start)
            }
            SyncState::Idle => {
                warn!("sync state finish called but not in running state");
                None
            }
        };

        self.last_sync = Some((Instant::now(), result));
        self.state = SyncState::Idle;
        start.map(|s| (s, self.resync_requested))
    }

    fn start_connect(&mut self, reason: SyncReason) -> bool {
        match self.state {
            // never run two syncs at the same time
            SyncState::Running { .. } => {
                debug!("abort connect: sync already running");
                if matches!(reason, SyncReason::SyncReport) {
                    debug!("resync queued");
                    self.resync_requested = true;
                }
                false
            }
            SyncState::Idle => {
                self.set_sync_running(Origin::Connect(reason));
                true
            }
        }
    }

    fn accept_request(&mut self, me: &NodeId, node: &NodeId) -> AcceptOutcome {
        let outcome = match &self.state {
            SyncState::Idle => AcceptOutcome::Allow,
            SyncState::Running { origin, .. } => match origin {
                Origin::Accept => AcceptOutcome::Reject(AbortReason::AlreadySyncing),
                // Incoming sync request while we are dialing ourselves.
                // In this case, compare the binary representations of our and the other node's id
                // to deterministically decide which of the two concurrent connections will succeed.
                Origin::Connect(_reason) => match expected_sync_direction(me, node) {
                    SyncDirection::Accept => AcceptOutcome::Allow,
                    SyncDirection::Connect => AcceptOutcome::Reject(AbortReason::AlreadySyncing),
                },
            },
        };
        if let AcceptOutcome::Allow = outcome {
            self.set_sync_running(Origin::Accept);
        }
        outcome
    }

    fn set_sync_running(&mut self, origin: Origin) {
        self.state = SyncState::Running {
            origin,
            start: SystemTime::now(),
        };
        self.resync_requested = false;
    }
}

#[derive(Debug)]
enum SyncDirection {
    Accept,
    Connect,
}

fn expected_sync_direction(self_node_id: &NodeId, other_node_id: &NodeId) -> SyncDirection {
    if self_node_id.as_bytes() > other_node_id.as_bytes() {
        SyncDirection::Accept
    } else {
        SyncDirection::Connect
    }
}
