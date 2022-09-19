//! Based on https://github.com/ipfs/go-peertaskqueue.

use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use keyed_priority_queue::KeyedPriorityQueue;
use libp2p::PeerId;

mod peer_task;
mod peer_tracker;

pub use self::peer_task::{Task, TaskMerger};
use self::peer_tracker::PeerTracker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    PeerAdded,
    PeerRemoved,
}

/// Prioritzed list of tasks to be executed on peers.
///
/// Tasks are added to the queue, then popped off alternately between peers (roughly)
/// to execute the block with the highest priority, or otherwise the one added first
/// if priorities are equal.
#[derive(Debug, Clone)]
pub struct PeerTaskQueue<T: Topic, D: Data, TM: TaskMerger<T, D>> {
    inner: Arc<Mutex<Inner<T, D, TM>>>,
}

#[derive(Debug)]
struct Inner<T: Topic, D: Data, TM: TaskMerger<T, D>> {
    queue: KeyedPriorityQueue<PeerId, PeerTracker<T, D, TM>>,
    peer_trackers: AHashMap<PeerId, PeerTracker<T, D, TM>>,
    frozen_peers: AHashSet<PeerId>,
    ignore_freezing: bool,
    task_merger: TM,
    max_outstanding_work_per_peer: usize,
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PeerTaskQueue<T, D, TM> {
    pub fn new() -> Self {
        todo!()
    }

    pub fn pop_tasks(&self, target_min_work: usize) -> (PeerId, Vec<Task<T, D>>, Option<usize>) {
        todo!()
    }

    pub fn push_tasks(&self, peer: PeerId, tasks: Vec<Task<T, D>>) {
        todo!()
    }

    pub fn push_task(&self, peer: PeerId, task: Task<T, D>) {
        todo!()
    }

    pub fn tasks_done(&self, peer: PeerId, tasks: &[Task<T, D>]) {
        todo!()
    }

    pub fn remove(&self, cid: Cid, peer: PeerId) {
        todo!()
    }

    pub fn thaw_round(&self) {
        todo!()
    }
}

/// A non-unique name for a task. It's used by the client library
/// to act on a task once it exits the queue.
pub trait Topic:
    Sized + Debug + PartialEq + Clone + Eq + PartialOrd + Ord + std::hash::Hash
{
}

impl<T: Sized + Debug + PartialEq + Clone + Eq + PartialOrd + Ord + std::hash::Hash> Topic for T {}

/// Metadata that can be attached to a task.
pub trait Data: Sized + Debug + Clone + PartialEq + Eq {}
impl<D: Sized + Debug + Clone + PartialEq + Eq> Data for D {}
