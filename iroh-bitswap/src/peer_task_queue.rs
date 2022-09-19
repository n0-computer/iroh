//! Based on https://github.com/ipfs/go-peertaskqueue.

use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use ahash::AHashSet;
use keyed_priority_queue::{Entry, KeyedPriorityQueue};
use libp2p::PeerId;

mod peer_task;
mod peer_tracker;

pub use self::peer_task::{Task, TaskMerger};
use self::peer_tracker::{PeerTracker, Topics};

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
    peer_queue: KeyedPriorityQueue<PeerId, PeerTracker<T, D, TM>>,
    frozen_peers: AHashSet<PeerId>,
    ignore_freezing: bool,
    task_merger: TM,
    max_outstanding_work_per_peer: usize,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Sets if freezing should be enabled or not.
    pub ignore_freezing: bool,
    /// Configures how many task a peer can have outstanding with the same topic as an existing topic.
    pub max_outstanding_work_per_peer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ignore_freezing: false,
            max_outstanding_work_per_peer: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub num_peers: usize,
    pub num_active: usize,
    pub num_pending: usize,
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PeerTaskQueue<T, D, TM> {
    pub fn new(task_merger: TM, config: Config) -> Self {
        // TODO: hooks
        PeerTaskQueue {
            inner: Arc::new(Mutex::new(Inner::<T, D, TM> {
                peer_queue: Default::default(),
                frozen_peers: Default::default(),
                ignore_freezing: config.ignore_freezing,
                task_merger,
                max_outstanding_work_per_peer: config.max_outstanding_work_per_peer,
            })),
        }
    }

    /// Returns stats about the queue.
    pub fn stats(&self) -> Stats {
        let this = self.inner.lock().unwrap();
        let mut stats = Stats {
            num_peers: this.peer_queue.len(),
            num_active: 0,
            num_pending: 0,
        };

        for (_, t) in this.peer_queue.iter() {
            let ts = t.stats();
            stats.num_active += ts.num_active;
            stats.num_pending += ts.num_pending;
        }

        stats
    }

    /// List all topics for a specific peer
    pub fn peer_topics(&self, peer: &PeerId) -> Option<Topics<T>> {
        let mut this = self.inner.lock().unwrap();
        if let Entry::Occupied(tracker) = this.peer_queue.entry(*peer) {
            let tracker = tracker.get_priority();
            return Some(tracker.topics());
        }

        None
    }

    /// Adds a new group of tasks for the given peer to the queue.
    pub fn push_tasks(&self, peer: PeerId, tasks: Vec<Task<T, D>>) {
        let mut this = self.inner.lock().unwrap();

        let mut peer_tracker = match this.peer_queue.remove(&peer) {
            Some(peer_tracker) => peer_tracker,
            None => {
                let peer_tracker = PeerTracker::new(
                    peer,
                    this.task_merger.clone(),
                    this.max_outstanding_work_per_peer,
                );
                // callHook(peer, Event::PeerAdded)
                peer_tracker
            }
        };

        peer_tracker.push_tasks(tasks);
        this.peer_queue.push(peer, peer_tracker);
    }

    pub fn push_task(&self, peer: PeerId, task: Task<T, D>) {
        self.push_tasks(peer, vec![task]);
    }

    /// Finds the peer with the highest priority and pops as many tasks
    /// off the peer's queue as necessary to cover targetMinWork, in priority order.
    ///
    /// If there are not enough tasks to cover targetMinWork it just returns
    /// whatever is in the peer's queue.
    ///   - Peers with the most "active" work are deprioritized.
    ///     This heuristic is for fairness, we try to keep all peers "busy".
    ///   - Peers with the most "pending" work are prioritized.
    ///     This heuristic is so that peers with a lot to do get asked for work first.
    ///
    /// The third response argument is pending work: the amount of work in the
    /// queue for this peer.
    pub fn pop_tasks(&self, target_min_work: usize) -> Option<(PeerId, Vec<Task<T, D>>, usize)> {
        let mut this = self.inner.lock().unwrap();

        let (peer, mut peer_tracker) = this.peer_queue.pop()?;
        let out = peer_tracker.pop_tasks(target_min_work);
        let pending_work = peer_tracker.get_pending_work();

        if peer_tracker.is_idle() {
            // Cleanup if no more tasks
            this.frozen_peers.remove(&peer);
            // callHook(peer, Event::PeerRemoved)
        } else {
            // otherwise, reinsert updated tracker
            this.peer_queue.push(peer, peer_tracker);
        }

        Some((peer, out, pending_work))
    }

    /// Called to indicate that the given tasks have completed.
    pub fn tasks_done(&self, peer: PeerId, tasks: &[Task<T, D>]) {
        let mut this = self.inner.lock().unwrap();

        match this.peer_queue.remove(&peer) {
            Some(mut peer_tracker) => {
                // tell the peer what was done
                for task in tasks {
                    peer_tracker.task_done(task);
                }
                this.peer_queue.push(peer, peer_tracker);
            }
            None => {
                return;
            }
        }
    }

    /// Removes a task from the queue
    pub fn remove(&self, topic: &T, peer: PeerId) {
        let mut this = self.inner.lock().unwrap();

        match this.peer_queue.remove(&peer) {
            Some(mut peer_tracker) => {
                peer_tracker.remove(topic);
                // freeze that partner, if they sent us a cancle for a block we are about to send them
                // we should wait a short period of time to make sure we receive any other in flight cancels before sending them a block they already potentially have
                if !this.ignore_freezing {
                    if !peer_tracker.is_frozen() {
                        this.frozen_peers.insert(peer);
                    }
                    peer_tracker.freeze();
                }
                this.peer_queue.push(peer, peer_tracker);
            }
            None => return,
        }
    }

    /// Completely thaws all peers in the queue so they can execute tasks.
    pub fn full_thaw(&self) {
        let mut this = self.inner.lock().unwrap();
        let frozen_peers: Vec<_> = this.frozen_peers.iter().copied().collect();
        for peer in frozen_peers {
            if let Some(mut peer_tracker) = this.peer_queue.remove(&peer) {
                peer_tracker.full_thaw();
                this.frozen_peers.remove(&peer);
                this.peer_queue.push(peer, peer_tracker);
            }
        }
    }

    /// Unthaws peers incrementally, so that those have been frozen the least become unfrozen
    /// and able to execute tasks first.
    pub fn thaw_round(&self) {
        let mut this = self.inner.lock().unwrap();

        let frozen_peers: Vec<_> = this.frozen_peers.iter().copied().collect();
        for peer in frozen_peers {
            if let Some(mut peer_tracker) = this.peer_queue.remove(&peer) {
                if peer_tracker.thaw() {
                    this.frozen_peers.remove(&peer);
                }
                this.peer_queue.push(peer, peer_tracker);
            }
        }
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
