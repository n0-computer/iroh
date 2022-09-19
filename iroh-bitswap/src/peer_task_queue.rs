//! Based on https://github.com/ipfs/go-peertaskqueue.

use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    time::Instant,
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use keyed_priority_queue::KeyedPriorityQueue;
use libp2p::PeerId;

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

/// A single task to be executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task<T: Topic, D: Data> {
    /// The topic of the task.
    pub topic: T,
    /// The priority of the task
    pub priority: isize,
    /// The size of the task
    /// - peers with most active work are deprioritzed
    /// - peers with most pending work are prioritized
    pub work: usize,
    /// Associated data.
    pub data: D,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueueTask<T: Topic, D: Data> {
    task: Task<T, D>,
    target: PeerId,
    /// Marks the time that the  task was added to the queue.
    created: Instant,
}

impl<T: Topic, D: Data> PartialOrd for QueueTask<T, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: Topic, D: Data> Ord for QueueTask<T, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}

impl<T: Topic, D: Data> QueueTask<T, D> {
    pub fn new(task: Task<T, D>, target: PeerId, created: Instant) -> Self {
        QueueTask {
            task,
            target,
            created,
        }
    }
}

/// Trait that is used to merge new tasks into the active and pending queues.
pub trait TaskMerger<T: Topic, D: Data>: PartialEq + Eq + Clone + std::fmt::Debug {
    /// Indicates whether the given task has more information than
    /// the existing group of tasks (which have the same Topic), and thus should be merged.
    fn has_new_info(&self, task_info: &Task<T, D>, existing_tasks: &[Task<T, D>]) -> bool;
    /// Copies relevant fields from a new task to an existing task.
    fn merge(&self, task: &Task<T, D>, exising: &mut Task<T, D>);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultTaskMerger {}
impl<T: Topic, D: Data> TaskMerger<T, D> for DefaultTaskMerger {
    fn has_new_info(&self, _task_info: &Task<T, D>, _existing_tasks: &[Task<T, D>]) -> bool {
        false
    }
    fn merge(&self, _task: &Task<T, D>, _exising: &mut Task<T, D>) {}
}

/// A non-unique name for a task. It's used by the client library
/// to act on a task once it exits the queue.
pub trait Topic: Sized + Debug + PartialEq + Clone + Eq + std::hash::Hash {}
impl Topic for Cid {}

/// Metadata that can be attached to a task.
pub trait Data: Sized + Debug + Clone + PartialEq + Eq {}

/// Tracks task blocks for a single peer, as well as its active tasks.
#[derive(Debug)]
struct PeerTracker<T: Topic, D: Data, TM: TaskMerger<T, D>> {
    target: PeerId,
    /// Priority queue of tasks belonging to this peer, stores the pending tasks.
    pending_tasks: KeyedPriorityQueue<T, QueueTask<T, D>>,
    active_tasks: AHashMap<T, Vec<Task<T, D>>>,
    active_work: usize,
    max_active_work_per_peer: usize,
    freeze_val: isize,
    task_merger: TM,
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PartialEq for PeerTracker<T, D, TM> {
    fn eq(&self, other: &Self) -> bool {
        if self.target == other.target
            && self.active_tasks == other.active_tasks
            && self.active_work == other.active_work
            && self.max_active_work_per_peer == other.max_active_work_per_peer
            && self.freeze_val == other.freeze_val
            && self.task_merger == other.task_merger
            && self.pending_tasks.len() == other.pending_tasks.len()
        {
            self.pending_tasks
                .iter()
                .zip(other.pending_tasks.iter())
                .all(|(a, b)| a == b)
        } else {
            false
        }
    }
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> Eq for PeerTracker<T, D, TM> {}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PeerTracker<T, D, TM> {
    fn new(target: PeerId, task_merger: TM, max_active_work_per_peer: usize) -> Self {
        PeerTracker {
            target,
            pending_tasks: Default::default(),
            active_tasks: Default::default(),
            active_work: 0,
            max_active_work_per_peer,
            freeze_val: 0,
            task_merger,
        }
    }

    /// Returns true if the peer has no active or queue tasks.
    fn is_idle(&self) -> bool {
        self.pending_tasks.is_empty() && self.active_tasks.is_empty()
    }

    fn stats(&self) -> Stats {
        Stats {
            num_pending: self.pending_tasks.len(),
            num_active: self.active_tasks.len(),
        }
    }

    fn topics(&self) -> Topics<T> {
        let pending = self
            .pending_tasks
            .iter()
            .map(|(_, qt)| qt.task.topic.clone())
            .collect();
        let active = self
            .active_tasks
            .values()
            .flat_map(|t| t.iter().map(|t| t.topic.clone()))
            .collect();
        Topics { pending, active }
    }

    fn push_tasks(&mut self, tasks: Vec<Task<T, D>>) {
        let now = Instant::now();
        for task in tasks {
            // If the new task doesn't add any more information over waht we already
            // have in the active qeue, then skip it.
            if !self.task_has_more_info_than_active_tasks(&task) {
                continue;
            }

            // if there is already a non-active task with this topic
            if let keyed_priority_queue::Entry::Occupied(existing_task_entry) =
                self.pending_tasks.entry(task.topic.clone())
            {
                let (key, mut existing_task) = existing_task_entry.remove();
                // if the task has a higher priority than the old task
                if task.priority > existing_task.task.priority {
                    // update priority
                    existing_task.task.priority = task.priority;
                }
                self.task_merger.merge(&task, &mut existing_task.task);
                self.pending_tasks.push(key, existing_task);

                // A task with the topic exists, so no need to add a new task
                // to the queue.
                continue;
            }

            let topic = task.topic.clone();
            let qtask = QueueTask::new(task, self.target, now);
            self.pending_tasks.push(topic, qtask);
        }
    }

    /// Pops off as many tasks as necessary to cover `target_min_work`, in priority order.
    /// If there are not enough tasks to cover `target_min_work`, it just returns everything
    /// available.
    fn pop_tasks(&mut self, target_min_work: usize) -> Vec<Task<T, D>> {
        let mut out = Vec::new();
        let mut work = 0;

        while !self.pending_tasks.is_empty() && self.freeze_val == 0 && work < target_min_work {
            if self.max_active_work_per_peer > 0 {
                // do not add work to a peer that is already maxed out
                if self.active_work >= self.max_active_work_per_peer {
                    break;
                }
            }

            // pop the next task off the queue
            if let Some((_, qtask)) = self.pending_tasks.pop() {
                // start the task
                let task = qtask.task;
                self.start_task(task.clone());
                work += task.work;
                out.push(task);
            }
        }

        out
    }

    fn start_task(&mut self, task: Task<T, D>) {
        // Add task to active queue
        self.active_work += task.work;
        self.active_tasks
            .entry(task.topic.clone())
            .or_default()
            .push(task);
    }

    fn get_pending_work(&self) -> usize {
        self.pending_tasks.iter().map(|(_, qt)| qt.task.work).sum()
    }

    /// Signals that the given task was completed for this peer.
    fn task_done(&self, task: Task<T, D>) {
        todo!()
    }

    fn remove(&mut self, topic: T) -> bool {
        todo!()
    }

    fn freeze(&mut self) {
        self.freeze_val += 1;
    }

    /// Decrements the freeze value for this peer. While a peer is frozen
    /// it will not execute any tasks.
    fn thaw(&mut self) -> bool {
        self.freeze_val -= (self.freeze_val + 1) / 2;
        self.freeze_val <= 0
    }

    /// Completely unfreezes this peer so it can execute tasks.
    fn full_thaw(&mut self) {
        self.freeze_val = 0;
    }

    /// Returns whether this peer is frozen and unable to execute tasks.
    fn is_frozen(&self) -> bool {
        self.freeze_val > 0
    }

    fn task_has_more_info_than_active_tasks(&self, task: &Task<T, D>) -> bool {
        if let Some(tasks_with_topic) = self.active_tasks.get(&task.topic) {
            if tasks_with_topic.is_empty() {
                return true;
            }
            return self.task_merger.has_new_info(task, tasks_with_topic);
        }

        true
    }
}

struct Stats {
    num_pending: usize,
    num_active: usize,
}

struct Topics<T: Topic> {
    pending: Vec<T>,
    active: Vec<T>,
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PartialOrd for PeerTracker<T, D, TM> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> Ord for PeerTracker<T, D, TM> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // having no pending tasks means lowest priority
        if self.pending_tasks.is_empty() {
            return std::cmp::Ordering::Less;
        }
        if other.pending_tasks.is_empty() {
            return std::cmp::Ordering::Greater;
        }

        // frozen peers have lowest priority
        if self.freeze_val > other.freeze_val {
            return std::cmp::Ordering::Less;
        }
        if self.freeze_val > other.freeze_val {
            return std::cmp::Ordering::Greater;
        }

        // If each peer has an equal amount of work in its active queue, choose
        // the peer with most amount of work pending.
        if self.active_work == other.active_work {
            return self.pending_tasks.len().cmp(&other.pending_tasks.len());
        }

        // Choose the peer with the least amount of work in its active queue.
        // This way we "keep peers busy" by sending them as much data as they can process.
        other.active_work.cmp(&self.active_work)
    }
}
