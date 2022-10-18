use std::time::Instant;

use libp2p::PeerId;

use super::{Data, Topic};

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

/// Contains a Task, and also some bookkeeping information.
/// It is used internally by the PeerTracker to keep track of tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueTask<T: Topic, D: Data> {
    pub task: Task<T, D>,
    pub target: PeerId,
    /// Marks the time that the  task was added to the queue.
    pub created: Instant,
}

impl<T: Topic, D: Data> PartialOrd for QueueTask<T, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: Topic, D: Data> Ord for QueueTask<T, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.target == other.target && self.task.priority != other.task.priority {
            return self.task.priority.cmp(&other.task.priority);
        }

        // FIFO
        other.created.cmp(&self.created)
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
pub trait TaskMerger<T: Topic, D: Data>:
    PartialEq + Eq + Clone + std::fmt::Debug + Send + Sync + 'static
{
    /// Indicates whether the given task has more information than
    /// the existing group of tasks (which have the same Topic), and thus should be merged.
    fn has_new_info(&self, task_info: &Task<T, D>, existing_tasks: &[Task<T, D>]) -> bool;
    /// Copies relevant fields from a new task to an existing task.
    fn merge(&self, task: &Task<T, D>, existing: &mut Task<T, D>);
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DefaultTaskMerger {}
impl<T: Topic, D: Data> TaskMerger<T, D> for DefaultTaskMerger {
    fn has_new_info(&self, _task_info: &Task<T, D>, _existing_tasks: &[Task<T, D>]) -> bool {
        false
    }
    fn merge(&self, _task: &Task<T, D>, _exising: &mut Task<T, D>) {}
}
