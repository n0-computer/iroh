use std::time::Instant;

use ahash::AHashMap;
use keyed_priority_queue::{Entry, KeyedPriorityQueue};
use libp2p::PeerId;

use super::{peer_task::QueueTask, Data, Task, TaskMerger, Topic};

/// Tracks task blocks for a single peer, as well as its active tasks.
#[derive(Debug)]
pub struct PeerTracker<T: Topic, D: Data, TM: TaskMerger<T, D>> {
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
    pub fn new(target: PeerId, task_merger: TM, max_active_work_per_peer: usize) -> Self {
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
    pub fn is_idle(&self) -> bool {
        self.pending_tasks.is_empty() && self.active_tasks.is_empty()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            num_pending: self.pending_tasks.len(),
            num_active: self.active_tasks.len(),
        }
    }

    pub fn topics(&self) -> Topics<T> {
        let mut pending: Vec<_> = self
            .pending_tasks
            .iter()
            .map(|(_, qt)| qt.task.topic.clone())
            .collect();
        pending.sort();
        let mut active: Vec<_> = self
            .active_tasks
            .values()
            .flat_map(|t| t.iter().map(|t| t.topic.clone()))
            .collect();
        active.sort();
        Topics { pending, active }
    }

    pub fn push_tasks(&mut self, tasks: Vec<Task<T, D>>) {
        let now = Instant::now();
        for task in tasks {
            // If the new task doesn't add any more information over waht we already
            // have in the active qeue, then skip it.
            if !self.task_has_more_info_than_active_tasks(&task) {
                continue;
            }

            // if there is already a non-active task with this topic
            if let Entry::Occupied(existing_task_entry) =
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
    pub fn pop_tasks(&mut self, target_min_work: usize) -> Vec<Task<T, D>> {
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

    pub fn start_task(&mut self, task: Task<T, D>) {
        // Add task to active queue
        self.active_work += task.work;
        self.active_tasks
            .entry(task.topic.clone())
            .or_default()
            .push(task);
    }

    pub fn get_pending_work(&self) -> usize {
        self.pending_tasks.iter().map(|(_, qt)| qt.task.work).sum()
    }

    /// Signals that the given task was completed for this peer.
    pub fn task_done(&mut self, task: &Task<T, D>) {
        // remove tasks from active tasks
        if let Some(active_tasks) = self.active_tasks.get_mut(&task.topic) {
            let mut work_done = 0;
            active_tasks.retain(|at| {
                if at == task {
                    work_done += task.work;
                    false
                } else {
                    true
                }
            });

            assert!(
                self.active_work >= work_done,
                "more work finished than started"
            );
            self.active_work -= work_done;

            if active_tasks.is_empty() {
                self.active_tasks.remove(&task.topic);
            }
        }
    }

    pub fn remove(&mut self, topic: &T) -> bool {
        self.pending_tasks.remove(topic).is_some()
    }

    pub fn freeze(&mut self) {
        self.freeze_val += 1;
    }

    /// Decrements the freeze value for this peer. While a peer is frozen
    /// it will not execute any tasks.
    pub fn thaw(&mut self) -> bool {
        self.freeze_val -= (self.freeze_val + 1) / 2;
        self.freeze_val <= 0
    }

    /// Completely unfreezes this peer so it can execute tasks.
    pub fn full_thaw(&mut self) {
        self.freeze_val = 0;
    }

    /// Returns whether this peer is frozen and unable to execute tasks.
    pub fn is_frozen(&self) -> bool {
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

#[derive(Debug)]
pub struct Stats {
    pub num_pending: usize,
    pub num_active: usize,
}

#[derive(Debug)]
pub struct Topics<T: Topic> {
    pub pending: Vec<T>,
    pub active: Vec<T>,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::peer_task_queue::peer_task::DefaultTaskMerger;

    use super::*;

    const MAX_ACTIVE_WORK_PER_PEER: usize = 100;

    #[test]
    fn test_empty() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<&'static [u8], (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = tracker.pop_tasks(100);
        assert!(tasks.is_empty());
    }

    #[test]
    fn test_push_pop() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<&'static [u8], (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![Task {
            topic: &b"1"[..],
            priority: 1,
            work: 10,
            data: (),
        }];
        tracker.push_tasks(tasks);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, b"1");
    }

    #[test]
    fn test_pop_zero_size() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<&'static [u8], (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![Task {
            topic: &b"1"[..],
            priority: 1,
            work: 10,
            data: (),
        }];
        tracker.push_tasks(tasks);

        let popped = tracker.pop_tasks(0);
        assert!(popped.is_empty());
    }

    #[test]
    fn test_pop_size_order() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: (),
            },
            Task {
                topic: 2,
                priority: 20,
                work: 10,
                data: (),
            },
            Task {
                topic: 3,
                priority: 15,
                work: 10,
                data: (),
            },
        ];
        tracker.push_tasks(tasks);

        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 2);
        assert_eq!(tracker.get_pending_work(), 20);

        let topics = tracker.topics();
        assert_eq!(topics.active.len(), 1);
        assert_eq!(topics.active[0], popped[0].topic);

        assert_eq!(dbg!(&topics).pending.len(), 2);
        assert_eq!(topics.pending[0], 1);
        assert_eq!(topics.pending[1], 3);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0].topic, 3);
        assert_eq!(popped[1].topic, 1);
        assert_eq!(tracker.get_pending_work(), 0);

        let topics = tracker.topics();
        assert_eq!(topics.active, [1, 2, 3]);
        assert!(topics.pending.is_empty());

        let popped = tracker.pop_tasks(100);
        assert!(popped.is_empty());
        assert_eq!(tracker.get_pending_work(), 0);
    }

    #[test]
    fn test_pop_first_item_always() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 20,
                work: 10,
                data: (),
            },
            Task {
                topic: 2,
                priority: 10,
                work: 5,
                data: (),
            },
        ];
        tracker.push_tasks(tasks);

        // should always return the first task, even if it's under target work
        let popped = tracker.pop_tasks(7);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 1);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 2);
    }

    #[test]
    fn test_pop_items_to_cover_target_work() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 20,
                work: 5,
                data: (),
            },
            Task {
                topic: 2,
                priority: 10,
                work: 5,
                data: (),
            },
            Task {
                topic: 3,
                priority: 5,
                work: 5,
                data: (),
            },
        ];
        tracker.push_tasks(tasks);

        // should always return the first task, even if it's under target work
        let popped = tracker.pop_tasks(7);
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0].topic, 1);
        assert_eq!(popped[1].topic, 2);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 3);
    }

    #[test]
    fn test_single_remove() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: (),
            },
            Task {
                topic: 2,
                priority: 20,
                work: 10,
                data: (),
            },
            Task {
                topic: 3,
                priority: 15,
                work: 10,
                data: (),
            },
        ];
        tracker.push_tasks(tasks);

        tracker.remove(&2);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0].topic, 3);
        assert_eq!(popped[1].topic, 1);
    }

    #[test]
    fn test_multi_remove() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, (), _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: (),
            },
            Task {
                topic: 1,
                priority: 20,
                work: 1,
                data: (),
            },
            Task {
                topic: 2,
                priority: 15,
                work: 10,
                data: (),
            },
        ];
        tracker.push_tasks(tasks);

        tracker.remove(&1);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 2);
    }

    #[test]
    fn test_task_done() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 2,
                priority: 20,
                work: 10,
                data: "b",
            },
        ];

        // push task "a"
        tracker.push_tasks(vec![tasks[0].clone()]); // Topic 1

        // check topic state
        let topics = tracker.topics();
        assert!(topics.active.is_empty());
        assert_eq!(topics.pending.len(), 1);

        // pop task "a", making it active
        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);

        // check topic state
        let topics = tracker.topics();
        assert_eq!(topics.active.len(), 1);
        assert!(topics.pending.is_empty());

        // mark task "a" as done
        tracker.task_done(&popped[0]);

        // check topic state
        let topics = tracker.topics();
        assert!(topics.pending.is_empty());
        assert!(topics.pending.is_empty());

        // push task "b"
        tracker.push_tasks(vec![tasks[1].clone()]);

        // check topic state
        let topics = tracker.topics();
        assert!(topics.active.is_empty());
        assert_eq!(topics.pending.len(), 1);

        // pop all tasks, "a" was done, "b" should have been allowed to be added
        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);

        // check topic state
        let topics = tracker.topics();
        assert_eq!(topics.active.len(), 1);
        assert!(topics.pending.is_empty());
    }

    #[derive(Default, Debug, Clone, PartialEq, Eq)]
    struct PermissiveTaskMerger {}

    impl<T: Topic, D: Data> TaskMerger<T, D> for PermissiveTaskMerger {
        fn has_new_info(&self, _task_info: &Task<T, D>, _existing_tasks: &[Task<T, D>]) -> bool {
            true
        }

        fn merge(&self, task: &Task<T, D>, existing: &mut Task<T, D>) {
            existing.data = task.data.clone();
            existing.work = task.work;
        }
    }
    #[test]
    fn test_replace_task_permissive() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            PermissiveTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 20,
                work: 10,
                data: "b",
            },
        ];

        // push task "a"
        tracker.push_tasks(vec![tasks[0].clone()]); // Topic 1

        // push task "b", should replace "a"
        tracker.push_tasks(vec![tasks[1].clone()]); // Topic 1

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].data, "b");
        assert_eq!(popped[0].priority, 20);
    }

    #[test]
    fn test_replace_task_size() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            PermissiveTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 20,
                work: 20,
                data: "b",
            },
            Task {
                topic: 2,
                priority: 5,
                work: 5,
                data: "c",
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        // same topic, should replace "a" and update work from 10 to 20
        tracker.push_tasks(vec![tasks[1].clone()]);
        tracker.push_tasks(vec![tasks[2].clone()]);

        let popped = tracker.pop_tasks(15);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].data, "b");
        assert_eq!(tracker.get_pending_work(), 5);

        let popped = tracker.pop_tasks(30);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].data, "c");
        assert_eq!(tracker.get_pending_work(), 0);
    }

    #[test]
    fn test_replace_active_task() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            PermissiveTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 20,
                work: 10,
                data: "b",
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        // make "a" active
        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);

        let a = &popped[0];

        // push "b"
        tracker.push_tasks(vec![tasks[1].clone()]);

        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);

        let b = &popped[0];

        // finish tasks
        assert!(!tracker.is_idle());
        tracker.task_done(a);
        assert!(!tracker.is_idle());
        tracker.task_done(b);
        assert!(tracker.is_idle());
    }

    #[test]
    fn test_replace_active_task_non_permissive() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 20,
                work: 10,
                data: "b",
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);

        // non permissive merger should ignore this new t ask
        tracker.push_tasks(vec![tasks[1].clone()]);
        let popped = tracker.pop_tasks(100);
        assert!(popped.is_empty());
    }

    #[test]
    fn test_replace_task_active_and_pending() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            PermissiveTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "b",
            },
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "c",
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);

        // "b" some topic, should be added to pending
        tracker.push_tasks(vec![tasks[1].clone()]);

        // "c", permissive should replace "b"
        tracker.push_tasks(vec![tasks[2].clone()]);

        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].data, "c");
    }

    #[test]
    fn test_remove_active() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            PermissiveTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 10,
                data: "a",
            },
            Task {
                topic: 1,
                priority: 20,
                work: 10,
                data: "b",
            },
            Task {
                topic: 2,
                priority: 15,
                work: 10,
                data: "c",
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        let popped = tracker.pop_tasks(10);
        assert_eq!(popped.len(), 1);

        // "b" and "c"
        tracker.push_tasks(vec![tasks[1].clone()]);
        tracker.push_tasks(vec![tasks[2].clone()]);

        // remove all topic 1
        tracker.remove(&1);
        let popped = tracker.pop_tasks(100);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 2);
    }

    #[test]
    fn test_push_pop_equal_priorities() {
        let partner = PeerId::random();
        let mut tracker = PeerTracker::<usize, _, _>::new(
            partner,
            DefaultTaskMerger::default(),
            MAX_ACTIVE_WORK_PER_PEER,
        );

        let tasks = vec![
            Task {
                topic: 1,
                priority: 10,
                work: 1,
                data: (),
            },
            Task {
                topic: 2,
                priority: 10,
                work: 1,
                data: (),
            },
            Task {
                topic: 3,
                priority: 10,
                work: 1,
                data: (),
            },
        ];

        tracker.push_tasks(vec![tasks[0].clone()]);
        std::thread::sleep(Duration::from_millis(10));
        tracker.push_tasks(vec![tasks[1].clone()]);
        std::thread::sleep(Duration::from_millis(10));
        tracker.push_tasks(vec![tasks[2].clone()]);

        let popped = tracker.pop_tasks(1);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 1);

        let popped = tracker.pop_tasks(1);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 2);
        let popped = tracker.pop_tasks(1);

        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].topic, 3);
    }
}
