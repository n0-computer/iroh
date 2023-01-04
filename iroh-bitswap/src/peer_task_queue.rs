//! Based on <https://github.com/ipfs/go-peertaskqueue>.

use std::{fmt::Debug, sync::Arc};

use ahash::AHashSet;
use keyed_priority_queue::{Entry, KeyedPriorityQueue};
use libp2p::PeerId;
use tokio::sync::Mutex;
use tracing::warn;

mod peer_task;
mod peer_tracker;

pub use self::peer_task::{Task, TaskMerger};
use self::{
    peer_task::DefaultTaskMerger,
    peer_tracker::{PeerTracker, Topics},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
}

/// Prioritzed list of tasks to be executed on peers.
///
/// Tasks are added to the queue, then popped off alternately between peers (roughly)
/// to execute the block with the highest priority, or otherwise the one added first
/// if priorities are equal.
#[derive(Debug, Clone)]
pub struct PeerTaskQueue<T: Topic, D: Data, TM: TaskMerger<T, D> = DefaultTaskMerger> {
    inner: Arc<Mutex<Inner<T, D, TM>>>,
}
impl<T: Topic, D: Data, TM: TaskMerger<T, D> + Default> Default for PeerTaskQueue<T, D, TM> {
    fn default() -> Self {
        Self::new(TM::default(), Config::default())
    }
}

#[derive(Debug)]
struct Inner<T: Topic, D: Data, TM: TaskMerger<T, D>> {
    peer_queue: KeyedPriorityQueue<PeerId, PeerTracker<T, D, TM>>,
    frozen_peers: AHashSet<PeerId>,
    ignore_freezing: bool,
    task_merger: TM,
    max_outstanding_work_per_peer: usize,
    hooks: Vec<async_channel::Sender<Event>>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Sets if freezing should be enabled or not.
    pub ignore_freezing: bool,
    /// Configures how many task a peer can have outstanding with the same topic as an existing topic.
    pub max_outstanding_work_per_peer: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub num_peers: usize,
    pub num_active: usize,
    pub num_pending: usize,
}

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> PeerTaskQueue<T, D, TM> {
    pub fn new(task_merger: TM, config: Config) -> Self {
        PeerTaskQueue {
            inner: Arc::new(Mutex::new(Inner::<T, D, TM> {
                peer_queue: Default::default(),
                frozen_peers: Default::default(),
                ignore_freezing: config.ignore_freezing,
                task_merger,
                max_outstanding_work_per_peer: config.max_outstanding_work_per_peer,
                hooks: Vec::new(),
            })),
        }
    }

    /// Adds a hook to be notified on `Event`s.
    pub async fn add_hook(&self, cap: usize) -> async_channel::Receiver<Event> {
        let (s, r) = async_channel::bounded(cap);
        let mut this = self.inner.lock().await;
        this.hooks.push(s);

        r
    }

    /// Returns stats about the queue.
    pub async fn stats(&self) -> Stats {
        let this = self.inner.lock().await;
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
    pub async fn peer_topics(&self, peer: &PeerId) -> Option<Topics<T>> {
        let mut this = self.inner.lock().await;
        if let Entry::Occupied(tracker) = this.peer_queue.entry(*peer) {
            let tracker = tracker.get_priority();
            return Some(tracker.topics());
        }

        None
    }

    /// Adds a new group of tasks for the given peer to the queue.
    pub async fn push_tasks(&self, peer: PeerId, tasks: Vec<Task<T, D>>) {
        let mut this = self.inner.lock().await;

        let mut peer_tracker = match this.peer_queue.remove(&peer) {
            Some(peer_tracker) => peer_tracker,
            None => {
                let peer_tracker = PeerTracker::new(
                    peer,
                    this.task_merger.clone(),
                    this.max_outstanding_work_per_peer,
                );
                this.call_hook(Event::PeerAdded(peer)).await;
                peer_tracker
            }
        };

        peer_tracker.push_tasks(tasks);
        this.peer_queue.push(peer, peer_tracker);
    }

    pub async fn push_task(&self, peer: PeerId, task: Task<T, D>) {
        self.push_tasks(peer, vec![task]).await;
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
    pub async fn pop_tasks(
        &self,
        target_min_work: usize,
    ) -> Option<(PeerId, Vec<Task<T, D>>, usize)> {
        let mut this = self.inner.lock().await;
        let (peer, mut peer_tracker) = this.peer_queue.pop()?;
        let out = peer_tracker.pop_tasks(target_min_work);
        let pending_work = peer_tracker.get_pending_work();

        if peer_tracker.is_idle() {
            // Cleanup if no more tasks
            this.frozen_peers.remove(&peer);
            this.call_hook(Event::PeerRemoved(peer)).await;
        } else {
            // otherwise, reinsert updated tracker
            this.peer_queue.push(peer, peer_tracker);
        }

        Some((peer, out, pending_work))
    }

    /// Called to indicate that the given tasks have completed.
    pub async fn tasks_done(&self, peer: PeerId, tasks: &[Task<T, D>]) {
        let mut this = self.inner.lock().await;

        if let Some(mut peer_tracker) = this.peer_queue.remove(&peer) {
            // tell the peer what was done
            for task in tasks {
                peer_tracker.task_done(task);
            }
            this.peer_queue.push(peer, peer_tracker);
        }
    }

    /// Removes a task from the queue
    pub async fn remove(&self, topic: &T, peer: PeerId) {
        let mut this = self.inner.lock().await;

        if let Some(mut peer_tracker) = this.peer_queue.remove(&peer) {
            if peer_tracker.remove(topic) {
                // freeze that partner, if they sent us a cancle for a block we are about to send them
                // we should wait a short period of time to make sure we receive any other in flight cancels before sending them a block they already potentially have
                if !this.ignore_freezing {
                    if !peer_tracker.is_frozen() {
                        this.frozen_peers.insert(peer);
                    }
                    peer_tracker.freeze();
                }
            }
            this.peer_queue.push(peer, peer_tracker);
        }
    }

    /// Completely thaws all peers in the queue so they can execute tasks.
    pub async fn full_thaw(&self) {
        let mut this = self.inner.lock().await;
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
    pub async fn thaw_round(&self) {
        let mut this = self.inner.lock().await;

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

impl<T: Topic, D: Data, TM: TaskMerger<T, D>> Inner<T, D, TM> {
    async fn call_hook(&self, event: Event) {
        for hook in &self.hooks {
            if let Err(err) = hook.send(event.clone()).await {
                warn!("failed to call hook for {:?}: {:?}", event, err);
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
pub trait Data: Sized + Debug + Clone + PartialEq + Eq + Send {}
impl<D: Sized + Debug + Clone + PartialEq + Eq + Send> Data for D {}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use super::{peer_task::DefaultTaskMerger, *};

    #[tokio::test]
    async fn test_push_pop() {
        let ptq = PeerTaskQueue::<_, _, DefaultTaskMerger>::default();
        let partner = PeerId::random();
        let mut alphabet: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let mut vowels: Vec<char> = "aeiou".chars().collect();
        let mut consonants: Vec<char> = alphabet
            .iter()
            .filter(|c| !vowels.contains(c))
            .copied()
            .collect();
        alphabet.sort();
        vowels.sort();
        consonants.sort();

        // Add blocks, cancel some, drain the queue.
        // The queue should only have the kept tasks at the end.

        let mut shuffled_alphabet = alphabet.clone();
        let mut rng = thread_rng();
        shuffled_alphabet.shuffle(&mut rng);
        // add blocks for all letters
        for letter in shuffled_alphabet {
            let i = alphabet.iter().position(|c| *c == letter).unwrap();
            println!("{letter} - {i}");
            ptq.push_task(
                partner,
                Task {
                    topic: letter,
                    priority: i32::MAX as isize - i as isize,
                    work: 0,
                    data: (),
                },
            )
            .await;
        }

        for consonant in &consonants {
            ptq.remove(consonant, partner).await;
        }

        ptq.full_thaw().await;

        let mut out = Vec::new();
        while let Some((_, received, _)) = ptq.pop_tasks(100).await {
            if received.is_empty() {
                break;
            }
            for task in received {
                out.push(task.topic);
            }
        }

        assert_eq!(out.len(), vowels.len());

        // should be in correct order
        for (i, expected) in vowels.into_iter().enumerate() {
            assert_eq!(out[i], expected);
        }
    }

    #[tokio::test]
    async fn test_freeze_unfreeze() {
        let ptq = PeerTaskQueue::<_, _, DefaultTaskMerger>::default();
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let d = PeerId::random();

        for i in 0..5 {
            let task = Task {
                topic: i,
                work: 1,
                priority: 0,
                data: (),
            };

            ptq.push_task(a, task.clone()).await;
            ptq.push_task(b, task.clone()).await;
            ptq.push_task(c, task.clone()).await;
            ptq.push_task(d, task).await;
        }

        println!("all four");
        match_n_tasks(&ptq, 4, &[a, b, c, d][..]).await;
        ptq.remove(&1, b).await;

        // b should be frozen
        println!("frozen b");
        match_n_tasks(&ptq, 3, &[a, c, d][..]).await;

        ptq.thaw_round().await;

        println!("unfrozen b");
        match_n_tasks(&ptq, 1, &[b][..]).await;

        // remove non existent task
        ptq.remove(&9, b).await;

        // b should not be frozen
        println!("all four again");
        match_n_tasks(&ptq, 4, &[a, b, c, d][..]).await;
    }

    #[tokio::test]
    async fn test_freeze_unfreeze_no_freezing() {
        let config = Config {
            ignore_freezing: true,
            ..Default::default()
        };
        let ptq =
            PeerTaskQueue::<_, _, DefaultTaskMerger>::new(DefaultTaskMerger::default(), config);
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let d = PeerId::random();

        for i in 0..5 {
            let task = Task {
                topic: i,
                work: 1,
                priority: 0,
                data: (),
            };

            ptq.push_task(a, task.clone()).await;
            ptq.push_task(b, task.clone()).await;
            ptq.push_task(c, task.clone()).await;
            ptq.push_task(d, task).await;
        }

        match_n_tasks(&ptq, 4, &[a, b, c, d][..]).await;
        ptq.remove(&1, b).await;

        // b should not be frozen
        match_n_tasks(&ptq, 4, &[a, b, c, d][..]).await;
    }

    #[tokio::test]
    async fn test_peer_order() {
        let ptq = PeerTaskQueue::<_, _, DefaultTaskMerger>::default();
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();

        ptq.push_task(
            a,
            Task {
                topic: 1,
                work: 3,
                priority: 2,
                data: (),
            },
        )
        .await;
        ptq.push_task(
            a,
            Task {
                topic: 2,
                work: 1,
                priority: 1,
                data: (),
            },
        )
        .await;

        ptq.push_task(
            b,
            Task {
                topic: 3,
                work: 1,
                priority: 3,
                data: (),
            },
        )
        .await;
        ptq.push_task(
            b,
            Task {
                topic: 4,
                work: 3,
                priority: 2,
                data: (),
            },
        )
        .await;
        ptq.push_task(
            b,
            Task {
                topic: 5,
                work: 1,
                priority: 1,
                data: (),
            },
        )
        .await;

        ptq.push_task(
            c,
            Task {
                topic: 6,
                work: 2,
                priority: 2,
                data: (),
            },
        )
        .await;
        ptq.push_task(
            c,
            Task {
                topic: 7,
                work: 2,
                priority: 1,
                data: (),
            },
        )
        .await;

        // all peers have nothing in their active so equal of any peer being chosen

        let mut peers = Vec::new();
        let mut ids = Vec::new();
        for _i in 0..3 {
            let (peer, tasks, _) = ptq.pop_tasks(1).await.unwrap();
            peers.push(peer);
            assert_eq!(tasks.len(), 1);
            ids.push(tasks[0].topic);
        }

        assert_eq_unordered(peers, [a, b, c]);
        assert_eq_unordered(ids, [1, 3, 6]);

        // Active queues:
        // a: 3            Pending: [1]
        // b: 1            Pending: [3, 1]
        // c: 2            Pending: [2]
        // So next peer should be b (least work in active queue)
        let (peer, task, pending) = ptq.pop_tasks(1).await.unwrap();
        assert_eq!(task.len(), 1);
        assert_eq!(peer, b);
        assert_eq!(task[0].topic, 4);
        assert_eq!(pending, 1);

        // Active queues:
        // a: 3            Pending: [1]
        // b: 1 + 3        Pending: [1]
        // c: 2            Pending: [2]
        // So next peer should be c (least work in active queue)
        let (peer, task, _) = ptq.pop_tasks(1).await.unwrap();
        assert_eq!(task.len(), 1);
        assert_eq!(peer, c);
        assert_eq!(task[0].topic, 7);

        // Active queues:
        // a: 3            Pending: [1]
        // b: 1 + 3        Pending: [1]
        // c: 2 + 2
        // So next peer should be a (least work in active queue)
        let (peer, task, pending) = ptq.pop_tasks(1).await.unwrap();
        assert_eq!(task.len(), 1);
        assert_eq!(peer, a);
        assert_eq!(task[0].topic, 2);
        assert_eq!(pending, 0);

        // Active queues:
        // a: 3 + 1
        // b: 1 + 3        Pending: [1]
        // c: 2 + 2
        // a & c have no more pending tasks, so next peer should be b
        let (peer, task, pending) = ptq.pop_tasks(1).await.unwrap();
        assert_eq!(task.len(), 1);
        assert_eq!(peer, b);
        assert_eq!(task[0].topic, 5);
        assert_eq!(pending, 0);

        // Active queues:
        // a: 3 + 1
        // b: 1 + 3 + 1
        // c: 2 + 2
        // No more pending tasks, so next pop should return nothing
        let (_peer, task, pending) = ptq.pop_tasks(1).await.unwrap();
        assert!(task.is_empty());
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    async fn test_hooks() {
        let ptq = PeerTaskQueue::<_, _, DefaultTaskMerger>::default();
        let hook = ptq.add_hook(5).await;

        let a = PeerId::random();
        let b = PeerId::random();

        ptq.push_task(
            a,
            Task {
                topic: 1,
                priority: 0,
                work: 0,
                data: (),
            },
        )
        .await;
        ptq.push_task(
            b,
            Task {
                topic: 2,
                priority: 0,
                work: 0,
                data: (),
            },
        )
        .await;

        assert_eq!(hook.recv().await.unwrap(), Event::PeerAdded(a));
        assert_eq!(hook.recv().await.unwrap(), Event::PeerAdded(b));

        let (peer, tasks, _) = ptq.pop_tasks(100).await.unwrap();
        ptq.tasks_done(peer, &tasks).await;
        let (peer, tasks, _) = ptq.pop_tasks(100).await.unwrap();
        ptq.tasks_done(peer, &tasks).await;
        ptq.pop_tasks(100).await;
        ptq.pop_tasks(100).await;

        assert_eq!(hook.recv().await.unwrap(), Event::PeerRemoved(b));
        assert_eq!(hook.recv().await.unwrap(), Event::PeerRemoved(a));
        assert!(hook.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_cleaning_up() {
        let ptq = PeerTaskQueue::<_, _, DefaultTaskMerger>::default();
        let peer = PeerId::random();

        let peer_tasks: Vec<_> = (0..5)
            .map(|i| Task {
                topic: i,
                priority: 0,
                work: 0,
                data: (),
            })
            .collect();
        // push a block, pop a block,  complete eerything, should be removed

        ptq.push_tasks(peer, peer_tasks.clone()).await;
        let (peer, tasks, _) = ptq.pop_tasks(100).await.unwrap();
        ptq.tasks_done(peer, &tasks).await;
        let (_, tasks, _) = ptq.pop_tasks(100).await.unwrap();
        assert!(tasks.is_empty());
        assert!(ptq.inner.lock().await.peer_queue.is_empty());
        // push a block, remove each of its entries, should be removed
        ptq.push_tasks(peer, peer_tasks.clone()).await;
        for task in peer_tasks {
            ptq.remove(&task.topic, peer).await;
        }
        let (_, tasks, _) = ptq.pop_tasks(100).await.unwrap();
        assert!(tasks.is_empty());
        assert!(ptq.inner.lock().await.peer_queue.is_empty());
    }

    async fn match_n_tasks<T: Topic, D: Data, TM: TaskMerger<T, D>>(
        ptq: &PeerTaskQueue<T, D, TM>,
        n: usize,
        expected: &[PeerId],
    ) {
        let mut targets = Vec::new();
        for i in 0..n {
            let (peer, tasks, _) = ptq.pop_tasks(1).await.unwrap();
            assert_eq!(tasks.len(), 1, "task {i} did not match: {tasks:?}");
            targets.push(peer);
        }
        assert_eq_unordered(expected, targets);
    }

    fn assert_eq_unordered<T: Ord + Eq + Debug + Clone>(a: impl AsRef<[T]>, b: impl AsRef<[T]>) {
        let mut a: Vec<_> = a.as_ref().iter().collect();
        a.sort();
        let mut b: Vec<_> = b.as_ref().iter().collect();
        b.sort();
        assert_eq!(a, b);
    }
}
