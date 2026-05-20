//! A registry of supervised, keyed actors.
//!
//! [`ActorRegistry`] owns one actor per key. Actors are spawned on demand,
//! their inbox senders are kept in a map, and their tasks are supervised: when
//! an actor terminates the registry either forgets it or restarts it with the
//! messages it did not get to handle.
//!
//! The registry is generic over the key, the message, and an [`ActorFactory`]
//! that builds concrete actors, so its lifecycle logic can be tested without
//! any of a concrete actor's dependencies.

use std::{
    future::poll_fn,
    hash::Hash,
    task::{Context, Poll, Waker, ready},
};

use n0_future::task::JoinSet;
use tokio::sync::mpsc;
use tracing::{error, trace};

use crate::socket::concurrent_read_map::{ConcurrentReadMap, ReadOnlyMap};

/// Builds an actor for a key and spawns its task into the registry's [`JoinSet`].
pub(super) trait ActorFactory<K, M> {
    /// Builds an actor for `key` and spawns its task into `tasks`.
    ///
    /// `initial_messages` carries messages handed over from a previous incarnation of
    /// the actor. The actor must handle them before reading its inbox. On a
    /// fresh spawn `initial` is empty.
    ///
    /// Returns the actor's inbox sender. The spawned task must resolve to
    /// `key` and the inbox receiver, so the registry can recover any messages
    /// the actor did not handle before terminating.
    ///
    /// Before terminating, the actor must close its inbox receiver. A
    /// concurrent [`ActorRegistry::send`] would otherwise queue into a channel
    /// no task will ever read; the closed receiver makes that send fail
    /// instead, which is what drives the registry's recovery.
    fn spawn(
        &mut self,
        key: K,
        initial_messages: Vec<M>,
        tasks: &mut JoinSet<(K, mpsc::Receiver<M>)>,
    ) -> mpsc::Sender<M>;
}

/// A map of supervised actors, one per key.
///
/// Each actor owns an `mpsc` inbox. The registry keeps the sending half in its
/// sender map and the actor task in a [`JoinSet`]. [`ActorRegistry::send`]
/// routes a message to the actor for a key, spawning it on demand and
/// restarting it if it terminated concurrently. [`ActorRegistry::cleanup`]
/// joins terminated actor tasks and either forgets them or restarts them with
/// their unhandled messages.
#[derive(Debug)]
pub(super) struct ActorRegistry<K: Eq + Hash, M, F> {
    /// The inbox sender of each running actor.
    senders: ConcurrentReadMap<K, mpsc::Sender<M>>,
    tasks: Tasks<K, M, F>,
}

#[derive(derive_more::Debug)]
struct Tasks<K, M, F> {
    /// The actor tasks. Each resolves to its key and the actor's inbox.
    tasks: JoinSet<(K, mpsc::Receiver<M>)>,
    /// Waker for a [`ActorRegistry::cleanup`] caller, woken when a task is spawned.
    cleanup_waker: Option<Waker>,
    /// Builds and spawns actor tasks.
    factory: F,
}

impl<K, M, F> ActorRegistry<K, M, F>
where
    K: Hash + Eq + Copy + Send + 'static,
    M: Send + 'static,
    F: ActorFactory<K, M>,
{
    /// Creates an empty registry that builds actors with `factory`.
    pub(super) fn new(factory: F) -> Self {
        Self {
            senders: Default::default(),
            tasks: Tasks {
                tasks: JoinSet::new(),
                cleanup_waker: None,
                factory,
            },
        }
    }

    /// Returns a read-only view of the actor inbox senders.
    pub(super) fn senders(&self) -> ReadOnlyMap<K, mpsc::Sender<M>> {
        self.senders.read_only()
    }

    /// Sends `message` to the actor for `key`, spawning it if it is not running.
    ///
    /// If the actor is terminating, the inbox send fails. The registry then
    /// joins the terminating task and restarts the actor with `message`
    /// appended to the messages it left unhandled. `message` is handed to the
    /// replacement as part of its initial backlog, never re-sent through the
    /// inbox channel, so a full inbox cannot make the send fail or overflow.
    pub(super) async fn send(&mut self, key: K, message: M) {
        let sender = self
            .senders
            .get_or_insert_with(key, || self.tasks.spawn(key, Vec::new()));
        if let Err(mpsc::error::SendError(message)) = sender.send(message).await {
            // The send failed: the actor is terminating. Join its task before
            // spawning a replacement, both so the messages it left behind restart
            // into the new actor and so a later `cleanup` does not remove the
            // replacement's sender. The task cannot have been joined already
            // because we hold `&mut self`.
            loop {
                let (actor_key, inbox) = poll_fn(|cx| self.tasks.poll_join_next(cx)).await;
                let leftover_messages = drain_inbox(inbox);
                if actor_key == key {
                    let mut initial_messages = leftover_messages;
                    initial_messages.push(message);
                    let sender = self.tasks.spawn(key, initial_messages);
                    self.senders.insert(key, sender);
                    break;
                } else {
                    self.restart_or_remove(actor_key, leftover_messages);
                }
            }
        }
    }

    /// Joins the next terminated actor task, returning its key.
    ///
    /// An actor that terminated with unhandled messages is restarted with
    /// those messages; an actor that terminated cleanly is removed from the
    /// registry. Resolves once any actor task has joined, whether it was
    /// restarted or removed.
    ///
    /// Returns pending while no actor task has terminated. Should be called in
    /// a loop; only one task may poll it concurrently.
    pub(super) async fn cleanup(&mut self) -> K {
        let (key, inbox) = poll_fn(|cx| self.tasks.poll_join_next(cx)).await;
        self.restart_or_remove(key, drain_inbox(inbox));
        key
    }

    /// Removes the actor for `key`, or restarts it if `initial` is non-empty.
    fn restart_or_remove(&mut self, key: K, initial_messages: Vec<M>) {
        if initial_messages.is_empty() {
            trace!("actor terminated, removed from registry");
            self.senders.remove(&key);
        } else {
            trace!("actor terminated with unhandled messages, restarting");
            let sender = self.tasks.spawn(key, initial_messages);
            self.senders.insert(key, sender);
        }
    }
}

impl<K, M, F> Tasks<K, M, F>
where
    K: Hash + Eq + Copy + Send + 'static,
    M: Send + 'static,
    F: ActorFactory<K, M>,
{
    /// Polls for the next terminated actor task.
    ///
    /// A panicked task aborts the registry by resuming the panic; a cancelled
    /// task is skipped. Registers `cx`'s waker when no task has terminated.
    fn poll_join_next(&mut self, cx: &mut Context<'_>) -> Poll<(K, mpsc::Receiver<M>)> {
        while let Some(result) = ready!(self.tasks.poll_join_next(cx)) {
            match result {
                Ok((key, leftover_messages)) => return Poll::Ready((key, leftover_messages)),
                Err(err) => {
                    if let Ok(panic) = err.try_into_panic() {
                        error!("actor task panicked");
                        std::panic::resume_unwind(panic);
                    }
                }
            }
        }
        // The `JoinSet` is empty. Register to be woken when `spawn` adds a task.
        self.cleanup_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Spawns a fresh actor task for `key` with `initial_messages`.
    fn spawn(&mut self, key: K, initial_messages: Vec<M>) -> mpsc::Sender<M> {
        let sender = self.factory.spawn(key, initial_messages, &mut self.tasks);
        if let Some(waker) = self.cleanup_waker.take() {
            waker.wake();
        }
        sender
    }
}

/// Closes `inbox` and collects every message still queued in it.
fn drain_inbox<M>(mut inbox: mpsc::Receiver<M>) -> Vec<M> {
    inbox.close();
    let mut unhandled = Vec::new();
    while let Ok(message) = inbox.try_recv() {
        unhandled.push(message);
    }
    unhandled
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use n0_future::future::now_or_never;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// A message for the test actor: reply with the actor's identity.
    #[derive(Debug)]
    struct WhoAreYou(oneshot::Sender<(u8, u32)>);

    /// An [`ActorFactory`] of trivial test actors keyed by `u8`.
    ///
    /// Each spawned actor gets a unique generation number, so a test can tell
    /// which incarnation answered, and a fresh [`CancellationToken`] that
    /// [`TestFactory::stop`] uses to terminate it.
    #[derive(Debug, Clone, Default)]
    struct TestFactory {
        state: Arc<Mutex<TestFactoryState>>,
    }

    #[derive(Debug, Default)]
    struct TestFactoryState {
        next_generation: u32,
        tokens: HashMap<u8, CancellationToken>,
    }

    impl TestFactory {
        /// Terminates the live actor for `key`.
        fn stop(&self, key: u8) {
            if let Some(token) = self.state.lock().unwrap().tokens.get(&key) {
                token.cancel();
            }
        }
    }

    impl ActorFactory<u8, WhoAreYou> for TestFactory {
        fn spawn(
            &mut self,
            key: u8,
            initial: Vec<WhoAreYou>,
            tasks: &mut JoinSet<(u8, mpsc::Receiver<WhoAreYou>)>,
        ) -> mpsc::Sender<WhoAreYou> {
            let (sender, inbox) = mpsc::channel(16);
            let cancel = CancellationToken::new();
            let generation = {
                let mut state = self.state.lock().unwrap();
                state.next_generation += 1;
                state.tokens.insert(key, cancel.clone());
                state.next_generation
            };
            tasks.spawn(test_actor(key, generation, initial, inbox, cancel));
            sender
        }
    }

    /// Creates a registry that spawns [`test_actor`]s, paired with the
    /// [`TestFactory`] that hands out their generations and cancel tokens.
    fn test_registry() -> (ActorRegistry<u8, WhoAreYou, TestFactory>, TestFactory) {
        let factory = TestFactory::default();
        (ActorRegistry::new(factory.clone()), factory)
    }

    /// Runs a test actor: handles its `initial` backlog, then its inbox until
    /// cancelled or the inbox closes, then closes the inbox and hands it back
    /// to the registry, as the [`ActorFactory`] contract requires.
    async fn test_actor(
        key: u8,
        generation: u32,
        initial: Vec<WhoAreYou>,
        mut inbox: mpsc::Receiver<WhoAreYou>,
        cancel: CancellationToken,
    ) -> (u8, mpsc::Receiver<WhoAreYou>) {
        for msg in initial {
            msg.0.send((key, generation)).ok();
        }
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                msg = inbox.recv() => match msg {
                    Some(msg) => {
                        msg.0.send((key, generation)).ok();
                    }
                    None => break,
                }
            }
        }
        // Close the inbox so a send racing the actor's termination fails and
        // triggers recovery, mirroring what a real actor must do.
        inbox.close();
        (key, inbox)
    }

    /// `send` spawns an actor on the first message for a key.
    #[tokio::test(flavor = "current_thread")]
    async fn send_spawns_actor_on_demand() {
        let (mut registry, _factory) = test_registry();
        let (tx, rx) = oneshot::channel();
        registry.send(1, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (1, 1));
    }

    /// `send` recovers when the actor terminated and its sender is closed: it
    /// joins the dead task, spawns a replacement, and delivers the message.
    #[tokio::test(flavor = "current_thread")]
    async fn send_recovers_after_actor_terminated() {
        let (mut registry, factory) = test_registry();

        // Generation 1 answers once.
        let (tx, rx) = oneshot::channel();
        registry.send(1, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (1, 1));

        // Stop it; the sender held by the registry is now closed.
        factory.stop(1);
        tokio::task::yield_now().await;

        // The next send must notice the closed sender, join the terminated
        // task, restart the actor (generation 2) with the message as its
        // backlog, and deliver.
        let (tx, rx) = oneshot::channel();
        registry.send(1, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (1, 2));
    }

    /// An actor that terminates with messages still in its inbox is restarted
    /// by `cleanup` with those messages as its initial backlog.
    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_restarts_actor_with_unhandled_messages() {
        let (mut registry, factory) = test_registry();

        // Queue two messages. The actor task is spawned but, with no yield,
        // never polled, so the messages sit unread in its inbox.
        let (tx_a, rx_a) = oneshot::channel();
        registry.send(9, WhoAreYou(tx_a)).await;
        let (tx_b, rx_b) = oneshot::channel();
        registry.send(9, WhoAreYou(tx_b)).await;

        // Stop the actor before it processes anything.
        factory.stop(9);

        // `cleanup` joins the stopped actor and restarts it with the two
        // unhandled messages as the replacement's initial backlog.
        assert_eq!(registry.cleanup().await, 9);

        // The restarted actor (generation 2) answers both.
        assert_eq!(rx_a.await.unwrap(), (9, 2));
        assert_eq!(rx_b.await.unwrap(), (9, 2));
    }

    /// A `cleanup` must not remove the sender of an actor that `send` already
    /// restarted.
    ///
    /// `send`'s recovery joins the terminated task before spawning the
    /// replacement, so a later `cleanup` finds nothing to reap. Were the
    /// replacement spawned first, `cleanup` would join the stale task and
    /// remove the replacement's sender, stranding it.
    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_does_not_remove_a_restarted_actor() {
        let (mut registry, factory) = test_registry();

        // Generation 1.
        let (tx, rx) = oneshot::channel();
        registry.send(2, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (2, 1));

        // Stop generation 1 and let its task finish.
        factory.stop(2);
        tokio::task::yield_now().await;

        // This send joins generation 1's task and spawns generation 2.
        let (tx, rx) = oneshot::channel();
        registry.send(2, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (2, 2));

        // A stray cleanup finds nothing to do and must not strand generation 2.
        assert!(now_or_never(registry.cleanup()).is_none());

        // The next send still reaches generation 2.
        let (tx, rx) = oneshot::channel();
        registry.send(2, WhoAreYou(tx)).await;
        assert_eq!(rx.await.unwrap(), (2, 2));
    }
}
