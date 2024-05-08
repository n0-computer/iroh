use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    rc::Rc,
    sync::Arc,
    thread::JoinHandle,
};

use futures::{future::LocalBoxFuture, FutureExt};
use genawaiter::{sync::Gen, GeneratorState};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, instrument, warn, Span};
// use iroh_net::NodeId;

use super::Store;
use crate::{
    proto::{grouping::ThreeDRange, keys::NamespaceId, willow::Entry},
    session::{
        coroutine::{Channels, Coroutine, Readyness, Yield},
        Error, SessionInit, SessionState, SharedSessionState,
    },
};
use iroh_base::key::NodeId;

pub const CHANNEL_CAP: usize = 1024;

#[derive(Debug, Clone)]
pub struct StoreHandle {
    tx: flume::Sender<ToActor>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Interest {
    Send,
    Recv,
}

#[derive(Debug)]
pub struct CoroutineNotifier {
    tx: flume::Sender<ToActor>,
}
impl CoroutineNotifier {
    pub async fn notify(&self, peer: NodeId, notify: Readyness) -> anyhow::Result<()> {
        let msg = ToActor::Resume { peer, notify };
        self.tx.send_async(msg).await?;
        Ok(())
    }
    pub fn notify_sync(&self, peer: NodeId, notify: Readyness) -> anyhow::Result<()> {
        let msg = ToActor::Resume { peer, notify };
        self.tx.send(msg)?;
        Ok(())
    }
    pub fn notifier(&self, peer: NodeId, notify: Readyness) -> Notifier {
        Notifier {
            tx: self.tx.clone(),
            peer,
            notify,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Notifier {
    tx: flume::Sender<ToActor>,
    notify: Readyness,
    peer: NodeId,
}

impl Notifier {
    pub async fn notify(&self) -> anyhow::Result<()> {
        let msg = ToActor::Resume {
            peer: self.peer,
            notify: self.notify,
        };
        self.tx.send_async(msg).await?;
        Ok(())
    }
    pub fn notify_sync(&self) -> anyhow::Result<()> {
        let msg = ToActor::Resume {
            peer: self.peer,
            notify: self.notify,
        };
        self.tx.send(msg)?;
        Ok(())
    }
}

impl StoreHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> StoreHandle {
        let (tx, rx) = flume::bounded(CHANNEL_CAP);
        let actor_tx = tx.clone();
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("store", me=%me.fmt_short());
                let _enter = span.enter();

                let mut actor = StorageThread {
                    store: Rc::new(RefCell::new(store)),
                    sessions: Default::default(),
                    actor_rx: rx,
                    actor_tx,
                };
                if let Err(error) = actor.run() {
                    error!(?error, "storage thread failed");
                };
            })
            .expect("failed to spawn thread");
        let join_handle = Arc::new(Some(join_handle));
        StoreHandle { tx, join_handle }
    }
    pub async fn send(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
    pub fn send_blocking(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send(action)?;
        Ok(())
    }
    pub fn notifier(&self, peer: NodeId, notify: Readyness) -> Notifier {
        Notifier {
            tx: self.tx.clone(),
            peer,
            notify,
        }
    }
}

impl Drop for StoreHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            self.tx.send(ToActor::Shutdown { reply: None }).ok();
            let handle = handle.take().expect("this can only run once");
            if let Err(err) = handle.join() {
                warn!(?err, "Failed to join sync actor");
            }
        }
    }
}
#[derive(derive_more::Debug, strum::Display)]
pub enum ToActor {
    InitSession {
        peer: NodeId,
        #[debug(skip)]
        state: SessionState,
        #[debug(skip)]
        channels: Channels,
        init: SessionInit,
    },
    DropSession {
        peer: NodeId,
    },
    Resume {
        peer: NodeId,
        notify: Readyness,
    },
    GetEntries {
        namespace: NamespaceId,
        #[debug(skip)]
        reply: flume::Sender<Entry>,
    },
    Shutdown {
        #[debug(skip)]
        reply: Option<oneshot::Sender<()>>,
    },
}

#[derive(Debug)]
struct StorageSession {
    state: SharedSessionState,
    channels: Channels,
    pending: PendingCoroutines,
}

#[derive(derive_more::Debug, Default)]
struct PendingCoroutines {
    #[debug(skip)]
    inner: HashMap<Readyness, VecDeque<ReconcileGen>>,
}

impl PendingCoroutines {
    fn get_mut(&mut self, pending_on: Readyness) -> &mut VecDeque<ReconcileGen> {
        self.inner.entry(pending_on).or_default()
    }
    fn push_back(&mut self, pending_on: Readyness, generator: ReconcileGen) {
        self.get_mut(pending_on).push_back(generator);
    }
    fn pop_front(&mut self, pending_on: Readyness) -> Option<ReconcileGen> {
        self.get_mut(pending_on).pop_front()
    }
    // fn push_front(&mut self, pending_on: Readyness, generator: ReconcileGen) {
    //     self.get_mut(pending_on).push_front(generator);
    // }
    // fn len(&self, pending_on: &Readyness) -> usize {
    //     self.inner.get(pending_on).map(|v| v.len()).unwrap_or(0)
    // }
    //
    // fn is_empty(&self) -> bool {
    //     self.inner.values().any(|v| !v.is_empty())
    // }
}

#[derive(Debug)]
pub struct StorageThread<S> {
    store: Rc<RefCell<S>>,
    sessions: HashMap<NodeId, StorageSession>,
    actor_rx: flume::Receiver<ToActor>,
    actor_tx: flume::Sender<ToActor>,
}

type ReconcileFut = LocalBoxFuture<'static, Result<(), Error>>;
type ReconcileGen = (Span, Gen<Yield, (), ReconcileFut>);

impl<S: Store> StorageThread<S> {
    pub fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let message = match self.actor_rx.recv() {
                Err(_) => break,
                Ok(message) => message,
            };
            match message {
                ToActor::Shutdown { reply } => {
                    if let Some(reply) = reply {
                        reply.send(()).ok();
                    }
                    break;
                }
                message => self.handle_message(message)?,
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        debug!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                init, // start,
            } => {
                let session = StorageSession {
                    state: Rc::new(RefCell::new(state)),
                    channels,
                    pending: Default::default(),
                };
                self.sessions.insert(peer, session);
                debug!("start coroutine control");
                self.start_coroutine(
                    peer,
                    |routine| routine.run_control(init).boxed_local(),
                    error_span!("control", peer=%peer.fmt_short()),
                )?;
            }
            ToActor::DropSession { peer } => {
                self.sessions.remove(&peer);
            }
            ToActor::Resume { peer, notify } => {
                self.resume_next(peer, notify)?;
            }
            ToActor::GetEntries { namespace, reply } => {
                let store = self.store.borrow();
                let entries = store
                    .get_entries(namespace, &ThreeDRange::full())
                    .filter_map(|r| r.ok());
                for entry in entries {
                    reply.send(entry).ok();
                }
            }
        }
        Ok(())
    }
    fn session_mut(&mut self, peer: &NodeId) -> Result<&mut StorageSession, Error> {
        self.sessions.get_mut(peer).ok_or(Error::SessionNotFound)
    }

    fn start_coroutine(
        &mut self,
        peer: NodeId,
        producer: impl FnOnce(Coroutine<S::Snapshot, S>) -> ReconcileFut,
        span: Span,
    ) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
        let store_snapshot = Rc::new(self.store.borrow_mut().snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();
        let store_writer = Rc::clone(&self.store);
        let notifier = CoroutineNotifier {
            tx: self.actor_tx.clone(),
        };

        let generator = Gen::new(move |co| {
            let routine = Coroutine {
                peer,
                store_snapshot,
                store_writer,
                notifier,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        self.resume_coroutine(peer, (span, generator))
    }

    #[instrument(skip_all, fields(session=%peer.fmt_short()))]
    fn resume_next(&mut self, peer: NodeId, notify: Readyness) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
        let generator = session.pending.pop_front(notify);
        match generator {
            Some(generator) => self.resume_coroutine(peer, generator),
            None => {
                debug!("nothing to resume");
                Ok(())
            }
        }
    }

    fn resume_coroutine(&mut self, peer: NodeId, generator: ReconcileGen) -> Result<(), Error> {
        let (span, mut generator) = generator;
        let _guard = span.enter();
        debug!("resume");
        loop {
            match generator.resume() {
                GeneratorState::Yielded(yielded) => {
                    debug!(?yielded, "yield");
                    match yielded {
                        Yield::Pending(notify) => {
                            let session = self.session_mut(&peer)?;
                            drop(_guard);
                            session.pending.push_back(notify, (span, generator));
                            break Ok(());
                        }
                        Yield::StartReconciliation(start) => {
                            debug!("start coroutine reconciliation");
                            self.start_coroutine(
                                peer,
                                |routine| routine.run_reconciliation(start).boxed_local(),
                                error_span!("reconcile"),
                            )?;
                        }
                    }
                }
                GeneratorState::Complete(res) => {
                    debug!(?res, "complete");
                    break res;
                }
            }
        }
    }
}
