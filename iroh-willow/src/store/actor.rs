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
use tracing::{debug, error, error_span, instrument, trace, warn, Span};
// use iroh_net::NodeId;

use super::Store;
use crate::{
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        willow::{AuthorisedEntry, Entry},
    },
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

// #[derive(Debug)]
// pub struct Notifier {
//     tx: flume::Sender<ToActor>,
// }
// impl Notifier {
//     pub async fn notify(&self, peer: NodeId, notify: Readyness) -> anyhow::Result<()> {
//         let msg = ToActor::Resume { peer, notify };
//         self.tx.send_async(msg).await?;
//         Ok(())
//     }
//     pub fn notify_sync(&self, peer: NodeId, notify: Readyness) -> anyhow::Result<()> {
//         let msg = ToActor::Resume { peer, notify };
//         self.tx.send(msg)?;
//         Ok(())
//     }
//     pub fn notifier(&self, peer: NodeId) -> Notifier {
//         Notifier {
//             tx: self.tx.clone(),
//         }
//     }
// }

#[derive(Debug, Clone)]
pub struct AssignedWaker {
    waker: CoroutineWaker,
    peer: NodeId,
    notify: Readyness,
}

impl AssignedWaker {
    pub fn wake(&self) -> anyhow::Result<()> {
        self.waker.wake(self.peer, self.notify)
    }
}

#[derive(Debug, Clone)]
pub struct CoroutineWaker {
    tx: flume::Sender<ToActor>,
}

impl CoroutineWaker {
    pub fn wake(&self, peer: NodeId, notify: Readyness) -> anyhow::Result<()> {
        let msg = ToActor::Resume { peer, notify };
        // TODO: deadlock
        self.tx.send(msg)?;
        Ok(())
    }

    pub fn with_notify(&self, peer: NodeId, notify: Readyness) -> AssignedWaker {
        AssignedWaker {
            waker: self.clone(),
            peer,
            notify,
        }
    }
}

impl StoreHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> StoreHandle {
        let (tx, rx) = flume::bounded(CHANNEL_CAP);
        // let actor_tx = tx.clone();
        let waker = CoroutineWaker { tx: tx.clone() };
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("store", me=%me.fmt_short());
                let _enter = span.enter();

                let mut actor = StorageThread {
                    store: Rc::new(RefCell::new(store)),
                    sessions: Default::default(),
                    actor_rx: rx,
                    waker,
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
    pub fn waker(&self) -> CoroutineWaker {
        CoroutineWaker {
            tx: self.tx.clone(),
        }
    }
    pub async fn ingest_entry(&self, entry: AuthorisedEntry) -> anyhow::Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::IngestEntry { entry, reply }).await?;
        reply_rx.await??;
        Ok(())
    }
    //
    // pub fn ingest_stream(&self, stream: impl Stream<Item = AuthorisedEntry>) -> Result<()> {
    // }
    // pub fn ingest_iter(&self, iter: impl <Item = AuthorisedEntry>) -> Result<()> {
    // }
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
        reply: oneshot::Sender<Result<(), Error>>,
    },
    // DropSession {
    //     peer: NodeId,
    // },
    Resume {
        peer: NodeId,
        notify: Readyness,
    },
    GetEntries {
        namespace: NamespaceId,
        #[debug(skip)]
        reply: flume::Sender<Entry>,
    },
    IngestEntry {
        entry: AuthorisedEntry,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown {
        #[debug(skip)]
        reply: Option<oneshot::Sender<()>>,
    },
}

#[derive(Debug)]
struct Session {
    state: SharedSessionState,
    channels: Channels,
    pending: PendingCoroutines,
    on_done: oneshot::Sender<Result<(), Error>>,
}

#[derive(derive_more::Debug, Default)]
struct PendingCoroutines {
    #[debug(skip)]
    inner: HashMap<Readyness, VecDeque<CoroutineState>>,
}

impl PendingCoroutines {
    fn get_mut(&mut self, pending_on: Readyness) -> &mut VecDeque<CoroutineState> {
        self.inner.entry(pending_on).or_default()
    }
    fn push_back(&mut self, pending_on: Readyness, generator: CoroutineState) {
        self.get_mut(pending_on).push_back(generator);
    }
    fn pop_front(&mut self, pending_on: Readyness) -> Option<CoroutineState> {
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
    sessions: HashMap<NodeId, Session>,
    actor_rx: flume::Receiver<ToActor>,
    waker: CoroutineWaker, // actor_tx: flume::Sender<ToActor>,
}

type ReconcileFut = LocalBoxFuture<'static, Result<(), Error>>;
type ReconcileGen = Gen<Yield, (), ReconcileFut>;

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
        trace!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                init,
                reply,
            } => {
                let session = Session {
                    state: Rc::new(RefCell::new(state)),
                    channels,
                    pending: Default::default(),
                    on_done: reply,
                };
                self.sessions.insert(peer, session);

                debug!("start coroutine control");

                if let Err(error) = self.start_coroutine(
                    peer,
                    |routine| routine.run_control(init).boxed_local(),
                    error_span!("control", peer=%peer.fmt_short()),
                    true,
                ) {
                    warn!(?error, peer=%peer.fmt_short(), "abort session: starting failed");
                    self.remove_session(&peer, Err(error));
                }
            }
            ToActor::Resume { peer, notify } => {
                if self.sessions.contains_key(&peer) {
                    if let Err(error) = self.resume_next(peer, notify) {
                        warn!(?error, peer=%peer.fmt_short(), "abort session: coroutine failed");
                        self.remove_session(&peer, Err(error));
                    }
                }
            }
            // ToActor::DropSession { peer } => {
            //     self.remove_session(&peer, Ok(()));
            // }
            ToActor::GetEntries { namespace, reply } => {
                let store = self.store.borrow();
                let entries = store
                    .get_entries(namespace, &ThreeDRange::full())
                    .filter_map(|r| r.ok());
                for entry in entries {
                    reply.send(entry).ok();
                }
            }
            ToActor::IngestEntry { entry, reply } => {
                let res = self.store.borrow_mut().ingest_entry(&entry);
                reply.send(res).ok();
            }
        }
        Ok(())
    }

    fn remove_session(&mut self, peer: &NodeId, result: Result<(), Error>) {
        let session = self.sessions.remove(peer);
        if let Some(session) = session {
            session.channels.close_all();
            session.on_done.send(result).ok();
        } else {
            warn!("remove_session called for unknown session");
        }
    }

    fn start_coroutine(
        &mut self,
        peer: NodeId,
        producer: impl FnOnce(Coroutine<S::Snapshot, S>) -> ReconcileFut,
        span: Span,
        finalizes_session: bool,
    ) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
        let store_snapshot = Rc::new(self.store.borrow_mut().snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();
        let store_writer = Rc::clone(&self.store);
        // let waker = self.waker.clone();

        let gen = Gen::new(move |co| {
            let routine = Coroutine {
                peer,
                store_snapshot,
                store_writer,
                // waker,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        let state = CoroutineState {
            gen,
            span,
            finalizes_session,
        };
        self.resume_coroutine(peer, state)
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

    fn resume_coroutine(&mut self, peer: NodeId, mut state: CoroutineState) -> Result<(), Error> {
        let _guard = state.span.enter();
        trace!(peer=%peer.fmt_short(), "resume");
        loop {
            match state.gen.resume() {
                GeneratorState::Yielded(yielded) => {
                    trace!(?yielded, "yield");
                    match yielded {
                        Yield::Pending(resume_on) => {
                            let session =
                                self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
                            drop(_guard);
                            match resume_on {
                                Readyness::Channel(ch, interest) => {
                                    let waker = self
                                        .waker
                                        .with_notify(peer, Readyness::Channel(ch, interest));
                                    match interest {
                                        Interest::Send => {
                                            session.channels.sender(ch).register_waker(waker)
                                        }
                                        Interest::Recv => {
                                            session.channels.receiver(ch).register_waker(waker)
                                        }
                                    };
                                }
                                Readyness::Resource(handle) => {
                                    let waker =
                                        self.waker.with_notify(peer, Readyness::Resource(handle));
                                    let mut state = session.state.borrow_mut();
                                    state.their_resources.register_waker(handle, waker);
                                }
                            }
                            session.pending.push_back(resume_on, state);
                            break Ok(());
                        }
                        Yield::StartReconciliation(start) => {
                            debug!("start coroutine reconciliation");
                            self.start_coroutine(
                                peer,
                                |routine| routine.run_reconciliation(start).boxed_local(),
                                error_span!("reconcile"),
                                false,
                            )?;
                        }
                    }
                }
                GeneratorState::Complete(res) => {
                    debug!(?res, "complete");
                    if res.is_err() || state.finalizes_session {
                        self.remove_session(&peer, res)
                    }
                    break Ok(());
                }
            }
        }
    }
}

struct CoroutineState {
    gen: ReconcileGen,
    span: Span,
    finalizes_session: bool,
}
