use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
    task::Wake,
    thread::JoinHandle,
};

use futures::{future::LocalBoxFuture, FutureExt};
use genawaiter::{sync::Gen, GeneratorState};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn, Span};

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

pub type SessionId = NodeId;

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
    waker: Notifier,
    coro_id: CoroId,
}

impl AssignedWaker {
    pub fn wake(&self) {
        self.waker.wake(self.coro_id)
    }
}

impl Wake for AssignedWaker {
    fn wake(self: Arc<Self>) {
        self.waker.wake(self.coro_id)
    }
}

#[derive(Debug, Clone)]
pub struct Notifier {
    tx: flume::Sender<CoroId>,
}

impl Notifier {
    pub fn wake(&self, coro_id: CoroId) {
        self.tx.send(coro_id).ok();
    }

    pub fn create_waker(&self, coro_id: CoroId) -> std::task::Waker {
        Arc::new(AssignedWaker {
            waker: self.clone(),
            coro_id,
        })
        .into()
    }
}

impl StoreHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> StoreHandle {
        let (tx, rx) = flume::bounded(CHANNEL_CAP);
        // This channel only tracks wake to resume messages to coroutines, which are a sinlge u64
        // per wakeup. We want to issue wake calls synchronosuly without blocking, so we use an
        // unbounded channel here. The actual capacity is bounded by the number of sessions times
        // the number of coroutines per session (which is fixed, currently at 2).
        let (notify_tx, notify_rx) = flume::unbounded();
        // let actor_tx = tx.clone();
        let waker = Notifier { tx: notify_tx };
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("store", me=%me.fmt_short());
                let _enter = span.enter();

                let mut actor = StorageThread {
                    store: Rc::new(RefCell::new(store)),
                    sessions: Default::default(),
                    coroutines: Default::default(),

                    next_coro_id: Default::default(),
                    inbox_rx: rx,
                    notify_rx,
                    notifier: waker,
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
        on_done: oneshot::Sender<Result<(), Error>>,
    },
    // DropSession {
    //     peer: NodeId,
    // },
    // Resume {
    //     session_id: SessionId,
    //     coro_id: CoroId,
    // },
    GetEntries {
        namespace: NamespaceId,
        range: ThreeDRange,
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
    coroutines: HashSet<CoroId>,
    on_done: oneshot::Sender<Result<(), Error>>,
}

type CoroId = u64;

#[derive(Debug)]
pub struct StorageThread<S> {
    inbox_rx: flume::Receiver<ToActor>,
    notify_rx: flume::Receiver<CoroId>,
    store: Rc<RefCell<S>>,
    sessions: HashMap<SessionId, Session>,
    coroutines: HashMap<CoroId, CoroutineState>,
    next_coro_id: u64,
    notifier: Notifier, // actor_tx: flume::Sender<ToActor>,
}

type ReconcileFut = LocalBoxFuture<'static, Result<(), Error>>;
type ReconcileGen = Gen<Yield, (), ReconcileFut>;

#[derive(derive_more::Debug)]
struct CoroutineState {
    id: CoroId,
    session_id: SessionId,
    #[debug("Generator")]
    gen: ReconcileGen,
    span: Span,
    finalizes_session: bool,
}

impl<S: Store> StorageThread<S> {
    pub fn run(&mut self) -> anyhow::Result<()> {
        enum Op {
            Inbox(ToActor),
            Notify(CoroId),
        }
        loop {
            let op = flume::Selector::new()
                .recv(&self.inbox_rx, |r| r.map(Op::Inbox))
                .recv(&self.notify_rx, |r| r.map(Op::Notify))
                .wait();

            let Ok(op) = op else {
                break;
            };

            match op {
                Op::Inbox(ToActor::Shutdown { reply }) => {
                    if let Some(reply) = reply {
                        reply.send(()).ok();
                    }
                    break;
                }
                Op::Inbox(message) => self.handle_message(message)?,
                Op::Notify(coro_id) => self.handle_resume(coro_id),
            }
        }
        Ok(())
    }

    fn handle_resume(&mut self, coro_id: CoroId) {
        if let Some(coro) = self.coroutines.remove(&coro_id) {
            let session_id = coro.session_id;
            if let Err(error) = self.resume_coroutine(coro) {
                warn!(?error, session=%session_id.fmt_short(), "abort session: coroutine failed");
                self.remove_session(&session_id, Err(error));
            }
        } else {
            debug!(%coro_id, "received wakeup for dropped coroutine");
        }
    }

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        trace!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                init: setup,
                on_done,
            } => {
                let session = Session {
                    state: Rc::new(RefCell::new(state)),
                    channels,
                    coroutines: Default::default(),
                    on_done,
                };
                self.sessions.insert(peer, session);

                debug!("start coroutine control");

                if let Err(error) = self.start_coroutine(
                    peer,
                    |routine| routine.run_control(setup).boxed_local(),
                    error_span!("session", peer=%peer.fmt_short()),
                    true,
                ) {
                    warn!(?error, peer=%peer.fmt_short(), "abort session: starting failed");
                    self.remove_session(&peer, Err(error));
                }
            }
            ToActor::GetEntries { namespace, range, reply } => {
                let store = self.store.borrow();
                let entries = store
                    .get_entries(namespace, &range)
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
            for coro_id in session.coroutines {
                self.coroutines.remove(&coro_id);
            }
        } else {
            warn!("remove_session called for unknown session");
        }
    }

    fn start_coroutine(
        &mut self,
        session_id: SessionId,
        producer: impl FnOnce(Coroutine<S::Snapshot, S>) -> ReconcileFut,
        span: Span,
        finalizes_session: bool,
    ) -> Result<(), Error> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(Error::SessionNotFound)?;
        let store_snapshot = Rc::new(self.store.borrow_mut().snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();
        let store_writer = Rc::clone(&self.store);

        let gen = Gen::new(move |co| {
            let routine = Coroutine {
                store_snapshot,
                store_writer,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        let id = {
            let next_id = self.next_coro_id;
            self.next_coro_id += 1;
            next_id
        };
        session.coroutines.insert(id);
        let state = CoroutineState {
            id,
            session_id,
            gen,
            span,
            finalizes_session,
        };
        self.resume_coroutine(state)
    }

    fn resume_coroutine(&mut self, mut coro: CoroutineState) -> Result<(), Error> {
        let _guard = coro.span.enter();
        trace!("resume");
        loop {
            match coro.gen.resume() {
                GeneratorState::Yielded(yielded) => {
                    trace!(?yielded, "yield");
                    match yielded {
                        Yield::Pending(waiting_for) => {
                            let session = self
                                .sessions
                                .get_mut(&coro.session_id)
                                .ok_or(Error::SessionNotFound)?;
                            drop(_guard);
                            match waiting_for {
                                Readyness::Channel(ch, interest) => {
                                    let waker = self.notifier.create_waker(coro.id);
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
                                    let waker = self.notifier.create_waker(coro.id);
                                    let mut state = session.state.borrow_mut();
                                    state.their_resources.register_waker(handle, waker);
                                }
                            }
                            self.coroutines.insert(coro.id, coro);
                            break Ok(());
                        }
                        Yield::StartReconciliation(start) => {
                            debug!("start coroutine reconciliation");
                            self.start_coroutine(
                                coro.session_id,
                                |state| state.run_reconciliation(start).boxed_local(),
                                error_span!("reconcile"),
                                false,
                            )?;
                        }
                    }
                }
                GeneratorState::Complete(res) => {
                    debug!(?res, "complete");
                    if res.is_err() || coro.finalizes_session {
                        self.remove_session(&coro.session_id, res)
                    }
                    break Ok(());
                }
            }
        }
    }

    // fn next_coro_id(&mut self) -> u64 {
    //     let next_id = self.next_coro_id;
    //     self.next_coro_id += 1;
    //     next_id
    // }
}
