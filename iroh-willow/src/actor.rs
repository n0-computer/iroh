use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread::JoinHandle,
};

use futures_lite::{
    future::{Boxed as BoxFuture, BoxedLocal as LocalBoxFuture},
    stream::Stream,
};
use futures_util::future::{FutureExt, Shared};
use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use iroh_base::key::NodeId;
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn, Span};

use crate::{
    net::InitialTransmission,
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        wgps::AreaOfInterestHandle,
        willow::{AuthorisedEntry, Entry},
    },
    session::{
        coroutine::{ControlRoutine, ReconcileRoutine},
        Channels, Error, Role, SessionInit, SessionState, SharedSessionState,
    },
    store::Store,
};

pub const INBOX_CAP: usize = 1024;

pub type SessionId = NodeId;

#[derive(Debug, Clone)]
pub struct ActorHandle {
    tx: flume::Sender<ToActor>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

impl ActorHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> ActorHandle {
        let (tx, rx) = flume::bounded(INBOX_CAP);
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
                let span = error_span!("willow_thread", me=%me.fmt_short());
                let _guard = span.enter();

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
        ActorHandle { tx, join_handle }
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

    pub async fn get_entries(
        &self,
        namespace: NamespaceId,
        range: ThreeDRange,
    ) -> anyhow::Result<impl Stream<Item = Entry>> {
        let (tx, rx) = flume::bounded(1024);
        self.send(ToActor::GetEntries {
            namespace,
            reply: tx,
            range,
        })
        .await?;
        Ok(rx.into_stream())
    }

    pub async fn init_session(
        &self,
        peer: NodeId,
        our_role: Role,
        initial_transmission: InitialTransmission,
        channels: Channels,
        init: SessionInit,
    ) -> anyhow::Result<SessionHandle> {
        let state = SessionState::new(our_role, initial_transmission);

        let (on_finish_tx, on_finish_rx) = oneshot::channel();
        self.send(ToActor::InitSession {
            peer,
            state,
            channels,
            init,
            on_finish: on_finish_tx,
        })
        .await?;

        let on_finish = on_finish_rx
            .map(|r| match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(Arc::new(err.into())),
                Err(_) => Err(Arc::new(Error::ActorFailed)),
            })
            .boxed();
        let on_finish = on_finish.shared();
        let handle = SessionHandle { on_finish };
        Ok(handle)
    }
}

impl Drop for ActorHandle {
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

#[derive(Debug)]
pub struct SessionHandle {
    on_finish: Shared<BoxFuture<Result<(), Arc<Error>>>>,
}

impl SessionHandle {
    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn on_finish(self) -> Result<(), Arc<Error>> {
        self.on_finish.await
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
        on_finish: oneshot::Sender<Result<(), Error>>,
    },
    GetEntries {
        namespace: NamespaceId,
        range: ThreeDRange,
        #[debug(skip)]
        reply: flume::Sender<Entry>,
    },
    IngestEntry {
        entry: AuthorisedEntry,
        reply: oneshot::Sender<anyhow::Result<bool>>,
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
    span: Span,
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
    notifier: Notifier,
    next_coro_id: u64,
}

type CoroFut = LocalBoxFuture<Result<(), Error>>;

#[derive(derive_more::Debug)]
struct CoroutineState {
    id: CoroId,
    session_id: SessionId,
    #[debug("Generator")]
    gen: Gen<Yield, (), CoroFut>,
    span: Span,
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
                init,
                on_finish: on_done,
            } => {
                let span = error_span!("session", peer=%peer.fmt_short());
                let session = Session {
                    state: Rc::new(RefCell::new(state)),
                    channels,
                    coroutines: Default::default(),
                    span,
                    on_done,
                };
                self.sessions.insert(peer, session);

                if let Err(error) = self.start_control_routine(peer, init) {
                    warn!(?error, peer=%peer.fmt_short(), "abort session: starting failed");
                    self.remove_session(&peer, Err(error));
                }
            }
            ToActor::GetEntries {
                namespace,
                range,
                reply,
            } => {
                let store = self.store.borrow();
                let entries = store.get_entries(namespace, &range).filter_map(|r| r.ok());
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

    fn start_control_routine(
        &mut self,
        session_id: SessionId,
        init: SessionInit,
    ) -> Result<(), Error> {
        let create_fn = |co, session: &mut Session| {
            let channels = session.channels.clone();
            let state = session.state.clone();
            ControlRoutine::new(co, channels, state)
                .run(init)
                .boxed_local()
        };
        let span_fn = || error_span!("control");
        self.start_coroutine(session_id, create_fn, span_fn)
    }

    fn start_reconcile_routine(
        &mut self,
        session_id: SessionId,
        start: Option<InitWithArea>,
    ) -> Result<(), Error> {
        let store_snapshot = Rc::new(self.store.borrow_mut().snapshot()?);
        let store_writer = Rc::clone(&self.store);
        let create_fn = |co, session: &mut Session| {
            let channels = session.channels.clone();
            let state = session.state.clone();
            ReconcileRoutine::new(co, channels, state, store_snapshot, store_writer)
                .run(start)
                .boxed_local()
        };
        let span_fn = || error_span!("reconcile");
        self.start_coroutine(session_id, create_fn, span_fn)
    }

    fn start_coroutine(
        &mut self,
        session_id: SessionId,
        create_fn: impl FnOnce(WakeableCoro, &mut Session) -> CoroFut,
        span_fn: impl FnOnce() -> Span,
    ) -> Result<(), Error> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(Error::SessionNotFound)?;

        let id = {
            let id = self.next_coro_id;
            self.next_coro_id += 1;
            id
        };

        session.coroutines.insert(id);
        let waker = self.notifier.create_waker(id);

        let _guard = session.span.enter();
        let span = span_fn();
        drop(_guard);

        let gen = Gen::new(move |co| {
            let co = WakeableCoro::new(co, waker);
            create_fn(co, session)
        });
        let state = CoroutineState {
            id,
            session_id,
            gen,
            span,
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
                        Yield::Pending => {
                            drop(_guard);
                            self.coroutines.insert(coro.id, coro);
                            break Ok(());
                        }
                        Yield::StartReconciliation(start) => {
                            self.start_reconcile_routine(coro.session_id, start)?;
                        }
                    }
                }
                GeneratorState::Complete(res) => {
                    let session = self
                        .sessions
                        .get_mut(&coro.session_id)
                        .ok_or(Error::SessionNotFound)?;
                    session.coroutines.remove(&coro.id);
                    let is_last = session.coroutines.is_empty();
                    debug!(?res, ?is_last, "routine completed");
                    if res.is_err() || is_last {
                        self.remove_session(&coro.session_id, res)
                    }
                    break Ok(());
                }
            }
        }
    }

    // fn on_coroutine_complete(&mut self, id: CoroId)
}

pub type InitWithArea = (AreaOfInterestHandle, AreaOfInterestHandle);

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Yield {
    Pending,
    StartReconciliation(Option<InitWithArea>),
}

#[derive(derive_more::Debug)]
pub struct WakeableCoro {
    pub waker: Waker,
    #[debug(skip)]
    pub co: Co<Yield, ()>,
}

impl WakeableCoro {
    pub fn new(co: Co<Yield, ()>, waker: Waker) -> Self {
        Self { co, waker }
    }
    pub async fn yield_(&self, value: Yield) {
        self.co.yield_(value).await
    }

    pub async fn yield_wake<T>(&self, fut: impl Future<Output = T>) -> T {
        tokio::pin!(fut);
        let mut ctx = Context::from_waker(&self.waker);
        loop {
            match Pin::new(&mut fut).poll(&mut ctx) {
                Poll::Ready(output) => return output,
                Poll::Pending => {
                    self.co.yield_(Yield::Pending).await;
                }
            }
        }
    }

    pub fn poll_once<T>(&self, fut: impl Future<Output = T>) -> Poll<T> {
        tokio::pin!(fut);
        let mut ctx = Context::from_waker(&self.waker);
        Pin::new(&mut fut).poll(&mut ctx)
    }
}

#[derive(Debug, Clone)]
pub struct CoroWaker {
    waker: Notifier,
    coro_id: CoroId,
}

impl CoroWaker {
    pub fn wake(&self) {
        self.waker.wake(self.coro_id)
    }
}

impl Wake for CoroWaker {
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
        Arc::new(CoroWaker {
            waker: self.clone(),
            coro_id,
        })
        .into()
    }
}
