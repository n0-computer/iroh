use std::{
    cell::RefCell,
    collections::{hash_map, HashMap, VecDeque},
    rc::Rc,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use futures::{
    future::{BoxFuture, LocalBoxFuture},
    FutureExt,
};
use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, info, instrument, warn};
// use iroh_net::NodeId;

use super::Store;
use crate::{
    proto::{
        grouping::{NamespacedRange, ThreeDRange},
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, HandleType, LogicalChannel, Message, ReconciliationSendEntry,
            ResourceHandle,
        },
        willow::{AuthorisedEntry, Entry},
    },
    session::{
        coroutine::{Channels, Coroutine, SessionState, Yield},
        Error,
    },
    util::channel::{self, ReadOutcome, Receiver},
};
use iroh_base::key::NodeId;

pub const CHANNEL_CAP: usize = 1024;

// #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
// pub struct SessionId(u64);
// pub type NodeId = SessionId;

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
    pub async fn notify(&self, peer: NodeId, notify: Yield) -> anyhow::Result<()> {
        let msg = ToActor::Resume { peer, notify };
        self.tx.send_async(msg).await?;
        Ok(())
    }
    pub fn notify_sync(&self, peer: NodeId, notify: Yield) -> anyhow::Result<()> {
        let msg = ToActor::Resume { peer, notify };
        self.tx.send(msg)?;
        Ok(())
    }
    pub fn notifier(&self, peer: NodeId, notify: Yield) -> Notifier {
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
    notify: Yield,
    peer: NodeId,
    // channel: LogicalChannel,
    // direction: Interest,
}

impl Notifier {
    // pub fn channel(&self) -> LogicalChannel {
    //     self.channel
    // }
    pub async fn notify(&self) -> anyhow::Result<()> {
        // let notify = YieldReason::ChannelPending(self.channel, self.direction);
        let msg = ToActor::Resume {
            peer: self.peer,
            notify: self.notify,
        };
        self.tx.send_async(msg).await?;
        Ok(())
    }
    pub fn notify_sync(&self) -> anyhow::Result<()> {
        // let notify = YieldReason::ChannelPending(self.channel, self.direction);
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
    pub fn notifier_channel(
        &self,
        channel: LogicalChannel,
        direction: Interest,
        peer: NodeId,
    ) -> Notifier {
        let notify = Yield::ChannelPending(channel, direction);
        Notifier {
            tx: self.tx.clone(),
            peer,
            notify,
        }
    }
    pub fn notifier_resource(&self, peer: NodeId, handle: ResourceHandle) -> Notifier {
        let notify = Yield::ResourceMissing(handle);
        Notifier {
            tx: self.tx.clone(),
            notify,
            peer,
        }
    }
    pub fn notifier(&self, peer: NodeId, notify: Yield) -> Notifier {
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
#[derive(derive_more::Debug)]
pub enum ToActor {
    InitSession {
        peer: NodeId,
        #[debug(skip)]
        state: SessionState,
        #[debug(skip)]
        channels: Arc<Channels>,
        start: Option<(AreaOfInterestHandle, AreaOfInterestHandle)>,
    },
    DropSession {
        peer: NodeId,
    },
    Resume {
        peer: NodeId,
        notify: Yield,
    },
    // ResumeSend {
    //     peer: NodeId,
    //     channel: LogicalChannel,
    // },
    // ResumeRecv {
    //     peer: NodeId,
    //     channel: LogicalChannel,
    // },
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
    state: SessionState,
    channels: Arc<Channels>,
    pending: PendingCoroutines,
}

#[derive(derive_more::Debug, Default)]
struct PendingCoroutines {
    #[debug(skip)]
    inner: HashMap<Yield, VecDeque<ReconcileGen>>, // #[debug("{}", "on_control.len()")]
                                                   // on_control: VecDeque<ReconcileGen>,
                                                   // #[debug("{}", "on_reconciliation.len()")]
                                                   // on_reconciliation: VecDeque<ReconcileGen>,
}

impl PendingCoroutines {
    fn get_mut(&mut self, pending_on: Yield) -> &mut VecDeque<ReconcileGen> {
        self.inner.entry(pending_on).or_default()
    }
    fn push_back(&mut self, pending_on: Yield, generator: ReconcileGen) {
        self.get_mut(pending_on).push_back(generator);
    }
    fn push_front(&mut self, pending_on: Yield, generator: ReconcileGen) {
        self.get_mut(pending_on).push_front(generator);
    }
    fn pop_front(&mut self, pending_on: Yield) -> Option<ReconcileGen> {
        self.get_mut(pending_on).pop_front()
    }
    fn len(&self, pending_on: &Yield) -> usize {
        self.inner.get(pending_on).map(|v| v.len()).unwrap_or(0)
    }

    fn is_empty(&self) -> bool {
        self.inner.values().any(|v| !v.is_empty())
    }
}

#[derive(Debug)]
pub struct StorageThread<S> {
    store: Rc<RefCell<S>>,
    sessions: HashMap<NodeId, StorageSession>,
    actor_rx: flume::Receiver<ToActor>,
    actor_tx: flume::Sender<ToActor>,
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
        debug!(?message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                start,
            } => {
                let session = StorageSession {
                    state,
                    channels,
                    pending: Default::default(),
                };
                self.sessions.insert(peer, session);
                self.start_coroutine(peer, |routine| routine.run(start).boxed_local())?;
            }
            ToActor::DropSession { peer } => {
                self.sessions.remove(&peer);
            }
            ToActor::Resume { peer, notify } => {
                self.resume_yielded(peer, notify)?;
            }
            // ToActor::ResumeRecv { peer, channel } => {
            //     self.resume_recv(peer, channel)?;
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
        }
        Ok(())
    }
    fn session_mut(&mut self, peer: &NodeId) -> Result<&mut StorageSession, Error> {
        self.sessions.get_mut(peer).ok_or(Error::SessionNotFound)
    }

    fn session(&mut self, peer: &NodeId) -> Result<&StorageSession, Error> {
        self.sessions.get(peer).ok_or(Error::SessionNotFound)
    }
    fn start_coroutine(
        &mut self,
        peer: NodeId,
        producer: impl FnOnce(Coroutine<S::Snapshot, S>) -> ReconcileFut,
    ) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
        let snapshot = Arc::new(self.store.borrow_mut().snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();
        let store_writer = Rc::clone(&self.store);
        let notifier = CoroutineNotifier {
            tx: self.actor_tx.clone(),
        };

        let generator = Gen::new(move |co| {
            let routine = Coroutine {
                peer,
                store_snapshot: snapshot,
                store_writer,
                notifier,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        self.resume_coroutine(peer, generator)
    }

    // #[instrument(skip_all, fields(session=%peer.fmt_short(),ch=%channel.fmt_short()))]
    // fn resume_recv(&mut self, peer: NodeId, channel: LogicalChannel) -> Result<(), Error> {
    //     let session = self.session(&peer)?;
    //     debug!("resume");
    //     let channel = session.channels.receiver(channel).clone();
    //     loop {
    //         match channel.read_message_or_set_notify()? {
    //             ReadOutcome::Closed => {
    //                 debug!("yield: Closed");
    //                 break;
    //             }
    //             ReadOutcome::ReadBufferEmpty => {
    //                 debug!("yield: ReadBufferEmpty");
    //                 break;
    //             }
    //             ReadOutcome::Item(message) => {
    //                 debug!(?message, "recv");
    //                 self.on_message(peer, message)?;
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    #[instrument(skip_all, fields(session=%peer.fmt_short()))]
    fn resume_yielded(&mut self, peer: NodeId, notify: Yield) -> Result<(), Error> {
        let session = self.session_mut(&peer)?;
        debug!(pending = session.pending.len(&notify), "resume");
        let generator = session.pending.pop_front(notify);
        match generator {
            Some(generator) => self.resume_coroutine(peer, generator),
            None => {
                debug!("nothing to resume");
                Ok(())
            }
        }
    }

    fn resume_coroutine(&mut self, peer: NodeId, mut generator: ReconcileGen) -> Result<(), Error> {
        debug!(session = peer.fmt_short(), "resume");
        let session = self.session_mut(&peer)?;
        match generator.resume() {
            GeneratorState::Yielded(reason) => {
                info!(?reason, "yield");
                // match &reason {
                //     YieldReason::ResourceMissing(handle) => {
                //         // match handle.ty
                //         // self.actor_rx.s
                //         let notifier = Notifier {
                //             peer,
                //             tx,
                //             notify: YieldReason::ResourceMissing(*handle),
                //         };
                //         session
                //             .state
                //             .lock()
                //             .unwrap()
                //             .their_resources
                //             .register_notify(*handle, notifier);
                //     }
                //     _ => {}
                // }
                session.pending.push_back(reason, generator);
                Ok(())
            }
            GeneratorState::Complete(res) => {
                info!(?res, "complete");
                res
            }
        }
    }
}

// #[derive(Debug, Clone, Hash, Eq, PartialEq)]
// enum PendingOn {
//     Channel {
//         channel: LogicalChannel,
//         interest: Interest,
//     },
//     Resource {
//         handle: ResourceHandle,
//     },
// }
// fn on_message(&mut self, peer: NodeId, message: Message) -> Result<(), Error> {
//     info!(msg=%message, "recv");
//     match message {
//         Message::ReconciliationSendFingerprint(message) => {
//             self.start_coroutine(peer, |routine| {
//                 routine.on_send_fingerprint(message).boxed_local()
//             })?;
//         }
//         Message::ReconciliationAnnounceEntries(message) => {
//             self.start_coroutine(peer, |routine| {
//                 routine.on_announce_entries(message).boxed_local()
//             })?;
//         }
//         Message::ReconciliationSendEntry(message) => {
//             let session = self.session_mut(&peer)?;
//             let authorised_entry = {
//                 let mut state = session.state.lock().unwrap();
//                 let authorised_entry = state.authorize_send_entry(message)?;
//                 state.trigger_notify_if_complete();
//                 authorised_entry
//             };
//             self.store.ingest_entry(&authorised_entry)?;
//             debug!("ingested entry");
//         }
//         _ => return Err(Error::UnsupportedMessage),
//     }
//     let session = self.session(&peer)?;
//     let state = session.state.lock().unwrap();
//     let started = state.reconciliation_started;
//     let pending_ranges = &state.pending_ranges;
//     let pending_entries = &state.pending_entries;
//     let is_complete = state.is_complete();
//     info!(
//         is_complete,
//         started,
//         ?pending_entries,
//         ?pending_ranges,
//         "handled"
//     );
//
//     Ok(())
// }
