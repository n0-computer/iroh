use std::{
    collections::{hash_map, HashMap, HashSet, VecDeque},
    future::Future,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use futures_lite::{Stream, StreamExt};
use futures_util::{FutureExt, Sink};
use genawaiter::rc::Co;
use iroh_net::{
    dialer::Dialer, endpoint::Connection, util::SharedAbortingJoinHandle, Endpoint, NodeId,
};
use tokio::{
    io::Interest,
    sync::{mpsc, oneshot},
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap, StreamNotifyClose};
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{debug, error_span, Instrument};

use crate::{
    actor::{Actor, ActorHandle, SessionHandle},
    auth::{Auth, InterestMap},
    net::{setup, ALPN},
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
        sync::{ReadAuthorisation, ReadCapability},
    },
    session::{
        error::ChannelReceiverDropped,
        events::{EventKind, ReceiverDropped},
        Error, Interests, Role, SessionId, SessionInit, SessionMode, SessionUpdate,
    },
    store::traits::Storage,
    util::gen_stream::GenStream,
};

type NamespaceInterests = HashMap<NamespaceId, HashSet<AreaOfInterest>>;

const INTENT_UPDATE_CAP: usize = 16;
const INTENT_EVENT_CAP: usize = 64;

pub type IntentId = u64;

type Sender<T> = mpsc::Sender<T>;
type Receiver<T> = mpsc::Receiver<T>;

#[derive(Debug)]
pub struct IntentData {
    pub init: SessionInit,
    pub channels: IntentChannels,
}

impl IntentData {
    pub(super) async fn send_abort(self, error: Arc<Error>) {
        self.channels
            .event_tx
            .send(EventKind::Abort { error })
            .await
            .ok();
    }
}

#[derive(Debug)]
pub enum Input {
    EmitEvent(EventKind),
    SubmitIntent(IntentData),
}

#[derive(Debug)]
pub enum Output {
    SubmitInterests(InterestMap),
    AllIntentsDropped,
}

#[derive(derive_more::Debug)]
pub struct IntentDispatcher<S: Storage> {
    pending_intents: VecDeque<IntentData>,
    intents: HashMap<IntentId, IntentInfo>,
    auth: Auth<S>,
    #[debug("StreamMap")]
    intent_update_rx: StreamMap<IntentId, StreamNotifyClose<ReceiverStream<IntentUpdate>>>,
    next_intent_id: u64,
    complete_areas: NamespaceInterests,
}

impl<S: Storage> IntentDispatcher<S> {
    pub fn new(auth: Auth<S>, initial_intents: impl IntoIterator<Item = IntentData>) -> Self {
        Self {
            pending_intents: initial_intents.into_iter().collect(),
            intents: Default::default(),
            auth,
            intent_update_rx: Default::default(),
            next_intent_id: 0,
            complete_areas: Default::default(),
        }
    }

    pub async fn abort_all(&self, error: Arc<Error>) {
        let _ = futures_buffered::join_all(
            self.pending_intents
                .iter()
                .map(|intent| &intent.channels.event_tx)
                .chain(self.intents.values().map(|intent| &intent.event_tx))
                .map(|event_tx| {
                    let error = error.clone();
                    async move { event_tx.send(EventKind::Abort { error }).await }
                }),
        )
        .await;
    }

    /// Run the [`IntentDispatcher`].
    ///
    /// The returned stream is a generator, so it must be polled repeatedly to progress.
    pub fn run_gen(
        &mut self,
        inbox: impl Stream<Item = Input> + 'static,
    ) -> GenStream<Output, Error, impl Future<Output = Result<(), Error>> + '_> {
        GenStream::new(|co| self.run(co, inbox))
    }

    pub async fn run(
        &mut self,
        co: Co<Output>,
        inbox: impl Stream<Item = Input>,
    ) -> Result<(), Error> {
        tokio::pin!(inbox);

        while let Some(intent) = self.pending_intents.pop_front() {
            self.submit_intent(&co, intent).await?;
        }
        debug!("submitted initial intents, start loop");
        loop {
            tokio::select! {
                input = inbox.next() => {
                    tracing::debug!(?input, "tick: inbox");
                    let Some(input) = input else {
                        break;
                    };
                    match input {
                        Input::SubmitIntent(data) => self.submit_intent(&co, data).await?,
                        Input::EmitEvent(event) => self.emit_event(&co, event).await,
                    }
                }
                Some((intent_id, event)) = self.intent_update_rx.next(), if !self.intent_update_rx.is_empty() => {
                    tracing::debug!(?intent_id, ?event, "tick: intent_update");
                    match event {
                        Some(event) => {
                            // Received an intent update.
                            if let Err(err) = self.update_intent(&co, intent_id, event).await {
                                tracing::warn!(%intent_id, ?err, "failed to update intent");
                            }
                        },
                        None => {
                            // The intent update sender was dropped: Cancel the intent if the event
                            // receiver is dropped too.
                            self.intent_update_rx.remove(&intent_id);
                            let events_tx_closed = self.intents.get(&intent_id).map(|intent| intent.events_closed()).unwrap_or(true);
                            if events_tx_closed {
                                self.cancel_intent(&co, intent_id).await;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn submit_intent(&mut self, co: &Co<Output>, intent: IntentData) -> Result<(), Error> {
        let interests = self.auth.resolve_interests(intent.init.interests)?;
        let intent_id = {
            let intent_id = self.next_intent_id;
            self.next_intent_id += 1;
            intent_id
        };
        let IntentChannels {
            event_tx,
            update_rx,
        } = intent.channels;
        let mut info = IntentInfo {
            interests: flatten_interests(&interests),
            mode: intent.init.mode,
            event_tx,
        };
        // Send out reconciled events for already-complete areas.
        for (namespace, areas) in &self.complete_areas {
            for area in areas {
                info.on_reconciled(*namespace, area).await?;
            }
        }

        if !info.is_complete() {
            self.intents.insert(intent_id, info);
            self.intent_update_rx.insert(
                intent_id,
                StreamNotifyClose::new(ReceiverStream::new(update_rx)),
            );
            co.yield_(Output::SubmitInterests(interests)).await;
        }

        Ok(())
    }

    async fn emit_event(&mut self, co: &Co<Output>, event: EventKind) {
        if let EventKind::Reconciled { namespace, area } = &event {
            self.complete_areas
                .entry(*namespace)
                .or_default()
                .insert(area.clone());
        }
        let send_futs = self
            .intents
            .iter_mut()
            .map(|(id, info)| info.handle_event(&event).map(|res| (*id, res)));
        let send_res = futures_buffered::join_all(send_futs).await;
        for (id, res) in send_res.into_iter() {
            match res {
                Err(ReceiverDropped) => {
                    if !self.intent_update_rx.contains_key(&id) {
                        self.cancel_intent(co, id).await;
                    }
                }
                Ok(is_complete) => {
                    if is_complete {
                        self.cancel_intent(co, id).await;
                    }
                }
            }
        }
    }

    pub async fn update_intent(
        &mut self,
        co: &Co<Output>,
        intent_id: u64,
        update: IntentUpdate,
    ) -> Result<()> {
        debug!(?intent_id, ?update, "intent update");
        match update {
            IntentUpdate::AddInterests(interests) => {
                let add_interests = self.auth.resolve_interests(interests)?;
                let Some(intent_info) = self.intents.get_mut(&intent_id) else {
                    anyhow::bail!("invalid intent id");
                };
                intent_info.merge_interests(&add_interests);
                co.yield_(Output::SubmitInterests(add_interests)).await;
            }
            IntentUpdate::Close => {
                self.cancel_intent(co, intent_id).await;
            }
        }
        Ok(())
    }

    pub async fn cancel_intent(&mut self, co: &Co<Output>, intent_id: u64) {
        debug!(?intent_id, "cancel intent");
        self.intent_update_rx.remove(&intent_id);
        self.intents.remove(&intent_id);
        if self.intents.is_empty() {
            co.yield_(Output::AllIntentsDropped).await;
        }
    }
}

#[derive(Debug)]
pub enum IntentUpdate {
    AddInterests(Interests),
    Close,
}

#[derive(Debug)]
pub struct IntentHandle {
    event_rx: Receiver<EventKind>,
    update_tx: Sender<IntentUpdate>,
}

#[derive(Debug)]
pub struct IntentChannels {
    event_tx: Sender<EventKind>,
    update_rx: Receiver<IntentUpdate>,
}

impl IntentHandle {
    pub fn new(init: SessionInit) -> (Self, IntentData) {
        let (handle, channels) = Self::with_cap(INTENT_EVENT_CAP, INTENT_UPDATE_CAP);
        let data = IntentData { init, channels };
        (handle, data)
    }

    pub fn with_cap(event_cap: usize, update_cap: usize) -> (Self, IntentChannels) {
        let (event_tx, event_rx) = mpsc::channel(event_cap);
        let (update_tx, update_rx) = mpsc::channel(update_cap);
        (
            IntentHandle {
                event_rx,
                update_tx,
            },
            IntentChannels {
                event_tx,
                update_rx,
            },
        )
    }
    pub fn split(self) -> (PollSender<IntentUpdate>, ReceiverStream<EventKind>) {
        (
            PollSender::new(self.update_tx),
            ReceiverStream::new(self.event_rx),
        )
    }

    pub async fn next(&mut self) -> Option<EventKind> {
        self.event_rx.recv().await
    }

    pub async fn complete(&mut self) -> Result<(), Arc<Error>> {
        while let Some(event) = self.event_rx.recv().await {
            if let EventKind::Abort { error } = event {
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn add_interests(&self, interests: impl Into<Interests>) -> Result<()> {
        self.update_tx
            .send(IntentUpdate::AddInterests(interests.into()))
            .await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.update_tx.send(IntentUpdate::Close).await.ok();
    }
}

#[derive(Debug)]
pub(super) struct IntentInfo {
    interests: NamespaceInterests,
    mode: SessionMode,
    event_tx: Sender<EventKind>,
}

impl IntentInfo {
    fn merge_interests(&mut self, interests: &InterestMap) {
        for (auth, aois) in interests.iter() {
            self.interests
                .entry(auth.namespace())
                .or_default()
                .extend(aois.clone());
        }
    }

    fn is_complete(&self) -> bool {
        self.interests.is_empty() && !self.mode.is_live()
    }

    fn events_closed(&self) -> bool {
        self.event_tx.is_closed()
    }

    async fn on_reconciled(&mut self, namespace: NamespaceId, area: &AreaOfInterest) -> Result<()> {
        if self.complete_area_if_matches(&namespace, &area.area) {
            self.send(EventKind::Reconciled {
                namespace,
                area: area.clone(),
            })
            .await?;
            if self.interests.is_empty() {
                self.send(EventKind::ReconciledAll).await?
            }
        }
        Ok(())
    }

    fn matches_area(&self, namespace: &NamespaceId, area: &Area) -> bool {
        self.interests
            .get(namespace)
            .map(|interests| interests.iter().any(|x| x.area.has_intersection(area)))
            .unwrap_or(false)
    }

    fn complete_area_if_matches(&mut self, namespace: &NamespaceId, area: &Area) -> bool {
        let mut namespace_complete = false;
        let mut matches = false;
        if let Some(interests) = self.interests.get_mut(namespace) {
            if interests.iter().any(|x| x.area.has_intersection(area)) {
                matches = true;
                interests.retain(|x| !area.includes_area(&x.area));
                if interests.is_empty() {
                    namespace_complete = true;
                }
            }
        }
        if namespace_complete {
            self.interests.remove(namespace);
        }
        matches
    }

    pub(super) async fn handle_event(
        &mut self,
        event: &EventKind,
    ) -> Result<bool, ReceiverDropped> {
        let matches = match event {
            EventKind::CapabilityIntersection { namespace, .. } => {
                self.interests.contains_key(namespace)
            }
            EventKind::InterestIntersection { area, namespace } => {
                self.matches_area(namespace, &area.area)
            }
            EventKind::Reconciled { area, namespace } => {
                self.complete_area_if_matches(namespace, &area.area)
            }
            EventKind::Abort { .. } => true,
            EventKind::ReconciledAll => false,
        };
        let is_reconciled = matches!(event, EventKind::Reconciled { .. });
        if matches {
            self.send(event.clone()).await?;
            if is_reconciled && self.interests.is_empty() {
                self.send(EventKind::ReconciledAll).await?
            }
        }
        Ok(self.is_complete())
    }

    async fn send(&self, event: EventKind) -> Result<(), ReceiverDropped> {
        self.event_tx.send(event).await.map_err(|_| ReceiverDropped)
    }
}

fn flatten_interests(interests: &InterestMap) -> NamespaceInterests {
    let mut out = NamespaceInterests::new();
    for (cap, aois) in interests {
        out.entry(cap.namespace()).or_default().extend(aois.clone());
    }
    out
}
