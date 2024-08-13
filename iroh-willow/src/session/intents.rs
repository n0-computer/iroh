//! Intents are handles onto a Willow synchronisation session.
//!
//! They are created with [`crate::Engine::sync_with_peer`].
//!
//! An intent receives events from the session, and can submit new interests to be synchronized.
//!
//! Once all intents for a peer are complete, the session is closed.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use futures_util::FutureExt;
use genawaiter::rc::Co;

use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamMap, StreamNotifyClose};
use tokio_util::sync::PollSender;
use tracing::{debug, trace, warn};

use crate::{
    interest::{InterestMap, Interests},
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
    },
    session::{error::ChannelReceiverDropped, Error, SessionInit, SessionMode},
    store::{auth::Auth, traits::Storage},
    util::gen_stream::GenStream,
};

type NamespaceInterests = HashMap<NamespaceId, HashSet<AreaOfInterest>>;

const INTENT_UPDATE_CAP: usize = 16;
const INTENT_EVENT_CAP: usize = 64;

pub type IntentId = u64;

type Sender<T> = mpsc::Sender<T>;
type Receiver<T> = mpsc::Receiver<T>;

/// Events emitted from a session for an synchronisation intent.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EventKind {
    /// We found an intersection between our and the peer's capabilities.
    CapabilityIntersection { namespace: NamespaceId, area: Area },
    /// We found an intersection between our and the peer's interests and will start to synchronize
    /// the area.
    InterestIntersection {
        namespace: NamespaceId,
        area: AreaOfInterest,
    },
    /// We reconciled an area.
    Reconciled {
        namespace: NamespaceId,
        area: AreaOfInterest,
    },
    /// We reconciled all interests submitted in this intent.
    ReconciledAll,
    /// The session was closed with an error.
    Abort { error: Arc<Error> },
}

impl EventKind {
    /// Returns the namespace if the event is related to a namespace.
    pub fn namespace(&self) -> Option<NamespaceId> {
        match self {
            EventKind::CapabilityIntersection { namespace, .. } => Some(*namespace),
            EventKind::InterestIntersection { namespace, .. } => Some(*namespace),
            EventKind::Reconciled { namespace, .. } => Some(*namespace),
            _ => None,
        }
    }
}

/// Updates that may be submitted from an intent into the synchronisation session.
#[derive(Debug)]
pub enum IntentUpdate {
    /// Submit new interests into the session.
    AddInterests(Interests),
    /// Close the intent.
    ///
    /// It is not required to send this, but may reduce the time an intent is lingering while no
    /// subscriber is live anymore.
    Close,
}

/// A synchronisation intent.
///
/// An intent contains a list of interests to sync, and optionally sends events from the session to
/// a [`IntentHandle`]. The [`IntentHandle`] can also submit updates to the list of interests.
///
/// Alternatively, an intent can be *detached*, which means that no events or updates are sent.
#[derive(Debug)]
pub struct Intent {
    pub(super) init: SessionInit,
    channels: Option<IntentChannels>,
}

impl Intent {
    /// Create a new intent with associated handle.
    ///
    /// The returned [`Intent`] must be passed into a session.
    /// The returned [`IntentHandle`] can issue updates to the intent, and receives events for the
    /// intent. The [`IntentHandle`] must be received from in a loop, otherwise the session will
    /// block.
    pub fn new(init: SessionInit) -> (Self, IntentHandle) {
        Self::new_with_cap(init, INTENT_EVENT_CAP, INTENT_UPDATE_CAP)
    }

    /// Create a new detached intent.
    ///
    /// A detached intent submits interests into a session, but does not allow to issue updates or
    /// receive events.
    pub fn new_detached(init: SessionInit) -> Self {
        Self {
            init,
            channels: None,
        }
    }

    fn new_with_cap(
        init: SessionInit,
        event_cap: usize,
        update_cap: usize,
    ) -> (Self, IntentHandle) {
        let (event_tx, event_rx) = mpsc::channel(event_cap);
        let (update_tx, update_rx) = mpsc::channel(update_cap);
        let handle = IntentHandle {
            event_rx,
            update_tx,
        };
        let channels = IntentChannels {
            event_tx,
            update_rx,
        };
        let intent = Intent {
            init,
            channels: Some(channels),
        };
        (intent, handle)
    }

    /// Abort the intent.
    ///
    /// Will send a final [`EventKind::Abort`] if the intent is not detached.
    pub async fn send_abort(self, error: Arc<Error>) {
        if let Some(channels) = self.channels {
            channels
                .event_tx
                .send(EventKind::Abort { error })
                .await
                .ok();
        }
    }
}

/// Outcome of driving an intent to completion.
#[derive(Debug, Eq, PartialEq)]
pub enum Completion {
    /// All interests were reconciled.
    Complete,
    /// Some interests were reconciled.
    Partial,
    /// No interests were reconciled.
    Nothing,
}

/// Handle to a [`Intent`].
///
/// The [`IntentHandle`] is a [`Stream`] of [`EventKind`]. It *must* be progressed in a loop,
/// otherwise the session will be blocked from progressing.
///
/// The [`IntentHandle`] can also submit new interests into the session.
#[derive(Debug)]
pub struct IntentHandle {
    event_rx: Receiver<EventKind>,
    update_tx: Sender<IntentUpdate>,
}

impl IntentHandle {
    /// Split the [`IntentHandle`] into a update sink and event stream.
    pub fn split(self) -> (PollSender<IntentUpdate>, ReceiverStream<EventKind>) {
        (
            PollSender::new(self.update_tx),
            ReceiverStream::new(self.event_rx),
        )
    }

    /// Wait for the intent to be completed.
    ///
    /// This future completes either if the session terminated, or if all interests of the intent
    /// are reconciled and the intent is not in live data mode.
    ///
    /// Note that successful completion of this future does not guarantee that all interests were
    /// fulfilled. If you need to know that, use the [`IntentHandle`] as a stream and wait for the
    /// [`EventKind::ReconciledAll`] event.
    pub async fn complete(&mut self) -> Result<Completion, Arc<Error>> {
        let mut complete = false;
        let mut partial = false;
        while let Some(event) = self.event_rx.recv().await {
            match event {
                EventKind::ReconciledAll => complete = true,
                // TODO: track partial reconciliations
                EventKind::Reconciled { .. } => partial = true,
                EventKind::Abort { error } => return Err(error),
                _ => {}
            }
        }
        let completion = if complete {
            Completion::Complete
        } else if partial {
            Completion::Partial
        } else {
            Completion::Nothing
        };

        Ok(completion)
    }

    /// Submit new synchronisation interests into the session.
    ///
    /// The [`IntentHandle`] will then receive events for these interests in addition to already
    /// submitted interests.
    pub async fn add_interests(&self, interests: impl Into<Interests>) -> Result<()> {
        self.update_tx
            .send(IntentUpdate::AddInterests(interests.into()))
            .await?;
        Ok(())
    }

    /// Close the intent.
    pub async fn close(&self) {
        self.update_tx.send(IntentUpdate::Close).await.ok();
    }
}

impl Stream for IntentHandle {
    type Item = EventKind;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.event_rx).poll_recv(cx)
    }
}

#[derive(derive_more::Debug)]
#[debug("IntentChannels")]
struct IntentChannels {
    event_tx: Sender<EventKind>,
    update_rx: Receiver<IntentUpdate>,
}

#[derive(Debug)]
pub(super) enum Input {
    EmitEvent(EventKind),
    SubmitIntent(Intent),
}

#[derive(Debug)]
pub(super) enum Output {
    SubmitInterests(InterestMap),
    AllIntentsDropped,
}

#[derive(derive_more::Debug)]
pub(super) struct IntentDispatcher<S: Storage> {
    pending_intents: VecDeque<Intent>,
    intents: HashMap<IntentId, IntentInfo>,
    auth: Auth<S>,
    #[debug("StreamMap")]
    intent_update_rx: StreamMap<IntentId, StreamNotifyClose<ReceiverStream<IntentUpdate>>>,
    next_intent_id: u64,
    complete_areas: NamespaceInterests,
}

impl<S: Storage> IntentDispatcher<S> {
    pub(super) fn new(auth: Auth<S>, initial_intents: impl IntoIterator<Item = Intent>) -> Self {
        Self {
            pending_intents: initial_intents.into_iter().collect(),
            intents: Default::default(),
            auth,
            intent_update_rx: Default::default(),
            next_intent_id: 0,
            complete_areas: Default::default(),
        }
    }

    /// Aborts all registered intents.
    pub(super) async fn abort_all(&self, error: Arc<Error>) {
        let _ = futures_buffered::join_all(
            Iterator::chain(
                self.pending_intents
                    .iter()
                    .flat_map(|intent| intent.channels.as_ref())
                    .map(|ch| &ch.event_tx),
                self.intents
                    .values()
                    .flat_map(|intent| intent.event_tx.as_ref()),
            )
            .map(|event_tx| {
                let error = error.clone();
                async move { event_tx.send(EventKind::Abort { error }).await }
            }),
        )
        .await;
    }

    /// Takes self and returns all pending intents.
    // TODO: What if one of the two channels closed?
    // Should not do Option<IntentChannels> but an option for each direction instead likely on Intent.
    pub(super) fn drain_all(mut self) -> Vec<Intent> {
        let mut intents: Vec<_> = self.pending_intents.into_iter().collect();
        for (id, info) in self.intents.drain() {
            let event_tx = info.event_tx;
            let update_rx = self.intent_update_rx.remove(&id);
            let update_rx = update_rx
                .and_then(|stream| stream.into_inner())
                .map(|stream| stream.into_inner());
            let channels = match (event_tx, update_rx) {
                (Some(event_tx), Some(update_rx)) => Some(IntentChannels {
                    event_tx,
                    update_rx,
                }),
                _ => None,
            };
            if let Some(channels) = channels {
                let intent = Intent {
                    init: info.original_init,
                    channels: Some(channels),
                };
                intents.push(intent);
            }
        }
        intents
    }

    /// Run the [`IntentDispatcher`].
    ///
    /// The returned stream is a generator, so it must be polled repeatedly to progress.
    pub(super) fn run_gen(
        &mut self,
        inbox: impl Stream<Item = Input> + 'static,
    ) -> GenStream<Output, Error, impl Future<Output = Result<(), Error>> + '_> {
        GenStream::new(|co| self.run(co, inbox))
    }

    async fn run(&mut self, co: Co<Output>, inbox: impl Stream<Item = Input>) -> Result<(), Error> {
        tokio::pin!(inbox);

        while let Some(intent) = self.pending_intents.pop_front() {
            self.submit_intent(&co, intent).await?;
        }
        trace!("submitted initial intents, start loop");
        loop {
            tokio::select! {
                input = inbox.next() => {
                    trace!(?input, "tick: inbox");
                    let Some(input) = input else {
                        break;
                    };
                    match input {
                        Input::SubmitIntent(data) => self.submit_intent(&co, data).await?,
                        Input::EmitEvent(event) => self.emit_event(&co, event).await,
                    }
                }
                Some((intent_id, event)) = self.intent_update_rx.next(), if !self.intent_update_rx.is_empty() => {
                    trace!(?intent_id, ?event, "tick: intent_update");
                    match event {
                        Some(event) => {
                            // Received an intent update.
                            if let Err(err) = self.update_intent(&co, intent_id, event).await {
                                warn!(%intent_id, ?err, "failed to update intent");
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

    async fn submit_intent(&mut self, co: &Co<Output>, intent: Intent) -> Result<(), Error> {
        let interests = self.auth.resolve_interests(intent.init.interests.clone())?;
        let intent_id = {
            let intent_id = self.next_intent_id;
            self.next_intent_id += 1;
            intent_id
        };
        let (event_tx, update_rx) = match intent.channels {
            None => (None, None),
            Some(IntentChannels {
                event_tx,
                update_rx,
            }) => (Some(event_tx), Some(update_rx)),
        };

        let mut info = IntentInfo {
            interests: flatten_interests(&interests),
            mode: intent.init.mode,
            event_tx,
            original_init: intent.init,
        };
        // Send out reconciled events for already-complete areas.
        for (namespace, areas) in &self.complete_areas {
            for area in areas {
                info.on_reconciled(*namespace, area).await?;
            }
        }

        if !info.is_complete() {
            self.intents.insert(intent_id, info);
            if let Some(update_rx) = update_rx {
                self.intent_update_rx.insert(
                    intent_id,
                    StreamNotifyClose::new(ReceiverStream::new(update_rx)),
                );
            }
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
                Err(ChannelReceiverDropped) => {
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

    async fn update_intent(
        &mut self,
        co: &Co<Output>,
        intent_id: u64,
        update: IntentUpdate,
    ) -> Result<()> {
        trace!(?intent_id, ?update, "intent update");
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

    async fn cancel_intent(&mut self, co: &Co<Output>, intent_id: u64) {
        trace!(?intent_id, "cancel intent");
        self.intent_update_rx.remove(&intent_id);
        self.intents.remove(&intent_id);
        if self.intents.is_empty() {
            co.yield_(Output::AllIntentsDropped).await;
        }
    }
}

#[derive(Debug)]
pub(super) struct IntentInfo {
    original_init: SessionInit,
    interests: NamespaceInterests,
    mode: SessionMode,
    event_tx: Option<Sender<EventKind>>,
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
        match &self.event_tx {
            None => false,
            Some(event_tx) => event_tx.is_closed(),
        }
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
            .map(|interests| {
                interests
                    .iter()
                    .any(|x| x.area.intersection(area).is_some())
            })
            .unwrap_or(false)
    }

    fn complete_area_if_matches(&mut self, namespace: &NamespaceId, area: &Area) -> bool {
        let mut namespace_complete = false;
        let mut matches = false;
        if let Some(interests) = self.interests.get_mut(namespace) {
            if interests
                .iter()
                .any(|x| x.area.intersection(area).is_some())
            {
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
    ) -> Result<bool, ChannelReceiverDropped> {
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

    async fn send(&self, event: EventKind) -> Result<(), ChannelReceiverDropped> {
        if let Some(event_tx) = &self.event_tx {
            event_tx
                .send(event)
                .await
                .map_err(|_| ChannelReceiverDropped)
        } else {
            Ok(())
        }
    }
}

fn flatten_interests(interests: &InterestMap) -> NamespaceInterests {
    let mut out = NamespaceInterests::new();
    for (cap, aois) in interests {
        out.entry(cap.namespace()).or_default().extend(aois.clone());
    }
    out
}
