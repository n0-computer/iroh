use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use futures_lite::StreamExt;
use genawaiter::rc::Co;
use iroh_blobs::store::Store as PayloadStore;
use tracing::debug;

use crate::{
    proto::{
        data_model::PayloadDigest,
        grouping::{AreaExt, AreaOfInterest, Range3d},
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, Fingerprint, IsHandle, LengthyEntry,
            ReconciliationAnnounceEntries, ReconciliationMessage, ReconciliationSendEntry,
            ReconciliationSendFingerprint, ReconciliationSendPayload,
            ReconciliationTerminatePayload,
        },
    },
    session::{
        aoi_finder::AoiIntersection,
        channels::{ChannelSenders, MessageReceiver},
        payload::{send_payload_chunked, CurrentPayload},
        static_tokens::StaticTokens,
        Error, Role, SessionId,
    },
    store::{
        traits::{EntryOrigin, EntryReader, EntryStorage, SplitAction, SplitOpts, Storage},
        Store,
    },
    util::{
        gen_stream::GenStream,
        stream::{Cancelable, CancelableReceiver},
    },
};

#[derive(Debug)]
pub enum Input {
    AoiIntersection(AoiIntersection),
}

#[derive(Debug)]
pub enum Output {
    ReconciledArea {
        namespace: NamespaceId,
        area: AreaOfInterest,
    },
    ReconciledAll,
}

#[derive(derive_more::Debug)]
pub struct Reconciler<S: Storage> {
    shared: Shared<S>,
    recv: Cancelable<MessageReceiver<ReconciliationMessage>>,
    targets: TargetMap,
    entry_state: EntryState,
}

type TargetId = (AreaOfInterestHandle, AreaOfInterestHandle);

impl<S: Storage> Reconciler<S> {
    /// Run the [`Reconciler`].
    ///
    /// The returned stream is a generator, so it must be polled repeatedly to progress.
    #[allow(clippy::too_many_arguments)]
    pub fn run_gen(
        inbox: CancelableReceiver<Input>,
        store: Store<S>,
        recv: Cancelable<MessageReceiver<ReconciliationMessage>>,
        static_tokens: StaticTokens,
        session_id: SessionId,
        send: ChannelSenders,
        our_role: Role,
        max_eager_payload_size: u64,
    ) -> impl futures_lite::Stream<Item = Result<Output, Error>> {
        GenStream::new(|co| {
            let shared = Shared {
                co,
                store,
                our_role,
                send,
                static_tokens,
                session_id,
                max_eager_payload_size,
            };
            Self {
                shared,
                recv,
                targets: TargetMap::new(inbox),
                entry_state: Default::default(),
            }
            .run()
        })
    }

    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Some(message) = self.recv.next() => {
                    tracing::trace!(?message, "tick: recv");
                    self.received_message(message?).await?;
                }
                Some(input) = self.targets.inbox.next() => {
                    tracing::trace!(?input, "tick: input");
                    match input {
                        Input::AoiIntersection(intersection) => {
                            self.targets.init_target(&self.shared, intersection).await?;
                        }
                    }
                }
                else => break,
            }
        }
        Ok(())
    }

    async fn received_message(&mut self, message: ReconciliationMessage) -> Result<(), Error> {
        match message {
            ReconciliationMessage::SendFingerprint(message) => {
                let target_id = message.handles();
                let target = self
                    .targets
                    .get_eventually(&self.shared, &target_id)
                    .await?;
                target
                    .received_send_fingerprint(&self.shared, message)
                    .await?;
                if target.is_complete() && self.entry_state.is_empty() {
                    self.complete_target(target_id).await?;
                }
            }
            ReconciliationMessage::AnnounceEntries(message) => {
                let target_id = message.handles();
                self.entry_state
                    .received_announce_entries(target_id, message.is_empty)?;
                let target = self
                    .targets
                    .get_eventually(&self.shared, &target_id)
                    .await?;
                target
                    .received_announce_entries(&self.shared, message)
                    .await?;
                if target.is_complete() && self.entry_state.is_empty() {
                    self.complete_target(target_id).await?;
                }
            }
            ReconciliationMessage::SendEntry(message) => {
                let authorised_entry = self
                    .shared
                    .static_tokens
                    .authorise_entry_eventually(
                        message.entry.entry.into(),
                        message.static_token_handle,
                        message.dynamic_token,
                    )
                    .await?;
                self.entry_state.received_send_entry(
                    *authorised_entry.entry().payload_digest(),
                    authorised_entry.entry().payload_length(),
                    message.entry.available,
                )?;
                self.shared.store.entries().ingest_entry(
                    &authorised_entry,
                    EntryOrigin::Remote(self.shared.session_id),
                )?;
            }
            ReconciliationMessage::SendPayload(message) => {
                self.entry_state
                    .received_send_payload(self.shared.store.payloads(), message.bytes)
                    .await?;
            }
            ReconciliationMessage::TerminatePayload(message) => {
                if let Some(completed_target) = self
                    .entry_state
                    .received_terminate_payload(message.is_final)
                    .await?
                {
                    let target = self
                        .targets
                        .map
                        .get(&completed_target)
                        .expect("target to exist");
                    if target.is_complete() {
                        self.complete_target(target.id()).await?;
                    }
                }
            }
        };
        Ok(())
    }

    pub async fn complete_target(&mut self, id: TargetId) -> Result<(), Error> {
        let target = self
            .targets
            .map
            .remove(&id)
            .ok_or(Error::InvalidMessageInCurrentState)?;
        debug!(
            our_handle = id.0.value(),
            their_handle = id.1.value(),
            "reconciled area"
        );
        self.out(Output::ReconciledArea {
            area: target.intersection.intersection.clone(),
            namespace: target.namespace(),
        })
        .await;
        if self.targets.map.is_empty() {
            debug!("reconciliation complete");
            self.out(Output::ReconciledAll).await;
        }
        Ok(())
    }

    async fn out(&self, output: Output) {
        self.shared.co.yield_(output).await;
    }
}

#[derive(Debug)]
struct TargetMap {
    map: HashMap<TargetId, Target>,
    inbox: CancelableReceiver<Input>,
}

impl TargetMap {
    pub fn new(inbox: CancelableReceiver<Input>) -> Self {
        Self {
            map: Default::default(),
            inbox,
        }
    }
    pub async fn get_eventually<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        requested_id: &TargetId,
    ) -> Result<&mut Target, Error> {
        if !self.map.contains_key(requested_id) {
            self.wait_for_target(shared, requested_id).await?;
        }
        return Ok(self.map.get_mut(requested_id).unwrap());
    }

    async fn wait_for_target<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        requested_id: &TargetId,
    ) -> Result<(), Error> {
        while let Some(input) = self.inbox.next().await {
            match input {
                Input::AoiIntersection(intersection) => {
                    let id = self.init_target(shared, intersection).await?;
                    if id == *requested_id {
                        return Ok(());
                    }
                }
            }
        }
        // TODO: Error?
        Ok(())
    }

    async fn init_target<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        intersection: AoiIntersection,
    ) -> Result<TargetId, Error> {
        let target = Target::init(shared, intersection).await?;
        let id = target.id();
        debug!(
            our_handle = id.0.value(),
            their_handle = id.1.value(),
            "init area"
        );
        self.map.insert(id, target);
        Ok(id)
    }
}

#[derive(Debug, Default)]
struct EntryState(Option<EntryStateInner>);

impl EntryState {
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn received_announce_entries(
        &mut self,
        target: TargetId,
        is_empty: bool,
    ) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        if !is_empty {
            self.0 = Some(EntryStateInner {
                target,
                current_payload: CurrentPayload::default(),
            });
        }
        Ok(())
    }

    pub fn received_send_entry(
        &mut self,
        payload_digest: PayloadDigest,
        total_payload_length: u64,
        available_payload_length: u64,
    ) -> Result<(), Error> {
        let state = self.get_mut()?;
        state.current_payload.ensure_none()?;
        state.current_payload.set(
            payload_digest,
            total_payload_length,
            Some(available_payload_length),
            None,
        )?;
        Ok(())
    }

    pub async fn received_send_payload<P: PayloadStore>(
        &mut self,
        store: &P,
        bytes: Bytes,
    ) -> Result<(), Error> {
        self.get_mut()?
            .current_payload
            .recv_chunk(store, bytes)
            .await?;
        Ok(())
    }

    pub async fn received_terminate_payload(
        &mut self,
        is_final: bool,
    ) -> Result<Option<TargetId>, Error> {
        let state = self.get_mut()?;
        state.current_payload.finalize().await?;
        if is_final {
            let target_id = state.target;
            self.0 = None;
            Ok(Some(target_id))
        } else {
            Ok(None)
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut EntryStateInner, Error> {
        match self.0.as_mut() {
            Some(s) => Ok(s),
            None => Err(Error::InvalidMessageInCurrentState),
        }
    }
}

#[derive(Debug)]
struct EntryStateInner {
    target: TargetId,
    current_payload: CurrentPayload,
}

#[derive(derive_more::Debug)]
struct Shared<S: Storage> {
    #[debug("Co")]
    co: Co<Output>,
    store: Store<S>,
    our_role: Role,
    send: ChannelSenders,
    static_tokens: StaticTokens,
    session_id: SessionId,
    max_eager_payload_size: u64,
}

#[derive(Debug)]
struct Target {
    intersection: AoiIntersection,
    our_uncovered_ranges: HashSet<u64>,
    started: bool,
    our_range_counter: u64,
    their_range_counter: u64,
}

impl Target {
    fn id(&self) -> TargetId {
        self.intersection.id()
    }
    async fn init<S: Storage>(
        shared: &Shared<S>,
        intersection: AoiIntersection,
    ) -> Result<Self, Error> {
        let mut this = Target {
            intersection,
            our_uncovered_ranges: Default::default(),
            started: false,
            our_range_counter: 0,
            their_range_counter: 0,
        };
        if shared.our_role == Role::Alfie {
            this.initiate(shared).await?;
        }
        Ok(this)
    }

    fn namespace(&self) -> NamespaceId {
        self.intersection.namespace
    }

    async fn initiate<S: Storage>(&mut self, shared: &Shared<S>) -> Result<(), Error> {
        let range = self.intersection.area().to_range();
        let fingerprint = shared
            .store
            .entries()
            .fingerprint(self.namespace(), &range)?;
        self.send_fingerprint(shared, range, fingerprint, None)
            .await?;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.started && self.our_uncovered_ranges.is_empty()
    }

    async fn received_send_fingerprint<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        self.started = true;
        if let Some(range_count) = message.covers {
            self.mark_our_range_covered(range_count)?;
        }
        let range_count = self.next_range_count_theirs();

        let our_fingerprint = shared
            .store
            .entries()
            .fingerprint(self.namespace(), &message.range)?;

        // case 1: fingerprint match.
        if our_fingerprint == message.fingerprint {
            self.announce_and_send_entries(shared, &message.range, false, Some(range_count), true)
                .await?;
        }
        // case 2: fingerprint is empty
        else if message.fingerprint.is_empty() {
            self.announce_and_send_entries(shared, &message.range, true, Some(range_count), false)
                .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            // TODO: Expose these options to a higher level.
            let split_opts = SplitOpts::default();
            let store = shared.store.entries().clone();
            let mut iter = store
                .split_range(self.namespace(), &message.range, &split_opts)?
                .peekable();
            while let Some(res) = iter.next() {
                let (subrange, action) = res?;
                let is_last = iter.peek().is_none();
                let covers = is_last.then_some(range_count);
                match action {
                    SplitAction::SendEntries(count) => {
                        self.announce_and_send_entries(shared, &subrange, true, covers, count == 0)
                            .await?;
                    }
                    SplitAction::SendFingerprint(fingerprint) => {
                        self.send_fingerprint(shared, subrange, fingerprint, covers)
                            .await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn received_announce_entries<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        self.started = true;
        if let Some(range_count) = message.covers {
            self.mark_our_range_covered(range_count)?;
        }

        if message.want_response {
            let range_count = self.next_range_count_theirs();
            self.announce_and_send_entries(shared, &message.range, false, Some(range_count), false)
                .await?;
        }
        Ok(())
    }

    async fn send_fingerprint<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        range: Range3d,
        fingerprint: Fingerprint,
        covers: Option<u64>,
    ) -> anyhow::Result<()> {
        self.mark_our_next_range_pending();
        let msg = ReconciliationSendFingerprint {
            range: range.into(),
            fingerprint,
            sender_handle: self.intersection.our_handle,
            receiver_handle: self.intersection.their_handle,
            covers,
        };
        shared.send.send(msg).await?;
        Ok(())
    }

    /// Send a [`ReconciliationAnnounceEntries`] message for a range, and all entries in the range unless
    /// `is_empty` is set to true.
    async fn announce_and_send_entries<S: Storage>(
        &mut self,
        shared: &Shared<S>,
        range: &Range3d,
        want_response: bool,
        covers: Option<u64>,
        is_empty: bool,
    ) -> Result<(), Error> {
        if want_response {
            self.mark_our_next_range_pending();
        }

        // If we know for sure that our range is empty, we can skip creating the entry iterator alltogether.
        let mut iter = if is_empty {
            None
        } else {
            Some(
                shared
                    .store
                    .entries()
                    .get_authorised_entries(self.namespace(), range)
                    .peekable(),
            )
        };
        // Find out if we will send any entries at all.
        let is_empty = iter
            .as_mut()
            .map(|iter| iter.peek().is_none())
            .unwrap_or(true);

        // Send the announce message
        let msg = ReconciliationAnnounceEntries {
            range: range.clone().into(),
            is_empty,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: self.intersection.our_handle,
            receiver_handle: self.intersection.their_handle,
            covers,
        };
        shared.send.send(msg).await?;

        // If our range is empty, we're done!
        let Some(mut iter) = iter else {
            return Ok(());
        };

        // Otherwise send all the entries in our iterator, and payloads if applicable.
        while let Some(authorised_entry) = iter.next() {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();

            let static_token = token.capability.into();
            let dynamic_token = token.signature;
            // TODO: partial payloads
            let payload_len = entry.payload_length();
            let available = payload_len;
            let static_token_handle = shared
                .static_tokens
                .bind_and_send_ours(static_token, &shared.send)
                .await?;
            let digest = *entry.payload_digest();
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            shared.send.send(msg).await?;

            // TODO: only send payload if configured to do so and/or under size limit.
            if payload_len <= shared.max_eager_payload_size {
                send_payload_chunked(digest, shared.store.payloads(), &shared.send, 0, |bytes| {
                    ReconciliationSendPayload { bytes }.into()
                })
                .await?;
            }
            let is_final = iter.peek().is_none();
            shared
                .send
                .send(ReconciliationTerminatePayload { is_final })
                .await?;
        }
        Ok(())
    }

    fn mark_our_next_range_pending(&mut self) {
        let range_count = self.next_range_count_ours();
        self.our_uncovered_ranges.insert(range_count);
    }

    fn mark_our_range_covered(&mut self, range_count: u64) -> Result<(), Error> {
        if !self.our_uncovered_ranges.remove(&range_count) {
            Err(Error::InvalidState(
                "attempted to mark an unknown range as covered",
            ))
        } else {
            Ok(())
        }
    }

    fn next_range_count_ours(&mut self) -> u64 {
        let range_count = self.our_range_counter;
        self.our_range_counter += 1;
        range_count
    }

    fn next_range_count_theirs(&mut self) -> u64 {
        let range_count = self.their_range_counter;
        self.their_range_counter += 1;
        range_count
    }
}
