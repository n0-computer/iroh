use std::{
    collections::{HashMap, HashSet, VecDeque},
    num::NonZeroU64,
};

use futures_lite::StreamExt;
use tracing::{debug, trace};

use crate::{
    proto::{
        grouping::{Area, ThreeDRange},
        keys::NamespaceId,
        sync::{
            AreaOfInterestHandle, Fingerprint, LengthyEntry, ReconciliationAnnounceEntries,
            ReconciliationMessage, ReconciliationSendEntry, ReconciliationSendFingerprint,
            ReconciliationSendPayload, ReconciliationTerminatePayload,
        },
    },
    session::{
        aoi_finder::{AoiIntersection, AoiIntersectionQueue},
        channels::{ChannelSenders, MessageReceiver},
        payload::{send_payload_chunked, CurrentPayload},
        static_tokens::StaticTokens,
        Error, Role, SessionId,
    },
    store::{
        traits::{EntryReader, EntryStorage, SplitAction, SplitOpts, Storage},
        Origin, Store,
    },
    util::stream::Cancelable,
};

#[derive(derive_more::Debug)]
pub struct Reconciler<S: Storage> {
    session_id: SessionId,
    our_role: Role,

    store: Store<S>,
    snapshot: <S::Entries as EntryStorage>::Snapshot,
    send: ChannelSenders,
    recv: Cancelable<MessageReceiver<ReconciliationMessage>>,

    static_tokens: StaticTokens,
    targets: Targets,
    current_payload: CurrentPayload,

    our_range_counter: u64,
    their_range_counter: u64,
    pending_announced_entries: Option<NonZeroU64>,
}

type TargetId = (AreaOfInterestHandle, AreaOfInterestHandle);

#[derive(Debug)]
struct Targets {
    intersection_queue: AoiIntersectionQueue,
    targets: HashMap<TargetId, State>,
    init_queue: VecDeque<TargetId>,
}

impl Targets {
    fn new(intersection_queue: AoiIntersectionQueue) -> Self {
        Self {
            intersection_queue,
            targets: Default::default(),
            init_queue: Default::default(),
        }
    }
    fn iter(&self) -> impl Iterator<Item = &State> {
        self.targets.values()
    }

    fn get(&self, target: &TargetId) -> Result<&State, Error> {
        self.targets
            .get(target)
            .ok_or(Error::MissingResource(target.1.into()))
    }
    fn get_mut(&mut self, target: &TargetId) -> Result<&mut State, Error> {
        self.targets
            .get_mut(target)
            .ok_or(Error::MissingResource(target.1.into()))
    }

    async fn init_next(&mut self) -> Option<TargetId> {
        if let Some(target_id) = self.init_queue.pop_front() {
            Some(target_id)
        } else {
            self.recv_next().await
        }
    }

    async fn get_eventually(&mut self, target_id: TargetId) -> Result<&mut State, Error> {
        if self.targets.contains_key(&target_id) {
            return Ok(self.targets.get_mut(&target_id).unwrap());
        }

        while let Some(next_target_id) = self.recv_next().await {
            self.init_queue.push_back(next_target_id);
            if next_target_id == target_id {
                return Ok(self.targets.get_mut(&target_id).unwrap());
            }
        }
        Err(Error::InvalidState("aoi finder closed"))
    }

    async fn recv_next(&mut self) -> Option<TargetId> {
        let intersection = self.intersection_queue.recv_async().await.ok()?;
        let (target_id, state) = State::new(intersection);
        self.targets.insert(target_id, state);
        Some(target_id)
    }
}

#[derive(Debug)]
struct State {
    namespace: NamespaceId,
    area: Area,
    our_uncovered_ranges: HashSet<u64>,
    started: bool,
}

impl State {
    pub fn new(intersection: AoiIntersection) -> (TargetId, Self) {
        let target_id = (intersection.our_handle, intersection.their_handle);
        let state = Self {
            namespace: intersection.namespace,
            area: intersection.intersection,
            our_uncovered_ranges: Default::default(),
            started: false,
        };
        (target_id, state)
    }

    pub fn is_complete(&self) -> bool {
        self.started && self.our_uncovered_ranges.is_empty()
    }

    pub fn mark_our_range_pending(&mut self, range_count: u64) {
        tracing::warn!("mark ours pending: {range_count}");
        self.started = true;
        self.our_uncovered_ranges.insert(range_count);
    }

    pub fn mark_our_range_covered(&mut self, range_count: u64) -> Result<(), Error> {
        tracing::warn!(?self, "mark ours covered: {range_count}");
        if !self.our_uncovered_ranges.remove(&range_count) {
            Err(Error::InvalidState(
                "attempted to mark an unknown range as covered",
            ))
        } else {
            Ok(())
        }
    }
}

impl<S: Storage> Reconciler<S> {
    pub fn new(
        store: Store<S>,
        recv: Cancelable<MessageReceiver<ReconciliationMessage>>,
        aoi_intersection_queue: AoiIntersectionQueue,
        static_tokens: StaticTokens,
        session_id: SessionId,
        send: ChannelSenders,
        our_role: Role,
    ) -> Result<Self, Error> {
        let snapshot = store.entries().snapshot()?;
        Ok(Self {
            session_id,
            send,
            our_role,
            store,
            recv,
            snapshot,
            current_payload: Default::default(),
            our_range_counter: 0,
            their_range_counter: 0,
            targets: Targets::new(aoi_intersection_queue),
            pending_announced_entries: Default::default(),
            static_tokens,
        })
    }

    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                message = self.recv.try_next() => {
                    match message? {
                        None => break,
                        Some(message) => self.on_message(message).await?,
                    }
                }
                Some(target_id) = self.targets.init_next() => {
                    if self.our_role.is_alfie() {
                        self.initiate(target_id).await?;
                    }
                }
            }
            if self.is_complete() {
                debug!("reconciliation complete");
                break;
            }
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        if self.current_payload.is_active() {
            return false;
        }
        if self.pending_announced_entries.is_some() {
            return false;
        }
        self.targets.iter().all(|t| t.is_complete())
    }

    async fn on_message(&mut self, message: ReconciliationMessage) -> Result<(), Error> {
        match message {
            ReconciliationMessage::SendFingerprint(message) => {
                self.received_send_fingerprint(message).await?
            }
            ReconciliationMessage::AnnounceEntries(message) => {
                let res = self.received_announce_entries(message).await;
                tracing::warn!("received_announce_entries DONE: {res:?}");
                res?;
            }
            ReconciliationMessage::SendEntry(message) => self.received_send_entry(message).await?,
            ReconciliationMessage::SendPayload(message) => {
                self.received_send_payload(message).await?
            }
            ReconciliationMessage::TerminatePayload(message) => {
                self.received_terminate_payload(message).await?
            }
        };
        Ok(())
    }

    async fn initiate(&mut self, target_id: TargetId) -> Result<(), Error> {
        let target = self.targets.get(&target_id)?;
        let range = target.area.into_range();
        let fingerprint = self.snapshot.fingerprint(target.namespace, &range)?;
        self.send_fingerprint(target_id, range, fingerprint, None)
            .await?;
        Ok(())
    }

    async fn received_send_fingerprint(
        &mut self,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        let range_count = self.next_range_count_theirs();

        let target_id = (message.receiver_handle, message.sender_handle);
        let target = self.targets.get_eventually(target_id).await?;
        let namespace = target.namespace;

        if let Some(range_count) = message.covers {
            target.mark_our_range_covered(range_count)?;
        }

        let our_fingerprint = self.snapshot.fingerprint(namespace, &message.range)?;

        // case 1: fingerprint match.
        if our_fingerprint == message.fingerprint {
            let reply = ReconciliationAnnounceEntries {
                range: message.range.clone(),
                count: 0,
                want_response: false,
                will_sort: false,
                sender_handle: message.receiver_handle,
                receiver_handle: message.sender_handle,
                covers: Some(range_count),
            };
            self.send(reply).await?;
        }
        // case 2: fingerprint is empty
        else if message.fingerprint.is_empty() {
            self.announce_and_send_entries(
                target_id,
                namespace,
                &message.range,
                true,
                Some(range_count),
                None,
            )
            .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            // self.split_range_and_send_parts(target_id, namespace, &message.range, range_count)
            //     .await?;
            // TODO: Expose
            let split_opts = SplitOpts::default();
            let snapshot = self.snapshot.clone();
            let mut iter = snapshot
                .split_range(namespace, &message.range, &split_opts)?
                .peekable();
            while let Some(res) = iter.next() {
                let (subrange, action) = res?;
                let is_last = iter.peek().is_none();
                let covers = is_last.then_some(range_count);
                match action {
                    SplitAction::SendEntries(count) => {
                        self.announce_and_send_entries(
                            target_id,
                            namespace,
                            &subrange,
                            true,
                            covers,
                            Some(count),
                        )
                        .await?;
                    }
                    SplitAction::SendFingerprint(fingerprint) => {
                        self.send_fingerprint(target_id, subrange, fingerprint, covers)
                            .await?;
                    }
                }
            }
        }

        Ok(())
    }
    async fn received_announce_entries(
        &mut self,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        trace!("received_announce_entries start");
        self.current_payload.assert_inactive()?;
        if self.pending_announced_entries.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }

        let target_id = (message.receiver_handle, message.sender_handle);
        let target = self.targets.get_eventually(target_id).await?;
        let namespace = target.namespace;

        if let Some(range_count) = message.covers {
            target.mark_our_range_covered(range_count)?;
        }

        if let Some(c) = NonZeroU64::new(message.count) {
            self.pending_announced_entries = Some(c);
        }

        if message.want_response {
            let range_count = self.next_range_count_theirs();
            self.announce_and_send_entries(
                target_id,
                namespace,
                &message.range,
                false,
                Some(range_count),
                None,
            )
            .await?;
        }
        trace!("received_announce_entries done");
        Ok(())
    }

    fn decrement_pending_announced_entries(&mut self) -> Result<(), Error> {
        self.pending_announced_entries = match self.pending_announced_entries.take() {
            None => return Err(Error::InvalidMessageInCurrentState),
            Some(c) => NonZeroU64::new(c.get().saturating_sub(1)),
        };
        Ok(())
    }

    async fn received_send_entry(&mut self, message: ReconciliationSendEntry) -> Result<(), Error> {
        self.current_payload.assert_inactive()?;
        self.decrement_pending_announced_entries()?;
        let authorised_entry = self
            .static_tokens
            .authorise_entry_eventually(
                message.entry.entry.clone(),
                message.static_token_handle,
                message.dynamic_token,
            )
            .await?;
        self.store
            .entries()
            .ingest(&authorised_entry, Origin::Remote(self.session_id))?;
        self.current_payload
            .set(message.entry.entry, Some(message.entry.available))?;
        Ok(())
    }

    async fn received_send_payload(
        &mut self,
        message: ReconciliationSendPayload,
    ) -> Result<(), Error> {
        self.current_payload
            .recv_chunk(self.store.payloads(), message.bytes)
            .await?;
        Ok(())
    }

    async fn received_terminate_payload(
        &mut self,
        _message: ReconciliationTerminatePayload,
    ) -> Result<(), Error> {
        self.current_payload.finalize().await?;
        Ok(())
    }

    async fn send_fingerprint(
        &mut self,
        target_id: TargetId,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        covers: Option<u64>,
    ) -> anyhow::Result<()> {
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: target_id.0,
            receiver_handle: target_id.1,
            covers,
        };
        self.send(msg).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn announce_and_send_entries(
        &mut self,
        target_id: TargetId,
        namespace: NamespaceId,
        range: &ThreeDRange,
        want_response: bool,
        covers: Option<u64>,
        our_entry_count: Option<u64>,
    ) -> Result<(), Error> {
        let our_entry_count = match our_entry_count {
            Some(count) => count,
            None => self.snapshot.count(namespace, range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: our_entry_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: target_id.0,
            receiver_handle: target_id.1,
            covers,
        };

        self.send(msg).await?;
        let snapshot = self.snapshot.clone();
        for authorised_entry in snapshot.get_entries_with_authorisation(namespace, range) {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let static_token_handle = self
                .static_tokens
                .bind_and_send_ours(static_token, &self.send)
                .await?;
            let digest = entry.payload_digest;
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send(msg).await?;

            // TODO: only send payload if configured to do so and/or under size limit.
            let send_payloads = true;
            let chunk_size = 1024 * 64;
            if send_payloads
                && send_payload_chunked(
                    digest,
                    self.store.payloads(),
                    &self.send,
                    chunk_size,
                    |bytes| ReconciliationSendPayload { bytes }.into(),
                )
                .await?
            {
                let msg = ReconciliationTerminatePayload;
                self.send(msg).await?;
            }
        }
        Ok(())
    }

    async fn send(&mut self, message: impl Into<ReconciliationMessage>) -> Result<(), Error> {
        let message: ReconciliationMessage = message.into();
        let want_response = match &message {
            ReconciliationMessage::SendFingerprint(msg) => {
                Some((msg.sender_handle, msg.receiver_handle))
            }
            ReconciliationMessage::AnnounceEntries(msg) if msg.want_response => {
                Some((msg.sender_handle, msg.receiver_handle))
            }
            _ => None,
        };
        if let Some(target_id) = want_response {
            let range_count = self.next_range_count_ours();
            let target = self.targets.get_mut(&target_id)?;
            target.mark_our_range_pending(range_count);
        }
        self.send.send(message).await?;
        Ok(())
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
