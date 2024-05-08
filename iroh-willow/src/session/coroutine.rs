use std::{
    cell::{RefCell, RefMut},
    collections::HashSet,
    rc::Rc,
    sync::{Arc, Mutex},
};

use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use iroh_net::NodeId;
use smallvec::SmallVec;
use tokio::sync::Notify;
use tracing::{debug, info, trace, warn};

use crate::{
    proto::{
        challenge::ChallengeState,
        grouping::ThreeDRange,
        keys::{NamespaceId, NamespacePublicKey},
        meadowcap::McCapability,
        wgps::{
            AccessChallenge, AreaOfInterestHandle, CapabilityHandle, ChallengeHash,
            CommitmentReveal, Fingerprint, LengthyEntry, LogicalChannel, Message, ReadCapability,
            ReconciliationAnnounceEntries, ReconciliationSendEntry, ReconciliationSendFingerprint,
            ResourceHandle, SetupBindAreaOfInterest, SetupBindReadCapability, SetupBindStaticToken,
            StaticToken, StaticTokenHandle,
        },
        willow::{AuthorisationToken, AuthorisedEntry},
    },
    store::{
        actor::{CoroutineNotifier, Interest},
        ReadonlyStore, SplitAction, Store, SyncConfig,
    },
    util::channel::{ReadOutcome, Receiver, Sender, WriteOutcome},
};

use super::{resource::ScopedResources, Error, Role, Scope, SessionInit};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Yield {
    Pending(Readyness),
    StartReconciliation(Option<(AreaOfInterestHandle, AreaOfInterestHandle)>),
}
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Readyness {
    Channel(LogicalChannel, Interest),
    Resource(ResourceHandle),
}

#[derive(derive_more::Debug)]
pub struct Coroutine<S: ReadonlyStore, W: Store> {
    pub peer: NodeId,
    pub store_snapshot: Rc<S>,
    pub store_writer: Rc<RefCell<W>>,
    pub channels: Channels,
    pub state: SessionState,
    pub notifier: CoroutineNotifier,
    #[debug(skip)]
    pub co: Co<Yield, ()>,
}

pub type SessionState = Rc<RefCell<SessionStateInner>>;

#[derive(Debug, Clone)]
pub struct Channels {
    pub control_send: Sender<Message>,
    pub control_recv: Receiver<Message>,
    pub reconciliation_send: Sender<Message>,
    pub reconciliation_recv: Receiver<Message>,
}

impl Channels {
    pub fn close_send(&self) {
        self.control_send.close();
        self.reconciliation_send.close();
    }
    pub fn sender(&self, channel: LogicalChannel) -> &Sender<Message> {
        match channel {
            LogicalChannel::Control => &self.control_send,
            LogicalChannel::Reconciliation => &self.reconciliation_send,
        }
    }
    pub fn receiver(&self, channel: LogicalChannel) -> &Receiver<Message> {
        match channel {
            LogicalChannel::Control => &self.control_recv,
            LogicalChannel::Reconciliation => &self.reconciliation_recv,
        }
    }
}

#[derive(Debug)]
pub struct SessionStateInner {
    our_role: Role,
    peer: NodeId,
    our_resources: ScopedResources,
    their_resources: ScopedResources,
    reconciliation_started: bool,
    pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pending_entries: Option<u64>,
    notify_complete: Arc<Notify>,
    challenge: ChallengeState,
    our_current_aoi: Option<AreaOfInterestHandle>,
}

impl SessionStateInner {
    pub fn new(
        our_role: Role,
        peer: NodeId,
        our_nonce: AccessChallenge,
        received_commitment: ChallengeHash,
        _their_maximum_payload_size: usize,
    ) -> Self {
        let challenge_state = ChallengeState::Committed {
            our_nonce,
            received_commitment,
        };
        Self {
            our_role,
            peer,
            challenge: challenge_state,
            reconciliation_started: false,
            our_resources: Default::default(),
            their_resources: Default::default(),
            pending_ranges: Default::default(),
            pending_entries: Default::default(),
            notify_complete: Default::default(),
            our_current_aoi: Default::default(),
        }
    }
    fn resources(&self, scope: Scope) -> &ScopedResources {
        match scope {
            Scope::Ours => &self.our_resources,
            Scope::Theirs => &self.their_resources,
        }
    }
    pub fn is_complete(&self) -> bool {
        let is_complete = self.reconciliation_started
            && self.pending_ranges.is_empty()
            && self.pending_entries.is_none();
        trace!(
            started = self.reconciliation_started,
            pending_ranges = self.pending_ranges.len(),
            pending_entries = ?self.pending_entries,
            "is_complete {is_complete}"
        );
        is_complete
    }

    pub fn trigger_notify_if_complete(&mut self) -> bool {
        if self.is_complete() {
            self.notify_complete.notify_waiters();
            true
        } else {
            false
        }
    }

    pub fn notify_complete(&self) -> Arc<Notify> {
        Arc::clone(&self.notify_complete)
    }

    pub fn commitment_reveal(&mut self) -> Result<Message, Error> {
        match self.challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce }.into())
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
        // let msg = CommitmentReveal { nonce: our_nonce };
    }

    pub fn on_commitment_reveal(
        &mut self,
        msg: CommitmentReveal,
        init: &SessionInit,
    ) -> Result<[Message; 2], Error> {
        self.challenge.reveal(self.our_role, msg.nonce)?;
        self.setup(init)
    }

    pub fn on_setup_bind_read_capability(
        &mut self,
        msg: SetupBindReadCapability,
    ) -> Result<(), Error> {
        // TODO: verify intersection handle
        msg.capability.validate()?;
        self.challenge
            .verify(msg.capability.receiver(), &msg.signature)?;
        self.their_resources.capabilities.bind(msg.capability);
        Ok(())
    }

    pub fn on_setup_bind_static_token(&mut self, msg: SetupBindStaticToken) {
        self.their_resources.static_tokens.bind(msg.static_token);
    }

    fn setup(&mut self, init: &SessionInit) -> Result<[Message; 2], Error> {
        let area_of_interest = init.area_of_interest.clone();
        let capability = init.capability.clone();

        debug!(?init, "init");
        if *capability.receiver() != init.user_secret_key.public_key() {
            return Err(Error::WrongSecretKeyForCapability);
        }

        // TODO: implement private area intersection
        let intersection_handle = 0.into();
        let signature = self.challenge.sign(&init.user_secret_key)?;

        let our_capability_handle = self.our_resources.capabilities.bind(capability.clone());
        let msg1 = SetupBindReadCapability {
            capability,
            handle: intersection_handle,
            signature,
        };

        let msg2 = SetupBindAreaOfInterest {
            area_of_interest,
            authorisation: our_capability_handle,
        };
        let our_aoi_handle = self.our_resources.areas_of_interest.bind(msg2.clone());
        self.our_current_aoi = Some(our_aoi_handle);
        Ok([msg1.into(), msg2.into()])
    }

    pub fn on_setup_bind_area_of_interest(
        &mut self,
        msg: SetupBindAreaOfInterest,
    ) -> Result<(NodeId, Option<(AreaOfInterestHandle, AreaOfInterestHandle)>), Error> {
        let capability = self
            .resources(Scope::Theirs)
            .capabilities
            .get(&msg.authorisation)?;
        capability.try_granted_area(&msg.area_of_interest.area)?;
        let their_handle = self.their_resources.areas_of_interest.bind(msg);
        let start = if self.our_role == Role::Alfie {
            let our_handle = self
                .our_current_aoi
                .clone()
                .ok_or(Error::InvalidMessageInCurrentState)?;
            Some((our_handle, their_handle))
        } else {
            None
        };
        Ok((self.peer, start))
    }

    pub fn on_send_entry(&mut self) -> Result<(), Error> {
        let remaining = self
            .pending_entries
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        *remaining -= 1;
        if *remaining == 0 {
            self.pending_entries = None;
        }
        Ok(())
    }

    fn clear_pending_range_if_some(
        &mut self,
        our_handle: AreaOfInterestHandle,
        pending_range: Option<ThreeDRange>,
    ) -> Result<(), Error> {
        if let Some(range) = pending_range {
            // TODO: avoid clone
            if !self.pending_ranges.remove(&(our_handle, range.clone())) {
                warn!("received duplicate final reply for range marker");
                Err(Error::InvalidMessageInCurrentState)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn bind_our_static_token(
        &mut self,
        static_token: StaticToken,
    ) -> anyhow::Result<(StaticTokenHandle, Option<SetupBindStaticToken>)> {
        let (handle, is_new) = self
            .our_resources
            .static_tokens
            .bind_if_new(static_token.clone());
        let msg = is_new.then(|| SetupBindStaticToken { static_token });
        Ok((handle, msg))
    }

    fn handle_to_namespace_id(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let aoi = self.resources(scope).areas_of_interest.get(handle)?;
        let capability = self.resources(scope).capabilities.get(&aoi.authorisation)?;
        let namespace_id = capability.granted_namespace().into();
        Ok(namespace_id)
    }

    fn range_is_authorised(
        &self,
        range: &ThreeDRange,
        receiver_handle: &AreaOfInterestHandle,
        sender_handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let our_namespace = self.handle_to_namespace_id(Scope::Ours, receiver_handle)?;
        let their_namespace = self.handle_to_namespace_id(Scope::Theirs, sender_handle)?;
        if our_namespace != their_namespace {
            return Err(Error::AreaOfInterestNamespaceMismatch);
        }
        let our_aoi = self.handle_to_aoi(Scope::Ours, receiver_handle)?;
        let their_aoi = self.handle_to_aoi(Scope::Theirs, sender_handle)?;

        if !our_aoi.area().includes_range(&range) || !their_aoi.area().includes_range(&range) {
            return Err(Error::RangeOutsideCapability);
        }
        Ok(our_namespace.into())
    }

    fn handle_to_aoi(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<&SetupBindAreaOfInterest, Error> {
        self.resources(scope).areas_of_interest.get(handle)
    }
}

// Note that all async methods yield to the owner of the coroutine. They are not running in a tokio
// context. You may not perform regular async operations in them.
impl<S: ReadonlyStore, W: Store> Coroutine<S, W> {
    pub async fn run_reconciliation(
        mut self,
        start: Option<(AreaOfInterestHandle, AreaOfInterestHandle)>,
    ) -> Result<(), Error> {
        if let Some((our_handle, their_handle)) = start {
            self.init_reconciliation(our_handle, their_handle).await?;
        }

        while let Some(message) = self.recv(LogicalChannel::Reconciliation).await {
            let message = message?;
            self.on_reconciliation_message(message).await?;
            if self.state_mut().trigger_notify_if_complete() {
                break;
            }
        }

        Ok(())
    }

    pub async fn run_control(mut self, init: SessionInit) -> Result<(), Error> {
        let reveal_message = self.state_mut().commitment_reveal()?;
        self.send_control(reveal_message).await?;

        while let Some(message) = self.recv(LogicalChannel::Control).await {
            let message = message?;
            debug!(%message, "run_control recv");
            self.on_control_message(message, &init).await?;
            if self.state_mut().trigger_notify_if_complete() {
                break;
            }
        }

        Ok(())
    }

    async fn on_control_message(
        &mut self,
        message: Message,
        init: &SessionInit,
    ) -> Result<(), Error> {
        match message {
            Message::CommitmentReveal(msg) => {
                let setup_messages = self.state_mut().on_commitment_reveal(msg, &init)?;
                for message in setup_messages {
                    debug!(%message, "send");
                    self.send_control(message).await?;
                }
            }
            Message::SetupBindReadCapability(msg) => {
                self.state_mut().on_setup_bind_read_capability(msg)?;
            }
            Message::SetupBindStaticToken(msg) => {
                self.state_mut().on_setup_bind_static_token(msg);
            }
            Message::SetupBindAreaOfInterest(msg) => {
                let (_peer, start) = self.state_mut().on_setup_bind_area_of_interest(msg)?;
                self.co.yield_(Yield::StartReconciliation(start)).await;
            }
            Message::ControlFreeHandle(_msg) => {
                // TODO: Free handles
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
    }

    async fn on_reconciliation_message(&mut self, message: Message) -> Result<(), Error> {
        trace!(%message, "recv");
        match message {
            Message::ReconciliationSendFingerprint(message) => {
                self.on_send_fingerprint(message).await?
            }
            Message::ReconciliationAnnounceEntries(message) => {
                self.on_announce_entries(message).await?
            }
            Message::ReconciliationSendEntry(message) => self.on_send_entry(message).await?,
            _ => return Err(Error::UnsupportedMessage),
        };
        Ok(())
    }

    async fn init_reconciliation(
        &mut self,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        debug!("init reconciliation");
        let mut state = self.state_mut();
        let our_aoi = state.our_resources.areas_of_interest.get(&our_handle)?;
        let their_aoi = state.their_resources.areas_of_interest.get(&their_handle)?;

        let our_capability = state
            .our_resources
            .capabilities
            .get(&our_aoi.authorisation)?;
        let namespace: NamespaceId = our_capability.granted_namespace().into();

        let common_aoi = &our_aoi
            .area()
            .intersection(&their_aoi.area())
            .ok_or(Error::AreaOfInterestDoesNotOverlap)?;

        let range = common_aoi.into_range();
        state.reconciliation_started = true;
        drop(state);
        let fingerprint = self.store_snapshot.fingerprint(namespace, &range)?;
        self.send_fingerprint(range, fingerprint, our_handle, their_handle, None)
            .await?;
        Ok(())
    }

    async fn on_send_fingerprint(
        &mut self,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        trace!("on_send_fingerprint start");
        let ReconciliationSendFingerprint {
            range,
            fingerprint: their_fingerprint,
            sender_handle: their_handle,
            receiver_handle: our_handle,
            is_final_reply_for_range,
        } = message;

        let namespace = {
            let mut state = self.state_mut();
            state.reconciliation_started = true;
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            state.range_is_authorised(&range, &our_handle, &their_handle)?
        };

        let our_fingerprint = self.store_snapshot.fingerprint(namespace, &range)?;

        // case 1: fingerprint match.
        if our_fingerprint == their_fingerprint {
            let msg = ReconciliationAnnounceEntries {
                range: range.clone(),
                count: 0,
                want_response: false,
                will_sort: false,
                sender_handle: our_handle,
                receiver_handle: their_handle,
                is_final_reply_for_range: Some(range),
            };
            self.send_reconciliation(msg).await?;
        }
        // case 2: fingerprint is empty
        else if their_fingerprint.is_empty() {
            self.announce_and_send_entries(
                namespace,
                &range,
                our_handle,
                their_handle,
                true,
                Some(range.clone()),
                None,
            )
            .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            self.split_range_and_send_parts(namespace, &range, our_handle, their_handle)
                .await?;
        }
        trace!("on_send_fingerprint done");
        Ok(())
    }
    async fn on_announce_entries(
        &mut self,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        trace!("on_announce_entries start");
        let ReconciliationAnnounceEntries {
            range,
            count,
            want_response,
            will_sort: _,
            sender_handle: their_handle,
            receiver_handle: our_handle,
            is_final_reply_for_range,
        } = message;

        let namespace = {
            let mut state = self.state_mut();
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            if state.pending_entries.is_some() {
                return Err(Error::InvalidMessageInCurrentState);
            }
            let namespace = state.range_is_authorised(&range, &our_handle, &their_handle)?;
            if count != 0 {
                state.pending_entries = Some(count);
            }
            namespace
        };
        if want_response {
            self.announce_and_send_entries(
                namespace,
                &range,
                our_handle,
                their_handle,
                false,
                Some(range.clone()),
                None,
            )
            .await?;
        }
        trace!("on_announce_entries done");
        Ok(())
    }

    async fn on_send_entry(&mut self, message: ReconciliationSendEntry) -> Result<(), Error> {
        let static_token = self.get_static_token(message.static_token_handle).await;

        self.state_mut().on_send_entry()?;

        let authorised_entry = AuthorisedEntry::try_from_parts(
            message.entry.entry,
            static_token,
            message.dynamic_token,
        )?;
        self.store_writer
            .borrow_mut()
            .ingest_entry(&authorised_entry)?;
        Ok(())
    }

    async fn get_static_token(&mut self, handle: StaticTokenHandle) -> StaticToken {
        loop {
            let mut state = self.state.borrow_mut();
            match state
                .their_resources
                .static_tokens
                .get_or_notify(&handle, || {
                    self.notifier
                        .notifier(self.peer, Readyness::Resource(handle.into()))
                }) {
                Some(token) => break token.clone(),
                None => {
                    drop(state);
                    self.co
                        .yield_(Yield::Pending(Readyness::Resource(handle.into())))
                        .await
                }
            }
        }
    }

    async fn send_reconciliation(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send_control(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send(&self, message: impl Into<Message>) -> anyhow::Result<()> {
        let message: Message = message.into();
        let channel = message.logical_channel();
        // debug!(%message, ?channel, "send");
        let sender = self.channels.sender(channel);

        loop {
            match sender.send_or_set_notify(&message)? {
                WriteOutcome::Ok => {
                    debug!(msg=%message, ch=%channel.fmt_short(), "sent");
                    break Ok(());
                }
                WriteOutcome::BufferFull => {
                    debug!(msg=%message, ch=%channel.fmt_short(), "sent buf full, yield");
                    self.co
                        .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Send)))
                        .await;
                }
            }
        }
    }

    async fn recv_bulk<const N: usize>(
        &self,
        channel: LogicalChannel,
    ) -> Option<anyhow::Result<SmallVec<[Message; N]>>> {
        let receiver = self.channels.receiver(channel);
        let mut buf = SmallVec::<[Message; N]>::new();
        loop {
            match receiver.read_message_or_set_notify() {
                Err(err) => return Some(Err(err)),
                Ok(outcome) => match outcome {
                    ReadOutcome::Closed => {
                        if buf.is_empty() {
                            debug!("recv: closed");
                            return None;
                        } else {
                            return Some(Ok(buf));
                        }
                    }
                    ReadOutcome::ReadBufferEmpty => {
                        if buf.is_empty() {
                            self.co
                                .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Recv)))
                                .await;
                        } else {
                            return Some(Ok(buf));
                        }
                    }
                    ReadOutcome::Item(message) => {
                        debug!(%message, "recv");
                        buf.push(message);
                        if buf.len() == N {
                            return Some(Ok(buf));
                        }
                    }
                },
            }
        }
    }
    async fn recv(&self, channel: LogicalChannel) -> Option<anyhow::Result<Message>> {
        let receiver = self.channels.receiver(channel);
        loop {
            match receiver.read_message_or_set_notify() {
                Err(err) => return Some(Err(err)),
                Ok(outcome) => match outcome {
                    ReadOutcome::Closed => {
                        debug!("recv: closed");
                        return None;
                    }
                    ReadOutcome::ReadBufferEmpty => {
                        self.co
                            .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Recv)))
                            .await;
                    }
                    ReadOutcome::Item(message) => {
                        debug!(%message, "recv");
                        return Some(Ok(message));
                    }
                },
            }
        }
    }

    async fn send_fingerprint(
        &mut self,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        is_final_reply_for_range: Option<ThreeDRange>,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state_mut();
            state.pending_ranges.insert((our_handle, range.clone()));
        }
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.send_reconciliation(msg).await?;
        Ok(())
    }

    async fn announce_and_send_entries(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
        is_final_reply_for_range: Option<ThreeDRange>,
        our_count: Option<u64>,
    ) -> Result<(), Error> {
        if want_response {
            let mut state = self.state_mut();
            state.pending_ranges.insert((our_handle, range.clone()));
        }
        let our_count = match our_count {
            Some(count) => count,
            None => self.store_snapshot.count(namespace, &range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: our_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.send_reconciliation(msg).await?;
        for authorised_entry in self
            .store_snapshot
            .get_entries_with_authorisation(namespace, &range)
        {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let (static_token_handle, static_token_bind_msg) = self
                .state
                .borrow_mut()
                .bind_our_static_token(static_token)?;
            if let Some(msg) = static_token_bind_msg {
                self.send_control(msg).await?;
            }
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send_reconciliation(msg).await?;
        }
        Ok(())
    }

    async fn split_range_and_send_parts(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        // TODO: expose this config
        let config = SyncConfig::default();
            // clone to avoid borrow checker trouble
            let store_snapshot = Rc::clone(&self.store_snapshot);
            let mut iter = store_snapshot
                .split_range(namespace, &range, &config)?
                .peekable();
            while let Some(res) = iter.next() {
                let (subrange, action) = res?;
                let is_last = iter.peek().is_none();
                let is_final_reply = is_last.then(|| range.clone());
                match action {
                    SplitAction::SendEntries(count) => {
                        self.announce_and_send_entries(
                            namespace,
                            &subrange,
                            our_handle,
                            their_handle,
                            true,
                            is_final_reply,
                            Some(count),
                        )
                        .await?;
                    }
                    SplitAction::SendFingerprint(fingerprint) => {
                        self.send_fingerprint(
                            subrange,
                            fingerprint,
                            our_handle,
                            their_handle,
                            is_final_reply,
                        )
                        .await?;
                    }
                }
            }
        Ok(())
    }

    fn state_mut(&mut self) -> RefMut<SessionStateInner> {
        self.state.borrow_mut()
    }
}
