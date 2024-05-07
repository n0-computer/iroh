use std::{
    cell::RefCell,
    collections::HashSet,
    rc::Rc,
    sync::{Arc, Mutex},
};

use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use iroh_net::NodeId;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::{
    proto::{
        grouping::ThreeDRange,
        keys::{NamespaceId, NamespacePublicKey},
        wgps::{
            AreaOfInterestHandle, CapabilityHandle, Fingerprint, LengthyEntry, LogicalChannel,
            Message, ReadCapability, ReconciliationAnnounceEntries, ReconciliationSendEntry,
            ReconciliationSendFingerprint, ResourceHandle, SetupBindAreaOfInterest,
            SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
        willow::{AuthorisationToken, AuthorisedEntry},
    },
    store::{
        actor::{CoroutineNotifier, Interest},
        ReadonlyStore, SplitAction, Store, SyncConfig,
    },
    util::channel::{ReadOutcome, Receiver, Sender, WriteOutcome},
};

use super::{resource::ScopedResources, Error, Role, Scope};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Yield {
    ChannelPending(LogicalChannel, Interest),
    ResourceMissing(ResourceHandle),
}

#[derive(derive_more::Debug)]
pub struct Coroutine<S: ReadonlyStore, W: Store> {
    pub peer: NodeId,
    pub store_snapshot: Arc<S>,
    pub store_writer: Rc<RefCell<W>>,
    pub channels: Arc<Channels>,
    pub state: SessionState,
    pub notifier: CoroutineNotifier,
    #[debug(skip)]
    pub co: Co<Yield, ()>,
}

pub type SessionState = Arc<Mutex<SessionStateInner>>;

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

#[derive(Debug, Default)]
pub struct SessionStateInner {
    pub our_resources: ScopedResources,
    pub their_resources: ScopedResources,
    pub reconciliation_started: bool,
    pub pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pub pending_entries: Option<u64>,
    pub notify_complete: Arc<Notify>,
}

impl SessionStateInner {
    fn resources(&self, scope: Scope) -> &ScopedResources {
        match scope {
            Scope::Ours => &self.our_resources,
            Scope::Theirs => &self.their_resources,
        }
    }
    pub fn is_complete(&self) -> bool {
        self.reconciliation_started
            && self.pending_ranges.is_empty()
            && self.pending_entries.is_none()
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

    // fn get_resource(&self, scope: Scope, handle: impl Into<Handle>) {
    //     match handle.into() {
    //
    //     }
    // }

    pub fn setup_bind_area_of_interest(
        &mut self,
        msg: SetupBindAreaOfInterest,
    ) -> Result<AreaOfInterestHandle, Error> {
        let capability = self
            .resources(Scope::Theirs)
            .capabilities
            .get(&msg.authorisation)?;
        capability.try_granted_area(&msg.area_of_interest.area)?;
        let their_handle = self.their_resources.areas_of_interest.bind(msg);
        Ok(their_handle)
    }

    pub fn authorize_send_entry(
        &mut self,
        message: ReconciliationSendEntry,
    ) -> Result<AuthorisedEntry, Error> {
        let ReconciliationSendEntry {
            entry,
            static_token_handle,
            dynamic_token,
        } = message;
        let remaining = self
            .pending_entries
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        *remaining -= 1;
        if *remaining == 0 {
            self.pending_entries = None;
        }
        let static_token = self
            .their_resources
            .static_tokens
            .get(&static_token_handle)?
            .clone();

        let authorisation_token = AuthorisationToken::from_parts(static_token, dynamic_token);
        let authorised_entry = AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
        Ok(authorised_entry)
    }

    // async fn get_static_token_or_yield(
    //     &mut self,
    //     handle: &StaticTokenHandle,
    // ) -> Result<StaticToken, Error> {
    //     // loop {
    //     // match self
    //     //     .their_resources
    //     //     .static_tokens
    //     //     .get(&static_token_handle) {
    //     //         Ok(token) => return Ok(token.clone()),
    //     //             Err(_)=> {}
    //     //     }
    //     // }
    //     todo!()
    // }

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
    pub async fn run(
        mut self,
        init: Option<(AreaOfInterestHandle, AreaOfInterestHandle)>,
    ) -> Result<(), Error> {
        if let Some((our_handle, their_handle)) = init {
            self.init_reconciliation(our_handle, their_handle).await?;
        }

        while let Some(message) = self.recv(LogicalChannel::Reconciliation).await {
            let message = message?;
            self.on_message(message).await?;
            if self.state.lock().unwrap().trigger_notify_if_complete() {
                break;
            }
        }

        Ok(())
    }

    pub async fn on_message(&mut self, message: Message) -> Result<(), Error> {
        info!(%message, "recv");
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

    pub async fn init_reconciliation(
        &mut self,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        debug!("init reconciliation");
        let mut state = self.state.lock().unwrap();
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

    pub async fn on_send_fingerprint(
        &mut self,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        debug!("on_send_fingerprint start");
        let ReconciliationSendFingerprint {
            range,
            fingerprint: their_fingerprint,
            sender_handle: their_handle,
            receiver_handle: our_handle,
            is_final_reply_for_range,
        } = message;

        let namespace = {
            let mut state = self.state.lock().unwrap();
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
        debug!("on_send_fingerprint done");
        Ok(())
    }
    pub async fn on_announce_entries(
        &mut self,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        debug!("on_announce_entries start");
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
            let mut state = self.state.lock().unwrap();
            debug!(?state, "STATE");
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            if state.pending_entries.is_some() {
                return Err(Error::InvalidMessageInCurrentState);
            }
            debug!("after");
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
        debug!("on_announce_entries done");
        Ok(())
    }

    async fn on_send_entry(&mut self, message: ReconciliationSendEntry) -> Result<(), Error> {
        let ReconciliationSendEntry {
            entry,
            static_token_handle,
            dynamic_token,
        } = message;
        info!("on_send_entry");

        let mut state = self.state.lock().unwrap();

        let remaining = state
            .pending_entries
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        info!(?remaining, "on_send_entry");
        *remaining -= 1;
        if *remaining == 0 {
            state.pending_entries = None;
        }
        drop(state);

        let static_token = loop {
            let mut state = self.state.lock().unwrap();
            let token = state
                .their_resources
                .static_tokens
                .get(&static_token_handle);
            info!(?token, "loop get_static_token");
            // let token = token.clone();
            match token {
                Ok(token) => break token.clone(),
                Err(Error::MissingResource(handle)) => {
                    state.their_resources.register_notify(
                        handle,
                        self.notifier
                            .notifier(self.peer, Yield::ResourceMissing(handle)),
                    );
                    drop(state);
                    self.co.yield_(Yield::ResourceMissing(handle)).await;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };
        // .clone() {}

        let authorisation_token = AuthorisationToken::from_parts(static_token, dynamic_token);
        let authorised_entry = AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
        // Ok(authorised_entry)

        // TODO: Remove clone
        //     match state.authorize_send_entry(message.clone()) {
        //         Ok(entry) => break entry,
        //         Err(Error::MissingResource(handle)) => {
        //             // state.their_resources.register_notify(handle, notify)
        //             self.co.yield_(YieldReason::ResourceMissing(handle)).await
        //         }
        //         Err(err) => return Err(err),
        //     }
        // };
        self.store_writer
            .borrow_mut()
            .ingest_entry(&authorised_entry)?;
        debug!("ingested entry");
        Ok(())
    }

    // fn on_send_entry(&self, message: ReconciliationSendEntry) -> Result<(), Error> {
    //     // Message::ReconciliationSendEntry(message) => {
    //     //     let ReconciliationSendEntry {
    //     //         entry,
    //     //         static_token_handle,
    //     //         dynamic_token,
    //     //     } = message;
    //     //     let static_token = {
    //     //         let mut state = self.state.lock().unwrap();
    //     //         let mut remaining = state
    //     //             .pending_entries
    //     //             .clone()
    //     //             .ok_or(Error::InvalidMessageInCurrentState)?;
    //     //         remaining -= 1;
    //     //         if remaining == 0 {
    //     //             state.pending_entries = None;
    //     //         }
    //     //         state
    //     //             .their_resources
    //     //             .static_tokens
    //     //             .get(&static_token_handle)?
    //     //             .clone()
    //     //     };
    //     //
    //     //     let authorisation_token =
    //     //         AuthorisationToken::from_parts(static_token, dynamic_token);
    //     //     let authorised_entry =
    //     //         AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
    //     //     self.store.ingest_entry(&authorised_entry)?;
    //     Ok(())
    // }

    async fn send_reconciliation(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send_control(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send(&self, message: impl Into<Message>) -> anyhow::Result<()> {
        let message: Message = message.into();
        let channel = message.logical_channel();
        let sender = self.channels.sender(message.logical_channel());

        loop {
            match sender.send_or_set_notify(&message)? {
                WriteOutcome::Ok => {
                    info!(msg=%message, "sent");
                    break Ok(());
                }
                WriteOutcome::BufferFull => {
                    self.co
                        .yield_(Yield::ChannelPending(channel, Interest::Send))
                        .await;
                }
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
                            .yield_(Yield::ChannelPending(channel, Interest::Recv))
                            .await;
                    }
                    ReadOutcome::Item(message) => {
                        debug!(?message, "recv");
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
            let mut state = self.state.lock().unwrap();
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
            let mut state = self.state.lock().unwrap();
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
            // TODO avoid such frequent locking
            let (static_token_handle, static_token_bind_msg) = self
                .state
                .lock()
                .unwrap()
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
        {
            let iter = self.store_snapshot.split(namespace, &range, &config)?;
            // TODO: avoid collect
            let iter = iter.collect::<Vec<_>>().into_iter();
            let mut iter = iter.peekable();
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
        }
        Ok(())
    }
}
