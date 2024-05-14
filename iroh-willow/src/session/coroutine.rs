use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};

use futures_lite::StreamExt;
use strum::IntoEnumIterator;
use tracing::{debug, error_span, trace};

use crate::{
    actor::AreaOfInterestHandlePair,
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, ControlIssueGuarantee, Fingerprint, LengthyEntry, LogicalChannel,
            Message, ReconciliationAnnounceEntries, ReconciliationMessage, ReconciliationSendEntry,
            ReconciliationSendFingerprint, SetupBindAreaOfInterest,
        },
        willow::AuthorisedEntry,
    },
    session::{
        channels::LogicalChannelReceivers, Channels, Error, SessionInit, SessionState,
        SharedSessionState,
    },
    store::{ReadonlyStore, SplitAction, Store, SyncConfig},
    util::{
        channel::{Receiver, WriteError},
        task_set::TaskKey,
    },
};

use super::channels::{ChannelReceivers, MessageReceiver};

const INITIAL_GUARANTEES: u64 = u64::MAX;

#[derive(derive_more::Debug)]
pub struct ControlRoutine<S> {
    control_recv: Receiver<Message>,
    state: SharedSessionState<S>,
    init: Option<SessionInit>,
}

#[derive(Debug)]
pub enum ReconcileState {
    Idle(Option<MessageReceiver<ReconciliationMessage>>),
    Running(TaskKey),
}

impl ReconcileState {
    fn take_receiver(&mut self) -> Option<MessageReceiver<ReconciliationMessage>> {
        match self {
            Self::Idle(recv) => recv.take(),
            _ => None,
        }
    }
}

impl<S: Store> ControlRoutine<S> {
    pub async fn run(
        channels: Channels,
        state: SessionState,
        store: Rc<RefCell<S>>,
        init: SessionInit,
    ) -> Result<(), Error> {
        let Channels { send, recv } = channels;
        let ChannelReceivers {
            control_recv,
            logical_recv,
        } = recv;
        let LogicalChannelReceivers {
            reconciliation_recv,
            mut static_tokens_recv,
            mut capability_recv,
            mut aoi_recv,
        } = logical_recv;

        let reconcile_state = ReconcileState::Idle(Some(reconciliation_recv));
        let state = SharedSessionState::new(state, send, store, reconcile_state);

        // spawn a task to handle incoming static tokens.
        state.spawn(error_span!("stt"), move |state| async move {
            while let Some(message) = static_tokens_recv.try_next().await? {
                state.state_mut().on_setup_bind_static_token(message);
            }
            Ok(())
        });

        // spawn a task to handle incoming capabilities.
        state.spawn(error_span!("cap"), move |state| async move {
            while let Some(message) = capability_recv.try_next().await? {
                state.state_mut().on_setup_bind_read_capability(message)?;
            }
            Ok(())
        });

        // spawn a task to handle incoming areas of interest.
        state.spawn(error_span!("aoi"), move |state| async move {
            while let Some(message) = aoi_recv.try_next().await? {
                Self::on_bind_area_of_interest(state.clone(), message).await?;
            }
            Ok(())
        });

        Self {
            control_recv,
            state,
            init: Some(init),
        }
        .run_inner()
        .await
    }

    async fn run_inner(mut self) -> Result<(), Error> {
        debug!(role = ?self.state().our_role, "start session");

        // reveal our nonce.
        let reveal_message = self.state().commitment_reveal()?;
        self.state.send(reveal_message).await?;

        // issue guarantees for all logical channels.
        for channel in LogicalChannel::iter() {
            let msg = ControlIssueGuarantee {
                amount: INITIAL_GUARANTEES,
                channel,
            };
            self.state.send(msg).await?;
        }

        let res = loop {
            tracing::info!("WAIT");
            tokio::select! {
                // _ = self.state.notify_complete.notified() => {
                //     tracing::info!("NOTIFIED!");
                //     break Ok(())
                // },
                message = self.control_recv.recv() => {
                    match message {
                        Some(message) => self.on_control_message(message?)?,
                        // If the remote closed their control stream, we abort the session.
                        None => break Ok(()),
                     }
                },
                Some((key, result)) = self.state.join_next_task(), if !self.state.tasks.borrow().is_empty() => {
                    debug!(?key, ?result, "task completed");
                    result?;
                    // Is this the right place for this check? It would run after each task
                    // completion, so necessarily including the completion of the reconciliation
                    // task, which is the only condition in which reconciliation can complete at
                    // the moment.
                    //
                    // TODO: We'll want to emit the completion event back to the application and
                    // let it decide what to do (stop, keep open) - or pass relevant config in
                    // SessionInit.
                    if self.state.state_mut().reconciliation_is_complete() {
                        tracing::debug!("stop session: reconciliation is complete");
                        break Ok(());
                    }
                }
            }
        };

        // Close all our send streams.
        //
        // This makes the networking send loops stop.
        self.state.send.close_all();

        res
    }
    fn on_control_message(&mut self, message: Message) -> Result<(), Error> {
        debug!(%message, "recv");
        match message {
            Message::CommitmentReveal(msg) => {
                self.state().on_commitment_reveal(msg)?;
                let init = self
                    .init
                    .take()
                    .ok_or_else(|| Error::InvalidMessageInCurrentState)?;
                self.state
                    .spawn(error_span!("setup"), |state| Self::setup(state, init));
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                let sender = self.state.send.get_logical(channel);
                debug!(?channel, %amount, "add guarantees");
                sender.add_guarantees(amount);
            }
            // Message::ControlFreeHandle(_msg) => {
            // TODO: Free handles
            // }
            _ => return Err(Error::UnsupportedMessage),
        }

        Ok(())
    }

    async fn on_bind_area_of_interest(
        session: SharedSessionState<S>,
        message: SetupBindAreaOfInterest,
    ) -> Result<(), Error> {
        let capability = session
            .get_their_resource_eventually(|r| &mut r.capabilities, message.authorisation)
            .await;
        capability.try_granted_area(&message.area_of_interest.area)?;
        let mut state = session.state.borrow_mut();
        let their_handle = state.their_resources.areas_of_interest.bind(message);
        match state.find_shared_aoi_from_theirs(&their_handle)? {
            None => {
                debug!("no shared aoi, skip");
                Ok(())
            }
            Some(our_handle) => {
                drop(state);
                debug!("shared aoi found, start reconcile");
                Self::start_reconcile(session, (our_handle, their_handle))
            }
        }
    }

    fn start_reconcile(
        mut session: SharedSessionState<S>,
        (our_handle, their_handle): AreaOfInterestHandlePair,
    ) -> Result<(), Error> {
        let recv = session
            .reconcile_state
            .borrow_mut()
            .take_receiver()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        let snapshot = Rc::new(session.store().snapshot()?);
        let fut = ReconcileRoutine {
            state: session.clone(),
            snapshot,
            recv,
        }
        .run((our_handle, their_handle));
        let task_key = session.spawn(error_span!("reconcile"), |_| fut);
        *session.reconcile_state.borrow_mut() = ReconcileState::Running(task_key);
        Ok(())
    }

    async fn setup(session: SharedSessionState<S>, init: SessionInit) -> Result<(), Error> {
        debug!(interests = init.interests.len(), "start setup");
        for (capability, aois) in init.interests.into_iter() {
            if *capability.receiver() != init.user_secret_key.public_key() {
                return Err(Error::WrongSecretKeyForCapability);
            }

            // TODO: implement private area intersection
            let intersection_handle = 0.into();
            let (our_capability_handle, message) = session.state_mut().bind_and_sign_capability(
                &init.user_secret_key,
                intersection_handle,
                capability,
            )?;
            if let Some(message) = message {
                session.send(message).await?;
            }

            for area_of_interest in aois {
                let msg = SetupBindAreaOfInterest {
                    area_of_interest,
                    authorisation: our_capability_handle,
                };

                let (our_handle, is_new) = session
                    .state_mut()
                    .our_resources
                    .areas_of_interest
                    .bind_if_new(msg.clone());

                if is_new {
                    session.send(msg).await?;
                    if let Some(their_handle) =
                        session.state_mut().find_shared_aoi_from_ours(&our_handle)?
                    {
                        debug!("sent aoi, shared, start reconcile");
                        Self::start_reconcile(session.clone(), (our_handle, their_handle))?;
                    } else {
                        debug!("sent aoi, not yet shared");
                    }
                }
            }
        }
        debug!("setup done");
        Ok(())
    }

    fn state(&mut self) -> RefMut<SessionState> {
        self.state.state_mut()
    }
}

#[derive(derive_more::Debug)]
pub struct ReconcileRoutine<S: ReadonlyStore, W: Store> {
    snapshot: Rc<S>,
    recv: MessageReceiver<ReconciliationMessage>,
    state: SharedSessionState<W>,
}

// Note that all async methods yield to the owner of the coroutine. They are not running in a tokio
// context. You may not perform regular async operations in them.
impl<S: ReadonlyStore, W: Store> ReconcileRoutine<S, W> {
    pub async fn run(mut self, shared_aoi: AreaOfInterestHandlePair) -> Result<(), Error> {
        let our_role = self.state().our_role;
        tracing::warn!(init = our_role.is_alfie(), "start reconciliation");
        // optionally initiate reconciliation with a first fingerprint. only alfie may do this.
        if our_role.is_alfie() {
            self.initiate(shared_aoi.0, shared_aoi.1).await?;
        }

        while let Some(message) = self.recv.recv().await {
            let message = message?;
            debug!(?message, "recv");
            match message {
                ReconciliationMessage::SendFingerprint(message) => {
                    self.on_send_fingerprint(message).await?
                }
                ReconciliationMessage::AnnounceEntries(message) => {
                    self.on_announce_entries(message).await?
                }
                ReconciliationMessage::SendEntry(message) => self.on_send_entry(message).await?,
            };

            if self.state().reconciliation_is_complete() {
                tracing::info!("reconciliation complete, close session");
                break;
            }
        }

        Ok(())
    }

    async fn initiate(
        &mut self,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        let mut state = self.state();
        let our_aoi = state.our_resources.areas_of_interest.try_get(&our_handle)?;
        let their_aoi = state
            .their_resources
            .areas_of_interest
            .try_get(&their_handle)?;

        let our_capability = state
            .our_resources
            .capabilities
            .try_get(&our_aoi.authorisation)?;
        let namespace: NamespaceId = our_capability.granted_namespace().into();

        let common_aoi = &our_aoi
            .area()
            .intersection(&their_aoi.area())
            .ok_or(Error::AreaOfInterestDoesNotOverlap)?;

        let range = common_aoi.into_range();
        state.reconciliation_started = true;
        drop(state);
        let fingerprint = self.snapshot.fingerprint(namespace, &range)?;
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
            let mut state = self.state();
            state.reconciliation_started = true;
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            state.range_is_authorised(&range, &our_handle, &their_handle)?
        };

        let our_fingerprint = self.snapshot.fingerprint(namespace, &range)?;

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
            self.send(msg).await?;
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
            let mut state = self.state();
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
        let static_token = self
            .state
            .get_their_resource_eventually(|r| &mut r.static_tokens, message.static_token_handle)
            .await;

        self.state().on_send_entry()?;

        let authorised_entry = AuthorisedEntry::try_from_parts(
            message.entry.entry,
            static_token,
            message.dynamic_token,
        )?;

        self.state.store().ingest_entry(&authorised_entry)?;

        Ok(())
    }

    async fn send_fingerprint(
        &mut self,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        is_final_reply_for_range: Option<ThreeDRange>,
    ) -> anyhow::Result<()> {
        self.state()
            .pending_ranges
            .insert((our_handle, range.clone()));
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.send(msg).await?;
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
            let mut state = self.state();
            state.pending_ranges.insert((our_handle, range.clone()));
        }
        let our_count = match our_count {
            Some(count) => count,
            None => self.snapshot.count(namespace, &range)?,
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
        self.send(msg).await?;
        for authorised_entry in self
            .snapshot
            .get_entries_with_authorisation(namespace, &range)
        {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let (static_token_handle, static_token_bind_msg) =
                self.state.state_mut().bind_our_static_token(static_token)?;
            if let Some(msg) = static_token_bind_msg {
                self.send(msg).await?;
            }
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send(msg).await?;
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
        let store_snapshot = Rc::clone(&self.snapshot);
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

    fn state(&mut self) -> RefMut<SessionState> {
        self.state.state_mut()
    }

    async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
        self.state.send(message).await
    }
}
