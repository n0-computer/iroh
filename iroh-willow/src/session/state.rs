use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashSet,
    future::poll_fn,
    pin::Pin,
    rc::Rc,
    task::Poll,
};

use futures_lite::Stream;
use tracing::{debug, trace, Instrument, Span};

use crate::{
    proto::{
        challenge::ChallengeState,
        grouping::ThreeDRange,
        keys::NamespaceId,
        sync::{
            AreaOfInterestHandle, CapabilityHandle, Channel, CommitmentReveal, DynamicToken,
            IntersectionHandle, IsHandle, LogicalChannel, Message, ReadCapability,
            ReconciliationAnnounceEntries, ReconciliationSendFingerprint, SetupBindAreaOfInterest,
            SetupBindReadCapability, SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
        willow::{AuthorisedEntry, Entry},
    },
    session::InitialTransmission,
    store::traits::SecretStorage,
    util::{channel::WriteError, queue::Queue, task::JoinMap},
};

use super::{
    channels::ChannelSenders,
    resource::{ResourceMap, ResourceMaps},
    AreaOfInterestIntersection, Error, Role, Scope, SessionId, SessionMode,
};

#[derive(Debug, Clone)]
pub struct Session(Rc<SessionInner>);

#[derive(derive_more::Debug)]
struct SessionInner {
    id: SessionId,
    our_role: Role,
    mode: SessionMode,
    state: RefCell<SessionState>,
    send: ChannelSenders,
    tasks: RefCell<JoinMap<Span, Result<(), Error>>>,
}

impl Session {
    pub fn new(
        id: SessionId,
        mode: SessionMode,
        our_role: Role,
        send: ChannelSenders,
        initial_transmission: InitialTransmission,
    ) -> Self {
        let state = SessionState::new(initial_transmission);
        Self(Rc::new(SessionInner {
            mode,
            id,
            our_role,
            state: RefCell::new(state),
            send,
            tasks: Default::default(),
        }))
    }

    pub fn id(&self) -> &SessionId {
        &self.0.id
    }

    pub fn mode(&self) -> &SessionMode {
        &self.0.mode
    }

    pub fn spawn<F, Fut>(&self, span: Span, f: F)
    where
        F: FnOnce(Session) -> Fut,
        Fut: std::future::Future<Output = Result<(), Error>> + 'static,
    {
        let state = self.clone();
        let fut = f(state);
        let fut = fut.instrument(span.clone());
        self.0.tasks.borrow_mut().spawn_local(span, fut);
    }

    pub async fn join_next_task(&self) -> Option<(Span, Result<(), Error>)> {
        poll_fn(|cx| {
            let mut tasks = self.0.tasks.borrow_mut();
            let res = std::task::ready!(Pin::new(&mut tasks).poll_join_next(cx));
            let res = match res {
                None => None,
                Some((key, Ok(r))) => Some((key, r)),
                Some((key, Err(r))) => Some((key, Err(r.into()))),
            };
            Poll::Ready(res)
        })
        .await
    }

    pub fn abort_all_tasks(&self) {
        self.0.tasks.borrow_mut().abort_all();
    }

    // pub fn remaining_tasks(&self) -> usize {
    //     let tasks = self.0.tasks.borrow();
    //     tasks.len()
    // }

    pub fn remaining_tasks(&self) -> String {
        let tasks = self.0.tasks.borrow();
        let mut out = vec![];
        for (span, _k) in tasks.iter() {
            let name = span.metadata().unwrap().name();
            out.push(name.to_string());
        }
        out.join(",")
    }

    pub fn log_remaining_tasks(&self) {
        let tasks = self.0.tasks.borrow();
        let names = tasks
            .iter()
            .map(|t| t.0.metadata().unwrap().name())
            .collect::<Vec<_>>();
        debug!(tasks=?names, "active_tasks");
    }

    pub async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
        let message: Message = message.into();
        if let Some((their_handle, range_count)) = message.covers_region() {
            if let Err(err) = self
                .state_mut()
                .mark_their_range_covered(their_handle, range_count)
            {
                // TODO: Is this really unreachable? I think so, as this would indicate a logic
                // error purely on our side.
                unreachable!("mark_their_range_covered: {err:?}");
            }
        }
        self.0.send.send(message).await
    }

    pub fn close_senders(&self) {
        self.0.send.close_all();
    }

    pub fn add_guarantees(&self, channel: LogicalChannel, amount: u64) {
        self.0
            .send
            .get(Channel::Logical(channel))
            .add_guarantees(amount);
    }

    pub fn our_role(&self) -> Role {
        self.0.our_role
    }

    pub async fn next_aoi_intersection(&self) -> Option<AreaOfInterestIntersection> {
        poll_fn(|cx| {
            let mut queue = &mut self.0.state.borrow_mut().intersection_queue;
            Pin::new(&mut queue).poll_next(cx)
        })
        .await
    }

    pub fn get_our_resource<F, H: IsHandle, R: Eq + PartialEq + Clone>(
        &self,
        selector: F,
        handle: H,
    ) -> Result<R, Error>
    where
        F: for<'a> Fn(&'a ResourceMaps) -> &'a ResourceMap<H, R>,
    {
        let state = self.0.state.borrow_mut();
        state.our_resources.get(&selector, handle)
    }

    pub async fn get_their_resource_eventually<F, H: IsHandle, R: Eq + PartialEq + Clone>(
        &self,
        selector: F,
        handle: H,
    ) -> R
    where
        F: for<'a> Fn(&'a mut ResourceMaps) -> &'a mut ResourceMap<H, R>,
    {
        let inner = &self.clone().0;
        poll_fn(move |cx| {
            let mut state = inner.state.borrow_mut();
            state
                .their_resources
                .poll_get_eventually(&selector, handle, cx)
        })
        .await
    }

    pub fn bind_and_sign_capability<K: SecretStorage>(
        &self,
        key_store: &K,
        our_intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<(CapabilityHandle, Option<SetupBindReadCapability>), Error> {
        let mut inner = self.0.state.borrow_mut();
        let signable = inner.challenge.signable()?;
        let signature = key_store.sign_user(&capability.receiver().id(), &signable)?;

        let (our_handle, is_new) = inner
            .our_resources
            .capabilities
            .bind_if_new(capability.clone());
        let maybe_message = is_new.then(|| SetupBindReadCapability {
            capability,
            handle: our_intersection_handle,
            signature,
        });
        Ok((our_handle, maybe_message))
    }

    pub fn mark_our_range_pending(&self, our_handle: AreaOfInterestHandle) {
        let mut state = self.state_mut();
        state.reconciliation_started = true;
        let range_count = state.our_range_counter;
        state.our_uncovered_ranges.insert((our_handle, range_count));
        state.our_range_counter += 1;
    }

    pub async fn on_announce_entries(
        &self,
        message: &ReconciliationAnnounceEntries,
    ) -> Result<(NamespaceId, Option<u64>), Error> {
        let range_count = {
            let mut state = self.state_mut();
            if let Some(range_count) = message.covers {
                state.mark_our_range_covered(message.receiver_handle, range_count)?;
            }
            if state.pending_announced_entries.is_some() {
                return Err(Error::InvalidMessageInCurrentState);
            }
            if message.count != 0 {
                state.pending_announced_entries = Some(message.count);
            }
            if message.want_response {
                let range_count = state.add_pending_range_theirs(message.sender_handle);
                Some(range_count)
            } else {
                None
            }
        };
        let namespace = self
            .range_is_authorised_eventually(
                &message.range,
                message.receiver_handle,
                message.sender_handle,
            )
            .await?;
        Ok((namespace, range_count))
    }

    pub async fn on_send_fingerprint(
        &self,
        message: &ReconciliationSendFingerprint,
    ) -> Result<(NamespaceId, u64), Error> {
        let range_count = {
            let mut state = self.state_mut();
            state.reconciliation_started = true;
            if let Some(range_count) = message.covers {
                state.mark_our_range_covered(message.receiver_handle, range_count)?;
            }
            state.add_pending_range_theirs(message.sender_handle)
        };

        let namespace = self
            .range_is_authorised_eventually(
                &message.range,
                message.receiver_handle,
                message.sender_handle,
            )
            .await?;
        Ok((namespace, range_count))
    }

    async fn range_is_authorised_eventually(
        &self,
        range: &ThreeDRange,
        receiver_handle: AreaOfInterestHandle,
        sender_handle: AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let our_namespace = self.our_aoi_to_namespace(&receiver_handle)?;
        let their_namespace = self
            .their_aoi_to_namespace_eventually(sender_handle)
            .await?;
        if our_namespace != their_namespace {
            return Err(Error::AreaOfInterestNamespaceMismatch);
        }
        let our_aoi = self.get_our_resource(|r| &r.areas_of_interest, receiver_handle)?;
        let their_aoi = self
            .get_their_resource_eventually(|r| &mut r.areas_of_interest, sender_handle)
            .await;

        if !our_aoi.area().includes_range(range) || !their_aoi.area().includes_range(range) {
            return Err(Error::RangeOutsideCapability);
        }
        Ok(our_namespace)
    }

    pub fn on_setup_bind_static_token(&self, msg: SetupBindStaticToken) {
        self.state_mut()
            .their_resources
            .static_tokens
            .bind(msg.static_token);
    }

    pub fn on_setup_bind_read_capability(&self, msg: SetupBindReadCapability) -> Result<(), Error> {
        // TODO: verify intersection handle
        trace!("received capability {msg:?}");
        msg.capability.validate()?;
        let mut state = self.state_mut();
        state
            .challenge
            .verify(msg.capability.receiver(), &msg.signature)?;
        state.their_resources.capabilities.bind(msg.capability);
        Ok(())
    }

    pub fn reconciliation_is_complete(&self) -> bool {
        let state = self.state();
        // tracing::debug!(
        //     "reconciliation_is_complete started {} our_pending_ranges {}, their_pending_ranges {}, pending_entries {:?} mode {:?}",
        //     state.reconciliation_started,
        //     state.our_uncovered_ranges.len(),
        //     state.their_uncovered_ranges.len(),
        //     state.pending_announced_entries,
        //     self.mode(),
        // );
        state.reconciliation_started
            && state.our_uncovered_ranges.is_empty()
            && state.their_uncovered_ranges.is_empty()
            && state.pending_announced_entries.is_none()
    }

    pub fn reveal_commitment(&self) -> Result<CommitmentReveal, Error> {
        let state = self.state();
        match state.challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce })
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn on_commitment_reveal(&self, msg: CommitmentReveal) -> Result<(), Error> {
        let our_role = self.our_role();
        let mut state = self.state_mut();
        state.challenge.reveal(our_role, msg.nonce)
    }

    /// Bind a area of interest, and start reconciliation if this area of interest has an
    /// intersection with a remote area of interest.
    ///
    /// Will fail if the capability is missing. Await [`Self::get_our_resource_eventually`] or
    /// [`Self::get_their_resource_eventually`] before calling this.
    ///
    /// Returns `true` if the capability was newly bound, and `false` if not.
    pub fn bind_area_of_interest(
        &self,
        scope: Scope,
        message: SetupBindAreaOfInterest,
        capability: &ReadCapability,
    ) -> Result<(), Error> {
        self.state_mut()
            .bind_area_of_interest(scope, message, capability)
    }

    pub async fn on_bind_area_of_interest(
        &self,
        message: SetupBindAreaOfInterest,
    ) -> Result<(), Error> {
        let capability = self
            .get_their_resource_eventually(|r| &mut r.capabilities, message.authorisation)
            .await;
        self.state_mut()
            .bind_area_of_interest(Scope::Theirs, message, &capability)?;
        Ok(())
    }

    pub async fn authorise_sent_entry(
        &self,
        entry: Entry,
        static_token_handle: StaticTokenHandle,
        dynamic_token: DynamicToken,
    ) -> Result<AuthorisedEntry, Error> {
        let static_token = self
            .get_their_resource_eventually(|r| &mut r.static_tokens, static_token_handle)
            .await;

        let authorised_entry = AuthorisedEntry::try_from_parts(entry, static_token, dynamic_token)?;

        Ok(authorised_entry)
    }

    // pub async fn on_send_entry2(&self, entry: Entry, static_token_handle: StaticTokenHandle, dynamic_token: DynamicToken) -> Result<(), Error> {
    //     let static_token = self
    //         .get_their_resource_eventually(|r| &mut r.static_tokens, message.static_token_handle)
    //         .await;
    //
    //     let authorised_entry = AuthorisedEntry::try_from_parts(
    //         message.entry.entry,
    //         static_token,
    //         message.dynamic_token,
    //     )?;
    //
    //     self.state_mut().decrement_pending_announced_entries();
    //
    //     Ok(authorised_entry)
    // }

    pub fn decrement_pending_announced_entries(&self) -> Result<(), Error> {
        self.state_mut().decrement_pending_announced_entries()
    }

    // pub fn prepare_entry_for_send(&self, entry: AuthorisedEntry) -> Result<

    pub fn bind_our_static_token(
        &self,
        static_token: StaticToken,
    ) -> (StaticTokenHandle, Option<SetupBindStaticToken>) {
        let mut state = self.state_mut();
        let (handle, is_new) = state
            .our_resources
            .static_tokens
            .bind_if_new(static_token.clone());
        let msg = is_new.then(|| SetupBindStaticToken { static_token });
        (handle, msg)
    }

    async fn their_aoi_to_namespace_eventually(
        &self,
        handle: AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let aoi = self
            .get_their_resource_eventually(|r| &mut r.areas_of_interest, handle)
            .await;
        let capability = self
            .get_their_resource_eventually(|r| &mut r.capabilities, aoi.authorisation)
            .await;
        let namespace_id = capability.granted_namespace().into();
        Ok(namespace_id)
    }

    fn our_aoi_to_namespace(&self, handle: &AreaOfInterestHandle) -> Result<NamespaceId, Error> {
        let state = self.state_mut();
        let aoi = state.our_resources.areas_of_interest.try_get(handle)?;
        let capability = state
            .our_resources
            .capabilities
            .try_get(&aoi.authorisation)?;
        let namespace_id = capability.granted_namespace().into();
        Ok(namespace_id)
    }

    fn state(&self) -> Ref<SessionState> {
        self.0.state.borrow()
    }

    fn state_mut(&self) -> RefMut<SessionState> {
        self.0.state.borrow_mut()
    }
}

#[derive(Debug)]
struct SessionState {
    challenge: ChallengeState,
    our_resources: ResourceMaps,
    their_resources: ResourceMaps,
    reconciliation_started: bool,
    our_range_counter: u64,
    their_range_counter: u64,
    our_uncovered_ranges: HashSet<(AreaOfInterestHandle, u64)>,
    their_uncovered_ranges: HashSet<(AreaOfInterestHandle, u64)>,
    pending_announced_entries: Option<u64>,
    intersection_queue: Queue<AreaOfInterestIntersection>,
}

impl SessionState {
    fn new(initial_transmission: InitialTransmission) -> Self {
        let challenge_state = ChallengeState::Committed {
            our_nonce: initial_transmission.our_nonce,
            received_commitment: initial_transmission.received_commitment,
        };
        // TODO: make use of initial_transmission.their_max_payload_size.
        Self {
            challenge: challenge_state,
            reconciliation_started: false,
            our_resources: Default::default(),
            their_resources: Default::default(),
            our_range_counter: 0,
            their_range_counter: 0,
            our_uncovered_ranges: Default::default(),
            their_uncovered_ranges: Default::default(),
            pending_announced_entries: Default::default(),
            intersection_queue: Default::default(),
        }
    }

    fn bind_area_of_interest(
        &mut self,
        scope: Scope,
        msg: SetupBindAreaOfInterest,
        capability: &ReadCapability,
    ) -> Result<(), Error> {
        capability.try_granted_area(&msg.area_of_interest.area)?;

        let namespace = *capability.granted_namespace();
        let area = msg.area_of_interest.area.clone();
        let handle = match scope {
            Scope::Ours => self.our_resources.areas_of_interest.bind(msg),
            Scope::Theirs => self.their_resources.areas_of_interest.bind(msg),
        };

        let other_resources = match scope {
            Scope::Ours => &self.their_resources,
            Scope::Theirs => &self.our_resources,
        };

        for (candidate_handle, candidate) in other_resources.areas_of_interest.iter() {
            let candidate_handle = *candidate_handle;
            // Ignore areas without a capability.
            let Some(cap) = other_resources.capabilities.get(&candidate.authorisation) else {
                continue;
            };
            // Ignore areas for a different namespace.
            if *cap.granted_namespace() != namespace {
                continue;
            }
            // Check if we have an intersection.
            if let Some(intersection) = candidate.area().intersection(&area) {
                // We found an intersection!
                let (our_handle, their_handle) = match scope {
                    Scope::Ours => (handle, candidate_handle),
                    Scope::Theirs => (candidate_handle, handle),
                };
                let info = AreaOfInterestIntersection {
                    our_handle,
                    their_handle,
                    intersection,
                    namespace: namespace.into(),
                };
                self.intersection_queue.push_back(info);
            }
        }
        Ok(())
    }

    fn decrement_pending_announced_entries(&mut self) -> Result<(), Error> {
        let remaining = self
            .pending_announced_entries
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        *remaining -= 1;
        if *remaining == 0 {
            self.pending_announced_entries = None;
        }
        Ok(())
    }

    fn mark_our_range_covered(
        &mut self,
        our_handle: AreaOfInterestHandle,
        range_count: u64,
    ) -> Result<(), Error> {
        if !self.our_uncovered_ranges.remove(&(our_handle, range_count)) {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }

    fn mark_their_range_covered(
        &mut self,
        their_handle: AreaOfInterestHandle,
        range_count: u64,
    ) -> Result<(), Error> {
        // trace!(?their_handle, ?range_count, "mark_their_range_covered");
        if !self
            .their_uncovered_ranges
            .remove(&(their_handle, range_count))
        {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }

    fn add_pending_range_theirs(&mut self, their_handle: AreaOfInterestHandle) -> u64 {
        let range_count = self.their_range_counter;
        self.their_range_counter += 1;
        // debug!(?their_handle, ?range_count, "add_pending_range_theirs");
        self.their_uncovered_ranges
            .insert((their_handle, range_count));
        range_count
    }
}
