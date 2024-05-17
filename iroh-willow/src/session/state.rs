use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{HashSet, VecDeque},
    future::poll_fn,
    pin::Pin,
    rc::Rc,
    task::{Poll, Waker},
};

use futures_lite::Stream;
use tracing::{Instrument, Span};

use crate::{
    net::InitialTransmission,
    proto::{
        challenge::ChallengeState,
        grouping::{Area, ThreeDRange},
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, CapabilityHandle, Channel, CommitmentReveal, IntersectionHandle,
            IsHandle, LogicalChannel, Message, ReadCapability, ReconciliationAnnounceEntries,
            ReconciliationSendFingerprint, SetupBindAreaOfInterest, SetupBindReadCapability,
            SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
    },
    store::{KeyStore, Shared},
    util::{channel::WriteError, task_set::TaskMap},
};

use super::{
    channels::ChannelSenders,
    resource::{ResourceMap, ScopedResources},
    Error, Role, Scope,
};

#[derive(Debug, Clone)]
pub struct Session(Rc<SessionInner>);

#[derive(derive_more::Debug)]
struct SessionInner {
    state: RefCell<SessionState>,
    send: ChannelSenders,
    tasks: RefCell<TaskMap<Span, Result<(), Error>>>,
}

impl Session {
    pub fn new(
        send: ChannelSenders,
        our_role: Role,
        initial_transmission: InitialTransmission,
    ) -> Self {
        let state = SessionState::new(our_role, initial_transmission);
        Self(Rc::new(SessionInner {
            state: RefCell::new(state),
            send,
            tasks: Default::default(),
        }))
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
            let res = std::task::ready!(Pin::new(&mut tasks).poll_next(cx));
            let res = match res {
                None => None,
                Some((key, Ok(r))) => Some((key, r)),
                Some((key, Err(r))) => Some((key, Err(r.into()))),
            };
            Poll::Ready(res)
        })
        .await
    }

    pub fn remaining_tasks(&self) -> usize {
        let tasks = self.0.tasks.borrow();
        tasks.len()
    }

    pub async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
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
        self.0.state.borrow().our_role
    }

    pub async fn next_aoi_intersection(&self) -> Option<AreaOfInterestIntersection> {
        poll_fn(|cx| {
            let mut aoi_queue = &mut self.0.state.borrow_mut().aoi_queue;
            Pin::new(&mut aoi_queue).poll_next(cx)
        })
        .await
    }

    pub fn get_our_resource<F, H: IsHandle, R: Eq + PartialEq + Clone>(
        &self,
        selector: F,
        handle: H,
    ) -> Result<R, Error>
    where
        F: for<'a> Fn(&'a mut ScopedResources) -> &'a mut ResourceMap<H, R>,
    {
        let mut state = self.0.state.borrow_mut();
        let res = selector(&mut std::ops::DerefMut::deref_mut(&mut state).our_resources);
        res.try_get(&handle).cloned()
    }

    pub async fn get_their_resource_eventually<F, H: IsHandle, R: Eq + PartialEq + Clone>(
        &self,
        selector: F,
        handle: H,
    ) -> R
    where
        F: for<'a> Fn(&'a mut ScopedResources) -> &'a mut ResourceMap<H, R>,
    {
        let inner = &self.clone().0;
        poll_fn(move |cx| {
            let mut state = inner.state.borrow_mut();
            let res = selector(&mut std::ops::DerefMut::deref_mut(&mut state).their_resources);
            let r = std::task::ready!(res.poll_get_eventually(handle, cx));
            Poll::Ready(r.clone())
        })
        .await
    }

    pub fn bind_and_sign_capability<K: KeyStore>(
        &self,
        key_store: &Shared<K>,
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

    pub fn mark_range_pending(&self, our_handle: AreaOfInterestHandle) {
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
                state.mark_range_covered(message.receiver_handle, range_count)?;
            }
            if state.pending_entries.is_some() {
                return Err(Error::InvalidMessageInCurrentState);
            }
            if message.count != 0 {
                state.pending_entries = Some(message.count);
            }
            if message.want_response {
                let range_count = state.their_range_counter;
                state.their_range_counter += 1;
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
                state.mark_range_covered(message.receiver_handle, range_count)?;
            }
            let range_count = state.their_range_counter;
            state.their_range_counter += 1;
            range_count
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
        let our_aoi = self.get_our_resource(|r| &mut r.areas_of_interest, receiver_handle)?;
        let their_aoi = self
            .get_their_resource_eventually(|r| &mut r.areas_of_interest, sender_handle)
            .await;

        if !our_aoi.area().includes_range(&range) || !their_aoi.area().includes_range(&range) {
            return Err(Error::RangeOutsideCapability);
        }
        Ok(our_namespace.into())
    }

    pub fn on_setup_bind_static_token(&self, msg: SetupBindStaticToken) {
        self.state_mut()
            .their_resources
            .static_tokens
            .bind(msg.static_token);
    }

    pub fn on_setup_bind_read_capability(&self, msg: SetupBindReadCapability) -> Result<(), Error> {
        // TODO: verify intersection handle
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
        tracing::debug!(
            "reconciliation_is_complete started {} pending_ranges {}, pending_entries {:?}",
            state.reconciliation_started,
            state.our_uncovered_ranges.len(),
            state.pending_entries
        );
        state.reconciliation_started
            && state.our_uncovered_ranges.is_empty()
            // && state.their_uncovered_ranges.is_empty()
            && state.pending_entries.is_none()
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
        let mut state = self.state_mut();
        let our_role = state.our_role;
        state.challenge.reveal(our_role, msg.nonce)
    }

    pub fn bind_area_of_interest(
        &self,
        scope: Scope,
        message: SetupBindAreaOfInterest,
    ) -> Result<(), Error> {
        self.state_mut().bind_area_of_interest(scope, message)
    }

    pub async fn on_bind_area_of_interest(
        &self,
        message: SetupBindAreaOfInterest,
    ) -> Result<(), Error> {
        self.get_their_resource_eventually(|r| &mut r.capabilities, message.authorisation)
            .await;
        self.bind_area_of_interest(Scope::Theirs, message)?;
        Ok(())
    }

    pub fn on_send_entry(&self) -> Result<(), Error> {
        self.state_mut().decrement_pending_entries()
    }

    pub fn bind_our_static_token(
        &self,
        token: StaticToken,
    ) -> (StaticTokenHandle, Option<SetupBindStaticToken>) {
        self.state_mut().bind_our_static_token(token)
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
    our_role: Role,
    our_resources: ScopedResources,
    their_resources: ScopedResources,
    reconciliation_started: bool,
    our_uncovered_ranges: HashSet<(AreaOfInterestHandle, u64)>,
    // their_uncovered_ranges: HashSet<(AreaOfInterestHandle, u64)>,
    our_range_counter: u64,
    their_range_counter: u64,
    pending_entries: Option<u64>,
    challenge: ChallengeState,
    aoi_queue: AoiQueue,
}

impl SessionState {
    fn new(our_role: Role, initial_transmission: InitialTransmission) -> Self {
        let challenge_state = ChallengeState::Committed {
            our_nonce: initial_transmission.our_nonce,
            received_commitment: initial_transmission.received_commitment,
        };
        // TODO: make use of initial_transmission.their_max_payload_size.
        Self {
            our_role,
            challenge: challenge_state,
            reconciliation_started: false,
            our_resources: Default::default(),
            their_resources: Default::default(),
            our_range_counter: 0,
            their_range_counter: 0,
            our_uncovered_ranges: Default::default(),
            // their_uncovered_ranges: Default::default(),
            pending_entries: Default::default(),
            aoi_queue: Default::default(),
        }
    }

    /// Bind a area of interest, and start reconciliation if this area of interest has an
    /// intersection with a remote area of interest.
    ///
    /// Will fail if the capability is missing. Await [`Self::get_our_resource_eventually`] or
    /// [`Self::get_their_resource_eventually`] before calling this.
    ///
    /// Returns `true` if the capability was newly bound, and `false` if not.
    fn bind_area_of_interest(
        &mut self,
        scope: Scope,
        msg: SetupBindAreaOfInterest,
    ) -> Result<(), Error> {
        let capability = match scope {
            Scope::Ours => self
                .our_resources
                .capabilities
                .try_get(&msg.authorisation)?,
            Scope::Theirs => self
                .their_resources
                .capabilities
                .try_get(&msg.authorisation)?,
        };
        capability.try_granted_area(&msg.area_of_interest.area)?;

        let namespace = *capability.granted_namespace();
        let area = msg.area_of_interest.area.clone();
        let handle = match scope {
            Scope::Ours => self.our_resources.areas_of_interest.bind(msg),
            Scope::Theirs => self.their_resources.areas_of_interest.bind(msg),
        };

        let haystack = match scope {
            Scope::Ours => &self.their_resources,
            Scope::Theirs => &self.our_resources,
        };

        for (candidate_handle, candidate) in haystack.areas_of_interest.iter() {
            let candidate_handle = *candidate_handle;
            // Ignore areas without a capability.
            let Some(cap) = haystack.capabilities.get(&candidate.authorisation) else {
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
                let shared = AreaOfInterestIntersection {
                    our_handle,
                    their_handle,
                    intersection,
                    namespace: namespace.into(),
                };
                self.aoi_queue.push(shared);
            }
        }
        Ok(())
    }

    fn decrement_pending_entries(&mut self) -> Result<(), Error> {
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

    fn mark_range_covered(
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

    fn bind_our_static_token(
        &mut self,
        static_token: StaticToken,
    ) -> (StaticTokenHandle, Option<SetupBindStaticToken>) {
        let (handle, is_new) = self
            .our_resources
            .static_tokens
            .bind_if_new(static_token.clone());
        let msg = is_new.then(|| SetupBindStaticToken { static_token });
        (handle, msg)
    }
}

#[derive(Debug, Clone)]
pub struct AreaOfInterestIntersection {
    pub our_handle: AreaOfInterestHandle,
    pub their_handle: AreaOfInterestHandle,
    pub intersection: Area,
    pub namespace: NamespaceId,
}

#[derive(Default, Debug)]
pub struct AoiQueue {
    found: VecDeque<AreaOfInterestIntersection>,
    // closed: bool,
    wakers: VecDeque<Waker>,
}

impl AoiQueue {
    pub fn push(&mut self, pair: AreaOfInterestIntersection) {
        self.found.push_back(pair);
        self.wake();
    }
    // pub fn close(&mut self) {
    //     self.closed = true;
    //     self.wake();
    // }
    fn wake(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    pub fn poll_next(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<AreaOfInterestIntersection>> {
        // if self.closed {
        //     return Poll::Ready(None);
        // }
        if let Some(item) = self.found.pop_front() {
            Poll::Ready(Some(item))
        } else {
            self.wakers.push_back(cx.waker().to_owned());
            Poll::Pending
        }
    }
}

impl Stream for AoiQueue {
    type Item = AreaOfInterestIntersection;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Self::poll_next(self.get_mut(), cx)
    }
}
