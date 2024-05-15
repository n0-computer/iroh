use std::{
    cell::{RefCell, RefMut},
    collections::{HashSet, VecDeque},
    future::poll_fn,
    pin::Pin,
    rc::Rc,
    task::{Poll, Waker},
};

use futures_lite::Stream;
use tracing::{warn, Instrument, Span};

use crate::{
    net::InitialTransmission,
    proto::{
        challenge::ChallengeState,
        grouping::{Area, ThreeDRange},
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, CapabilityHandle, CommitmentReveal, IntersectionHandle, IsHandle,
            Message, ReadCapability, SetupBindAreaOfInterest, SetupBindReadCapability,
            SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
    },
    store::{KeyStore, Store},
    util::{channel::WriteError, task_set::TaskMap},
};

use super::{
    channels::ChannelSenders,
    resource::{ResourceMap, ScopedResources},
    Error, Role, Scope,
};

#[derive(derive_more::Debug)]
pub struct Session<S> {
    pub state: Rc<RefCell<SessionState>>,
    pub send: ChannelSenders,
    #[debug("Store")]
    pub store: Rc<RefCell<S>>,
    pub tasks: Rc<RefCell<TaskMap<Span, Result<(), Error>>>>,
}
impl<S> Clone for Session<S> {
    fn clone(&self) -> Self {
        Self {
            state: Rc::clone(&self.state),
            send: self.send.clone(),
            store: Rc::clone(&self.store),
            tasks: Rc::clone(&self.tasks),
        }
    }
}

impl<S: Store> Session<S> {
    pub fn new(
        store: Rc<RefCell<S>>,
        send: ChannelSenders,
        our_role: Role,
        initial_transmission: InitialTransmission,
    ) -> Self {
        let state = SessionState::new(our_role, initial_transmission);
        Self {
            state: Rc::new(RefCell::new(state)),
            send,
            store,
            tasks: Default::default(),
        }
    }

    pub fn spawn<F, Fut>(&self, span: Span, f: F)
    where
        F: FnOnce(Session<S>) -> Fut,
        Fut: std::future::Future<Output = Result<(), Error>> + 'static,
    {
        let state = self.clone();
        let fut = f(state);
        let fut = fut.instrument(span.clone());
        self.tasks.borrow_mut().spawn_local(span, fut);
    }

    pub async fn join_next_task(&self) -> Option<(Span, Result<(), Error>)> {
        poll_fn(|cx| {
            let mut tasks = self.tasks.borrow_mut();
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

    pub async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
        self.send.send(message).await
    }

    pub async fn next_aoi_intersection(&self) -> Option<AreaOfInterestIntersection> {
        poll_fn(|cx| {
            let mut aoi_queue = &mut self.state.borrow_mut().aoi_queue;
            Pin::new(&mut aoi_queue).poll_next(cx)
        })
        .await
    }

    pub async fn get_their_resource_eventually<F, H: IsHandle, R: Eq + PartialEq + Clone>(
        &self,
        selector: F,
        handle: H,
    ) -> R
    where
        F: for<'a> Fn(&'a mut ScopedResources) -> &'a mut ResourceMap<H, R>,
    {
        let inner = self.state.clone();
        poll_fn(move |cx| {
            let mut inner = inner.borrow_mut();
            let res = selector(&mut std::ops::DerefMut::deref_mut(&mut inner).their_resources);
            let r = std::task::ready!(res.poll_get_eventually(handle, cx));
            Poll::Ready(r.clone())
        })
        .await
    }

    pub fn bind_and_sign_capability(
        &self,
        our_intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<(CapabilityHandle, Option<SetupBindReadCapability>), Error> {
        let mut inner = self.state.borrow_mut();
        let signable = inner.challenge.signable()?;
        let signature = self
            .store
            .borrow_mut()
            .key_store()
            .sign_user(&capability.receiver().id(), &signable)?;

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

    pub fn state_mut(&self) -> RefMut<SessionState> {
        self.state.borrow_mut()
    }

    pub fn store(&self) -> RefMut<S> {
        self.store.borrow_mut()
    }
}

#[derive(Debug)]
pub struct SessionState {
    pub our_role: Role,
    pub our_resources: ScopedResources,
    pub their_resources: ScopedResources,
    pub reconciliation_started: bool,
    pub pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pub pending_entries: Option<u64>,
    pub challenge: ChallengeState,
    pub aoi_queue: AoiQueue,
}

impl SessionState {
    pub fn new(our_role: Role, initial_transmission: InitialTransmission) -> Self {
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
            pending_ranges: Default::default(),
            pending_entries: Default::default(),
            aoi_queue: Default::default(),
        }
    }
    fn resources(&self, scope: Scope) -> &ScopedResources {
        match scope {
            Scope::Ours => &self.our_resources,
            Scope::Theirs => &self.their_resources,
        }
    }
    // fn resources_mut(&mut self, scope: Scope) -> &ScopedResources {
    //     match scope {
    //         Scope::Ours => &mut self.our_resources,
    //         Scope::Theirs => &mut self.their_resources,
    //     }
    // }
    pub fn reconciliation_is_complete(&self) -> bool {
        // tracing::debug!(
        //     "reconciliation_is_complete started {} pending_ranges {}, pending_entries {}",
        //     self.reconciliation_started,
        //     self.pending_ranges.len(),
        //     self.pending_entries.is_some()
        // );
        self.reconciliation_started
            && self.pending_ranges.is_empty()
            && self.pending_entries.is_none()
    }

    pub fn commitment_reveal(&mut self) -> Result<CommitmentReveal, Error> {
        match self.challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce })
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn on_commitment_reveal(&mut self, msg: CommitmentReveal) -> Result<(), Error> {
        self.challenge.reveal(self.our_role, msg.nonce)
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

    /// Bind a area of interest, and start reconciliation if this area of interest has an
    /// intersection with a remote area of interest.
    ///
    /// Will fail if the capability is missing. Await [`Self::get_our_resource_eventually`] or
    /// [`Self::get_their_resource_eventually`] before calling this.
    ///
    /// Returns `true` if the capability was newly bound, and `false` if not.
    pub fn bind_area_of_interest(
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

    pub fn clear_pending_range_if_some(
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

    pub fn bind_our_static_token(
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

    pub fn handle_to_namespace_id(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let aoi = self.resources(scope).areas_of_interest.try_get(handle)?;
        let capability = self
            .resources(scope)
            .capabilities
            .try_get(&aoi.authorisation)?;
        let namespace_id = capability.granted_namespace().into();
        Ok(namespace_id)
    }

    pub fn range_is_authorised(
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
        self.resources(scope).areas_of_interest.try_get(handle)
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
    closed: bool,
    wakers: VecDeque<Waker>,
}

impl AoiQueue {
    pub fn push(&mut self, pair: AreaOfInterestIntersection) {
        self.found.push_back(pair);
        self.wake();
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.wake();
    }
    fn wake(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    pub fn poll_next(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<AreaOfInterestIntersection>> {
        if self.closed {
            return Poll::Ready(None);
        }
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
