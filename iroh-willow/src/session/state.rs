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
pub type SharedSessionState = Rc<RefCell<SessionState>>;

#[derive(Debug)]
pub struct SessionState {
    pub our_role: Role,
    peer: NodeId,
    pub our_resources: ScopedResources,
    pub their_resources: ScopedResources,
    pub reconciliation_started: bool,
    pub pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pub pending_entries: Option<u64>,
    notify_complete: Arc<Notify>,
    challenge: ChallengeState,
    our_current_aoi: Option<AreaOfInterestHandle>,
}

impl SessionState {
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
        let aoi = self.resources(scope).areas_of_interest.get(handle)?;
        let capability = self.resources(scope).capabilities.get(&aoi.authorisation)?;
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
        self.resources(scope).areas_of_interest.get(handle)
    }
}
